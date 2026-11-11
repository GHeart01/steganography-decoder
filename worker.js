// Runs the two models off the main thread so the page stays responsive.
// With 8 GB+ of memory both models stay loaded between images (reloading
// costs ~5 s); on smaller machines only one is kept at a time, because
// integrated GPUs share system RAM.
import {
  env, AutoProcessor, Florence2ForConditionalGeneration, Qwen3VLForConditionalGeneration,
  RawImage, TextStreamer, cat,
} from "https://cdn.jsdelivr.net/npm/@huggingface/transformers@4.3.2";
import { OPFSCache } from "./lib/opfs-cache.js";

const MODELS = {
  florence: "onnx-community/Florence-2-base-ft",
  qwen: "onnx-community/Qwen3-VL-2B-Instruct-ONNX",
};

let device = "wasm";
const loaded = new Map();  // name -> { name, model, processor }
const loading = new Map(); // name -> Promise, so concurrent requests share one load
const keepBoth = (navigator.deviceMemory ?? 8) >= 8;
let stopRequested = false;

const post = (msg) => self.postMessage(msg);
const timing = (label, started, extra = {}) => post({ type: "timing", label, ms: Math.round(performance.now() - started), ...extra });

async function setup() {
  if (await OPFSCache.available()) {
    env.useCustomCache = true;
    env.customCache = new OPFSCache();
    env.useBrowserCache = false;
  }
  let f16 = false;
  try {
    const adapter = await navigator.gpu?.requestAdapter();
    if (adapter) {
      device = "webgpu";
      f16 = adapter.features.has("shader-f16");
    }
  } catch {}
  return { device, f16, keepBoth };
}

// Model weights report one whole-model total up front (progress_total), so
// the bar never jumps backwards when the next file starts. The processor's
// small files are only recorded (for the stored-files list), not shown.
function progress(name, showBar = true) {
  return (p) => {
    if (p.status === "initiate") post({ type: "file", model: name, file: p.file, repo: p.name });
    if (showBar && p.status === "progress_total" && p.total) {
      post({ type: "progress", model: name, loaded: p.loaded, total: p.total });
    }
  };
}

async function unloadAll(except) {
  for (const [name, entry] of loaded) {
    if (name === except) continue;
    loaded.delete(name);
    await entry.model.dispose();
    post({ type: "status", model: name, status: "unloaded" });
  }
}

function load(name, f16) {
  if (loaded.has(name)) return Promise.resolve(loaded.get(name));
  if (!loading.has(name)) {
    const p = doLoad(name, f16).finally(() => loading.delete(name));
    loading.set(name, p);
  }
  return loading.get(name);
}

async function doLoad(name, f16) {
  if (!keepBoth) await unloadAll(name);
  post({ type: "status", model: name, status: "loading" });
  const loadStart = performance.now();
  const id = MODELS[name];
  const progress_callback = progress(name);
  let model;
  if (name === "florence") {
    const dtype = device === "webgpu" && f16
      ? { embed_tokens: "fp16", vision_encoder: "fp16", encoder_model: "q4", decoder_model_merged: "q4" }
      : "q8";
    model = await Florence2ForConditionalGeneration.from_pretrained(id, { device, dtype, progress_callback });
  } else {
    if (device !== "webgpu") throw new Error("Deep analysis needs WebGPU (Chrome, Edge or Safari 26+).");
    const dtype = f16
      ? { embed_tokens: "q4f16", vision_encoder: "q4f16", decoder_model_merged: "q4f16" }
      : { embed_tokens: "q4", vision_encoder: "q4", decoder_model_merged: "q4" };
    model = await Qwen3VLForConditionalGeneration.from_pretrained(id, { device, dtype, progress_callback });
  }
  const processor = await AutoProcessor.from_pretrained(id, { progress_callback: progress(name, false) });
  const entry = { name, model, processor };
  loaded.set(name, entry);
  timing(`load ${name}`, loadStart);
  post({ type: "status", model: name, status: "ready" });
  return entry;
}

const toRaw = (img) => new RawImage(new Uint8ClampedArray(img.data), img.width, img.height, 4).rgb();

// Florence-2: OCR with positions on each tile, one tile per call. Batching
// tiles was tried and measured ~2.5× slower in Transformers.js 4.3.2: the
// whole batch keeps decoding until its longest tile finishes.
async function florence({ tiles, f16 }) {
  const { model, processor } = await load("florence", f16);
  const task = "<OCR_WITH_REGION>";
  const prompts = processor.construct_prompts(task);
  const results = [];
  const ocrStart = performance.now();
  for (let i = 0; i < tiles.length && !stopRequested; i++) {
    const t = tiles[i];
    const image = toRaw(t.image);
    const inputs = await processor(image, prompts);
    const ids = await model.generate({ ...inputs, max_new_tokens: 256, num_beams: 1, do_sample: false });
    const text = processor.batch_decode(ids, { skip_special_tokens: false })[0];
    const out = processor.post_process_generation(text, task, [image.width, image.height])[task];
    results.push({ id: t.id, labels: out.labels, quads: out.quad_boxes });
    post({ type: "tile", done: i + 1, total: tiles.length });
  }
  timing("ocr", ocrStart, { tiles: tiles.length });
  return results;
}

// Qwen3-VL: one prompt over several images, streamed back token by token.
// Transformers.js 4.3.2 treats an image list as video frames, so each image
// is preprocessed separately and the results concatenated.
async function qwen({ images, system, prompt, maxNewTokens, f16 }) {
  const { model, processor } = await load("qwen", f16);
  const prepStart = performance.now();
  const per = [];
  for (const img of images) per.push(await processor.image_processor(toRaw(img)));
  const pixel_values = cat(per.map((x) => x.pixel_values), 0);
  const image_grid_thw = cat(per.map((x) => x.image_grid_thw), 0);
  const thw = image_grid_thw.tolist().map((r) => r.map(Number));
  const merge = processor.image_processor.config.merge_size ** 2;

  const conversation = [
    { role: "system", content: system },
    { role: "user", content: [...images.map(() => ({ type: "image" })), { type: "text", text: prompt }] },
  ];
  let text = processor.apply_chat_template(conversation, { add_generation_prompt: true });
  let k = 0;
  text = text.replace(/<\|image_pad\|>/g, () => {
    const [t, h, w] = thw[k++];
    return "<|placeholder|>".repeat((t * h * w) / merge);
  }).replaceAll("<|placeholder|>", "<|image_pad|>");
  const inputs = { ...processor.tokenizer(text), pixel_values, image_grid_thw };
  timing("qwen prepare", prepStart);

  // Small models can loop ("- The text X is…" forever). Stop when the same
  // line has come out three times.
  let partial = "", looping = false, firstToken = 0, tokens = 0;
  const lineCounts = new Map();
  const streamer = new TextStreamer(processor.tokenizer, {
    skip_prompt: true,
    skip_special_tokens: true,
    callback_function: (t) => {
      if (!firstToken) firstToken = performance.now();
      tokens++;
      post({ type: "token", text: t });
      partial += t;
      const parts = partial.split("\n");
      partial = parts.pop();
      for (const line of parts) {
        const key = line.trim().toLowerCase();
        if (key.length < 8) continue;
        const c = (lineCounts.get(key) ?? 0) + 1;
        lineCounts.set(key, c);
        if (c >= 3) looping = true;
      }
    },
  });
  const started = performance.now();
  // Sampling settings recommended for Qwen3-VL Instruct; greedy decoding
  // makes a 2B model repeat itself.
  const out = await model.generate({
    ...inputs,
    max_new_tokens: maxNewTokens,
    do_sample: true,
    temperature: 0.7,
    top_p: 0.8,
    top_k: 20,
    repetition_penalty: 1.05,
    streamer,
    stopping_criteria: [() => [stopRequested || looping]],
  });
  const n = inputs.input_ids.dims.at(-1);
  const genEnd = performance.now();
  post({ type: "timing", label: "qwen first token", ms: Math.round((firstToken || genEnd) - started), promptTokens: n });
  post({ type: "timing", label: "qwen decode", ms: Math.round(genEnd - firstToken), chunks: tokens });
  let answer = processor.batch_decode(out.slice(null, [n, null]), { skip_special_tokens: true })[0];
  // Drop repeated lines left over from a loop.
  const seenLines = new Set();
  answer = answer.split("\n").filter((line) => {
    const key = line.trim().toLowerCase();
    if (key.length < 8) return true;
    if (seenLines.has(key)) return false;
    seenLines.add(key);
    return true;
  }).join("\n");
  return { text: answer, promptTokens: n, seconds: (performance.now() - started) / 1000, looped: looping };
}

const ready = setup();

// One model job at a time. ONNX Runtime stalls when a session is created
// while another model is running in the same worker (seen as OCR stuck on
// its first tile while Qwen3-VL loaded), so loads and runs are queued.
let queue = Promise.resolve();
function exclusive(job) {
  const run = queue.then(job, job);
  queue = run.catch(() => {});
  return run;
}

self.onmessage = async ({ data }) => {
  const { id, cmd, args } = data;
  try {
    const caps = await ready;
    if (cmd === "caps") return post({ id, result: caps });
    if (cmd === "stop") { stopRequested = true; return post({ id, result: true }); }
    const result = await exclusive(async () => {
      if (cmd === "unload") { await unloadAll(); return true; }
      if (cmd === "preload") {
        // Warm-up only; never replaces a model that's in use on small machines.
        if (!keepBoth && loaded.size) return false;
        await load(args.name, caps.f16);
        return true;
      }
      const fn = { florence, qwen }[cmd];
      stopRequested = false;
      return fn({ ...args, f16: caps.f16 });
    });
    post({ id, result });
  } catch (err) {
    console.error(err);
    post({ id, error: String(err?.message ?? err) });
  }
};
