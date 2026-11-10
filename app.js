import { decodeImage } from "./lib/decode.js";
import { analyzeContainer } from "./lib/metadata.js";
import { analyzeLsb, analyzeSpectrum, analyzeColor, scalingAttackCheck, lsbPlaneView, fitSize } from "./lib/forensics.js";
import { makeViews, VIEW_INFO } from "./lib/views.js";
import { makeTiles, mergeOcr, ocrFindings, buildVlmInputs, buildPrompt } from "./lib/pipeline.js";
import { cacheStatus, clearCache } from "./lib/opfs-cache.js";
import { makeSample, drawSamplePreview } from "./lib/sample.js";

const $ = (id) => document.getElementById(id);
const tick = () => new Promise((r) => setTimeout(r, 0));
const MODEL_NAMES = { florence: "Florence-2", qwen: "Qwen3-VL-2B" };
const SEVERITY = ["high", "medium", "low", "info"];

// ---------------------------------------------------------------------------
// Worker RPC

const worker = new Worker(new URL("./worker.js", import.meta.url), { type: "module" });
const pending = new Map();
let nextId = 1;
const listeners = new Set();
worker.onmessage = ({ data }) => {
  if (data.id && pending.has(data.id)) {
    const { resolve, reject } = pending.get(data.id);
    pending.delete(data.id);
    data.error ? reject(new Error(data.error)) : resolve(data.result);
  } else {
    for (const l of listeners) l(data);
  }
};
function call(cmd, args = {}) {
  const id = nextId++;
  return new Promise((resolve, reject) => {
    pending.set(id, { resolve, reject });
    worker.postMessage({ id, cmd, args });
  });
}

// ---------------------------------------------------------------------------
// Model storage: remember which files each model needs, so we can tell
// whether it is fully stored on this device.

const manifestKey = (m) => `aid-manifest-${m}`;
const fileUrls = { florence: new Set(), qwen: new Set() };
const readManifest = (m) => {
  try { return JSON.parse(localStorage.getItem(manifestKey(m)) ?? "[]"); } catch { return []; }
};
const writeManifest = (m) => {
  try { localStorage.setItem(manifestKey(m), JSON.stringify([...fileUrls[m]])); } catch {}
};

const storedModels = new Set();

async function showStorage() {
  const parts = [];
  let total = 0;
  for (const m of ["florence", "qwen"]) {
    const urls = readManifest(m);
    if (!urls.length) continue;
    const s = await cacheStatus(urls);
    total = s.bytes;
    if (s.complete) storedModels.add(m); else storedModels.delete(m);
    parts.push(`${MODEL_NAMES[m]} ${s.complete ? "saved" : "partly saved (will finish downloading next time)"}`);
  }
  if (!total) { $("storage").hidden = true; return; }
  $("storage-text").textContent = `${parts.join(" · ")} on this device (${(total / 1e9).toFixed(2)} GB).`;
  $("clear").hidden = false;
  $("storage").hidden = false;
}

$("clear").addEventListener("click", async () => {
  await call("unload");
  try { await clearCache(); } catch {}
  for (const m of ["florence", "qwen"]) { try { localStorage.removeItem(manifestKey(m)); } catch {} }
  storedModels.clear();
  $("storage-text").textContent = "Downloaded models removed from this device.";
  $("clear").hidden = true;
});

// ---------------------------------------------------------------------------
// Progress UI

const stepEls = new Map();
function setSteps(names) {
  $("steps").replaceChildren(...names.map((n) => {
    const li = document.createElement("li");
    li.textContent = n;
    stepEls.set(n, li);
    return li;
  }));
  $("progress-card").hidden = false;
}
function step(name, state) {
  const li = stepEls.get(name);
  if (li) li.className = state;
}
function bar(fraction, text) {
  $("bar-wrap").hidden = fraction === null;
  if (fraction !== null) $("bar").style.width = `${(fraction * 100).toFixed(1)}%`;
  $("bar-text").textContent = text ?? "";
}

window.__timings = [];
listeners.add((m) => {
  if (m.type === "timing") { window.__timings.push(m); console.debug("timing", m); }
  if (m.type === "file" && fileUrls[m.model]) fileUrls[m.model].add(`https://huggingface.co/${m.repo}/resolve/main/${m.file}`);
  if (m.type === "progress") {
    const mb = `${(m.loaded / 1e6).toFixed(0)} / ${(m.total / 1e6).toFixed(0)} MB`;
    bar(m.loaded / m.total, storedModels.has(m.model)
      ? `Loading ${MODEL_NAMES[m.model]} from this device… ${mb}`
      : `Downloading ${MODEL_NAMES[m.model]}… ${mb} (only the first time)`);
  }
  if (m.type === "status" && m.status === "loading") bar(null, `Loading ${MODEL_NAMES[m.model]}…`);
  if (m.type === "status" && m.status === "ready") {
    writeManifest(m.model);
    navigator.storage?.persist?.().catch(() => {});
    bar(null, "");
  }
  if (m.type === "tile") bar(m.done / m.total, `Reading text: part ${m.done} of ${m.total}`);
  if (m.type === "token") $("ai").textContent += m.text;
});

// ---------------------------------------------------------------------------
// Rendering helpers (all untrusted text goes through textContent)

function el(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined) e.textContent = text;
  return e;
}

function renderFindings(findings) {
  const sorted = [...findings].sort((a, b) => SEVERITY.indexOf(a.severity) - SEVERITY.indexOf(b.severity));
  if (!sorted.length) {
    $("findings").replaceChildren(el("li", "empty", "Nothing suspicious found so far."));
    return;
  }
  $("findings").replaceChildren(...sorted.map((f) => {
    const li = el("li", `finding ${f.severity}`);
    li.append(el("div", "sev", f.severity === "info" ? "note" : f.severity));
    li.append(el("div", "title", f.title));
    if (f.detail) li.append(el("div", "detail", f.detail));
    if (f.text) li.append(el("pre", "", f.text));
    return li;
  }));
}

function toCanvas(img, canvas = document.createElement("canvas")) {
  canvas.width = img.width;
  canvas.height = img.height;
  canvas.getContext("2d").putImageData(new ImageData(new Uint8ClampedArray(img.data), img.width, img.height), 0, 0);
  return canvas;
}

let state = null;

function renderView(name) {
  const v = state.viewList.find((x) => x.key === name);
  for (const b of $("tabs").children) b.setAttribute("aria-selected", String(b.dataset.key === name));
  $("view-info").textContent = v.info;
  const canvas = $("view");
  toCanvas(v.img, canvas);
  canvas.classList.toggle("pixelated", name === "lsb" || name === "nearest");
  const svg = $("overlay");
  svg.replaceChildren();
  if (v.boxes && $("show-boxes").checked) {
    svg.setAttribute("viewBox", `0 0 ${state.width} ${state.height}`);
    for (const t of state.texts) {
      const r = document.createElementNS("http://www.w3.org/2000/svg", "rect");
      r.setAttribute("x", t.box.x0); r.setAttribute("y", t.box.y0);
      r.setAttribute("width", t.box.x1 - t.box.x0); r.setAttribute("height", t.box.y1 - t.box.y0);
      if (t.enhancedOnly) r.setAttribute("class", "hidden-text");
      svg.append(r);
    }
  }
}

function renderViews() {
  $("tabs").replaceChildren(...state.viewList.map((v) => {
    const b = el("button", "", v.label);
    b.type = "button";
    b.dataset.key = v.key;
    b.setAttribute("role", "tab");
    b.addEventListener("click", () => { state.current = v.key; renderView(v.key); });
    return b;
  }));
  renderView(state.current);
}
$("show-boxes").addEventListener("change", () => state && renderView(state.current));

function renderTexts() {
  const tbody = $("texts");
  tbody.replaceChildren(...state.texts.map((t) => {
    const tr = el("tr");
    const td = el("td");
    td.append(el("span", "", t.text));
    if (t.enhancedOnly) { td.append(" "); td.append(el("span", "tag warn", "only after enhancement")); }
    if (t.repeated) { td.append(" "); td.append(el("span", "tag warn", "repeated")); }
    tr.append(td);
    const views = el("td");
    for (const v of t.views) views.append(el("span", "tag", v));
    tr.append(views);
    tr.append(el("td", "", `${Math.round(t.box.x0)}, ${Math.round(t.box.y0)}`));
    return tr;
  }));
  $("texts-empty").hidden = state.texts.length > 0;
}

function stats(dl, pairs) {
  dl.replaceChildren(...pairs.flatMap(([k, v]) => [el("dt", "", k), el("dd", "", v)]));
}

function renderColor(color) {
  $("palette").replaceChildren(...color.palette.map((p) => {
    const d = el("div");
    d.style.background = p.hex;
    d.style.flex = String(p.share);
    d.title = `${p.name} ${p.hex} · ${Math.round(p.share * 100)}%`;
    return d;
  }));
  stats($("color-stats"), [
    ["Main colours", color.palette.slice(0, 5).map((p) => `${p.name} ${p.hex} ${Math.round(p.share * 100)}%`).join(", ")],
    ["Unique colours", color.uniqueColors.toLocaleString()],
    ["Average saturation", `${Math.round(color.meanSaturation * 100)}%`],
    ["Strongly saturated", `${Math.round(color.highSaturationShare * 100)}% of pixels`],
    ["Grey", `${Math.round(color.grayShare * 100)}% of pixels`],
  ]);
}

function renderFile(file, decoded, meta) {
  const pairs = [
    ["Name", file.name],
    ["Format", `${decoded.format.toUpperCase()}, ${decoded.img.width}×${decoded.img.height}, ${(file.size / 1024).toFixed(0)} KB`],
    ...Object.entries(meta.fields).map(([k, v]) => [k, String(v)]),
  ];
  if (meta.provenance) pairs.push(["Provenance", meta.provenance]);
  stats($("file-stats"), pairs);
  $("structure").textContent = meta.structure.join(" → ") || "(not parsed)";
}

// ---------------------------------------------------------------------------
// The analysis

let running = false;
let stopped = false;
let caps = null;
const setInputs = (on) => {
  for (const b of [$("file"), $("sample"), ...document.querySelectorAll("button.demo")]) b.disabled = !on;
};

async function analyze(file) {
  if (running) return;
  running = true;
  stopped = false;
  setInputs(false);
  const useOcr = $("use-ocr").checked;
  const useVlm = $("use-vlm").checked && !$("use-vlm").disabled;
  const S = {
    read: "Read the image",
    file: "Check the file structure",
    pixels: "Check pixels, colours and patterns",
    ocr: "Read text in normal, high- and low-saturation views",
    vlm: "Interpret with Qwen3-VL-2B",
  };
  setSteps([S.read, S.file, S.pixels, ...(useOcr ? [S.ocr] : []), ...(useVlm ? [S.vlm] : [])]);
  $("results").hidden = true;
  $("ai-card").hidden = true;
  $("ai").textContent = "";
  bar(null, "");
  let currentStep = S.read;
  const findings = [];

  try {
    window.__timings = [];
    const T0 = performance.now();
    const mark = (label, since) => window.__timings.push({ label, ms: Math.round(performance.now() - since) });
    step(S.read, "active");
    let t = performance.now();
    const decoded = await decodeImage(file);
    mark("decode", t);
    const { img } = decoded;
    step(S.read, "done");

    currentStep = S.file; step(S.file, "active"); await tick();
    const meta = await analyzeContainer(decoded.bytes);
    findings.push(...meta.findings.map((f) => ({ ...f, layer: f.layer ?? (f.severity === "info" ? "file" : "hidden") })));
    step(S.file, "done");

    currentStep = S.pixels; step(S.pixels, "active"); await tick();
    t = performance.now();
    const lossy = !decoded.exact;
    const lsb = analyzeLsb(img, { lossy });
    await tick();
    const spectrum = analyzeSpectrum(img, { lossy: decoded.format === "jpeg" || decoded.format === "webp" });
    await tick();
    const color = analyzeColor(img);
    const [nw, nh] = fitSize(img.width, img.height, 250_000, 1);
    const scaling = scalingAttackCheck(img, nw, nh);
    findings.push(
      ...lsb.findings.map((f) => ({ ...f, layer: "hidden" })),
      ...color.findings.map((f) => ({ ...f, layer: f.title.startsWith("Colours come in") ? "hidden" : "pixels" })),
      ...spectrum.findings, ...scaling.findings,
    );
    const views = makeViews(img);
    mark("pixel checks + views", t);
    step(S.pixels, "done");

    state = {
      width: img.width, height: img.height, texts: [], current: "normal",
      viewList: [
        { key: "normal", label: "Normal", img: views.normal, info: VIEW_INFO.normal, boxes: true },
        { key: "high", label: "High saturation", img: views.high, info: VIEW_INFO.high, boxes: true },
        { key: "low", label: "Low saturation", img: views.low, info: VIEW_INFO.low, boxes: true },
        { key: "lsb", label: "Lowest bits", img: lsbPlaneView(img), boxes: true,
          info: "Lowest bit of each colour channel, amplified. Untouched areas look like the image's noise; hidden data looks like static, often in a block at the top." },
        { key: "spectrum", label: "Frequency spectrum", img: spectrum.view,
          info: "2-D frequency spectrum (centre = smooth areas, edges = fine detail). Bright isolated dots away from the centre lines are repeating patterns." },
        { key: "nearest", label: "Point-sampled shrink", img: scaling.nearest,
          info: "The image shrunk by picking single pixels instead of averaging. If this looks like a different picture, the image is built to fool resizing." },
      ],
    };
    $("notes").textContent = decoded.notes.join(" ");
    renderFindings(findings);
    renderViews();
    renderTexts();
    renderColor(color);
    renderFile(file, decoded, meta);
    $("text-card").hidden = !useOcr;
    $("results").hidden = false;

    // Load Qwen while OCR runs instead of afterwards (when both fit in memory).
    if (useVlm && useOcr && caps?.keepBoth) call("preload", { name: "qwen" }).catch(() => {});

    if (useOcr) {
      currentStep = S.ocr; step(S.ocr, "active");
      $("stop").hidden = false;
      const tiles = makeTiles(views);
      const results = await call("florence", { tiles: tiles.map(({ id, image }) => ({ id, image })) });
      state.texts = mergeOcr(tiles, results);
      findings.push(...ocrFindings(state.texts, img.width, img.height).map((f) => ({ ...f, layer: "ocr" })));
      renderFindings(findings);
      renderTexts();
      renderView(state.current);
      step(S.ocr, stopped ? "failed" : "done");
    }

    if (stopped) {
      if (useVlm) step(S.vlm, "failed");
      bar(null, "Stopped. Results above are from the steps that finished.");
    } else if (useVlm) {
      currentStep = S.vlm; step(S.vlm, "active");
      $("stop").hidden = false;
      $("ai-card").hidden = false;
      const { images, captions } = buildVlmInputs(views, state.texts);
      const { system, prompt } = buildPrompt({ captions, findings, texts: state.texts, color, meta });
      $("ai-images").replaceChildren(...images.map((im) => toCanvas(im)));
      $("ai-prompt").textContent = prompt;
      const res = await call("qwen", { images, system, prompt, maxNewTokens: 450 });
      $("ai").textContent = res.text.trim();
      $("ai").dataset.looped = res.looped ? "1" : "";
      step(S.vlm, stopped ? "failed" : "done");
      if (stopped) bar(null, "Stopped. The interpretation above is incomplete.");
    }
    mark("total", T0);
    if (!stopped) {
      const secs = (performance.now() - T0) / 1000;
      bar(null, `Done in ${secs < 10 ? secs.toFixed(1) : Math.round(secs)} s.${useVlm && $("ai").dataset.looped ? " The AI stopped early because it started repeating itself." : ""}`);
    }
  } catch (err) {
    console.error(err);
    step(currentStep, "failed");
    bar(null, `Couldn't finish "${currentStep}": ${err.message ?? err}`);
  } finally {
    $("stop").hidden = true;
    running = false;
    setInputs(true);
    showStorage();
  }
}

// ---------------------------------------------------------------------------
// Wire up

$("file").addEventListener("change", (e) => {
  const f = e.target.files[0];
  if (f) markDemo(null);
  if (f) analyze(f);
  e.target.value = "";
});
const drop = $("drop");
drop.addEventListener("dragover", (e) => { e.preventDefault(); drop.classList.add("over"); });
drop.addEventListener("dragleave", () => drop.classList.remove("over"));
drop.addEventListener("drop", (e) => {
  e.preventDefault();
  drop.classList.remove("over");
  const f = e.dataTransfer.files[0];
  if (f) { markDemo(null); analyze(f); }
});
// Mark which demo is being analysed (cleared when a file is chosen instead).
function markDemo(card) {
  for (const c of document.querySelectorAll(".demo-card")) c.setAttribute("aria-pressed", String(c === card));
}
drawSamplePreview($("sample-preview"));
$("sample").addEventListener("click", () => { markDemo($("sample")); analyze(makeSample()); });
// Real demo images in demo/ (see demo/README.md for where they come from).
for (const b of document.querySelectorAll("button.demo")) {
  b.addEventListener("click", async () => {
    if (running) return;
    markDemo(b);
    const blob = await (await fetch(new URL(b.dataset.src, import.meta.url))).blob();
    analyze(new File([blob], b.dataset.src.split("/").pop(), { type: blob.type }));
  });
}
$("stop").addEventListener("click", () => {
  stopped = true;
  $("stop").hidden = true;
  bar(null, "Stopping…");
  call("stop");
});

// If the models are already stored on this device, load them in the
// background so the first analysis doesn't wait for them. Nothing is
// downloaded here: only stored models are warmed up.
async function warmUp() {
  for (const m of ["florence", "qwen"]) {
    if (running) return; // an analysis loads what it needs itself
    if (!storedModels.has(m)) continue;
    if (m === "florence" && !$("use-ocr").checked) continue;
    if (m === "qwen" && (!$("use-vlm").checked || $("use-vlm").disabled)) continue;
    if (!caps?.keepBoth && m === "qwen") continue;
    $("caps").dataset.base ??= $("caps").textContent;
    $("caps").textContent = `${$("caps").dataset.base} Getting ${MODEL_NAMES[m]} ready…`;
    try { await call("preload", { name: m }); } catch {}
  }
  if ($("caps").dataset.base) $("caps").textContent = `${$("caps").dataset.base} Models ready.`;
}

(async () => {
  try {
    caps = await call("caps");
    if (caps.device === "webgpu") {
      $("caps").textContent = caps.f16
        ? "Your browser supports WebGPU, so the models run on your graphics chip."
        : "WebGPU is available without 16-bit support; AI interpretation will be slower and download a little more.";
      $("use-vlm").checked = true;
    } else {
      $("caps").textContent = "No WebGPU in this browser: text reading runs on the CPU (slower) and AI interpretation is unavailable. Try Chrome, Edge or Safari 26+.";
      $("use-vlm").disabled = true;
      $("ocr-size").textContent = "about 280 MB";
    }
  } catch (err) {
    $("caps").textContent = `Couldn't start the model worker: ${err.message ?? err}`;
  }
  await showStorage();
  warmUp();
})();
