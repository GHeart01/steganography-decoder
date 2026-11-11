import { decodeImage } from "./lib/decode.js";
import { analyzeContainer } from "./lib/metadata.js";
import { analyzeLsb, analyzeSpectrum, analyzeColor, scalingAttackCheck, lsbPlaneView, fitSize, faintMarks, faintStrip } from "./lib/forensics.js";
import { makeViews, VIEW_INFO } from "./lib/views.js";
import { makeTiles, mergeOcr, ocrFindings, buildVlmInputs, buildPrompt, cornerCrops, cornerMarks, cornerMarkFindings } from "./lib/pipeline.js";
import { cacheStatus, clearCache } from "./lib/opfs-cache.js";
import { makeSample, drawSamplePreview } from "./lib/sample.js";
import {
  extractBits, capacity, fileTypeAt, carveFile, looksLikeText, printableRun, asLatin1, decodeLayers,
  bitPlaneView, colourMapView, hexDump, describeCfg, cfgCode, normalizeCfg, scanConfigs, CHANNEL_SETS, hitPayload,
} from "./lib/stego.js";

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
  readyModels.clear();
  $("storage-text").textContent = "Downloaded models removed from this device.";
  if (caps?.device === "webgpu") setStatus("ready", "WebGPU ready", { idle: true });
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
  if (fraction !== null) $("bar").style.transform = `scaleX(${Math.max(0, Math.min(1, fraction)).toFixed(4)})`;
  $("bar-text").textContent = text ?? "";
}

// Status pill in the top bar: idle | busy | ready | warn.
let idleStatus = ["idle", "Ready"];
function setStatus(kind, text, { idle = false } = {}) {
  if (idle) idleStatus = [kind, text];
  $("status").dataset.kind = kind;
  $("status-text").textContent = text;
}

// One progress state that every source feeds, so the bar doesn't flicker
// between Florence-2 loading, Qwen loading in the background and OCR.
const loads = new Map(); // model -> { loaded, total }
let ocrProgress = null;  // { done, total } while text is being read
let phaseText = "";      // what the current step is doing, when nothing is loading
let vlmActive = false;   // the interpretation step has started
const readyModels = new Set();
const WRITING = "Qwen3-VL-2B is writing its steganalysis…";
const mb = (b) => Math.round(b / 1e6).toLocaleString();

function loadText(m, l) {
  const where = storedModels.has(m) ? "Loading" : "Downloading";
  const bytes = l.total ? ` ${mb(l.loaded)} / ${mb(l.total)} MB` : "";
  const first = storedModels.has(m) ? "" : " (only the first time)";
  return `${where} ${MODEL_NAMES[m]}…${bytes}${first}`;
}

function renderProgress() {
  if (!running) return; // warm-up on page load reports in the caps line instead
  // OCR is the main bar once it has started; before that, a model that is
  // still loading (and that OCR is waiting for) is.
  if (ocrProgress && (ocrProgress.done > 0 || (readyModels.has("florence") && !loads.size))) {
    const bg = [...loads].map(([m, l]) => `${MODEL_NAMES[m]} is ${storedModels.has(m) ? "loading" : "downloading"} in the background${l.total ? ` (${Math.round((l.loaded / l.total) * 100)}%)` : ""}`);
    bar(ocrProgress.done / ocrProgress.total, [`Reading text: part ${ocrProgress.done} of ${ocrProgress.total}`, ...bg].join(" · "));
  } else if (loads.size) {
    let loaded = 0, total = 0;
    for (const l of loads.values()) { loaded += l.loaded; total += l.total; }
    bar(total ? loaded / total : 0, [...loads].map(([m, l]) => loadText(m, l)).join(" · "));
  } else if (ocrProgress) {
    bar(0, `Getting ${MODEL_NAMES.florence} ready…`); // about to report loading
  } else {
    bar(null, phaseText);
  }
}

window.__timings = [];
listeners.add((m) => {
  if (m.type === "timing") { window.__timings.push(m); console.debug("timing", m); }
  if (m.type === "file" && fileUrls[m.model]) fileUrls[m.model].add(`https://huggingface.co/${m.repo}/resolve/main/${m.file}`);
  if (m.type === "status" && m.status === "loading") { loads.set(m.model, { loaded: 0, total: 0 }); renderProgress(); }
  if (m.type === "progress" && loads.has(m.model)) { loads.set(m.model, { loaded: m.loaded, total: m.total }); renderProgress(); }
  if (m.type === "status" && m.status === "unloaded") readyModels.delete(m.model);
  if (m.type === "status" && m.status === "ready") {
    readyModels.add(m.model);
    if (m.model === "qwen" && vlmActive) phaseText = WRITING;
    loads.delete(m.model);
    writeManifest(m.model);
    navigator.storage?.persist?.().catch(() => {});
    renderProgress();
  }
  if (m.type === "tile") { ocrProgress = { done: m.done, total: m.total }; renderProgress(); }
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
  $("findings").replaceChildren(...sorted.map((f, i) => {
    const li = el("li", `finding ${f.severity}`);
    li.style.setProperty("--i", Math.min(i, 8));
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


// Lay out the report: the five headings as headings, everything else as
// bullets. The model sometimes writes "- Verdict: text" on one line.
const AI_HEADINGS = ["Verdict", "Recovered payloads", "Hiding technique", "What it means", "Next steps"];
function renderAi(text) {
  const box = $("ai");
  box.replaceChildren();
  box.dataset.raw = text;
  for (let line of text.split("\n")) {
    line = line.trim();
    if (!line) continue;
    const bare = line.replace(/^[-*•]\s*/, "").replace(/^\d\.\s*/, "").replace(/^\*\*|\*\*$/g, "");
    const h = AI_HEADINGS.find((x) => bare.toLowerCase().startsWith(x.toLowerCase()));
    if (h) {
      box.append(el("p", "ai-h", h));
      const rest = bare.slice(h.length).replace(/^[\s:*–-]+/, "");
      if (rest) box.append(el("p", "ai-b", rest));
    } else {
      box.append(el("p", "ai-b", line.replace(/^[-*•]\s*/, "")));
    }
  }
}

let state = null;

function renderView(name) {
  const v = state.viewList.find((x) => x.key === name);
  for (const b of $("tabs").children) b.setAttribute("aria-selected", String(b.dataset.key === name));
  $("view-info").textContent = v.info;
  const canvas = $("view");
  toCanvas(v.img, canvas);
  canvas.classList.toggle("pixelated", name === "lsb" || name === "nearest" || name === "colours");
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
    for (const m of state.faint ?? []) {
      const r = document.createElementNS("http://www.w3.org/2000/svg", "rect");
      r.setAttribute("x", m.box.x0 - 4); r.setAttribute("y", m.box.y0 - 4);
      r.setAttribute("width", m.box.x1 - m.box.x0 + 8); r.setAttribute("height", m.box.y1 - m.box.y0 + 8);
      r.setAttribute("rx", 4);
      r.setAttribute("class", "faint");
      svg.append(r);
    }
    for (const m of state.marks) {
      const r = document.createElementNS("http://www.w3.org/2000/svg", "rect");
      const pad = 6;
      r.setAttribute("x", m.box.x0 - pad); r.setAttribute("y", m.box.y0 - pad);
      r.setAttribute("width", m.box.x1 - m.box.x0 + 2 * pad); r.setAttribute("height", m.box.y1 - m.box.y0 + 2 * pad);
      r.setAttribute("rx", 6);
      r.setAttribute("class", "mark");
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
  $("texts").closest("table").hidden = state.texts.length === 0;
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
// Decoder: read any bits of any channels, see them, save them.

function saveBytes(bytes, name, type = "application/octet-stream") {
  const url = URL.createObjectURL(new Blob([bytes], { type }));
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}

const kb = (n) => (n < 1024 ? `${n} bytes` : `${(n / 1024).toFixed(n < 10240 ? 1 : 0)} KB`);
let dec = null; // { img, cfg, hits, current }

function segButtons(id, items, isOn, onPick, multi = false) {
  $(id).replaceChildren(...items.map(([value, label]) => {
    const b = el("button", "", label);
    b.type = "button";
    b.setAttribute("role", multi ? "checkbox" : "radio");
    b.setAttribute("aria-checked", String(isOn(value)));
    b.addEventListener("click", () => onPick(value));
    return b;
  }));
}

function renderDecoderControls() {
  const c = dec.cfg;
  const hasAlpha = scanConfigs(dec.img).some((x) => x.channels.includes("A"));
  const sets = CHANNEL_SETS.filter((s) => hasAlpha || !s.includes("A"));
  segButtons("dec-channels", sets.map((s) => [s, s]), (v) => v === c.channels, (v) => setCfg({ channels: v }));
  segButtons("dec-bits", [7, 6, 5, 4, 3, 2, 1, 0].map((b) => [b, String(b)]), (v) => c.bits.includes(v), (v) => {
    const bits = c.bits.includes(v) ? c.bits.filter((x) => x !== v) : [...c.bits, v];
    if (bits.length) setCfg({ bits });
  }, true);
  segButtons("dec-order", [["rows", "Rows"], ["cols", "Columns"]], (v) => v === c.order, (v) => setCfg({ order: v }));
  segButtons("dec-msb", [[true, "High bit first"], [false, "Low bit first"]], (v) => v === c.msbFirst, (v) => setCfg({ msbFirst: v }));
}

function setCfg(change, hitIndex = null) {
  dec.cfg = normalizeCfg({ ...dec.cfg, ...change });
  dec.current = hitIndex;
  renderDecoder();
}

function describeBytes(bytes) {
  const file = fileTypeAt(bytes);
  if (file) return { file, text: `Starts with a ${file.label}.` };
  const run = printableRun(bytes, 0);
  if (run >= 8 && looksLikeText(bytes, 0, run)) {
    const msg = asLatin1(bytes, 0, run);
    const layers = decodeLayers(msg);
    const last = layers.at(-1);
    return { text: last ? `Starts with ${layers.map((l) => l.encoding).join(", then ")} text that decodes to: ${(last.text ?? `a ${last.file.label}`).slice(0, 120)}` : "Starts with readable text." };
  }
  return { text: "No readable text or known file at the start. Untouched bits look like this: noise or the picture's own texture." };
}

function hitSummary(hit) {
  const at = hit.offset ? ` It starts at byte ${hit.offset}${hit.framing ? ` (${hit.framing})` : ""}.` : hit.framing ? ` Framing: ${hit.framing}.` : "";
  if (hit.kind === "file") return `A hidden ${hit.label}.${at}`;
  const last = hit.decoded?.at(-1);
  const chain = hit.decoded?.map((l) => l.encoding).join(", then ");
  return `Hidden text, ${hit.message.length.toLocaleString()} characters.${at}${last ? ` Decoded (${chain}): ${last.file ? `a ${last.file.label}` : `“${last.text.slice(0, 160)}”`}` : ""}`;
}

function renderDecoder() {
  const { img, cfg } = dec;
  for (const [i, li] of [...$("hits").children].entries()) li.setAttribute("aria-current", String(i === dec.current));
  renderDecoderControls();
  toCanvas(bitPlaneView(img, cfg), $("plane"));
  const hit = dec.current != null ? dec.hits[dec.current] : null;
  // Dump from where the hit starts, so the bytes shown are the ones described.
  const start = hit?.offset ?? 0;
  const head = extractBits(img, cfg, start + 512).subarray(start);
  const cap = capacity(img, cfg);
  $("dec-summary").textContent = `${describeCfg(cfg)}. ${hit ? hitSummary(hit) : describeBytes(head).text}`;
  $("dump").textContent = hexDump(head, 32, start);
  $("dec-save-info").textContent = `Up to ${kb(cap)} fit in these bits.`;
}

$("dec-save").addEventListener("click", () => {
  const hit = dec.current != null ? dec.hits[dec.current] : null;
  const name = `hidden-${cfgCode(dec.cfg)}`;
  if (hit) {
    const p = hitPayload(dec.img, hit);
    if (p.kind === "file") {
      saveBytes(p.bytes, `${name}.${p.file.ext}`, p.file.type);
      $("dec-save-info").textContent = p.exact
        ? `Saved the ${p.encoded ? "decoded " : ""}${p.file.label} (${kb(p.bytes.length)}).`
        : `Saved ${kb(p.bytes.length)}: the ${p.file.label}'s end couldn't be found, so trailing bytes are included.`;
    } else {
      saveBytes(p.bytes, `${name}.txt`, "text/plain");
      $("dec-save-info").textContent = `Saved the message as text (${kb(p.bytes.length)}).`;
    }
    return;
  }
  const all = extractBits(dec.img, dec.cfg);
  const file = fileTypeAt(all);
  if (file) {
    const { bytes, exact } = carveFile(all, file);
    saveBytes(bytes, `${name}.${file.ext}`, file.type);
    $("dec-save-info").textContent = exact ? `Saved the ${file.label} (${kb(bytes.length)}).` : `Saved ${kb(bytes.length)}: the ${file.label}'s end couldn't be found, so trailing bytes are included.`;
  } else {
    saveBytes(all, `bits-${cfgCode(dec.cfg)}.bin`);
    $("dec-save-info").textContent = `Saved all ${kb(all.length)}.`;
  }
});

function renderHits(hits, tried) {
  if (!hits.length) {
    $("hits").replaceChildren(el("li", "hint", `The scan tried ${tried} channel and bit orderings and found no readable text or known file.`));
    return;
  }
  $("hits").replaceChildren(...hits.map((h, i) => {
    const li = el("li", "hit");
    li.append(el("span", "hit-title", h.kind === "file" ? `${h.label}` : "Readable text"));
    const b = el("button", "secondary", "Open");
    b.type = "button";
    b.addEventListener("click", () => setCfg(h.cfg, i));
    li.append(b);
    li.append(el("span", "hit-sub", `${h.order}${h.framing ? ` · ${h.framing}` : ""}`));
    if (h.kind === "text") {
      const last = h.decoded?.at(-1);
      li.append(el("span", "hit-text", h.preview + (last ? `\n→ ${h.decoded.map((l) => l.encoding).join(", then ")}: ${last.text ?? last.file.label}` : "")));
    }
    return li;
  }));
}

function setupDecoder(img, lsb) {
  dec = { img, hits: lsb.messages, current: lsb.messages.length ? 0 : null, cfg: normalizeCfg(lsb.messages[0]?.cfg ?? {}) };
  renderHits(lsb.messages, scanConfigs(img).length);
  renderDecoder();
}

let trailing = null;
$("save-trailing").addEventListener("click", () => {
  if (!trailing) return;
  const file = fileTypeAt(trailing);
  const { bytes } = file ? carveFile(trailing, file) : { bytes: trailing };
  saveBytes(bytes, `appended.${file?.ext ?? "bin"}`, file?.type);
});
function setupTrailing(decoded, meta) {
  trailing = meta.trailing ? decoded.bytes.slice(meta.trailing.offset) : null;
  $("trailing-actions").hidden = !trailing;
  if (trailing) {
    const what = fileTypeAt(trailing)?.label ?? meta.trailing.embedded;
    $("trailing-info").textContent = `${kb(trailing.length)} after the end of the image${what ? `, a ${what}` : ""}.`;
  }
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
  setStatus("busy", "Analysing…");
  const useOcr = $("use-ocr").checked;
  const useVlm = $("use-vlm").checked && !$("use-vlm").disabled;
  const S = {
    read: "Read the image",
    file: "Check the file structure",
    pixels: "Check pixels, colours and patterns",
    ocr: "Read text and look for corner logos",
    vlm: "Steganalysis with Qwen3-VL-2B",
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
    const faint = faintMarks(img);
    const strip = faint.marks.length ? faintStrip(faint.view, faint.marks) : null;
    if (faint.marks.length) {
      const c = faint.marks.map((m) => m.contrast);
      findings.push({
        layer: "pixels",
        severity: faint.marks.length >= 2 ? "high" : "medium",
        title: `${faint.marks.length} faint shape${faint.marks.length === 1 ? "" : "s"} hidden in flat colour`,
        detail: `Each is drawn only ${Math.min(...c)}–${Math.max(...c)} shades (summed over R, G and B) off the colour around it, too faint to notice. See the Faint marks view.`,
      });
    }
    mark("pixel checks + views", t);
    step(S.pixels, "done");

    state = {
      width: img.width, height: img.height, texts: [], marks: [], faint: faint.marks, current: faint.marks.length ? "faint" : "normal",
      viewList: [
        { key: "normal", label: "Normal", img: views.normal, info: VIEW_INFO.normal, boxes: true },
        { key: "high", label: "High saturation", img: views.high, info: VIEW_INFO.high, boxes: true },
        { key: "low", label: "Low saturation", img: views.low, info: VIEW_INFO.low, boxes: true },
        ...(faint.marks.length ? [{ key: "faint", label: "Faint marks", img: faint.view, boxes: true,
          info: "Each pixel's difference from the flat colour around it, amplified. Shapes drawn a few shades off their background show up white." }] : []),
        { key: "colours", label: "Random colours", img: colourMapView(img), boxes: true,
          info: "Every distinct colour swapped for a random one. Shades that differ by a single step, invisible normally, become obviously different." },
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
    setupDecoder(img, lsb);
    setupTrailing(decoded, meta);
    $("text-card").hidden = !useOcr;
    $("results").hidden = false;

    if (useOcr) {
      currentStep = S.ocr; step(S.ocr, "active");
      $("stop").hidden = false;
      const tiles = makeTiles(views);
      ocrProgress = { done: 0, total: tiles.length };
      renderProgress();
      const results = await call("florence", { tiles: tiles.map(({ id, image }) => ({ id, image })) });
      ocrProgress = null;
      renderProgress();
      state.texts = mergeOcr(tiles, results);
      findings.push(...ocrFindings(state.texts, img.width, img.height).map((f) => ({ ...f, layer: "ocr" })));
      if (!stopped && strip) {
        phaseText = "Reading the faint shapes…";
        renderProgress();
        const [read] = await call("florence", { tiles: [{ id: "faint", image: strip }] });
        const tokens = (read?.labels ?? []).map((t) => t.replace(/<\/?s>|<pad>/g, "").trim()).filter(Boolean);
        let said = tokens.join(" ");
        if (tokens.length && tokens.join("").replace(/\s+/g, "").length === faint.marks.length) said = tokens.join("").replace(/\s+/g, "");
        if (said) {
          state.faintText = said;
          findings.push({
            layer: "ocr", severity: "high",
            title: `The faint shapes spell “${said}”`,
            detail: "Read from the hidden shapes in reading order (top to bottom, left to right).",
            text: said,
          });
        }
      }
      if (!stopped) {
        phaseText = "Looking for logos in the corners…";
        renderProgress();
        const crops = cornerCrops(img);
        const grounded = await call("regions", {
          images: crops.map((c) => c.image), task: "<CAPTION_TO_PHRASE_GROUNDING>", text: "logo",
        });
        state.marks = cornerMarks(crops, grounded);
        findings.push(...cornerMarkFindings(state.marks, state.texts).map((f) => ({ ...f, layer: "ocr" })));
        phaseText = "";
      }
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
      const { images, captions } = buildVlmInputs(views, state.texts, state.marks, strip, state.viewList.find((v) => v.key === "lsb").img);
      const payloads = [];
      for (const m of lsb.messages) {
        const last = m.decoded?.at(-1);
        if (m.kind === "file") payloads.push({ where: m.order, text: `a ${m.label}` });
        else payloads.push({ where: m.order, text: last ? `${m.preview.slice(0, 60)}… which decodes (${m.decoded.map((l) => l.encoding).join(", then ")}) to: ${last.text ?? `a ${last.file.label}`}` : m.message });
      }
      if (meta.trailing) payloads.push({ where: `data appended after the end of the image${meta.trailing.embedded ? ` (${meta.trailing.embedded})` : ""}`, text: meta.trailing.strings.join(" ") || `${meta.trailing.length} bytes` });
      if (state.faintText) payloads.push({ where: "near-invisible shapes in flat colour, read in order", text: state.faintText });
      const techniques = [];
      for (const m of lsb.messages) techniques.push(`LSB replacement: ${m.kind === "file" ? "a file" : "text"} in ${[...m.cfg.channels].join(",")} bit ${m.cfg.bits.join("+")}, ${m.cfg.order === "cols" ? "by columns" : "by rows"}${m.framing ? `, ${m.framing}` : ""}${m.decoded?.length ? `, ${m.decoded.map((l) => l.encoding).join(" + ")}-encoded` : ""}`);
      if (meta.trailing) techniques.push("a file appended after the image's end marker, which viewers ignore");
      if (findings.some((f) => /look filled|Noise in the lowest bits/.test(f.title))) techniques.push("statistical signs of data in the lowest bits");
      if (findings.some((f) => /^Embedded text|generation prompt/.test(f.title))) techniques.push("text stored in the file's metadata");
      if (state.faint?.length) techniques.push("letters drawn a few shades off a flat background");
      if (state.texts.some((t) => t.enhancedOnly || t.repeated)) techniques.push("a faint or repeated watermark, visible after enhancement");
      if (state.marks?.length) techniques.push("a small logo mark in a corner");
      const stego = { techniques, format: decoded.format.toUpperCase(), lossy: decoded.format === "jpeg" || decoded.format === "webp", tried: scanConfigs(img).length, hits: lsb.messages.length, payloads };
      const { system, prompt } = buildPrompt({ captions, findings, texts: state.texts, color, meta, stego });
      $("ai-images").replaceChildren(...images.map((im) => toCanvas(im)));
      $("ai-prompt").textContent = prompt;
      vlmActive = true;
      // If Qwen still has to load, its loading line shows first and the
      // "writing" line follows once it's ready (no flash of the wrong text).
      if (readyModels.has("qwen")) { phaseText = WRITING; renderProgress(); }
      const res = await call("qwen", { images, system, prompt, maxNewTokens: 450 });
      renderAi(res.text.trim());
      $("ai").dataset.looped = res.looped ? "1" : "";
      step(S.vlm, stopped ? "failed" : "done");
      if (stopped) bar(null, "Stopped. The steganalysis above is incomplete.");
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
    phaseText = "";
    vlmActive = false;
    $("stop").hidden = true;
    running = false;
    setInputs(true);
    setStatus(...idleStatus);
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
  let warmed = false;
  for (const m of ["florence", "qwen"]) {
    if (running) return; // an analysis loads what it needs itself
    if (!storedModels.has(m)) continue;
    if (m === "florence" && !$("use-ocr").checked) continue;
    if (m === "qwen" && (!$("use-vlm").checked || $("use-vlm").disabled)) continue;
    if (!caps?.keepBoth && m === "qwen") continue;
    setStatus("busy", `Loading ${MODEL_NAMES[m]}…`);
    try { await call("preload", { name: m }); warmed = true; } catch {}
  }
  if (warmed && !running) setStatus("ready", "Models ready", { idle: true });
}

(async () => {
  try {
    caps = await call("caps");
    if (caps.device === "webgpu") {
      $("caps").textContent = caps.f16
        ? "Models run on your graphics chip through WebGPU."
        : "WebGPU is available without 16-bit support: AI steganalysis is slower and downloads a little more.";
      $("use-vlm").checked = true;
      setStatus("ready", "WebGPU ready", { idle: true });
    } else {
      $("caps").textContent = "No WebGPU in this browser: text reading runs on the CPU (slower) and AI steganalysis is unavailable. Try Chrome, Edge or Safari 26+.";
      setStatus("warn", "No WebGPU", { idle: true });
      $("use-vlm").disabled = true;
      $("ocr-size").textContent = "about 280 MB";
    }
  } catch (err) {
    $("caps").textContent = `Couldn't start the model worker: ${err.message ?? err}`;
    setStatus("warn", "Worker failed", { idle: true });
  }
  await showStorage();
  warmUp();
})();
