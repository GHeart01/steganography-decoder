// File-container analysis: metadata, provenance (C2PA), comments, unknown
// chunks and data appended after the end of the image. Works on raw bytes
// with no DOM, so it runs in Node tests too.

const latin1 = (b, s = 0, e = b.length) => {
  let out = "";
  for (let i = s; i < e && i < b.length; i++) out += String.fromCharCode(b[i]);
  return out;
};
const utf8 = (b) => new TextDecoder("utf-8", { fatal: false }).decode(b);
const u16be = (b, i) => (b[i] << 8) | b[i + 1];
const u32be = (b, i) => ((b[i] << 24) | (b[i + 1] << 16) | (b[i + 2] << 8) | b[i + 3]) >>> 0;
const u32le = (b, i) => (b[i] | (b[i + 1] << 8) | (b[i + 2] << 16) | (b[i + 3] << 24)) >>> 0;

const SIGNATURES = [
  [[0x50, 0x4b, 0x03, 0x04], "ZIP archive (or .docx/.apk/.jar)"],
  [[0x25, 0x50, 0x44, 0x46], "PDF document"],
  [[0x89, 0x50, 0x4e, 0x47], "PNG image"],
  [[0xff, 0xd8, 0xff], "JPEG image"],
  [[0x47, 0x49, 0x46, 0x38], "GIF image"],
  [[0x37, 0x7a, 0xbc, 0xaf], "7-Zip archive"],
  [[0x52, 0x61, 0x72, 0x21], "RAR archive"],
  [[0x1f, 0x8b], "gzip data"],
  [[0x7f, 0x45, 0x4c, 0x46], "Linux executable (ELF)"],
  [[0x4d, 0x5a], "Windows executable (MZ)"],
];

export function sniff(bytes, at = 0) {
  for (const [sig, label] of SIGNATURES) {
    if (sig.every((v, i) => bytes[at + i] === v)) return label;
  }
  return null;
}

export function detectFormat(bytes) {
  if (bytes[0] === 0x89 && latin1(bytes, 1, 4) === "PNG") return "png";
  if (bytes[0] === 0xff && bytes[1] === 0xd8) return "jpeg";
  if (latin1(bytes, 0, 4) === "RIFF" && latin1(bytes, 8, 12) === "WEBP") return "webp";
  if (latin1(bytes, 0, 4) === "GIF8") return "gif";
  if (latin1(bytes, 0, 2) === "BM") return "bmp";
  return "unknown";
}

function strings(bytes, min = 6, limit = 20) {
  const out = [];
  let cur = "";
  for (let i = 0; i < bytes.length && out.length < limit; i++) {
    const b = bytes[i];
    if (b >= 0x20 && b < 0x7f) cur += String.fromCharCode(b);
    else { if (cur.length >= min) out.push(cur); cur = ""; }
  }
  if (cur.length >= min && out.length < limit) out.push(cur);
  return out;
}

function describeTrailing(bytes, start) {
  const tail = bytes.subarray(start);
  // Ignore a few bytes of padding (zeros / newlines), which some tools add.
  if (tail.length <= 16 && tail.every((b) => b === 0 || b === 0x0a || b === 0x0d)) return null;
  let embedded = sniff(tail);
  if (!embedded) {
    for (let i = 1; i < Math.min(tail.length, 64); i++) { embedded = sniff(tail, i); if (embedded) break; }
  }
  return { offset: start, length: tail.length, embedded, strings: strings(tail, 6, 12) };
}

// ---------------------------------------------------------------------------
// EXIF (TIFF) — just the human-readable tags people care about.

const EXIF_TAGS = {
  0x010e: "Description", 0x010f: "Camera make", 0x0110: "Camera model", 0x0131: "Software",
  0x0132: "Date", 0x013b: "Artist", 0x8298: "Copyright", 0x9003: "Taken", 0x9286: "User comment",
  0xa430: "Owner", 0xa431: "Body serial", 0xa434: "Lens",
};

function parseExif(b) {
  const out = {};
  if (b.length < 8) return out;
  const le = b[0] === 0x49;
  const r16 = (i) => (le ? b[i] | (b[i + 1] << 8) : u16be(b, i));
  const r32 = (i) => (le ? u32le(b, i) : u32be(b, i));
  const seen = new Set();
  const readIfd = (off) => {
    if (!off || off + 2 > b.length || seen.has(off)) return;
    seen.add(off);
    const count = r16(off);
    for (let k = 0; k < count; k++) {
      const e = off + 2 + k * 12;
      if (e + 12 > b.length) break;
      const tag = r16(e), type = r16(e + 2), n = r32(e + 4);
      if (tag === 0x8769) { readIfd(r32(e + 8)); continue; } // Exif sub-IFD
      if (tag === 0x8825) { out["GPS location"] = "present"; continue; }
      const name = EXIF_TAGS[tag];
      if (!name) continue;
      if (type === 2 || type === 7) { // ASCII / UNDEFINED
        const start = n <= 4 ? e + 8 : r32(e + 8);
        if (start + n > b.length) continue;
        let raw = b.subarray(start, start + n);
        if (tag === 0x9286 && n > 8) raw = raw.subarray(8); // skip charset header
        const v = utf8(raw).replace(/\0+$/, "").trim();
        if (v) out[name] = v;
      }
    }
  };
  readIfd(r32(4));
  return out;
}

// XMP is XML; pull out the handful of fields that matter.
function summarizeXmp(xml) {
  const pick = (re) => (xml.match(re) || [])[1];
  const out = {};
  const tool = pick(/xmp:CreatorTool[=>"']+([^"'<]+)/);
  const creator = pick(/<dc:creator>[\s\S]*?<rdf:li[^>]*>([^<]+)/);
  const rights = pick(/<dc:rights>[\s\S]*?<rdf:li[^>]*>([^<]+)/);
  const desc = pick(/<dc:description>[\s\S]*?<rdf:li[^>]*>([^<]+)/);
  if (tool) out["Creator tool"] = tool;
  if (creator) out["Creator"] = creator;
  if (rights) out["Rights"] = rights;
  if (desc) out["Description"] = desc;
  if (/DigitalSourceType[^>]*trainedAlgorithmicMedia|trainedAlgorithmicMedia/.test(xml)) out["AI-generated"] = "declared (IPTC trainedAlgorithmicMedia)";
  if (/photoshop:History|xmpMM:History/.test(xml)) out["Edit history"] = "present";
  return out;
}

async function inflate(bytes) {
  try {
    const ds = new DecompressionStream("deflate");
    const buf = await new Response(new Blob([bytes]).stream().pipeThrough(ds)).arrayBuffer();
    return new Uint8Array(buf);
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// C2PA content credentials. The manifest is CBOR inside JUMBF boxes; instead
// of a full parser, find known keys and read the CBOR text that follows.
// The signature is NOT verified here.

function cborText(b, i) {
  const h = b[i];
  let len, start;
  if (h >= 0x60 && h <= 0x77) { len = h - 0x60; start = i + 1; }
  else if (h === 0x78) { len = b[i + 1]; start = i + 2; }
  else if (h === 0x79) { len = u16be(b, i + 1); start = i + 3; }
  else return null;
  if (start + len > b.length) return null;
  return utf8(b.subarray(start, start + len));
}

function* keyPositions(b, key) {
  const k = new TextEncoder().encode(key);
  const header = k.length < 24 ? [0x60 + k.length] : [0x78, k.length];
  const pat = [...header, ...k];
  outer: for (let i = 0; i + pat.length <= b.length; i++) {
    for (let j = 0; j < pat.length; j++) if (b[i + j] !== pat[j]) continue outer;
    yield i + pat.length; // position of the value
  }
}

// Text value of `key`, or of a "name" key shortly after it (for values that
// are maps such as softwareAgent or claim_generator_info).
function valuesOf(b, key) {
  const out = [];
  for (const at of keyPositions(b, key)) {
    let v = cborText(b, at);
    if (v === null) {
      const window = b.subarray(at, Math.min(b.length, at + 64));
      for (const nameAt of keyPositions(window, "name")) { v = cborText(window, nameAt); break; }
    }
    if (v) out.push(v);
  }
  return [...new Set(out)];
}

const SOURCE_TYPES = {
  trainedAlgorithmicMedia: "AI-generated",
  compositeWithTrainedAlgorithmicMedia: "edited or combined with AI",
  algorithmicallyEnhanced: "algorithmically enhanced",
  algorithmicMedia: "computer-generated (not AI)",
  digitalCapture: "camera capture",
  computationalCapture: "camera capture with computational processing",
  digitalArt: "digital art",
  composite: "composite of several images",
  screenCapture: "screenshot",
};

const ACTIONS = {
  created: "created",
  opened: "opened",
  edited: "edited",
  converted: "converted to another format",
  color_adjustments: "colour adjusted",
  cropped: "cropped",
  resized: "resized",
  placed: "combined with another image",
  watermarked: "invisible watermark added",
  "watermarked.bound": "invisible watermark added",
  "watermarked.unbound": "invisible watermark added",
};

export function readC2pa(chunks) {
  if (!chunks.length) return null;
  const total = chunks.reduce((n, c) => n + c.length, 0);
  const b = new Uint8Array(total);
  let o = 0;
  for (const c of chunks) { b.set(c, o); o += c.length; }
  const generators = [...valuesOf(b, "claim_generator"), ...valuesOf(b, "claim_generator_info")];
  const sources = valuesOf(b, "digitalSourceType").map((u) => u.split("/").pop());
  const actions = valuesOf(b, "action").filter((a) => a.startsWith("c2pa.")).map((a) => a.slice(5));
  const agents = valuesOf(b, "softwareAgent");
  const ai = sources.some((t) => t === "trainedAlgorithmicMedia" || t === "compositeWithTrainedAlgorithmicMedia");
  return {
    generators: [...new Set(generators)].slice(0, 4),
    sources: [...new Set(sources)],
    sourceLabels: [...new Set(sources.map((t) => SOURCE_TYPES[t] ?? t))],
    actions: [...new Set(actions)],
    agents: agents.slice(0, 4),
    ai,
  };
}

// ---------------------------------------------------------------------------
// PNG

const PNG_KNOWN = new Set(["IHDR", "PLTE", "IDAT", "IEND", "tRNS", "cHRM", "gAMA", "iCCP", "sBIT", "sRGB", "cICP", "mDCv",
  "cLLi", "tEXt", "zTXt", "iTXt", "bKGD", "hIST", "pHYs", "sPLT", "eXIf", "tIME", "acTL", "fcTL", "fdAT", "caBX"]);

async function parsePng(b, r) {
  let i = 8;
  while (i + 8 <= b.length) {
    const len = u32be(b, i), type = latin1(b, i + 4, i + 8);
    const data = b.subarray(i + 8, i + 8 + len);
    r.structure.push(`${type} (${len} B)`);
    if (type === "tEXt") {
      const z = data.indexOf(0);
      r.text.push({ key: latin1(data, 0, z), value: latin1(data, z + 1) });
    } else if (type === "zTXt") {
      const z = data.indexOf(0);
      const inflated = await inflate(data.subarray(z + 2));
      r.text.push({ key: latin1(data, 0, z), value: inflated ? latin1(inflated) : "(compressed, could not read)" });
    } else if (type === "iTXt") {
      const z = data.indexOf(0);
      const compressed = data[z + 1] === 1;
      let p = z + 3;
      p = data.indexOf(0, p) + 1; // language tag
      p = data.indexOf(0, p) + 1; // translated keyword
      let body = data.subarray(p);
      if (compressed) body = (await inflate(body)) ?? new Uint8Array();
      const key = latin1(data, 0, z), value = utf8(body);
      if (key === "XML:com.adobe.xmp") Object.assign(r.fields, summarizeXmp(value));
      else r.text.push({ key, value });
    } else if (type === "eXIf") {
      Object.assign(r.fields, parseExif(data));
    } else if (type === "caBX") {
      r.provenance = "C2PA content credentials present";
      r.c2paChunks.push(data);
    } else if (type === "iDOT") {
      r.fields["Saved by"] = "macOS (Apple iDOT block, typical of screenshots)";
    } else if (!PNG_KNOWN.has(type)) {
      r.unknownChunks.push({ type, length: len, strings: strings(data, 6, 5) });
    }
    i += 12 + len;
    if (type === "IEND") { if (i < b.length) r.trailing = describeTrailing(b, i); break; }
  }
}

// ---------------------------------------------------------------------------
// JPEG

async function parseJpeg(b, r) {
  let i = 2;
  const segment = () => {
    const marker = b[i + 1], len = u16be(b, i + 2);
    const data = b.subarray(i + 4, i + 2 + len);
    return { marker, len, data };
  };
  while (i + 4 <= b.length) {
    if (b[i] !== 0xff) { i++; continue; }
    const marker = b[i + 1];
    if (marker === 0xd9) { // EOI
      if (i + 2 < b.length) r.trailing = describeTrailing(b, i + 2);
      return;
    }
    if (marker === 0xff || (marker >= 0xd0 && marker <= 0xd7) || marker === 0x01) { i += marker === 0xff ? 1 : 2; continue; }
    const { len, data } = segment();
    const name = marker >= 0xe0 && marker <= 0xef ? `APP${marker - 0xe0}` : marker === 0xfe ? "COM" : `FF${marker.toString(16).toUpperCase()}`;
    r.structure.push(`${name} (${len} B)`);
    if (marker === 0xe1 && latin1(data, 0, 6) === "Exif\0\0") Object.assign(r.fields, parseExif(data.subarray(6)));
    else if (marker === 0xe1 && latin1(data, 0, 28) === "http://ns.adobe.com/xap/1.0/") Object.assign(r.fields, summarizeXmp(utf8(data)));
    else if (marker === 0xeb && latin1(data, 0, 2) === "JP") {
      r.provenance = "C2PA content credentials present (JUMBF)";
      r.c2paChunks.push(data);
    }
    else if (marker === 0xfe) r.text.push({ key: "Comment", value: utf8(data) });
    else if (marker >= 0xe0 && marker <= 0xef && ![0xe0, 0xe1, 0xe2, 0xed, 0xee, 0xeb].includes(marker)) {
      r.unknownChunks.push({ type: name, length: len, strings: strings(data, 6, 5) });
    }
    i += 2 + len;
    if (marker === 0xda) {
      // Entropy-coded scan: skip until the next real marker.
      while (i + 1 < b.length) {
        if (b[i] === 0xff && b[i + 1] !== 0x00 && !(b[i + 1] >= 0xd0 && b[i + 1] <= 0xd7)) break;
        i++;
      }
    }
  }
}

// ---------------------------------------------------------------------------
// WebP (RIFF)

function parseWebp(b, r) {
  const riffEnd = 8 + u32le(b, 4);
  let i = 12;
  while (i + 8 <= Math.min(riffEnd, b.length)) {
    const type = latin1(b, i, i + 4), len = u32le(b, i + 4);
    const data = b.subarray(i + 8, i + 8 + len);
    r.structure.push(`${type.trim()} (${len} B)`);
    if (type === "C2PA") { r.provenance = "C2PA content credentials present"; r.c2paChunks.push(data); }
    else if (type === "EXIF") Object.assign(r.fields, parseExif(latin1(data, 0, 6) === "Exif\0\0" ? data.subarray(6) : data));
    else if (type === "XMP ") Object.assign(r.fields, summarizeXmp(utf8(data)));
    else if (!["VP8 ", "VP8L", "VP8X", "ALPH", "ANIM", "ANMF", "ICCP", "C2PA"].includes(type)) {
      r.unknownChunks.push({ type: type.trim(), length: len, strings: strings(data, 6, 5) });
    }
    i += 8 + len + (len & 1);
  }
  if (riffEnd < b.length) r.trailing = describeTrailing(b, riffEnd);
}

// ---------------------------------------------------------------------------

export async function analyzeContainer(bytes) {
  const format = detectFormat(bytes);
  const r = { format, structure: [], fields: {}, text: [], unknownChunks: [], provenance: null, trailing: null, c2paChunks: [] };
  try {
    if (format === "png") await parsePng(bytes, r);
    else if (format === "jpeg") await parseJpeg(bytes, r);
    else if (format === "webp") parseWebp(bytes, r);
  } catch (err) {
    r.error = String(err?.message ?? err);
  }

  const findings = [];
  if (r.trailing) {
    findings.push({
      severity: "high",
      title: r.trailing.embedded ? `A ${r.trailing.embedded} is appended after the image` : "Extra data hidden after the end of the image",
      detail: `${r.trailing.length.toLocaleString()} bytes start at byte ${r.trailing.offset.toLocaleString()}. Image viewers ignore them.`,
      text: r.trailing.strings.length ? r.trailing.strings.join("\n") : undefined,
    });
  }
  for (const c of r.unknownChunks) {
    findings.push({
      severity: "medium",
      title: `Non-standard ${c.type} block in the file`,
      detail: `${c.length} bytes that standard viewers don't use.`,
      text: c.strings.length ? c.strings.join("\n") : undefined,
    });
  }
  // PNG/JPEG text fields: AI-generation settings, ordinary metadata copied
  // in by converters (ImageMagick writes dozens of exif:* fields), and the
  // rest, which may be a message.
  const STANDARD = /^(date:|exif:|icc:|xmp:|png:|tiff:|photoshop:|8bim:|jpeg:)|^(Software|Creation Time|Author|Title|Copyright|Source|Description|Disclaimer|Warning|XML:com\.adobe\.xmp)$/i;
  let standard = 0;
  for (const t of r.text) {
    const v = t.value ?? "";
    if (t.key === "parameters" && /Steps:\s*\d+/.test(v)) {
      findings.push({ severity: "medium", title: "Stable Diffusion generation prompt and settings are embedded", text: v.slice(0, 2000) });
    } else if ((t.key === "prompt" || t.key === "workflow") && /class_type|"nodes"/.test(v)) {
      findings.push({ severity: "medium", title: `ComfyUI ${t.key} is embedded (the image was generated with AI)`, text: v.slice(0, 600) });
    } else if (STANDARD.test(t.key)) {
      standard++;
    } else {
      findings.push({ severity: "low", title: `Embedded text: ${t.key || "(no key)"}`, text: v.slice(0, 2000) });
    }
  }
  if (standard) findings.push({ severity: "info", title: `${standard} ordinary metadata field${standard === 1 ? "" : "s"} stored as text`, detail: "Camera, date or colour-profile details copied in by the software that saved the file." });
  r.c2pa = readC2pa(r.c2paChunks);
  delete r.c2paChunks;
  if (r.c2pa) {
    const c = r.c2pa;
    const made = [...c.agents, ...c.generators].filter((v, i, a) => a.indexOf(v) === i);
    const parts = [];
    if (c.sourceLabels.length) parts.push(`Declared source: ${c.sourceLabels.join(", ")}.`);
    if (made.length) parts.push(`Made or signed with: ${made.join("; ")}.`);
    if (c.actions.length) parts.push(`Recorded steps: ${[...new Set(c.actions.map((a) => ACTIONS[a] ?? a))].join(", ")}.`);
    parts.push("The signature isn't checked here; verify it at contentcredentials.org/verify.");
    findings.push({
      severity: c.ai ? "medium" : "info",
      title: c.ai ? "Content credentials say this image was made with AI" : "Content credentials (C2PA) present",
      detail: parts.join(" "),
    });
    if (c.sourceLabels.length) r.fields["Declared source (C2PA)"] = c.sourceLabels.join(", ");
    if (made.length) r.fields["Made with (C2PA)"] = made.join("; ");
    if (c.actions.some((a) => a.startsWith("watermarked"))) {
      findings.push({
        severity: "medium",
        title: "Content credentials record an invisible watermark",
        detail: "The maker says it embedded a watermark that can't be seen. This tool can't decode those (they need the maker's detector), but its spectrum and lowest-bit checks may show traces.",
      });
    }
  } else if (r.provenance) {
    findings.push({ severity: "info", title: r.provenance, detail: "The file carries signed provenance data (who made or edited it)." });
  }
  if (r.fields["AI-generated"]) findings.push({ severity: "info", title: "Metadata says the image is AI-generated" });
  if (r.fields["GPS location"]) findings.push({ severity: "info", title: "Metadata includes a GPS location" });
  r.findings = findings;
  return r;
}
