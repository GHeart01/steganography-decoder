// Steganography decoding.
//
// Simple hiding tools (Stegano, most "LSB" scripts and CTF puzzles) write a
// message into chosen bits of chosen colour channels, pixel by pixel.
//  - extractBits() reads those bits back for any combination of channels,
//    bit positions, bit order and pixel order.
//  - scanLsb() tries the combinations common tools use and keeps the ones
//    that give readable text or a known file.
//  - decodeLayers() unwraps Base64, hex and binary text.
//  - carveFile() trims an embedded file to its real end so it can be saved.
//  - bitPlaneView() and colourMapView() make pictures for looking by eye.
//
// Out of reach: tools that scramble with a password (steghide, OutGuess,
// OpenStego with a key) and JPEG coefficient hiding (F5, JSteg).

const IDX = { R: 0, G: 1, B: 2, A: 3 };
export const CHANNEL_SETS = ["RGB", "BGR", "R", "G", "B", "A", "RGBA"];

// ---------------------------------------------------------------------------
// Reading bits

// cfg.bits lists bit positions inside each channel value (0 = lowest). They
// are read from the highest listed bit down, so [1, 0] reads bit 1 then bit 0.
// cfg.msbFirst: the first bit read becomes the byte's high bit.
// cfg.order: "rows" (left to right, top to bottom) or "cols" (top to bottom,
// left to right).
export function normalizeCfg(cfg = {}) {
  return {
    channels: cfg.channels ?? "RGB",
    bits: [...new Set(cfg.bits ?? [0])].sort((a, b) => b - a),
    msbFirst: cfg.msbFirst ?? true,
    order: cfg.order ?? "rows",
  };
}

export function capacity(img, cfg) {
  const c = normalizeCfg(cfg);
  return Math.floor((img.width * img.height * c.channels.length * c.bits.length) / 8);
}

export function extractBits(img, cfg = {}, maxBytes = Infinity) {
  const c = normalizeCfg(cfg);
  const { width: w, height: h, data } = img;
  const n = Math.min(capacity(img, c), maxBytes);
  const out = new Uint8Array(n);
  if (n === 0) return out;
  const ch = [...c.channels].map((x) => IDX[x]);
  const bits = c.bits;
  const rows = c.order !== "cols";
  const outer = rows ? h : w, inner = rows ? w : h;
  let byte = 0, k = 0, idx = 0;
  for (let a = 0; a < outer; a++) {
    for (let b = 0; b < inner; b++) {
      const o = (rows ? a * w + b : b * w + a) * 4;
      for (let ci = 0; ci < ch.length; ci++) {
        const v = data[o + ch[ci]];
        for (let bi = 0; bi < bits.length; bi++) {
          const x = (v >> bits[bi]) & 1;
          byte = c.msbFirst ? (byte << 1) | x : byte | (x << k);
          if (++k === 8) {
            out[idx++] = byte & 0xff;
            byte = 0; k = 0;
            if (idx === n) return out;
          }
        }
      }
    }
  }
  return out;
}

const ORDER_WORDS = { rows: "row by row", cols: "column by column" };
function bitWords(bits) {
  if (bits.length === 1) return bits[0] === 0 ? "lowest bit" : `bit ${bits[0]}`;
  if (bits.length === 2 && bits[0] === 1 && bits[1] === 0) return "two lowest bits";
  return `bits ${bits.join(", ")}`;
}

// "Lowest bit of R, G, B · row by row · high bit first"
export function describeCfg(cfg) {
  const c = normalizeCfg(cfg);
  return `${bitWords(c.bits)[0].toUpperCase()}${bitWords(c.bits).slice(1)} of ${[...c.channels].join(", ")} · ${ORDER_WORDS[c.order]} · ${c.msbFirst ? "high bit first" : "low bit first"}`;
}

// Where in the pixels, for finding titles: "the lowest bits", "bit 1".
export function bitPlaceWords(cfg) {
  const c = normalizeCfg(cfg);
  if (c.bits.length === 1 && c.bits[0] === 0) return "the lowest bits";
  if (c.bits.length === 1) return `bit ${c.bits[0]} of the pixels`;
  return `the ${bitWords(c.bits)}`;
}

// Short code for file names: "rgb-b0-msb-rows".
export function cfgCode(cfg) {
  const c = normalizeCfg(cfg);
  return `${c.channels.toLowerCase()}-b${c.bits.join("")}-${c.msbFirst ? "msb" : "lsb"}-${c.order}`;
}

// ---------------------------------------------------------------------------
// Recognising what came out

const enc = (s) => [...s].map((ch) => ch.charCodeAt(0));
// Signatures are long enough (or checked further) that random bits almost
// never match one: the scan tries dozens of bit orderings.
export const MAGIC = [
  { sig: [0x89, ...enc("PNG\r\n\x1a\n")], label: "PNG image", ext: "png", type: "image/png" },
  { sig: [0xff, 0xd8, 0xff], next: (b) => b === 0xdb || b === 0xc0 || b === 0xc4 || b === 0xfe || (b >= 0xe0 && b <= 0xef), label: "JPEG image", ext: "jpg", type: "image/jpeg" },
  { sig: enc("GIF87a"), label: "GIF image", ext: "gif", type: "image/gif" },
  { sig: enc("GIF89a"), label: "GIF image", ext: "gif", type: "image/gif" },
  { sig: enc("PK\x03\x04"), next: (b) => b <= 63, label: "ZIP archive", ext: "zip", type: "application/zip" },
  { sig: enc("%PDF-"), label: "PDF document", ext: "pdf", type: "application/pdf" },
  { sig: enc("7z\xbc\xaf\x27\x1c"), label: "7-Zip archive", ext: "7z", type: "application/x-7z-compressed" },
  { sig: enc("Rar!\x1a\x07"), label: "RAR archive", ext: "rar", type: "application/vnd.rar" },
  { sig: [0x1f, 0x8b, 0x08], next: (b) => b <= 0x1f, label: "gzip data", ext: "gz", type: "application/gzip" },
  { sig: enc("RIFF"), at8: enc("WEBP"), label: "WebP image", ext: "webp", type: "image/webp" },
  { sig: [0x7f, ...enc("ELF")], label: "Linux program", ext: "elf", type: "application/octet-stream" },
];

export function fileTypeAt(bytes, off = 0) {
  for (const m of MAGIC) {
    if (off + m.sig.length + 1 > bytes.length) continue;
    if (!m.sig.every((b, i) => bytes[off + i] === b)) continue;
    if (m.next && !m.next(bytes[off + m.sig.length])) continue;
    if (m.at8 && !m.at8.every((b, i) => bytes[off + 8 + i] === b)) continue;
    return m;
  }
  return null;
}

function indexOfBytes(bytes, pat, from = 0) {
  outer: for (let i = from; i <= bytes.length - pat.length; i++) {
    for (let j = 0; j < pat.length; j++) if (bytes[i + j] !== pat[j]) continue outer;
    return i;
  }
  return -1;
}
function lastIndexOfBytes(bytes, pat) {
  outer: for (let i = bytes.length - pat.length; i >= 0; i--) {
    for (let j = 0; j < pat.length; j++) if (bytes[i + j] !== pat[j]) continue outer;
    return i;
  }
  return -1;
}

// Walk JPEG segments (so thumbnails inside APP1 don't end it early), then
// scan the compressed data for the end marker.
function jpegEnd(b) {
  let i = 2;
  while (i + 4 <= b.length) {
    if (b[i] !== 0xff) return -1;
    const m = b[i + 1];
    if (m === 0xd9) return i + 2;
    if (m === 0xd8 || (m >= 0xd0 && m <= 0xd7) || m === 0x01 || m === 0xff) { i += m === 0xff ? 1 : 2; continue; }
    const len = (b[i + 2] << 8) | b[i + 3];
    i += 2 + len;
    if (m === 0xda) {
      while (i + 1 < b.length) {
        if (b[i] === 0xff && b[i + 1] !== 0x00 && !(b[i + 1] >= 0xd0 && b[i + 1] <= 0xd7)) break;
        i++;
      }
    }
  }
  return -1;
}

// Cut an embedded file at its real end. exact=false means the format has no
// clear end marker (or it wasn't found) and the whole stream is returned.
export function carveFile(bytes, magic = fileTypeAt(bytes)) {
  let end = -1;
  if (magic?.ext === "png") {
    const i = indexOfBytes(bytes, enc("IEND"));
    if (i >= 0) end = i + 8;
  } else if (magic?.ext === "jpg") {
    end = jpegEnd(bytes);
  } else if (magic?.ext === "zip") {
    const i = indexOfBytes(bytes, enc("PK\x05\x06"));
    if (i >= 0 && i + 22 <= bytes.length) end = i + 22 + (bytes[i + 20] | (bytes[i + 21] << 8));
  } else if (magic?.ext === "pdf") {
    const i = lastIndexOfBytes(bytes, enc("%%EOF"));
    if (i >= 0) end = i + 5;
  } else if (magic?.ext === "webp") {
    end = 8 + ((bytes[4] | (bytes[5] << 8) | (bytes[6] << 16) | (bytes[7] << 24)) >>> 0);
  }
  if (end > 0 && end <= bytes.length) return { bytes: bytes.slice(0, end), exact: true };
  return { bytes, exact: false };
}

export const isPrintable = (b) => (b >= 0x20 && b < 0x7f) || b === 0x0a || b === 0x0d || b === 0x09;

export function printableRun(bytes, start) {
  let i = start;
  while (i < bytes.length && isPrintable(bytes[i])) i++;
  return i - start;
}

// Smooth or dithered areas produce repeating bit patterns ("qwwwqwww…",
// "UUUU…") that happen to be printable. Real text uses many different
// characters and no single one dominates.
export function looksLikeText(bytes, start = 0, len = bytes.length - start) {
  if (len <= 0) return false;
  const counts = new Map();
  for (let i = start; i < start + len; i++) counts.set(bytes[i], (counts.get(bytes[i]) ?? 0) + 1);
  const top = Math.max(...counts.values());
  let letters = 0;
  for (const [b, c] of counts) if ((b >= 65 && b <= 90) || (b >= 97 && b <= 122)) letters += c;
  return counts.size >= Math.min(8, Math.ceil(len / 3)) && top / len < 0.35 && letters / len > 0.5;
}

export function asLatin1(bytes, start = 0, len = bytes.length - start) {
  let s = "";
  for (let i = start; i < start + len && i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return s;
}

// End markers that tutorials and CTF scripts put after the message.
const DELIMITERS = ["#####", "$t3g0", "=====", "[END]", "<END>", "*^*^*"];

// Strip a tool's framing from a recovered message.
export function cleanMessage(text) {
  // Stegano writes "<length>:<message>".
  const m = /^(\d{1,7}):/.exec(text);
  if (m) {
    const len = Number(m[1]);
    const body = text.slice(m[0].length);
    if (len > 0 && len <= body.length) return { message: body.slice(0, len), framing: "length prefix (Stegano style)" };
  }
  for (const d of DELIMITERS) {
    const i = text.indexOf(d);
    if (i > 0) return { message: text.slice(0, i), framing: `ends with “${d}”` };
  }
  return { message: text, framing: null };
}

function bytesFromBinaryString(bin) {
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
const readable = (bytes) => bytes.length >= 4 && bytes.every(isPrintable) && looksLikeText(bytes);

function tryBase64(s) {
  let t = s.replace(/[\r\n]+/g, "").trim();
  if (t.length < 12 || !/^[A-Za-z0-9+/_-]+={0,2}$/.test(t)) return null;
  t = t.replace(/-/g, "+").replace(/_/g, "/");
  if (t.length % 4 === 1) return null;
  while (t.length % 4) t += "=";
  try { return bytesFromBinaryString(atob(t)); } catch { return null; }
}
function tryHex(s) {
  const t = s.replace(/[\s:]+/g, "");
  if (t.length < 16 || t.length % 2 || !/^[0-9a-fA-F]+$/.test(t)) return null;
  const out = new Uint8Array(t.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(t.slice(i * 2, i * 2 + 2), 16);
  return out;
}
function tryBinary(s) {
  const t = s.replace(/\s+/g, "");
  if (t.length < 32 || t.length % 8 || !/^[01]+$/.test(t)) return null;
  const out = new Uint8Array(t.length / 8);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(t.slice(i * 8, i * 8 + 8), 2);
  return out;
}

// Classic CTF ciphers: a Caesar shift (ROT13 is shift 13) is accepted only if
// it turns non-English into text made of common English words.
const COMMON = new Set(("the be to of and a in that have it for not on with he as you do at this but his by from they we say her " +
  "she or an will my one all would there their what so up out if about who get which go me when make can like time no just him " +
  "know take people into year your good some could them see other than then now look only come its over think also back after " +
  "use two how our work first well way even new want because any these give day most us is are was were meet under key find " +
  "hidden secret message here behind left right north south east west door box code password flag").split(" "));
function englishScore(s) {
  const words = s.toLowerCase().match(/[a-z]+/g) ?? [];
  return { words: words.length, score: words.length ? words.filter((w) => COMMON.has(w)).length / words.length : 0 };
}
const shiftText = (s, k) => s.replace(/[a-z]/gi, (c) => {
  const a = c <= "Z" ? 65 : 97;
  return String.fromCharCode(((c.charCodeAt(0) - a + k) % 26) + a);
});
function tryCaesar(s) {
  const base = englishScore(s);
  if (base.words < 3 || base.score >= 0.2) return null;
  let best = null;
  for (let k = 1; k < 26; k++) {
    const t = shiftText(s, k);
    const { score } = englishScore(t);
    if (!best || score > best.score) best = { k, t, score };
  }
  if (best.score < 0.3) return null;
  const n = 26 - best.k; // the shift the hider applied
  return { encoding: n === 13 ? "ROT13" : `a Caesar shift of ${n}`, text: best.t };
}

// Peel off up to three layers of text encoding. Each layer only counts if it
// decodes to readable text (or a known file).
export function decodeLayers(text, depth = 3) {
  const layers = [];
  let cur = text;
  for (let d = 0; d < depth; d++) {
    let hit = null;
    for (const [name, fn] of [["binary", tryBinary], ["hex", tryHex], ["Base64", tryBase64]]) {
      const bytes = fn(cur);
      if (!bytes) continue;
      const file = fileTypeAt(bytes);
      if (file) { layers.push({ encoding: name, file, bytes }); return layers; }
      if (readable(bytes)) { hit = { encoding: name, text: asLatin1(bytes) }; break; }
    }
    hit ??= tryCaesar(cur);
    if (!hit) break;
    layers.push(hit);
    cur = hit.text;
  }
  return layers;
}

// ---------------------------------------------------------------------------
// The scan

function alphaVaries(img) {
  const d = img.data;
  for (let i = 3; i < d.length; i += 4) if (d[i] !== 255) return true;
  return false;
}

// Orderings to try, most common first (duplicates keep the first label).
export function scanConfigs(img) {
  const sets = ["RGB", "BGR", "R", "G", "B", ...(alphaVaries(img) ? ["A", "RGBA"] : [])];
  const out = [];
  for (const order of ["rows", "cols"]) for (const bits of [[0], [1], [1, 0]]) for (const channels of sets) for (const msbFirst of [true, false]) {
    out.push({ channels, bits, msbFirst, order });
  }
  return out;
}

function u32(b, i, le) {
  return le ? ((b[i] | (b[i + 1] << 8) | (b[i + 2] << 16) | (b[i + 3] << 24)) >>> 0)
    : (((b[i] << 24) | (b[i + 1] << 16) | (b[i + 2] << 8) | b[i + 3]) >>> 0);
}

function detect(bytes, cap) {
  const file = fileTypeAt(bytes, 0);
  if (file) return { kind: "file", offset: 0, file };
  const run0 = printableRun(bytes, 0);
  if (run0 >= 12 && looksLikeText(bytes, 0, run0)) return { kind: "text", offset: 0 };
  // 32-bit length prefix (big- or little-endian) followed by the message.
  for (const le of [false, true]) {
    const len = u32(bytes, 0, le);
    if (len < 4 || len > cap) continue;
    const f = fileTypeAt(bytes, 4);
    if (f) return { kind: "file", offset: 4, declared: len, file: f, framing: "32-bit length prefix" };
    const run = printableRun(bytes, 4);
    if (run >= Math.min(len, 12) && run >= 4 && looksLikeText(bytes, 4, Math.min(len, run))) {
      return { kind: "text", offset: 4, declared: len, framing: "32-bit length prefix" };
    }
  }
  // A long readable run anywhere in the first few KB.
  for (let i = 1; i < bytes.length; i++) {
    const run = printableRun(bytes, i);
    if (run >= 24 && looksLikeText(bytes, i, run)) return { kind: "text", offset: i };
    i += run;
  }
  return null;
}

// The message a text hit points at, read from the whole bit stream (the scan
// itself only looks at the first few KB).
function fullText(img, cfg, offset, declared) {
  const all = extractBits(img, cfg);
  const run = printableRun(all, offset);
  return asLatin1(all, offset, declared ? Math.min(declared, run) : run);
}

// The exact bytes a scan hit points at, for showing and saving.
export function hitPayload(img, hit) {
  if (hit.kind === "text") {
    const last = hit.decoded?.at(-1);
    if (last?.file) return { kind: "file", file: last.file, ...carveFile(last.bytes, last.file), encoded: true };
    return { kind: "text", text: hit.message, bytes: new TextEncoder().encode(hit.message) };
  }
  const all = extractBits(img, hit.cfg);
  if (hit.declared) return { kind: "file", file: hit.file, bytes: all.slice(hit.offset, hit.offset + hit.declared), exact: true };
  return { kind: "file", file: hit.file, ...carveFile(all.subarray(hit.offset), hit.file) };
}

export function scanLsb(img, { maxBytes = 4096 } = {}) {
  const found = [];
  const seen = new Set();
  for (const cfg of scanConfigs(img)) {
    const bytes = extractBits(img, cfg, maxBytes);
    if (bytes.length < 16) continue;
    const hit = detect(bytes, capacity(img, cfg));
    if (!hit) continue;
    const base = { cfg, order: describeCfg(cfg), offset: hit.offset, declared: hit.declared };
    if (hit.kind === "file") {
      const key = `file:${hit.file.label}:${hit.offset}:${asLatin1(bytes, hit.offset, 64)}`;
      if (seen.has(key)) continue;
      seen.add(key);
      found.push({ ...base, kind: "file", label: hit.file.label, file: hit.file, framing: hit.framing, preview: hit.file.label });
      continue;
    }
    const { message, framing } = cleanMessage(fullText(img, cfg, hit.offset, hit.declared));
    if (seen.has(message)) continue;
    seen.add(message);
    found.push({
      ...base, kind: "text", length: message.length,
      framing: hit.framing ?? framing,
      preview: message.slice(0, 400),
      message,
      decoded: decodeLayers(message),
    });
  }
  return dropOverlaps(found);
}

// A message in bits 1+0 also leaves every other bit in bit 1 alone, which
// can read as a shorter jumble. Keep only the longer of two overlapping reads.
export function dropOverlaps(found) {
  const overlaps = (a, b) => a.cfg.channels === b.cfg.channels && a.cfg.order === b.cfg.order &&
    a.cfg.msbFirst === b.cfg.msbFirst && a.cfg.bits.some((x) => b.cfg.bits.includes(x)) &&
    Math.abs((a.offset ?? 0) - (b.offset ?? 0)) < 64;
  const size = (m) => m.message?.length ?? Infinity;
  return found.filter((m) => !found.some((o) => o !== m && overlaps(m, o) && size(o) > size(m)));
}

// Signatures long enough to look for at every byte of a whole bit stream
// (millions of positions) without matching noise by chance.
const STRONG = new Set(["png", "gif", "pdf", "7z", "rar", "zip"]);
const STRONG_FIRST = new Set(MAGIC.filter((m) => STRONG.has(m.ext)).map((m) => m.sig[0]));

// The whole-image search for one ordering: readable text or a file starting
// anywhere in the stream, not just in its first few KB. Slower (about 10 ms
// per ordering per megapixel), so it runs on request.
export function deepScanOne(img, cfg, { maxHits = 8 } = {}) {
  const all = extractBits(img, cfg);
  const hits = [];
  const order = describeCfg(cfg);
  for (let i = 0; i < all.length && hits.length < maxHits; i++) {
    if (STRONG_FIRST.has(all[i])) {
      const file = fileTypeAt(all, i);
      if (file && STRONG.has(file.ext)) {
        hits.push({ cfg, order, offset: i, kind: "file", label: file.label, file, preview: file.label });
        continue;
      }
    }
    const run = printableRun(all, i);
    if (run >= 20 && looksLikeText(all, i, run)) {
      const { message, framing } = cleanMessage(asLatin1(all, i, run));
      hits.push({ cfg, order, offset: i, kind: "text", length: message.length, framing, preview: message.slice(0, 400), message, decoded: decodeLayers(message) });
    }
    i += run;
  }
  return hits;
}

export function deepScan(img) {
  const found = [];
  const seen = new Set();
  for (const cfg of scanConfigs(img)) {
    for (const h of deepScanOne(img, cfg)) {
      const key = h.kind === "text" ? h.message : `file:${h.label}:${h.offset}`;
      if (seen.has(key)) continue;
      seen.add(key);
      found.push(h);
    }
  }
  return dropOverlaps(found);
}

// Small point-sampled picture of one bit of one channel, for a grid of all
// bit planes. Point sampling keeps the bit noise as noise; averaging would
// turn it grey.
export function planeThumb(img, channel, bit, tw, th) {
  const { width, height, data } = img;
  const c = IDX[channel];
  const out = new Uint8ClampedArray(tw * th * 4);
  for (let y = 0; y < th; y++) {
    const sy = Math.min(height - 1, Math.floor(((y + 0.5) * height) / th));
    for (let x = 0; x < tw; x++) {
      const sx = Math.min(width - 1, Math.floor(((x + 0.5) * width) / tw));
      const v = ((data[(sy * width + sx) * 4 + c] >> bit) & 1) * 255;
      const o = (y * tw + x) * 4;
      out[o] = out[o + 1] = out[o + 2] = v;
      out[o + 3] = 255;
    }
  }
  return { width: tw, height: th, data: out };
}

// Grid of bit planes: one row per channel, one column per bit, with a gap.
export function planeSheet(img, { channels = ["R", "G", "B"], bits = [0, 1, 2, 3], tile = 240, gap = 6 } = {}) {
  const th = Math.max(1, Math.round((tile * img.height) / img.width));
  const W = bits.length * tile + (bits.length - 1) * gap;
  const H = channels.length * th + (channels.length - 1) * gap;
  const out = new Uint8ClampedArray(W * H * 4).fill(128);
  channels.forEach((ch, r) => bits.forEach((b, col) => {
    const t = planeThumb(img, ch, b, tile, th);
    for (let y = 0; y < th; y++) {
      const o = ((r * (th + gap) + y) * W + col * (tile + gap)) * 4;
      out.set(t.data.subarray(y * tile * 4, (y + 1) * tile * 4), o);
    }
  }));
  return { width: W, height: H, data: out, channels, bits };
}

// ---------------------------------------------------------------------------
// Pictures

// The chosen bits of the chosen channels, stretched to full brightness.
// One channel shows as grey; several show in their own colours.
export function bitPlaneView(img, cfg = {}) {
  const c = normalizeCfg(cfg);
  const { width, height, data } = img;
  // Pack the selected bits together so e.g. bits 1+0 give 0..3.
  const levels = 2 ** c.bits.length - 1;
  const pack = new Uint8Array(256);
  for (let v = 0; v < 256; v++) {
    let x = 0;
    for (const b of c.bits) x = (x << 1) | ((v >> b) & 1);
    pack[v] = Math.round((x / levels) * 255);
  }
  const ch = [...c.channels].map((x) => IDX[x]);
  const colour = ch.filter((i) => i < 3);
  const out = new Uint8ClampedArray(width * height * 4);
  for (let i = 0; i < width * height; i++) {
    const o = i * 4;
    if (ch.length === 1 || colour.length === 0) {
      out[o] = out[o + 1] = out[o + 2] = pack[data[o + ch[0]]];
    } else {
      for (const k of colour) out[o + k] = pack[data[o + k]];
    }
    out[o + 3] = 255;
  }
  return { width, height, data: out };
}

// Every distinct colour gets its own random colour, so shades that differ by
// a single step (invisible normally) become obviously different.
export function colourMapView(img) {
  const { width, height, data } = img;
  const out = new Uint8ClampedArray(width * height * 4);
  for (let i = 0; i < width * height; i++) {
    const o = i * 4;
    let h = (data[o] << 16) | (data[o + 1] << 8) | data[o + 2];
    h = Math.imul(h ^ (h >>> 16), 0x45d9f3b);
    h = Math.imul(h ^ (h >>> 16), 0x45d9f3b);
    h ^= h >>> 16;
    out[o] = h & 255; out[o + 1] = (h >>> 8) & 255; out[o + 2] = (h >>> 16) & 255; out[o + 3] = 255;
  }
  return { width, height, data: out };
}

// Hex + text dump, 16 bytes a line.
export function hexDump(bytes, maxLines = 32, base = 0) {
  const lines = [];
  for (let off = 0; off < bytes.length && lines.length < maxLines; off += 16) {
    const row = bytes.subarray(off, off + 16);
    const hex = [...row].map((b) => b.toString(16).padStart(2, "0")).join(" ").padEnd(47, " ");
    const txt = [...row].map((b) => (b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : "·")).join("");
    lines.push(`${(base + off).toString(16).padStart(6, "0")}  ${hex}  ${txt}`);
  }
  return lines.join("\n");
}
