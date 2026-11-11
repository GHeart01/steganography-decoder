// Steganography decoder tests: hide data the way real tools do, check it comes
// back out, and check clean images give nothing.
import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import { encode, decode } from "fast-png";
import {
  extractBits, scanLsb, scanConfigs, normalizeCfg, decodeLayers, cleanMessage, carveFile, fileTypeAt,
  bitPlaneView, colourMapView, hexDump, describeCfg, cfgCode, hitPayload,
} from "../lib/stego.js";
import { analyzeLsb } from "../lib/forensics.js";

const W = 200, H = 150;

function rng(seed) {
  return () => { seed = (seed * 1664525 + 1013904223) >>> 0; return seed / 4294967296; };
}
function photo(seed = 7, { alpha = false } = {}) {
  const r = rng(seed);
  const data = new Uint8Array(W * H * 4);
  for (let y = 0; y < H; y++) for (let x = 0; x < W; x++) {
    const o = (y * W + x) * 4;
    const n = () => (r() - 0.5) * 12;
    data[o] = Math.max(0, Math.min(255, 120 + 80 * Math.sin(x / 23) + n()));
    data[o + 1] = Math.max(0, Math.min(255, 100 + 60 * Math.cos(y / 19) + n()));
    data[o + 2] = Math.max(0, Math.min(255, 90 + 50 * Math.sin((x + y) / 31) + n()));
    data[o + 3] = alpha ? 200 + Math.floor(r() * 55) : 255;
  }
  return { width: W, height: H, data };
}

// The inverse of extractBits: write bytes into the chosen bits.
const IDX = { R: 0, G: 1, B: 2, A: 3 };
function embedBits(img, bytes, cfg) {
  const c = normalizeCfg(cfg);
  const out = { ...img, data: img.data.slice() };
  const ch = [...c.channels].map((x) => IDX[x]);
  const rows = c.order !== "cols";
  let k = 0;
  const total = bytes.length * 8;
  for (let a = 0; a < (rows ? H : W) && k < total; a++) for (let b = 0; b < (rows ? W : H) && k < total; b++) {
    const o = (rows ? a * W + b : b * W + a) * 4;
    for (const ci of ch) for (const bit of c.bits) {
      if (k >= total) break;
      const byte = bytes[k >> 3], j = k & 7;
      const x = c.msbFirst ? (byte >> (7 - j)) & 1 : (byte >> j) & 1;
      out.data[o + ci] = (out.data[o + ci] & ~(1 << bit)) | (x << bit);
      k++;
    }
  }
  return out;
}
const text = (s) => new TextEncoder().encode(s);

function loadPng(path) {
  const p = decode(fs.readFileSync(new URL(path, import.meta.url)));
  const n = p.width * p.height, data = new Uint8Array(n * 4);
  for (let i = 0; i < n; i++) {
    for (let c = 0; c < 3; c++) data[i * 4 + c] = p.data[i * p.channels + c];
    data[i * 4 + 3] = p.channels === 4 ? p.data[i * 4 + 3] : 255;
  }
  return { width: p.width, height: p.height, data };
}

test("extractBits reads back what embedBits wrote, for every ordering", () => {
  const msg = text("Round trip check 0123456789");
  for (const cfg of scanConfigs(photo(1, { alpha: true }))) {
    const img = embedBits(photo(1, { alpha: true }), msg, cfg);
    assert.deepEqual([...extractBits(img, cfg, msg.length)], [...msg], describeCfg(cfg));
  }
});

test("real tool: a message hidden by Stegano is recovered without its length prefix", () => {
  const [hit, ...rest] = scanLsb(loadPng("./fixtures/stegano-lsb.png"));
  assert.equal(rest.length, 0);
  assert.equal(hit.message, "Stegano was here: the drop is behind the fountain.");
  assert.match(hit.framing, /Stegano/);
});

test("real tool: a Base64 message hidden by Stegano is decoded", () => {
  const [hit] = scanLsb(loadPng("./fixtures/stegano-base64.png"));
  assert.equal(hit.decoded.at(-1).text, "Encoded twice: look under the bench.");
  const titles = analyzeLsb(loadPng("./fixtures/stegano-base64.png")).findings.map((f) => f.title);
  assert.ok(titles.includes("The hidden text decodes (Base64) to readable text"), titles.join(" | "));
});

test("finds messages in less common orderings", () => {
  const cases = [
    { channels: "B", bits: [1], msbFirst: true, order: "cols" },
    { channels: "BGR", bits: [0], msbFirst: false, order: "rows" },
    { channels: "G", bits: [1, 0], msbFirst: true, order: "rows" },
  ];
  for (const cfg of cases) {
    const secret = `Orderings matter: ${cfgCode(cfg)} works.`;
    const found = scanLsb(embedBits(photo(2), text(secret + "\0"), cfg));
    assert.equal(found.length, 1, describeCfg(cfg));
    assert.equal(found[0].message, secret);
    assert.deepEqual(normalizeCfg(found[0].cfg), normalizeCfg(cfg));
  }
});

test("finds a message in the alpha channel, but only tries alpha when it varies", () => {
  const cfg = { channels: "A", bits: [0] };
  const found = scanLsb(embedBits(photo(3, { alpha: true }), text("Alpha channels hide things too."), cfg));
  assert.equal(found[0]?.message, "Alpha channels hide things too.");
  assert.ok(!scanConfigs(photo(3)).some((c) => c.channels.includes("A")));
});

test("32-bit little-endian length prefix and end delimiters are stripped", () => {
  const body = "Length prefixed note for the decoder.";
  const len = new Uint8Array([body.length, 0, 0, 0]);
  const found = scanLsb(embedBits(photo(4), new Uint8Array([...len, ...text(body), 0, 0]), { channels: "RGB" }));
  assert.equal(found[0].message, body);
  assert.equal(cleanMessage("hello from the other side#####garbage").message, "hello from the other side");
});

test("a PNG hidden in the lowest bits is found and carved to its exact length", () => {
  const tiny = encode({ width: 4, height: 4, data: new Uint8Array(64).fill(200), channels: 4 });
  const cfg = { channels: "RGB", bits: [0] };
  const img = embedBits(photo(5), tiny, cfg);
  const [hit] = scanLsb(img);
  assert.equal(hit.kind, "file");
  assert.equal(hit.label, "PNG image");
  const carved = carveFile(extractBits(img, cfg));
  assert.equal(carved.exact, true);
  assert.equal(carved.bytes.length, tiny.length);
});

test("carving: ZIP ends after its directory record, JPEG after its end marker", () => {
  const zip = new Uint8Array([...text("PK\x03\x04\x14\x00rest"), ...text("PK\x05\x06"), ...new Uint8Array(16), 2, 0, 0x41, 0x42, 9, 9, 9]);
  assert.equal(carveFile(zip).bytes.length, zip.length - 3);
  const jpg = new Uint8Array([0xff, 0xd8, 0xff, 0xe0, 0, 4, 1, 2, 0xff, 0xda, 0, 2, 5, 0xff, 0, 6, 0xff, 0xd9, 7, 7]);
  assert.equal(carveFile(jpg).bytes.length, 18);
});

test("file signatures need their full pattern, so short noise doesn't match", () => {
  assert.equal(fileTypeAt(new Uint8Array([0x1f, 0x8b, 0x00, 0x00, 0x00])), null);
  assert.equal(fileTypeAt(new Uint8Array([0x1f, 0x8b, 0x08, 0x00, 0x00]))?.label, "gzip data");
  assert.equal(fileTypeAt(new Uint8Array([0xff, 0xd8, 0xff, 0x12, 0x00])), null);
});

test("decodeLayers: hex, binary and nested Base64; plain words stay plain", () => {
  const b64 = (s) => Buffer.from(s).toString("base64");
  assert.equal(decodeLayers(Buffer.from("Hex is easy to spot").toString("hex"))[0].text, "Hex is easy to spot");
  assert.equal(decodeLayers([...text("Bits!")].map((b) => b.toString(2).padStart(8, "0")).join(" "))[0].text, "Bits!");
  const nested = decodeLayers(b64(b64("Two layers of Base64 here")));
  assert.deepEqual(nested.map((l) => l.encoding), ["Base64", "Base64"]);
  assert.equal(nested[1].text, "Two layers of Base64 here");
  assert.deepEqual(decodeLayers("Meet at noon by the lighthouse"), []);
  assert.deepEqual(decodeLayers("helloworldhelloworld"), []);
});

test("clean images give no messages in any ordering", () => {
  for (const seed of [11, 12, 13]) assert.deepEqual(scanLsb(photo(seed, { alpha: true })), []);
  const flat = { width: W, height: H, data: new Uint8Array(W * H * 4).fill(255) };
  assert.deepEqual(scanLsb(flat), []);
});

test("bit plane and colour map pictures", () => {
  const img = { width: 2, height: 1, data: new Uint8Array([3, 2, 1, 255, 0, 0, 0, 255]) };
  const lsb = bitPlaneView(img, { channels: "R", bits: [0] });
  assert.deepEqual([...lsb.data.slice(0, 4)], [255, 255, 255, 255]);
  const two = bitPlaneView(img, { channels: "RGB", bits: [1, 0] });
  assert.deepEqual([...two.data.slice(0, 3)], [255, 170, 85]);
  const near = { width: 2, height: 1, data: new Uint8Array([100, 100, 100, 255, 100, 100, 101, 255]) };
  const map = colourMapView(near).data;
  assert.notDeepEqual([...map.slice(0, 3)], [...map.slice(4, 7)]);
  assert.match(hexDump(text("Hi\x00")), /^000000  48 69 00 +Hi·$/);
});

test("a message longer than the scan window is read in full, Stegano prefix stripped", () => {
  const body = "Long message. ".repeat(400).trim(); // ~5.6 KB, past the 4 KB scan window
  const img = embedBits(photo(6), text(`${body.length}:${body}`), { channels: "RGB" });
  const [hit] = scanLsb(img);
  assert.equal(hit.message, body);
  assert.equal(hitPayload(img, hit).text, body);
});

test("length-prefixed text and files: payload starts after the prefix", () => {
  const be = (n) => [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255];
  const note = "Prefixed text payload for checking offsets.";
  const t = embedBits(photo(8), new Uint8Array([...be(note.length), ...text(note), 0x41, 0x42]), { channels: "RGB" });
  const [th] = scanLsb(t);
  assert.equal(th.offset, 4);
  assert.equal(hitPayload(t, th).text, note);

  const tiny = encode({ width: 3, height: 3, data: new Uint8Array(36).fill(90), channels: 4 });
  const f = embedBits(photo(9), new Uint8Array([...be(tiny.length), ...tiny]), { channels: "RGB" });
  const [fh] = scanLsb(f);
  assert.equal(fh.kind, "file");
  assert.equal(fh.offset, 4);
  const p = hitPayload(f, fh);
  assert.deepEqual([...p.bytes], [...tiny]);
});

test("decodeLayers: ROT13 and Caesar ciphers are broken; English and noise are left alone", () => {
  const rot13 = (t) => t.replace(/[a-z]/gi, (c) => { const a = c <= "Z" ? 65 : 97; return String.fromCharCode(((c.charCodeAt(0) - a + 13) % 26) + a); });
  const r = decodeLayers(rot13("The key is under the third stone from the lighthouse."));
  assert.equal(r[0].encoding, "ROT13");
  assert.equal(r[0].text, "The key is under the third stone from the lighthouse.");
  const caesar3 = "Wkh phhwlqj lv dw wkh rog ploo diwhu gdun."; // shift 3
  const c = decodeLayers(caesar3);
  assert.equal(c[0].encoding, "a Caesar shift of 3");
  assert.equal(c[0].text, "The meeting is at the old mill after dark.");
  // Base64 of ROT13 text: two layers.
  const two = decodeLayers(Buffer.from(rot13("Meet me at the north gate at noon")).toString("base64"));
  assert.deepEqual(two.map((l) => l.encoding), ["Base64", "ROT13"]);
  assert.deepEqual(decodeLayers("Meet at noon by the lighthouse"), []);
  assert.deepEqual(decodeLayers("Xq7 Lmp Wrt Bzzk Qqf"), []);
});
