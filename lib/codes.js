// QR codes: in the picture itself, in its saturation views, and in each low
// bit plane, where a hidden QR code is invisible in the normal image. The
// decoder (jsQR) is passed in so this runs in the browser and in Node tests.
import { planeThumb } from "./stego.js";
import { resizeNearest } from "./forensics.js";

// Larger pictures are point-sampled down first. Bit planes get a smaller
// limit: jsQR takes seconds on a full-size plane of noise (every speck looks
// like a possible finder pattern) but a fraction of that at 800 px. A hidden
// QR code with modules of about 3 px or more (in a 1920 px image) still reads.
const MAX_SIDE = 1600;
const MAX_PLANE_SIDE = 800;

function fit(w, h, max) {
  const side = Math.max(w, h);
  return side <= max ? [w, h] : [Math.round((w * max) / side), Math.round((h * max) / side)];
}

function prepare(img, s) {
  if (s.plane) {
    const [w, h] = fit(img.width, img.height, MAX_PLANE_SIDE);
    return planeThumb(img, s.plane.ch, s.plane.bit, w, h);
  }
  const [w, h] = fit(s.img.width, s.img.height, MAX_SIDE);
  return w === s.img.width ? s.img : resizeNearest(s.img, w, h);
}

// Pictures worth checking, cheapest and most likely first.
export function codeSources(img, views = {}) {
  const out = [{ label: "the picture", img }];
  if (views.high) out.push({ label: "the high-saturation view", img: views.high });
  for (const ch of ["R", "G", "B"]) for (const bit of [0, 1]) {
    out.push({ label: `bit ${bit} of ${ch}`, plane: { ch, bit } });
  }
  return out;
}

// Where in a bit plane a QR code could be: 16 px blocks that hold both
// colours in solid runs (a QR code's modules) rather than pixel noise or one
// flat colour, grouped into regions. jsQR then reads only those regions, which
// skips the slow, hopeless search through planes of pure noise.
const BLOCK = 16;
export function qrCandidates(pic) {
  const { width: w, height: h, data } = pic;
  const bw = Math.floor(w / BLOCK), bh = Math.floor(h / BLOCK);
  const flag = new Uint8Array(bw * bh);
  for (let by = 0; by < bh; by++) for (let bx = 0; bx < bw; bx++) {
    let same = 0, pairs = 0, ones = 0;
    for (let y = by * BLOCK; y < (by + 1) * BLOCK; y++) for (let x = bx * BLOCK; x < (bx + 1) * BLOCK; x++) {
      const v = data[(y * w + x) * 4];
      if (v) ones++;
      if (x + 1 < (bx + 1) * BLOCK) { pairs++; if (data[(y * w + x + 1) * 4] === v) same++; }
      if (y + 1 < (by + 1) * BLOCK) { pairs++; if (data[((y + 1) * w + x) * 4] === v) same++; }
    }
    const share = ones / (BLOCK * BLOCK);
    flag[by * bw + bx] = same / pairs > 0.75 && share > 0.08 && share < 0.92 ? 1 : 0;
  }
  const seen = new Uint8Array(bw * bh);
  const crops = [];
  for (let i = 0; i < flag.length; i++) {
    if (!flag[i] || seen[i]) continue;
    let x0 = bw, y0 = bh, x1 = 0, y1 = 0, n = 0;
    const stack = [i];
    seen[i] = 1;
    while (stack.length) {
      const j = stack.pop();
      const x = j % bw, y = (j / bw) | 0;
      n++;
      if (x < x0) x0 = x; if (x > x1) x1 = x; if (y < y0) y0 = y; if (y > y1) y1 = y;
      for (const [dx, dy] of [[1, 0], [-1, 0], [0, 1], [0, -1], [1, 1], [-1, -1], [1, -1], [-1, 1]]) {
        const nx = x + dx, ny = y + dy;
        if (nx < 0 || ny < 0 || nx >= bw || ny >= bh) continue;
        const k = ny * bw + nx;
        if (flag[k] && !seen[k]) { seen[k] = 1; stack.push(k); }
      }
    }
    // A readable code spans at least ~3 blocks each way.
    if (n < 6 || x1 - x0 < 2 || y1 - y0 < 2) continue;
    const m = 2; // margin for the quiet zone and solid module areas
    crops.push({
      x: Math.max(0, (x0 - m) * BLOCK), y: Math.max(0, (y0 - m) * BLOCK),
      x2: Math.min(w, (x1 + 1 + m) * BLOCK), y2: Math.min(h, (y1 + 1 + m) * BLOCK),
    });
  }
  return crops;
}

function cropPic(pic, c) {
  const w = c.x2 - c.x, h = c.y2 - c.y;
  const out = new Uint8ClampedArray(w * h * 4);
  for (let y = 0; y < h; y++) out.set(pic.data.subarray(((c.y + y) * pic.width + c.x) * 4, ((c.y + y) * pic.width + c.x + w) * 4), y * w * 4);
  return { width: w, height: h, data: out };
}

// Returns [{ label, text, box }] for every source that holds a readable code.
// Pass onEach to yield to the page between sources.
export async function findCodes(img, sources, jsQR, onEach = async () => {}) {
  const found = [];
  const seen = new Set();
  for (const s of sources) {
    const pic = prepare(img, s);
    // Pictures are read whole; bit planes only where a code could be.
    const regions = s.plane ? qrCandidates(pic).map((c) => ({ c, pic: cropPic(pic, c) })) : [{ c: { x: 0, y: 0 }, pic }];
    for (const { c, pic: p } of regions) {
      const res = jsQR(new Uint8ClampedArray(p.data.buffer, p.data.byteOffset, p.data.length), p.width, p.height, { inversionAttempts: "attemptBoth" });
      if (!res?.data || seen.has(res.data)) continue;
      seen.add(res.data);
      const sx = img.width / pic.width, sy = img.height / pic.height;
      const corners = [res.location.topLeftCorner, res.location.topRightCorner, res.location.bottomLeftCorner, res.location.bottomRightCorner];
      const xs = corners.map((q) => (q.x + c.x) * sx), ys = corners.map((q) => (q.y + c.y) * sy);
      found.push({ label: s.label, text: res.data, inPlane: !!s.plane, box: { x0: Math.min(...xs), y0: Math.min(...ys), x1: Math.max(...xs), y1: Math.max(...ys) } });
    }
    await onEach();
  }
  return found;
}

export function codeFindings(codes) {
  return codes.map((c) => ({
    severity: c.inPlane ? "high" : "medium",
    payload: c.inPlane,
    title: c.inPlane ? `A QR code is hidden in ${c.label}` : `QR code in ${c.label}`,
    detail: c.inPlane
      ? "Invisible in the normal picture: it only appears when that single bit is shown on its own. Pick that bit in the Decoder to see it."
      : `Found at x=${Math.round(c.box.x0)}, y=${Math.round(c.box.y0)}.`,
    text: c.text,
  }));
}
