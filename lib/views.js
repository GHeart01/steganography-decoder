// Enhancement views: the same image with colour pushed one way or the other,
// so faint text, hidden marks and colour patterns stand out. Pure functions
// over RGBA images.

import { resizeArea } from "./forensics.js";

const luma = (r, g, b) => 0.299 * r + 0.587 * g + 0.114 * b;

// Scale saturation around each pixel's luminance (0 = greyscale, 1 = unchanged).
function scaleSaturation(img, factor) {
  const { width, height, data } = img;
  const out = new Uint8ClampedArray(data.length);
  for (let i = 0; i < data.length; i += 4) {
    const r = data[i], g = data[i + 1], b = data[i + 2];
    const l = luma(r, g, b);
    out[i] = l + (r - l) * factor;
    out[i + 1] = l + (g - l) * factor;
    out[i + 2] = l + (b - l) * factor;
    out[i + 3] = 255;
  }
  return { width, height, data: out };
}

// Stretch each channel so its 0.5th–99.5th percentiles span the full range.
function autoContrast(img) {
  const { data } = img;
  const n = data.length / 4;
  for (let c = 0; c < 3; c++) {
    const h = new Uint32Array(256);
    for (let i = c; i < data.length; i += 4) h[data[i]]++;
    let lo = 0, hi = 255, acc = 0;
    for (; lo < 255; lo++) { acc += h[lo]; if (acc > n * 0.005) break; }
    acc = 0;
    for (; hi > 0; hi--) { acc += h[hi]; if (acc > n * 0.005) break; }
    if (hi <= lo) continue;
    const s = 255 / (hi - lo);
    for (let i = c; i < data.length; i += 4) data[i] = (data[i] - lo) * s;
  }
  return img;
}

// Histogram-equalise brightness: subtle shading differences become obvious.
function equalize(img) {
  const { data } = img;
  const n = data.length / 4;
  const h = new Uint32Array(256);
  for (let i = 0; i < data.length; i += 4) h[data[i]]++;
  const lut = new Uint8ClampedArray(256);
  let acc = 0, firstNonZero = 0;
  while (firstNonZero < 255 && !h[firstNonZero]) firstNonZero++;
  const base = h[firstNonZero];
  for (let v = 0; v < 256; v++) {
    acc += h[v];
    lut[v] = n - base > 0 ? ((acc - base) / (n - base)) * 255 : v;
  }
  for (let i = 0; i < data.length; i += 4) {
    const v = lut[data[i]];
    data[i] = data[i + 1] = data[i + 2] = v;
  }
  return img;
}

export const VIEW_INFO = {
  normal: "Normal: the image as it is",
  high: "High saturation: colour differences boosted 3× and contrast stretched. Reveals marks that differ only in hue",
  low: "Low saturation: colour removed and brightness equalised. Reveals faint marks that differ only in shade",
  squint: "Squint: shrunk to a few dozen pixels across and blurred, like squinting. Words or shapes formed by clouds, trees or patterns stand out",
};

export function makeViews(img) {
  return {
    normal: img,
    high: autoContrast(scaleSaturation(img, 3)),
    low: equalize(scaleSaturation(img, 0)),
  };
}

// "Squint" view: the picture shrunk to a few dozen pixels across, blown back
// up smoothly and contrast-stretched. Fine detail disappears and only large
// light and dark shapes remain, which is how people spot words or figures
// formed by clouds, trees or patterns (AI "hidden word" illusion images).
export function squintView(img, { cols = 96, width = 768 } = {}) {
  const sw = Math.max(8, Math.min(cols, img.width));
  const sh = Math.max(4, Math.round((sw * img.height) / img.width));
  const small = resizeArea(img, sw, sh);
  // Brightness only: colour is part of the detail being thrown away.
  const lum = new Float32Array(sw * sh);
  for (let i = 0; i < sw * sh; i++) lum[i] = 0.299 * small.data[i * 4] + 0.587 * small.data[i * 4 + 1] + 0.114 * small.data[i * 4 + 2];
  const W = Math.min(width, img.width * 2), H = Math.max(1, Math.round((W * img.height) / img.width));
  const up = new Float32Array(W * H);
  for (let y = 0; y < H; y++) {
    const fy = Math.min(sh - 1, Math.max(0, ((y + 0.5) * sh) / H - 0.5));
    const y0 = Math.floor(fy), y1 = Math.min(sh - 1, y0 + 1), ty = fy - y0;
    for (let x = 0; x < W; x++) {
      const fx = Math.min(sw - 1, Math.max(0, ((x + 0.5) * sw) / W - 0.5));
      const x0 = Math.floor(fx), x1 = Math.min(sw - 1, x0 + 1), tx = fx - x0;
      const a = lum[y0 * sw + x0] * (1 - tx) + lum[y0 * sw + x1] * tx;
      const b = lum[y1 * sw + x0] * (1 - tx) + lum[y1 * sw + x1] * tx;
      up[y * W + x] = a * (1 - ty) + b * ty;
    }
  }
  // Stretch the 2nd–98th percentile to full range.
  const sorted = Float32Array.from(up).sort();
  const lo = sorted[Math.floor(sorted.length * 0.02)], hi = sorted[Math.floor(sorted.length * 0.98)];
  const out = new Uint8ClampedArray(W * H * 4);
  for (let i = 0; i < W * H; i++) {
    const v = ((up[i] - lo) / Math.max(1, hi - lo)) * 255;
    out[i * 4] = out[i * 4 + 1] = out[i * 4 + 2] = v;
    out[i * 4 + 3] = 255;
  }
  return { width: W, height: H, data: out };
}
