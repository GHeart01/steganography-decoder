// Enhancement views: the same image with colour pushed one way or the other,
// so faint text, hidden marks and colour patterns stand out. Pure functions
// over RGBA images.

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
};

export function makeViews(img) {
  return {
    normal: img,
    high: autoContrast(scaleSaturation(img, 3)),
    low: equalize(scaleSaturation(img, 0)),
  };
}
