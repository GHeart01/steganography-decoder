// Turn an image file into exact RGBA pixels.
//
// PNGs are decoded in JavaScript, byte for byte. Browser decoding through a
// <canvas> can be altered by colour management and by anti-fingerprinting
// protections (Brave, Firefox, Safari) that add noise to pixel reads, which
// would destroy lowest-bit evidence.
import { decode as decodePng, convertIndexedToRgb } from "https://cdn.jsdelivr.net/npm/fast-png@8.0.0/+esm";
import { detectFormat } from "./metadata.js";

const MAX_PIXELS = 40_000_000;

function pngToRgba(png) {
  const { width, height, depth } = png;
  const n = width * height;
  const out = new Uint8ClampedArray(n * 4);
  let src = png.data, channels = png.channels;
  if (png.palette) {
    src = convertIndexedToRgb(png);
    channels = src.length / n;
  }
  const scale = png.palette ? 1 : depth === 16 ? 1 / 257 : depth < 8 ? 255 / (2 ** depth - 1) : 1;
  const v = (i) => (scale === 1 ? src[i] : Math.round(src[i] * scale));
  for (let p = 0; p < n; p++) {
    const o = p * 4, s = p * channels;
    if (channels >= 3) {
      out[o] = v(s); out[o + 1] = v(s + 1); out[o + 2] = v(s + 2);
      out[o + 3] = channels === 4 ? v(s + 3) : 255;
    } else {
      out[o] = out[o + 1] = out[o + 2] = v(s);
      out[o + 3] = channels === 2 ? v(s + 1) : 255;
    }
  }
  return { width, height, data: out };
}

// Does this browser add noise when reading canvas pixels?
function canvasReadsAreExact() {
  try {
    const c = new OffscreenCanvas(16, 16);
    const ctx = c.getContext("2d", { willReadFrequently: true });
    const src = new ImageData(16, 16);
    for (let i = 0; i < src.data.length; i++) src.data[i] = i % 4 === 3 ? 255 : (i * 37) & 255;
    ctx.putImageData(src, 0, 0);
    const back = ctx.getImageData(0, 0, 16, 16).data;
    return back.every((b, i) => b === src.data[i]);
  } catch {
    return false;
  }
}

export async function decodeImage(file) {
  const bytes = new Uint8Array(await file.arrayBuffer());
  const format = detectFormat(bytes);
  const notes = [];

  if (format === "png") {
    try {
      const png = decodePng(bytes);
      if (png.width * png.height > MAX_PIXELS) throw new Error("too large");
      if (png.depth === 16) notes.push("16-bit PNG: analysis uses the top 8 bits of each value, so data hidden in the low byte is missed.");
      return { img: pngToRgba(png), bytes, format, exact: png.depth !== 16, notes };
    } catch (err) {
      if (err.message === "too large") throw new Error("This image is over 40 megapixels. Please use a smaller one.");
      notes.push("The PNG couldn't be decoded directly, so the browser decoded it instead.");
    }
  }

  const bmp = await createImageBitmap(new Blob([bytes]), { colorSpaceConversion: "none", premultiplyAlpha: "none" });
  if (bmp.width * bmp.height > MAX_PIXELS) throw new Error("This image is over 40 megapixels. Please use a smaller one.");
  const canvas = new OffscreenCanvas(bmp.width, bmp.height);
  const ctx = canvas.getContext("2d", { willReadFrequently: true });
  ctx.drawImage(bmp, 0, 0);
  const id = ctx.getImageData(0, 0, bmp.width, bmp.height);
  bmp.close();
  const exactReads = canvasReadsAreExact();
  if (!exactReads) notes.push("Your browser adds privacy noise to canvas pixel reads, so lowest-bit results are unreliable for this image.");
  if (format === "jpeg" || format === "webp") notes.push(`${format.toUpperCase()} is lossy: compression rewrites the lowest bits, so LSB results are weak evidence.`);
  return {
    img: { width: id.width, height: id.height, data: id.data },
    bytes, format,
    exact: exactReads && format !== "jpeg" && format !== "webp",
    notes,
  };
}
