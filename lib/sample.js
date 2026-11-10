// Builds a 1920×1080 sample PNG with known hidden content, so visitors (and
// tests) can see every check fire:
//  - visible caption text
//  - a faint, repeated "PROOF" watermark (only obvious after enhancement)
//  - text whose colour differs from the background only in hue
//  - a message in the lowest bits
//  - a text chunk in the PNG and a ZIP file appended after the image
import { encode } from "https://cdn.jsdelivr.net/npm/fast-png@8.0.0/+esm";

export const SAMPLE_SECRET = "The key is under the third stone from the lighthouse.";

export function makeSample() {
  const W = 1920, H = 1080;
  const c = new OffscreenCanvas(W, H);
  const ctx = c.getContext("2d", { willReadFrequently: true });

  // Sky, sea and a lighthouse-ish shape.
  const sky = ctx.createLinearGradient(0, 0, 0, H * 0.6);
  sky.addColorStop(0, "#f4d7b5"); sky.addColorStop(1, "#f7efe3");
  ctx.fillStyle = sky; ctx.fillRect(0, 0, W, H * 0.6);
  const sea = ctx.createLinearGradient(0, H * 0.6, 0, H);
  sea.addColorStop(0, "#5b8fa8"); sea.addColorStop(1, "#23485c");
  ctx.fillStyle = sea; ctx.fillRect(0, H * 0.6, W, H * 0.4);
  ctx.fillStyle = "#e9e4dc"; ctx.fillRect(1380, 300, 90, 350);
  ctx.fillStyle = "#b8473b";
  for (let y = 340; y < 640; y += 80) ctx.fillRect(1380, y, 90, 30);
  ctx.fillStyle = "#3a3a3a"; ctx.fillRect(1365, 270, 120, 40);

  // Visible caption.
  ctx.fillStyle = "#1d2b33";
  ctx.font = "bold 72px sans-serif";
  ctx.fillText("Harbour at dawn", 120, 180);
  ctx.font = "32px sans-serif";
  ctx.fillText("Photo: sample image for AI Image Decoder", 1240, 1040);

  // Faint repeated watermark (2% opacity).
  ctx.save();
  ctx.globalAlpha = 0.04;
  ctx.fillStyle = "#000";
  ctx.font = "bold 90px sans-serif";
  for (let y = 300; y < 620; y += 220) for (let x = 80; x < 1300; x += 420) ctx.fillText("PROOF", x, y);
  ctx.restore();

  // Hue-only text on a grey panel: same brightness, different colour.
  ctx.fillStyle = "rgb(128,128,128)"; ctx.fillRect(140, 760, 760, 140);
  ctx.fillStyle = "rgb(150,119,137)"; // luma ≈ 128
  ctx.font = "bold 64px sans-serif";
  ctx.fillText("MEET AT NOON", 170, 850);

  const id = ctx.getImageData(0, 0, W, H);
  const data = new Uint8Array(id.data);

  // Message in the lowest bits: R,G,B interleaved, high bit first.
  const bytes = new TextEncoder().encode(SAMPLE_SECRET);
  for (let bit = 0; bit < bytes.length * 8; bit++) {
    const p = Math.floor(bit / 3), ch = bit % 3;
    const b = (bytes[bit >> 3] >> (7 - (bit & 7))) & 1;
    data[p * 4 + ch] = (data[p * 4 + ch] & 0xfe) | b;
  }

  const png = encode({ width: W, height: H, data, channels: 4, depth: 8, text: { Comment: "Look closer." } });
  const zip = new Uint8Array([0x50, 0x4b, 0x03, 0x04, ...new TextEncoder().encode("notes.txt Meet at noon by the lighthouse.")]);
  const out = new Uint8Array(png.length + zip.length);
  out.set(png); out.set(zip, png.length);
  return new File([out], "sample-harbour.png", { type: "image/png" });
}
