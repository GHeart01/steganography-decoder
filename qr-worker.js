// QR-code scan in its own worker, so it runs alongside text reading instead
// of blocking the page (a few seconds on a large image).
import jsQR from "https://cdn.jsdelivr.net/npm/jsqr@1.4.0/+esm";
import { findCodes, codeSources } from "./lib/codes.js";

self.onmessage = async ({ data: { img, views } }) => {
  try {
    const t = performance.now();
    const codes = await findCodes(img, codeSources(img, views), jsQR);
    self.postMessage({ codes, ms: Math.round(performance.now() - t) });
  } catch (err) {
    self.postMessage({ codes: [], error: String(err?.message ?? err) });
  }
};
