// Pixel-level forensics. Pure functions over an RGBA image
// ({ width, height, data: Uint8ClampedArray|Uint8Array }), no DOM, so they run
// in the browser and in Node tests alike.

import { scanLsb, bitPlaceWords } from "./stego.js";

const CH = ["R", "G", "B"];

// ---------------------------------------------------------------------------
// Statistics helpers

function normalCdf(z) {
  // Abramowitz & Stegun 7.1.26 approximation of erf.
  const t = 1 / (1 + 0.3275911 * Math.abs(z) / Math.SQRT2);
  const y = 1 - (((((1.061405429 * t - 1.453152027) * t) + 1.421413741) * t - 0.284496736) * t + 0.254829592) * t
    * Math.exp(-(z * z) / 2);
  return z >= 0 ? (1 + y) / 2 : (1 - y) / 2;
}

// Upper tail of the chi-square distribution (Wilson–Hilferty approximation).
function chiSquareUpper(x, df) {
  if (df <= 0) return NaN;
  const k = 2 / (9 * df);
  const z = (Math.cbrt(x / df) - (1 - k)) / Math.sqrt(k);
  return 1 - normalCdf(z);
}

// ---------------------------------------------------------------------------
// LSB: chi-square attack (Westfeld & Pfitzmann). Sequential LSB embedding
// makes the counts of each value pair (2k, 2k+1) nearly equal. p close to 1
// means "pairs equalized", i.e. likely embedding in that part of the image.

function chiSquareAttack(data, channel, start, end) {
  const hist = new Float64Array(256);
  for (let i = start; i < end; i++) hist[data[i * 4 + channel]]++;
  let chi = 0, pairs = 0;
  for (let k = 0; k < 128; k++) {
    const a = hist[2 * k], b = hist[2 * k + 1];
    const expected = (a + b) / 2;
    if (expected < 5) continue;
    chi += ((a - expected) ** 2) / expected;
    pairs++;
  }
  if (pairs < 8) return null; // too few populated value pairs to judge
  return chiSquareUpper(chi, pairs - 1);
}

// Blocks whose values take exactly two neighbouring values, v and v+1.
// Hiding data in the lowest bit of a flat patch turns v into {v, v^1}: an
// "aligned" pair (2k, 2k+1). Dithering and sensor noise produce aligned and
// misaligned pairs (2k-1, 2k) about equally often. A strong excess of aligned
// pairs is the fingerprint of LSB embedding. Found on a real image: noise in
// near-black areas clips to {0, 1}, so blocks touching 0 or 255 are ignored.
function flatBlockNoise(img, block = 8) {
  const { width, height, data } = img;
  let constant = 0, aligned = 0, misaligned = 0;
  for (let by = 0; by + block <= height; by += block) {
    for (let bx = 0; bx + block <= width; bx += block) {
      for (let c = 0; c < 3; c++) {
        let lo = 255, hi = 0, odd = 0, flips = 0;
        for (let y = by; y < by + block && hi - lo <= 1; y++) {
          for (let x = bx; x < bx + block; x++) {
            const v = data[(y * width + x) * 4 + c];
            if (v < lo) lo = v;
            if (v > hi) hi = v;
            odd += v & 1;
            if (x > bx && ((v ^ data[(y * width + x - 1) * 4 + c]) & 1)) flips++;
          }
        }
        if (hi === lo) { constant++; continue; }
        // Skip blocks touching 0 or 255: noise clipped at pure black (or
        // white) can only flicker between 0 and 1 (254 and 255), which looks
        // "aligned" without any hidden data.
        if (hi - lo !== 1 || lo === 0 || hi === 255) continue;
        // Hidden data flips many pixels at random; the soft edge of a faint
        // shape changes only a few (seen: letters 5 shades off a stripe).
        const minority = Math.min(odd, block * block - odd) / (block * block);
        if (minority < 0.2) continue;
        // ...and scatters them: neighbouring pixels differ about as often as
        // chance predicts. A solid stroke one shade off is a clump instead.
        const pairs = block * (block - 1);
        if (flips / pairs < 0.5 * 2 * minority * (1 - minority)) continue;
        lo % 2 === 0 ? aligned++ : misaligned++;
      }
    }
  }
  const pairs = aligned + misaligned;
  return { constantBlocks: constant, alignedBlocks: aligned, misalignedBlocks: misaligned, alignedShare: pairs ? aligned / pairs : 0 };
}

export function analyzeLsb(img, { lossy = false } = {}) {
  const n = img.width * img.height;
  // Compare a window at the start of the image (where sequential tools write)
  // with an equally sized window at the end. Equal sizes matter: the test
  // gets more sensitive with more pixels, so unequal windows fake a contrast.
  const fractions = [0.01, 0.05, 0.1, 0.25];
  const chi = CH.map((name, c) => ({
    channel: name,
    windows: fractions.map((f) => {
      const len = Math.max(1, Math.floor(n * f));
      return { fraction: f, start: chiSquareAttack(img.data, c, 0, len), end: chiSquareAttack(img.data, c, n - len, n) };
    }),
  }));
  const flat = flatBlockNoise(img);
  const messages = scanLsb(img);

  const findings = [];
  for (const m of messages) {
    const where = bitPlaceWords(m.cfg);
    findings.push({
      severity: lossy ? "medium" : "high",
      title: m.kind === "file" ? `Hidden ${m.label} in ${where}` : `Readable text hidden in ${where}`,
      detail: `${m.order}${m.offset ? `, starting at byte ${m.offset}` : ""}${m.framing ? `, ${m.framing}` : ""}. Open it in the Decoder below to see or save the bytes.`,
      text: m.kind === "text" ? m.preview : undefined,
    });
    const last = m.decoded?.at(-1);
    if (last) {
      const chain = m.decoded.map((l) => l.encoding).join(", then ");
      findings.push({
        severity: lossy ? "medium" : "high",
        title: last.file ? `The hidden text is ${chain} for a ${last.file.label}` : `The hidden text is ${chain}: it decodes to readable text`,
        detail: "Decoded in the browser. Open it in the Decoder below to save it.",
        text: last.text?.slice(0, 400),
      });
    }
  }
  // Sequential embedding: the start looks equalized (p high) while the end
  // clearly doesn't, in at least two colour channels.
  const seq = chi.map((c) => {
    const hit = c.windows.find((w) => w.fraction <= 0.1 && w.start !== null && w.end !== null && w.start > 0.95 && w.end < 0.05);
    return hit ? { channel: c.channel, fraction: hit.fraction } : null;
  }).filter(Boolean);
  if (seq.length >= 2) {
    findings.push({
      severity: lossy ? "low" : "medium",
      title: "Start of the image's lowest bits look filled with data",
      detail: `Chi-square attack: the first rows look equalized (p>0.95) but the last rows don't (p<0.05) in ${seq.map((x) => x.channel).join(", ")}. Sequential hiding tools write from the top.`,
    });
  }
  if (flat.alignedBlocks >= 20 && flat.alignedShare > 0.8) {
    findings.push({
      severity: lossy ? "low" : "high",
      title: "Noise in the lowest bits of flat areas",
      detail: `${flat.alignedBlocks} flat blocks flicker between values 2k and 2k+1 but only ${flat.misalignedBlocks} between 2k−1 and 2k. Natural noise and dithering do both equally; hidden data does the first.`,
    });
  }
  return {
    chi, flat, messages, findings,
    reliable: !lossy,
    note: lossy ? "Lossy (JPEG/WebP) compression rewrites the lowest bits, so LSB results here are weak evidence." : undefined,
  };
}

// Picture of one channel's (or all channels') lowest bit, amplified to black/white.
export function lsbPlaneView(img, channel = "rgb") {
  const { width, height, data } = img;
  const out = new Uint8ClampedArray(width * height * 4);
  for (let i = 0; i < width * height; i++) {
    const o = i * 4;
    if (channel === "rgb") {
      out[o] = (data[o] & 1) * 255;
      out[o + 1] = (data[o + 1] & 1) * 255;
      out[o + 2] = (data[o + 2] & 1) * 255;
    } else {
      const v = (data[o + channel] & 1) * 255;
      out[o] = out[o + 1] = out[o + 2] = v;
    }
    out[o + 3] = 255;
  }
  return { width, height, data: out };
}

// ---------------------------------------------------------------------------
// Resizing

// Area-average (box) resize: every source pixel contributes, no aliasing tricks.
export function resizeArea(img, tw, th) {
  const { width: sw, height: sh, data } = img;
  const out = new Uint8ClampedArray(tw * th * 4);
  const sx = sw / tw, sy = sh / th;
  for (let ty = 0; ty < th; ty++) {
    const y0 = ty * sy, y1 = y0 + sy;
    for (let tx = 0; tx < tw; tx++) {
      const x0 = tx * sx, x1 = x0 + sx;
      let r = 0, g = 0, b = 0, a = 0, wsum = 0;
      for (let y = Math.floor(y0); y < Math.ceil(y1); y++) {
        const wy = Math.min(y + 1, y1) - Math.max(y, y0);
        for (let x = Math.floor(x0); x < Math.ceil(x1); x++) {
          const w = (Math.min(x + 1, x1) - Math.max(x, x0)) * wy;
          const i = (y * sw + x) * 4;
          r += data[i] * w; g += data[i + 1] * w; b += data[i + 2] * w; a += data[i + 3] * w;
          wsum += w;
        }
      }
      const o = (ty * tw + tx) * 4;
      out[o] = r / wsum; out[o + 1] = g / wsum; out[o + 2] = b / wsum; out[o + 3] = a / wsum;
    }
  }
  return { width: tw, height: th, data: out };
}

export function resizeNearest(img, tw, th) {
  const { width: sw, height: sh, data } = img;
  const out = new Uint8ClampedArray(tw * th * 4);
  for (let ty = 0; ty < th; ty++) {
    const y = Math.min(sh - 1, Math.floor((ty + 0.5) * sh / th));
    for (let tx = 0; tx < tw; tx++) {
      const x = Math.min(sw - 1, Math.floor((tx + 0.5) * sw / tw));
      const i = (y * sw + x) * 4, o = (ty * tw + tx) * 4;
      out[o] = data[i]; out[o + 1] = data[i + 1]; out[o + 2] = data[i + 2]; out[o + 3] = data[i + 3];
    }
  }
  return { width: tw, height: th, data: out };
}

// Largest size within maxPixels that keeps the aspect ratio, snapped to a
// multiple of `multiple` (Qwen3-VL uses 32×32 pixels per visual token).
export function fitSize(w, h, maxPixels, multiple = 32) {
  const scale = Math.min(1, Math.sqrt(maxPixels / (w * h)));
  const snap = (v) => Math.max(multiple, Math.floor((v * scale) / multiple) * multiple);
  return [snap(w), snap(h)];
}

export function crop(img, x, y, w, h) {
  x = Math.max(0, Math.round(x)); y = Math.max(0, Math.round(y));
  w = Math.min(img.width - x, Math.round(w)); h = Math.min(img.height - y, Math.round(h));
  const out = new Uint8ClampedArray(w * h * 4);
  for (let r = 0; r < h; r++) {
    out.set(img.data.subarray(((y + r) * img.width + x) * 4, ((y + r) * img.width + x + w) * 4), r * w * 4);
  }
  return { width: w, height: h, data: out };
}

// Image-scaling attack check: a crafted image can show different content when
// downscaled with nearest-neighbour sampling than with proper averaging.
export function scalingAttackCheck(img, tw, th) {
  const area = resizeArea(img, tw, th);
  const nearest = resizeNearest(img, tw, th);
  let diff = 0;
  for (let i = 0; i < area.data.length; i += 4) {
    diff += Math.abs(area.data[i] - nearest.data[i]) + Math.abs(area.data[i + 1] - nearest.data[i + 1])
      + Math.abs(area.data[i + 2] - nearest.data[i + 2]);
  }
  const mad = diff / (tw * th * 3);
  const findings = mad > 40 ? [{
    severity: "high",
    title: "Image changes a lot depending on how it's shrunk",
    detail: `Average difference ${mad.toFixed(1)}/255 between averaged and point-sampled downscales. This is how image-scaling attacks hide a second picture.`,
  }] : [];
  return { meanAbsDiff: mad, nearest, findings };
}

// ---------------------------------------------------------------------------
// Frequency analysis: periodic patterns (grids, halftone, moiré, frequency
// watermarks) show up as isolated peaks in the 2-D spectrum.

function fft1d(re, im) {
  const n = re.length;
  for (let i = 1, j = 0; i < n; i++) {
    let bit = n >> 1;
    for (; j & bit; bit >>= 1) j ^= bit;
    j ^= bit;
    if (i < j) {
      [re[i], re[j]] = [re[j], re[i]];
      [im[i], im[j]] = [im[j], im[i]];
    }
  }
  for (let len = 2; len <= n; len <<= 1) {
    const ang = (-2 * Math.PI) / len;
    const wr = Math.cos(ang), wi = Math.sin(ang);
    for (let i = 0; i < n; i += len) {
      let cr = 1, ci = 0;
      for (let k = 0; k < len / 2; k++) {
        const a = i + k, b = a + len / 2;
        const tr = re[b] * cr - im[b] * ci, ti = re[b] * ci + im[b] * cr;
        re[b] = re[a] - tr; im[b] = im[a] - ti;
        re[a] += tr; im[a] += ti;
        const ncr = cr * wr - ci * wi;
        ci = cr * wi + ci * wr; cr = ncr;
      }
    }
  }
}

export function analyzeSpectrum(img, { lossy = false, N = 512 } = {}) {
  const small = resizeArea(img, N, N);
  const re = new Float64Array(N * N), im = new Float64Array(N * N);
  let mean = 0;
  for (let i = 0; i < N * N; i++) {
    const o = i * 4;
    re[i] = 0.299 * small.data[o] + 0.587 * small.data[o + 1] + 0.114 * small.data[o + 2];
    mean += re[i];
  }
  mean /= N * N;
  const hann = new Float64Array(N);
  for (let i = 0; i < N; i++) hann[i] = 0.5 - 0.5 * Math.cos((2 * Math.PI * i) / (N - 1));
  for (let y = 0; y < N; y++) for (let x = 0; x < N; x++) re[y * N + x] = (re[y * N + x] - mean) * hann[x] * hann[y];

  const rr = new Float64Array(N), ri = new Float64Array(N);
  for (let y = 0; y < N; y++) {
    rr.set(re.subarray(y * N, y * N + N)); ri.set(im.subarray(y * N, y * N + N));
    fft1d(rr, ri);
    re.set(rr, y * N); im.set(ri, y * N);
  }
  for (let x = 0; x < N; x++) {
    for (let y = 0; y < N; y++) { rr[y] = re[y * N + x]; ri[y] = im[y * N + x]; }
    fft1d(rr, ri);
    for (let y = 0; y < N; y++) { re[y * N + x] = rr[y]; im[y * N + x] = ri[y]; }
  }

  // Shifted log-magnitude: centre = zero frequency.
  const mag = new Float64Array(N * N);
  const half = N / 2;
  for (let y = 0; y < N; y++) for (let x = 0; x < N; x++) {
    const sy = (y + half) % N, sx = (x + half) % N;
    const i = y * N + x;
    mag[sy * N + sx] = Math.log1p(Math.hypot(re[i], im[i]));
  }

  // Radial median as the "expected" spectrum at each distance from centre.
  const byRadius = Array.from({ length: half + 1 }, () => []);
  for (let y = 0; y < N; y++) for (let x = 0; x < N; x++) {
    const r = Math.round(Math.hypot(x - half, y - half));
    if (r <= half) byRadius[r].push(mag[y * N + x]);
  }
  const radialMedian = byRadius.map((a) => {
    if (!a.length) return 0;
    a.sort((p, q) => p - q);
    return a[a.length >> 1];
  });

  // Local maxima well above the radial median, one per symmetric pair.
  const peaks = [];
  for (let y = 1; y < N - 1; y++) for (let x = 1; x < N - 1; x++) {
    const u = x - half, v = y - half;
    if (v < 0 || (v === 0 && u <= 0)) continue; // half-plane
    const r = Math.hypot(u, v);
    if (r < 8 || r > half) continue;
    if (Math.abs(u) <= 1 || Math.abs(v) <= 1) continue; // edge streaks along axes
    const m = mag[y * N + x];
    const score = m - radialMedian[Math.round(r)];
    if (score < 3) continue;
    let isMax = true;
    for (let dy = -1; dy <= 1 && isMax; dy++) for (let dx = -1; dx <= 1; dx++) {
      if ((dx || dy) && mag[(y + dy) * N + x + dx] > m) { isMax = false; break; }
    }
    if (!isMax) continue;
    const fx = u / img.width, fy = v / img.height; // cycles per original pixel
    const period = 1 / Math.hypot(fx, fy);
    const angle = (Math.atan2(fy, fx) * 180) / Math.PI;
    const px = 1 / Math.abs(fx), py = 1 / Math.abs(fy);
    const jpegGrid = lossy && [8, 4, 8 / 3, 2].some((p) => Math.abs(px - p) / p < 0.06 || Math.abs(py - p) / p < 0.06);
    peaks.push({ u, v, score, period, angle, jpegGrid });
  }
  peaks.sort((a, b) => b.score - a.score);
  const top = peaks.slice(0, 12);

  // Spectrum picture for display.
  let lo = Infinity, hi = -Infinity;
  for (const m of mag) { if (m < lo) lo = m; if (m > hi) hi = m; }
  const view = new Uint8ClampedArray(N * N * 4);
  for (let i = 0; i < N * N; i++) {
    const v = ((mag[i] - lo) / (hi - lo || 1)) * 255;
    view[i * 4] = view[i * 4 + 1] = view[i * 4 + 2] = v;
    view[i * 4 + 3] = 255;
  }

  const real = top.filter((p) => !p.jpegGrid);
  const findings = [];
  if (real.length >= 2 || (real[0] && real[0].score > 4.5)) {
    const desc = real.slice(0, 3).map((p) => `every ~${p.period.toFixed(1)} px at ${p.angle.toFixed(0)}°`).join("; ");
    findings.push({
      severity: real[0].score > 4.5 ? "medium" : "low",
      title: "Repeating pattern in the frequency spectrum",
      detail: `${real.length} strong periodic component(s): ${desc}. Can be a grid, halftone, dithering, moiré, texture or a frequency-domain watermark.`,
    });
  }
  return { peaks: top, findings, view: { width: N, height: N, data: view } };
}

// ---------------------------------------------------------------------------
// Colour analysis

function mulberry32(seed) {
  return () => {
    seed |= 0; seed = (seed + 0x6d2b79f5) | 0;
    let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function kmeans(samples, k, iters = 12) {
  const n = samples.length / 3;
  const rand = mulberry32(42);
  const centers = [];
  const first = Math.floor(rand() * n);
  centers.push([samples[first * 3], samples[first * 3 + 1], samples[first * 3 + 2]]);
  const d2 = new Float64Array(n).fill(Infinity);
  while (centers.length < k) {
    const c = centers.at(-1);
    let sum = 0;
    for (let i = 0; i < n; i++) {
      const d = (samples[i * 3] - c[0]) ** 2 + (samples[i * 3 + 1] - c[1]) ** 2 + (samples[i * 3 + 2] - c[2]) ** 2;
      if (d < d2[i]) d2[i] = d;
      sum += d2[i];
    }
    if (sum === 0) break;
    let t = rand() * sum, pick = 0;
    for (; pick < n - 1; pick++) { t -= d2[pick]; if (t <= 0) break; }
    centers.push([samples[pick * 3], samples[pick * 3 + 1], samples[pick * 3 + 2]]);
  }
  const assign = new Uint8Array(n);
  for (let it = 0; it < iters; it++) {
    const acc = centers.map(() => [0, 0, 0, 0]);
    for (let i = 0; i < n; i++) {
      let best = 0, bd = Infinity;
      for (let c = 0; c < centers.length; c++) {
        const d = (samples[i * 3] - centers[c][0]) ** 2 + (samples[i * 3 + 1] - centers[c][1]) ** 2
          + (samples[i * 3 + 2] - centers[c][2]) ** 2;
        if (d < bd) { bd = d; best = c; }
      }
      assign[i] = best;
      const a = acc[best];
      a[0] += samples[i * 3]; a[1] += samples[i * 3 + 1]; a[2] += samples[i * 3 + 2]; a[3]++;
    }
    acc.forEach((a, c) => { if (a[3]) centers[c] = [a[0] / a[3], a[1] / a[3], a[2] / a[3]]; });
  }
  const counts = new Array(centers.length).fill(0);
  for (let i = 0; i < n; i++) counts[assign[i]]++;
  return centers.map((c, i) => ({ rgb: c.map(Math.round), share: counts[i] / n }))
    .filter((c) => c.share > 0)
    .sort((a, b) => b.share - a.share);
}

const hex = (rgb) => "#" + rgb.map((v) => v.toString(16).padStart(2, "0")).join("");

// Plain-English colour name, so people and the language model don't have to
// read hex codes.
export function colorName([r, g, b]) {
  const max = Math.max(r, g, b) / 255, min = Math.min(r, g, b) / 255;
  const l = (max + min) / 2, d = max - min;
  const s = d === 0 ? 0 : d / (1 - Math.abs(2 * l - 1));
  const tone = l > 0.85 ? "very light " : l > 0.65 ? "light " : l < 0.2 ? "very dark " : l < 0.38 ? "dark " : "";
  if (s < 0.12 || d < 0.06) return l > 0.92 ? "white" : l < 0.08 ? "black" : `${tone}grey`.trim();
  let h;
  if (max === r / 255) h = ((g - b) / 255 / d) % 6;
  else if (max === g / 255) h = (b - r) / 255 / d + 2;
  else h = (r - g) / 255 / d + 4;
  h = (h * 60 + 360) % 360;
  const hues = [[15, "red"], [40, "orange"], [65, "yellow"], [160, "green"], [195, "teal"], [250, "blue"], [290, "purple"], [335, "pink"], [360, "red"]];
  let name = hues.find(([lim]) => h < lim)[1];
  if (name === "orange" && l > 0.7) name = s < 0.5 ? "beige" : "peach";
  if (name === "orange" && l < 0.35) name = "brown";
  const muted = s < 0.3 && name !== "beige" ? "greyish " : "";
  return `${tone}${muted}${name}`;
}

export function analyzeColor(img) {
  const { width, height, data } = img;
  const n = width * height;
  const hist = [new Uint32Array(256), new Uint32Array(256), new Uint32Array(256)];
  const seen = new Uint8Array(1 << 21); // 2^24 bits
  let unique = 0, satSum = 0, highSat = 0, gray = 0;
  for (let i = 0; i < n; i++) {
    const o = i * 4, r = data[o], g = data[o + 1], b = data[o + 2];
    hist[0][r]++; hist[1][g]++; hist[2][b]++;
    const key = (r << 16) | (g << 8) | b;
    if (!(seen[key >> 3] & (1 << (key & 7)))) { seen[key >> 3] |= 1 << (key & 7); unique++; }
    const max = Math.max(r, g, b), min = Math.min(r, g, b);
    const s = max ? (max - min) / max : 0;
    satSum += s;
    if (s > 0.6 && max > 60) highSat++;
    if (max - min < 8) gray++;
  }

  const step = Math.max(1, Math.floor(n / 150000));
  const samples = new Float64Array(Math.ceil(n / step) * 3);
  let s = 0;
  for (let i = 0; i < n; i += step) {
    samples[s++] = data[i * 4]; samples[s++] = data[i * 4 + 1]; samples[s++] = data[i * 4 + 2];
  }
  const palette = kmeans(samples.subarray(0, s), 8).map((c) => ({ ...c, hex: hex(c.rgb), name: colorName(c.rgb) }));

  // Histogram gaps (empty values between the darkest and brightest) suggest
  // contrast stretching or other edits.
  const gaps = hist.map((h) => {
    let lo = 0, hi = 255;
    while (lo < 255 && !h[lo]) lo++;
    while (hi > 0 && !h[hi]) hi--;
    let empty = 0;
    for (let v = lo; v <= hi; v++) if (!h[v]) empty++;
    return hi > lo ? empty / (hi - lo + 1) : 0;
  });

  // Colours that come in lowest-bit twins (v, v^1) in a graphic with few
  // colours: the fingerprint of LSB embedding in flat artwork. Smooth
  // gradients have both kinds of ±1 neighbours, so compare aligned twins
  // (2k, 2k+1) with misaligned ones (2k-1, 2k).
  let pairedShare = null, misalignedShare = null;
  if (unique <= 4096) {
    const has = (k) => k >= 0 && k < 1 << 24 && (seen[k >> 3] & (1 << (k & 7)));
    let paired = 0, mis = 0;
    for (let key = 0; key < 1 << 24; key++) {
      if (!has(key)) continue;
      if ([0, 8, 16].some((sh) => has(key ^ (1 << sh)))) paired++;
      if ([0, 8, 16].some((sh) => {
        const v = (key >> sh) & 255;
        const w = v % 2 === 0 ? v - 1 : v + 1;
        return w >= 0 && w <= 255 && has((key & ~(255 << sh)) | (w << sh));
      })) mis++;
    }
    pairedShare = paired / unique;
    misalignedShare = mis / unique;
  }

  const findings = [];
  if (pairedShare !== null && unique >= 16 && pairedShare > 0.5 && misalignedShare < pairedShare * 0.3) {
    findings.push({
      severity: "medium",
      title: "Colours come in near-identical pairs",
      detail: `${Math.round(pairedShare * 100)}% of the ${unique} colours have a twin that differs only in the lowest bit. Flat artwork normally doesn't; embedded data often does.`,
    });
  }
  const meanGap = (gaps[0] + gaps[1] + gaps[2]) / 3;
  if (unique > 4096 && meanGap > 0.25) {
    findings.push({
      severity: "low",
      title: "Gaps in the colour histogram",
      detail: `${Math.round(meanGap * 100)}% of values in range never occur, typical of contrast or levels adjustments.`,
    });
  }
  return {
    uniqueColors: unique,
    meanSaturation: satSum / n,
    highSaturationShare: highSat / n,
    grayShare: gray / n,
    palette,
    histogram: hist,
    histogramGaps: gaps,
    pairedShare,
    misalignedShare,
    findings,
  };
}

// ---------------------------------------------------------------------------
// Faint marks: shapes drawn in almost the same colour as the flat area around
// them (e.g. letters a few shades off a stripe). Global contrast stretching
// barely shows them because the image already spans the full range; comparing
// each shape with its own surrounding colour does.

export function faintMarks(img, { minDist = 4, maxDist = 60 } = {}) {
  const { width: W, height: H, data } = img;
  const N = W * H;
  const key = new Uint32Array(N);
  for (let i = 0; i < N; i++) key[i] = (data[i * 4] << 16) | (data[i * 4 + 1] << 8) | data[i * 4 + 2];

  // 1. Exact-colour regions (4-connected).
  const label = new Int32Array(N).fill(-1);
  const stack = new Int32Array(N);
  const sizes = [], colors = [];
  for (let i = 0; i < N; i++) {
    if (label[i] >= 0) continue;
    const id = sizes.length, k = key[i];
    let sp = 0, size = 0;
    stack[sp++] = i; label[i] = id;
    while (sp) {
      const p = stack[--sp]; size++;
      const x = p % W;
      if (x > 0 && label[p - 1] < 0 && key[p - 1] === k) { label[p - 1] = id; stack[sp++] = p - 1; }
      if (x < W - 1 && label[p + 1] < 0 && key[p + 1] === k) { label[p + 1] = id; stack[sp++] = p + 1; }
      if (p >= W && label[p - W] < 0 && key[p - W] === k) { label[p - W] = id; stack[sp++] = p - W; }
      if (p < N - W && label[p + W] < 0 && key[p + W] === k) { label[p + W] = id; stack[sp++] = p + W; }
    }
    sizes.push(size); colors.push(k);
  }
  const bigMin = Math.max(400, N * 0.002);
  let bigPixels = 0;
  for (const s of sizes) if (s >= bigMin) bigPixels += s;
  const view = { width: W, height: H, data: new Uint8ClampedArray(N * 4) };
  for (let i = 0; i < N; i++) view.data[i * 4 + 3] = 255;
  // Photos have almost no exact-colour areas; the check only applies to flat artwork.
  if (bigPixels < N * 0.3) return { marks: [], view, applicable: false };
  const isBig = (p) => sizes[label[p]] >= bigMin;

  // 2. Everything else, grouped into 8-connected blobs; keep blobs enclosed by
  //    one flat region whose colour they only faintly differ from.
  const seen = new Uint8Array(N);
  const marks = [];
  const dist = (p, c) => Math.abs((key[p] >> 16) - (c >> 16)) + Math.abs(((key[p] >> 8) & 255) - ((c >> 8) & 255)) + Math.abs((key[p] & 255) - (c & 255));
  const maxBlob = N * 0.02;
  for (let i = 0; i < N; i++) {
    if (seen[i] || isBig(i)) continue;
    const pixels = [];
    let sp = 0; stack[sp++] = i; seen[i] = 1;
    const border = new Map();
    while (sp) {
      const p = stack[--sp];
      pixels.push(p);
      const x = p % W, y = (p / W) | 0;
      for (let dy = -1; dy <= 1; dy++) for (let dx = -1; dx <= 1; dx++) {
        if (!dx && !dy) continue;
        const nx = x + dx, ny = y + dy;
        if (nx < 0 || ny < 0 || nx >= W || ny >= H) continue;
        const q = ny * W + nx;
        if (isBig(q)) { if (!dx || !dy) border.set(label[q], (border.get(label[q]) ?? 0) + 1); }
        else if (!seen[q]) { seen[q] = 1; stack[sp++] = q; }
      }
    }
    if (pixels.length < 20 || pixels.length > maxBlob || !border.size) continue;
    let bestId = -1, best = 0, total = 0;
    for (const [id, n] of border) { total += n; if (n > best) { best = n; bestId = id; } }
    if (best / total < 0.9) continue; // not enclosed by a single flat area
    const bg = colors[bestId];
    let mx = 0, x0 = W, y0 = H, x1 = 0, y1 = 0;
    for (const p of pixels) {
      mx = Math.max(mx, dist(p, bg));
      const x = p % W, y = (p / W) | 0;
      if (x < x0) x0 = x; if (x > x1) x1 = x; if (y < y0) y0 = y; if (y > y1) y1 = y;
    }
    if (mx < minDist || mx > maxDist || x1 - x0 < 4 || y1 - y0 < 4) continue;
    for (const p of pixels) {
      const v = (dist(p, bg) / mx) * 255;
      view.data[p * 4] = view.data[p * 4 + 1] = view.data[p * 4 + 2] = v;
    }
    marks.push({ box: { x0, y0, x1: x1 + 1, y1: y1 + 1 }, contrast: mx, bg: "#" + bg.toString(16).padStart(6, "0") });
  }
  return { marks: readingOrder(marks), view, applicable: true };
}

// Top-to-bottom lines (marks whose vertical ranges overlap), left to right.
export function readingOrder(marks) {
  const sorted = [...marks].sort((a, b) => a.box.y0 - b.box.y0);
  const lines = [];
  for (const m of sorted) {
    const line = lines.find((l) => m.box.y0 < l.y1 && m.box.y1 > l.y0);
    if (line) { line.items.push(m); line.y0 = Math.min(line.y0, m.box.y0); line.y1 = Math.max(line.y1, m.box.y1); }
    else lines.push({ y0: m.box.y0, y1: m.box.y1, items: [m] });
  }
  lines.sort((a, b) => a.y0 - b.y0);
  return lines.flatMap((l, li) => l.items.sort((a, b) => a.box.x0 - b.box.x0).map((m) => ({ ...m, line: li })));
}

// The marks cropped from the amplified view, lined up in reading order as
// dark shapes on white, centred on a square canvas (Florence-2 squashes every
// input to a square, so a long strip would be distorted).
export function faintStrip(view, marks, height = 64) {
  const pad = 6, gap = 18, lineGap = 34;
  const crops = marks.map((m) => {
    const c = crop(view, m.box.x0 - pad, m.box.y0 - pad, m.box.x1 - m.box.x0 + 2 * pad, m.box.y1 - m.box.y0 + 2 * pad);
    const w = Math.max(1, Math.round((c.width / c.height) * height));
    return { img: resizeArea(c, w, height), line: m.line };
  });
  let width = 0;
  crops.forEach((c, i) => { width += c.img.width + (i ? (c.line !== crops[i - 1].line ? lineGap : gap) : 0); });
  const side = Math.max(width + 40, height + 40);
  const out = new Uint8ClampedArray(side * side * 4).fill(255);
  let x = 20;
  const y = Math.round((side - height) / 2);
  crops.forEach((c, i) => {
    if (i) x += c.line !== crops[i - 1].line ? lineGap : gap;
    for (let r = 0; r < c.img.height; r++) for (let q = 0; q < c.img.width; q++) {
      const s = (r * c.img.width + q) * 4, o = ((y + r) * side + x + q) * 4;
      const v = 255 - c.img.data[s];
      out[o] = out[o + 1] = out[o + 2] = v;
    }
    x += c.img.width;
  });
  return { width: side, height: side, data: out };
}
