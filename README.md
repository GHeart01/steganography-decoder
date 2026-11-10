---
title: Pattern Finder
emoji: 🔍
colorFrom: indigo
colorTo: yellow
sdk: static
app_file: index.html
pinned: false
short_description: Find text, watermarks and hidden data in images, in-browser
models:
  - onnx-community/Florence-2-base-ft
  - onnx-community/Qwen3-VL-2B-Instruct-ONNX
---

# Pattern Finder

Looks for text, watermarks, colour patterns and hidden data in an image.
Everything runs in the visitor's browser with
[Transformers.js](https://huggingface.co/docs/transformers.js); the image is
never uploaded. Aimed at laptops and desktops with WebGPU (Chrome, Edge,
Safari 26+).

## What it checks

| Layer | How | Model |
|---|---|---|
| File structure | Metadata (EXIF, XMP, PNG text), AI-generation prompts, non-standard blocks, data appended after the image | none |
| Content credentials | C2PA manifest: declared source (e.g. AI-generated), the tool that made it, and recorded steps such as an added invisible watermark. Not signature-verified | none |
| Lowest bits | Message extraction in common orderings, chi-square attack, aligned-pair analysis of flat areas | none |
| Frequency | 2-D FFT; isolated peaks reveal grids, halftone, moiré and frequency watermarks | none |
| Colour | Palette (k-means), saturation, histogram gaps, lowest-bit colour twins | none |
| Resizing | Averaged vs point-sampled shrink, to catch image-scaling attacks | none |
| Text | OCR on 768 px tiles of three views: normal, high saturation, low saturation. Text seen only in an enhanced view is flagged | Florence-2-base (~360 MB) |
| Interpretation | The downscaled image (~1 MP), a saturated view and close-ups of flagged regions, plus all findings | Qwen3-VL-2B-Instruct (~1.4 GB) |

PNG files are decoded in JavaScript so pixel values are exact. Browser
(canvas) decoding can be altered by colour management and anti-fingerprinting
noise, which would destroy lowest-bit evidence.

Models download once and are stored in the browser's private file system
(OPFS), because the default Cache API can refuse single files near 1 GB.
Visitors can remove them with one click.

## Demos

Four one-click demos: two ChatGPT images whose credentials declare them
AI-generated and watermarked, a real photo with an edit history, and a sample
with planted hidden content. See [`demo/README.md`](demo/README.md).

Source and screenshots: [github.com/GHeart01/pattern-finder](https://github.com/GHeart01/pattern-finder)

## Limits

- JPEG and WebP compression rewrite the lowest bits, so hidden-bit results on
  those formats are weak evidence.
- There is no trained visible-watermark detector; watermarks are inferred from
  repeated text, text that appears only after enhancement, and the AI's reading.
- Invisible model watermarks (SynthID, Stable Diffusion's DWT-DCT mark) are not
  decoded.
- The AI interpretation can be wrong. Text read from the image is passed to it
  as data, and the raw findings are always shown next to it.

## Development

```bash
python3 -m http.server 8766        # then open http://localhost:8766
cd tests && npm install && npm test  # forensics tests with planted data
```
