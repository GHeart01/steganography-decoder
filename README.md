---
title: Steganography Decoder
emoji: 🔍
colorFrom: indigo
colorTo: yellow
sdk: static
app_file: index.html
pinned: false
short_description: Find and decode hidden messages and files in images
models:
  - onnx-community/Florence-2-base-ft
  - onnx-community/Qwen3-VL-2B-Instruct-ONNX
---

# Steganography Decoder

Finds and decodes what an image is hiding: messages in the pixels' bits,
embedded and attached files, faint text and watermarks.
Everything runs in the visitor's browser with
[Transformers.js](https://huggingface.co/docs/transformers.js); the image is
never uploaded. Aimed at laptops and desktops with WebGPU (Chrome, Edge,
Safari 26+).

## What it checks

| Layer | How | Model |
|---|---|---|
| File structure | Metadata (EXIF, XMP, PNG text), AI-generation prompts, non-standard blocks, data appended after the image | none |
| Content credentials | C2PA manifest: declared source (e.g. AI-generated), the tool that made it, and recorded steps such as an added invisible watermark. Not signature-verified | none |
| Hidden bits | Scans 60 channel, bit and order combinations (84 with alpha) for text and file signatures; strips tool framing (Stegano length prefix, end markers); decodes Base64, hex and binary. Plus a chi-square attack and aligned-pair analysis of flat areas | none |
| Decoder | Any bit plane as a picture, a grid of all planes, a whole-image search, a pixel readout, a hex dump, and saving the bytes; embedded files cut at their real end; appended data saveable | none |
| Text in bit planes | Reads the lowest plane of each channel as a picture; keeps words not visible in the image | Florence-2-base |
| QR codes | jsQR over the picture and the two lowest bit planes of each channel | none |
| Faint marks | In flat-colour artwork, shapes only a few shades off the flat area around them; shown amplified and read in order | Florence-2-base |
| Frequency | 2-D FFT; isolated peaks reveal grids, halftone, moiré and frequency watermarks | none |
| Colour | Palette (k-means), saturation, histogram gaps, lowest-bit colour twins | none |
| Resizing | Averaged vs point-sampled shrink, to catch image-scaling attacks | none |
| Text | OCR on 768 px tiles of three views: normal, high saturation, low saturation. Text seen only in an enhanced view is flagged | Florence-2-base (~360 MB) |
| Corner logos | Florence-2 grounds "logo" in each corner crop; a small tight box near the edges is a mark | Florence-2-base |
| AI steganalysis | The downscaled image (~0.5 MP), a grid of its lowest bit planes, close-ups, recovered payloads and detected techniques; reports verdict, payloads, visual clues, technique, meaning and next steps | Qwen3-VL-2B-Instruct (~1.4 GB) |

PNG files are decoded in JavaScript so pixel values are exact. Browser
(canvas) decoding can be altered by colour management and anti-fingerprinting
noise, which would destroy lowest-bit evidence.

Models download once and are stored in the browser's private file system
(OPFS), because the default Cache API can refuse single files near 1 GB.
Visitors can remove them with one click.

## Demos

Four one-click demos: a starfield with a sentence in its lowest bits,
colour stripes hiding seven faint letters, a real photo with an
edit history, and a sample with three messages in its bits, an attached file
and a faint watermark. See [`demo/README.md`](demo/README.md).

Source and screenshots: [github.com/GHeart01/steganography-decoder](https://github.com/GHeart01/steganography-decoder)

## Limits

- Password-keyed tools (steghide, OutGuess, OpenStego with a password) and
  JPEG-coefficient hiding (F5, JSteg) can't be decoded.
- JPEG and WebP compression rewrite the lowest bits, so hidden-bit results on
  those formats are weak evidence.
- There is no trained visible-watermark detector; watermarks are inferred from
  repeated text, text that appears only after enhancement, and the AI's reading.
- Invisible model watermarks (SynthID, Stable Diffusion's DWT-DCT mark) are not
  decoded.
- The AI steganalysis can be wrong. Text read from the image is passed to it
  as data, and the raw findings are always shown next to it.

## Development

```bash
python3 -m http.server 8766        # then open http://localhost:8766
cd tests && npm install && npm test  # decoder and forensics tests with planted data
```
