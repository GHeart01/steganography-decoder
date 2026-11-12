# Demo images

- `quiet-signal.png`: a 1200×800 starfield of translucent circles and streaks.
  The lowest bit of R, G and B, read row by row, spells "THE QUIETEST SIGNAL
  CARRIES THE MESSAGE".
- `colour-stripes.png`: twenty flat colour stripes. Seven of them hide a letter
  drawn only a few shades off the stripe's colour.

- `ribbons-c2pa.jpg`: a real photo carrying C2PA content credentials that record
  it being opened and colour-adjusted. From the
  [c2pa-rs](https://github.com/contentauth/c2pa-rs) test fixtures (`CA.jpg`),
  © Adobe and C2PA contributors, licensed MIT / Apache-2.0.

`thumbs/` holds 480 px previews for the demo picker.

The "Harbour" sample with planted hidden content (two hidden messages, one of
them Base64 in bit 1 of blue, an appended file, a PNG comment and a faint
watermark) is generated in the browser by
[`lib/sample.js`](../lib/sample.js), so it isn't stored here.
