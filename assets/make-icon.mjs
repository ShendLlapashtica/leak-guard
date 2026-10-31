#!/usr/bin/env node
/*!
 * Draws assets/icon.png — a shield with a keyhole, 512×512.
 *
 * The plugin directory wants a square PNG and will not take an SVG, so the
 * icon is generated here rather than committed as an unexplained binary: run
 * `node assets/make-icon.mjs` and you get the same file back. No dependencies;
 * the PNG is assembled chunk by chunk with zlib.
 */

import { deflateSync } from 'node:zlib';
import { writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const SIZE = 512;
const SS = 3;                                    // supersample, for smooth edges
const BG = [0x0e, 0x11, 0x17];
const SHIELD = [0xf3, 0xf5, 0xf9];
const ACCENT = [0x3b, 0x82, 0xf6];

const px = (x, y) => {
  // Normalised coordinates: (0,0) centre, y positive downwards.
  const nx = (x / SIZE) * 2 - 1;
  const ny = (y / SIZE) * 2 - 1;
  if (!inShield(nx, ny)) return BG;
  if (inKeyhole(nx, ny)) return BG;
  // A rim, so the shield still reads as a shape against a light background.
  if (!inShield(nx / 0.90, (ny - CY) / 0.90 + CY)) return ACCENT;
  return SHIELD;
};

const CY = 0.03;                                 // the shield's visual centre

/** Rounded top, curving in to a point: the usual shield. */
function inShield(x, y) {
  const top = -0.80, shoulder = 0.10, bottom = 0.86, halfW = 0.62, r = 0.17;
  if (y < top || y > bottom) return false;
  if (y <= shoulder) {
    const dy = Math.min(0, y - (top + r));       // only the top corners round off
    const w = halfW - (r - Math.sqrt(Math.max(0, r * r - dy * dy)));
    return Math.abs(x) <= w;
  }
  // Quarter ellipse: full width at the shoulder, vertical tangent at the tip.
  const t = (y - shoulder) / (bottom - shoulder);
  return Math.abs(x) <= halfW * Math.sqrt(Math.max(0, 1 - t * t));
}

/** Circle over a tapering slot. */
function inKeyhole(x, y) {
  const cy = -0.20, r = 0.19;
  if (x * x + (y - cy) * (y - cy) <= r * r) return true;
  if (y > cy && y < 0.34) {
    const t = (y - cy) / (0.34 - cy);
    return Math.abs(x) <= 0.105 * (1 - 0.45 * t);
  }
  return false;
}

// ── render ────────────────────
function main() {
  const raw = Buffer.alloc(SIZE * (SIZE * 3 + 1));
  let p = 0;
  for (let y = 0; y < SIZE; y++) {
    raw[p++] = 0;                                  // filter: none
    for (let x = 0; x < SIZE; x++) {
      let r = 0, g = 0, b = 0;
      for (let sy = 0; sy < SS; sy++) {
        for (let sx = 0; sx < SS; sx++) {
          const c = px(x + (sx + 0.5) / SS, y + (sy + 0.5) / SS);
          r += c[0]; g += c[1]; b += c[2];
        }
      }
      const n = SS * SS;
      raw[p++] = Math.round(r / n);
      raw[p++] = Math.round(g / n);
      raw[p++] = Math.round(b / n);
    }
  }

  const out = join(dirname(fileURLToPath(import.meta.url)), 'icon.png');
  writeFileSync(out, png(raw, SIZE, SIZE));
  console.log(`wrote ${out}`);
}

// ── PNG container ─────────────────────────────────────────────────────────────
function png(rawData, w, h) {
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(w, 0);
  ihdr.writeUInt32BE(h, 4);
  ihdr[8] = 8;                                   // bit depth
  ihdr[9] = 2;                                   // colour type: truecolour
  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk('IHDR', ihdr),
    chunk('IDAT', deflateSync(rawData, { level: 9 })),
    chunk('IEND', Buffer.alloc(0)),
  ]);
}

function chunk(type, data) {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length, 0);
  const body = Buffer.concat([Buffer.from(type, 'ascii'), data]);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(body) >>> 0, 0);
  return Buffer.concat([len, body, crc]);
}

const TABLE = (() => {
  const t = new Int32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[n] = c;
  }
  return t;
})();

function crc32(buf) {
  let c = -1;
  for (const byte of buf) c = TABLE[(c ^ byte) & 0xff] ^ (c >>> 8);
  return c ^ -1;
}

// Called last: the CRC table and the helpers above are const declarations,
// which are not initialised until the module body has finished running.
main();
