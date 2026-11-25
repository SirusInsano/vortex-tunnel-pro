const fs = require('fs');
const path = require('path');
const zlib = require('zlib');

// CRC32 table for valid PNG chunks
const crcTable = new Uint32Array(256);
for (let n = 0; n < 256; n++) {
  let c = n;
  for (let k = 0; k < 8; k++) {
    c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  }
  crcTable[n] = c >>> 0;
}

function crc32(buf) {
  let c = 0xffffffff;
  for (let i = 0; i < buf.length; i++) {
    c = crcTable[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
  }
  return (c ^ 0xffffffff) >>> 0;
}

function makeChunk(typeStr, dataBuf) {
  const typeBuf = Buffer.from(typeStr, 'ascii');
  const lenBuf = Buffer.alloc(4);
  lenBuf.writeUInt32BE(dataBuf.length, 0);
  const crcInput = Buffer.concat([typeBuf, dataBuf]);
  const crcBuf = Buffer.alloc(4);
  crcBuf.writeUInt32BE(crc32(crcInput), 0);
  return Buffer.concat([lenBuf, typeBuf, dataBuf, crcBuf]);
}

function writePng(filePath, width, height, rgba) {
  const stride = width * 4;
  const raw = Buffer.alloc((stride + 1) * height);
  for (let y = 0; y < height; y++) {
    const rowStart = y * (stride + 1);
    raw[rowStart] = 0; // filter 0
    rgba.copy(raw, rowStart + 1, y * stride, (y + 1) * stride);
  }
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(width, 0);
  ihdr.writeUInt32BE(height, 4);
  ihdr[8] = 8; // bit depth
  ihdr[9] = 6; // RGBA
  ihdr[10] = 0;
  ihdr[11] = 0;
  ihdr[12] = 0;

  const idat = zlib.deflateSync(raw, { level: 9 });
  const sig = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
  const png = Buffer.concat([
    sig,
    makeChunk('IHDR', ihdr),
    makeChunk('IDAT', idat),
    makeChunk('IEND', Buffer.alloc(0))
  ]);
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, png);
}

function pointInPoly(x, y, poly) {
  let inside = false;
  for (let i = 0, j = poly.length - 1; i < poly.length; j = i++) {
    const xi = poly[i][0], yi = poly[i][1];
    const xj = poly[j][0], yj = poly[j][1];
    const intersect = yi > y !== yj > y && x < ((xj - xi) * (y - yi)) / (yj - yi) + xi;
    if (intersect) inside = !inside;
  }
  return inside;
}

function distToSeg(px, py, x1, y1, x2, y2) {
  const dx = x2 - x1, dy = y2 - y1;
  const l2 = dx * dx + dy * dy;
  if (l2 === 0) return Math.hypot(px - x1, py - y1);
  const t = Math.max(0, Math.min(1, ((px - x1) * dx + (py - y1) * dy) / l2));
  return Math.hypot(px - (x1 + t * dx), py - (y1 + t * dy));
}

function renderVortexIcon(size) {
  const buf = Buffer.alloc(size * size * 4);
  const cx = size * 0.5;
  const cy = size * 0.5;
  const rad = size * 0.48;

  const bolt = [
    [0.08, -0.58],
    [-0.34, 0.06],
    [-0.02, 0.06],
    [-0.12, 0.58],
    [0.36, -0.08],
    [0.03, -0.08]
  ];

  const shield = [
    [0.0, -0.76],
    [0.62, -0.44],
    [0.54, 0.34],
    [0.0, 0.78],
    [-0.54, 0.34],
    [-0.62, -0.44]
  ];

  for (let y = 0; y < size; y++) {
    const ny = (y - cy) / rad;
    for (let x = 0; x < size; x++) {
      const nx = (x - cx) / rad;
      const idx = (y * size + x) * 4;

      const squircle = Math.pow(Math.pow(Math.abs(nx), 4.2) + Math.pow(Math.abs(ny), 4.2), 1 / 4.2);
      if (squircle > 1.0) continue;

      const edgeAlpha = Math.max(0, Math.min(1, (1.0 - squircle) * size * 0.35));
      const rDist = Math.hypot(nx, ny);
      const angle = Math.atan2(ny, nx);

      const swirl = Math.sin(angle * 3.0 - rDist * 7.5) * 0.5 + 0.5;
      const ringGlow = Math.exp(-Math.pow(rDist - 0.64, 2) / 0.012);
      const coreGlow = Math.exp(-(rDist * rDist) / 0.18);

      let r = 8 + 14 * coreGlow + 10 * swirl * ringGlow;
      let g = 14 + 55 * coreGlow + 170 * ringGlow * (0.4 + 0.6 * swirl);
      let b = 26 + 85 * coreGlow + 235 * ringGlow * (1.0 - 0.4 * swirl);

      let minSDist = 999;
      for (let i = 0; i < shield.length; i++) {
        const [x1, y1] = shield[i];
        const [x2, y2] = shield[(i + 1) % shield.length];
        const d = distToSeg(nx, ny, x1, y1, x2, y2);
        if (d < minSDist) minSDist = d;
      }

      if (pointInPoly(nx, ny, shield)) {
        r += 6;
        g += 28 * (1 - rDist);
        b += 45 * (1 - rDist);
      }

      const shieldStroke = Math.exp(-(minSDist * minSDist) / 0.0014);
      const tGrad = (ny + 0.8) / 1.6;
      const sg = 245 * (1 - tGrad) + 185 * tGrad;
      const sb = 135 * (1 - tGrad) + 255 * tGrad;
      g += sg * shieldStroke;
      b += sb * shieldStroke;

      let minBDist = 999;
      for (let i = 0; i < bolt.length; i++) {
        const [x1, y1] = bolt[i];
        const [x2, y2] = bolt[(i + 1) % bolt.length];
        const d = distToSeg(nx, ny, x1, y1, x2, y2);
        if (d < minBDist) minBDist = d;
      }

      const boltBloom = Math.exp(-(minBDist * minBDist) / 0.0048);
      r += 25 * boltBloom;
      g += 250 * boltBloom;
      b += 175 * boltBloom;

      if (pointInPoly(nx, ny, bolt)) {
        r = 215 + 40 * (1 - tGrad);
        g = 255;
        b = 240 + 15 * tGrad;
      }

      buf[idx] = Math.max(0, Math.min(255, Math.round(r)));
      buf[idx + 1] = Math.max(0, Math.min(255, Math.round(g)));
      buf[idx + 2] = Math.max(0, Math.min(255, Math.round(b)));
      buf[idx + 3] = Math.max(0, Math.min(255, Math.round(edgeAlpha * 255)));
    }
  }
  return buf;
}

const targets = [
  ['F:\\vortex-tunnel\\android\\app\\src\\main\\res\\mipmap-mdpi\\ic_launcher.png', 48],
  ['F:\\vortex-tunnel\\android\\app\\src\\main\\res\\mipmap-hdpi\\ic_launcher.png', 72],
  ['F:\\vortex-tunnel\\android\\app\\src\\main\\res\\mipmap-xhdpi\\ic_launcher.png', 96],
  ['F:\\vortex-tunnel\\android\\app\\src\\main\\res\\mipmap-xxhdpi\\ic_launcher.png', 144],
  ['F:\\vortex-tunnel\\android\\app\\src\\main\\res\\mipmap-xxxhdpi\\ic_launcher.png', 192],
  ['F:\\vortex-tunnel\\public\\icon.png', 256],
  ['C:\\Users\\SirusInsano\\.gemini\\antigravity\\brain\\d605f418-ae3a-417c-9b70-85747b2cf168\\vortex_icon_preview.png', 256]
];

const cache = {};
for (const [filePath, sz] of targets) {
  if (!cache[sz]) cache[sz] = renderVortexIcon(sz);
  writePng(filePath, sz, sz, cache[sz]);
  console.log(`Generated ${filePath} (${sz}x${sz})`);
}
