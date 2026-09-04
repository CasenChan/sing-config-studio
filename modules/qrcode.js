// 自包含的 QR Code 编码器：Byte 模式，纠错等级 L / M，版本 1–40。
// 依据 ISO/IEC 18004；不依赖第三方库。

const EC_LEVELS = { L: 1, M: 0 };

// 每个版本的 RS 块：[块数, 每块总码字, 每块数据码字, (第二组同样三项)]
const RS_BLOCKS = {
  L: [
    [1,26,19],[1,44,34],[1,70,55],[1,100,80],[1,134,108],[2,86,68],[2,98,78],[2,121,97],[2,146,116],[2,86,68,2,87,69],
    [4,101,81],[2,116,92,2,117,93],[4,133,107],[3,145,115,1,146,116],[5,109,87,1,110,88],[5,122,98,1,123,99],[1,135,107,5,136,108],[5,150,120,1,151,121],[3,141,113,4,142,114],[3,135,107,5,136,108],
    [4,144,116,4,145,117],[2,139,111,7,140,112],[4,151,121,5,152,122],[6,147,117,4,148,118],[8,132,106,4,133,107],[10,142,114,2,143,115],[8,152,122,4,153,123],[3,147,117,10,148,118],[7,146,116,7,147,117],[5,145,115,10,146,116],
    [13,145,115,3,146,116],[17,145,115],[17,145,115,1,146,116],[13,145,115,6,146,116],[12,151,121,7,152,122],[6,151,121,14,152,122],[17,152,122,4,153,123],[4,152,122,18,153,123],[20,147,117,4,148,118],[19,148,118,6,149,119]
  ],
  M: [
    [1,26,16],[1,44,28],[1,70,44],[2,50,32],[2,67,43],[4,43,27],[4,49,31],[2,60,38,2,61,39],[3,58,36,2,59,37],[4,69,43,1,70,44],
    [1,80,50,4,81,51],[6,58,36,2,59,37],[8,59,37,1,60,38],[4,64,40,5,65,41],[5,65,41,5,66,42],[7,73,45,3,74,46],[10,74,46,1,75,47],[9,69,43,4,70,44],[3,70,44,11,71,45],[3,67,41,13,68,42],
    [17,68,42],[17,74,46],[4,75,47,14,76,48],[6,73,45,14,74,46],[8,75,47,13,76,48],[19,74,46,4,75,47],[22,73,45,3,74,46],[3,73,45,23,74,46],[21,73,45,7,74,46],[19,75,47,10,76,48],
    [2,74,46,29,75,47],[10,74,46,23,75,47],[14,74,46,21,75,47],[14,74,46,23,75,47],[12,75,47,26,76,48],[6,75,47,34,76,48],[29,74,46,14,75,47],[13,74,46,32,75,47],[40,75,47,7,76,48],[18,75,47,31,76,48]
  ]
};

const ALIGNMENT = [
  [], [], [6,18],[6,22],[6,26],[6,30],[6,34],[6,22,38],[6,24,42],[6,26,46],[6,28,50],
  [6,30,54],[6,32,58],[6,34,62],[6,26,46,66],[6,26,48,70],[6,26,50,74],[6,30,54,78],[6,30,56,82],[6,30,58,86],[6,34,62,90],
  [6,28,50,72,94],[6,26,50,74,98],[6,30,54,78,102],[6,28,54,80,106],[6,32,58,84,110],[6,30,58,86,114],[6,34,62,90,118],[6,26,50,74,98,122],[6,30,54,78,102,126],[6,26,52,78,104,130],
  [6,30,56,82,108,134],[6,34,60,86,112,138],[6,30,58,86,114,142],[6,34,62,90,118,146],[6,30,54,78,102,126,150],[6,24,50,76,102,128,154],[6,28,54,80,106,132,158],[6,32,58,84,110,136,162],[6,26,54,82,110,138,166],[6,30,58,86,114,142,170]
];

// GF(256)
const EXP = new Uint8Array(512);
const LOG = new Uint8Array(256);
(() => {
  let x = 1;
  for (let i = 0; i < 255; i += 1) {
    EXP[i] = x;
    LOG[x] = i;
    x <<= 1;
    if (x & 0x100) x ^= 0x11d;
  }
  for (let i = 255; i < 512; i += 1) EXP[i] = EXP[i - 255];
})();

function gfMul(a, b) {
  return a && b ? EXP[LOG[a] + LOG[b]] : 0;
}

function generatorPoly(degree) {
  let poly = [1];
  for (let i = 0; i < degree; i += 1) {
    const next = new Array(poly.length + 1).fill(0);
    for (let j = 0; j < poly.length; j += 1) {
      next[j] ^= poly[j];
      next[j + 1] ^= gfMul(poly[j], EXP[i]);
    }
    poly = next;
  }
  return poly;
}

function rsEncode(data, ecCount) {
  const gen = generatorPoly(ecCount);
  const result = new Array(ecCount).fill(0);
  for (const byte of data) {
    const factor = byte ^ result[0];
    result.shift();
    result.push(0);
    if (factor) for (let i = 0; i < ecCount; i += 1) result[i] ^= gfMul(gen[i + 1], factor);
  }
  return result;
}

function blocksFor(version, level) {
  const row = RS_BLOCKS[level][version - 1];
  const blocks = [];
  for (let i = 0; i < row.length; i += 3) for (let n = 0; n < row[i]; n += 1) blocks.push({ total: row[i + 1], data: row[i + 2] });
  return blocks;
}

export function totalCodewords(version) {
  const size = version * 4 + 17;
  let modules = size * size;
  modules -= 3 * 64; // finder + separators (8x8 each)
  const align = ALIGNMENT[version].length;
  if (align) modules -= 25 * (align * align - 3);
  modules -= 2 * (size - 16); // timing
  modules -= 31; // format info + dark module
  if (version >= 7) modules -= 36;
  return Math.floor(modules / 8);
}

function countBits(version) {
  return version <= 9 ? 8 : 16;
}

export function dataCapacity(version, level) {
  const dataCodewords = blocksFor(version, level).reduce((sum, block) => sum + block.data, 0);
  return Math.floor((dataCodewords * 8 - 4 - countBits(version)) / 8);
}

export function chooseVersion(byteLength, level) {
  for (let version = 1; version <= 40; version += 1) if (dataCapacity(version, level) >= byteLength) return version;
  return 0;
}

class BitBuffer {
  constructor() { this.bits = []; }
  put(value, length) { for (let i = length - 1; i >= 0; i -= 1) this.bits.push((value >>> i) & 1); }
  get length() { return this.bits.length; }
}

function buildCodewords(bytes, version, level) {
  const blocks = blocksFor(version, level);
  const dataCodewords = blocks.reduce((sum, block) => sum + block.data, 0);
  const buffer = new BitBuffer();
  buffer.put(0b0100, 4);
  buffer.put(bytes.length, countBits(version));
  for (const byte of bytes) buffer.put(byte, 8);
  const capacity = dataCodewords * 8;
  buffer.put(0, Math.min(4, capacity - buffer.length));
  while (buffer.length % 8) buffer.bits.push(0);
  const data = [];
  for (let i = 0; i < buffer.length; i += 8) data.push(parseInt(buffer.bits.slice(i, i + 8).join(""), 2));
  for (let pad = 0xec; data.length < dataCodewords; pad ^= 0xec ^ 0x11) data.push(pad);

  const dataBlocks = [];
  const ecBlocks = [];
  let offset = 0;
  for (const block of blocks) {
    const chunk = data.slice(offset, offset + block.data);
    offset += block.data;
    dataBlocks.push(chunk);
    ecBlocks.push(rsEncode(chunk, block.total - block.data));
  }
  const out = [];
  const maxData = Math.max(...dataBlocks.map((b) => b.length));
  for (let i = 0; i < maxData; i += 1) for (const block of dataBlocks) if (i < block.length) out.push(block[i]);
  const maxEc = Math.max(...ecBlocks.map((b) => b.length));
  for (let i = 0; i < maxEc; i += 1) for (const block of ecBlocks) if (i < block.length) out.push(block[i]);
  return out;
}

function makeMatrix(version) {
  const size = version * 4 + 17;
  const modules = Array.from({ length: size }, () => new Array(size).fill(null));
  const reserved = Array.from({ length: size }, () => new Array(size).fill(false));
  const set = (r, c, v) => { modules[r][c] = v; reserved[r][c] = true; };

  const finder = (row, col) => {
    for (let r = -1; r <= 7; r += 1) for (let c = -1; c <= 7; c += 1) {
      const rr = row + r; const cc = col + c;
      if (rr < 0 || cc < 0 || rr >= size || cc >= size) continue;
      const on = r >= 0 && r <= 6 && c >= 0 && c <= 6 && (r === 0 || r === 6 || c === 0 || c === 6 || (r >= 2 && r <= 4 && c >= 2 && c <= 4));
      set(rr, cc, on);
    }
  };
  finder(0, 0); finder(0, size - 7); finder(size - 7, 0);

  const positions = ALIGNMENT[version];
  for (const r of positions) for (const c of positions) {
    if (reserved[r][c]) continue;
    for (let dr = -2; dr <= 2; dr += 1) for (let dc = -2; dc <= 2; dc += 1) {
      set(r + dr, c + dc, Math.max(Math.abs(dr), Math.abs(dc)) !== 1);
    }
  }
  for (let i = 8; i < size - 8; i += 1) {
    if (!reserved[6][i]) set(6, i, i % 2 === 0);
    if (!reserved[i][6]) set(i, 6, i % 2 === 0);
  }
  // 预留格式信息与版本信息区
  for (let i = 0; i < 9; i += 1) { if (!reserved[8][i]) set(8, i, false); if (!reserved[i][8]) set(i, 8, false); }
  for (let i = 0; i < 8; i += 1) { set(8, size - 1 - i, false); set(size - 1 - i, 8, false); }
  set(size - 8, 8, true);
  if (version >= 7) {
    for (let i = 0; i < 6; i += 1) for (let j = 0; j < 3; j += 1) { set(i, size - 11 + j, false); set(size - 11 + j, i, false); }
  }
  return { size, modules, reserved };
}

function placeData(matrix, codewords) {
  const { size, modules, reserved } = matrix;
  const bits = [];
  for (const byte of codewords) for (let i = 7; i >= 0; i -= 1) bits.push((byte >> i) & 1);
  let index = 0;
  let upward = true;
  for (let col = size - 1; col > 0; col -= 2) {
    if (col === 6) col -= 1;
    for (let step = 0; step < size; step += 1) {
      const row = upward ? size - 1 - step : step;
      for (const c of [col, col - 1]) {
        if (reserved[row][c]) continue;
        modules[row][c] = index < bits.length ? bits[index] === 1 : false;
        index += 1;
      }
    }
    upward = !upward;
  }
}

const MASKS = [
  (r, c) => (r + c) % 2 === 0,
  (r) => r % 2 === 0,
  (r, c) => c % 3 === 0,
  (r, c) => (r + c) % 3 === 0,
  (r, c) => (Math.floor(r / 2) + Math.floor(c / 3)) % 2 === 0,
  (r, c) => ((r * c) % 2) + ((r * c) % 3) === 0,
  (r, c) => (((r * c) % 2) + ((r * c) % 3)) % 2 === 0,
  (r, c) => (((r + c) % 2) + ((r * c) % 3)) % 2 === 0
];

function formatBits(level, mask) {
  const data = (EC_LEVELS[level] << 3) | mask;
  let rem = data << 10;
  for (let i = 14; i >= 10; i -= 1) if ((rem >> i) & 1) rem ^= 0x537 << (i - 10);
  return ((data << 10) | rem) ^ 0x5412;
}

function versionBits(version) {
  let rem = version << 12;
  for (let i = 17; i >= 12; i -= 1) if ((rem >> i) & 1) rem ^= 0x1f25 << (i - 12);
  return (version << 12) | rem;
}

function writeFormat(matrix, level, mask) {
  const { size, modules } = matrix;
  const bits = formatBits(level, mask);
  for (let i = 0; i < 15; i += 1) {
    const bit = ((bits >> i) & 1) === 1;
    // 左上
    if (i < 6) modules[i][8] = bit;
    else if (i < 8) modules[i + 1][8] = bit;
    else modules[8][14 - i] = bit;
    // 右上 / 左下
    if (i < 8) modules[8][size - 1 - i] = bit;
    else modules[size - 15 + i][8] = bit;
  }
  modules[size - 8][8] = true;
}

function writeVersion(matrix, version) {
  if (version < 7) return;
  const { size, modules } = matrix;
  const bits = versionBits(version);
  for (let i = 0; i < 18; i += 1) {
    const bit = ((bits >> i) & 1) === 1;
    modules[Math.floor(i / 3)][size - 11 + (i % 3)] = bit;
    modules[size - 11 + (i % 3)][Math.floor(i / 3)] = bit;
  }
}

function penalty(modules, size) {
  let score = 0;
  for (let r = 0; r < size; r += 1) {
    let run = 1;
    for (let c = 1; c < size; c += 1) {
      if (modules[r][c] === modules[r][c - 1]) { run += 1; if (run === 5) score += 3; else if (run > 5) score += 1; } else run = 1;
    }
  }
  for (let c = 0; c < size; c += 1) {
    let run = 1;
    for (let r = 1; r < size; r += 1) {
      if (modules[r][c] === modules[r - 1][c]) { run += 1; if (run === 5) score += 3; else if (run > 5) score += 1; } else run = 1;
    }
  }
  for (let r = 0; r < size - 1; r += 1) for (let c = 0; c < size - 1; c += 1) {
    const v = modules[r][c];
    if (v === modules[r][c + 1] && v === modules[r + 1][c] && v === modules[r + 1][c + 1]) score += 3;
  }
  const pattern = [true, false, true, true, true, false, true];
  const hasPattern = (get) => {
    for (let i = 0; i < 7; i += 1) if (get(i) !== pattern[i]) return false;
    return true;
  };
  for (let r = 0; r < size; r += 1) for (let c = 0; c <= size - 7; c += 1) {
    if (hasPattern((i) => modules[r][c + i])) {
      if ((c >= 4 && !modules[r].slice(c - 4, c).some(Boolean)) || (c + 11 <= size && !modules[r].slice(c + 7, c + 11).some(Boolean))) score += 40;
    }
    if (hasPattern((i) => modules[c + i][r])) {
      const before = c >= 4 && ![0, 1, 2, 3].some((i) => modules[c - 4 + i][r]);
      const after = c + 11 <= size && ![0, 1, 2, 3].some((i) => modules[c + 7 + i][r]);
      if (before || after) score += 40;
    }
  }
  let dark = 0;
  for (const row of modules) for (const v of row) if (v) dark += 1;
  const ratio = Math.abs((dark * 100) / (size * size) - 50);
  score += Math.floor(ratio / 5) * 10;
  return score;
}

export function encodeQr(text, { level = "M" } = {}) {
  if (!(level in EC_LEVELS)) throw new Error("纠错等级只支持 L 或 M");
  const bytes = new TextEncoder().encode(text);
  const version = chooseVersion(bytes.length, level);
  if (!version) return null;
  const codewords = buildCodewords(bytes, version, level);
  let best = null;
  for (let mask = 0; mask < 8; mask += 1) {
    const matrix = makeMatrix(version);
    placeData(matrix, codewords);
    const { size, modules, reserved } = matrix;
    for (let r = 0; r < size; r += 1) for (let c = 0; c < size; c += 1) if (!reserved[r][c] && MASKS[mask](r, c)) modules[r][c] = !modules[r][c];
    writeFormat(matrix, level, mask);
    writeVersion(matrix, version);
    const score = penalty(modules, size);
    if (!best || score < best.score) best = { score, mask, size, modules, version, level };
  }
  return { version: best.version, level, mask: best.mask, size: best.size, modules: best.modules };
}

export function qrToSvg(qr, { module = 4, quiet = 4, dark = "#111", light = "#fff" } = {}) {
  const total = (qr.size + quiet * 2) * module;
  let path = "";
  for (let r = 0; r < qr.size; r += 1) for (let c = 0; c < qr.size; c += 1) {
    if (qr.modules[r][c]) path += `M${(c + quiet) * module} ${(r + quiet) * module}h${module}v${module}h-${module}z`;
  }
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${total} ${total}" width="${total}" height="${total}" shape-rendering="crispEdges" role="img" aria-label="QR Code"><rect width="100%" height="100%" fill="${light}"/><path d="${path}" fill="${dark}"/></svg>`;
}
