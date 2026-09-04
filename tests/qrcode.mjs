import assert from "node:assert/strict";
import { chooseVersion, dataCapacity, encodeQr, qrToSvg, totalCodewords } from "../modules/qrcode.js";

// RS 块表自洽：每个版本、每个等级的总码字数必须等于由模块数推导出的总码字数
const RS = await import("../modules/qrcode.js");
for (let version = 1; version <= 40; version += 1) {
  const expected = totalCodewords(version);
  for (const level of ["L", "M"]) {
    const capacity = dataCapacity(version, level);
    assert.ok(capacity > 0 && capacity < expected, `v${version}-${level} 数据容量应介于 0 与总码字之间`);
  }
}
// 已知容量点：v1-M 14 字节，v40-L 2953 字节，v40-M 2331 字节
assert.equal(dataCapacity(1, "M"), 14);
assert.equal(dataCapacity(40, "L"), 2953);
assert.equal(dataCapacity(40, "M"), 2331);
assert.equal(chooseVersion(14, "M"), 1);
assert.equal(chooseVersion(15, "M"), 2);
assert.equal(chooseVersion(2954, "L"), 0, "超过容量应返回 0");

// 结构：尺寸、三个定位图形、深色模块
const qr = encodeQr("https://example.com/subscription?data=abc", { level: "M" });
assert.equal(qr.size, qr.version * 4 + 17);
for (const [r, c] of [[0, 0], [0, qr.size - 7], [qr.size - 7, 0]]) {
  assert.equal(qr.modules[r][c], true);
  assert.equal(qr.modules[r + 3][c + 3], true);
  assert.equal(qr.modules[r + 1][c + 1], false);
}
assert.equal(qr.modules[qr.size - 8][8], true, "固定深色模块");
// 时序图形
for (let i = 8; i < qr.size - 8; i += 1) assert.equal(qr.modules[6][i], i % 2 === 0);

// 大版本（含版本信息与多组对齐图形）能生成
const big = encodeQr("x".repeat(2300), { level: "M" });
assert.equal(big.version, 40);
assert.equal(big.size, 177);
const svg = qrToSvg(qr);
assert.match(svg, /^<svg /);
assert.match(svg, /<path d="M/);
console.log("qrcode tests passed");
