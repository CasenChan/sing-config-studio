import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import { sha256, sha256Fallback } from "../modules/sha256.js";
import { subscriptionPayload } from "../modules/subscription-payload.js";

for (const text of ["", "abc", "中文配置🔐", "\ud800", "a".repeat(1_000_000), subscriptionPayload({ data: "abc", name: "订阅" })]) {
  const expected = createHash("sha256").update(text).digest("hex");
  assert.equal(sha256Fallback(new TextEncoder().encode(text)), expected);
  assert.equal(await sha256(text), expected);
}
// 填充边界、多数据块与完整字节范围均与 Node 原生实现交叉检查。
for (const length of [1, 31, 55, 56, 57, 63, 64, 65, 119, 120, 127, 128, 129, 255, 1024, 524288]) {
  const bytes = randomBytes(length);
  assert.equal(sha256Fallback(bytes), createHash("sha256").update(bytes).digest("hex"));
}
console.log("SHA-256 native and HTTP fallback tests passed");
