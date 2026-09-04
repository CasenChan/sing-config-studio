// 订阅端点：明文 base64url 与 deflate 压缩两种 data 编码都要能解出同一份配置
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { deflateRawSync } from "node:zlib";

const port = Number(process.env.TEST_PORT || 4198);
const server = spawn(process.execPath, ["server.mjs"], { env: { ...process.env, PORT: String(port), SUBSCRIPTION_TOKEN: "" }, stdio: "ignore" });
const base = `http://127.0.0.1:${port}`;
for (let i = 0; i < 40; i += 1) { try { await fetch(`${base}/health`); break; } catch { await new Promise((r) => setTimeout(r, 100)); } }
try {
  const config = { log: { level: "info" }, inbounds: [{ type: "mixed", tag: "m", listen_port: 7890 }], outbounds: [{ type: "direct", tag: "direct" }], dns: { servers: [{ type: "local", tag: "l" }] } };
  const json = JSON.stringify(config);
  const b64url = (buf) => buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  const plain = await fetch(`${base}/subscription?data=${b64url(Buffer.from(json))}`);
  assert.equal(plain.status, 200);
  assert.deepEqual(JSON.parse(await plain.text()), config);
  const compressed = deflateRawSync(Buffer.from(json));
  assert.ok(compressed.length < Buffer.byteLength(json), "deflate 应缩短");
  const inflated = await fetch(`${base}/subscription?data=${b64url(compressed)}&enc=deflate`);
  assert.equal(inflated.status, 200);
  assert.deepEqual(JSON.parse(await inflated.text()), config);
  assert.equal(inflated.headers.get("profile-update-interval"), "60");
  const bad = await fetch(`${base}/subscription?data=${b64url(compressed)}&enc=gzip`);
  assert.equal(bad.status, 400);
  const notConfig = await fetch(`${base}/subscription?data=${b64url(Buffer.from('{"hello":1}'))}`);
  assert.equal(notConfig.status, 400, "不是 sing-box 配置的数据应被拒绝");
  const status = await (await fetch(`${base}/api/status`)).json();
  assert.equal(status.tokenRequired, false);
  console.log("subscription endpoint tests passed");
} finally {
  server.kill();
}
