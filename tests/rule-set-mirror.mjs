import assert from "node:assert/strict";
import { createServer } from "node:http";
import { mkdtemp, readFile, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { isBinaryRuleSet, ruleSetMirror } from "../server/rule-set-mirror.mjs";
import { startTestServer } from "./server-helper.mjs";

const srs = (label) => Buffer.concat([Buffer.from("SRS"), Buffer.from([1]), Buffer.from(label)]);
const upstream = { "geosite-cn": { status: 200, body: srs("site-v1") }, "geoip-cn": { status: 200, body: Buffer.from("<html>blocked</html>") } };
const server = createServer((req, res) => {
  const tag = req.url.replace(/^\//, "").replace(/\.srs$/, "");
  const item = upstream[tag];
  if (!item) { res.statusCode = 404; return res.end(); }
  res.statusCode = item.status;
  res.end(item.body);
});
await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
const upstreamBase = `http://127.0.0.1:${server.address().port}/`;
const quiet = { warn() {} };

assert.equal(isBinaryRuleSet(srs("x")), true);
assert.equal(isBinaryRuleSet(Buffer.from("<html>")), false);

// 同步：只接受 SRS；失败时保留上一份有效文件；重启从磁盘恢复
const directory = await mkdtemp(join(tmpdir(), "rule-set-mirror-"));
try {
  const mirror = ruleSetMirror(directory, { upstreamBase, sync: false, logger: quiet });
  await mirror.start();
  assert.deepEqual(mirror.status(), { "geosite-cn": false, "geoip-cn": false });
  await mirror.sync();
  assert.deepEqual(mirror.status(), { "geosite-cn": true, "geoip-cn": false }, "非 SRS 内容（如被劫持的 HTML）不能被缓存");
  assert.deepEqual(mirror.get("geosite-cn").content, srs("site-v1"));
  const firstEtag = mirror.get("geosite-cn").etag;

  upstream["geosite-cn"] = { status: 502, body: Buffer.from("bad gateway") };
  await mirror.sync();
  assert.deepEqual(mirror.get("geosite-cn").content, srs("site-v1"), "同步失败时保留上一份有效文件");

  upstream["geosite-cn"] = { status: 200, body: srs("site-v2") };
  upstream["geoip-cn"] = { status: 200, body: srs("ip-v1") };
  await mirror.sync();
  assert.deepEqual(mirror.get("geosite-cn").content, srs("site-v2"));
  assert.notEqual(mirror.get("geosite-cn").etag, firstEtag);
  assert.deepEqual(mirror.status(), { "geosite-cn": true, "geoip-cn": true });
  assert.deepEqual((await readdir(join(directory, "rule-sets"))).sort(), ["geoip-cn.srs", "geosite-cn.srs"], "原子写入不留下临时文件");

  const restarted = ruleSetMirror(directory, { upstreamBase: "http://127.0.0.1:1/", sync: false, logger: quiet });
  await restarted.start();
  assert.deepEqual(restarted.status(), { "geosite-cn": true, "geoip-cn": true }, "重启后无需联网即可提供已同步的文件");
  assert.deepEqual(await readFile(join(directory, "rule-sets", "geoip-cn.srs")), srs("ip-v1"));
} finally {
  await rm(directory, { recursive: true, force: true });
}

// 目录不可写时不影响服务启动，只是没有镜像
const blocked = await mkdtemp(join(tmpdir(), "rule-set-blocked-"));
try {
  const { writeFile } = await import("node:fs/promises");
  await writeFile(join(blocked, "not-a-directory"), "");
  const unusable = ruleSetMirror(join(blocked, "not-a-directory"), { upstreamBase, logger: quiet });
  await unusable.start();
  assert.deepEqual(unusable.status(), { "geosite-cn": false, "geoip-cn": false });
  unusable.stop();
} finally {
  await rm(blocked, { recursive: true, force: true });
}

// 服务端路由：公开、不要求 token、不限流，支持 ETag / HEAD；未同步时 503
upstream["geosite-cn"] = { status: 200, body: srs("served") };
upstream["geoip-cn"] = { status: 503, body: Buffer.from("later") };
const app = await startTestServer({ RULE_SET_SYNC: "on", RULE_SET_UPSTREAM: upstreamBase, SUBSCRIPTION_TOKEN: "private-token", RATE_LIMIT_MAX: "2" });
try {
  let status;
  for (let attempt = 0; attempt < 50; attempt += 1) {
    status = await (await fetch(`${app.base}/api/status`)).json();
    if (status.ruleSets?.["geosite-cn"]) break;
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  assert.deepEqual(status.ruleSets, { "geosite-cn": true, "geoip-cn": false });

  for (let index = 0; index < 5; index += 1) {
    const response = await fetch(`${app.base}/rule-sets/geosite-cn.srs`);
    assert.equal(response.status, 200, "规则集不受订阅 token 与限流约束");
    assert.deepEqual(Buffer.from(await response.arrayBuffer()), srs("served"));
  }
  const first = await fetch(`${app.base}/rule-sets/geosite-cn.srs`);
  assert.equal(first.headers.get("content-type"), "application/octet-stream");
  const etag = first.headers.get("etag");
  assert.match(etag, /^"[A-Za-z0-9_-]{32}"$/);
  assert.equal((await fetch(`${app.base}/rule-sets/geosite-cn.srs`, { headers: { "if-none-match": etag } })).status, 304);
  const head = await fetch(`${app.base}/rule-sets/geosite-cn.srs`, { method: "HEAD" });
  assert.equal(head.status, 200);
  assert.equal(Number(head.headers.get("content-length")), srs("served").length);
  assert.equal((await fetch(`${app.base}/rule-sets/geoip-cn.srs`)).status, 503, "未同步成功时明确返回 503");
  assert.equal((await fetch(`${app.base}/rule-sets/geosite-cn.srs`, { method: "POST" })).status, 405);
  for (const path of ["rule-sets/other.srs", "rule-sets/geosite-cn.json", "rule-sets/..%2Fserver.mjs", "rule-sets/geosite-cn.srs/x"]) {
    assert.equal((await fetch(`${app.base}/${path}`)).status, 404, path);
  }
} finally {
  await app.close();
  server.close();
}

console.log("rule-set mirror tests passed: sync validation, keep-last-good, restart, ETag, 503, no token or rate limit");
