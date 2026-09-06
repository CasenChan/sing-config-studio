import assert from "node:assert/strict";
import { EventEmitter, once } from "node:events";
import { Readable } from "node:stream";
import { connect } from "node:net";
import { gzipSync } from "node:zlib";
import { symlink, unlink } from "node:fs/promises";
import { startTestServer } from "./server-helper.mjs";
import { fetchRemoteSubscription, isPublicAddress, validateRemoteUrl } from "../server/remote-subscription.mjs";

for (const address of ["127.0.0.1", "10.1.2.3", "169.254.169.254", "100.64.0.1", "198.18.0.1", "198.19.1.2", "0.0.0.0", "192.0.2.1", "224.0.0.1", "::1", "fe80::1", "fc00::1", "::ffff:127.0.0.1", "64:ff9b::7f00:1", "2002:7f00:1::1", "2001:db8::1"])
  assert.equal(isPublicAddress(address), false, address);
for (const address of ["1.1.1.1", "8.8.8.8", "2606:4700:4700::1111"]) assert.equal(isPublicAddress(address), true);
for (const url of ["file:///etc/passwd", "http://localhost", "http://a.localhost./", "http://a.local/", "http://2130706433", "http://0x7f000001", "http://[::ffff:127.0.0.1]", "http://user:password@example.com"])
  await assert.rejects(validateRemoteUrl(url));
await assert.rejects(validateRemoteUrl("https://mixed.example", { resolve: async () => [{ address: "1.1.1.1" }, { address: "10.0.0.1" }] }), /局域网/);

let lookups = 0;
const seen = [];
const resolve = async () => [{ address: ++lookups === 1 ? "1.1.1.1" : "127.0.0.1", family: 4 }];
function mockRequest(responses) {
  return (url, options, callback) => {
    const req = new EventEmitter();
    req.end = () => queueMicrotask(() => {
      options.lookup(url.hostname, { all: true }, (error, addresses) => {
        if (error) return req.emit("error", error);
        seen.push({ url: url.toString(), addresses, agent: options.agent });
        const fixture = responses.shift();
        const response = Readable.from([fixture.body || Buffer.from("nodes")]);
        response.statusCode = fixture.status || 200;
        response.headers = fixture.headers || {};
        callback(response);
      });
    });
    return req;
  };
}
assert.equal((await fetchRemoteSubscription("https://rebind.example:8443/feed", { resolve, request: mockRequest([{}]) })).content, "nodes");
assert.equal(lookups, 1, "连接必须使用已审核的 DNS 地址，不能二次解析");
assert.deepEqual(seen.pop(), { url: "https://rebind.example:8443/feed", addresses: [{ address: "1.1.1.1", family: 4 }], agent: false });
const publicResolve = async () => [{ address: "1.1.1.1", family: 4 }];
await assert.rejects(fetchRemoteSubscription("https://public.example", { resolve: publicResolve, request: mockRequest([{ status: 302, headers: { location: "http://127.0.0.1/private" } }]) }), /局域网/);
lookups = 0;
await assert.rejects(fetchRemoteSubscription("https://rebind.example", { resolve, request: mockRequest([{ status: 302, headers: { location: "/next" } }]) }), /局域网/);
assert.equal(lookups, 2, "每次重定向必须重新审核并锁定 DNS");
const decoded = "example subscription";
assert.equal((await fetchRemoteSubscription("https://public.example", { resolve: publicResolve, request: mockRequest([{ body: gzipSync(decoded), headers: { "content-encoding": "gzip" } }]) })).content, decoded);
await assert.rejects(fetchRemoteSubscription("https://public.example", { resolve: publicResolve, maxBytes: 32, request: mockRequest([{ body: gzipSync("x".repeat(1000)), headers: { "content-encoding": "gzip" } }]) }), /超过/);
await assert.rejects(fetchRemoteSubscription("https://public.example", { resolve: publicResolve, request: mockRequest(Array.from({ length: 4 }, () => ({ status: 302, headers: { location: "/again" } }))) }), /重定向次数/);
// Keep the event loop alive while testing the unref'ed AbortSignal timer.
const timer = setInterval(() => {}, 1000);
try { await assert.rejects(fetchRemoteSubscription("https://slow.example", { timeoutMs: 20, resolve: () => new Promise(() => {}) }), /超时/); }
finally { clearInterval(timer); }

const server = await startTestServer();
const link = new URL(`../modules/security-link-${process.pid}.js`, import.meta.url);
async function rawRequest(target, headers) {
  const socket = connect(Number(new URL(server.base).port), "127.0.0.1");
  socket.setTimeout(3000, () => socket.destroy(new Error("raw request timed out")));
  let data = "";
  socket.on("data", chunk => { data += chunk; });
  await once(socket, "connect");
  const ended = once(socket, "end");
  socket.end(`GET ${target} HTTP/1.1\r\n${headers}\r\nConnection: close\r\n\r\n`);
  await ended;
  return data;
}
try {
  for (const path of ["/", "/app.js", "/styles.css", "/modules/fakeip.js", "/modules/subscription-payload.js"])
    assert.equal((await fetch(new URL(path, server.base))).status, 200, path);
  for (const path of ["/.git/config", "/.env", "/.data/subscription-signing-key", "/server.mjs", "/server/subscription-signing.mjs", "/package.json", "/README.md", "/tests/importer.mjs", "/output/playwright/fakeip-default-config.json", "/modules/../server.mjs", "/modules/%2e%2e%2fserver.mjs", "/%252e%252e/server.mjs"])
    assert.equal((await fetch(new URL(path, server.base))).status, 404, path);
  await symlink(new URL("../server.mjs", import.meta.url), link);
  assert.equal((await fetch(new URL(`/modules/security-link-${process.pid}.js`, server.base))).status, 404, "白名单路径中的符号链接不能泄漏后台文件");
  assert.match(await rawRequest("/%ZZ", "Host: localhost"), /^HTTP\/1\.1 400/);
  for (const headers of ["Host: [", "Host: user@localhost", "Host: localhost:99999", "Host: bad/host", "Host: localhost\r\nHost: second", ""]) {
    assert.match(await rawRequest("/health", headers), /^HTTP\/1\.1 400/, headers);
    assert.equal((await fetch(new URL("health", server.base))).status, 200, "非法 Host 后进程仍正常响应");
  }
  for (const target of ["//evil.example/health", "http://evil.example/health", "/\\evil.example/health"])
    assert.match(await rawRequest(target, "Host: localhost"), /^HTTP\/1\.1 400/);
  const rejected = await fetch(new URL("api/fetch-subscription", server.base), { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ url: new URL("health", server.base).toString() }) });
  assert.equal(rejected.status, 400);
  assert.match((await rejected.json()).error, /局域网/);
  console.log("server isolation, malformed requests and DNS pinning tests passed");
} finally {
  await unlink(link).catch(() => {});
  await server.close();
}
