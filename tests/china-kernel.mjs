// 使用真实 sing-box 路由器和官方 SRS；出口接本机 HTTP 接收器，不创建 TUN 或访问目标网站。
import assert from "node:assert/strict";
import { createServer as httpServer } from "node:http";
import { createServer as netServer, connect } from "node:net";
import { once } from "node:events";
import { spawn, spawnSync } from "node:child_process";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";

const bin = process.env.SING_BOX_BIN;
assert.ok(bin, "请设置 SING_BOX_BIN 为 sing-box 1.14 可执行文件");
const directory = resolve("output/china-kernel");
await mkdir(directory, { recursive: true });
const version = spawnSync(bin, ["version"], { encoding: "utf8" });
assert.match(version.stdout, /sing-box version 1\.14\./);
for (const [tag, repo] of [["geosite-cn", "sing-geosite"], ["geoip-cn", "sing-geoip"]]) {
  const response = await fetch(`https://raw.githubusercontent.com/SagerNet/${repo}/rule-set/${tag}.srs`, { signal: AbortSignal.timeout(30000) });
  assert.equal(response.status, 200);
  await writeFile(`${directory}/${tag}.srs`, Buffer.from(await response.arrayBuffer()));
}
const defaultConfig = JSON.parse(await readFile("output/playwright/china-default-config.json", "utf8"));
const defaultCheck = spawnSync(bin, ["check", "-c", resolve("output/playwright/china-default-config.json")], { encoding: "utf8", timeout: 30000 });
assert.equal(defaultCheck.status, 0, defaultCheck.stderr);
const sinks = [];
const sockets = new Set();
const received = [];
async function sink(label) {
  const server = httpServer();
  server.on("connect", (request, socket) => {
    received.push({ label, destination: request.url });
    sockets.add(socket);
    socket.on("close", () => sockets.delete(socket));
    socket.on("error", () => {});
    socket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
  });
  await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
  sinks.push(server);
  return server.address().port;
}
async function freePort() {
  const server = netServer();
  await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
  const port = server.address().port;
  await new Promise(resolve => server.close(resolve));
  return port;
}
const directPort = await sink("direct");
const proxyPort = await sink("proxy");
const socksPort = await freePort(), apiPort = await freePort(), dnsPort = await freePort();
const config = structuredClone(defaultConfig);
delete config.$schema;
config.log = { level: "debug", disabled: false };
config.inbounds = [
  { type: "mixed", tag: "test-in", listen: "127.0.0.1", listen_port: socksPort },
  { type: "direct", tag: "dns-in", listen: "127.0.0.1", listen_port: dnsPort }
];
config.outbounds = [{ type: "http", tag: "direct", server: "127.0.0.1", server_port: directPort }, { type: "http", tag: "proxy", server: "127.0.0.1", server_port: proxyPort }];
config.route.rule_set = config.route.rule_set.map(set => ({ type: "local", tag: set.tag, format: "binary", path: `${directory}/${set.tag}.srs` }));
config.route.rules.unshift({ inbound: ["dns-in"], action: "hijack-dns" });
config.route.auto_detect_interface = false;
config.experimental = { clash_api: { external_controller: `127.0.0.1:${apiPort}`, default_mode: "Rule" }, cache_file: { enabled: true, path: `${directory}/runtime-cache.db`, store_fakeip: true } };
const predefined = { "baidu.com": ["114.114.114.114"], "qq.com": ["114.114.114.114"], "www.google.com": ["8.8.8.8"], "example.com": ["8.8.8.8"] };
config.dns.servers = config.dns.servers.map(server => ({ type: "hosts", tag: server.tag, predefined }));
config.dns.servers.push({ type: "fakeip", tag: "test-fakeip", inet4_range: "198.18.0.0/15" });
config.dns.rules.push({ query_type: ["A"], action: "route", server: "test-fakeip" });
const path = `${directory}/runtime.json`;
await writeFile(path, JSON.stringify(config, null, 2));
const check = spawnSync(bin, ["check", "-c", path], { encoding: "utf8" });
assert.equal(check.status, 0, check.stderr);
let output = "";
const child = spawn(bin, ["run", "-c", path], { stdio: ["ignore", "pipe", "pipe"] });
child.stdout.on("data", chunk => { output += chunk; });
child.stderr.on("data", chunk => { output += chunk; });
const pause = ms => new Promise(resolve => setTimeout(resolve, ms));
async function tcp(port) {
  const socket = connect(port, "127.0.0.1");
  socket.setTimeout(5000, () => socket.destroy(new Error("test timed out")));
  await once(socket, "connect");
  return socket;
}
async function routeDestination(host, expected) {
  const socket = await tcp(socksPort);
  const start = received.length;
  try {
    let data = once(socket, "data");
    socket.write(Buffer.from([5, 1, 0]));
    assert.equal((await data)[0][1], 0);
    const address = /^\d+\.\d+\.\d+\.\d+$/.test(host) ? Buffer.from([1, ...host.split(".").map(Number)]) : Buffer.concat([Buffer.from([3, Buffer.byteLength(host)]), Buffer.from(host)]);
    data = once(socket, "data");
    socket.write(Buffer.concat([Buffer.from([5, 1, 0]), address, Buffer.from([0, 80])]));
    // 提供 HTTP 头使默认 sniff 规则可立即完成（域名仍以 SOCKS 目标为准）。
    socket.write(Buffer.from(`GET / HTTP/1.1\r\nHost: ${host}\r\n\r\n`));
    assert.equal((await data)[0][1], 0);
    for (let i = 0; received.length === start && i < 30; i++) await pause(50);
    assert.equal(received[start]?.label, expected, `${host}: ${JSON.stringify(received.slice(start))}\n${output}`);
  } finally { socket.destroy(); }
}
async function dnsA(domain) {
  const socket = await tcp(dnsPort);
  try {
    const labels = domain.split(".").flatMap(label => [Buffer.from([label.length]), Buffer.from(label)]);
    const query = Buffer.concat([Buffer.from([0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0]), ...labels, Buffer.from([0, 0, 1, 0, 1])]);
    const length = Buffer.alloc(2); length.writeUInt16BE(query.length);
    socket.write(Buffer.concat([length, query]));
    let bytes = Buffer.alloc(0);
    for await (const chunk of socket) {
      bytes = Buffer.concat([bytes, chunk]);
      if (bytes.length >= 2 && bytes.length >= bytes.readUInt16BE(0) + 2) break;
    }
    assert.ok(bytes.readUInt16BE(8) > 0, "DNS 必须返回 A 记录");
    return [...bytes.subarray(-4)].join(".");
  } finally { socket.destroy(); }
}
try {
  let ready = false;
  for (let i = 0; i < 80; i++) {
    try { ready = (await fetch(`http://127.0.0.1:${apiPort}/configs`)).ok; } catch {}
    if (ready) break;
    if (child.exitCode !== null) break;
    await pause(100);
  }
  assert.ok(ready, output);
  for (const host of ["baidu.com", "qq.com", "114.114.114.114"]) await routeDestination(host, "direct");
  for (const host of ["www.google.com", "8.8.8.8"]) await routeDestination(host, "proxy");
  const mainland = await dnsA("baidu.com");
  assert.equal(mainland, "114.114.114.114", "大陆 DNS 应使用真实解析");
  const foreign = await dnsA("www.google.com");
  assert.match(foreign, /^198\.(18|19)\./, "其他 A 查询仍使用 FakeIP");
  await routeDestination(mainland, "direct");
  await routeDestination(foreign, "proxy");
  for (const [mode, domain, expected] of [["Global", "baidu.com", "proxy"], ["Direct", "www.google.com", "direct"], ["Rule", "baidu.com", "direct"]]) {
    const response = await fetch(`http://127.0.0.1:${apiPort}/configs`, { method: "PATCH", headers: { "content-type": "application/json" }, body: JSON.stringify({ mode }) });
    assert.ok(response.ok);
    await routeDestination(domain, expected);
  }
  await writeFile(`${directory}/verification.txt`, `${version.stdout}\nDefault remote-rule config check passed.\nRuntime Rule/Global/Direct, mainland domains and IPs, foreign destinations, real mainland DNS and FakeIP mapping passed.\nTraffic ended at local mock HTTP outbounds; no TUN or external target website connections.\n${JSON.stringify(received, null, 2)}\n`);
  console.log("sing-box 1.14 mainland routing runtime tests passed");
} finally {
  await writeFile(`${directory}/runtime.log`, output);
  if (child.exitCode === null) { const ended = once(child, "exit"); child.kill(); await ended; }
  for (const socket of sockets) socket.destroy();
  await Promise.all(sinks.map(server => new Promise(resolve => server.close(resolve))));
}
