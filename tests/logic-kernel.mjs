// 仅使用本机 HTTP 规则集与回环监听，不创建 TUN、不连接真实代理或目标站点。
import assert from "node:assert/strict";
import { createServer as httpServer } from "node:http";
import { createServer as netServer } from "node:net";
import { spawn, spawnSync } from "node:child_process";
import { mkdir, mkdtemp, writeFile } from "node:fs/promises";
import { resolve, join } from "node:path";
import { importConfig } from "../modules/importer.js";
import { planChinaRouting } from "../modules/china-routing.js";
import { detectConflicts, hasBlockingConflicts } from "../modules/conflicts.js";
import { configFromState } from "./fakeip-fixtures.mjs";

const bin = process.env.SING_BOX_BIN;
assert.ok(bin, "请设置 SING_BOX_BIN 为 sing-box 1.14 可执行文件");
const version = spawnSync(bin, ["version"], { encoding: "utf8" });
assert.match(version.stdout, /sing-box version 1\.14\./);
const output = resolve("output/logic-kernel");
await mkdir(output, { recursive: true });
const directory = await mkdtemp(join(output, "run-"));
const results = [];
const requests = [];
const server = httpServer((request, response) => {
  requests.push({ url: request.url, client: request.headers["x-client"] });
  response.setHeader("content-type", "application/json");
  response.end(JSON.stringify({ version: 3, rules: [{ domain: ["example.com"] }] }));
});
await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
async function verify(name, config) {
  const path = join(directory, name + ".json");
  await writeFile(path, JSON.stringify(config, null, 2));
  const checked = spawnSync(bin, ["check", "-c", path], { encoding: "utf8", timeout: 15000 });
  assert.equal(checked.status, 0, checked.stderr);
  const child = spawn(bin, ["run", "-c", path], { cwd: directory, stdio: ["ignore", "pipe", "pipe"] });
  let log = "", timer;
  const closed = new Promise(resolve => child.once("close", resolve));
  try {
    await new Promise((resolve, reject) => {
      timer = setTimeout(() => reject(new Error(name + " startup timeout: " + log)), 8000);
      const receive = data => { log += data; if (log.includes("sing-box started")) resolve(); };
      child.stdout.on("data", receive);
      child.stderr.on("data", receive);
      child.once("error", reject);
      child.once("close", code => { if (!log.includes("sing-box started")) reject(new Error(name + " exit " + code + ": " + log)); });
    });
    results.push(name + ": check and startup passed");
  } finally {
    clearTimeout(timer);
    if (child.exitCode === null && child.signalCode === null) child.kill();
    await closed;
    await writeFile(join(directory, name + ".log"), log.replace(/\x1b\[[0-9;]*m/g, ""));
  }
}
try {
  const minimal = {
    log: { level: "info" }, inbounds: [], outbounds: [{ type: "direct", tag: "direct" }],
    dns: { servers: [{ type: "local", tag: "local" }], final: "local" },
    route: { final: "direct", default_domain_resolver: { server: "local", strategy: "ipv4_only", disable_cache: true } }
  };
  const url = "http://127.0.0.1:" + server.address().port + "/rules.json";
  for (const mode of ["explicit", "default"]) {
    const source = {
      ...structuredClone(minimal),
      http_clients: [{ tag: "rules-client", domain_resolver: "local", headers: { "X-Client": "preserved-" + mode } }],
      route: { ...minimal.route, default_http_client: "rules-client", rule_set: [{ type: "remote", tag: "local-rules", format: "source", url, ...(mode === "explicit" ? { http_client: "rules-client" } : {}) }] }
    };
    const imported = configFromState(importConfig(source).state);
    assert.deepEqual(imported.http_clients, source.http_clients);
    assert.deepEqual(imported.route.default_domain_resolver, source.route.default_domain_resolver);
    const before = requests.length;
    await verify("http-client-" + mode + "-round-trip", imported);
    assert.ok(requests.slice(before).some(request => request.client === "preserved-" + mode), "规则集必须确实使用导入保留的 HTTP Client");
  }
  const plan = planChinaRouting(importConfig(minimal).state);
  assert.deepEqual(plan.errors, []);
  const china = configFromState(plan.state);
  assert.ok(china.route.rule_set.every(set => !set.http_client.detour));
  for (const set of china.route.rule_set) { set.format = "source"; set.url = url; }
  china.experimental.cache_file.path = join(directory, "china-cache.db");
  await verify("mainland-without-proxy", china);

  const probe = netServer();
  await new Promise(resolve => probe.listen(0, "127.0.0.1", resolve));
  const port = probe.address().port;
  await new Promise(resolve => probe.close(resolve));
  const listeners = { ...minimal, inbounds: ["tcp", "udp"].map(network => ({ type: "direct", tag: network, network, listen: "127.0.0.1", listen_port: port, override_address: "127.0.0.1", override_port: 9 })) };
  assert.equal(hasBlockingConflicts(detectConflicts(listeners)), false);
  await verify("same-port-tcp-and-udp", listeners);
  await writeFile(join(output, "verification.txt"), version.stdout + "\n" + results.join("\n") + "\nNo TUN, external proxy or target-site traffic.\n");
  console.log(results.join("\n"));
} finally { await new Promise(resolve => server.close(resolve)); }
