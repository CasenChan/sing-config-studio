// 显式提供 sing-box 1.14 可执行文件；只做 check，不启动系统 TUN。
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdir, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { planFakeipPreset } from "../modules/fakeip.js";
import { normalizeInbound } from "../modules/inbound.js";
import { normalizeDnsRule, normalizeDnsServer } from "../modules/dns.js";
import { normalizeTailscaleEndpoint } from "../modules/tailscale.js";
import { emptyState, fakeServer, configFromState } from "./fakeip-fixtures.mjs";

const bin = process.env.SING_BOX_BIN;
assert.ok(bin, "请设置 SING_BOX_BIN 指向 sing-box 1.14 可执行文件");
const version = spawnSync(bin, ["version"], { encoding: "utf8" });
assert.equal(version.status, 0, version.stderr || version.error?.message);
assert.match(version.stdout, /sing-box version 1\.14\./);
const out = resolve("output/fakeip-kernel");
await mkdir(out, { recursive: true });
const cases = [
  ["dual-stack", emptyState(), fakeServer()],
  ["ipv4", emptyState(), fakeServer({ inet6Range: "" })],
  ["ipv6", emptyState(), fakeServer({ inet4Range: "" })]
];
const existing = emptyState();
existing.dns.servers = [normalizeDnsServer({ id: "real", tag: "real", type: "https", server: "1.1.1.1" })];
existing.dns.final = "real";
existing.dns.defaultDomainResolver = "real";
existing.dns.rules = [normalizeDnsRule({ id: "corp", domainSuffix: ".example.com", server: "real" })];
existing.inbounds = [normalizeInbound({ id: "tun", type: "tun", tag: "tun", address: "172.19.0.1/30", routeAddress: "0.0.0.0/0", dnsAddress: "172.19.0.2" })];
cases.push(["existing-real-dns", existing, fakeServer()]);
const magic = emptyState();
magic.endpoints = [normalizeTailscaleEndpoint({ id: "tail", tag: "tail", type: "tailscale", magicDns: true })];
cases.push(["magic-dns", magic, fakeServer()]);
const checked = [];
for (const [name, source, server] of cases) {
  const plan = planFakeipPreset(source, server);
  assert.deepEqual(plan.errors, [], `${name}: ${plan.errors.join("; ")}`);
  const path = `${out}/${name}.json`;
  await writeFile(path, JSON.stringify(configFromState(plan.state), null, 2));
  checked.push(path);
}
if (existsSync("output/playwright/fakeip-default-config.json")) checked.push(resolve("output/playwright/fakeip-default-config.json"));
for (const path of checked) {
  const result = spawnSync(bin, ["check", "-c", path], { encoding: "utf8", timeout: 30000, cwd: out });
  assert.equal(result.status, 0, `${path}: ${result.stderr || result.error?.message}`);
  console.log(`sing-box 1.14 check passed: ${path}`);
}
await writeFile(`${out}/verification.txt`, `${version.stdout}\n${checked.length} configurations passed sing-box check.\nRuntime TUN/DNS/routing/cache persistence were not tested: this test does not request root or change host routing.\n`);
