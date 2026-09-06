import assert from "node:assert/strict";
import { planFakeipPreset, planFakeipRemoval, planFakeipServerSave, hasFakeipPreset } from "../modules/fakeip.js";
import { normalizeInbound } from "../modules/inbound.js";
import { normalizeDnsServer, normalizeDnsRule } from "../modules/dns.js";
import { normalizeRouteRule } from "../modules/route.js";
import { normalizeTailscaleEndpoint } from "../modules/tailscale.js";
import { importConfig } from "../modules/importer.js";
import { detectConflicts } from "../modules/conflicts.js";
import { emptyState, fakeServer, configFromState } from "./fakeip-fixtures.mjs";

const clone = (state) => structuredClone(state);
const apply = (state, server = fakeServer(), options) => {
  const result = planFakeipPreset(state, server, options);
  assert.deepEqual(result.errors, [], result.errors.join("\n"));
  return result.state;
};
const fallback = (state, tag = "fakeip") => state.dns.rules.find((rule) => rule.server === tag);
const base = emptyState();
const original = clone(base);
const applied = apply(base);
assert.deepEqual(base, original, "预览不能写入原状态");
assert.equal(hasFakeipPreset(base, "fake-test"), false);
assert.equal(hasFakeipPreset(applied, "fake-test"), true);
let config = configFromState(applied);
assert.deepEqual(config.dns.rules.at(-1), { query_type: ["A", "AAAA"], action: "route", server: "fakeip" });
assert.deepEqual(config.dns.rules[0].domain, ["localhost"]);
assert.deepEqual(config.dns.rules[0].domain_suffix, [".lan", ".local", ".home.arpa"]);
assert.equal(config.dns.final, "local-dns");
assert.equal(config.route.default_domain_resolver, "local-dns");
assert.deepEqual(config.route.rules[0], { inbound: ["tun-in"], port: [53], action: "hijack-dns" });
assert.deepEqual(config.inbounds[0].address, ["172.19.0.1/30", "fdfe:dcba:9876::1/126"]);
assert.equal(config.inbounds[0].stack, "mixed");
assert.equal(config.inbounds[0].dns_mode, "hijack");
assert.equal(config.experimental.cache_file.store_fakeip, true);
assert.equal(config.experimental.cache_file.path, "custom-cache.db");
assert.equal(JSON.stringify(config).includes("fakeipPresets"), false);
assert.deepEqual(apply(applied), applied, "重复应用完全幂等，不覆盖最初的还原值");
assert.deepEqual(apply(JSON.parse(JSON.stringify(applied))), applied, "备份往返保留关联记录");

let removed = planFakeipRemoval(applied, "fake-test");
assert.deepEqual(removed.state.inbounds, []);
assert.deepEqual(removed.state.dns.servers, []);
assert.deepEqual(removed.state.dns.rules, []);
assert.deepEqual(removed.state.route.rules, []);
assert.equal(removed.state.route.autoDetectInterface, "off");
assert.equal(removed.state.serviceState.cacheEnabled, false);
assert.equal(removed.state.serviceState.cacheStoreFakeip, false);
assert.deepEqual(removed.warnings, []);
assert.equal(applied.inbounds.length, 1, "清理预览也不写入");

// 原有 DNS、TUN、规则、固定接口和缓存路径不会取得删除权限。
const existing = emptyState();
existing.dns.servers.push(normalizeDnsServer({ id: "real", type: "udp", tag: "real", server: "1.1.1.1" }));
existing.dns.final = "real";
existing.dns.defaultDomainResolver = "real";
existing.dns.rules.push(normalizeDnsRule({ id: "my-dns", domainSuffix: ".example.com", server: "real" }));
existing.inbounds.push(normalizeInbound({ id: "my-tun", type: "tun", tag: "my-tun", autoRoute: false, dnsMode: "disabled", mtu: "1400" }));
existing.route.rules.push(normalizeRouteRule({ id: "my-route", domainSuffix: ".example.com", outbound: "direct" }));
existing.route.defaultInterface = "en0";
const beforeExisting = clone(existing);
const withExisting = apply(existing);
assert.equal(withExisting.dns.final, "real");
assert.equal(withExisting.dns.defaultDomainResolver, "real");
assert.deepEqual(withExisting.dns.rules[0], existing.dns.rules[0]);
assert.deepEqual(withExisting.route.rules.at(-1), existing.route.rules[0]);
removed = planFakeipRemoval(withExisting, "fake-test");
delete removed.state.dns.fakeipPresets;
assert.deepEqual(removed.state, beforeExisting);
const compliantTun = clone(existing);
compliantTun.inbounds[0].autoRoute = true;
const compliantApplied = apply(compliantTun);
compliantApplied.inbounds[0].autoRoute = false;
assert.ok(planFakeipPreset(compliantApplied, fakeServer()).errors.some((text) => text.includes("手动设置")), "预设复用但未修改的字段，后来手改也应保留并提示");

// 手改生成对象、单字段、外部引用及依赖恢复。
const edited = clone(applied);
edited.inbounds[0].mtu = "1300";
edited.dns.rules[0].domainSuffix += ", .corp";
edited.dns.final = "my-resolver";
removed = planFakeipRemoval(edited, "fake-test");
assert.equal(removed.state.inbounds[0].mtu, "1300");
assert.equal(removed.state.dns.final, "my-resolver");
assert.ok(removed.state.dns.servers.some((item) => item.tag === "local-dns"));
assert.equal(removed.state.route.autoDetectInterface, "on");
assert.ok(removed.preserved.some((text) => text.includes("已手动修改")));
const referenced = clone(applied);
referenced.route.rules.push(normalizeRouteRule({ id: "custom", inbound: "tun-in", outbound: "direct" }));
referenced.dns.rules.push(normalizeDnsRule({ id: "custom-dns", domain: "example.test", server: "local-dns" }));
removed = planFakeipRemoval(referenced, "fake-test");
assert.equal(removed.state.inbounds.length, 1);
assert.equal(removed.state.route.autoDetectInterface, "on", "保留有外部引用的 TUN 时不能还原成路由环路");
assert.equal(removed.state.dns.servers[0].tag, "local-dns");

// 补齐删除项，不复制已有项；由表单地址族或所选 TUN 改变的规则同步更新。
const missing = clone(applied);
missing.dns.rules = [];
missing.dns.servers = missing.dns.servers.filter((item) => item.type === "fakeip");
missing.route.rules = [];
missing.inbounds = [];
assert.deepEqual(apply(missing), applied);
const v4 = apply(base, fakeServer({ inet6Range: "" }));
assert.equal(fallback(v4).queryType, "A");
const v6 = apply(base, fakeServer({ inet4Range: "" }));
assert.equal(fallback(v6).queryType, "AAAA");
const strategy = clone(applied);
strategy.dns.strategy = "ipv4_only";
assert.equal(fallback(apply(strategy)).queryType, "A");
strategy.inbounds[0].address = "fdfe:dcba:9876::1/126";
assert.ok(planFakeipPreset(strategy, fakeServer()).errors.some((text) => text.includes("共同可用")));
const tuns = emptyState();
tuns.inbounds = [
  normalizeInbound({ id: "tun-a", type: "tun", tag: "a", interfaceName: "utun9", address: "172.19.0.1/30" }),
  normalizeInbound({ id: "tun-b", type: "tun", tag: "b", interfaceName: "utun10", address: "fdfe:dcba:9876::1/126" })
];
assert.ok(planFakeipPreset(tuns, fakeServer()).errors.some((text) => text.includes("请选择")));
const chosen = apply(tuns, fakeServer(), { tunId: "tun-a" });
assert.equal(fallback(chosen).queryType, "A");
const switched = apply(chosen, fakeServer(), { tunId: "tun-b" });
assert.equal(fallback(switched).queryType, "AAAA");
assert.equal(switched.route.rules[0].inbound, "b");

// 重命名只更新仍保持原样的自有引用；复制和普通导入没有清理权限。
const rename = planFakeipServerSave(applied, fakeServer({ tag: "renamed" }));
assert.equal(fallback(rename.state, "renamed").server, "renamed");
assert.equal(planFakeipRemoval(rename.state, "fake-test").warnings.length, 0);
const renameManual = clone(applied);
fallback(renameManual).domain = "example.com";
const manualResult = planFakeipServerSave(renameManual, fakeServer({ tag: "new" }));
assert.equal(fallback(manualResult.state).server, "fakeip");
assert.ok(manualResult.warnings.length);
const duplicated = planFakeipServerSave(applied, fakeServer({ id: "copy", tag: "copy" })).state;
assert.equal(hasFakeipPreset(duplicated, "copy"), false);
assert.equal(planFakeipRemoval(duplicated, "copy").state.inbounds.length, 1);
const imported = importConfig(configFromState(applied)).state;
const importedFake = imported.dns.servers.find((item) => item.type === "fakeip");
assert.equal(hasFakeipPreset(imported, importedFake.id), false);
assert.equal(planFakeipRemoval(imported, importedFake.id).state.inbounds.length, 1);

// 仅删除明确保留配套设置，残留引用仍阻断输出。
const only = planFakeipRemoval(applied, "fake-test", { cleanup: false });
assert.deepEqual(only.state.inbounds, applied.inbounds);
assert.deepEqual(only.state.dns.rules, applied.dns.rules);
assert.deepEqual(only.state.serviceState, applied.serviceState);
assert.ok(only.warnings.some((text) => text.includes("仍有引用")));
assert.ok(detectConflicts(configFromState(only.state)).some((item) => item.level === "error" && item.message.includes("fakeip")));

// 内核只允许一个启用的 FakeIP，但切换档案后可保留多份历史与共享资源。
const inactive = clone(applied);
inactive.dns.servers.find((item) => item.type === "fakeip").enabled = false;
fallback(inactive).enabled = false;
const shared = apply(inactive, fakeServer({ id: "second", tag: "second" }));
const localResource = shared.dns.fakeipPresets.resources.find((item) => item.role === "本地解析器");
assert.deepEqual(localResource.owners, ["fake-test", "second"]);
const firstRelease = planFakeipRemoval(shared, "fake-test").state;
assert.equal(firstRelease.serviceState.cacheStoreFakeip, true);
assert.equal(firstRelease.inbounds.length, 1);
const lastRelease = planFakeipRemoval(firstRelease, "second").state;
assert.equal(lastRelease.serviceState.cacheEnabled, false);
assert.equal(lastRelease.serviceState.cacheStoreFakeip, false);
assert.equal(lastRelease.inbounds.length, 0);
const explicitlyKept = planFakeipRemoval(shared, "fake-test", { cleanup: false }).state;
assert.equal(planFakeipRemoval(explicitlyKept, "second").state.inbounds.length, 1);

// 阻断地址池错误、接口冲突、TUN 路由排除/覆盖缺口和前置终止规则。
for (const server of [fakeServer({ inet4Range: "999.1.0.0/16" }), fakeServer({ inet4Range: "fc00::/18" }), fakeServer({ inet6Range: ":::1/64" }), fakeServer({ inet4Range: "172.19.0.0/16" })]) {
  assert.ok(planFakeipPreset(base, server).errors.length);
}
for (const values of [{ routeExcludeAddress: "198.18.0.0/16" }, { routeAddress: "10.0.0.0/8" }]) {
  const state = emptyState();
  state.inbounds = [normalizeInbound({ id: "tun", type: "tun", tag: "tun", ...values })];
  assert.ok(planFakeipPreset(state, fakeServer()).errors.some((text) => /覆盖/.test(text)));
}
for (const values of [{ action: "route", server: "real" }, { action: "reject", queryType: "A" }, { action: "predefined", queryType: "AAAA" }]) {
  const state = clone(existing);
  state.dns.rules.unshift(normalizeDnsRule({ id: "catchall", ...values }));
  assert.ok(planFakeipPreset(state, fakeServer()).errors.some((text) => text.includes("遮挡")));
}
assert.ok(planFakeipPreset(applied, fakeServer({ id: "another", tag: "another", inet4Range: "198.20.0.0/15", inet6Range: "fd00::/18" })).errors.some((text) => text.includes("多个 FakeIP")));
const manualCache = clone(applied);
manualCache.serviceState.cacheEnabled = false;
assert.ok(planFakeipPreset(manualCache, fakeServer()).errors.some((text) => text.includes("手动关闭")));
const malformed = clone(existing);
malformed.dns.rules[0].advancedJson = "{";
assert.ok(planFakeipPreset(malformed, fakeServer()).errors.length, "无效高级 JSON 返回预览错误，不抛出页面异常");

const logical = clone(existing);
logical.dns.rules.unshift(normalizeDnsRule({ id: "logical-all", ruleType: "logical", mode: "or", rulesJson: '[{"query_type":"A"},{"query_type":"AAAA"}]', server: "real" }));
assert.ok(planFakeipPreset(logical, fakeServer()).errors.some((text) => text.includes("遮挡")));
const advancedTun = clone(existing);
advancedTun.inbounds[0].advancedJson = '{"route_exclude_address":["198.18.0.0/15"]}';
assert.ok(planFakeipPreset(advancedTun, fakeServer()).errors.some((text) => text.includes("排除范围")));
const notDefault = clone(existing);
notDefault.dns.final = "";
notDefault.dns.defaultDomainResolver = "";
assert.equal(apply(notDefault).dns.final, "local-dns", "缺省解析器使用直连 Local DNS");
const magic = emptyState();
magic.endpoints = [normalizeTailscaleEndpoint({ id: "tail", tag: "tail", magicDns: true })];
const withMagic = apply(magic);
assert.equal(configFromState(withMagic).dns.rules[0].preferred_by, "tail-dns");
assert.deepEqual(withMagic.endpoints, magic.endpoints);
assert.equal(configFromState(planFakeipRemoval(withMagic, "fake-test").state).dns.servers[0].tag, "tail-dns", "清理不能删除 MagicDNS");

console.log("fakeip preset and cleanup tests passed");
