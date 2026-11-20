import assert from "node:assert/strict";
import { CHINA_RULE_SETS, planChinaRouting, repairLegacyChinaRuleSets, stripChinaPreset } from "../modules/china-routing.js";
import { hostRuleSetsOnServer } from "../modules/rule-set-hosting.js";
import { normalizeGroup, normalizeOutbound } from "../modules/outbound.js";
import { planFakeipPreset } from "../modules/fakeip.js";
import { normalizeRouteRule } from "../modules/route.js";
import { normalizeDnsRule } from "../modules/dns.js";
import { emptyState, fakeServer, configFromState } from "./fakeip-fixtures.mjs";

const initial = emptyState();
const untouched = structuredClone(initial);
const result = planChinaRouting(initial);
assert.deepEqual(result.errors, []);
assert.deepEqual(initial, untouched, "预览不能改写原状态");
assert.deepEqual(planChinaRouting(result.state).state, result.state, "重复补齐不重复创建");
const config = configFromState(result.state);
assert.equal(config.route.rule_set.length, 2);
assert.ok(config.route.rule_set.every(set => set.http_client && !set.download_detour));
assert.ok(config.route.rules.every(rule => rule.outbound === "direct"));
assert.deepEqual(config.route.rules[0].rules, [{ clash_mode: "Global", invert: true }, { rule_set: ["geosite-cn"] }]);
assert.equal(config.dns.rules[0].server, "cn-local-dns");
assert.equal(config.experimental.cache_file.path, "custom-cache.db");

const custom = emptyState();
custom.route.final = "direct";
custom.route.rules = [normalizeRouteRule({ id: "override", domain: "baidu.com", action: "reject" }), normalizeRouteRule({ id: "all", action: "route", outbound: "direct" })];
custom.dns.rules = [normalizeDnsRule({ id: "dns-override", domain: "baidu.com", action: "reject" })];
const supplemented = planChinaRouting(custom);
assert.deepEqual(supplemented.errors, []);
assert.deepEqual(supplemented.state.route.rules[0], custom.route.rules[0]);
assert.equal(supplemented.state.route.rules.at(-1).id, "all");
assert.deepEqual(supplemented.state.dns.rules[0], custom.dns.rules[0]);
assert.equal(supplemented.state.route.final, "direct", "显式默认出口保持不变");

for (const fakeFirst of [true, false]) {
  let state = emptyState();
  if (fakeFirst) state = planFakeipPreset(state, fakeServer()).state;
  const plan = planChinaRouting(state);
  assert.deepEqual(plan.errors, []);
  state = fakeFirst ? plan.state : planFakeipPreset(plan.state, fakeServer()).state;
  const built = configFromState(state);
  const domestic = built.dns.rules.findIndex(rule => rule.rules?.some(item => item.rule_set?.includes("geosite-cn")));
  const fallback = built.dns.rules.findIndex(rule => rule.server === "fakeip");
  assert.ok(domestic >= 0 && domestic < fallback, "两种应用顺序下大陆解析均优先于 FakeIP 通用兜底");
  assert.deepEqual(planChinaRouting(state).state, state);
}
const disabled = structuredClone(result.state);
disabled.route.ruleSets[0].enabled = false;
assert.match(planChinaRouting(disabled).errors.join(), /已停用/);
const wrongDirect = emptyState();
wrongDirect.nodes = [{ type: "socks", tag: "direct", server: "127.0.0.1", port: 1080 }];
assert.match(planChinaRouting(wrongDirect).errors.join(), /Direct 出站/);
// 下载方式：有代理时只经代理（不带 domain_resolver，避免本地解析被污染）；无代理时用非空 http_client 直连
const withProxy = emptyState();
withProxy.nodes = [normalizeOutbound({ id: "n1", type: "trojan", tag: "node-a", server: "a.example.net", port: 443, password: "p" })];
withProxy.groups = [normalizeGroup({ id: "g", type: "selector", tag: "proxy", includeAllNodes: true })];
const proxiedSets = configFromState(planChinaRouting(withProxy).state).route.rule_set;
assert.deepEqual(proxiedSets.map(set => set.http_client), [{ detour: "proxy" }, { detour: "proxy" }]);
assert.deepEqual(config.route.rule_set.map(set => set.http_client), [{ domain_resolver: "cn-local-dns" }, { domain_resolver: "cn-local-dns" }], "无代理时直连下载");
const planned = planChinaRouting(withProxy);
assert.equal(planned.state.nodes, withProxy.nodes, "生成时按引用共享节点，不复制大数组");

// 旧版预设写入的 {detour, domain_resolver} 原样修复；用户自定义的值不动
const legacy = structuredClone(planned.state);
legacy.route.ruleSets = legacy.route.ruleSets.map(set => ({ ...set, httpClientJson: JSON.stringify({ detour: "proxy", domain_resolver: "cn-local-dns" }) }));
assert.deepEqual(repairLegacyChinaRuleSets(legacy).route.ruleSets.map(set => JSON.parse(set.httpClientJson)), [{ detour: "proxy" }, { detour: "proxy" }]);
const customized = structuredClone(legacy);
customized.route.ruleSets[0].httpClientJson = JSON.stringify({ detour: "proxy", domain_resolver: "cn-local-dns", headers: { "x-a": "1" } });
assert.equal(repairLegacyChinaRuleSets(customized).route.ruleSets[0].httpClientJson, customized.route.ruleSets[0].httpClientJson);
const directLegacy = structuredClone(legacy);
directLegacy.route.ruleSets[0].httpClientJson = JSON.stringify({ detour: "direct", domain_resolver: "cn-local-dns" });
assert.equal(repairLegacyChinaRuleSets(directLegacy).route.ruleSets[0].httpClientJson, directLegacy.route.ruleSets[0].httpClientJson, "直连下载需要本地解析，保留");

// 收回为开关时只去掉预设生成的条目
const stripped = stripChinaPreset(planned.state);
assert.deepEqual(stripped.route.ruleSets, withProxy.route.ruleSets);
assert.deepEqual(stripped.route.rules, withProxy.route.rules);
assert.deepEqual(stripped.dns.rules, withProxy.dns.rules);
assert.deepEqual(planChinaRouting(stripped).state.route.rules, planned.state.route.rules, "去掉后重新展开得到同样的规则");

// 生成订阅时换成订阅服务器上的镜像：只在服务器报告就绪时替换，直连并使用本地解析器
const proxiedConfig = configFromState(planned.state);
const ready = { ruleSets: { "geosite-cn": true, "geoip-cn": true } };
const hosted = hostRuleSetsOnServer(proxiedConfig, "https://sub.example.org/base/", ready);
assert.deepEqual(hosted.hosted, ["geosite-cn", "geoip-cn"]);
assert.deepEqual(hosted.config.route.rule_set.map(set => [set.url, set.http_client]), [
  ["https://sub.example.org/base/rule-sets/geosite-cn.srs", { domain_resolver: "cn-local-dns" }],
  ["https://sub.example.org/base/rule-sets/geoip-cn.srs", { domain_resolver: "cn-local-dns" }]
]);
assert.equal(proxiedConfig.route.rule_set[0].url, CHINA_RULE_SETS[0].url, "不修改传入的配置");
const partial = hostRuleSetsOnServer(proxiedConfig, "https://sub.example.org/", { ruleSets: { "geosite-cn": true, "geoip-cn": false } });
assert.deepEqual(partial.hosted, ["geosite-cn"]);
assert.deepEqual(partial.config.route.rule_set[1].http_client, { detour: "proxy" }, "未就绪的文件保持原下载方式");
assert.equal(hostRuleSetsOnServer(proxiedConfig, "https://old.example.org/", { tokenRequired: false }).config, proxiedConfig, "旧版服务器不提供规则集时原样返回");
const customSet = structuredClone(proxiedConfig);
customSet.route.rule_set[0].url = "https://mirror.example.org/geosite-cn.srs";
assert.deepEqual(hostRuleSetsOnServer(customSet, "https://sub.example.org/", ready).hosted, ["geoip-cn"], "自定义地址的规则集不替换");

console.log("mainland routing preset tests passed");
