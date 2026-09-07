import assert from "node:assert/strict";
import { planChinaRouting } from "../modules/china-routing.js";
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
console.log("mainland routing preset tests passed");
