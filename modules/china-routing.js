import { buildRouteRule, normalizeRouteRule, normalizeRouteState, normalizeRuleSet } from "./route.js";
import { buildDnsRule, buildDnsServer, normalizeDnsRule, normalizeDnsServer, normalizeDnsState } from "./dns.js";
import { normalizeServiceState } from "./services.js";
import { outboundModule } from "./outbound.js";

export const CHINA_RULE_SETS = Object.freeze([
  { tag: "geosite-cn", url: "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-cn.srs" },
  { tag: "geoip-cn", url: "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-cn.srs" }
]);
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);
const enabled = item => item.enabled !== false;
const unique = (items, key, prefix) => {
  const used = new Set(items.map(item => item[key]));
  let value = prefix;
  for (let n = 2; used.has(value); n += 1) value = `${prefix}-${n}`;
  return value;
};
// 保留已有具体规则的优先级，在不带匹配条件的兜底前补齐。
function fallback(rule, dns, fakeTags) {
  if (rule.clash_mode && rule.clash_mode.toLowerCase() !== "rule") return false;
  const terminal = dns ? ["route", "reject", "predefined", "respond"] : ["route", "reject", "bypass"];
  if (!terminal.includes(rule.action || "route")) return false;
  const keys = ["action", "outbound", "server", "clash_mode", "method", "no_drop", "rcode", "answer", "ns", "extra"];
  if (dns && fakeTags.includes(rule.server)) keys.push("query_type");
  return Object.keys(rule).every(key => keys.includes(key));
}

export function planChinaRouting(source) {
  const state = JSON.parse(JSON.stringify(source));
  state.route = normalizeRouteState(state.route);
  state.dns = normalizeDnsState(state.dns);
  state.serviceState = normalizeServiceState(state.serviceState);
  const result = { state, changes: [], warnings: [], errors: [], preserved: [], summary: "大陆域名和 IP 直连；已有具体规则继续优先，未命中流量使用原来的默认出站。" };
  try {
    const outbounds = outboundModule.extendConfig({}, state).outbounds;
    const direct = outbounds.find(item => item.tag === "direct");
    if (direct?.type !== "direct" || direct.detour) throw new Error("标签 direct 必须是未设置 detour 的 Direct 出站，请先修正该出站");
    const proxy = outbounds.find(item => item.type === "selector") || outbounds.find(item => item.type === "urltest") || outbounds.find(item => !["direct", "block"].includes(item.type));
    // Local 解析器避免在规则集尚未下载时依赖代理 DNS。已有直连 Local 可复用。
    let local = state.dns.servers.find(item => {
      const built = buildDnsServer(item);
      return enabled(item) && built.type === "local" && (!built.detour || built.detour === "direct");
    });
    if (!local) {
      local = normalizeDnsServer({ id: unique(state.dns.servers, "id", "dns-cn-local"), tag: unique(state.dns.servers, "tag", "cn-local-dns"), type: "local" });
      state.dns.servers.push(local);
      result.changes.push(`添加直连 Local DNS：${local.tag}`);
    }
    const realTags = state.dns.servers.filter(item => enabled(item) && item.type !== "fakeip").map(item => item.tag);
    const resolver = state.dns.defaultDomainResolver;
    let resolverTag = resolver;
    if (typeof resolver === "string" && resolver.trim().startsWith("{")) resolverTag = JSON.parse(resolver).server;
    if (!realTags.includes(resolverTag)) {
      state.dns.defaultDomainResolver = local.tag;
      result.changes.push(`节点解析器使用 ${local.tag}，避免缺失解析器或指向 FakeIP`);
    }
    if (!realTags.includes(state.dns.final)) {
      state.dns.final = local.tag;
      result.changes.push(`真实 DNS 默认服务器使用 ${local.tag}`);
    }
    const tags = [];
    for (const preset of CHINA_RULE_SETS) {
      let set = state.route.ruleSets.find(item => item.tag === preset.tag || item.url === preset.url);
      if (set && !enabled(set)) throw new Error(`规则集 ${set.tag} 已停用，请先启用或调整该规则集后再补齐`);
      if (!set) {
        set = normalizeRuleSet({ id: unique(state.route.ruleSets, "id", `ruleset-${preset.tag}`), type: "remote", ...preset, format: "binary", updateInterval: "1d", httpClientMode: "inline", httpClientJson: JSON.stringify({ detour: proxy?.tag || "direct", domain_resolver: local.tag }) });
        state.route.ruleSets.push(set);
        result.changes.push(`添加大陆${preset.tag === "geosite-cn" ? "域名" : "IP"}规则集 ${set.tag}（每日更新）`);
      }
      tags.push(String(set.tag).split(/[,\s]+/)[0]);
    }
    const fakeTags = state.dns.servers.filter(item => item.type === "fakeip").map(item => item.tag);
    const addRule = (list, item, build, dns, label) => {
      const desired = build(item);
      if (list.some(existing => enabled(existing) && same(build(existing), desired))) return;
      item.id = unique(list, "id", item.id);
      const before = list.findIndex(existing => enabled(existing) && fallback(build(existing), dns, fakeTags));
      list.splice(before < 0 ? list.length : before, 0, item);
      result.changes.push(label);
    };
    // 排除 Global，即使该模式的终止规则尚未设置，也不会被大陆直连意外覆盖。
    const conditions = tag => JSON.stringify([{ clash_mode: "Global", invert: true }, { rule_set: [tag] }]);
    tags.forEach((tag, index) => addRule(state.route.rules, normalizeRouteRule({ id: `route-cn-${index ? "ip" : "domain"}`, ruleType: "logical", mode: "and", rulesJson: conditions(tag), action: "route", outbound: "direct" }), buildRouteRule, false, `补齐大陆${index ? "IP" : "域名"} → direct`));
    addRule(state.dns.rules, normalizeDnsRule({ id: "dns-cn-domain", ruleType: "logical", mode: "and", rulesJson: conditions(tags[0]), action: "route", server: local.tag }), buildDnsRule, true, `补齐大陆域名真实解析 → ${local.tag}（放在 FakeIP 通用兜底前）`);
    if (!state.serviceState.cacheEnabled) {
      state.serviceState.cacheEnabled = true;
      result.changes.push("开启规则集缓存，保留已有缓存路径");
    }
    if (!result.changes.length) result.changes.push("大陆直连与解析规则已齐全，无需重复添加");
    result.warnings.push("规则集首次下载需要可用网络与有效节点；下载地址和出口可在规则集中修改。自定义规则和域名例外仍按原顺序优先匹配。");
  } catch (error) { result.errors.push(error.message); }
  return result;
}
