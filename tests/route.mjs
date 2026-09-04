import assert from "node:assert/strict";
import {
  buildHeadlessRule,
  buildRouteRule,
  buildRouteSection,
  buildRuleSet,
  normalizeHeadlessRule,
  normalizeRouteRule,
  normalizeRuleSet,
  skippedRouteRules,
  validateHeadlessRule,
  validateRouteRule,
  validateRouteState,
  validateRuleSet
} from "../modules/route.js";

const outboundTags = ["direct", "proxy", "auto"];
const context = { outboundTags, ruleSetTags: ["geosite-cn"], dnsServerTags: ["local-dns", "remote-dns"], inboundTags: ["tun-in"] };
const rule = (overrides) => normalizeRouteRule({ id: overrides.id || "r", ...overrides });

// 动作：route / bypass / reject / hijack-dns / route-options / sniff / resolve
const routeRule = rule({ domainSuffix: ".cn, .com.cn", action: "route", outbound: "direct" });
assert.equal(validateRouteRule(routeRule, context), "");
assert.deepEqual(buildRouteRule(routeRule), { domain_suffix: [".cn", ".com.cn"], action: "route", outbound: "direct" });

const sniffRule = rule({ action: "sniff", sniffer: "tls, http", sniffTimeout: "300ms" });
assert.equal(validateRouteRule(sniffRule, context), "");
assert.deepEqual(buildRouteRule(sniffRule), { action: "sniff", sniffer: ["tls", "http"], timeout: "300ms" });
assert.match(validateRouteRule(rule({ action: "sniff", sniffer: "smtp" }), context), /嗅探器无效/);

const hijack = rule({ protocol: "dns", action: "hijack-dns" });
assert.deepEqual(buildRouteRule(hijack), { protocol: ["dns"], action: "hijack-dns" });

const rejectRule = rule({ network: "icmp", action: "reject", rejectMethod: "reply" });
assert.equal(validateRouteRule(rejectRule, context), "");
assert.deepEqual(buildRouteRule(rejectRule), { network: ["icmp"], action: "reject", method: "reply" });
assert.match(validateRouteRule(rule({ action: "reject", rejectMethod: "drop", rejectNoDrop: true }), context), /no_drop/);

const resolveRule = rule({ action: "resolve", resolveServer: "local-dns", resolveStrategy: "prefer_ipv4", resolveTimeout: "3s", resolveDisableOptimisticCache: true, resolveRewriteTtl: "0" });
assert.equal(validateRouteRule(resolveRule, context), "");
assert.deepEqual(buildRouteRule(resolveRule), {
  action: "resolve", server: "local-dns", strategy: "prefer_ipv4", disable_optimistic_cache: true, rewrite_ttl: 0, timeout: "3s"
});
assert.match(validateRouteRule(rule({ action: "resolve", resolveServer: "ghost" }), context), /DNS Server 不存在/);

const options = rule({ action: "route-options", tlsFragment: true, tlsRecordFragment: true, tlsSpoof: "www.example.com", tlsSpoofMethod: "wrong-checksum", udpConnect: true });
assert.equal(validateRouteRule(options, context), "");
assert.deepEqual(buildRouteRule(options), {
  action: "route-options", udp_connect: true, tls_fragment: true, tls_record_fragment: true, tls_spoof: "www.example.com", tls_spoof_method: "wrong-checksum"
});
assert.match(validateRouteRule(rule({ action: "route-options", tlsSpoofMethod: "wrong-checksum" }), context), /伪造 SNI/);

const bypass = rule({ action: "bypass", outbound: "direct", ipIsPrivate: true });
assert.deepEqual(buildRouteRule(bypass), { ip_is_private: true, action: "bypass", outbound: "direct" });

// 匹配条件与引用校验
assert.match(validateRouteRule(rule({ action: "route", outbound: "ghost" }), context), /出站不存在/);
assert.match(validateRouteRule(rule({ action: "route", outbound: "direct", ruleSet: "missing" }), context), /规则集不存在/);
assert.match(validateRouteRule(rule({ action: "route", outbound: "direct", inbound: "ghost-in" }), context), /入站不存在/);
assert.match(validateRouteRule(rule({ action: "route", outbound: "direct", network: "sctp" }), context), /网络无效/);
assert.match(validateRouteRule(rule({ action: "route", outbound: "direct", preferredBy: "openvpn" }), context), /出站偏好路由无效/);
assert.equal(validateRouteRule(rule({ action: "route", outbound: "direct", preferredBy: "tailscale, wireguard" }), context), "");
assert.match(validateRouteRule(rule({ action: "route", outbound: "direct", portRange: "80" }), context), /端口范围/);
assert.match(validateRouteRule(rule({ action: "route", outbound: "direct", ipCidr: "10.0.0" }), context), /目标 IP CIDR无效/);
assert.match(validateRouteRule(rule({ action: "route", outbound: "direct", advancedJson: '{"geoip":["cn"]}' }), context), /已弃用|已移除/);
assert.equal(validateRouteRule(rule({ action: "route", outbound: "direct", advancedJson: '{"interface_address":{"en0":["2000::/3"]}}' }), context), "");
assert.deepEqual(buildRouteRule(rule({ action: "route", outbound: "direct", advancedJson: '{"interface_address":{"en0":["2000::/3"]}}' })).interface_address, { en0: ["2000::/3"] });

// 逻辑规则
const logical = rule({ ruleType: "logical", mode: "or", rulesJson: '[{"domain_suffix":".cn"},{"rule_set":"geosite-cn"}]', action: "route", outbound: "direct" });
assert.equal(validateRouteRule(logical, context), "");
assert.equal(buildRouteRule(logical).type, "logical");
assert.match(validateRouteRule(rule({ ruleType: "logical", rulesJson: '[{"action":"route","outbound":"direct"}]', action: "route", outbound: "direct" }), context), /不能带动作/);

// 规则集：inline / local / remote
const inlineSet = normalizeRuleSet({
  id: "s1", type: "inline", tag: "custom-block",
  headlessRules: [normalizeHeadlessRule({ domainSuffix: ".ads.example.com", network: "tcp" })]
});
assert.equal(validateRuleSet(inlineSet, {}), "");
assert.deepEqual(buildRuleSet(inlineSet), { type: "inline", tag: "custom-block", rules: [{ network: ["tcp"], domain_suffix: [".ads.example.com"] }] });

const localSet = normalizeRuleSet({ id: "s2", type: "local", tag: "geosite-cn", path: "/etc/sing-box/geosite-cn.srs" });
assert.equal(validateRuleSet(localSet, {}), "");
assert.deepEqual(buildRuleSet(localSet), { type: "local", tag: "geosite-cn", path: "/etc/sing-box/geosite-cn.srs" });
assert.match(validateRuleSet(normalizeRuleSet({ id: "s2", type: "local", tag: "x", path: "/etc/rules.dat" }), {}), /必须显式选择规则集格式/);

const remoteSet = normalizeRuleSet({
  id: "s3", type: "remote", tag: "geoip-cn",
  url: "https://example.com/geoip-cn.srs", updateInterval: "1d", initialPath: "/var/lib/sing-box/geoip-cn.srs"
});
assert.equal(validateRuleSet(remoteSet, {}), "");
assert.deepEqual(buildRuleSet(remoteSet), {
  type: "remote", tag: "geoip-cn", url: "https://example.com/geoip-cn.srs",
  initial_path: "/var/lib/sing-box/geoip-cn.srs", update_interval: "1d"
});

// 1.14 多标签与 {tag} 占位符
const multiSet = normalizeRuleSet({ id: "s4", type: "remote", tag: "geosite-cn, geoip-cn", url: "https://example.com/{tag}.srs" });
assert.equal(validateRuleSet(multiSet, {}), "");
assert.deepEqual(buildRuleSet(multiSet).tag, ["geosite-cn", "geoip-cn"]);
assert.match(validateRuleSet(normalizeRuleSet({ id: "s4", type: "remote", tag: "a, b", url: "https://example.com/x.srs" }), {}), /\{tag\} 占位符/);
assert.match(validateRuleSet(normalizeRuleSet({ id: "s4", type: "inline", tag: "a, b", headlessRules: [normalizeHeadlessRule({ domain: "x.com" })] }), {}), /不支持一次定义多个标签/);

// 1.14 http_client 取代已弃用的 download_detour
const clientSet = normalizeRuleSet({
  id: "s5", type: "remote", tag: "rules", url: "https://example.com/rules.srs",
  httpClientMode: "inline", httpClientJson: '{"detour":"direct"}'
});
assert.equal(validateRuleSet(clientSet, { outboundTags }), "");
assert.deepEqual(buildRuleSet(clientSet).http_client, { detour: "direct" });
assert.match(validateRuleSet(normalizeRuleSet({ ...clientSet, httpClientJson: '{"detour":"ghost"}' }), { outboundTags }), /detour 出站不存在/);
assert.match(validateRuleSet(normalizeRuleSet({ ...clientSet, advancedJson: '{"download_detour":"direct"}' }), {}), /已弃用|已移除/);
assert.equal(buildRuleSet(normalizeRuleSet({ ...clientSet, httpClientMode: "tag", httpClientTag: "shared-client" })).http_client, "shared-client");

// 标签唯一性
assert.match(validateRuleSet(normalizeRuleSet({ id: "s6", type: "local", tag: "geosite-cn", path: "/x.srs" }), { ruleSets: [localSet] }), /标签必须唯一/);

// Headless 规则项
assert.equal(validateHeadlessRule(normalizeHeadlessRule({ domain: "example.com" }), 0), "");
assert.match(validateHeadlessRule(normalizeHeadlessRule({}), 0), /至少需要一个匹配条件/);
assert.match(validateHeadlessRule(normalizeHeadlessRule({ ipCidr: "not-an-ip" }), 1), /规则项 2 IP CIDR无效/);
assert.deepEqual(buildHeadlessRule(normalizeHeadlessRule({ queryType: "A, 65", invert: true })), { query_type: ["A", 65], invert: true });
assert.equal(buildHeadlessRule(normalizeHeadlessRule({ ruleType: "logical", mode: "or", rulesJson: '[{"domain":"a.com"}]' })).type, "logical");
assert.match(validateHeadlessRule(normalizeHeadlessRule({ ruleType: "logical", rulesJson: '[{"rule_set":"x"}]' }), 0), /不支持的字段/);

// 路由整体
const routeState = {
  final: "",
  autoDetectInterface: "auto",
  rules: [
    normalizeRouteRule({ id: "a", action: "sniff" }),
    normalizeRouteRule({ id: "b", protocol: "dns", action: "hijack-dns" }),
    normalizeRouteRule({ id: "c", ipIsPrivate: true, action: "route", outbound: "direct" }),
    normalizeRouteRule({ id: "d", clashMode: "Global", action: "route", outbound: "proxy" })
  ],
  ruleSets: [localSet]
};
assert.equal(validateRouteState(routeState, context), "");

const section = buildRouteSection(routeState, { outboundTags, tunEnabled: true, defaultDomainResolver: "local-dns" });
assert.equal(section.rules.length, 4);
assert.equal(section.auto_detect_interface, true);
assert.equal(section.default_domain_resolver, "local-dns");
assert.equal(section.rule_set.length, 1);
assert.equal(section.final, undefined);
assert.equal(buildRouteSection(routeState, { outboundTags, tunEnabled: false }).auto_detect_interface, undefined);
assert.equal(buildRouteSection({ ...routeState, autoDetectInterface: "on" }, { outboundTags, tunEnabled: false }).auto_detect_interface, true);
assert.equal(buildRouteSection({ ...routeState, final: "proxy" }, { outboundTags }).final, "proxy");

// 引用缺失出站的规则不会写入配置，但会被报告
const withoutProxy = buildRouteSection(routeState, { outboundTags: ["direct"], tunEnabled: true });
assert.equal(withoutProxy.rules.length, 3);
assert.deepEqual(skippedRouteRules(routeState, ["direct"]).map((item) => item.id), ["d"]);
assert.equal(skippedRouteRules(routeState, outboundTags).length, 0);

// 禁用项不参与生成
assert.equal(buildRouteSection({ ...routeState, rules: [{ ...routeState.rules[0], enabled: false }, routeState.rules[1]] }, { outboundTags }).rules.length, 1);

// 全局字段校验
assert.match(validateRouteState({ ...routeState, defaultMark: "-1" }, context), /非负整数/);
assert.match(validateRouteState({ ...routeState, autoDetectInterface: "on", defaultInterface: "en0" }, context), /只能选择一个/);
assert.match(validateRouteState({ ...routeState, defaultFallbackNetworkType: "wifi" }, context), /只有 fallback/);
assert.match(validateRouteState({ ...routeState, advancedJson: '{"geoip":{}}' }, context), /已弃用|已移除/);
assert.match(validateRouteState({ ...routeState, final: "ghost" }, context), /默认出站不存在/);

console.log("route module tests passed");

// final 留空时回退到调用方给出的自动值（保持 proxy 选择器语义）
assert.equal(buildRouteSection(routeState, { outboundTags, fallbackFinal: "proxy" }).final, "proxy");
assert.equal(buildRouteSection({ ...routeState, final: "direct" }, { outboundTags, fallbackFinal: "proxy" }).final, "direct");
assert.equal(buildRouteSection(routeState, { outboundTags: ["direct"], fallbackFinal: "proxy" }).final, undefined);

console.log("route final fallback test passed");
