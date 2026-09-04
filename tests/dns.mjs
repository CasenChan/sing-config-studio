import assert from "node:assert/strict";
import {
  buildDnsRule,
  buildDnsSection,
  buildDnsServer,
  defaultDomainResolverTag,
  normalizeDnsRule,
  normalizeDnsServer,
  validateDnsRule,
  validateDnsServer,
  validateDnsState
} from "../modules/dns.js";

const endpoints = [
  { id: "ts", type: "tailscale", tag: "ts-ep" },
  { id: "oc", type: "openconnect", tag: "oc-ep" },
  { id: "ov", type: "openvpn-client", tag: "ovpn-ep" }
];

function server(overrides) {
  return normalizeDnsServer({ id: overrides.tag, ...overrides });
}

// 每种 DNS Server 类型都能生成最小有效配置
const minimal = {
  local: server({ type: "local", tag: "local-dns" }),
  hosts: server({ type: "hosts", tag: "hosts", predefinedJson: '{"router.lan":"192.168.1.1"}' }),
  tcp: server({ type: "tcp", tag: "tcp-dns", server: "9.9.9.9" }),
  udp: server({ type: "udp", tag: "udp-dns", server: "223.5.5.5", serverPort: "53" }),
  tls: server({ type: "tls", tag: "dot", server: "1.1.1.1", tlsServerName: "cloudflare-dns.com" }),
  quic: server({ type: "quic", tag: "doq", server: "94.140.14.14", tlsServerName: "dns.adguard-dns.com" }),
  https: server({ type: "https", tag: "doh", server: "1.1.1.1", path: "/dns-query", tlsServerName: "cloudflare-dns.com" }),
  h3: server({ type: "h3", tag: "doh3", server: "8.8.8.8", tlsServerName: "dns.google" }),
  dhcp: server({ type: "dhcp", tag: "dhcp-dns", interface: "en0" }),
  mdns: server({ type: "mdns", tag: "mdns", interface: "en0, en1" }),
  fakeip: server({ type: "fakeip", tag: "fakeip" }),
  tailscale: server({ type: "tailscale", tag: "ts-dns", endpoint: "ts-ep", acceptSearchDomain: true }),
  openconnect: server({ type: "openconnect", tag: "oc-dns", endpoint: "oc-ep" }),
  openvpn: server({ type: "openvpn", tag: "ovpn-dns", endpoint: "ovpn-ep" }),
  resolved: server({ type: "resolved", tag: "resolved-dns", service: "resolved" })
};

for (const [type, entry] of Object.entries(minimal)) {
  assert.equal(validateDnsServer(entry, { endpoints, serviceTags: ["resolved"] }), "", `${type} 应通过校验`);
  const built = buildDnsServer(entry);
  assert.equal(built.type, type, `${type} 类型应保留`);
  assert.equal(built.tag, entry.tag);
  assert.ok(!("enabled" in built) && !("advancedJson" in built), `${type} 不应输出界面内部字段`);
}

assert.deepEqual(buildDnsServer(minimal.mdns).interface, ["en0", "en1"]);
assert.deepEqual(buildDnsServer(minimal.hosts).predefined, { "router.lan": "192.168.1.1" });
assert.equal(buildDnsServer(minimal.https).tls.enabled, true);
assert.equal(buildDnsServer(minimal.https).tls.server_name, "cloudflare-dns.com");
assert.equal(buildDnsServer(minimal.fakeip).inet4_range, "198.18.0.0/15");
assert.equal(buildDnsServer(minimal.tailscale).accept_search_domain, true);
assert.equal(buildDnsServer(minimal.udp).server_port, 53);

// local 的 1.14 邻居域
const localNeighbor = server({ type: "local", tag: "local-dns", neighborDomain: ".,.lan", preferGo: true });
assert.equal(validateDnsServer(localNeighbor, { endpoints }), "");
assert.deepEqual(buildDnsServer(localNeighbor).neighbor_domain, [".", ".lan"]);
assert.equal(buildDnsServer(localNeighbor).prefer_go, true);
assert.match(validateDnsServer(server({ type: "local", tag: "l", neighborDomain: "lan" }), {}), /必须以 \. 开头/);

// 域名上游必须配置 domain_resolver
assert.match(validateDnsServer(server({ type: "https", tag: "doh", server: "dns.google" }), {}), /domain_resolver/);
assert.equal(validateDnsServer(server({ type: "https", tag: "doh", server: "dns.google", domainResolver: "local-dns" }), {}), "");

// 端点引用校验
assert.match(validateDnsServer(server({ type: "tailscale", tag: "ts-dns", endpoint: "missing" }), { endpoints }), /端点不存在/);
assert.match(validateDnsServer(server({ type: "openvpn", tag: "ovpn-dns", endpoint: "oc-ep" }), { endpoints }), /不是 OpenVPN 端点/);

// FakeIP 段校验
assert.match(validateDnsServer(server({ type: "fakeip", tag: "fakeip", inet4Range: "198.18.0.0" }), {}), /CIDR/);

// 附加参数拒绝旧格式字段
assert.match(validateDnsServer(server({ type: "udp", tag: "u", server: "1.1.1.1", advancedJson: '{"address":"1.1.1.1"}' }), {}), /已弃用|不由本模块生成/);
assert.match(validateDnsServer(server({ type: "udp", tag: "u", server: "1.1.1.1", advancedJson: '{"nope":1}' }), {}), /不是该类型的 1.14 字段/);

// 规则：基础路由
const routeRule = normalizeDnsRule({ id: "r1", domainSuffix: ".lan, .local", action: "route", server: "local-dns" });
assert.equal(validateDnsRule(routeRule, { serverTags: ["local-dns"] }), "");
assert.deepEqual(buildDnsRule(routeRule), { domain_suffix: [".lan", ".local"], action: "route", server: "local-dns" });

// 规则：1.14 preferred_by
const preferredRule = normalizeDnsRule({ id: "r2", preferredBy: "hosts", action: "route", server: "hosts" });
assert.equal(validateDnsRule(preferredRule, { serverTags: ["hosts"] }), "");
assert.deepEqual(buildDnsRule(preferredRule).preferred_by, ["hosts"]);
assert.match(validateDnsRule(normalizeDnsRule({ preferredBy: "ghost", action: "route", server: "hosts" }), { serverTags: ["hosts"] }), /preferred_by/);

// 规则：拒绝 1.14 已弃用的旧地址过滤
const legacyFilter = normalizeDnsRule({ ipCidr: "10.0.0.0/8", action: "route", server: "local-dns" });
assert.match(validateDnsRule(legacyFilter, { serverTags: ["local-dns"] }), /match_response/);
const responseFilter = normalizeDnsRule({ matchResponse: "true", ipCidr: "10.0.0.0/8", action: "route", server: "local-dns" });
assert.equal(validateDnsRule(responseFilter, { serverTags: ["local-dns"] }), "");
assert.equal(buildDnsRule(responseFilter).match_response, true);

// 规则：race / speculative 约束
assert.match(validateDnsRule(normalizeDnsRule({ race: true, speculative: true, matchResponse: "true", action: "route", server: "s" }), { serverTags: ["s"] }), /race 与 speculative/);
assert.match(validateDnsRule(normalizeDnsRule({ race: true, action: "evaluate", server: "s" }), { serverTags: ["s"] }), /race 只能用于/);
assert.match(validateDnsRule(normalizeDnsRule({ race: true, action: "route", server: "s" }), { serverTags: ["s"] }), /match_response/);

// 规则：predefined 与 reject
const predefined = normalizeDnsRule({ queryType: "HTTPS, 65", action: "predefined", predefinedRcode: "NXDOMAIN" });
assert.equal(validateDnsRule(predefined, {}), "");
assert.deepEqual(buildDnsRule(predefined), { query_type: ["HTTPS", 65], action: "predefined", rcode: "NXDOMAIN" });
assert.match(validateDnsRule(normalizeDnsRule({ action: "reject", rejectMethod: "drop", rejectNoDrop: true }), {}), /no_drop/);

// 规则：client_subnet 互斥与 1.14 选项
const options = normalizeDnsRule({ action: "route-options", removeClientSubnet: true, disableOptimisticCache: true, timeout: "2s" });
assert.equal(validateDnsRule(options, {}), "");
assert.deepEqual(buildDnsRule(options), { action: "route-options", disable_optimistic_cache: true, timeout: "2s", remove_client_subnet: true });
assert.match(validateDnsRule(normalizeDnsRule({ action: "route-options", clientSubnet: "1.1.1.1", removeClientSubnet: true }), {}), /不能同时设置/);

// 规则：逻辑规则
const logical = normalizeDnsRule({ ruleType: "logical", mode: "or", rulesJson: '[{"domain_suffix":".cn"},{"rule_set":"geosite-cn"}]', action: "route", server: "local-dns" });
assert.equal(validateDnsRule(logical, { serverTags: ["local-dns"] }), "");
assert.equal(buildDnsRule(logical).type, "logical");
assert.match(validateDnsRule(normalizeDnsRule({ ruleType: "logical", rulesJson: '[{"action":"evaluate","server":"a"}]', action: "route", server: "s" }), { serverTags: ["s"] }), /顶层/);
assert.match(validateDnsRule(normalizeDnsRule({ ruleType: "logical", rulesJson: '[{"geoip":["cn"]}]', action: "route", server: "s" }), { serverTags: ["s"] }), /已弃用|已移除/);

// 规则：附加 JSON 拒绝已移除字段
assert.match(validateDnsRule(normalizeDnsRule({ action: "route", server: "s", advancedJson: '{"outbound":["direct"]}' }), { serverTags: ["s"] }), /已弃用|已移除/);

// 整体状态：evaluate / match_response / respond 顺序
const state = {
  final: "doh",
  strategy: "prefer_ipv4",
  defaultDomainResolver: "local-dns",
  optimistic: true,
  optimisticTimeout: "1d",
  timeout: "5s",
  servers: [minimal.local, minimal.https],
  rules: [
    normalizeDnsRule({ id: "a", action: "evaluate", server: "doh", evaluateTag: "probe" }),
    normalizeDnsRule({ id: "b", matchResponse: "probe", ipIsPrivate: true, action: "route", server: "local-dns" }),
    normalizeDnsRule({ id: "c", action: "respond" })
  ]
};
assert.equal(validateDnsState(state, { endpoints }), "");

const section = buildDnsSection(state);
assert.equal(section.final, "doh");
assert.deepEqual(section.optimistic, { enabled: true, timeout: "1d" });
assert.equal(section.timeout, "5s");
assert.equal(section.servers.length, 2);
assert.equal(section.rules.length, 3);
assert.equal(JSON.stringify(section).includes("independent_cache"), false);
assert.equal(buildDnsSection({ ...state, optimisticTimeout: "" }).optimistic, true);
assert.match(validateDnsState({ ...state, optimistic: true, disableCache: true }, {}), /冲突/);
assert.match(validateDnsState({ ...state, rules: [state.rules[1]] }, {}), /match_response 需要前置/);
assert.match(validateDnsState({ ...state, rules: [state.rules[2]] }, {}), /respond 需要前置/);
assert.match(validateDnsState({ ...state, rules: [state.rules[0], normalizeDnsRule({ matchResponse: "other", action: "route", server: "doh" })] }, {}), /找不到标签/);
assert.match(validateDnsState({ ...state, final: "ghost" }, {}), /默认 DNS Server 不存在/);
assert.match(validateDnsState({ ...state, servers: [] }, {}), /至少需要一个/);
assert.match(validateDnsState({ ...state, servers: [minimal.local, { ...minimal.https, tag: "local-dns" }] }, {}), /标签重复/);

// 禁用项不参与生成
const disabled = buildDnsSection({ ...state, servers: [minimal.local, { ...minimal.https, enabled: false }], final: "local-dns" });
assert.equal(disabled.servers.length, 1);

// detour 引用不存在的出站时不会写入配置
const detoured = buildDnsSection(
  { ...state, servers: [{ ...minimal.https, detour: "proxy" }], final: "doh", rules: [] },
  { outboundTags: ["direct"] }
);
assert.equal(detoured.servers[0].detour, undefined);
assert.equal(buildDnsSection({ ...state, servers: [{ ...minimal.https, detour: "proxy" }], rules: [] }, { outboundTags: ["direct", "proxy"] }).servers[0].detour, "proxy");

// 默认域名解析器回退
assert.equal(defaultDomainResolverTag(state), "local-dns");
assert.equal(defaultDomainResolverTag({ ...state, defaultDomainResolver: "ghost" }), "local-dns");
assert.equal(defaultDomainResolverTag({ servers: [minimal.https] }), "doh");

console.log("dns module tests passed");

// Tailscale MagicDNS 联动：preferred_by 引用 DNS Server 标签而不是端点标签
const { normalizeTailscaleEndpoint, tailscaleModule } = await import("../modules/tailscale.js");
const magicConfig = { dns: { servers: [], rules: [] } };
tailscaleModule.extendConfig(magicConfig, {
  endpoints: [normalizeTailscaleEndpoint({ id: "ts", tag: "ts-ep", magicDns: true })]
});
assert.equal(magicConfig.dns.servers[0].tag, "ts-ep-dns");
assert.equal(magicConfig.dns.servers[0].endpoint, "ts-ep");
assert.equal(magicConfig.dns.rules[0].preferred_by, "ts-ep-dns");
assert.equal(magicConfig.dns.rules[0].server, "ts-ep-dns");

console.log("tailscale magicdns rule test passed");
