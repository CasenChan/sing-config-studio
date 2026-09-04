import assert from "node:assert/strict";
import { importConfig } from "../modules/importer.js";
import { buildInbound } from "../modules/inbound.js";
import { buildOutbound, buildGroup } from "../modules/outbound.js";
import { buildDnsSection } from "../modules/dns.js";
import { buildRouteSection } from "../modules/route.js";
import { buildService, buildNtp, buildExperimental } from "../modules/services.js";
import { buildStandardEndpoint } from "../modules/endpoints.js";

const source = {
  log: { level: "warn", timestamp: true },
  ntp: { enabled: true, server: "time.apple.com", server_port: 123, interval: "30m" },
  certificate: { store: "mozilla", certificate_path: ["/etc/ssl/extra.pem"] },
  dns: {
    servers: [
      { type: "local", tag: "local-dns", neighbor_domain: [".", ".lan"] },
      { type: "https", tag: "remote-dns", server: "1.1.1.1", path: "/dns-query", detour: "proxy", tls: { enabled: true, server_name: "cloudflare-dns.com" } },
      { type: "fakeip", tag: "fakeip", inet4_range: "198.18.0.0/15", inet6_range: "fc00::/18" }
    ],
    rules: [
      { domain_suffix: [".lan"], action: "route", server: "local-dns" },
      { action: "evaluate", server: "remote-dns", tag: "probe" },
      { match_response: "probe", ip_is_private: true, action: "route", server: "local-dns" }
    ],
    final: "remote-dns",
    strategy: "prefer_ipv4",
    optimistic: { enabled: true, timeout: "1d" },
    timeout: "5s"
  },
  inbounds: [
    { type: "tun", tag: "tun-in", address: ["172.19.0.1/30"], auto_route: true, strict_route: true, stack: "mixed", dns_mode: "hijack" },
    { type: "mixed", tag: "mixed-in", listen: "127.0.0.1", listen_port: 7890, users: [{ username: "u", password: "p" }] },
    { type: "vless", tag: "vless-in", listen_port: 8443, users: [{ name: "u", uuid: "17f6f870-6f59-4c91-a4dc-46cfe797c241", flow: "xtls-rprx-vision" }], tls: { enabled: true, server_name: "example.com", certificate_path: "/c.pem", key_path: "/k.pem" } }
  ],
  outbounds: [
    { type: "urltest", tag: "auto", outbounds: ["node-a", "node-b"], url: "https://www.gstatic.com/generate_204", interval: "3m", tolerance: 50 },
    { type: "selector", tag: "proxy", outbounds: ["auto", "node-a", "node-b", "direct"], default: "auto" },
    { type: "vless", tag: "node-a", server: "a.example.com", server_port: 443, uuid: "17f6f870-6f59-4c91-a4dc-46cfe797c241", flow: "xtls-rprx-vision", tls: { enabled: true, server_name: "www.microsoft.com", utls: { enabled: true, fingerprint: "chrome" }, reality: { enabled: true, public_key: "pk", short_id: "sid" } } },
    { type: "trojan", tag: "node-b", server: "b.example.com", server_port: 443, password: "pass", tls: { enabled: true, server_name: "b.example.com" }, transport: { type: "ws", path: "/ws", headers: { Host: "cdn.example.com" } }, multiplex: { enabled: true, protocol: "h2mux", max_connections: 4 } },
    { type: "direct", tag: "direct" }
  ],
  endpoints: [
    { type: "wireguard", tag: "wg", address: ["10.7.0.2/32"], private_key: "QEkbUOD7+9ROtG4HRvsWG8ddIp8tQZg8nVq6UBLdk1o=", peers: [{ address: "127.0.0.1", port: 51820, public_key: "sLupvbHfve+mEfOCiTG7CXp3xvV52YRDZZsj1RLA/SU=", allowed_ips: ["0.0.0.0/0"] }] }
  ],
  route: {
    rules: [
      { action: "sniff" },
      { protocol: ["dns"], action: "hijack-dns" },
      { ip_is_private: true, action: "route", outbound: "direct" },
      { rule_set: ["geosite-cn"], action: "route", outbound: "direct" },
      { action: "resolve", server: "local-dns", strategy: "prefer_ipv4" }
    ],
    rule_set: [
      { type: "remote", tag: "geosite-cn", format: "binary", url: "https://example.com/geosite-cn.srs", update_interval: "1d" },
      { type: "inline", tag: "custom", rules: [{ domain_suffix: [".ads.example.com"] }] }
    ],
    final: "proxy",
    auto_detect_interface: true,
    default_domain_resolver: "local-dns",
    find_neighbor: true
  },
  services: [
    { type: "api", tag: "api", listen: "127.0.0.1", listen_port: 9090, secret: "s" }
  ],
  experimental: {
    cache_file: { enabled: true, store_fakeip: true },
    clash_api: { external_controller: "127.0.0.1:9090", default_mode: "Rule" }
  }
};

const { state, notices, counts } = importConfig(source);

// 计数
assert.deepEqual(counts, {
  inbounds: 3, nodes: 2, groups: 2, endpoints: 1,
  dnsServers: 3, dnsRules: 3, routeRules: 5, ruleSets: 2, services: 1
});
assert.equal(state.settings.logLevel, "warn");
assert.equal(notices.filter((item) => item.level === "error").length, 0);

// 入站往返
assert.deepEqual(state.inbounds.map((item) => buildInbound(item)), source.inbounds);

// 出站与出站组往返
const nodeTags = state.nodes.map((node) => node.tag);
const groupTags = state.groups.map((group) => group.tag);
assert.deepEqual(state.nodes.map(buildOutbound), source.outbounds.filter((item) => ["vless", "trojan"].includes(item.type)));
assert.deepEqual(state.groups.map((group) => buildGroup(group, { nodeTags, groupTags })), source.outbounds.slice(0, 2));

// 端点往返
assert.deepEqual(state.endpoints.map(buildStandardEndpoint), source.endpoints);

// DNS 往返
const dns = buildDnsSection(state.dns, { outboundTags: ["proxy", "direct"] });
assert.deepEqual(dns.servers, source.dns.servers);
assert.deepEqual(dns.rules, source.dns.rules);
assert.equal(dns.final, "remote-dns");
assert.deepEqual(dns.optimistic, { enabled: true, timeout: "1d" });

// 路由往返
const route = buildRouteSection(state.route, { outboundTags: ["proxy", "direct"], tunEnabled: true, defaultDomainResolver: "local-dns" });
assert.deepEqual(route.rules, source.route.rules);
assert.deepEqual(route.rule_set, source.route.rule_set);
assert.equal(route.final, "proxy");
assert.equal(route.find_neighbor, true);

// 服务与实验性往返
assert.deepEqual(state.serviceState.services.map(buildService), source.services);
assert.deepEqual(buildNtp(state.serviceState), source.ntp);
assert.deepEqual(buildExperimental(state.serviceState), source.experimental);

// 未建模字段进入附加参数，保证无损
const withExtra = importConfig({
  inbounds: [{ type: "mixed", tag: "m", listen_port: 1080, domain_resolver: { server: "local-dns", strategy: "prefer_ipv4" } }],
  outbounds: [{ type: "trojan", tag: "t", server: "s", server_port: 443, password: "p", tls: { enabled: true, kernel_tx: true } }],
  dns: { servers: [{ type: "local", tag: "local-dns" }] }
});
assert.match(withExtra.state.inbounds[0].advancedJson, /domain_resolver/);
assert.deepEqual(buildInbound(withExtra.state.inbounds[0]).domain_resolver, { server: "local-dns", strategy: "prefer_ipv4" });
assert.equal(buildOutbound(withExtra.state.nodes[0]).tls.kernel_tx, true);

// 弃用字段：提示 + 丢弃
const legacy = importConfig({
  inbounds: [{ type: "mixed", tag: "m", listen_port: 1080, sniff: true, domain_strategy: "prefer_ipv4" }],
  outbounds: [{ type: "direct", tag: "direct" }],
  dns: { servers: [{ type: "local", tag: "local-dns" }] },
  route: { rules: [{ geoip: ["cn"], action: "route", outbound: "direct" }] }
});
assert.ok(legacy.notices.some((item) => item.message.includes("sniff")));
assert.ok(legacy.notices.some((item) => item.message.includes("domain_strategy")));
assert.ok(legacy.notices.some((item) => item.message.includes("geoip")));
assert.equal(JSON.stringify(buildInbound(legacy.state.inbounds[0])).includes("sniff"), false);

// 空配置与非法输入
assert.throws(() => importConfig(null), /JSON 对象/);
assert.throws(() => importConfig([]), /JSON 对象/);
const empty = importConfig({});
assert.equal(empty.counts.inbounds, 0);
assert.ok(empty.notices.some((item) => item.message.includes("没有入站")));

// 服务端 REALITY 往返
const realityIn = { type: "anytls", tag: "at", listen_port: 443, users: [{ password: "p" }], tls: { enabled: true, server_name: "www.microsoft.com", reality: { enabled: true, handshake: { server: "www.microsoft.com", server_port: 443 }, private_key: "priv", short_id: ["abcd"] } } };
const realityState = importConfig({ inbounds: [realityIn], outbounds: [{ type: "direct", tag: "direct" }], dns: { servers: [{ type: "local", tag: "l" }] } }).state;
assert.deepEqual(buildInbound(realityState.inbounds[0]), realityIn);

console.log("importer round-trip tests passed");
