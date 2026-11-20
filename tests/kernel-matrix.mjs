// 用真实 sing-box 内核对每种模块类型执行 `sing-box check`。
// 每个用例先通过本项目自己的校验器，再交给内核：校验器放行但内核拒绝即为缺陷。
// 只执行 check，不启动服务、不创建 TUN、不连接任何远端。
// 用法：SING_BOX_BIN=/path/to/sing-box node tests/kernel-matrix.mjs
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdir, rm, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { INBOUND_TYPES, buildInbound, normalizeInbound, validateInbound } from "../modules/inbound.js";
import { OUTBOUND_TYPES, buildGroup, buildOutbound, normalizeGroup, normalizeOutbound, validateOutbound } from "../modules/outbound.js";
import { DNS_SERVER_TYPES, buildDnsRule, buildDnsServer, normalizeDnsRule, normalizeDnsServer, validateDnsRule, validateDnsServer } from "../modules/dns.js";
import { buildRouteRule, buildRuleSet, normalizeRouteRule, normalizeRuleSet, validateRouteRule, validateRuleSet } from "../modules/route.js";
import { SERVICE_TYPES, buildService, normalizeService, validateService } from "../modules/services.js";
import { buildStandardEndpoint, normalizeStandardEndpoint, validateStandardEndpoint } from "../modules/endpoints.js";
import { normalizeTailscaleEndpoint, tailscaleModule, validateTailscaleEndpoint } from "../modules/tailscale.js";

const bin = process.env.SING_BOX_BIN;
assert.ok(bin, "请设置 SING_BOX_BIN 为 sing-box 可执行文件");
const versionText = spawnSync(bin, ["version"], { encoding: "utf8" }).stdout || "";
const version = versionText.match(/sing-box version (\S+)/)?.[1];
assert.ok(version, "无法读取 sing-box 版本：" + versionText);

const output = resolve("output/kernel-matrix", version);
await rm(output, { recursive: true, force: true });
await mkdir(output, { recursive: true });

function generate(...args) {
  const result = spawnSync(bin, ["generate", ...args], { encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
  return result.stdout;
}
const keyValue = (text) => Object.fromEntries(text.trim().split("\n").map((line) => line.split(/:\s*/)));

const pem = generate("tls-keypair", "localhost");
const certPath = join(output, "cert.pem");
const keyPath = join(output, "key.pem");
await writeFile(certPath, pem.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/)[0] + "\n");
await writeFile(keyPath, pem.match(/-----BEGIN PRIVATE KEY-----[\s\S]+?-----END PRIVATE KEY-----/)[0] + "\n");
const reality = keyValue(generate("reality-keypair"));
const wg = keyValue(generate("wg-keypair"));
const ss2022Key = generate("rand", "16", "--base64").trim();
const cloudflaredToken = Buffer.from(JSON.stringify({ a: "0".repeat(32), t: "17f6f870-6f59-4c91-a4dc-46cfe797c241", s: Buffer.from("x".repeat(32)).toString("base64") })).toString("base64");
const uuid = "17f6f870-6f59-4c91-a4dc-46cfe797c241";
const tls = { tlsCertificatePath: certPath, tlsKeyPath: keyPath };
const direct = { type: "direct", tag: "direct" };
const localDns = buildDnsServer(normalizeDnsServer({ id: "local-dns", type: "local", tag: "local-dns" }));
// 生成器总会写出 default_domain_resolver，矩阵用例保持一致
const shell = (config) => ({
  log: { level: "warn" },
  ...config,
  dns: { ...config.dns, servers: [localDns, ...(config.dns?.servers || []).filter((item) => item.tag !== "local-dns")] },
  outbounds: config.outbounds || [direct],
  route: { default_domain_resolver: "local-dns", ...config.route }
});

const cases = [];
// validation：本项目校验器的返回值（"" 表示放行）
const add = (group, name, config, validation = "") => cases.push({ group, name, config: shell(config), validation });
const firstError = (...messages) => messages.find(Boolean) || "";

// 入站：与 tests/inbound.mjs 的最小模板一致，证书换成真实文件
const inboundSources = {
  mixed: { type: "mixed", tag: "mixed-in", listenPort: "7890" },
  socks: { type: "socks", tag: "socks-in", listenPort: "1080" },
  http: { type: "http", tag: "http-in", listenPort: "8080" },
  direct: { type: "direct", tag: "direct-in", listenPort: "5353", overrideAddress: "1.1.1.1", overridePort: "53" },
  tun: { type: "tun", tag: "tun-in" },
  redirect: { type: "redirect", tag: "redirect-in", listenPort: "1081" },
  tproxy: { type: "tproxy", tag: "tproxy-in", listenPort: "1082" },
  shadowsocks: { type: "shadowsocks", tag: "ss-in", listenPort: "8388", password: ss2022Key },
  vmess: { type: "vmess", tag: "vmess-in", listenPort: "8443", usersJson: `[{"name":"u","uuid":"${uuid}"}]` },
  vless: { type: "vless", tag: "vless-in", listenPort: "8444", usersJson: `[{"name":"u","uuid":"${uuid}","flow":"xtls-rprx-vision"}]` },
  trojan: { type: "trojan", tag: "trojan-in", listenPort: "8445", usersJson: '[{"name":"u","password":"p"}]', tlsEnabled: true, ...tls },
  naive: { type: "naive", tag: "naive-in", listenPort: "8446", usersJson: '[{"username":"u","password":"p"}]', ...tls },
  hysteria: { type: "hysteria", tag: "hy-in", listenPort: "8447", usersJson: '[{"name":"u","auth_str":"p"}]', up: "100 Mbps", down: "100 Mbps", ...tls },
  hysteria2: { type: "hysteria2", tag: "hy2-in", listenPort: "8448", usersJson: '[{"name":"u","password":"p"}]', ...tls },
  shadowtls: { type: "shadowtls", tag: "stls-in", listenPort: "8449", usersJson: '[{"name":"u","password":"p"}]', handshakeServer: "example.com", detour: "ss-in" },
  tuic: { type: "tuic", tag: "tuic-in", listenPort: "8450", usersJson: `[{"name":"u","uuid":"${uuid}","password":"p"}]`, ...tls },
  anytls: { type: "anytls", tag: "anytls-in", listenPort: "8451", usersJson: '[{"name":"u","password":"p"}]', ...tls },
  snell: { type: "snell", tag: "snell-in", listenPort: "8452", psk: "psk" },
  cloudflared: { type: "cloudflared", tag: "cf-in", token: cloudflaredToken }
};
assert.deepEqual(Object.keys(inboundSources).sort(), [...INBOUND_TYPES].sort());
const inboundVariants = {
  "vless+reality": {
    type: "vless", tag: "vless-reality", listenPort: "8460", usersJson: `[{"uuid":"${uuid}","flow":"xtls-rprx-vision"}]`,
    tlsEnabled: true, tlsServerName: "www.example.com", realityEnabled: true, realityHandshakeServer: "www.example.com",
    realityHandshakePort: "443", realityPrivateKey: reality.PrivateKey, realityShortId: "0123456789abcdef"
  },
  "tun+dns_mode": { type: "tun", tag: "tun-dns", dnsMode: "native" },
  "shadowsocks2022+users": { type: "shadowsocks", tag: "ss-multi", listenPort: "8461", password: ss2022Key, usersJson: JSON.stringify([{ name: "u", password: ss2022Key }]) },
  "shadowsocks+legacy-users": { type: "shadowsocks", tag: "ss-legacy", listenPort: "8462", method: "aes-128-gcm", usersJson: '[{"name":"u","password":"p"}]' }
};
const inboundList = Object.values(inboundSources).map((item) => normalizeInbound({ id: item.tag, ...item }));
for (const [name, source] of Object.entries({ ...inboundSources, ...inboundVariants })) {
  const inbound = normalizeInbound({ id: source.tag, ...source });
  const extra = name === "shadowtls" ? [buildInbound(inboundList.find((item) => item.tag === "ss-in"))] : [];
  const validation = validateInbound(inbound, { inbounds: [inbound, ...inboundList.filter((item) => item.tag === "ss-in")], outboundTags: ["direct"], dnsServerTags: ["local-dns"] });
  add("inbound", name, { inbounds: [buildInbound(inbound), ...extra] }, validation);
}

// 出站：与 tests/outbound.mjs 的最小模板一致
const outboundSources = {
  direct: { type: "direct", tag: "direct-out" },
  bridge: { type: "bridge", tag: "bridge-out", interface: "eth0" },
  socks: { type: "socks", tag: "socks-out" },
  http: { type: "http", tag: "http-out" },
  shadowsocks: { type: "shadowsocks", tag: "ss-out", password: ss2022Key },
  vmess: { type: "vmess", tag: "vmess-out", uuid },
  vless: { type: "vless", tag: "vless-out", uuid },
  trojan: { type: "trojan", tag: "trojan-out", password: "pass" },
  naive: { type: "naive", tag: "naive-out", username: "u", password: "p" },
  hysteria: { type: "hysteria", tag: "hy-out", authString: "auth", up: "50 Mbps", down: "100 Mbps" },
  hysteria2: { type: "hysteria2", tag: "hy2-out", password: "pass" },
  shadowtls: { type: "shadowtls", tag: "stls-out", password: "pass" },
  tuic: { type: "tuic", tag: "tuic-out", uuid, password: "pass" },
  anytls: { type: "anytls", tag: "anytls-out", password: "pass" },
  snell: { type: "snell", tag: "snell-out", psk: "psk" },
  tor: { type: "tor", tag: "tor-out" },
  ssh: { type: "ssh", tag: "ssh-out", port: 22, user: "root", password: "pass" }
};
assert.deepEqual(Object.keys(outboundSources).sort(), [...OUTBOUND_TYPES].sort());
const outboundVariants = {
  "shadowsocks+plain-password": { type: "shadowsocks", tag: "ss-weak", password: "pass" },
  "vless+reality": { type: "vless", tag: "v-reality", uuid, tls: true, sni: "www.example.com", fingerprint: "chrome", reality: true, publicKey: reality.PublicKey, shortId: "0123456789abcdef" },
  "vmess+ws+tls": { type: "vmess", tag: "v-ws", uuid, tls: true, transport: "ws", path: "/ray", host: "cdn.example.com", maxEarlyData: "2048", earlyDataHeaderName: "Sec-WebSocket-Protocol" },
  "vless+grpc": { type: "vless", tag: "v-grpc", uuid, tls: true, transport: "grpc", path: "/svc" },
  "vless+httpupgrade": { type: "vless", tag: "v-hu", uuid, tls: true, transport: "httpupgrade", path: "/up", host: "cdn.example.com" },
  "trojan+mux+brutal": { type: "trojan", tag: "t-mux", password: "p", multiplexEnabled: true, multiplexProtocol: "h2mux", maxConnections: "4", brutalEnabled: true, brutalUp: "50", brutalDown: "100" },
  "trojan+tls-fragment": { type: "trojan", tag: "t-frag", password: "p", tls: true, tlsFragment: true, tlsFragmentFallbackDelay: "500ms", tlsRecordFragment: true },
  "shadowsocks+uot": { type: "shadowsocks", tag: "ss-uot", password: ss2022Key, uotEnabled: true, uotVersion: "2" },
  "hysteria2+port-hopping": { type: "hysteria2", tag: "hy2-hop", password: "p", serverPorts: "443:500", hopInterval: "30s" }
};
for (const [name, source] of Object.entries({ ...outboundSources, ...outboundVariants })) {
  const node = normalizeOutbound({ id: source.tag, server: "example.com", port: 443, ...source });
  add("outbound", name, { outbounds: [buildOutbound(node), direct] }, validateOutbound(node, { nodes: [node], outboundTags: ["direct"], dnsServerTags: ["local-dns"] }));
}
const nodeTags = ["node-a", "node-b"];
const groupNodes = nodeTags.map((tag) => buildOutbound(normalizeOutbound({ id: tag, type: "trojan", tag, server: "example.com", port: 443, password: "p" })));
add("outbound", "selector+urltest", {
  outbounds: [
    ...groupNodes,
    buildGroup(normalizeGroup({ id: "g1", type: "urltest", tag: "auto", includeAllNodes: true, url: "https://www.gstatic.com/generate_204", interval: "3m", tolerance: "50" }), { nodeTags }),
    buildGroup(normalizeGroup({ id: "g2", type: "selector", tag: "proxy", includeAllNodes: true, includeDirect: true, members: "auto", defaultMember: "auto" }), { nodeTags, groupTags: ["auto"] }),
    direct
  ]
});

// 端点
const endpointSources = {
  wireguard: {
    type: "wireguard", id: "wg", tag: "wg-ep", address: "10.7.0.2/32", privateKey: wg.PrivateKey,
    peersJson: JSON.stringify([{ address: "127.0.0.1", port: 51820, public_key: wg.PublicKey, allowed_ips: ["0.0.0.0/0"] }]),
    udpMapping: "address_dependent"
  },
  openconnect: { type: "openconnect", id: "oc", tag: "oc-ep", server: "vpn.example.com", flavor: "gp" },
  "openvpn-client": { type: "openvpn-client", id: "ovc", tag: "ovpn-ep", server: "127.0.0.1", serverPort: "1194", tlsPeerFingerprint: "a".repeat(64) },
  "openvpn-server": { type: "openvpn-server", id: "ovs", tag: "ovpn-server", listenPort: "1194", address: "10.8.0.1/24", tlsCertificatePath: certPath, tlsKeyPath: keyPath, tlsVerifyClientCertificate: "none" }
};
const endpoints = {};
for (const [name, source] of Object.entries(endpointSources)) {
  const endpoint = normalizeStandardEndpoint(source);
  endpoints[name] = buildStandardEndpoint(endpoint);
  add("endpoint", name, { endpoints: [endpoints[name]] }, validateStandardEndpoint(endpoint, { endpoints: [endpoint], outboundTags: ["direct"] }));
}
const tailscaleSource = normalizeTailscaleEndpoint({ id: "ts", tag: "ts-ep", enabled: true, stateDirectory: join(output, "tailscale"), acceptRoutes: true });
const tailscaleConfig = tailscaleModule.extendConfig({ dns: { servers: [], rules: [] }, outbounds: [direct], route: { rules: [] } }, { endpoints: [tailscaleSource], dns: { servers: [], rules: [] } }, {});
endpoints.tailscale = tailscaleConfig.endpoints.find((item) => item.type === "tailscale");
const tailscaleValidation = validateTailscaleEndpoint(tailscaleSource, { endpoints: [tailscaleSource], outboundTags: ["direct"] });
add("endpoint", "tailscale", { endpoints: [endpoints.tailscale] }, tailscaleValidation);
add("endpoint", "tailscale+magicdns", tailscaleConfig, tailscaleValidation);

// DNS Server：与 tests/dns.mjs 的最小模板一致，配上被引用的端点和服务
const dnsSources = {
  local: { type: "local", tag: "local-dns" },
  hosts: { type: "hosts", tag: "hosts", predefinedJson: '{"router.lan":"192.168.1.1"}' },
  tcp: { type: "tcp", tag: "tcp-dns", server: "9.9.9.9" },
  udp: { type: "udp", tag: "udp-dns", server: "223.5.5.5", serverPort: "53" },
  tls: { type: "tls", tag: "dot", server: "1.1.1.1", tlsServerName: "cloudflare-dns.com" },
  quic: { type: "quic", tag: "doq", server: "94.140.14.14", tlsServerName: "dns.adguard-dns.com" },
  https: { type: "https", tag: "doh", server: "1.1.1.1", path: "/dns-query", tlsServerName: "cloudflare-dns.com" },
  h3: { type: "h3", tag: "doh3", server: "8.8.8.8", tlsServerName: "dns.google" },
  dhcp: { type: "dhcp", tag: "dhcp-dns", interface: "eth0" },
  mdns: { type: "mdns", tag: "mdns", interface: "eth0" },
  fakeip: { type: "fakeip", tag: "fakeip" },
  tailscale: { type: "tailscale", tag: "ts-dns", endpoint: "ts-ep", acceptSearchDomain: true },
  openconnect: { type: "openconnect", tag: "oc-dns", endpoint: "oc-ep" },
  openvpn: { type: "openvpn", tag: "ovpn-dns", endpoint: "ovpn-ep" },
  resolved: { type: "resolved", tag: "resolved-dns", service: "resolved" }
};
assert.deepEqual(Object.keys(dnsSources).sort(), [...DNS_SERVER_TYPES].sort());
const dnsEndpoints = [{ id: "ts", type: "tailscale", tag: "ts-ep" }, { id: "oc", type: "openconnect", tag: "oc-ep" }, { id: "ov", type: "openvpn-client", tag: "ovpn-ep" }];
const resolvedService = buildService(normalizeService({ id: "resolved", type: "resolved", tag: "resolved" }));
const fakeipInbound = buildInbound(normalizeInbound({ id: "tun", type: "tun", tag: "tun-in" }));
for (const [type, source] of Object.entries(dnsSources)) {
  const entry = normalizeDnsServer({ id: source.tag, ...source });
  const config = { dns: { servers: [buildDnsServer(entry)] } };
  if (type === "tailscale") config.endpoints = [endpoints.tailscale];
  if (type === "openconnect") config.endpoints = [endpoints.openconnect];
  if (type === "openvpn") config.endpoints = [endpoints["openvpn-client"]];
  if (type === "resolved") config.services = [resolvedService];
  if (type === "fakeip") {
    config.dns.rules = [buildDnsRule(normalizeDnsRule({ id: "f", queryType: "A, AAAA", action: "route", server: "fakeip" }))];
    config.inbounds = [fakeipInbound];
  }
  add("dns-server", type, config, validateDnsServer(entry, { endpoints: dnsEndpoints, serviceTags: ["resolved"], outboundTags: ["direct"] }));
}

// DNS 规则动作
const doh = buildDnsServer(normalizeDnsServer({ id: "doh", ...dnsSources.https }));
function addDnsRules(name, sources) {
  const rules = sources.map((source, index) => normalizeDnsRule({ id: "r" + index, ...source }));
  const validation = firstError(...rules.map((rule) => validateDnsRule(rule, { serverTags: ["local-dns", "doh"], ruleSetTags: [] })));
  add("dns-rule", name, { dns: { servers: [doh], rules: rules.map(buildDnsRule), final: "doh" } }, validation);
}
addDnsRules("route", [{ domainSuffix: ".lan", action: "route", server: "local-dns" }]);
addDnsRules("route-options", [{ domainSuffix: ".lan", action: "route-options", disableCache: true }]);
addDnsRules("reject", [{ domainSuffix: ".ads", action: "reject" }]);
addDnsRules("predefined", [{ domain: "router.lan", action: "predefined", predefinedRcode: "NOERROR", predefinedAnswer: "router.lan. IN A 192.168.1.1" }]);
addDnsRules("evaluate+respond", [
  { action: "evaluate", server: "doh" },
  { matchResponse: "true", ipIsPrivate: true, action: "respond" }
]);
addDnsRules("evaluate+race", [
  { action: "evaluate", server: "doh" },
  { matchResponse: "true", ipIsPrivate: true, action: "route", server: "local-dns", race: true },
  { domainSuffix: ".example", action: "route", server: "doh", speculative: true }
]);

// 路由规则动作与规则集
const mixedInbound = buildInbound(normalizeInbound({ id: "mixed", ...inboundSources.mixed }));
function addRoute(name, sources, ruleSets = []) {
  const rules = sources.map((source, index) => normalizeRouteRule({ id: "r" + index, ...source }));
  const sets = ruleSets.map((source) => normalizeRuleSet(source));
  const ruleSetTags = sets.map((set) => set.tag);
  const validation = firstError(
    ...rules.map((rule) => validateRouteRule(rule, { outboundTags: ["direct"], ruleSetTags, dnsServerTags: ["local-dns"], inboundTags: ["mixed-in"] })),
    ...sets.map((set) => validateRuleSet(set, { ruleSets: sets, outboundTags: ["direct"] }))
  );
  const route = { rules: rules.map(buildRouteRule), final: "direct" };
  if (sets.length) route.rule_set = sets.map(buildRuleSet);
  add("route-rule", name, { inbounds: [mixedInbound], route }, validation);
}
addRoute("route", [{ ipIsPrivate: true, action: "route", outbound: "direct" }]);
addRoute("bypass", [{ ipIsPrivate: true, action: "bypass", outbound: "direct" }]);
addRoute("reject", [{ domainSuffix: ".ads", action: "reject", rejectMethod: "drop" }]);
addRoute("hijack-dns", [{ protocol: "dns", action: "hijack-dns" }]);
addRoute("sniff", [{ action: "sniff", sniffer: "tls, http", sniffTimeout: "300ms" }]);
addRoute("resolve", [{ action: "resolve", resolveServer: "local-dns", resolveStrategy: "prefer_ipv4", resolveTimeout: "3s", resolveDisableOptimisticCache: true }]);
addRoute("route-options+fragment", [{ action: "route-options", tlsFragment: true, tlsFragmentFallbackDelay: "500ms", udpConnect: true }]);
addRoute("route-options+record-fragment", [{ action: "route-options", tlsRecordFragment: true }]);
addRoute("route-options+both-fragments", [{ action: "route-options", tlsFragment: true, tlsRecordFragment: true }]);
addRoute("route-options+empty", [{ action: "route-options" }]);
addRoute("route+both-fragments", [{ ipIsPrivate: true, action: "route", outbound: "direct", tlsFragment: true, tlsRecordFragment: true }]);
addRoute("route-options+tls_spoof", [{ action: "route-options", tlsSpoof: "www.example.com", tlsSpoofMethod: "wrong-checksum" }]);
const localRuleSet = join(output, "local-rule-set.json");
await writeFile(localRuleSet, JSON.stringify({ version: 3, rules: [{ domain_suffix: [".internal"] }] }));
addRoute("rule-set inline+local+remote", [{ ruleSet: "inline-set, local-set, remote-set", action: "route", outbound: "direct" }], [
  { id: "s1", type: "inline", tag: "inline-set", headlessRules: [{ domainSuffix: ".example" }] },
  { id: "s2", type: "local", tag: "local-set", format: "source", path: localRuleSet },
  { id: "s3", type: "remote", tag: "remote-set", format: "binary", url: "https://example.com/rules.srs", updateInterval: "1d" }
]);

// 服务：与 tests/services.mjs 的最小模板一致
const serviceSources = {
  api: { type: "api", tag: "api" },
  derp: { type: "derp", tag: "derp", tlsEnabled: true, ...tls },
  resolved: { type: "resolved", tag: "resolved" },
  "ssm-api": { type: "ssm-api", tag: "ssm", serversJson: '{"/":"ss-in"}' },
  ccm: { type: "ccm", tag: "ccm", usersJson: '[{"name":"u","token":"t"}]' },
  ocm: { type: "ocm", tag: "ocm", usersJson: '[{"name":"u","token":"t"}]' },
  "hysteria-realm": { type: "hysteria-realm", tag: "realm", tlsEnabled: true, ...tls, usersJson: '[{"name":"u","token":"t"}]' },
  "usbip-server": { type: "usbip-server", tag: "usbip-server" },
  "usbip-client": { type: "usbip-client", tag: "usbip-client", server: "10.0.0.2" }
};
assert.deepEqual(Object.keys(serviceSources).sort(), [...SERVICE_TYPES].sort());
const serviceVariants = {
  "derp+config_path": { ...serviceSources.derp, configPath: join(output, "derp.key") },
  "usbip-server+devices": { ...serviceSources["usbip-server"], devicesJson: '[{"bus_id":"1-1"}]' }
};
const ssManaged = { ...buildInbound(normalizeInbound({ id: "ss-in", ...inboundSources.shadowsocks })), managed: true };
for (const [name, source] of Object.entries({ ...serviceSources, ...serviceVariants })) {
  const service = normalizeService({ id: source.tag, ...source });
  const config = { services: [buildService(service)] };
  if (name === "ssm-api") config.inbounds = [ssManaged];
  add("service", name, config, validateService(service, { services: [service], outboundTags: ["direct"] }));
}

const bugs = [];
const fixtures = [];
const lines = [];
for (const { group, name, config, validation } of cases) {
  const file = join(output, `${group}-${name.replace(/[^a-z0-9.+-]+/gi, "_")}.json`);
  await writeFile(file, JSON.stringify(config, null, 2));
  const checked = spawnSync(bin, ["check", "-c", file], { encoding: "utf8", timeout: 20000 });
  const message = (checked.stderr || checked.stdout || "").replace(/\x1b\[[0-9;]*m/g, "").trim();
  const kernelOk = checked.status === 0;
  const label = `${group}/${name}`;
  let status;
  if (validation && !kernelOk) status = "rejected";
  else if (validation) status = "STRICT";
  else status = kernelOk ? "ok" : "BUG";
  const note = status === "BUG" ? message.split("\n").pop() : status === "STRICT" ? "validator: " + validation : status === "rejected" ? "validator: " + validation : message ? "warn: " + message.split("\n")[0] : "";
  lines.push(`${status.padEnd(11)} ${label}${note ? "  — " + note : ""}`);
  if (status === "BUG") bugs.push(label);
  if (status === "STRICT") fixtures.push(label);
}
const passed = cases.filter((_, index) => lines[index].startsWith("ok")).length;
const rejected = cases.filter((_, index) => lines[index].startsWith("rejected")).length;
const report = [
  `sing-box ${version}: ${cases.length} cases — ${passed} ok, ${rejected} expected rejections (validator and kernel agree), ${bugs.length} BUG (validator accepts, kernel rejects), ${fixtures.length} STRICT (validator only)`,
  ...lines
].join("\n");
await writeFile(join(output, "report.txt"), report + "\n");
console.log(report);
if (bugs.length) process.exitCode = 1;
