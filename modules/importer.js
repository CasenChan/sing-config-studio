// 把一份完整的 sing-box 配置反序列化成各模块的表单状态。
// 表单没有建模的字段会原样放进对应条目的“附加参数”，保证往返不丢配置。

import { normalizeDnsRule, normalizeDnsServer, normalizeDnsState } from "./dns.js";
import { normalizeStandardEndpoint } from "./endpoints.js";
import { normalizeTailscaleEndpoint } from "./tailscale.js";
import { normalizeInbound, buildInbound, INBOUND_TYPE_META } from "./inbound.js";
import { normalizeOutbound, buildOutbound, normalizeGroup, OUTBOUND_TYPE_META, GROUP_TYPE_META } from "./outbound.js";
import { normalizeRouteRule, normalizeRouteState, normalizeRuleSet, normalizeHeadlessRule } from "./route.js";
import { normalizeService, normalizeServiceState, SERVICE_TYPE_META } from "./services.js";
import { buildDnsServer, buildDnsRule } from "./dns.js";
import { buildRouteRule, buildRuleSet } from "./route.js";
import { buildService } from "./services.js";

// 只在特定路径下才算弃用的字段（同名字段在别处仍然合法）
const SCOPED_HINTS = [
  { key: "address", scope: /^\$\.dns\.servers\[\d+\]$/, hint: "旧版 DNS Server 格式已被 type 化的 DNS Server 取代" },
  { key: "outbound", scope: /^\$\.dns\.rules\[\d+\]$/, hint: "DNS 规则的 outbound 匹配项已在 1.14 移除" },
  { key: "fakeip", scope: /^\$\.dns$/, hint: "旧的 dns.fakeip 已在 1.14 移除，请改用 fakeip 类型的 DNS Server" }
];

const DEPRECATED_HINTS = {
  sniff: "入站 sniff 已由路由规则动作 sniff 取代",
  sniff_override_destination: "已由路由规则动作 sniff 取代",
  sniff_timeout: "已由路由规则动作 sniff 的 timeout 取代",
  domain_strategy: "已在 1.14 移除，请改用 domain_resolver 或 resolve 规则动作",
  udp_disable_domain_unmapping: "已由路由规则的 route-options 取代",
  inet4_address: "已合并为 TUN 的 address",
  inet6_address: "已合并为 TUN 的 address",
  inet4_route_address: "已合并为 TUN 的 route_address",
  inet6_route_address: "已合并为 TUN 的 route_address",
  inet4_route_exclude_address: "已合并为 TUN 的 route_exclude_address",
  inet6_route_exclude_address: "已合并为 TUN 的 route_exclude_address",
  endpoint_independent_nat: "已由 udp_mapping / udp_filtering 取代",
  proxy_protocol: "已在 1.13 移除",
  geoip: "已在 1.12 移除，请改用 rule-set",
  geosite: "已在 1.12 移除，请改用 rule-set",
  source_geoip: "已在 1.12 移除，请改用 rule-set",

  independent_cache: "已在 1.14 弃用",
  store_rdrc: "已迁移到 cache_file.rdrc_timeout",
  download_detour: "已由 rule-set 的 http_client 取代",
  rule_set_ipcidr_match_source: "已更名为 rule_set_ip_cidr_match_source",
  rule_set_ip_cidr_accept_empty: "已在 1.14 弃用，请改用 evaluate + match_response",
  address_resolver: "旧版 DNS Server 格式已被 domain_resolver 取代",
  address_strategy: "旧版 DNS Server 格式已被 domain_resolver 取代",
  gso: "已在 1.14 移除",
  recv_window_conn: "已在 1.14 移除",
  disable_mtu_discovery: "已在 1.14 移除",
  acme: "已由 certificate_provider 取代",
};

function camelCase(key) {
  return key.replace(/_([a-z0-9])/g, (_, char) => char.toUpperCase());
}

function toFieldValue(value, sample) {
  if (typeof sample === "boolean") return Boolean(value);
  if (Array.isArray(value)) return value.map((item) => (typeof item === "object" ? JSON.stringify(item) : String(item))).join(", ");
  if (value === undefined || value === null) return "";
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
}

// 导入时先把模板清空，源配置里没有的字段就不该凭默认值凭空出现
function emptyTemplate(base) {
  return Object.fromEntries(Object.entries(base).map(([key, value]) => {
    if (key === "type") return [key, value];
    if (typeof value === "boolean") return [key, false];
    if (Array.isArray(value)) return [key, []];
    return [key, ""];
  }));
}

function assignSimple(defaults, source, skip = []) {
  const result = {};
  for (const [key, value] of Object.entries(source || {})) {
    if (skip.includes(key)) continue;
    const camel = camelCase(key);
    if (!(camel in defaults)) continue;
    // 对象或对象数组交给附加参数保留，避免被压成字符串
    if (value && typeof value === "object" && !Array.isArray(value)) continue;
    if (Array.isArray(value) && value.some((item) => item && typeof item === "object")) continue;
    result[camel] = toFieldValue(value, defaults[camel]);
  }
  return result;
}

function deepLeftover(source, built) {
  if (!source || typeof source !== "object" || Array.isArray(source)) return {};
  const result = {};
  for (const [key, value] of Object.entries(source)) {
    const other = built?.[key];
    if (other === undefined) {
      result[key] = value;
      continue;
    }
    if (value && typeof value === "object" && !Array.isArray(value)) {
      const nested = deepLeftover(value, other);
      if (Object.keys(nested).length) result[key] = nested;
    }
  }
  return result;
}

function collectDeprecated(value, path, notices, seen) {
  if (Array.isArray(value)) {
    value.forEach((item, index) => collectDeprecated(item, `${path}[${index}]`, notices, seen));
    return;
  }
  if (!value || typeof value !== "object") return;
  for (const [key, child] of Object.entries(value)) {
    const scoped = SCOPED_HINTS.find((item) => item.key === key && item.scope.test(path));
    const hint = DEPRECATED_HINTS[key] || scoped?.hint;
    if (hint && !seen.has(`${key}@${scoped ? "scoped" : "global"}`)) {
      seen.add(`${key}@${scoped ? "scoped" : "global"}`);
      notices.push({ level: "warning", message: `${path}.${key}：${hint}，导入时已忽略` });
    }
    collectDeprecated(child, `${path}.${key}`, notices, seen);
  }
}

function stripDeprecated(value) {
  if (Array.isArray(value)) return value.map(stripDeprecated);
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(
    Object.entries(value)
      .filter(([key]) => !DEPRECATED_HINTS[key])
      .map(([key, child]) => [key, stripDeprecated(child)])
  );
}

// DNS Server / DNS 规则里的同名字段单独剔除
function stripScoped(value, keys) {
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(Object.entries(value).filter(([key]) => !keys.includes(key)));
}

function withLeftover(item, source, build) {
  let built = {};
  try {
    built = build({ ...item, advancedJson: "" }) || {};
  } catch {
    built = {};
  }
  const leftover = stripDeprecated(deepLeftover(source, built));
  delete leftover.type;
  delete leftover.tag;
  return Object.keys(leftover).length ? { ...item, advancedJson: JSON.stringify(leftover, null, 2) } : item;
}

function makeId(prefix, index) {
  return `${prefix}-${index}-${Math.random().toString(16).slice(2, 8)}`;
}

function importTls(source, target) {
  const tls = source.tls;
  if (!tls || typeof tls !== "object") return;
  if ("enabled" in target) target.enabled = Boolean(tls.enabled);
  target.tlsEnabled = Boolean(tls.enabled);
  target.tls = Boolean(tls.enabled);
  target.sni = tls.server_name || "";
  target.tlsServerName = tls.server_name || "";
  target.insecure = Boolean(tls.insecure);
  target.disableSni = Boolean(tls.disable_sni);
  target.alpn = (tls.alpn || []).join(", ");
  target.tlsAlpn = (tls.alpn || []).join(", ");
  target.tlsMinVersion = tls.min_version || "";
  target.tlsMaxVersion = tls.max_version || "";
  target.tlsCertificatePath = tls.certificate_path || "";
  target.tlsCertificate = Array.isArray(tls.certificate) ? tls.certificate.join("\n") : tls.certificate || "";
  target.tlsKeyPath = tls.key_path || "";
  target.tlsKey = Array.isArray(tls.key) ? tls.key.join("\n") : tls.key || "";
  target.fingerprint = tls.utls?.enabled ? tls.utls.fingerprint || "" : "";
  target.tlsFragment = Boolean(tls.fragment);
  target.tlsRecordFragment = Boolean(tls.record_fragment);
  target.tlsFragmentFallbackDelay = tls.fragment_fallback_delay || "";
  if (tls.reality?.enabled) {
    target.reality = true;
    target.publicKey = tls.reality.public_key || "";
    target.shortId = Array.isArray(tls.reality.short_id) ? tls.reality.short_id.join(", ") : tls.reality.short_id || "";
    // 服务端 REALITY 字段
    target.realityEnabled = true;
    target.realityHandshakeServer = tls.reality.handshake?.server || "";
    target.realityHandshakePort = String(tls.reality.handshake?.server_port || 443);
    target.realityPrivateKey = tls.reality.private_key || "";
    target.realityShortId = target.shortId;
    target.realityMaxTimeDifference = tls.reality.max_time_difference || "";
  }
  if (tls.ech?.enabled) {
    target.echEnabled = true;
    target.echConfig = Array.isArray(tls.ech.config) ? tls.ech.config.join("\n") : tls.ech.config || "";
    target.echConfigPath = tls.ech.config_path || "";
  }
}

function importTransport(source, target) {
  const transport = source.transport;
  if (!transport || typeof transport !== "object") return;
  target.transport = transport.type || "tcp";
  target.transportType = transport.type || "";
  if (transport.type === "grpc") {
    target.path = transport.service_name || "";
    target.transportServiceName = transport.service_name || "";
  } else {
    target.path = transport.path || "";
    target.transportPath = transport.path || "";
  }
  const headerHost = Object.entries(transport.headers || {}).find(([key]) => key.toLowerCase() === "host")?.[1];
  const host = headerHost || transport.host;
  target.host = Array.isArray(host) ? host.join(", ") : host || "";
  target.transportHost = target.host;
  if (transport.max_early_data) target.maxEarlyData = String(transport.max_early_data);
  if (transport.early_data_header_name) target.earlyDataHeaderName = transport.early_data_header_name;
  if (transport.method) target.transportMethod = transport.method;
}

function importMultiplex(source, target) {
  const multiplex = source.multiplex;
  if (!multiplex || typeof multiplex !== "object") return;
  target.multiplexEnabled = Boolean(multiplex.enabled);
  target.multiplexProtocol = multiplex.protocol || "";
  target.maxConnections = multiplex.max_connections ? String(multiplex.max_connections) : "";
  target.minStreams = multiplex.min_streams ? String(multiplex.min_streams) : "";
  target.maxStreams = multiplex.max_streams ? String(multiplex.max_streams) : "";
  target.multiplexPadding = Boolean(multiplex.padding);
  if (multiplex.brutal?.enabled) {
    target.brutalEnabled = true;
    target.brutalUp = String(multiplex.brutal.up_mbps || "");
    target.brutalDown = String(multiplex.brutal.down_mbps || "");
  }
}

export function importInbound(source, index) {
  if (!INBOUND_TYPE_META[source?.type]) return null;
  const base = normalizeInbound({ type: source.type });
  const item = {
    ...emptyTemplate(base),
    id: makeId("inbound", index),
    tag: source.tag || base.tag,
    enabled: true,
    ...assignSimple(base, source, ["tls", "transport", "multiplex", "users", "obfs", "handshake", "platform", "headers", "predefined"])
  };
  importTls(source, item);
  importTransport(source, item);
  importMultiplex(source, item);
  if (Array.isArray(source.users)) item.usersJson = JSON.stringify(source.users, null, 2);
  if (source.platform) item.platformJson = JSON.stringify(source.platform, null, 2);
  if (source.obfs) {
    item.obfsType = source.obfs.type || "";
    item.obfsPassword = source.obfs.password || "";
  }
  if (source.handshake) {
    item.handshakeServer = source.handshake.server || "";
    item.handshakePort = String(source.handshake.server_port || 443);
  }
  return withLeftover(normalizeInbound(item), source, buildInbound);
}

export function importOutbound(source, index) {
  if (GROUP_TYPE_META[source?.type]) return null;
  if (!OUTBOUND_TYPE_META[source?.type]) return null;
  const base = normalizeOutbound({ type: source.type });
  const item = {
    ...emptyTemplate(base),
    id: makeId("node", index),
    tag: source.tag || base.tag,
    enabled: true,
    server: source.server || "",
    port: source.server_port || base.port,
    ...assignSimple(base, source, ["tls", "transport", "multiplex", "obfs", "udp_over_tcp", "server", "server_port", "headers", "torrc"])
  };
  importTls(source, item);
  importTransport(source, item);
  importMultiplex(source, item);
  if (source.obfs) {
    if (typeof source.obfs === "string") item.obfs = source.obfs;
    else {
      item.obfsType = source.obfs.type || "";
      item.obfsPassword = source.obfs.password || "";
    }
  }
  if (source.udp_over_tcp) {
    item.uotEnabled = Boolean(source.udp_over_tcp.enabled ?? true);
    if (source.udp_over_tcp.version) item.uotVersion = String(source.udp_over_tcp.version);
  }
  if (source.headers) item.headersJson = JSON.stringify(source.headers, null, 2);
  if (source.torrc) item.torrcJson = JSON.stringify(source.torrc, null, 2);
  if (source.auth_str) item.authString = source.auth_str;
  return withLeftover(normalizeOutbound(item), source, buildOutbound);
}

export function importGroup(source, index) {
  if (!GROUP_TYPE_META[source?.type]) return null;
  return normalizeGroup({
    id: makeId("group", index),
    type: source.type,
    tag: source.tag || "",
    enabled: true,
    includeAllNodes: false,
    includeDirect: (source.outbounds || []).includes("direct"),
    members: (source.outbounds || []).filter((tag) => tag !== "direct").join(", "),
    defaultMember: source.default || "",
    interruptExistConnections: Boolean(source.interrupt_exist_connections),
    url: source.url || "",
    interval: source.interval || "",
    tolerance: source.tolerance ? String(source.tolerance) : "",
    idleTimeout: source.idle_timeout || ""
  });
}

export function importEndpoint(source, index) {
  if (!source?.type) return null;
  const id = makeId("endpoint", index);
  if (source.type === "tailscale") {
    const base = normalizeTailscaleEndpoint({});
    const item = { ...emptyTemplate(base), id, tag: source.tag || "", ...assignSimple(base, source, ["ssh_server"]) };
    if (source.ssh_server) {
      item.sshServer = true;
      if (typeof source.ssh_server === "object") {
        item.sshDisablePty = Boolean(source.ssh_server.disable_pty);
        item.sshDisableSftp = Boolean(source.ssh_server.disable_sftp);
        item.sshDisableForwarding = Boolean(source.ssh_server.disable_forwarding);
      }
    }
    return normalizeTailscaleEndpoint(item);
  }
  const base = normalizeStandardEndpoint({ type: source.type });
  if (base.type !== source.type) return null;
  const item = {
    ...emptyTemplate(base),
    id,
    tag: source.tag || "",
    ...assignSimple(base, source, ["peers", "users", "tls", "push", "servers", "token"])
  };
  if (Array.isArray(source.peers)) item.peersJson = JSON.stringify(source.peers, null, 2);
  if (Array.isArray(source.users)) item.usersJson = JSON.stringify(source.users, null, 2);
  if (Array.isArray(source.servers)) item.serversJson = JSON.stringify(source.servers, null, 2);
  const leftover = stripDeprecated(deepLeftover(source, { type: source.type, tag: source.tag }));
  delete leftover.type;
  delete leftover.tag;
  return normalizeStandardEndpoint(item);
}

export function importDnsServer(source, index) {
  if (!source?.type) return null;
  const base = normalizeDnsServer({ type: source.type });
  if (base.type !== source.type) return null;
  source = stripScoped(source, ["address", "address_resolver", "address_strategy", "address_fallback_delay"]);
  const item = {
    ...emptyTemplate(base),
    id: makeId("dns", index),
    tag: source.tag || base.tag,
    enabled: true,
    ...assignSimple(base, source, ["tls", "predefined", "headers"])
  };
  if (source.tls) {
    item.tlsServerName = source.tls.server_name || "";
    item.tlsInsecure = Boolean(source.tls.insecure);
    item.tlsDisableSni = Boolean(source.tls.disable_sni);
    item.tlsAlpn = (source.tls.alpn || []).join(", ");
    item.tlsMinVersion = source.tls.min_version || "";
    item.tlsMaxVersion = source.tls.max_version || "";
    item.tlsCertificatePath = source.tls.certificate_path || "";
    item.tlsUtlsFingerprint = source.tls.utls?.enabled ? source.tls.utls.fingerprint || "" : "";
  }
  if (source.predefined) item.predefinedJson = JSON.stringify(source.predefined, null, 2);
  if (source.headers) item.headersJson = JSON.stringify(source.headers, null, 2);
  if (Array.isArray(source.path)) item.path = source.path.join("\n");
  return withLeftover(normalizeDnsServer(item), source, buildDnsServer);
}

function importRuleCommon(base, source, skip) {
  const item = { ...emptyTemplate(base), action: "route", ruleType: "default", mode: "and", ...assignSimple(base, source, skip) };
  if (source.type === "logical") {
    item.ruleType = "logical";
    item.mode = source.mode || "and";
    item.rulesJson = JSON.stringify(source.rules || [], null, 2);
  }
  return item;
}

export function importDnsRule(source, index) {
  source = stripScoped(source, ["outbound"]);
  const base = normalizeDnsRule({});
  const item = importRuleCommon(base, source, ["rules", "answer", "ns", "extra", "match_response", "server", "tag"]);
  item.id = makeId("dns-rule", index);
  item.enabled = true;
  item.action = source.action || "route";
  item.server = source.server || "";
  if (source.action === "evaluate") item.evaluateTag = source.tag || "";
  if (source.match_response !== undefined) item.matchResponse = source.match_response === true ? "true" : String(source.match_response);
  if (source.action === "predefined") {
    item.predefinedRcode = source.rcode || "";
    item.predefinedAnswer = (source.answer || []).join("\n");
    item.predefinedNs = (source.ns || []).join("\n");
    item.predefinedExtra = (source.extra || []).join("\n");
  }
  if (source.method) item.rejectMethod = source.method;
  if (source.no_drop) item.rejectNoDrop = true;
  return withLeftover(normalizeDnsRule(item), source, buildDnsRule);
}

export function importRouteRule(source, index) {
  const base = normalizeRouteRule({});
  const item = importRuleCommon(base, source, ["rules", "sniffer", "timeout", "server", "strategy", "method", "no_drop"]);
  item.id = makeId("route-rule", index);
  item.enabled = true;
  item.action = source.action || "route";
  item.outbound = source.outbound || "";
  if (source.action === "sniff") {
    item.sniffer = (source.sniffer || []).join(", ");
    item.sniffTimeout = source.timeout || "";
  }
  if (source.action === "resolve") {
    item.resolveServer = source.server || "";
    item.resolveStrategy = source.strategy || "";
    item.resolveTimeout = source.timeout || "";
    item.resolveDisableCache = Boolean(source.disable_cache);
    item.resolveDisableOptimisticCache = Boolean(source.disable_optimistic_cache);
    item.resolveRewriteTtl = source.rewrite_ttl === undefined ? "" : String(source.rewrite_ttl);
    item.resolveClientSubnet = source.client_subnet || "";
  }
  if (source.action === "reject") {
    item.rejectMethod = source.method || "";
    item.rejectNoDrop = Boolean(source.no_drop);
  }
  return withLeftover(normalizeRouteRule(item), source, buildRouteRule);
}

export function importRuleSet(source, index) {
  const tags = Array.isArray(source.tag) ? source.tag : [source.tag].filter(Boolean);
  const item = normalizeRuleSet({
    id: makeId("rule-set", index),
    type: source.type || "remote",
    tag: tags.join(", "),
    enabled: true,
    format: source.format || "",
    path: source.path || "",
    url: source.url || "",
    initialPath: source.initial_path || "",
    updateInterval: source.update_interval || "",
    httpClientMode: typeof source.http_client === "string" ? "tag" : source.http_client ? "inline" : "",
    httpClientTag: typeof source.http_client === "string" ? source.http_client : "",
    httpClientJson: source.http_client && typeof source.http_client === "object" ? JSON.stringify(source.http_client, null, 2) : "",
    headlessRules: (source.rules || []).map((rule) => {
      const base = normalizeHeadlessRule({});
      const mapped = { ...emptyTemplate(base), ruleType: "default", mode: "and", ...assignSimple(base, rule, ["rules"]) };
      if (rule.type === "logical") {
        mapped.ruleType = "logical";
        mapped.mode = rule.mode || "and";
        mapped.rulesJson = JSON.stringify(rule.rules || [], null, 2);
      }
      return normalizeHeadlessRule(mapped);
    })
  });
  return withLeftover(item, source, buildRuleSet);
}

export function importService(source, index) {
  if (!SERVICE_TYPE_META[source?.type]) return null;
  const base = normalizeService({ type: source.type });
  const item = {
    ...emptyTemplate(base),
    id: makeId("service", index),
    tag: source.tag || base.tag,
    enabled: true,
    ...assignSimple(base, source, ["tls", "users", "servers", "headers", "devices", "dashboard", "stun", "verify_client_url"])
  };
  if (source.tls) {
    item.tlsEnabled = Boolean(source.tls.enabled);
    item.tlsServerName = source.tls.server_name || "";
    item.tlsCertificatePath = source.tls.certificate_path || "";
    item.tlsKeyPath = source.tls.key_path || "";
  }
  if (Array.isArray(source.users)) item.usersJson = JSON.stringify(source.users, null, 2);
  if (source.servers) item.serversJson = JSON.stringify(source.servers, null, 2);
  if (source.headers) item.headersJson = JSON.stringify(source.headers, null, 2);
  if (Array.isArray(source.devices)) item.devicesJson = JSON.stringify(source.devices, null, 2);
  if (source.dashboard) {
    item.dashboardEnabled = Boolean(source.dashboard.enabled);
    item.dashboardPath = source.dashboard.path || "";
    item.dashboardDownloadUrl = source.dashboard.download_url || "";
    item.dashboardUpdateInterval = source.dashboard.update_interval || "";
  }
  if (source.stun) {
    item.stunListen = source.stun.listen || "";
    item.stunListenPort = String(source.stun.listen_port || "");
  }
  if (Array.isArray(source.verify_client_url)) {
    item.verifyClientUrl = source.verify_client_url.map((entry) => (typeof entry === "string" ? entry : entry.url)).join(", ");
  }
  return withLeftover(normalizeService(item), source, buildService);
}

export function importConfig(config) {
  if (!config || typeof config !== "object" || Array.isArray(config)) throw new Error("配置必须是 JSON 对象");
  const notices = [];
  const seen = new Set();
  collectDeprecated(config, "$", notices, seen);

  const inbounds = (config.inbounds || []).map(importInbound).filter(Boolean);
  const skippedInbounds = (config.inbounds || []).length - inbounds.length;
  if (skippedInbounds > 0) notices.push({ level: "warning", message: `${skippedInbounds} 个入站类型暂不支持，已跳过` });

  const nodes = (config.outbounds || []).map(importOutbound).filter(Boolean).filter((node) => node.type !== "direct" || node.tag !== "direct");
  const groups = (config.outbounds || []).map(importGroup).filter(Boolean);
  const endpoints = (config.endpoints || []).map(importEndpoint).filter(Boolean);
  const services = (config.services || []).map(importService).filter(Boolean);

  const dnsState = normalizeDnsState({
    final: config.dns?.final || "",
    strategy: config.dns?.strategy || "",
    defaultDomainResolver: typeof config.route?.default_domain_resolver === "object"
      ? config.route.default_domain_resolver.server || ""
      : config.route?.default_domain_resolver || "",
    disableCache: Boolean(config.dns?.disable_cache),
    disableExpire: Boolean(config.dns?.disable_expire),
    cacheCapacity: config.dns?.cache_capacity ? String(config.dns.cache_capacity) : "",
    optimistic: Boolean(config.dns?.optimistic),
    optimisticTimeout: typeof config.dns?.optimistic === "object" ? config.dns.optimistic.timeout || "" : "",
    timeout: config.dns?.timeout || "",
    reverseMapping: Boolean(config.dns?.reverse_mapping),
    clientSubnet: config.dns?.client_subnet || "",
    servers: (config.dns?.servers || []).map(importDnsServer).filter(Boolean),
    rules: (config.dns?.rules || []).map(importDnsRule)
  });

  const routeState = normalizeRouteState({
    final: config.route?.final || "",
    autoDetectInterface: config.route?.auto_detect_interface ? "on" : (config.route ? "off" : "auto"),
    overrideAndroidVpn: Boolean(config.route?.override_android_vpn),
    defaultInterface: config.route?.default_interface || "",
    defaultMark: config.route?.default_mark ? String(config.route.default_mark) : "",
    findProcess: Boolean(config.route?.find_process),
    findNeighbor: Boolean(config.route?.find_neighbor),
    dhcpLeaseFiles: (config.route?.dhcp_lease_files || []).join("\n"),
    defaultNetworkStrategy: config.route?.default_network_strategy || "",
    defaultNetworkType: (config.route?.default_network_type || []).join(", "),
    defaultFallbackNetworkType: (config.route?.default_fallback_network_type || []).join(", "),
    defaultFallbackDelay: config.route?.default_fallback_delay || "",
    rules: (config.route?.rules || []).map(importRouteRule),
    ruleSets: (config.route?.rule_set || []).map(importRuleSet)
  });

  const serviceState = normalizeServiceState({
    ntpEnabled: Boolean(config.ntp?.enabled),
    ntpServer: config.ntp?.server || "time.apple.com",
    ntpServerPort: config.ntp?.server_port ? String(config.ntp.server_port) : "123",
    ntpInterval: config.ntp?.interval || "",
    ntpWriteToSystem: Boolean(config.ntp?.write_to_system),
    ntpDetour: config.ntp?.detour || "",
    certificateStore: config.certificate?.store || "",
    certificatePath: (config.certificate?.certificate_path || []).join("\n"),
    certificateDirectoryPath: (config.certificate?.certificate_directory_path || []).join("\n"),
    cacheEnabled: Boolean(config.experimental?.cache_file?.enabled),
    cachePath: config.experimental?.cache_file?.path || "",
    cacheId: config.experimental?.cache_file?.cache_id || "",
    cacheStoreFakeip: Boolean(config.experimental?.cache_file?.store_fakeip),
    cacheStoreDns: Boolean(config.experimental?.cache_file?.store_dns),
    cacheRdrcTimeout: config.experimental?.cache_file?.rdrc_timeout || "",
    clashEnabled: Boolean(config.experimental?.clash_api),
    clashController: config.experimental?.clash_api?.external_controller || "127.0.0.1:9090",
    clashSecret: config.experimental?.clash_api?.secret || "",
    clashDefaultMode: config.experimental?.clash_api?.default_mode || "Rule",
    clashExternalUi: config.experimental?.clash_api?.external_ui || "",
    clashExternalUiDownloadUrl: config.experimental?.clash_api?.external_ui_download_url || "",
    clashAllowOrigin: (config.experimental?.clash_api?.access_control_allow_origin || []).join(", "),
    clashAllowPrivateNetwork: Boolean(config.experimental?.clash_api?.access_control_allow_private_network),
    v2rayEnabled: Boolean(config.experimental?.v2ray_api),
    v2rayListen: config.experimental?.v2ray_api?.listen || "127.0.0.1:8080",
    v2rayStats: Boolean(config.experimental?.v2ray_api?.stats?.enabled),
    v2rayStatsInbounds: (config.experimental?.v2ray_api?.stats?.inbounds || []).join(", "),
    v2rayStatsOutbounds: (config.experimental?.v2ray_api?.stats?.outbounds || []).join(", "),
    v2rayStatsUsers: (config.experimental?.v2ray_api?.stats?.users || []).join(", "),
    services
  });

  const settings = { logLevel: config.log?.level || "info" };
  const counts = {
    inbounds: inbounds.length,
    nodes: nodes.length,
    groups: groups.length,
    endpoints: endpoints.length,
    dnsServers: dnsState.servers.length,
    dnsRules: dnsState.rules.length,
    routeRules: routeState.rules.length,
    ruleSets: routeState.ruleSets.length,
    services: services.length
  };
  if (!inbounds.length) notices.push({ level: "warning", message: "导入的配置没有入站，生成前需要至少添加一个" });
  if (!dnsState.servers.length) notices.push({ level: "warning", message: "导入的配置没有 DNS Server，生成前需要至少添加一个" });

  return { state: { settings, inbounds, nodes, groups, endpoints, dns: dnsState, route: routeState, serviceState }, notices, counts };
}
