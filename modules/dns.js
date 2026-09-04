import {
  DIAL_DEFAULTS,
  DURATION_PATTERN,
  buildDialFields,
  compact,
  hasForbiddenKeys,
  mergeDeep,
  optionalPort,
  optionalPositiveInteger,
  parseJsonArray,
  parseJsonObject,
  splitLines,
  splitList,
  validateDialFields
} from "./shared.js";

export const DNS_SERVER_TYPE_META = Object.freeze({
  local: { label: "Local", note: "系统解析器 · 支持邻居域与 mDNS", prefix: "local-dns", dial: true },
  hosts: { label: "Hosts", note: "hosts 文件与预定义记录", prefix: "hosts" },
  tcp: { label: "TCP", note: "明文 DNS over TCP", prefix: "tcp-dns", dial: true, port: 53 },
  udp: { label: "UDP", note: "明文 DNS over UDP", prefix: "udp-dns", dial: true, port: 53 },
  tls: { label: "TLS · DoT", note: "DNS over TLS", prefix: "dot", dial: true, tls: true, port: 853 },
  quic: { label: "QUIC · DoQ", note: "DNS over QUIC", prefix: "doq", dial: true, tls: true, port: 853 },
  https: { label: "HTTPS · DoH", note: "DNS over HTTPS", prefix: "doh", dial: true, tls: true, http: true, port: 443 },
  h3: { label: "HTTP/3 · DoH3", note: "DNS over HTTP/3", prefix: "doh3", dial: true, tls: true, http: true, port: 443 },
  dhcp: { label: "DHCP", note: "跟随 DHCP 下发的上游", prefix: "dhcp-dns", dial: true },
  mdns: { label: "mDNS", note: "链路本地组播解析", prefix: "mdns", dial: true, badge: "1.14" },
  fakeip: { label: "Fake IP", note: "虚拟地址映射，需配合路由使用", prefix: "fakeip" },
  tailscale: { label: "Tailscale", note: "MagicDNS", prefix: "tailscale-dns", endpointTypes: ["tailscale"] },
  openconnect: { label: "OpenConnect", note: "VPN 下发的解析器", prefix: "openconnect-dns", endpointTypes: ["openconnect"], badge: "1.14" },
  openvpn: { label: "OpenVPN", note: "VPN 下发的解析器", prefix: "openvpn-dns", endpointTypes: ["openvpn-client"], badge: "1.14" },
  resolved: { label: "Resolved", note: "systemd-resolved 服务", prefix: "resolved-dns", service: true }
});

export const DNS_SERVER_TYPES = Object.keys(DNS_SERVER_TYPE_META);

const TLS_DEFAULTS = Object.freeze({
  tlsServerName: "",
  tlsInsecure: false,
  tlsDisableSni: false,
  tlsAlpn: "",
  tlsMinVersion: "",
  tlsMaxVersion: "",
  tlsCertificatePath: "",
  tlsUtlsFingerprint: ""
});

const COMMON_DEFAULTS = Object.freeze({ tag: "", enabled: true, advancedJson: "" });

const SERVER_DEFAULTS = Object.freeze({
  local: { ...COMMON_DEFAULTS, type: "local", preferGo: false, neighborDomain: "", ...DIAL_DEFAULTS },
  hosts: { ...COMMON_DEFAULTS, type: "hosts", path: "", predefinedJson: "" },
  tcp: { ...COMMON_DEFAULTS, type: "tcp", server: "", serverPort: "", ...DIAL_DEFAULTS },
  udp: { ...COMMON_DEFAULTS, type: "udp", server: "", serverPort: "", ...DIAL_DEFAULTS },
  tls: { ...COMMON_DEFAULTS, type: "tls", server: "", serverPort: "", ...TLS_DEFAULTS, ...DIAL_DEFAULTS },
  quic: { ...COMMON_DEFAULTS, type: "quic", server: "", serverPort: "", ...TLS_DEFAULTS, ...DIAL_DEFAULTS },
  https: { ...COMMON_DEFAULTS, type: "https", server: "", serverPort: "", path: "", headersJson: "", ...TLS_DEFAULTS, ...DIAL_DEFAULTS },
  h3: { ...COMMON_DEFAULTS, type: "h3", server: "", serverPort: "", path: "", headersJson: "", ...TLS_DEFAULTS, ...DIAL_DEFAULTS },
  dhcp: { ...COMMON_DEFAULTS, type: "dhcp", interface: "", ...DIAL_DEFAULTS },
  mdns: { ...COMMON_DEFAULTS, type: "mdns", interface: "", ...DIAL_DEFAULTS },
  fakeip: { ...COMMON_DEFAULTS, type: "fakeip", inet4Range: "198.18.0.0/15", inet6Range: "fc00::/18" },
  tailscale: { ...COMMON_DEFAULTS, type: "tailscale", endpoint: "", acceptDefaultResolvers: false, acceptSearchDomain: false },
  openconnect: { ...COMMON_DEFAULTS, type: "openconnect", endpoint: "", acceptDefaultResolvers: false, acceptSearchDomain: false },
  openvpn: { ...COMMON_DEFAULTS, type: "openvpn", endpoint: "", acceptDefaultResolvers: false, acceptSearchDomain: false },
  resolved: { ...COMMON_DEFAULTS, type: "resolved", service: "resolved", acceptDefaultResolvers: false }
});

const SHARED_DIAL_KEYS = [
  "detour", "bind_interface", "inet4_bind_address", "inet6_bind_address", "bind_address_no_port", "routing_mark",
  "reuse_addr", "netns", "connect_timeout", "tcp_fast_open", "tcp_multi_path", "disable_tcp_keep_alive", "tcp_keep_alive",
  "tcp_keep_alive_interval", "udp_fragment", "domain_resolver", "network_strategy", "network_type",
  "fallback_network_type", "fallback_delay"
];

const SERVER_EXTRA_KEYS = {
  local: new Set(["prefer_go", "neighbor_domain", ...SHARED_DIAL_KEYS]),
  hosts: new Set(["path", "predefined"]),
  tcp: new Set(["server", "server_port", ...SHARED_DIAL_KEYS]),
  udp: new Set(["server", "server_port", ...SHARED_DIAL_KEYS]),
  tls: new Set(["server", "server_port", "tls", ...SHARED_DIAL_KEYS]),
  quic: new Set(["server", "server_port", "tls", ...SHARED_DIAL_KEYS]),
  https: new Set(["server", "server_port", "path", "headers", "tls", ...SHARED_DIAL_KEYS]),
  h3: new Set(["server", "server_port", "path", "headers", "tls", ...SHARED_DIAL_KEYS]),
  dhcp: new Set(["interface", ...SHARED_DIAL_KEYS]),
  mdns: new Set(["interface", ...SHARED_DIAL_KEYS]),
  fakeip: new Set(["inet4_range", "inet6_range"]),
  tailscale: new Set(["endpoint", "accept_default_resolvers", "accept_search_domain"]),
  openconnect: new Set(["endpoint", "accept_default_resolvers", "accept_search_domain"]),
  openvpn: new Set(["endpoint", "accept_default_resolvers", "accept_search_domain"]),
  resolved: new Set(["service", "accept_default_resolvers"])
};

const FORBIDDEN_SERVER_KEYS = new Set(["address", "address_resolver", "address_strategy", "address_fallback_delay", "strategy", "domain_strategy", "client_subnet"]);

export function normalizeDnsServer(server = {}) {
  const type = DNS_SERVER_TYPE_META[server.type] ? server.type : "local";
  return { ...SERVER_DEFAULTS[type], ...server, type };
}

function buildTlsFields(server) {
  return compact({
    enabled: true,
    disable_sni: server.tlsDisableSni || undefined,
    server_name: String(server.tlsServerName || "").trim(),
    insecure: server.tlsInsecure || undefined,
    alpn: splitList(server.tlsAlpn),
    min_version: server.tlsMinVersion || undefined,
    max_version: server.tlsMaxVersion || undefined,
    certificate_path: String(server.tlsCertificatePath || "").trim(),
    utls: server.tlsUtlsFingerprint ? { enabled: true, fingerprint: server.tlsUtlsFingerprint } : undefined
  });
}

function buildRemote(server) {
  return {
    server: String(server.server || "").trim(),
    server_port: optionalPort(server.serverPort),
    ...buildDialFields(server)
  };
}

const SERVER_BUILDERS = {
  local: (server) => ({
    prefer_go: server.preferGo || undefined,
    neighbor_domain: splitList(server.neighborDomain),
    ...buildDialFields(server)
  }),
  hosts: (server) => ({
    path: splitLines(server.path),
    predefined: parseJsonObject(server.predefinedJson, "预定义 hosts")
  }),
  tcp: buildRemote,
  udp: buildRemote,
  tls: (server) => ({ ...buildRemote(server), tls: buildTlsFields(server) }),
  quic: (server) => ({ ...buildRemote(server), tls: buildTlsFields(server) }),
  https: (server) => ({
    ...buildRemote(server),
    path: String(server.path || "").trim(),
    headers: parseJsonObject(server.headersJson, "附加请求头"),
    tls: buildTlsFields(server)
  }),
  h3: (server) => ({
    ...buildRemote(server),
    path: String(server.path || "").trim(),
    headers: parseJsonObject(server.headersJson, "附加请求头"),
    tls: buildTlsFields(server)
  }),
  dhcp: (server) => ({ interface: String(server.interface || "").trim(), ...buildDialFields(server) }),
  mdns: (server) => ({ interface: splitList(server.interface), ...buildDialFields(server) }),
  fakeip: (server) => ({
    inet4_range: String(server.inet4Range || "").trim(),
    inet6_range: String(server.inet6Range || "").trim()
  }),
  tailscale: (server) => buildPushedResolver(server),
  openconnect: (server) => buildPushedResolver(server),
  openvpn: (server) => buildPushedResolver(server),
  resolved: (server) => ({
    service: String(server.service || "").trim(),
    accept_default_resolvers: server.acceptDefaultResolvers || undefined
  })
};

function buildPushedResolver(server) {
  return {
    endpoint: String(server.endpoint || "").trim(),
    accept_default_resolvers: server.acceptDefaultResolvers || undefined,
    accept_search_domain: server.acceptSearchDomain || undefined
  };
}

export function buildDnsServer(source) {
  const server = normalizeDnsServer(source);
  const extra = parseJsonObject(server.advancedJson, "附加 DNS Server 参数");
  const built = compact({ type: server.type, tag: String(server.tag || "").trim(), ...SERVER_BUILDERS[server.type](server) });
  return mergeDeep(extra, built);
}

const IPV4_PATTERN = /^(?:\d{1,3}\.){3}\d{1,3}$/;

function isIpAddress(value) {
  const text = String(value || "").trim();
  if (IPV4_PATTERN.test(text)) return text.split(".").every((part) => Number(part) <= 255);
  return /^[0-9a-f:]+$/i.test(text) && text.includes(":");
}

export function isIpPrefix(value, { requirePrefix = false } = {}) {
  const parts = String(value || "").trim().split("/");
  if (parts.length > 2 || !isIpAddress(parts[0])) return false;
  if (parts.length === 1) return !requirePrefix;
  const max = parts[0].includes(":") ? 128 : 32;
  return /^\d+$/.test(parts[1]) && Number(parts[1]) <= max;
}

function validateDuration(value, label) {
  return value && !DURATION_PATTERN.test(String(value).trim()) ? `${label}不是有效的 Go Duration，例如 300ms、10s 或 5m` : "";
}

function validateAdvancedJson(value, allowed, label) {
  let extra;
  try {
    extra = parseJsonObject(value, label);
  } catch (error) {
    return error.message;
  }
  const forbidden = hasForbiddenKeys(extra, FORBIDDEN_SERVER_KEYS);
  if (forbidden) return `${label}包含已弃用或不由本模块生成的字段：${forbidden}`;
  const unknown = Object.keys(extra).find((key) => !allowed.has(key) && key !== "type" && key !== "tag");
  return unknown ? `${label}不是该类型的 1.14 字段：${unknown}` : "";
}

export function validateDnsServer(source, { servers = [], endpoints = [], outboundTags = [], serviceTags = [] } = {}) {
  const server = normalizeDnsServer(source);
  const meta = DNS_SERVER_TYPE_META[server.type];
  const tag = String(server.tag || "").trim();
  if (!tag) return "请填写 DNS Server 标签";
  if (servers.some((item) => item.id !== server.id && String(item.tag || "").trim() === tag)) return "DNS Server 标签必须唯一";
  const advancedError = validateAdvancedJson(server.advancedJson, SERVER_EXTRA_KEYS[server.type], "附加 DNS Server 参数");
  if (advancedError) return advancedError;

  if (meta.dial) {
    const dialError = validateDialFields(server, outboundTags);
    if (dialError) return dialError;
  }
  if (["tcp", "udp", "tls", "quic", "https", "h3"].includes(server.type)) {
    if (!String(server.server || "").trim()) return "请填写 DNS 服务器地址";
    if (server.serverPort !== "" && !optionalPort(server.serverPort)) return "DNS 服务器端口必须在 1–65535 之间";
    if (!isIpAddress(server.server) && !String(server.domainResolver || "").trim()) {
      return "服务器地址是域名时，必须设置域名解析器 domain_resolver";
    }
  }
  if (["https", "h3"].includes(server.type)) {
    const path = String(server.path || "").trim();
    if (path && !path.startsWith("/")) return "DoH 路径必须以 / 开头";
    const headersError = validateAdvancedJson(server.headersJson, new Set(), "附加请求头");
    if (headersError && !headersError.includes("不是该类型")) return headersError;
  }
  if (server.type === "local") {
    const invalid = splitList(server.neighborDomain).find((item) => !item.startsWith("."));
    if (invalid) return `邻居域必须以 . 开头：${invalid}`;
  }
  if (server.type === "hosts") {
    try {
      const predefined = parseJsonObject(server.predefinedJson, "预定义 hosts");
      for (const [domain, addresses] of Object.entries(predefined)) {
        const list = Array.isArray(addresses) ? addresses : [addresses];
        const invalid = list.find((item) => !isIpAddress(item));
        if (invalid) return `预定义 hosts 中 ${domain} 的地址无效：${invalid}`;
      }
    } catch (error) {
      return error.message;
    }
  }
  if (server.type === "fakeip") {
    if (!isIpPrefix(server.inet4Range, { requirePrefix: true })) return "FakeIP IPv4 段必须是 CIDR，例如 198.18.0.0/15";
    if (server.inet6Range && !isIpPrefix(server.inet6Range, { requirePrefix: true })) return "FakeIP IPv6 段必须是 CIDR，例如 fc00::/18";
  }
  if (meta.endpointTypes) {
    const endpoint = String(server.endpoint || "").trim();
    if (!endpoint) return `请选择 ${meta.label} 端点`;
    const matched = endpoints.find((item) => String(item.tag || "").trim() === endpoint);
    if (!matched) return `端点不存在：${endpoint}`;
    if (!meta.endpointTypes.includes(matched.type)) return `${endpoint} 不是 ${meta.label} 端点`;
  }
  if (server.type === "resolved") {
    const service = String(server.service || "").trim();
    if (!service) return "请填写 Resolved 服务标签";
    if (serviceTags.length && !serviceTags.includes(service)) return `Resolved 服务不存在：${service}`;
  }
  return "";
}

export const DNS_RULE_ACTION_META = Object.freeze({
  route: { label: "Route · 路由到服务器", server: true },
  evaluate: { label: "Evaluate · 预解析并继续", server: true, badge: "1.14" },
  respond: { label: "Respond · 返回预解析结果", badge: "1.14" },
  "route-options": { label: "Route Options · 仅设置选项" },
  reject: { label: "Reject · 拒绝查询" },
  predefined: { label: "Predefined · 返回固定记录" }
});

const RCODES = ["NOERROR", "FORMERR", "SERVFAIL", "NXDOMAIN", "NOTIMP", "REFUSED"];

export const DNS_RULE_DEFAULTS = Object.freeze({
  type: "dns-rule",
  enabled: true,
  ruleType: "default",
  mode: "and",
  rulesJson: "",
  inbound: "",
  ipVersion: "",
  queryType: "",
  queryClientSubnet: "",
  queryDnssec: false,
  network: "",
  authUser: "",
  protocol: "",
  domain: "",
  domainSuffix: "",
  domainKeyword: "",
  domainRegex: "",
  sourceIpCidr: "",
  sourceIpIsPrivate: false,
  sourcePort: "",
  sourcePortRange: "",
  port: "",
  portRange: "",
  processName: "",
  processPath: "",
  processPathRegex: "",
  packageName: "",
  packageNameRegex: "",
  user: "",
  userId: "",
  clashMode: "",
  networkType: "",
  networkIsExpensive: false,
  networkIsConstrained: false,
  wifiSsid: "",
  wifiBssid: "",
  sourceMacAddress: "",
  sourceHostname: "",
  preferredBy: "",
  ruleSet: "",
  ruleSetIpCidrMatchSource: false,
  matchResponse: "",
  responseRcode: "",
  responseAnswer: "",
  responseNs: "",
  responseExtra: "",
  ipCidr: "",
  ipIsPrivate: false,
  ipAcceptAny: false,
  invert: false,
  action: "route",
  race: false,
  server: "",
  evaluateTag: "",
  speculative: false,
  disableCache: false,
  disableOptimisticCache: false,
  rewriteTtl: "",
  timeout: "",
  clientSubnet: "",
  removeClientSubnet: false,
  rejectMethod: "",
  rejectNoDrop: false,
  predefinedRcode: "",
  predefinedAnswer: "",
  predefinedNs: "",
  predefinedExtra: "",
  advancedJson: ""
});

const RULE_EXTRA_KEYS = new Set([
  "inbound", "ip_version", "query_type", "query_client_subnet", "query_dnssec", "network", "auth_user", "protocol",
  "domain", "domain_suffix", "domain_keyword", "domain_regex", "source_ip_cidr", "source_ip_is_private", "source_port",
  "source_port_range", "port", "port_range", "process_name", "process_path", "process_path_regex", "package_name",
  "package_name_regex", "user", "user_id", "clash_mode", "network_type", "network_is_expensive", "network_is_constrained",
  "interface_address", "network_interface_address", "default_interface_address", "source_mac_address", "source_hostname",
  "preferred_by", "wifi_ssid", "wifi_bssid", "rule_set", "rule_set_ip_cidr_match_source", "match_response", "ip_cidr",
  "ip_is_private", "ip_accept_any", "response_rcode", "response_answer", "response_ns", "response_extra", "invert",
  "type", "mode", "rules", "action", "race", "server", "tag", "speculative", "disable_cache", "disable_optimistic_cache",
  "rewrite_ttl", "timeout", "client_subnet", "remove_client_subnet", "method", "no_drop", "rcode", "answer", "ns", "extra"
]);

const FORBIDDEN_RULE_KEYS = new Set([
  "geoip", "geosite", "source_geoip", "outbound", "strategy", "rule_set_ipcidr_match_source", "rule_set_ip_cidr_accept_empty", "server_strategy"
]);

export function normalizeDnsRule(rule = {}) {
  return { ...DNS_RULE_DEFAULTS, ...rule };
}

function numericOrText(value) {
  return /^\d+$/.test(value) ? Number(value) : value;
}

function buildMatchResponse(rule) {
  const value = String(rule.matchResponse || "").trim();
  if (!value) return undefined;
  return value === "true" ? true : value;
}

function buildMatchFields(rule) {
  return {
    inbound: splitList(rule.inbound),
    ip_version: rule.ipVersion ? Number(rule.ipVersion) : undefined,
    query_type: splitList(rule.queryType).map(numericOrText),
    query_client_subnet: splitList(rule.queryClientSubnet),
    query_dnssec: rule.queryDnssec || undefined,
    network: rule.network || undefined,
    auth_user: splitList(rule.authUser),
    protocol: splitList(rule.protocol),
    domain: splitList(rule.domain),
    domain_suffix: splitList(rule.domainSuffix),
    domain_keyword: splitList(rule.domainKeyword),
    domain_regex: splitLines(rule.domainRegex),
    source_ip_cidr: splitList(rule.sourceIpCidr),
    source_ip_is_private: rule.sourceIpIsPrivate || undefined,
    source_port: splitList(rule.sourcePort).map(Number),
    source_port_range: splitList(rule.sourcePortRange),
    port: splitList(rule.port).map(Number),
    port_range: splitList(rule.portRange),
    process_name: splitLines(rule.processName),
    process_path: splitLines(rule.processPath),
    process_path_regex: splitLines(rule.processPathRegex),
    package_name: splitList(rule.packageName),
    package_name_regex: splitLines(rule.packageNameRegex),
    user: splitList(rule.user),
    user_id: splitList(rule.userId).map(Number),
    clash_mode: rule.clashMode || undefined,
    network_type: splitList(rule.networkType),
    network_is_expensive: rule.networkIsExpensive || undefined,
    network_is_constrained: rule.networkIsConstrained || undefined,
    source_mac_address: splitList(rule.sourceMacAddress),
    source_hostname: splitList(rule.sourceHostname),
    preferred_by: splitList(rule.preferredBy),
    wifi_ssid: splitLines(rule.wifiSsid),
    wifi_bssid: splitList(rule.wifiBssid),
    rule_set: splitList(rule.ruleSet),
    rule_set_ip_cidr_match_source: rule.ruleSetIpCidrMatchSource || undefined,
    match_response: buildMatchResponse(rule),
    response_rcode: rule.responseRcode || undefined,
    response_answer: splitLines(rule.responseAnswer),
    response_ns: splitLines(rule.responseNs),
    response_extra: splitLines(rule.responseExtra),
    ip_cidr: splitList(rule.ipCidr),
    ip_is_private: rule.ipIsPrivate || undefined,
    ip_accept_any: rule.ipAcceptAny || undefined,
    invert: rule.invert || undefined
  };
}

function buildRouteOptions(rule) {
  return {
    disable_cache: rule.disableCache || undefined,
    disable_optimistic_cache: rule.disableOptimisticCache || undefined,
    rewrite_ttl: rule.rewriteTtl === "" ? undefined : Number(rule.rewriteTtl),
    timeout: String(rule.timeout || "").trim(),
    client_subnet: rule.removeClientSubnet ? undefined : String(rule.clientSubnet || "").trim(),
    remove_client_subnet: rule.removeClientSubnet || undefined
  };
}

function buildRuleAction(rule) {
  const action = rule.action || "route";
  const options = buildRouteOptions(rule);
  const race = rule.race ? { race: true } : {};
  switch (action) {
    case "evaluate":
      return { action, server: String(rule.server || "").trim(), tag: String(rule.evaluateTag || "").trim(), speculative: rule.speculative || undefined, ...options };
    case "respond":
      return { action, ...race };
    case "route-options":
      return { action, ...options };
    case "reject":
      return { action, method: rule.rejectMethod || undefined, no_drop: rule.rejectNoDrop || undefined, ...race };
    case "predefined":
      return {
        action,
        rcode: rule.predefinedRcode || undefined,
        answer: splitLines(rule.predefinedAnswer),
        ns: splitLines(rule.predefinedNs),
        extra: splitLines(rule.predefinedExtra),
        ...race
      };
    default:
      return { action: "route", server: String(rule.server || "").trim(), speculative: rule.speculative || undefined, ...options, ...race };
  }
}

export function buildDnsRule(source) {
  const rule = normalizeDnsRule(source);
  const extra = parseJsonObject(rule.advancedJson, "附加规则参数");
  const body = rule.ruleType === "logical"
    ? {
        type: "logical",
        mode: rule.mode || "and",
        rules: parseJsonArray(rule.rulesJson, "逻辑子规则"),
        match_response: buildMatchResponse(rule),
        invert: rule.invert || undefined
      }
    : buildMatchFields(rule);
  return mergeDeep(extra, compact({ ...body, ...buildRuleAction(rule) }));
}

function validatePortList(value, label) {
  const invalid = splitList(value).find((item) => !optionalPort(item));
  return invalid ? `${label}无效：${invalid}` : "";
}

function validatePortRangeList(value, label) {
  const invalid = splitList(value).find((item) => !/^(\d+)?:(\d+)?$/.test(item) || item === ":");
  return invalid ? `${label}必须是 1000:2000、:3000 或 4000: 形式：${invalid}` : "";
}

export function validateDnsRule(source, { serverTags = [], ruleSetTags = null } = {}) {
  const rule = normalizeDnsRule(source);
  const action = rule.action || "route";
  if (!DNS_RULE_ACTION_META[action]) return `不支持的 DNS 规则动作：${action}`;

  const advancedError = (() => {
    let extra;
    try {
      extra = parseJsonObject(rule.advancedJson, "附加规则参数");
    } catch (error) {
      return error.message;
    }
    const forbidden = hasForbiddenKeys(extra, FORBIDDEN_RULE_KEYS);
    if (forbidden) return `附加规则参数包含已弃用或已移除的字段：${forbidden}`;
    const unknown = Object.keys(extra).find((key) => !RULE_EXTRA_KEYS.has(key));
    return unknown ? `附加规则参数不是 1.14 DNS 规则字段：${unknown}` : "";
  })();
  if (advancedError) return advancedError;

  if (rule.ruleType === "logical") {
    let subRules;
    try {
      subRules = parseJsonArray(rule.rulesJson, "逻辑子规则");
    } catch (error) {
      return error.message;
    }
    if (subRules.length < 1) return "逻辑规则至少需要一条子规则";
    if (!["and", "or"].includes(rule.mode)) return "逻辑规则模式只能是 and 或 or";
    const invalidSub = subRules.find((item) => !item || typeof item !== "object" || Array.isArray(item));
    if (invalidSub !== undefined) return "逻辑子规则必须是对象";
    if (subRules.some((item) => item.action === "evaluate")) return "evaluate 动作只能用于顶层 DNS 规则";
    const forbiddenSub = hasForbiddenKeys(subRules, FORBIDDEN_RULE_KEYS);
    if (forbiddenSub) return `逻辑子规则包含已弃用或已移除的字段：${forbiddenSub}`;
  } else {
    if (rule.ipVersion && !["4", "6"].includes(String(rule.ipVersion))) return "IP 版本只能是 4 或 6";
    if (rule.network && !["tcp", "udp"].includes(rule.network)) return "网络只能是 tcp 或 udp";
    const portError = validatePortList(rule.port, "端口") || validatePortList(rule.sourcePort, "来源端口");
    if (portError) return portError;
    const rangeError = validatePortRangeList(rule.portRange, "端口范围") || validatePortRangeList(rule.sourcePortRange, "来源端口范围");
    if (rangeError) return rangeError;
    const invalidSubnet = splitList(rule.queryClientSubnet).find((item) => !isIpPrefix(item));
    if (invalidSubnet) return `查询客户端子网无效：${invalidSubnet}`;
    const invalidCidr = splitList(rule.ipCidr).find((item) => !isIpPrefix(item));
    if (invalidCidr) return `响应 IP CIDR 无效：${invalidCidr}`;
    const invalidNetworkType = splitList(rule.networkType).find((item) => !["wifi", "cellular", "ethernet", "other"].includes(item));
    if (invalidNetworkType) return `不支持的网络类型：${invalidNetworkType}`;
    const invalidMac = splitList(rule.sourceMacAddress).find((item) => !/^([0-9a-f]{2}:){5}[0-9a-f]{2}$/i.test(item));
    if (invalidMac) return `来源 MAC 地址无效：${invalidMac}`;
    const invalidPreferred = splitList(rule.preferredBy).find((item) => !serverTags.includes(item));
    if (invalidPreferred) return `preferred_by 引用的 DNS Server 不存在：${invalidPreferred}`;
    const invalidQueryType = splitList(rule.queryType).find((item) => !/^[A-Za-z][A-Za-z0-9-]*$/.test(item) && !/^\d+$/.test(item));
    if (invalidQueryType) return `查询类型无效：${invalidQueryType}`;
    if (rule.responseRcode && !RCODES.includes(rule.responseRcode)) return `响应 RCODE 无效：${rule.responseRcode}`;
    if (Array.isArray(ruleSetTags)) {
      const missing = splitList(rule.ruleSet).find((item) => !ruleSetTags.includes(item));
      if (missing) return `规则集不存在：${missing}`;
    }
    const responseOnly = [rule.responseRcode, rule.responseAnswer, rule.responseNs, rule.responseExtra, rule.ipCidr]
      .some((value) => String(value || "").trim()) || rule.ipIsPrivate || rule.ipAcceptAny;
    if (responseOnly && !String(rule.matchResponse || "").trim()) {
      return "响应匹配字段（含 ip_cidr、ip_is_private、ip_accept_any）需要先设置 match_response，否则会使用 1.14 已弃用的旧地址过滤";
    }
  }

  const durationError = validateDuration(rule.timeout, "查询超时");
  if (durationError) return durationError;
  if (rule.rewriteTtl !== "" && (!Number.isInteger(Number(rule.rewriteTtl)) || Number(rule.rewriteTtl) < 0)) return "TTL 重写必须是非负整数";
  if (rule.clientSubnet && !isIpPrefix(rule.clientSubnet)) return `客户端子网无效：${rule.clientSubnet}`;
  if (rule.clientSubnet && rule.removeClientSubnet) return "client_subnet 与 remove_client_subnet 不能同时设置";
  if (rule.race && rule.speculative) return "race 与 speculative 不能同时启用";
  if (rule.race && !["route", "respond", "reject", "predefined"].includes(action)) return "race 只能用于 route、respond、reject 或 predefined 动作";
  if (rule.race && !String(rule.matchResponse || "").trim() && rule.ruleType !== "logical") return "race 需要配合 match_response 使用";

  if (DNS_RULE_ACTION_META[action].server) {
    const server = String(rule.server || "").trim();
    if (!server) return "请选择目标 DNS Server";
    if (serverTags.length && !serverTags.includes(server)) return `DNS Server 不存在：${server}`;
  }
  if (action === "reject") {
    if (rule.rejectMethod && !["default", "drop"].includes(rule.rejectMethod)) return "拒绝方式只能是 default 或 drop";
    if (rule.rejectMethod === "drop" && rule.rejectNoDrop) return "method 为 drop 时不能启用 no_drop";
  }
  if (action === "predefined") {
    if (rule.predefinedRcode && !RCODES.includes(rule.predefinedRcode)) return `预定义 RCODE 无效：${rule.predefinedRcode}`;
    if (!rule.predefinedRcode && !splitLines(rule.predefinedAnswer).length) return "预定义响应至少需要 RCODE 或一条 answer 记录";
  }
  if (action !== "route" && action !== "evaluate" && rule.speculative) return "speculative 只能用于 route 或 evaluate 动作";
  return "";
}

export const DNS_STATE_DEFAULTS = Object.freeze({
  final: "",
  strategy: "",
  defaultDomainResolver: "",
  disableCache: false,
  disableExpire: false,
  cacheCapacity: "",
  optimistic: false,
  optimisticTimeout: "",
  timeout: "",
  reverseMapping: false,
  clientSubnet: "",
  servers: [],
  rules: []
});

export function normalizeDnsState(dns = {}) {
  return {
    ...DNS_STATE_DEFAULTS,
    ...dns,
    servers: (dns.servers || []).map(normalizeDnsServer),
    rules: (dns.rules || []).map(normalizeDnsRule)
  };
}

export function activeDnsServers(dns) {
  return normalizeDnsState(dns).servers.filter((server) => server.enabled !== false);
}

export function activeDnsRules(dns) {
  return normalizeDnsState(dns).rules.filter((rule) => rule.enabled !== false);
}

function buildOptimistic(dns) {
  if (!dns.optimistic) return undefined;
  const timeout = String(dns.optimisticTimeout || "").trim();
  return timeout ? { enabled: true, timeout } : true;
}

export function buildDnsSection(source, { outboundTags = null } = {}) {
  const dns = normalizeDnsState(source);
  const servers = activeDnsServers(dns).map((server) => {
    const built = buildDnsServer(server);
    if (Array.isArray(outboundTags) && built.detour && !outboundTags.includes(built.detour)) {
      const { detour, ...rest } = built;
      return rest;
    }
    return built;
  });
  const rules = activeDnsRules(dns).map(buildDnsRule);
  const serverTags = servers.map((server) => server.tag);
  const final = String(dns.final || "").trim();
  return compact({
    servers,
    rules,
    final: serverTags.includes(final) ? final : undefined,
    strategy: dns.strategy || undefined,
    disable_cache: dns.disableCache || undefined,
    disable_expire: dns.disableExpire || undefined,
    cache_capacity: optionalPositiveInteger(dns.cacheCapacity),
    optimistic: buildOptimistic(dns),
    timeout: String(dns.timeout || "").trim(),
    reverse_mapping: dns.reverseMapping || undefined,
    client_subnet: String(dns.clientSubnet || "").trim()
  });
}

export function defaultDomainResolverTag(source) {
  const dns = normalizeDnsState(source);
  const servers = activeDnsServers(dns);
  const preferred = String(dns.defaultDomainResolver || "").trim();
  if (servers.some((server) => String(server.tag || "").trim() === preferred)) return preferred;
  const local = servers.find((server) => server.type === "local") || servers.find((server) => !["fakeip"].includes(server.type));
  return local ? String(local.tag || "").trim() : "";
}

export function validateDnsState(source, context = {}) {
  const dns = normalizeDnsState(source);
  const servers = activeDnsServers(dns);
  if (!servers.length) return "至少需要一个启用的 DNS Server";
  const serverTags = servers.map((server) => String(server.tag || "").trim());
  const duplicate = serverTags.find((tag, index) => serverTags.indexOf(tag) !== index);
  if (duplicate) return `DNS Server 标签重复：${duplicate}`;
  for (const server of servers) {
    const error = validateDnsServer(server, { ...context, servers: dns.servers });
    if (error) return `DNS Server「${server.tag || "未命名"}」：${error}`;
  }

  const rules = activeDnsRules(dns);
  let hasEvaluate = false;
  const evaluateTags = new Set();
  for (const [index, rule] of rules.entries()) {
    const error = validateDnsRule(rule, { ...context, serverTags });
    if (error) return `第 ${index + 1} 条 DNS 规则：${error}`;
    const matchResponse = String(rule.matchResponse || "").trim();
    if (matchResponse && !hasEvaluate) return `第 ${index + 1} 条 DNS 规则：match_response 需要前置的 evaluate 规则`;
    if (matchResponse && matchResponse !== "true" && !evaluateTags.has(matchResponse)) {
      return `第 ${index + 1} 条 DNS 规则：找不到标签为 ${matchResponse} 的 evaluate 规则`;
    }
    if (rule.action === "respond" && !hasEvaluate) return `第 ${index + 1} 条 DNS 规则：respond 需要前置的 evaluate 规则`;
    if (rule.action === "evaluate") {
      hasEvaluate = true;
      const tag = String(rule.evaluateTag || "").trim();
      if (tag) evaluateTags.add(tag);
    }
  }

  if (dns.optimistic && (dns.disableCache || dns.disableExpire)) return "乐观缓存与禁用缓存、禁用缓存过期冲突";
  const optimisticError = validateDuration(dns.optimisticTimeout, "乐观缓存超时");
  if (optimisticError) return optimisticError;
  const timeoutError = validateDuration(dns.timeout, "默认查询超时");
  if (timeoutError) return timeoutError;
  if (dns.clientSubnet && !isIpPrefix(dns.clientSubnet)) return `默认客户端子网无效：${dns.clientSubnet}`;
  if (dns.cacheCapacity !== "" && optionalPositiveInteger(dns.cacheCapacity) === undefined) return "缓存容量必须是正整数";
  const final = String(dns.final || "").trim();
  if (final && !serverTags.includes(final)) return `默认 DNS Server 不存在：${final}`;
  const resolver = String(dns.defaultDomainResolver || "").trim();
  if (resolver && !serverTags.includes(resolver)) return `默认域名解析器不存在：${resolver}`;
  return "";
}

export const dnsModule = {
  key: "dns",
  extendConfig(config, state, context = {}) {
    const section = buildDnsSection(state.dns, { outboundTags: context.outboundTags || null });
    config.dns = { ...section, servers: section.servers || [], rules: section.rules || [] };
    return config;
  }
};
