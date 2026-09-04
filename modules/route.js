import {
  DURATION_PATTERN,
  compact,
  hasForbiddenKeys,
  mergeDeep,
  optionalPort,
  optionalPositiveInteger,
  parseJsonArray,
  parseJsonObject,
  splitLines,
  splitList
} from "./shared.js";

export const ROUTE_ACTION_META = Object.freeze({
  route: { label: "Route · 路由到出站", outbound: true, options: true },
  bypass: { label: "Bypass · 内核级绕过", outbound: true, options: true, badge: "1.13", note: "仅 Linux 且启用 auto_redirect 时生效" },
  reject: { label: "Reject · 拒绝连接" },
  "hijack-dns": { label: "Hijack DNS · 劫持到 DNS 模块" },
  "route-options": { label: "Route Options · 仅设置选项", options: true },
  sniff: { label: "Sniff · 协议嗅探" },
  resolve: { label: "Resolve · 解析目标域名" }
});

export const SNIFFERS = ["tls", "http", "quic", "dns", "stun", "bittorrent", "dtls", "ssh", "rdp", "ntp"];
const NETWORKS = ["tcp", "udp", "icmp"];
const INTERFACE_TYPES = ["wifi", "cellular", "ethernet", "other"];
const REJECT_METHODS = ["default", "drop", "reply"];
const TLS_SPOOF_METHODS = ["wrong-sequence", "wrong-checksum", "wrong-ack", "wrong-md5", "wrong-timestamp"];
const STRATEGIES = ["prefer_ipv4", "prefer_ipv6", "ipv4_only", "ipv6_only"];
const ROUTE_PREFERRED_BY = ["tailscale", "wireguard", "bridge"];

export const ROUTE_RULE_DEFAULTS = Object.freeze({
  enabled: true,
  ruleType: "default",
  mode: "and",
  rulesJson: "",
  inbound: "",
  ipVersion: "",
  network: "",
  authUser: "",
  protocol: "",
  client: "",
  domain: "",
  domainSuffix: "",
  domainKeyword: "",
  domainRegex: "",
  sourceIpCidr: "",
  sourceIpIsPrivate: false,
  ipCidr: "",
  ipIsPrivate: false,
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
  defaultInterfaceAddress: "",
  sourceMacAddress: "",
  sourceHostname: "",
  preferredBy: "",
  ruleSet: "",
  ruleSetIpCidrMatchSource: false,
  invert: false,
  action: "route",
  outbound: "",
  overrideAddress: "",
  overridePort: "",
  networkStrategy: "",
  udpDisableDomainUnmapping: false,
  udpConnect: false,
  udpTimeout: "",
  tlsFragment: false,
  tlsFragmentFallbackDelay: "",
  tlsRecordFragment: false,
  tlsSpoof: "",
  tlsSpoofMethod: "",
  rejectMethod: "",
  rejectNoDrop: false,
  sniffer: "",
  sniffTimeout: "",
  resolveServer: "",
  resolveStrategy: "",
  resolveDisableCache: false,
  resolveDisableOptimisticCache: false,
  resolveRewriteTtl: "",
  resolveTimeout: "",
  resolveClientSubnet: "",
  advancedJson: ""
});

const RULE_EXTRA_KEYS = new Set([
  "inbound", "ip_version", "network", "auth_user", "protocol", "client", "domain", "domain_suffix", "domain_keyword",
  "domain_regex", "source_ip_cidr", "source_ip_is_private", "ip_cidr", "ip_is_private", "source_port", "source_port_range",
  "port", "port_range", "process_name", "process_path", "process_path_regex", "package_name", "package_name_regex", "user",
  "user_id", "clash_mode", "network_type", "network_is_expensive", "network_is_constrained", "wifi_ssid", "wifi_bssid",
  "interface_address", "network_interface_address", "default_interface_address", "source_mac_address", "source_hostname",
  "preferred_by", "rule_set", "rule_set_ip_cidr_match_source", "invert", "type", "mode", "rules", "action", "outbound",
  "override_address", "override_port", "network_strategy", "network_type", "fallback_network_type", "fallback_delay",
  "udp_disable_domain_unmapping", "udp_connect", "udp_timeout", "tls_fragment", "tls_fragment_fallback_delay",
  "tls_record_fragment", "tls_spoof", "tls_spoof_method", "method", "no_drop", "sniffer", "timeout", "server", "strategy",
  "disable_cache", "disable_optimistic_cache", "rewrite_ttl", "client_subnet"
]);

const FORBIDDEN_RULE_KEYS = new Set(["geoip", "geosite", "source_geoip", "rule_set_ipcidr_match_source", "domain_strategy"]);

export function normalizeRouteRule(rule = {}) {
  return { ...ROUTE_RULE_DEFAULTS, ...rule };
}

function buildRouteMatchFields(rule) {
  return {
    inbound: splitList(rule.inbound),
    ip_version: rule.ipVersion ? Number(rule.ipVersion) : undefined,
    network: splitList(rule.network),
    auth_user: splitList(rule.authUser),
    protocol: splitList(rule.protocol),
    client: splitList(rule.client),
    domain: splitList(rule.domain),
    domain_suffix: splitList(rule.domainSuffix),
    domain_keyword: splitList(rule.domainKeyword),
    domain_regex: splitLines(rule.domainRegex),
    source_ip_cidr: splitList(rule.sourceIpCidr),
    source_ip_is_private: rule.sourceIpIsPrivate || undefined,
    ip_cidr: splitList(rule.ipCidr),
    ip_is_private: rule.ipIsPrivate || undefined,
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
    wifi_ssid: splitLines(rule.wifiSsid),
    wifi_bssid: splitList(rule.wifiBssid),
    default_interface_address: splitList(rule.defaultInterfaceAddress),
    source_mac_address: splitList(rule.sourceMacAddress),
    source_hostname: splitList(rule.sourceHostname),
    preferred_by: splitList(rule.preferredBy),
    rule_set: splitList(rule.ruleSet),
    rule_set_ip_cidr_match_source: rule.ruleSetIpCidrMatchSource || undefined,
    invert: rule.invert || undefined
  };
}

function buildRouteOptions(rule) {
  return {
    override_address: String(rule.overrideAddress || "").trim(),
    override_port: optionalPort(rule.overridePort),
    network_strategy: rule.networkStrategy || undefined,
    udp_disable_domain_unmapping: rule.udpDisableDomainUnmapping || undefined,
    udp_connect: rule.udpConnect || undefined,
    udp_timeout: String(rule.udpTimeout || "").trim(),
    tls_fragment: rule.tlsFragment || undefined,
    tls_fragment_fallback_delay: String(rule.tlsFragmentFallbackDelay || "").trim(),
    tls_record_fragment: rule.tlsRecordFragment || undefined,
    tls_spoof: String(rule.tlsSpoof || "").trim(),
    tls_spoof_method: rule.tlsSpoofMethod || undefined
  };
}

function buildRouteAction(rule) {
  const action = rule.action || "route";
  const meta = ROUTE_ACTION_META[action];
  const options = meta?.options ? buildRouteOptions(rule) : {};
  switch (action) {
    case "reject":
      return { action, method: rule.rejectMethod || undefined, no_drop: rule.rejectNoDrop || undefined };
    case "hijack-dns":
      return { action };
    case "sniff":
      return { action, sniffer: splitList(rule.sniffer), timeout: String(rule.sniffTimeout || "").trim() };
    case "resolve":
      return {
        action,
        server: String(rule.resolveServer || "").trim(),
        strategy: rule.resolveStrategy || undefined,
        disable_cache: rule.resolveDisableCache || undefined,
        disable_optimistic_cache: rule.resolveDisableOptimisticCache || undefined,
        rewrite_ttl: rule.resolveRewriteTtl === "" ? undefined : Number(rule.resolveRewriteTtl),
        timeout: String(rule.resolveTimeout || "").trim(),
        client_subnet: String(rule.resolveClientSubnet || "").trim()
      };
    case "route-options":
      return { action, ...options };
    default:
      return { action, outbound: String(rule.outbound || "").trim(), ...options };
  }
}

export function buildRouteRule(source) {
  const rule = normalizeRouteRule(source);
  const extra = parseJsonObject(rule.advancedJson, "附加规则参数");
  const body = rule.ruleType === "logical"
    ? { type: "logical", mode: rule.mode || "and", rules: parseJsonArray(rule.rulesJson, "逻辑子规则"), invert: rule.invert || undefined }
    : buildRouteMatchFields(rule);
  return mergeDeep(extra, compact({ ...body, ...buildRouteAction(rule) }));
}

export function routeRuleOutbound(source) {
  const rule = normalizeRouteRule(source);
  return ROUTE_ACTION_META[rule.action]?.outbound ? String(rule.outbound || "").trim() : "";
}

const IPV4_PATTERN = /^(?:\d{1,3}\.){3}\d{1,3}$/;

function isIpAddress(value) {
  const text = String(value || "").trim();
  if (IPV4_PATTERN.test(text)) return text.split(".").every((part) => Number(part) <= 255);
  return /^[0-9a-f:]+$/i.test(text) && text.includes(":");
}

function isIpPrefix(value, { requirePrefix = false } = {}) {
  const parts = String(value || "").trim().split("/");
  if (parts.length > 2 || !isIpAddress(parts[0])) return false;
  if (parts.length === 1) return !requirePrefix;
  const max = parts[0].includes(":") ? 128 : 32;
  return /^\d+$/.test(parts[1]) && Number(parts[1]) <= max;
}

function validateDuration(value, label) {
  return value && !DURATION_PATTERN.test(String(value).trim()) ? `${label}不是有效的 Go Duration，例如 300ms、10s 或 5m` : "";
}

function validateList(value, allowed, label) {
  const invalid = splitList(value).find((item) => !allowed.includes(item));
  return invalid ? `${label}无效：${invalid}` : "";
}

function validatePortList(value, label) {
  const invalid = splitList(value).find((item) => !optionalPort(item));
  return invalid ? `${label}无效：${invalid}` : "";
}

function validatePortRangeList(value, label) {
  const invalid = splitList(value).find((item) => !/^(\d+)?:(\d+)?$/.test(item) || item === ":");
  return invalid ? `${label}必须是 1000:2000、:3000 或 4000: 形式：${invalid}` : "";
}

function validateAdvanced(value, allowed, forbidden, label) {
  let extra;
  try {
    extra = parseJsonObject(value, label);
  } catch (error) {
    return error.message;
  }
  const banned = hasForbiddenKeys(extra, forbidden);
  if (banned) return `${label}包含已弃用或已移除的字段：${banned}`;
  const unknown = Object.keys(extra).find((key) => !allowed.has(key));
  return unknown ? `${label}不是 1.14 字段：${unknown}` : "";
}

export function validateRouteRule(source, { outboundTags = [], ruleSetTags = [], dnsServerTags = [], inboundTags = [] } = {}) {
  const rule = normalizeRouteRule(source);
  const action = rule.action || "route";
  const meta = ROUTE_ACTION_META[action];
  if (!meta) return `不支持的路由动作：${action}`;

  const advancedError = validateAdvanced(rule.advancedJson, RULE_EXTRA_KEYS, FORBIDDEN_RULE_KEYS, "附加规则参数");
  if (advancedError) return advancedError;

  if (rule.ruleType === "logical") {
    let subRules;
    try {
      subRules = parseJsonArray(rule.rulesJson, "逻辑子规则");
    } catch (error) {
      return error.message;
    }
    if (!subRules.length) return "逻辑规则至少需要一条子规则";
    if (!["and", "or"].includes(rule.mode)) return "逻辑规则模式只能是 and 或 or";
    if (subRules.some((item) => !item || typeof item !== "object" || Array.isArray(item))) return "逻辑子规则必须是对象";
    if (subRules.some((item) => item.action)) return "逻辑子规则不能带动作，动作只属于外层规则";
    const banned = hasForbiddenKeys(subRules, FORBIDDEN_RULE_KEYS);
    if (banned) return `逻辑子规则包含已弃用或已移除的字段：${banned}`;
  } else {
    if (rule.ipVersion && !["4", "6"].includes(String(rule.ipVersion))) return "IP 版本只能是 4 或 6";
    const listError = validateList(rule.network, NETWORKS, "网络")
      || validateList(rule.protocol, SNIFFERS, "嗅探协议")
      || validateList(rule.networkType, INTERFACE_TYPES, "网络类型")
      || validateList(rule.preferredBy, ROUTE_PREFERRED_BY, "出站偏好路由");
    if (listError) return listError;
    const portError = validatePortList(rule.port, "端口") || validatePortList(rule.sourcePort, "来源端口");
    if (portError) return portError;
    const rangeError = validatePortRangeList(rule.portRange, "端口范围") || validatePortRangeList(rule.sourcePortRange, "来源端口范围");
    if (rangeError) return rangeError;
    for (const [value, label] of [[rule.ipCidr, "目标 IP CIDR"], [rule.sourceIpCidr, "来源 IP CIDR"], [rule.defaultInterfaceAddress, "默认接口地址"]]) {
      const invalid = splitList(value).find((item) => !isIpPrefix(item));
      if (invalid) return `${label}无效：${invalid}`;
    }
    const invalidMac = splitList(rule.sourceMacAddress).find((item) => !/^([0-9a-f]{2}:){5}[0-9a-f]{2}$/i.test(item));
    if (invalidMac) return `来源 MAC 地址无效：${invalidMac}`;
    if (ruleSetTags.length || splitList(rule.ruleSet).length) {
      const missing = splitList(rule.ruleSet).find((item) => !ruleSetTags.includes(item));
      if (missing) return `规则集不存在：${missing}`;
    }
    if (inboundTags.length) {
      const missing = splitList(rule.inbound).find((item) => !inboundTags.includes(item));
      if (missing) return `入站不存在：${missing}`;
    }
  }

  if (meta.outbound) {
    const outbound = String(rule.outbound || "").trim();
    if (action === "route" && !outbound) return "请选择目标出站";
    if (outbound && outboundTags.length && !outboundTags.includes(outbound)) return `出站不存在：${outbound}`;
  }
  if (meta.options) {
    if (rule.overrideAddress && !isIpAddress(rule.overrideAddress)) return "覆盖目标地址必须是 IP 地址";
    if (rule.overridePort !== "" && !optionalPort(rule.overridePort)) return "覆盖目标端口必须在 1–65535 之间";
    if (rule.networkStrategy && !["default", "hybrid", "fallback"].includes(rule.networkStrategy)) return "网络策略无效";
    if (rule.tlsSpoofMethod && !TLS_SPOOF_METHODS.includes(rule.tlsSpoofMethod)) return "TLS 伪造方式无效";
    if (rule.tlsSpoofMethod && !rule.tlsSpoof) return "设置 TLS 伪造方式前需要先填写伪造 SNI";
    const durationError = validateDuration(rule.udpTimeout, "UDP 超时") || validateDuration(rule.tlsFragmentFallbackDelay, "TLS 分片回退延迟");
    if (durationError) return durationError;
  }
  if (action === "reject") {
    if (rule.rejectMethod && !REJECT_METHODS.includes(rule.rejectMethod)) return "拒绝方式只能是 default、drop 或 reply";
    if (rule.rejectMethod === "drop" && rule.rejectNoDrop) return "method 为 drop 时不能启用 no_drop";
  }
  if (action === "sniff") {
    const snifferError = validateList(rule.sniffer, SNIFFERS, "嗅探器");
    if (snifferError) return snifferError;
    const durationError = validateDuration(rule.sniffTimeout, "嗅探超时");
    if (durationError) return durationError;
  }
  if (action === "resolve") {
    if (rule.resolveStrategy && !STRATEGIES.includes(rule.resolveStrategy)) return "解析策略无效";
    if (rule.resolveServer && dnsServerTags.length && !dnsServerTags.includes(rule.resolveServer)) return `DNS Server 不存在：${rule.resolveServer}`;
    if (rule.resolveRewriteTtl !== "" && (!Number.isInteger(Number(rule.resolveRewriteTtl)) || Number(rule.resolveRewriteTtl) < 0)) return "TTL 重写必须是非负整数";
    if (rule.resolveClientSubnet && !isIpPrefix(rule.resolveClientSubnet)) return `客户端子网无效：${rule.resolveClientSubnet}`;
    const durationError = validateDuration(rule.resolveTimeout, "解析超时");
    if (durationError) return durationError;
  }
  return "";
}

export const RULE_SET_TYPE_META = Object.freeze({
  inline: { label: "Inline", note: "直接写在配置里的 Headless 规则", prefix: "inline-set" },
  local: { label: "Local File", note: "本机 source JSON 或 binary SRS 文件", prefix: "local-set" },
  remote: { label: "Remote File", note: "远程下载并按周期更新", prefix: "remote-set" }
});

export const HEADLESS_RULE_DEFAULTS = Object.freeze({
  ruleType: "default",
  mode: "and",
  rulesJson: "",
  queryType: "",
  network: "",
  domain: "",
  domainSuffix: "",
  domainKeyword: "",
  domainRegex: "",
  sourceIpCidr: "",
  ipCidr: "",
  sourcePort: "",
  sourcePortRange: "",
  port: "",
  portRange: "",
  processName: "",
  processPath: "",
  processPathRegex: "",
  packageName: "",
  packageNameRegex: "",
  networkType: "",
  networkIsExpensive: false,
  networkIsConstrained: false,
  wifiSsid: "",
  wifiBssid: "",
  defaultInterfaceAddress: "",
  invert: false
});

export const RULE_SET_DEFAULTS = Object.freeze({
  enabled: true,
  type: "remote",
  tag: "",
  format: "",
  path: "",
  url: "",
  initialPath: "",
  updateInterval: "",
  httpClientMode: "",
  httpClientTag: "",
  httpClientJson: "",
  headlessRules: [],
  advancedJson: ""
});

const HEADLESS_KEYS = new Set([
  "type", "mode", "rules", "query_type", "network", "domain", "domain_suffix", "domain_keyword", "domain_regex",
  "source_ip_cidr", "ip_cidr", "source_port", "source_port_range", "port", "port_range", "process_name", "process_path",
  "process_path_regex", "package_name", "package_name_regex", "network_type", "network_is_expensive",
  "network_is_constrained", "network_interface_address", "default_interface_address", "wifi_ssid", "wifi_bssid", "invert"
]);

const RULE_SET_EXTRA_KEYS = new Set(["type", "tag", "format", "path", "url", "initial_path", "http_client", "update_interval", "rules"]);
const FORBIDDEN_RULE_SET_KEYS = new Set(["download_detour", "geoip", "geosite"]);

export function normalizeHeadlessRule(rule = {}) {
  return { ...HEADLESS_RULE_DEFAULTS, ...rule };
}

export function normalizeRuleSet(set = {}) {
  const type = RULE_SET_TYPE_META[set.type] ? set.type : "remote";
  return {
    ...RULE_SET_DEFAULTS,
    ...set,
    type,
    headlessRules: (set.headlessRules || []).map(normalizeHeadlessRule)
  };
}

export function buildHeadlessRule(source) {
  const rule = normalizeHeadlessRule(source);
  if (rule.ruleType === "logical") {
    return compact({
      type: "logical",
      mode: rule.mode || "and",
      rules: parseJsonArray(rule.rulesJson, "Headless 逻辑子规则"),
      invert: rule.invert || undefined
    });
  }
  return compact({
    query_type: splitList(rule.queryType).map((item) => (/^\d+$/.test(item) ? Number(item) : item)),
    network: splitList(rule.network),
    domain: splitList(rule.domain),
    domain_suffix: splitList(rule.domainSuffix),
    domain_keyword: splitList(rule.domainKeyword),
    domain_regex: splitLines(rule.domainRegex),
    source_ip_cidr: splitList(rule.sourceIpCidr),
    ip_cidr: splitList(rule.ipCidr),
    source_port: splitList(rule.sourcePort).map(Number),
    source_port_range: splitList(rule.sourcePortRange),
    port: splitList(rule.port).map(Number),
    port_range: splitList(rule.portRange),
    process_name: splitLines(rule.processName),
    process_path: splitLines(rule.processPath),
    process_path_regex: splitLines(rule.processPathRegex),
    package_name: splitList(rule.packageName),
    package_name_regex: splitLines(rule.packageNameRegex),
    network_type: splitList(rule.networkType),
    network_is_expensive: rule.networkIsExpensive || undefined,
    network_is_constrained: rule.networkIsConstrained || undefined,
    wifi_ssid: splitLines(rule.wifiSsid),
    wifi_bssid: splitList(rule.wifiBssid),
    default_interface_address: splitList(rule.defaultInterfaceAddress),
    invert: rule.invert || undefined
  });
}

function buildHttpClient(set) {
  if (set.httpClientMode === "tag") return String(set.httpClientTag || "").trim() || undefined;
  if (set.httpClientMode === "inline") {
    const client = parseJsonObject(set.httpClientJson, "HTTP Client");
    return Object.keys(client).length ? client : undefined;
  }
  return undefined;
}

function ruleSetTags(set) {
  return splitList(set.tag);
}

export function buildRuleSet(source) {
  const set = normalizeRuleSet(source);
  const extra = parseJsonObject(set.advancedJson, "附加规则集参数");
  const tags = ruleSetTags(set);
  const tag = tags.length > 1 ? tags : tags[0];
  if (set.type === "inline") {
    return mergeDeep(extra, compact({
      type: "inline",
      tag,
      rules: set.headlessRules.map(buildHeadlessRule)
    }));
  }
  if (set.type === "local") {
    return mergeDeep(extra, compact({
      type: "local",
      tag,
      format: set.format || undefined,
      path: String(set.path || "").trim()
    }));
  }
  return mergeDeep(extra, compact({
    type: "remote",
    tag,
    format: set.format || undefined,
    url: String(set.url || "").trim(),
    initial_path: String(set.initialPath || "").trim(),
    http_client: buildHttpClient(set),
    update_interval: String(set.updateInterval || "").trim()
  }));
}

function formatFromExtension(value) {
  const text = String(value || "").trim().toLowerCase().split("?")[0];
  if (text.endsWith(".json")) return "source";
  if (text.endsWith(".srs")) return "binary";
  return "";
}

export function validateHeadlessRule(source, index = 0) {
  const rule = normalizeHeadlessRule(source);
  const label = `规则项 ${index + 1}`;
  if (rule.ruleType === "logical") {
    let subRules;
    try {
      subRules = parseJsonArray(rule.rulesJson, `${label} 子规则`);
    } catch (error) {
      return error.message;
    }
    if (!subRules.length) return `${label} 至少需要一条子规则`;
    if (!["and", "or"].includes(rule.mode)) return `${label} 模式只能是 and 或 or`;
    const unknown = subRules.flatMap((item) => Object.keys(item || {})).find((key) => !HEADLESS_KEYS.has(key));
    if (unknown) return `${label} 子规则包含 Headless 规则不支持的字段：${unknown}`;
    return "";
  }
  const listError = validateList(rule.network, NETWORKS, `${label} 网络`) || validateList(rule.networkType, INTERFACE_TYPES, `${label} 网络类型`);
  if (listError) return listError;
  const portError = validatePortList(rule.port, `${label} 端口`) || validatePortList(rule.sourcePort, `${label} 来源端口`);
  if (portError) return portError;
  const rangeError = validatePortRangeList(rule.portRange, `${label} 端口范围`) || validatePortRangeList(rule.sourcePortRange, `${label} 来源端口范围`);
  if (rangeError) return rangeError;
  for (const [value, name] of [[rule.ipCidr, "IP CIDR"], [rule.sourceIpCidr, "来源 IP CIDR"], [rule.defaultInterfaceAddress, "默认接口地址"]]) {
    const invalid = splitList(value).find((item) => !isIpPrefix(item));
    if (invalid) return `${label} ${name}无效：${invalid}`;
  }
  const invalidQueryType = splitList(rule.queryType).find((item) => !/^[A-Za-z][A-Za-z0-9-]*$/.test(item) && !/^\d+$/.test(item));
  if (invalidQueryType) return `${label} 查询类型无效：${invalidQueryType}`;
  if (!Object.keys(buildHeadlessRule(rule) || {}).length) return `${label} 至少需要一个匹配条件`;
  return "";
}

export function validateRuleSet(source, { ruleSets = [], outboundTags = [] } = {}) {
  const set = normalizeRuleSet(source);
  const tags = ruleSetTags(set);
  if (!tags.length) return "请填写规则集标签";
  const invalidTag = tags.find((tag) => !/^[\w.-]+$/.test(tag));
  if (invalidTag) return `规则集标签只能包含字母、数字、点、下划线和短横线：${invalidTag}`;
  const others = ruleSets.filter((item) => item.id !== set.id).flatMap((item) => splitList(item.tag));
  const duplicate = tags.find((tag) => others.includes(tag)) || tags.find((tag, index) => tags.indexOf(tag) !== index);
  if (duplicate) return `规则集标签必须唯一：${duplicate}`;

  const advancedError = validateAdvanced(set.advancedJson, RULE_SET_EXTRA_KEYS, FORBIDDEN_RULE_SET_KEYS, "附加规则集参数");
  if (advancedError) return advancedError;

  if (set.type === "inline") {
    if (tags.length > 1) return "Inline 规则集不支持一次定义多个标签";
    if (!set.headlessRules.length) return "Inline 规则集至少需要一条规则项";
    for (const [index, rule] of set.headlessRules.entries()) {
      const error = validateHeadlessRule(rule, index);
      if (error) return error;
    }
    return "";
  }

  if (set.format && !["source", "binary"].includes(set.format)) return "规则集格式只能是 source 或 binary";
  const source_ = set.type === "local" ? set.path : set.url;
  if (set.type === "local" && !String(set.path || "").trim()) return "请填写本地规则集路径";
  if (set.type === "remote") {
    const url = String(set.url || "").trim();
    if (!url) return "请填写远程规则集地址";
    try {
      const parsed = new URL(url);
      if (!["http:", "https:"].includes(parsed.protocol)) return "远程规则集地址只支持 HTTP 或 HTTPS";
    } catch {
      return "远程规则集地址不是有效 URL";
    }
    const intervalError = validateDuration(set.updateInterval, "更新周期");
    if (intervalError) return intervalError;
    if (set.httpClientMode === "tag" && !String(set.httpClientTag || "").trim()) return "请填写 HTTP Client 标签";
    if (set.httpClientMode === "inline") {
      const clientError = validateAdvanced(
        set.httpClientJson,
        new Set(["engine", "version", "disable_version_fallback", "headers", "tls", "detour", "bind_interface", "inet4_bind_address", "inet6_bind_address", "connect_timeout", "tcp_fast_open", "tcp_multi_path", "domain_resolver", "network_strategy", "network_type", "fallback_network_type", "fallback_delay", "netns", "routing_mark", "reuse_addr", "tcp_keep_alive", "tcp_keep_alive_interval", "disable_tcp_keep_alive", "udp_fragment", "bind_address_no_port", "http2", "quic"]),
        new Set(["domain_strategy", "download_detour"]),
        "HTTP Client"
      );
      if (clientError) return clientError;
      const client = parseJsonObject(set.httpClientJson, "HTTP Client");
      if (client.detour && outboundTags.length && !outboundTags.includes(client.detour)) return `HTTP Client detour 出站不存在：${client.detour}`;
    }
  }
  if (!set.format && !formatFromExtension(source_)) {
    return "路径或地址不是 .json / .srs 结尾时，必须显式选择规则集格式";
  }
  if (tags.length > 1 && !String(source_).includes("{tag}")) return "定义多个标签时，路径或地址必须包含 {tag} 占位符";
  if (set.type === "remote" && set.initialPath && tags.length > 1 && !set.initialPath.includes("{tag}")) {
    return "定义多个标签时，初始文件路径必须包含 {tag} 占位符";
  }
  return "";
}

export const ROUTE_STATE_DEFAULTS = Object.freeze({
  final: "",
  autoDetectInterface: "auto",
  overrideAndroidVpn: false,
  defaultInterface: "",
  defaultMark: "",
  findProcess: false,
  findNeighbor: false,
  dhcpLeaseFiles: "",
  defaultNetworkStrategy: "",
  defaultNetworkType: "",
  defaultFallbackNetworkType: "",
  defaultFallbackDelay: "",
  advancedJson: "",
  rules: [],
  ruleSets: []
});

const ROUTE_EXTRA_KEYS = new Set([
  "final", "auto_detect_interface", "override_android_vpn", "default_interface", "default_mark", "find_process",
  "find_neighbor", "dhcp_lease_files", "default_http_client", "default_domain_resolver", "default_network_strategy",
  "default_network_type", "default_fallback_network_type", "default_fallback_delay"
]);

const FORBIDDEN_ROUTE_KEYS = new Set(["geoip", "geosite", "rules", "rule_set"]);

export function normalizeRouteState(route = {}) {
  return {
    ...ROUTE_STATE_DEFAULTS,
    ...route,
    rules: (route.rules || []).map(normalizeRouteRule),
    ruleSets: (route.ruleSets || []).map(normalizeRuleSet)
  };
}

export function activeRouteRules(route) {
  return normalizeRouteState(route).rules.filter((rule) => rule.enabled !== false);
}

export function activeRuleSets(route) {
  return normalizeRouteState(route).ruleSets.filter((set) => set.enabled !== false);
}

export function skippedRouteRules(route, outboundTags = []) {
  if (!outboundTags.length) return [];
  return activeRouteRules(route).filter((rule) => {
    const outbound = routeRuleOutbound(rule);
    return outbound && !outboundTags.includes(outbound);
  });
}

export function buildRouteSection(source, context = {}) {
  const route = normalizeRouteState(source);
  const { outboundTags = [], tunEnabled = false, defaultDomainResolver = "", fallbackFinal = "" } = context;
  const skipped = new Set(skippedRouteRules(route, outboundTags).map((rule) => rule.id));
  const rules = activeRouteRules(route).filter((rule) => !skipped.has(rule.id)).map(buildRouteRule);
  const ruleSets = activeRuleSets(route).map(buildRuleSet);
  const final = String(route.final || "").trim();
  const autoDetect = route.autoDetectInterface === "auto" ? tunEnabled : route.autoDetectInterface === "on";
  const extra = parseJsonObject(route.advancedJson, "附加路由参数");
  return mergeDeep(extra, compact({
    rules,
    rule_set: ruleSets,
    final: outboundTags.includes(final) ? final : (outboundTags.includes(fallbackFinal) ? fallbackFinal : undefined),
    find_process: route.findProcess || undefined,
    find_neighbor: route.findNeighbor || undefined,
    dhcp_lease_files: splitLines(route.dhcpLeaseFiles),
    auto_detect_interface: autoDetect || undefined,
    override_android_vpn: route.overrideAndroidVpn || undefined,
    default_interface: String(route.defaultInterface || "").trim(),
    default_mark: route.defaultMark === "" ? undefined : Number(route.defaultMark),
    default_domain_resolver: defaultDomainResolver || undefined,
    default_network_strategy: route.defaultNetworkStrategy || undefined,
    default_network_type: splitList(route.defaultNetworkType),
    default_fallback_network_type: splitList(route.defaultFallbackNetworkType),
    default_fallback_delay: String(route.defaultFallbackDelay || "").trim()
  }));
}

export function validateRouteState(source, context = {}) {
  const route = normalizeRouteState(source);
  const sets = activeRuleSets(route);
  const tags = sets.flatMap((set) => splitList(set.tag));
  for (const set of route.ruleSets) {
    const error = validateRuleSet(set, { ...context, ruleSets: route.ruleSets });
    if (error) return `规则集「${splitList(set.tag)[0] || "未命名"}」：${error}`;
  }
  const ruleContext = { ...context, ruleSetTags: tags };
  for (const [index, rule] of activeRouteRules(route).entries()) {
    const error = validateRouteRule(rule, ruleContext);
    if (error) return `第 ${index + 1} 条路由规则：${error}`;
  }
  const advancedError = validateAdvanced(route.advancedJson, ROUTE_EXTRA_KEYS, FORBIDDEN_ROUTE_KEYS, "附加路由参数");
  if (advancedError) return advancedError;
  if (route.defaultMark !== "" && (!Number.isInteger(Number(route.defaultMark)) || Number(route.defaultMark) < 0)) return "默认路由标记必须是非负整数";
  const durationError = validateDuration(route.defaultFallbackDelay, "默认回退延迟");
  if (durationError) return durationError;
  const typeError = validateList(route.defaultNetworkType, INTERFACE_TYPES, "默认网络类型")
    || validateList(route.defaultFallbackNetworkType, INTERFACE_TYPES, "默认回退网络类型");
  if (typeError) return typeError;
  if (route.defaultNetworkStrategy !== "fallback" && splitList(route.defaultFallbackNetworkType).length) {
    return "只有 fallback 网络策略可以设置默认回退网络类型";
  }
  if (route.defaultInterface && route.autoDetectInterface === "on") return "自动检测接口与固定默认接口只能选择一个";
  const final = String(route.final || "").trim();
  if (final && context.outboundTags?.length && !context.outboundTags.includes(final)) return `默认出站不存在：${final}`;
  return "";
}

export const routeModule = {
  key: "route",
  extendConfig(config, state, context = {}) {
    const section = buildRouteSection(state.route, context);
    config.route = { ...(config.route || {}), ...section, rules: section.rules || [] };
    return config;
  }
};
