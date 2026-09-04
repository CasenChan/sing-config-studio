export const DIAL_DEFAULTS = Object.freeze({
  detour: "",
  bindInterface: "",
  inet4BindAddress: "",
  inet6BindAddress: "",
  bindAddressNoPort: false,
  routingMark: "",
  reuseAddr: false,
  netns: "",
  connectTimeout: "",
  tcpFastOpen: false,
  tcpMultiPath: false,
  disableTcpKeepAlive: false,
  tcpKeepAlive: "",
  tcpKeepAliveInterval: "",
  udpFragment: "",
  domainResolver: "",
  networkStrategy: "",
  networkType: "",
  fallbackNetworkType: "",
  fallbackDelay: ""
});

export const UDP_NAT_DEFAULTS = Object.freeze({
  udpTimeout: "",
  udpMapping: "",
  udpFiltering: "",
  udpNatMax: ""
});

export const LISTEN_DEFAULTS = Object.freeze({
  listen: "",
  listenPort: "",
  bindInterface: "",
  routingMark: "",
  reuseAddr: false,
  netns: "",
  tcpFastOpen: false,
  tcpMultiPath: false,
  disableTcpKeepAlive: false,
  tcpKeepAlive: "",
  tcpKeepAliveInterval: "",
  udpFragment: "",
  detour: ""
});

export const DURATION_PATTERN = /^-?(?:\d+(?:\.\d+)?(?:ns|us|µs|ms|s|m|h|d))+$/;

export function splitList(value) {
  if (Array.isArray(value)) return value.map(String).map((item) => item.trim()).filter(Boolean);
  return String(value || "").split(/[\n,]+/).map((item) => item.trim()).filter(Boolean);
}

export function splitLines(value) {
  if (Array.isArray(value)) return value.map(String).map((item) => item.trim()).filter(Boolean);
  return String(value || "").split(/\n+/).map((item) => item.trim()).filter(Boolean);
}

export function compact(value) {
  if (Array.isArray(value)) {
    const result = value.map(compact).filter((item) => item !== undefined);
    return result.length ? result : undefined;
  }
  if (value && typeof value === "object") {
    const result = Object.fromEntries(Object.entries(value).map(([key, child]) => [key, compact(child)]).filter(([, child]) => child !== undefined));
    return Object.keys(result).length ? result : undefined;
  }
  return value === "" || value === undefined || value === null ? undefined : value;
}

export function mergeDeep(base, overlay) {
  const result = { ...(base || {}) };
  for (const [key, value] of Object.entries(overlay || {})) {
    result[key] = value && typeof value === "object" && !Array.isArray(value)
      ? mergeDeep(result[key] && typeof result[key] === "object" ? result[key] : {}, value)
      : value;
  }
  return result;
}

export function optionalPort(value) {
  const number = Number(value);
  return Number.isInteger(number) && number > 0 ? number : undefined;
}

export function optionalPositiveInteger(value) {
  const number = Number(value);
  return Number.isInteger(number) && number > 0 ? number : undefined;
}

export function routingMark(value) {
  const text = String(value || "").trim();
  if (!text) return undefined;
  return /^0x[0-9a-f]+$/i.test(text) ? text : Number(text);
}

export function parseJsonObject(value, label = "高级参数") {
  const text = String(value || "").trim();
  if (!text) return {};
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch (error) {
    throw new Error(`${label}不是有效 JSON：${error.message}`);
  }
  if (!parsed || Array.isArray(parsed) || typeof parsed !== "object") throw new Error(`${label}必须是 JSON 对象`);
  return parsed;
}

export function parseJsonArray(value, label) {
  const text = String(value || "").trim();
  if (!text) return [];
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch (error) {
    throw new Error(`${label}不是有效 JSON：${error.message}`);
  }
  if (!Array.isArray(parsed)) throw new Error(`${label}必须是 JSON 数组`);
  return parsed;
}

export function buildDialFields(endpoint) {
  return {
    ...(endpoint.detour ? { detour: endpoint.detour.trim() } : {}),
    ...(endpoint.bindInterface ? { bind_interface: endpoint.bindInterface.trim() } : {}),
    ...(endpoint.inet4BindAddress ? { inet4_bind_address: endpoint.inet4BindAddress.trim() } : {}),
    ...(endpoint.inet6BindAddress ? { inet6_bind_address: endpoint.inet6BindAddress.trim() } : {}),
    ...(endpoint.bindAddressNoPort ? { bind_address_no_port: true } : {}),
    ...(String(endpoint.routingMark || "").trim() ? { routing_mark: routingMark(endpoint.routingMark) } : {}),
    ...(endpoint.reuseAddr ? { reuse_addr: true } : {}),
    ...(endpoint.netns ? { netns: endpoint.netns.trim() } : {}),
    ...(endpoint.connectTimeout ? { connect_timeout: endpoint.connectTimeout.trim() } : {}),
    ...(endpoint.tcpFastOpen ? { tcp_fast_open: true } : {}),
    ...(endpoint.tcpMultiPath ? { tcp_multi_path: true } : {}),
    ...(endpoint.disableTcpKeepAlive ? { disable_tcp_keep_alive: true } : {}),
    ...(endpoint.tcpKeepAlive ? { tcp_keep_alive: endpoint.tcpKeepAlive.trim() } : {}),
    ...(endpoint.tcpKeepAliveInterval ? { tcp_keep_alive_interval: endpoint.tcpKeepAliveInterval.trim() } : {}),
    ...(endpoint.udpFragment === "true" ? { udp_fragment: true } : {}),
    ...(endpoint.udpFragment === "false" ? { udp_fragment: false } : {}),
    ...(endpoint.domainResolver ? { domain_resolver: endpoint.domainResolver.trim() } : {}),
    ...(endpoint.networkStrategy ? { network_strategy: endpoint.networkStrategy } : {}),
    ...(splitList(endpoint.networkType).length ? { network_type: splitList(endpoint.networkType) } : {}),
    ...(splitList(endpoint.fallbackNetworkType).length ? { fallback_network_type: splitList(endpoint.fallbackNetworkType) } : {}),
    ...(endpoint.fallbackDelay ? { fallback_delay: endpoint.fallbackDelay.trim() } : {})
  };
}

export function buildUdpNatFields(endpoint) {
  return {
    ...(endpoint.udpTimeout ? { udp_timeout: endpoint.udpTimeout.trim() } : {}),
    ...(endpoint.udpMapping ? { udp_mapping: endpoint.udpMapping } : {}),
    ...(endpoint.udpFiltering ? { udp_filtering: endpoint.udpFiltering } : {}),
    ...(optionalPositiveInteger(endpoint.udpNatMax) ? { udp_nat_max: optionalPositiveInteger(endpoint.udpNatMax) } : {})
  };
}

export function buildListenFields(endpoint) {
  return {
    ...(endpoint.listen ? { listen: endpoint.listen.trim() } : {}),
    ...(optionalPort(endpoint.listenPort) ? { listen_port: optionalPort(endpoint.listenPort) } : {}),
    ...(endpoint.bindInterface ? { bind_interface: endpoint.bindInterface.trim() } : {}),
    ...(String(endpoint.routingMark || "").trim() ? { routing_mark: routingMark(endpoint.routingMark) } : {}),
    ...(endpoint.reuseAddr ? { reuse_addr: true } : {}),
    ...(endpoint.netns ? { netns: endpoint.netns.trim() } : {}),
    ...(endpoint.tcpFastOpen ? { tcp_fast_open: true } : {}),
    ...(endpoint.tcpMultiPath ? { tcp_multi_path: true } : {}),
    ...(endpoint.disableTcpKeepAlive ? { disable_tcp_keep_alive: true } : {}),
    ...(endpoint.tcpKeepAlive ? { tcp_keep_alive: endpoint.tcpKeepAlive.trim() } : {}),
    ...(endpoint.tcpKeepAliveInterval ? { tcp_keep_alive_interval: endpoint.tcpKeepAliveInterval.trim() } : {}),
    ...(endpoint.udpFragment === "true" ? { udp_fragment: true } : {}),
    ...(endpoint.detour ? { detour: endpoint.detour.trim() } : {})
  };
}

function validateRoutingMark(value) {
  if (!value) return "";
  return /^0x[0-9a-f]+$/i.test(String(value).trim()) || /^\d+$/.test(String(value).trim())
    ? ""
    : "路由标记应为十进制整数或 0x 开头的十六进制";
}

function validateDurations(entries) {
  for (const [value, name] of entries) {
    if (value && !DURATION_PATTERN.test(String(value).trim())) return `${name}不是有效的 Go Duration，例如 300ms、10s 或 5m`;
  }
  return "";
}

export function validateDialFields(endpoint, outboundTags = []) {
  const markError = validateRoutingMark(endpoint.routingMark);
  if (markError) return markError;
  const allowedNetworks = new Set(["wifi", "cellular", "ethernet", "other"]);
  const invalidNetwork = [...splitList(endpoint.networkType), ...splitList(endpoint.fallbackNetworkType)].find((item) => !allowedNetworks.has(item));
  if (invalidNetwork) return `不支持的网络类型：${invalidNetwork}`;
  const durationError = validateDurations([
    [endpoint.connectTimeout, "连接超时"],
    [endpoint.tcpKeepAlive, "TCP Keep Alive"],
    [endpoint.tcpKeepAliveInterval, "Keep Alive 间隔"],
    [endpoint.fallbackDelay, "回退延迟"]
  ]);
  if (durationError) return durationError;
  if (endpoint.networkStrategy !== "fallback" && splitList(endpoint.fallbackNetworkType).length) return "只有 fallback 网络策略可以设置回退网络类型";
  if (endpoint.detour && !outboundTags.includes(endpoint.detour.trim())) return `上游出站不存在：${endpoint.detour.trim()}`;
  if (endpoint.detour && (endpoint.bindInterface || endpoint.inet4BindAddress || endpoint.inet6BindAddress || endpoint.networkStrategy)) return "设置 detour 后，其它拨号路由字段不会生效，请二选一";
  return "";
}

export function validateUdpNatFields(endpoint) {
  const durationError = validateDurations([[endpoint.udpTimeout, "UDP NAT 超时"]]);
  if (durationError) return durationError;
  const modes = new Set(["", "endpoint_independent", "address_dependent", "address_and_port_dependent"]);
  if (!modes.has(endpoint.udpMapping || "")) return "UDP 映射模式无效";
  if (!modes.has(endpoint.udpFiltering || "")) return "UDP 过滤模式无效";
  if (endpoint.udpNatMax !== "" && (!Number.isInteger(Number(endpoint.udpNatMax)) || Number(endpoint.udpNatMax) < 0)) return "UDP NAT 会话上限必须是非负整数";
  return "";
}

export function validateListenFields(endpoint, detourTags = [], { detourLabel = "出站" } = {}) {
  const markError = validateRoutingMark(endpoint.routingMark);
  if (markError) return markError;
  if (endpoint.listenPort !== "" && (!Number.isInteger(Number(endpoint.listenPort)) || Number(endpoint.listenPort) < 1 || Number(endpoint.listenPort) > 65535)) return "监听端口必须在 1–65535 之间";
  const durationError = validateDurations([
    [endpoint.tcpKeepAlive, "TCP Keep Alive"],
    [endpoint.tcpKeepAliveInterval, "Keep Alive 间隔"]
  ]);
  if (durationError) return durationError;
  if (endpoint.detour && !detourTags.includes(endpoint.detour.trim())) return `监听 detour ${detourLabel}不存在：${endpoint.detour.trim()}`;
  return "";
}

export function hasForbiddenKeys(value, forbidden = new Set(["domain_strategy"])) {
  if (!value || typeof value !== "object") return "";
  for (const [key, child] of Object.entries(value)) {
    if (forbidden.has(key)) return key;
    const nested = hasForbiddenKeys(child, forbidden);
    if (nested) return nested;
  }
  return "";
}
