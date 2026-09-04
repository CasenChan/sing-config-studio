import {
  DIAL_DEFAULTS,
  DURATION_PATTERN,
  buildDialFields,
  compact,
  hasForbiddenKeys,
  mergeDeep,
  optionalPort,
  optionalPositiveInteger,
  parseJsonObject,
  splitLines,
  splitList,
  validateDialFields
} from "./shared.js";

export const OUTBOUND_TYPE_META = Object.freeze({
  direct: { label: "Direct", note: "直连出站", prefix: "direct", group: "basic", server: false },
  bridge: { label: "Bridge", note: "二层桥接 · 1.14", prefix: "bridge", group: "basic", server: false, badge: "1.14" },
  socks: { label: "SOCKS", note: "SOCKS4/4a/5 客户端", prefix: "socks", group: "basic", uot: true },
  http: { label: "HTTP", note: "HTTP 代理客户端", prefix: "http", group: "basic", tls: true },
  shadowsocks: { label: "Shadowsocks", note: "SS 客户端", prefix: "ss", group: "proxy", uot: true, multiplex: true },
  vmess: { label: "VMess", note: "VMess 客户端", prefix: "vmess", group: "proxy", tls: true, transport: true, multiplex: true },
  vless: { label: "VLESS", note: "VLESS 客户端，支持 Vision 与 REALITY", prefix: "vless", group: "proxy", tls: true, transport: true, multiplex: true, reality: true },
  trojan: { label: "Trojan", note: "Trojan 客户端", prefix: "trojan", group: "proxy", tls: true, transport: true, multiplex: true },
  naive: { label: "Naive", note: "NaïveProxy 客户端", prefix: "naive", group: "proxy", tls: true },
  hysteria: { label: "Hysteria", note: "Hysteria v1 客户端", prefix: "hysteria", group: "proxy", tls: true, tlsRequired: true },
  hysteria2: { label: "Hysteria 2", note: "Hysteria v2 客户端", prefix: "hy2", group: "proxy", tls: true, tlsRequired: true },
  shadowtls: { label: "ShadowTLS", note: "配合其它出站使用的握手伪装", prefix: "shadowtls", group: "proxy", tls: true },
  tuic: { label: "TUIC", note: "TUIC v5 客户端", prefix: "tuic", group: "proxy", tls: true, tlsRequired: true },
  anytls: { label: "AnyTLS", note: "AnyTLS 客户端", prefix: "anytls", group: "proxy", tls: true, tlsRequired: true },
  snell: { label: "Snell", note: "Snell v4 / v6 客户端", prefix: "snell", group: "proxy" },
  tor: { label: "Tor", note: "通过本机 Tor 出站", prefix: "tor", group: "special", server: false },
  ssh: { label: "SSH", note: "SSH 隧道出站", prefix: "ssh", group: "special" }
});

export const OUTBOUND_GROUP_LABELS = Object.freeze({
  basic: "基础出站",
  proxy: "代理协议",
  special: "特殊出站"
});

export const OUTBOUND_TYPES = Object.keys(OUTBOUND_TYPE_META);

const TLS_DEFAULTS = Object.freeze({
  tls: false,
  sni: "",
  insecure: false,
  disableSni: false,
  alpn: "",
  tlsMinVersion: "",
  tlsMaxVersion: "",
  tlsCertificate: "",
  tlsCertificatePath: "",
  fingerprint: "chrome",
  echEnabled: false,
  echConfig: "",
  echConfigPath: "",
  reality: false,
  publicKey: "",
  shortId: "",
  tlsFragment: false,
  tlsRecordFragment: false,
  tlsFragmentFallbackDelay: ""
});

const TRANSPORT_DEFAULTS = Object.freeze({
  transport: "tcp",
  path: "",
  host: "",
  transportMethod: "",
  earlyDataHeaderName: "",
  maxEarlyData: "",
  transportJson: ""
});

const MULTIPLEX_DEFAULTS = Object.freeze({
  multiplexEnabled: false,
  multiplexProtocol: "",
  maxConnections: "",
  minStreams: "",
  maxStreams: "",
  multiplexPadding: false,
  brutalEnabled: false,
  brutalUp: "",
  brutalDown: ""
});

const UOT_DEFAULTS = Object.freeze({ uotEnabled: false, uotVersion: "" });

const BASE_DEFAULTS = Object.freeze({
  tag: "",
  server: "",
  port: 443,
  network: "",
  advancedJson: "",
  ...DIAL_DEFAULTS
});

const TYPE_DEFAULTS = {
  direct: {},
  bridge: { interface: "", bridgeName: "", iproute2TableIndex: "", iproute2RuleIndex: "" },
  socks: { version: "5", username: "", password: "", ...UOT_DEFAULTS },
  http: { username: "", password: "", path: "", headersJson: "", ...TLS_DEFAULTS },
  shadowsocks: { method: "2022-blake3-aes-128-gcm", password: "", plugin: "", pluginOpts: "", ...UOT_DEFAULTS, ...MULTIPLEX_DEFAULTS },
  vmess: { uuid: "", security: "auto", alterId: "", globalPadding: false, authenticatedLength: false, packetEncoding: "", ...TLS_DEFAULTS, ...TRANSPORT_DEFAULTS, ...MULTIPLEX_DEFAULTS },
  vless: { uuid: "", flow: "", packetEncoding: "", ...TLS_DEFAULTS, ...TRANSPORT_DEFAULTS, ...MULTIPLEX_DEFAULTS },
  trojan: { password: "", ...TLS_DEFAULTS, ...TRANSPORT_DEFAULTS, ...MULTIPLEX_DEFAULTS },
  naive: { username: "", password: "", quic: false, quicCongestionControl: "", ...TLS_DEFAULTS, tls: true },
  hysteria: { up: "", down: "", obfs: "", authString: "", serverPorts: "", hopInterval: "", ...TLS_DEFAULTS, tls: true },
  hysteria2: { password: "", upMbps: "", downMbps: "", obfsType: "", obfsPassword: "", serverPorts: "", hopInterval: "", hopIntervalMax: "", bbrProfile: "", brutalDebug: false, ...TLS_DEFAULTS, tls: true },
  shadowtls: { version: "3", password: "", ...TLS_DEFAULTS, tls: true },
  tuic: { uuid: "", password: "", congestionControl: "bbr", udpRelayMode: "native", udpOverStream: false, zeroRttHandshake: false, heartbeat: "", ...TLS_DEFAULTS, tls: true },
  anytls: { password: "", idleSessionCheckInterval: "", idleSessionTimeout: "", minIdleSession: "", clientMetadata: "", ...TLS_DEFAULTS, tls: true },
  snell: { version: "4", psk: "", userKey: "", reuse: false, obfsMode: "", obfsHost: "", v6Mode: "" },
  tor: { executablePath: "", extraArgs: "", dataDirectory: "", torrcJson: "" },
  ssh: { user: "", password: "", privateKey: "", privateKeyPath: "", privateKeyPassphrase: "", hostKey: "", hostKeyAlgorithms: "", clientVersion: "" }
};

const DIAL_KEYS = [
  "detour", "bind_interface", "inet4_bind_address", "inet6_bind_address", "bind_address_no_port", "routing_mark",
  "reuse_addr", "netns", "connect_timeout", "tcp_fast_open", "tcp_multi_path", "disable_tcp_keep_alive", "tcp_keep_alive",
  "tcp_keep_alive_interval", "udp_fragment", "domain_resolver", "network_strategy", "network_type",
  "fallback_network_type", "fallback_delay"
];
const COMMON_KEYS = ["server", "server_port", "network", "tls", "transport", "multiplex", "udp_over_tcp", ...DIAL_KEYS];

const EXTRA_KEYS = {
  direct: new Set([...DIAL_KEYS]),
  bridge: new Set(["interface", "bridge_name", "iproute2_table_index", "iproute2_rule_index", ...DIAL_KEYS]),
  socks: new Set([...COMMON_KEYS, "version", "username", "password"]),
  http: new Set([...COMMON_KEYS, "username", "password", "path", "headers"]),
  shadowsocks: new Set([...COMMON_KEYS, "method", "password", "plugin", "plugin_opts"]),
  vmess: new Set([...COMMON_KEYS, "uuid", "security", "alter_id", "global_padding", "authenticated_length", "packet_encoding"]),
  vless: new Set([...COMMON_KEYS, "uuid", "flow", "packet_encoding"]),
  trojan: new Set([...COMMON_KEYS, "password"]),
  naive: new Set([...COMMON_KEYS, "username", "password", "insecure_concurrency", "extra_headers", "stream_receive_window", "quic", "quic_congestion_control", "quic_session_receive_window"]),
  hysteria: new Set([...COMMON_KEYS, "server_ports", "hop_interval", "up", "up_mbps", "down", "down_mbps", "obfs", "auth", "auth_str"]),
  hysteria2: new Set([...COMMON_KEYS, "server_ports", "hop_interval", "hop_interval_max", "up_mbps", "down_mbps", "obfs", "password", "bbr_profile", "brutal_debug", "disable_chrome_parrot", "realm"]),
  shadowtls: new Set([...COMMON_KEYS, "version", "password"]),
  tuic: new Set([...COMMON_KEYS, "uuid", "password", "congestion_control", "udp_relay_mode", "udp_over_stream", "zero_rtt_handshake", "heartbeat"]),
  anytls: new Set([...COMMON_KEYS, "password", "idle_session_check_interval", "idle_session_timeout", "min_idle_session", "client_metadata"]),
  snell: new Set([...COMMON_KEYS, "version", "psk", "userkey", "reuse", "obfs", "mode"]),
  tor: new Set(["executable_path", "extra_args", "data_directory", "torrc", ...DIAL_KEYS]),
  ssh: new Set([...COMMON_KEYS, "user", "password", "private_key", "private_key_path", "private_key_passphrase", "host_key", "host_key_algorithms", "client_version", "cipher", "mac", "kex_algorithm"])
};

const FORBIDDEN_KEYS = new Set([
  "domain_strategy", "recv_window_conn", "recv_window", "disable_mtu_discovery", "gso", "plugin_arguments",
  "alter_id_legacy", "up_mbps_legacy"
]);

export function normalizeOutbound(node = {}) {
  const type = OUTBOUND_TYPE_META[node.type] ? node.type : "direct";
  return { ...BASE_DEFAULTS, ...TYPE_DEFAULTS[type], ...node, type };
}

function buildTls(node) {
  const meta = OUTBOUND_TYPE_META[node.type];
  if (!meta.tls || !node.tls) return undefined;
  return compact({
    enabled: true,
    disable_sni: node.disableSni || undefined,
    server_name: String(node.sni || "").trim() || undefined,
    insecure: node.insecure || undefined,
    alpn: splitList(node.alpn),
    min_version: node.tlsMinVersion || undefined,
    max_version: node.tlsMaxVersion || undefined,
    certificate: String(node.tlsCertificate || "").trim(),
    certificate_path: String(node.tlsCertificatePath || "").trim(),
    fragment: node.tlsFragment || undefined,
    fragment_fallback_delay: String(node.tlsFragmentFallbackDelay || "").trim(),
    record_fragment: node.tlsRecordFragment || undefined,
    ech: node.echEnabled
      ? compact({ enabled: true, config: splitLines(node.echConfig), config_path: String(node.echConfigPath || "").trim() })
      : undefined,
    utls: node.fingerprint ? { enabled: true, fingerprint: node.fingerprint } : undefined,
    reality: meta.reality && node.reality
      ? compact({ enabled: true, public_key: String(node.publicKey || "").trim(), short_id: String(node.shortId || "").trim() })
      : undefined
  });
}

function buildTransport(node) {
  const meta = OUTBOUND_TYPE_META[node.type];
  if (!meta.transport) return undefined;
  const extra = parseJsonObject(node.transportJson, "传输层附加参数");
  const type = node.transport && node.transport !== "tcp" ? node.transport : "";
  if (!type) return Object.keys(extra).length ? extra : undefined;
  const base = { type };
  if (type === "ws") {
    base.path = String(node.path || "").trim() || undefined;
    if (node.host) base.headers = { Host: String(node.host).trim() };
    base.max_early_data = optionalPositiveInteger(node.maxEarlyData);
    base.early_data_header_name = String(node.earlyDataHeaderName || "").trim() || undefined;
  }
  if (type === "grpc") base.service_name = String(node.path || "").replace(/^\//, "").trim() || undefined;
  if (type === "httpupgrade") {
    base.host = String(node.host || "").trim() || undefined;
    base.path = String(node.path || "").trim() || undefined;
  }
  if (type === "http") {
    base.host = splitList(node.host);
    base.path = String(node.path || "").trim() || undefined;
    base.method = String(node.transportMethod || "").trim() || undefined;
  }
  return mergeDeep(extra, compact(base));
}

function buildMultiplex(node) {
  if (!OUTBOUND_TYPE_META[node.type].multiplex || !node.multiplexEnabled) return undefined;
  return compact({
    enabled: true,
    protocol: node.multiplexProtocol || undefined,
    max_connections: optionalPositiveInteger(node.maxConnections),
    min_streams: optionalPositiveInteger(node.minStreams),
    max_streams: optionalPositiveInteger(node.maxStreams),
    padding: node.multiplexPadding || undefined,
    brutal: node.brutalEnabled
      ? compact({ enabled: true, up_mbps: optionalPositiveInteger(node.brutalUp), down_mbps: optionalPositiveInteger(node.brutalDown) })
      : undefined
  });
}

function buildUdpOverTcp(node) {
  if (!OUTBOUND_TYPE_META[node.type].uot || !node.uotEnabled) return undefined;
  return compact({ enabled: true, version: node.uotVersion ? Number(node.uotVersion) : undefined });
}

function serverFields(node) {
  if (OUTBOUND_TYPE_META[node.type].server === false) return {};
  return { server: String(node.server || "").trim(), server_port: optionalPort(node.port) };
}

const BUILDERS = {
  direct: () => ({}),
  bridge: (node) => ({
    interface: String(node.interface || "").trim(),
    bridge_name: String(node.bridgeName || "").trim(),
    iproute2_table_index: optionalPositiveInteger(node.iproute2TableIndex),
    iproute2_rule_index: optionalPositiveInteger(node.iproute2RuleIndex)
  }),
  socks: (node) => ({
    version: node.version && node.version !== "5" ? node.version : undefined,
    username: String(node.username || "").trim(),
    password: node.password || undefined,
    udp_over_tcp: buildUdpOverTcp(node)
  }),
  http: (node) => ({
    username: String(node.username || "").trim(),
    password: node.password || undefined,
    path: String(node.path || "").trim(),
    headers: parseJsonObject(node.headersJson, "附加请求头"),
    tls: buildTls(node)
  }),
  shadowsocks: (node) => ({
    method: node.method,
    password: node.password,
    plugin: String(node.plugin || "").trim(),
    plugin_opts: String(node.pluginOpts || "").trim(),
    udp_over_tcp: buildUdpOverTcp(node),
    multiplex: buildMultiplex(node)
  }),
  vmess: (node) => ({
    uuid: String(node.uuid || "").trim(),
    security: node.security || "auto",
    alter_id: node.alterId === "" ? undefined : Number(node.alterId),
    global_padding: node.globalPadding || undefined,
    authenticated_length: node.authenticatedLength || undefined,
    packet_encoding: node.packetEncoding || undefined,
    tls: buildTls(node),
    transport: buildTransport(node),
    multiplex: buildMultiplex(node)
  }),
  vless: (node) => ({
    uuid: String(node.uuid || "").trim(),
    flow: node.reality && !node.flow ? "xtls-rprx-vision" : (node.flow || undefined),
    packet_encoding: node.packetEncoding || undefined,
    tls: buildTls(node),
    transport: buildTransport(node),
    multiplex: buildMultiplex(node)
  }),
  trojan: (node) => ({
    password: node.password,
    tls: buildTls(node),
    transport: buildTransport(node),
    multiplex: buildMultiplex(node)
  }),
  naive: (node) => ({
    username: String(node.username || "").trim(),
    password: node.password,
    quic: node.quic || undefined,
    quic_congestion_control: node.quicCongestionControl || undefined,
    tls: buildTls(node)
  }),
  hysteria: (node) => ({
    server_ports: splitList(node.serverPorts),
    hop_interval: String(node.hopInterval || "").trim(),
    up: String(node.up || "").trim(),
    down: String(node.down || "").trim(),
    obfs: String(node.obfs || "").trim(),
    auth_str: String(node.authString || "").trim(),
    tls: buildTls(node)
  }),
  hysteria2: (node) => ({
    server_ports: splitList(node.serverPorts),
    hop_interval: String(node.hopInterval || "").trim(),
    hop_interval_max: String(node.hopIntervalMax || "").trim(),
    up_mbps: optionalPositiveInteger(node.upMbps),
    down_mbps: optionalPositiveInteger(node.downMbps),
    obfs: node.obfsType ? compact({ type: node.obfsType, password: node.obfsPassword }) : undefined,
    password: node.password,
    bbr_profile: node.bbrProfile || undefined,
    brutal_debug: node.brutalDebug || undefined,
    tls: buildTls(node)
  }),
  shadowtls: (node) => ({
    version: Number(node.version) || 3,
    password: node.password,
    tls: buildTls(node)
  }),
  tuic: (node) => ({
    uuid: String(node.uuid || "").trim(),
    password: node.password,
    congestion_control: node.congestionControl || undefined,
    udp_relay_mode: node.udpOverStream ? undefined : (node.udpRelayMode || undefined),
    udp_over_stream: node.udpOverStream || undefined,
    zero_rtt_handshake: node.zeroRttHandshake || undefined,
    heartbeat: String(node.heartbeat || "").trim(),
    tls: buildTls(node)
  }),
  anytls: (node) => ({
    password: node.password,
    idle_session_check_interval: String(node.idleSessionCheckInterval || "").trim(),
    idle_session_timeout: String(node.idleSessionTimeout || "").trim(),
    min_idle_session: optionalPositiveInteger(node.minIdleSession),
    client_metadata: String(node.clientMetadata || "").trim(),
    tls: buildTls(node)
  }),
  snell: (node) => ({
    version: Number(node.version) || 4,
    psk: String(node.psk || "").trim(),
    userkey: String(node.userKey || "").trim(),
    reuse: node.reuse || undefined,
    obfs: node.obfsMode ? compact({ obfs_mode: node.obfsMode, host: String(node.obfsHost || "").trim() }) : undefined,
    mode: Number(node.version) === 6 && node.v6Mode ? node.v6Mode : undefined
  }),
  tor: (node) => ({
    executable_path: String(node.executablePath || "").trim(),
    extra_args: splitList(node.extraArgs),
    data_directory: String(node.dataDirectory || "").trim(),
    torrc: parseJsonObject(node.torrcJson, "torrc 参数")
  }),
  ssh: (node) => ({
    user: String(node.user || "").trim(),
    password: node.password || undefined,
    private_key: splitLines(node.privateKey),
    private_key_path: String(node.privateKeyPath || "").trim(),
    private_key_passphrase: node.privateKeyPassphrase || undefined,
    host_key: splitLines(node.hostKey),
    host_key_algorithms: splitList(node.hostKeyAlgorithms),
    client_version: String(node.clientVersion || "").trim()
  })
};

export function buildOutbound(source) {
  const node = normalizeOutbound(source);
  const extra = parseJsonObject(node.advancedJson, "附加出站参数");
  const built = compact({
    type: node.type,
    tag: String(node.tag || "").trim(),
    ...serverFields(node),
    ...BUILDERS[node.type](node),
    network: node.network || undefined,
    ...buildDialFields(node)
  });
  return mergeDeep(extra, built);
}

export function outboundIsComplete(source) {
  const node = normalizeOutbound(source);
  return !validateOutbound(node, { skipReferences: true });
}

function validateDuration(value, label) {
  return value && !DURATION_PATTERN.test(String(value).trim()) ? `${label}不是有效的 Go Duration，例如 300ms、10s 或 5m` : "";
}

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export function validateOutbound(source, { nodes = [], outboundTags = [], dnsServerTags = [], skipReferences = false } = {}) {
  const node = normalizeOutbound(source);
  const meta = OUTBOUND_TYPE_META[node.type];
  const tag = String(node.tag || "").trim();
  if (!tag) return "请填写出站标签";
  if (nodes.some((item) => item.id !== node.id && String(item.tag || "").trim() === tag)) return "出站标签必须唯一";

  let extra;
  try {
    extra = parseJsonObject(node.advancedJson, "附加出站参数");
  } catch (error) {
    return error.message;
  }
  const forbidden = hasForbiddenKeys(extra, FORBIDDEN_KEYS);
  if (forbidden) return `附加参数包含已弃用或已移除的字段：${forbidden}`;
  const unknown = Object.keys(extra).find((key) => !EXTRA_KEYS[node.type].has(key));
  if (unknown) return `附加参数不是 ${meta.label} 1.14 字段：${unknown}`;

  if (meta.server !== false) {
    if (!String(node.server || "").trim()) return "请填写服务器地址";
    if (!optionalPort(node.port)) return "服务器端口必须在 1–65535 之间";
  }
  if (!skipReferences) {
    const dialError = validateDialFields(node, outboundTags);
    if (dialError) return dialError;
    if (node.domainResolver && dnsServerTags.length && !dnsServerTags.includes(String(node.domainResolver).trim())) {
      return `域名解析器不存在：${node.domainResolver}`;
    }
  }
  if (node.network && !["tcp", "udp"].includes(node.network)) return "网络只能是 tcp 或 udp";

  if (meta.tlsRequired && !node.tls) return `${meta.label} 必须启用 TLS`;
  if (meta.tls && node.tls) {
    if (node.tlsCertificate && node.tlsCertificatePath) return "证书内容与证书路径不能同时设置";
    if (node.echEnabled && node.echConfig && node.echConfigPath) return "ECH 配置内容与路径不能同时设置";
    const durationError = validateDuration(node.tlsFragmentFallbackDelay, "TLS 分片回退延迟");
    if (durationError) return durationError;
  }
  if (node.reality) {
    if (!meta.reality) return `${meta.label} 不支持 REALITY`;
    if (!node.tls) return "REALITY 需要同时启用 TLS";
    if (!String(node.publicKey || "").trim()) return "REALITY 需要填写 Public Key";
    if (node.echEnabled) return "REALITY 与 ECH 不能同时启用";
  }

  if (["vmess", "vless"].includes(node.type)) {
    if (!UUID_PATTERN.test(String(node.uuid || "").trim())) return "UUID 格式无效";
  }
  if (node.type === "tuic") {
    if (!UUID_PATTERN.test(String(node.uuid || "").trim())) return "UUID 格式无效";
    if (!node.password) return "TUIC 需要填写密码";
    if (node.udpOverStream && node.udpRelayMode && node.udpRelayMode !== "native") return "udp_over_stream 与 udp_relay_mode 不能同时设置";
    const durationError = validateDuration(node.heartbeat, "心跳间隔");
    if (durationError) return durationError;
  }
  if (["trojan", "hysteria2", "anytls", "shadowsocks"].includes(node.type) && !node.password) return "请填写密码";
  if (node.type === "shadowsocks" && !node.method) return "请选择加密方法";
  if (node.type === "hysteria" && !String(node.authString || "").trim()) return "Hysteria 需要填写认证字符串";
  if (node.type === "hysteria2" && node.obfsType && !String(node.obfsPassword || "").trim()) return "启用混淆后需要填写混淆密码";
  if (["hysteria", "hysteria2"].includes(node.type)) {
    const durationError = validateDuration(node.hopInterval, "端口跳跃间隔") || validateDuration(node.hopIntervalMax, "端口跳跃间隔上限");
    if (durationError) return durationError;
    const invalidRange = splitList(node.serverPorts).find((item) => !/^\d+(:\d+)?$/.test(item));
    if (invalidRange) return `服务器端口范围无效：${invalidRange}`;
  }
  if (node.type === "shadowtls") {
    if (![1, 2, 3].includes(Number(node.version))) return "ShadowTLS 版本只能是 1、2 或 3";
    if (Number(node.version) !== 1 && !node.password) return "ShadowTLS v2 / v3 需要填写密码";
  }
  if (node.type === "snell") {
    if (![4, 6].includes(Number(node.version))) return "Snell 出站版本只能是 4 或 6";
    if (!String(node.psk || "").trim()) return "Snell 需要填写 PSK";
    if (Number(node.version) === 6 && node.obfsMode) return "Snell v6 不支持 obfs";
  }
  if (node.type === "ssh") {
    if (!String(node.user || "").trim()) return "SSH 需要填写用户名";
    if (!node.password && !String(node.privateKey || "").trim() && !String(node.privateKeyPath || "").trim()) {
      return "SSH 需要密码或私钥之一";
    }
  }
  if (node.type === "anytls") {
    const durationError = validateDuration(node.idleSessionCheckInterval, "空闲检查间隔") || validateDuration(node.idleSessionTimeout, "空闲超时");
    if (durationError) return durationError;
  }
  if (meta.multiplex && node.multiplexEnabled) {
    if (node.multiplexProtocol && !["h2mux", "smux", "yamux"].includes(node.multiplexProtocol)) return "多路复用协议无效";
    if (node.brutalEnabled && (!optionalPositiveInteger(node.brutalUp) || !optionalPositiveInteger(node.brutalDown))) {
      return "启用 TCP Brutal 后需要填写上下行带宽";
    }
  }
  if (meta.uot && node.uotEnabled && node.uotVersion && !["1", "2"].includes(String(node.uotVersion))) return "UDP over TCP 版本只能是 1 或 2";
  if (meta.transport && node.transport && !["tcp", "ws", "grpc", "http", "httpupgrade", "quic"].includes(node.transport)) return "传输层类型无效";
  if (meta.transport) {
    try {
      parseJsonObject(node.transportJson, "传输层附加参数");
    } catch (error) {
      return error.message;
    }
  }
  return "";
}

export const GROUP_TYPE_META = Object.freeze({
  selector: { label: "Selector", note: "手动选择，客户端可切换", prefix: "proxy" },
  urltest: { label: "URLTest", note: "自动选择延迟最低的成员", prefix: "auto" }
});

export const GROUP_DEFAULTS = Object.freeze({
  type: "selector",
  tag: "",
  enabled: true,
  includeAllNodes: true,
  includeDirect: false,
  members: "",
  defaultMember: "",
  interruptExistConnections: false,
  url: "",
  interval: "",
  tolerance: "",
  idleTimeout: "",
  advancedJson: ""
});

const GROUP_EXTRA_KEYS = new Set(["outbounds", "default", "interrupt_exist_connections", "url", "interval", "tolerance", "idle_timeout"]);

export function normalizeGroup(group = {}) {
  const type = GROUP_TYPE_META[group.type] ? group.type : "selector";
  return { ...GROUP_DEFAULTS, ...group, type };
}

export function groupMembers(source, { nodeTags = [], groupTags = [] } = {}) {
  const group = normalizeGroup(source);
  const explicit = splitList(group.members);
  const members = [];
  for (const tag of explicit) if (!members.includes(tag)) members.push(tag);
  if (group.includeAllNodes) for (const tag of nodeTags) if (!members.includes(tag)) members.push(tag);
  if (group.includeDirect && !members.includes("direct")) members.push("direct");
  return members.filter((tag) => tag !== group.tag && (nodeTags.includes(tag) || groupTags.includes(tag) || tag === "direct"));
}

export function buildGroup(source, context = {}) {
  const group = normalizeGroup(source);
  const extra = parseJsonObject(group.advancedJson, "附加出站组参数");
  const members = groupMembers(group, context);
  const base = {
    type: group.type,
    tag: String(group.tag || "").trim(),
    outbounds: members,
    interrupt_exist_connections: group.interruptExistConnections || undefined
  };
  if (group.type === "selector") {
    base.default = members.includes(String(group.defaultMember || "").trim()) ? group.defaultMember.trim() : undefined;
  } else {
    base.url = String(group.url || "").trim() || undefined;
    base.interval = String(group.interval || "").trim() || undefined;
    base.tolerance = optionalPositiveInteger(group.tolerance);
    base.idle_timeout = String(group.idleTimeout || "").trim() || undefined;
  }
  return mergeDeep(extra, compact(base));
}

export function validateGroup(source, { groups = [], nodeTags = [], groupTags = [] } = {}) {
  const group = normalizeGroup(source);
  const tag = String(group.tag || "").trim();
  if (!tag) return "请填写出站组标签";
  if (groups.some((item) => item.id !== group.id && String(item.tag || "").trim() === tag)) return "出站组标签必须唯一";
  if (nodeTags.includes(tag)) return "出站组标签不能与节点标签重复";
  let extra;
  try {
    extra = parseJsonObject(group.advancedJson, "附加出站组参数");
  } catch (error) {
    return error.message;
  }
  const unknown = Object.keys(extra).find((key) => !GROUP_EXTRA_KEYS.has(key));
  if (unknown) return `附加参数不是出站组 1.14 字段：${unknown}`;

  if (splitList(group.members).includes(tag)) return "出站组不能把自己作为成员";
  const known = [...nodeTags, ...groupTags, "direct"];
  const missing = splitList(group.members).find((item) => !known.includes(item));
  if (missing) return `成员不存在：${missing}`;
  const members = groupMembers(group, { nodeTags, groupTags });
  if (!members.length) return "出站组至少需要一个成员";
  if (group.defaultMember && !members.includes(String(group.defaultMember).trim())) return `默认成员不在成员列表里：${group.defaultMember}`;
  if (group.type === "urltest") {
    const durationError = validateDuration(group.interval, "测试间隔") || validateDuration(group.idleTimeout, "空闲超时");
    if (durationError) return durationError;
    if (group.tolerance !== "" && !optionalPositiveInteger(group.tolerance)) return "容差必须是正整数";
    if (group.url && !/^https?:\/\//i.test(group.url)) return "测试地址必须是 HTTP 或 HTTPS URL";
  }
  return "";
}

export function detectDetourCycles(nodes = [], groups = []) {
  const edges = new Map();
  for (const node of nodes) {
    const tag = String(node.tag || "").trim();
    const detour = String(node.detour || "").trim();
    if (tag && detour) edges.set(tag, [detour]);
  }
  for (const group of groups) {
    const tag = String(group.tag || "").trim();
    if (!tag) continue;
    const members = groupMembers(group, {
      nodeTags: nodes.map((node) => String(node.tag || "").trim()),
      groupTags: groups.map((item) => String(item.tag || "").trim())
    });
    edges.set(tag, [...(edges.get(tag) || []), ...members]);
  }
  const cycles = [];
  const state = new Map();
  const walk = (tag, path) => {
    if (state.get(tag) === "done") return;
    if (state.get(tag) === "visiting") {
      const start = path.indexOf(tag);
      if (start >= 0) cycles.push([...path.slice(start), tag]);
      return;
    }
    state.set(tag, "visiting");
    for (const next of edges.get(tag) || []) walk(next, [...path, tag]);
    state.set(tag, "done");
  };
  for (const tag of edges.keys()) walk(tag, []);
  const seen = new Set();
  return cycles.filter((cycle) => {
    const key = [...cycle].sort().join(">");
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

export const outboundModule = {
  key: "outbounds",
  extendConfig(config, state) {
    const nodes = (state.nodes || []).map(normalizeOutbound).filter((node) => node.enabled !== false && outboundIsComplete(node));
    const nodeTags = nodes.map((node) => String(node.tag || "").trim());
    const groups = (state.groups || []).map(normalizeGroup).filter((group) => group.enabled !== false);
    const groupTags = groups.map((group) => String(group.tag || "").trim());
    const builtGroups = groups
      .map((group) => buildGroup(group, { nodeTags, groupTags }))
      .filter((group) => (group.outbounds || []).length);
    config.outbounds = [...builtGroups, ...nodes.map(buildOutbound), { type: "direct", tag: "direct" }];
    return config;
  }
};
