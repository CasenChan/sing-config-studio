import {
  DURATION_PATTERN,
  LISTEN_DEFAULTS,
  UDP_NAT_DEFAULTS,
  buildListenFields,
  buildUdpNatFields,
  compact,
  hasForbiddenKeys,
  mergeDeep,
  optionalPort,
  optionalPositiveInteger,
  parseJsonArray,
  parseJsonObject,
  splitLines,
  splitList,
  validateListenFields,
  validateUdpNatFields
} from "./shared.js";

export const INBOUND_TYPE_META = Object.freeze({
  mixed: { label: "Mixed", note: "HTTP + SOCKS 混合代理", prefix: "mixed-in", listen: true, users: "auth", tls: true, systemProxy: true, group: "local" },
  socks: { label: "SOCKS", note: "SOCKS5 代理", prefix: "socks-in", listen: true, users: "auth", group: "local" },
  http: { label: "HTTP", note: "HTTP 代理", prefix: "http-in", listen: true, users: "auth", tls: true, systemProxy: true, group: "local" },
  direct: { label: "Direct", note: "端口转发到固定目标", prefix: "direct-in", listen: true, group: "local" },
  tun: { label: "TUN", note: "系统级虚拟网卡，全局接管", prefix: "tun-in", tun: true, udpNat: true, group: "transparent" },
  redirect: { label: "Redirect", note: "Linux 透明代理 · TCP", prefix: "redirect-in", listen: true, linux: true, group: "transparent" },
  tproxy: { label: "TProxy", note: "Linux 透明代理 · TCP/UDP", prefix: "tproxy-in", listen: true, udpNat: true, linux: true, group: "transparent" },
  shadowsocks: { label: "Shadowsocks", note: "服务端", prefix: "ss-in", listen: true, users: "shadowsocks", multiplex: true, group: "server" },
  vmess: { label: "VMess", note: "服务端", prefix: "vmess-in", listen: true, users: "vmess", tls: true, multiplex: true, transport: true, group: "server" },
  vless: { label: "VLESS", note: "服务端", prefix: "vless-in", listen: true, users: "vless", tls: true, multiplex: true, transport: true, group: "server" },
  trojan: { label: "Trojan", note: "服务端", prefix: "trojan-in", listen: true, users: "trojan", tls: true, multiplex: true, transport: true, group: "server" },
  naive: { label: "Naive", note: "NaïveProxy 服务端", prefix: "naive-in", listen: true, users: "auth", tls: true, tlsRequired: true, group: "server" },
  hysteria: { label: "Hysteria", note: "Hysteria v1 服务端", prefix: "hysteria-in", listen: true, users: "hysteria", tls: true, tlsRequired: true, group: "server" },
  hysteria2: { label: "Hysteria 2", note: "Hysteria v2 服务端", prefix: "hy2-in", listen: true, users: "hysteria2", tls: true, tlsRequired: true, group: "server" },
  shadowtls: { label: "ShadowTLS", note: "握手伪装，需转发到其它入站", prefix: "shadowtls-in", listen: true, users: "shadowtls", group: "server" },
  tuic: { label: "TUIC", note: "TUIC v5 服务端", prefix: "tuic-in", listen: true, users: "tuic", tls: true, tlsRequired: true, group: "server" },
  anytls: { label: "AnyTLS", note: "AnyTLS 服务端", prefix: "anytls-in", listen: true, users: "anytls", tls: true, tlsRequired: true, group: "server" },
  snell: { label: "Snell", note: "Snell v5 / v6 服务端", prefix: "snell-in", listen: true, users: "snell", group: "server" },
  cloudflared: { label: "Cloudflared", note: "Cloudflare Tunnel 客户端，无本地监听", prefix: "cloudflared-in", badge: "1.14", group: "tunnel" }
});

export const INBOUND_TYPES = Object.keys(INBOUND_TYPE_META);

export const INBOUND_GROUP_LABELS = Object.freeze({
  local: "本地代理",
  transparent: "系统与透明代理",
  server: "服务端协议",
  tunnel: "隧道"
});

const USER_SHAPES = {
  auth: { required: ["username", "password"], optional: [], sample: '[{"username": "user", "password": "pass"}]' },
  shadowsocks: { required: ["name", "password"], optional: [], sample: '[{"name": "user", "password": "base64key"}]' },
  vmess: { required: ["name", "uuid"], optional: ["alterId"], sample: '[{"name": "user", "uuid": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"}]' },
  vless: { required: ["name", "uuid"], optional: ["flow"], sample: '[{"name": "user", "uuid": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx", "flow": "xtls-rprx-vision"}]' },
  trojan: { required: ["name", "password"], optional: [], sample: '[{"name": "user", "password": "pass"}]' },
  hysteria: { required: ["auth_str"], optional: ["name", "auth"], sample: '[{"name": "user", "auth_str": "pass"}]' },
  hysteria2: { required: ["password"], optional: ["name"], sample: '[{"name": "user", "password": "pass"}]' },
  tuic: { required: ["uuid", "password"], optional: ["name"], sample: '[{"name": "user", "uuid": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx", "password": "pass"}]' },
  anytls: { required: ["password"], optional: ["name"], sample: '[{"name": "user", "password": "pass"}]' },
  shadowtls: { required: ["password"], optional: ["name"], sample: '[{"name": "user", "password": "pass"}]' },
  snell: { required: ["userkey"], optional: ["name"], sample: '[{"name": "user", "userkey": "psk"}]' }
};

export function userSample(type) {
  return USER_SHAPES[INBOUND_TYPE_META[type]?.users]?.sample || "[]";
}

const TLS_DEFAULTS = Object.freeze({
  tlsEnabled: false,
  tlsServerName: "",
  tlsAlpn: "",
  tlsMinVersion: "",
  tlsMaxVersion: "",
  tlsCertificate: "",
  tlsCertificatePath: "",
  tlsKey: "",
  tlsKeyPath: ""
});

const MULTIPLEX_DEFAULTS = Object.freeze({
  multiplexEnabled: false,
  multiplexPadding: false,
  brutalEnabled: false,
  brutalUp: "",
  brutalDown: ""
});

const TRANSPORT_DEFAULTS = Object.freeze({
  transportType: "",
  transportPath: "",
  transportHost: "",
  transportServiceName: "",
  transportJson: ""
});

const BASE_DEFAULTS = Object.freeze({ tag: "", enabled: true, advancedJson: "", usersJson: "" });

const TYPE_DEFAULTS = {
  mixed: { ...LISTEN_DEFAULTS, ...TLS_DEFAULTS, listen: "127.0.0.1", listenPort: "7890", setSystemProxy: false, domainResolver: "" },
  socks: { ...LISTEN_DEFAULTS, listen: "127.0.0.1", listenPort: "1080", domainResolver: "" },
  http: { ...LISTEN_DEFAULTS, ...TLS_DEFAULTS, listen: "127.0.0.1", listenPort: "8080", setSystemProxy: false, domainResolver: "" },
  direct: { ...LISTEN_DEFAULTS, listenPort: "", network: "", overrideAddress: "", overridePort: "" },
  tun: {
    ...UDP_NAT_DEFAULTS,
    interfaceName: "",
    netns: "",
    mtu: "",
    address: "172.19.0.1/30, fdfe:dcba:9876::1/126",
    dnsMode: "",
    dnsAddress: "",
    autoRoute: true,
    autoRedirect: false,
    strictRoute: true,
    stack: "mixed",
    routeAddress: "",
    routeExcludeAddress: "",
    routeAddressSet: "",
    routeExcludeAddressSet: "",
    includeInterface: "",
    excludeInterface: "",
    includeUid: "",
    excludeUid: "",
    includeUidRange: "",
    excludeUidRange: "",
    includePackage: "",
    excludePackage: "",
    includeAndroidUser: "",
    includeMacAddress: "",
    excludeMacAddress: "",
    loopbackAddress: "",
    excludeMptcp: false,
    iproute2TableIndex: "",
    iproute2RuleIndex: "",
    platformJson: ""
  },
  redirect: { ...LISTEN_DEFAULTS, listenPort: "" },
  tproxy: { ...LISTEN_DEFAULTS, ...UDP_NAT_DEFAULTS, listenPort: "", network: "" },
  shadowsocks: { ...LISTEN_DEFAULTS, ...MULTIPLEX_DEFAULTS, listenPort: "", method: "2022-blake3-aes-128-gcm", password: "", network: "", managed: false },
  vmess: { ...LISTEN_DEFAULTS, ...TLS_DEFAULTS, ...MULTIPLEX_DEFAULTS, ...TRANSPORT_DEFAULTS, listenPort: "" },
  vless: { ...LISTEN_DEFAULTS, ...TLS_DEFAULTS, ...MULTIPLEX_DEFAULTS, ...TRANSPORT_DEFAULTS, listenPort: "" },
  trojan: { ...LISTEN_DEFAULTS, ...TLS_DEFAULTS, ...MULTIPLEX_DEFAULTS, ...TRANSPORT_DEFAULTS, listenPort: "", fallbackServer: "", fallbackPort: "" },
  naive: { ...LISTEN_DEFAULTS, ...TLS_DEFAULTS, listenPort: "", network: "", quicCongestionControl: "", tlsEnabled: true },
  hysteria: { ...LISTEN_DEFAULTS, ...TLS_DEFAULTS, listenPort: "", up: "", down: "", obfs: "", tlsEnabled: true },
  hysteria2: { ...LISTEN_DEFAULTS, ...TLS_DEFAULTS, listenPort: "", upMbps: "", downMbps: "", obfsType: "", obfsPassword: "", ignoreClientBandwidth: false, masquerade: "", bbrProfile: "", brutalDebug: false, tlsEnabled: true },
  shadowtls: { ...LISTEN_DEFAULTS, listenPort: "", version: "3", password: "", handshakeServer: "", handshakePort: "443", strictMode: false, wildcardSni: "" },
  tuic: { ...LISTEN_DEFAULTS, ...TLS_DEFAULTS, listenPort: "", congestionControl: "", authTimeout: "", zeroRttHandshake: false, heartbeat: "", tlsEnabled: true },
  anytls: { ...LISTEN_DEFAULTS, ...TLS_DEFAULTS, listenPort: "", paddingScheme: "", tlsEnabled: true },
  snell: { ...LISTEN_DEFAULTS, listenPort: "", version: "5", psk: "", obfsMode: "", v6Mode: "" },
  cloudflared: { token: "", protocol: "", haConnections: "", postQuantum: false, edgeIpVersion: "", datagramVersion: "", gracePeriod: "", region: "" }
};

const LISTEN_KEYS = [
  "listen", "listen_port", "bind_interface", "routing_mark", "reuse_addr", "netns", "tcp_fast_open", "tcp_multi_path",
  "disable_tcp_keep_alive", "tcp_keep_alive", "tcp_keep_alive_interval", "udp_fragment", "udp_timeout", "detour"
];
const UDP_NAT_KEYS = ["udp_timeout", "udp_mapping", "udp_filtering", "udp_nat_max"];
const TLS_KEYS = ["tls"];
const MUX_KEYS = ["multiplex"];
const TRANSPORT_KEYS = ["transport"];

const EXTRA_KEYS = {
  mixed: new Set([...LISTEN_KEYS, ...TLS_KEYS, "users", "set_system_proxy", "domain_resolver"]),
  socks: new Set([...LISTEN_KEYS, "users", "domain_resolver"]),
  http: new Set([...LISTEN_KEYS, ...TLS_KEYS, "users", "set_system_proxy", "domain_resolver"]),
  direct: new Set([...LISTEN_KEYS, "network", "override_address", "override_port"]),
  tun: new Set([
    ...UDP_NAT_KEYS, "interface_name", "netns", "mtu", "address", "dns_mode", "dns_address", "auto_route", "auto_redirect",
    "auto_redirect_input_mark", "auto_redirect_output_mark", "auto_redirect_reset_mark", "auto_redirect_nfqueue",
    "auto_redirect_iproute2_fallback_rule_index", "iproute2_table_index", "iproute2_rule_index", "strict_route",
    "route_address", "route_address_set", "route_exclude_address", "route_exclude_address_set", "include_interface",
    "exclude_interface", "include_uid", "include_uid_range", "exclude_uid", "exclude_uid_range", "include_android_user",
    "include_package", "exclude_package", "include_mac_address", "exclude_mac_address", "loopback_address",
    "exclude_mptcp", "stack", "platform"
  ]),
  redirect: new Set([...LISTEN_KEYS]),
  tproxy: new Set([...LISTEN_KEYS, ...UDP_NAT_KEYS, "network"]),
  shadowsocks: new Set([...LISTEN_KEYS, ...MUX_KEYS, "network", "method", "password", "users", "destinations", "managed"]),
  vmess: new Set([...LISTEN_KEYS, ...TLS_KEYS, ...MUX_KEYS, ...TRANSPORT_KEYS, "users"]),
  vless: new Set([...LISTEN_KEYS, ...TLS_KEYS, ...MUX_KEYS, ...TRANSPORT_KEYS, "users"]),
  trojan: new Set([...LISTEN_KEYS, ...TLS_KEYS, ...MUX_KEYS, ...TRANSPORT_KEYS, "users", "fallback", "fallback_for_alpn"]),
  naive: new Set([...LISTEN_KEYS, ...TLS_KEYS, "users", "network", "quic_congestion_control"]),
  hysteria: new Set([...LISTEN_KEYS, ...TLS_KEYS, "up", "up_mbps", "down", "down_mbps", "obfs", "users"]),
  hysteria2: new Set([
    ...LISTEN_KEYS, ...TLS_KEYS, "up_mbps", "down_mbps", "obfs", "users", "ignore_client_bandwidth", "masquerade",
    "bbr_profile", "brutal_debug", "realm"
  ]),
  shadowtls: new Set([...LISTEN_KEYS, "version", "password", "users", "handshake", "handshake_for_server_name", "strict_mode", "wildcard_sni"]),
  tuic: new Set([...LISTEN_KEYS, ...TLS_KEYS, "users", "congestion_control", "auth_timeout", "zero_rtt_handshake", "heartbeat"]),
  anytls: new Set([...LISTEN_KEYS, ...TLS_KEYS, "users", "padding_scheme"]),
  snell: new Set([...LISTEN_KEYS, "version", "psk", "users", "obfs", "mode"]),
  cloudflared: new Set(["token", "ha_connections", "protocol", "post_quantum", "edge_ip_version", "datagram_version", "grace_period", "region", "control_dialer", "tunnel_dialer"])
};

const FORBIDDEN_KEYS = new Set([
  "sniff", "sniff_override_destination", "sniff_timeout", "domain_strategy", "udp_disable_domain_unmapping",
  "proxy_protocol", "proxy_protocol_accept_no_header", "gso", "inet4_address", "inet6_address", "inet4_route_address",
  "inet6_route_address", "inet4_route_exclude_address", "inet6_route_exclude_address", "endpoint_independent_nat",
  "acme", "recv_window_conn", "recv_window_client", "max_conn_client", "disable_mtu_discovery"
]);

export function normalizeInbound(inbound = {}) {
  const type = INBOUND_TYPE_META[inbound.type] ? inbound.type : "mixed";
  return { ...BASE_DEFAULTS, ...TYPE_DEFAULTS[type], ...inbound, type };
}

function buildTls(inbound) {
  const meta = INBOUND_TYPE_META[inbound.type];
  if (!meta.tls || !inbound.tlsEnabled) return undefined;
  return compact({
    enabled: true,
    server_name: String(inbound.tlsServerName || "").trim(),
    alpn: splitList(inbound.tlsAlpn),
    min_version: inbound.tlsMinVersion || undefined,
    max_version: inbound.tlsMaxVersion || undefined,
    certificate: String(inbound.tlsCertificate || "").trim(),
    certificate_path: String(inbound.tlsCertificatePath || "").trim(),
    key: String(inbound.tlsKey || "").trim(),
    key_path: String(inbound.tlsKeyPath || "").trim()
  });
}

function buildMultiplex(inbound) {
  if (!INBOUND_TYPE_META[inbound.type].multiplex || !inbound.multiplexEnabled) return undefined;
  return compact({
    enabled: true,
    padding: inbound.multiplexPadding || undefined,
    brutal: inbound.brutalEnabled
      ? compact({ enabled: true, up_mbps: optionalPositiveInteger(inbound.brutalUp), down_mbps: optionalPositiveInteger(inbound.brutalDown) })
      : undefined
  });
}

function buildTransport(inbound) {
  if (!INBOUND_TYPE_META[inbound.type].transport) return undefined;
  const extra = parseJsonObject(inbound.transportJson, "传输层附加参数");
  if (!inbound.transportType) return Object.keys(extra).length ? extra : undefined;
  const base = { type: inbound.transportType };
  if (inbound.transportType === "ws") {
    base.path = String(inbound.transportPath || "").trim() || undefined;
    if (inbound.transportHost) base.headers = { Host: inbound.transportHost.trim() };
  }
  if (inbound.transportType === "grpc") base.service_name = String(inbound.transportServiceName || "").trim() || undefined;
  if (inbound.transportType === "httpupgrade") {
    base.path = String(inbound.transportPath || "").trim() || undefined;
    base.host = String(inbound.transportHost || "").trim() || undefined;
  }
  if (inbound.transportType === "http") {
    base.host = splitList(inbound.transportHost);
    base.path = String(inbound.transportPath || "").trim() || undefined;
  }
  return mergeDeep(extra, compact(base));
}

function buildUsers(inbound) {
  const shape = INBOUND_TYPE_META[inbound.type].users;
  if (!shape) return undefined;
  const users = parseJsonArray(inbound.usersJson, "用户列表");
  return users.length ? users : undefined;
}

const BUILDERS = {
  mixed: (inbound) => ({
    ...buildListenFields(inbound),
    users: buildUsers(inbound),
    set_system_proxy: inbound.setSystemProxy || undefined,
    domain_resolver: String(inbound.domainResolver || "").trim(),
    tls: buildTls(inbound)
  }),
  socks: (inbound) => ({
    ...buildListenFields(inbound),
    users: buildUsers(inbound),
    domain_resolver: String(inbound.domainResolver || "").trim()
  }),
  http: (inbound) => ({
    ...buildListenFields(inbound),
    users: buildUsers(inbound),
    set_system_proxy: inbound.setSystemProxy || undefined,
    domain_resolver: String(inbound.domainResolver || "").trim(),
    tls: buildTls(inbound)
  }),
  direct: (inbound) => ({
    ...buildListenFields(inbound),
    network: inbound.network || undefined,
    override_address: String(inbound.overrideAddress || "").trim(),
    override_port: optionalPort(inbound.overridePort)
  }),
  tun: (inbound) => ({
    interface_name: String(inbound.interfaceName || "").trim(),
    netns: String(inbound.netns || "").trim(),
    address: splitList(inbound.address),
    mtu: optionalPositiveInteger(inbound.mtu),
    dns_mode: inbound.dnsMode || undefined,
    dns_address: splitList(inbound.dnsAddress),
    auto_route: inbound.autoRoute || undefined,
    auto_redirect: inbound.autoRedirect || undefined,
    iproute2_table_index: optionalPositiveInteger(inbound.iproute2TableIndex),
    iproute2_rule_index: optionalPositiveInteger(inbound.iproute2RuleIndex),
    strict_route: inbound.strictRoute || undefined,
    route_address: splitList(inbound.routeAddress),
    route_address_set: splitList(inbound.routeAddressSet),
    route_exclude_address: splitList(inbound.routeExcludeAddress),
    route_exclude_address_set: splitList(inbound.routeExcludeAddressSet),
    include_interface: splitList(inbound.includeInterface),
    exclude_interface: splitList(inbound.excludeInterface),
    include_uid: splitList(inbound.includeUid).map(Number),
    include_uid_range: splitList(inbound.includeUidRange),
    exclude_uid: splitList(inbound.excludeUid).map(Number),
    exclude_uid_range: splitList(inbound.excludeUidRange),
    include_android_user: splitList(inbound.includeAndroidUser).map(Number),
    include_package: splitList(inbound.includePackage),
    exclude_package: splitList(inbound.excludePackage),
    include_mac_address: splitList(inbound.includeMacAddress),
    exclude_mac_address: splitList(inbound.excludeMacAddress),
    loopback_address: splitList(inbound.loopbackAddress),
    exclude_mptcp: inbound.excludeMptcp || undefined,
    stack: inbound.stack || undefined,
    platform: parseJsonObject(inbound.platformJson, "平台参数"),
    ...buildUdpNatFields(inbound)
  }),
  redirect: (inbound) => ({ ...buildListenFields(inbound) }),
  tproxy: (inbound) => ({
    ...buildListenFields(inbound),
    network: inbound.network || undefined,
    ...buildUdpNatFields(inbound)
  }),
  shadowsocks: (inbound) => ({
    ...buildListenFields(inbound),
    network: inbound.network || undefined,
    method: inbound.method,
    password: buildUsers(inbound) ? undefined : inbound.password,
    users: buildUsers(inbound),
    managed: inbound.managed || undefined,
    multiplex: buildMultiplex(inbound)
  }),
  vmess: (inbound) => ({
    ...buildListenFields(inbound),
    users: buildUsers(inbound),
    tls: buildTls(inbound),
    multiplex: buildMultiplex(inbound),
    transport: buildTransport(inbound)
  }),
  vless: (inbound) => ({
    ...buildListenFields(inbound),
    users: buildUsers(inbound),
    tls: buildTls(inbound),
    multiplex: buildMultiplex(inbound),
    transport: buildTransport(inbound)
  }),
  trojan: (inbound) => ({
    ...buildListenFields(inbound),
    users: buildUsers(inbound),
    tls: buildTls(inbound),
    fallback: inbound.fallbackServer
      ? compact({ server: inbound.fallbackServer.trim(), server_port: optionalPort(inbound.fallbackPort) })
      : undefined,
    multiplex: buildMultiplex(inbound),
    transport: buildTransport(inbound)
  }),
  naive: (inbound) => ({
    ...buildListenFields(inbound),
    users: buildUsers(inbound),
    network: inbound.network || undefined,
    quic_congestion_control: inbound.quicCongestionControl || undefined,
    tls: buildTls(inbound)
  }),
  hysteria: (inbound) => ({
    ...buildListenFields(inbound),
    up: String(inbound.up || "").trim(),
    down: String(inbound.down || "").trim(),
    obfs: String(inbound.obfs || "").trim(),
    users: buildUsers(inbound),
    tls: buildTls(inbound)
  }),
  hysteria2: (inbound) => ({
    ...buildListenFields(inbound),
    up_mbps: optionalPositiveInteger(inbound.upMbps),
    down_mbps: optionalPositiveInteger(inbound.downMbps),
    obfs: inbound.obfsType ? compact({ type: inbound.obfsType, password: inbound.obfsPassword }) : undefined,
    users: buildUsers(inbound),
    ignore_client_bandwidth: inbound.ignoreClientBandwidth || undefined,
    masquerade: String(inbound.masquerade || "").trim(),
    bbr_profile: inbound.bbrProfile || undefined,
    brutal_debug: inbound.brutalDebug || undefined,
    tls: buildTls(inbound)
  }),
  shadowtls: (inbound) => ({
    ...buildListenFields(inbound),
    version: Number(inbound.version) || 3,
    password: Number(inbound.version) === 2 ? String(inbound.password || "").trim() : undefined,
    users: Number(inbound.version) === 3 ? buildUsers(inbound) : undefined,
    handshake: compact({ server: String(inbound.handshakeServer || "").trim(), server_port: optionalPort(inbound.handshakePort) }),
    strict_mode: inbound.strictMode || undefined,
    wildcard_sni: inbound.wildcardSni || undefined
  }),
  tuic: (inbound) => ({
    ...buildListenFields(inbound),
    users: buildUsers(inbound),
    congestion_control: inbound.congestionControl || undefined,
    auth_timeout: String(inbound.authTimeout || "").trim(),
    zero_rtt_handshake: inbound.zeroRttHandshake || undefined,
    heartbeat: String(inbound.heartbeat || "").trim(),
    tls: buildTls(inbound)
  }),
  anytls: (inbound) => ({
    ...buildListenFields(inbound),
    users: buildUsers(inbound),
    padding_scheme: splitLines(inbound.paddingScheme),
    tls: buildTls(inbound)
  }),
  snell: (inbound) => ({
    ...buildListenFields(inbound),
    version: Number(inbound.version) || 5,
    psk: buildUsers(inbound) ? undefined : String(inbound.psk || "").trim(),
    users: buildUsers(inbound),
    obfs: inbound.obfsMode ? { obfs_mode: inbound.obfsMode } : undefined,
    mode: Number(inbound.version) === 6 && inbound.v6Mode ? inbound.v6Mode : undefined
  }),
  cloudflared: (inbound) => ({
    token: String(inbound.token || "").trim(),
    protocol: inbound.protocol || undefined,
    ha_connections: optionalPositiveInteger(inbound.haConnections),
    post_quantum: inbound.postQuantum || undefined,
    edge_ip_version: inbound.edgeIpVersion ? Number(inbound.edgeIpVersion) : undefined,
    datagram_version: inbound.datagramVersion || undefined,
    grace_period: String(inbound.gracePeriod || "").trim(),
    region: String(inbound.region || "").trim()
  })
};

export function buildInbound(source) {
  const inbound = normalizeInbound(source);
  const extra = parseJsonObject(inbound.advancedJson, "附加入站参数");
  const built = compact({ type: inbound.type, tag: String(inbound.tag || "").trim(), ...BUILDERS[inbound.type](inbound) });
  return mergeDeep(extra, built);
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

function validateUsers(inbound) {
  const meta = INBOUND_TYPE_META[inbound.type];
  if (!meta.users) return "";
  const shape = USER_SHAPES[meta.users];
  let users;
  try {
    users = parseJsonArray(inbound.usersJson, "用户列表");
  } catch (error) {
    return error.message;
  }
  for (const [index, user] of users.entries()) {
    if (!user || typeof user !== "object" || Array.isArray(user)) return `用户 ${index + 1} 必须是对象`;
    const missing = shape.required.find((key) => !String(user[key] ?? "").trim());
    if (missing) return `用户 ${index + 1} 缺少 ${missing}`;
    const unknown = Object.keys(user).find((key) => !shape.required.includes(key) && !shape.optional.includes(key));
    if (unknown) return `用户 ${index + 1} 含有该协议不支持的字段：${unknown}`;
  }
  return "";
}

function validateTls(inbound, extra) {
  const meta = INBOUND_TYPE_META[inbound.type];
  if (!meta.tls) return "";
  const extraTls = extra.tls || {};
  if (meta.tlsRequired && !inbound.tlsEnabled && !extraTls.enabled) return `${meta.label} 必须启用 TLS`;
  if (!inbound.tlsEnabled) return "";
  const certificate = inbound.tlsCertificate || inbound.tlsCertificatePath || extraTls.certificate || extraTls.certificate_path || extraTls.certificate_provider;
  const key = inbound.tlsKey || inbound.tlsKeyPath || extraTls.key || extraTls.key_path || extraTls.certificate_provider;
  if (!certificate) return "启用 TLS 后需要填写证书内容或证书路径";
  if (!key) return "启用 TLS 后需要填写私钥内容或私钥路径";
  if (inbound.tlsCertificate && inbound.tlsCertificatePath) return "证书内容与证书路径不能同时设置";
  if (inbound.tlsKey && inbound.tlsKeyPath) return "私钥内容与私钥路径不能同时设置";
  return "";
}

export function validateInbound(source, { inbounds = [], outboundTags = [], dnsServerTags = [] } = {}) {
  const inbound = normalizeInbound(source);
  const meta = INBOUND_TYPE_META[inbound.type];
  const tag = String(inbound.tag || "").trim();
  if (!tag) return "请填写入站标签";
  if (inbounds.some((item) => item.id !== inbound.id && String(item.tag || "").trim() === tag)) return "入站标签必须唯一";

  let extra;
  try {
    extra = parseJsonObject(inbound.advancedJson, "附加入站参数");
  } catch (error) {
    return error.message;
  }
  const forbidden = hasForbiddenKeys(extra, FORBIDDEN_KEYS);
  if (forbidden) return `附加参数包含已弃用或已移除的字段：${forbidden}`;
  const unknown = Object.keys(extra).find((key) => !EXTRA_KEYS[inbound.type].has(key));
  if (unknown) return `附加参数不是 ${meta.label} 1.14 字段：${unknown}`;

  if (meta.listen) {
    const listenTags = inbounds.filter((item) => item.id !== inbound.id).map((item) => String(item.tag || "").trim());
    const listenError = validateListenFields(inbound, listenTags, { detourLabel: "入站" });
    if (listenError) return listenError;
    if (inbound.listen && !isIpAddress(inbound.listen)) return "监听地址必须是 IP 地址";
  }
  if (meta.udpNat) {
    const udpError = validateUdpNatFields(inbound);
    if (udpError) return udpError;
  }
  const usersError = validateUsers(inbound);
  if (usersError) return usersError;
  const tlsError = validateTls(inbound, extra);
  if (tlsError) return tlsError;

  if (inbound.type === "tun") {
    if (!splitList(inbound.address).length) return "请填写至少一个 TUN 接口地址";
    const invalidAddress = splitList(inbound.address).find((item) => !isIpPrefix(item, { requirePrefix: true }));
    if (invalidAddress) return `TUN 接口地址必须是 CIDR：${invalidAddress}`;
    for (const [value, label] of [[inbound.routeAddress, "路由地址"], [inbound.routeExcludeAddress, "排除路由地址"]]) {
      const invalid = splitList(value).find((item) => !isIpPrefix(item, { requirePrefix: true }));
      if (invalid) return `${label}必须是 CIDR：${invalid}`;
    }
    const invalidDns = splitList(inbound.dnsAddress).find((item) => !isIpAddress(item));
    if (invalidDns) return `TUN DNS 地址无效：${invalidDns}`;
    if (inbound.dnsMode && !["disabled", "native", "hijack"].includes(inbound.dnsMode)) return "TUN DNS 模式无效";
    if (inbound.stack && !["system", "gvisor", "mixed"].includes(inbound.stack)) return "TUN 网络栈无效";
    if (inbound.autoRedirect && !inbound.autoRoute) return "auto_redirect 需要同时启用 auto_route";
    if (inbound.mtu && !optionalPositiveInteger(inbound.mtu)) return "MTU 必须是正整数";
    const invalidMac = [...splitList(inbound.includeMacAddress), ...splitList(inbound.excludeMacAddress)].find((item) => !/^([0-9a-f]{2}:){5}[0-9a-f]{2}$/i.test(item));
    if (invalidMac) return `MAC 地址无效：${invalidMac}`;
    if (splitList(inbound.includeUid).some((item) => !/^\d+$/.test(item)) || splitList(inbound.excludeUid).some((item) => !/^\d+$/.test(item))) return "UID 必须是非负整数";
    try {
      parseJsonObject(inbound.platformJson, "平台参数");
    } catch (error) {
      return error.message;
    }
  }
  if (inbound.type === "direct" && inbound.overrideAddress && !isIpAddress(inbound.overrideAddress)) return "转发目标地址必须是 IP 地址";
  if (inbound.type === "shadowsocks") {
    if (!inbound.method) return "请选择 Shadowsocks 加密方法";
    const users = parseJsonArray(inbound.usersJson, "用户列表");
    if (!users.length && !String(inbound.password || "").trim()) return "请填写服务端密码或至少一个用户";
    if (inbound.method.startsWith("2022-") && users.length && !String(inbound.password || "").trim() && !extra.password) {
      return "2022 系列加密在多用户模式下仍需要服务端密码";
    }
  }
  if (inbound.type === "shadowtls") {
    const version = Number(inbound.version);
    if (![1, 2, 3].includes(version)) return "ShadowTLS 版本只能是 1、2 或 3";
    if (!String(inbound.handshakeServer || "").trim()) return "请填写 ShadowTLS 握手服务器";
    if (!optionalPort(inbound.handshakePort)) return "ShadowTLS 握手端口必须在 1–65535 之间";
    if (version === 2 && !String(inbound.password || "").trim()) return "ShadowTLS v2 需要填写密码";
    if (version === 3 && !parseJsonArray(inbound.usersJson, "用户列表").length) return "ShadowTLS v3 需要至少一个用户";
    if (!String(inbound.detour || "").trim()) return "ShadowTLS 需要通过 detour 转发到其它入站";
  }
  if (inbound.type === "snell") {
    if (![5, 6].includes(Number(inbound.version))) return "Snell 版本只能是 5 或 6";
    if (!String(inbound.psk || "").trim() && !parseJsonArray(inbound.usersJson, "用户列表").length) return "请填写 PSK 或至少一个用户";
    if (Number(inbound.version) === 6 && inbound.obfsMode) return "Snell v6 不支持 obfs";
  }
  if (inbound.type === "hysteria") {
    if (!parseJsonArray(inbound.usersJson, "用户列表").length) return "Hysteria 需要至少一个用户";
  }
  if (inbound.type === "hysteria2") {
    if (!parseJsonArray(inbound.usersJson, "用户列表").length) return "Hysteria 2 需要至少一个用户";
    if (inbound.obfsType && inbound.obfsType !== "salamander") return "Hysteria 2 混淆类型目前只支持 salamander";
    if (inbound.obfsType && !String(inbound.obfsPassword || "").trim()) return "启用混淆后需要填写混淆密码";
    if (inbound.masquerade && !/^(https?:\/\/|file:\/\/|string:)/i.test(inbound.masquerade)) return "伪装地址需要以 http://、https://、file:// 或 string: 开头";
  }
  if (["vmess", "vless", "trojan", "tuic", "anytls", "naive"].includes(inbound.type)) {
    if (!parseJsonArray(inbound.usersJson, "用户列表").length) return `${meta.label} 需要至少一个用户`;
  }
  if (inbound.type === "cloudflared" && !String(inbound.token || "").trim()) return "请填写 Cloudflare Tunnel Token";
  if (inbound.type === "tuic") {
    const durationError = validateDuration(inbound.authTimeout, "认证超时") || validateDuration(inbound.heartbeat, "心跳间隔");
    if (durationError) return durationError;
  }
  if (inbound.type === "cloudflared") {
    const durationError = validateDuration(inbound.gracePeriod, "优雅退出时间");
    if (durationError) return durationError;
  }
  if (meta.transport && inbound.transportType) {
    if (!["ws", "grpc", "http", "httpupgrade", "quic"].includes(inbound.transportType)) return "传输层类型无效";
    if (inbound.transportType === "grpc" && !String(inbound.transportServiceName || "").trim()) return "gRPC 传输需要填写 Service Name";
  }
  if (meta.transport) {
    try {
      parseJsonObject(inbound.transportJson, "传输层附加参数");
    } catch (error) {
      return error.message;
    }
  }
  if (inbound.domainResolver && dnsServerTags.length && !dnsServerTags.includes(inbound.domainResolver.trim())) {
    return `域名解析器不存在：${inbound.domainResolver.trim()}`;
  }
  return "";
}

export function activeInbounds(inbounds = []) {
  return inbounds.map(normalizeInbound).filter((inbound) => inbound.enabled !== false);
}

export function inboundTags(inbounds = []) {
  return activeInbounds(inbounds).map((inbound) => String(inbound.tag || "").trim()).filter(Boolean);
}

export function hasTunInbound(inbounds = []) {
  return activeInbounds(inbounds).some((inbound) => inbound.type === "tun");
}

export function validateInbounds(inbounds = [], context = {}) {
  const list = inbounds.map(normalizeInbound);
  if (!activeInbounds(inbounds).length) return "至少需要一个启用的入站";
  for (const inbound of activeInbounds(inbounds)) {
    const error = validateInbound(inbound, { ...context, inbounds: list });
    if (error) return `入站「${inbound.tag || "未命名"}」：${error}`;
  }
  return "";
}

export const inboundModule = {
  key: "inbounds",
  extendConfig(config, state) {
    config.inbounds = activeInbounds(state.inbounds || []).map(buildInbound);
    return config;
  }
};
