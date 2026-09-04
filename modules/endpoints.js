import {
  DIAL_DEFAULTS,
  LISTEN_DEFAULTS,
  UDP_NAT_DEFAULTS,
  buildDialFields,
  compact,
  mergeDeep,
  buildListenFields,
  buildUdpNatFields,
  hasForbiddenKeys,
  optionalPort,
  optionalPositiveInteger,
  parseJsonArray,
  parseJsonObject,
  splitList,
  validateDialFields,
  validateListenFields,
  validateUdpNatFields
} from "./shared.js";

export const ENDPOINT_TYPE_META = Object.freeze({
  wireguard: { label: "WireGuard", note: "现代组网端点", prefix: "wireguard" },
  tailscale: { label: "Tailscale", note: "Tailnet 设备与 MagicDNS", prefix: "tailscale" },
  openconnect: { label: "OpenConnect Client", note: "AnyConnect / GlobalProtect / Fortinet", prefix: "openconnect" },
  "openvpn-client": { label: "OpenVPN Client", note: "OpenVPN TLS 客户端", prefix: "openvpn-client" },
  "openvpn-server": { label: "OpenVPN Server", note: "OpenVPN TLS 服务端", prefix: "openvpn-server" }
});

const STANDARD_TYPES = new Set(["wireguard", "openconnect", "openvpn-client", "openvpn-server"]);

const WIREGUARD_DEFAULTS = Object.freeze({
  type: "wireguard",
  tag: "wireguard",
  system: false,
  name: "",
  mtu: "1408",
  address: "",
  privateKey: "",
  listenPort: "",
  peersJson: "[\n  {\n    \"address\": \"\",\n    \"port\": 51820,\n    \"public_key\": \"\",\n    \"allowed_ips\": [\"0.0.0.0/0\", \"::/0\"]\n  }\n]",
  workers: "",
  advancedJson: "",
  ...UDP_NAT_DEFAULTS,
  ...DIAL_DEFAULTS
});

const OPENCONNECT_DEFAULTS = Object.freeze({
  type: "openconnect",
  tag: "openconnect",
  system: false,
  name: "",
  server: "",
  flavor: "anyconnect",
  username: "",
  password: "",
  authGroup: "",
  cookie: "",
  tokenMode: "",
  tokenSecret: "",
  tokenSecretPath: "",
  tokenPin: "",
  tokenPassword: "",
  tokenDeviceId: "",
  tokenCounter: "",
  reportedOs: "",
  userAgent: "",
  localHostname: "",
  noUdp: false,
  ipv6Disabled: false,
  pfs: false,
  mtu: "",
  baseMtu: "",
  tlsInsecure: false,
  tlsServerName: "",
  tlsPeerFingerprint: "",
  tlsSystemTrustDisabled: false,
  tlsCertificateAuthority: "",
  tlsCertificateAuthorityPath: "",
  tlsClientCertificate: "",
  tlsClientCertificatePath: "",
  tlsClientKey: "",
  tlsClientKeyPath: "",
  tlsClientKeyPassword: "",
  advancedJson: "",
  ...UDP_NAT_DEFAULTS,
  ...DIAL_DEFAULTS
});

const OPENVPN_CLIENT_DEFAULTS = Object.freeze({
  type: "openvpn-client",
  tag: "openvpn-client",
  server: "",
  serverPort: "1194",
  serversJson: "",
  remoteRandom: false,
  network: "udp",
  address: "",
  topology: "",
  username: "",
  password: "",
  authRetry: "none",
  tlsServerName: "",
  tlsServerNameType: "name",
  tlsCertificate: "",
  tlsCertificatePath: "",
  tlsClientCertificate: "",
  tlsClientCertificatePath: "",
  tlsClientKey: "",
  tlsClientKeyPath: "",
  tlsPeerFingerprint: "",
  cipher: "",
  dataCiphers: "",
  dataCiphersFallback: "",
  auth: "",
  routeNoPull: false,
  routes: "",
  redirectGateway: false,
  redirectGatewayFlags: "",
  redirectPrivate: false,
  blockIpv6: false,
  system: false,
  name: "",
  mtu: "1500",
  advancedJson: "",
  ...UDP_NAT_DEFAULTS,
  ...DIAL_DEFAULTS
});

const OPENVPN_SERVER_DEFAULTS = Object.freeze({
  ...UDP_NAT_DEFAULTS,
  ...LISTEN_DEFAULTS,
  type: "openvpn-server",
  tag: "openvpn-server",
  listen: "",
  listenPort: "1194",
  network: "udp",
  system: false,
  name: "",
  mtu: "1500",
  maxClients: "1024",
  address: "",
  topology: "subnet",
  duplicateCn: false,
  usersJson: "",
  tlsCertificate: "",
  tlsCertificatePath: "",
  tlsKey: "",
  tlsKeyPath: "",
  tlsClientCertificate: "",
  tlsClientCertificatePath: "",
  tlsVerifyClientCertificate: "require",
  tlsPeerFingerprint: "",
  pushRoutes: "",
  pushDnsServers: "",
  pushSearchDomains: "",
  pushRedirectGateway: false,
  pushRedirectGatewayFlags: "",
  pushBlockOutsideDns: false,
  advancedJson: ""
});

const DEFAULTS = {
  wireguard: WIREGUARD_DEFAULTS,
  openconnect: OPENCONNECT_DEFAULTS,
  "openvpn-client": OPENVPN_CLIENT_DEFAULTS,
  "openvpn-server": OPENVPN_SERVER_DEFAULTS
};

const SHARED_EXTRA_KEYS = [
  "udp_timeout", "udp_mapping", "udp_filtering", "udp_nat_max", "detour", "bind_interface", "inet4_bind_address",
  "inet6_bind_address", "bind_address_no_port", "routing_mark", "reuse_addr", "netns", "connect_timeout", "tcp_fast_open",
  "tcp_multi_path", "disable_tcp_keep_alive", "tcp_keep_alive", "tcp_keep_alive_interval", "udp_fragment", "domain_resolver",
  "network_strategy", "network_type", "fallback_network_type", "fallback_delay"
];

const EXTRA_KEYS = {
  wireguard: new Set(["system", "name", "mtu", "address", "private_key", "listen_port", "peers", "workers", ...SHARED_EXTRA_KEYS]),
  openconnect: new Set([
    "system", "name", "server", "flavor", "username", "password", "auth_group", "cookie", "token", "reported_os", "user_agent",
    "version", "local_hostname", "mobile", "csd", "hip", "tncc", "fortinet_host_check", "no_udp", "dtls_local_port",
    "compression_disabled", "compression_mode", "ipv6_disabled", "http_keepalive_disabled", "xml_post_disabled",
    "external_auth_disabled", "password_authentication_disabled", "tcp_keep_alive_enabled", "pfs", "mtu", "base_mtu", "dpd_interval",
    "reconnect_timeout", "trojan_interval", "queue_length", "allow_insecure_crypto", "tls", "form_entries", ...SHARED_EXTRA_KEYS
  ]),
  "openvpn-client": new Set([
    "server", "server_port", "servers", "remote_random", "network", "address", "peer_address", "peer_address_ipv6", "topology",
    "username", "password", "auth_retry", "static_challenge", "static_challenge_echo", "tls", "cipher", "data_ciphers",
    "data_ciphers_fallback", "auth", "mss_fix", "mss_fix_disabled", "mss_fix_mode", "fragment", "replay_window",
    "replay_window_time", "compression", "compression_lzo", "allow_compression", "route_no_pull", "pull_filters", "routes",
    "route_gateway", "route_metric", "redirect_gateway", "redirect_gateway_flags", "redirect_private", "block_ipv6", "ping_interval",
    "ping_restart", "ping_restart_disabled", "renegotiate_interval", "renegotiate_disabled", "renegotiate_bytes", "renegotiate_packets",
    "tls_timeout", "handshake_window", "explicit_exit_notify", "system", "name", "mtu", ...SHARED_EXTRA_KEYS
  ]),
  "openvpn-server": new Set([
    "listen", "listen_port", "bind_interface", "routing_mark", "reuse_addr", "netns", "tcp_fast_open", "tcp_multi_path",
    "disable_tcp_keep_alive", "tcp_keep_alive", "tcp_keep_alive_interval", "udp_fragment", "detour", "system", "name", "mtu",
    "network", "max_clients", "address", "topology", "duplicate_cn", "users", "tls", "cipher", "data_ciphers",
    "data_ciphers_fallback", "auth", "mss_fix", "mss_fix_disabled", "mss_fix_mode", "replay_window", "replay_window_time", "push",
    "ping_interval", "ping_restart", "renegotiate_interval", "renegotiate_disabled", "renegotiate_bytes", "renegotiate_packets",
    "handshake_window", "udp_timeout", "udp_mapping", "udp_filtering", "udp_nat_max"
  ])
};

function advanced(endpoint) {
  return parseJsonObject(endpoint.advancedJson, "附加 1.14 参数");
}

function buildTlsContent(value) {
  return String(value || "").trim() || undefined;
}

function buildWireGuard(endpoint) {
  return compact({
    ...advanced(endpoint),
    type: "wireguard",
    tag: endpoint.tag.trim(),
    system: endpoint.system || undefined,
    name: endpoint.name?.trim(),
    mtu: optionalPositiveInteger(endpoint.mtu),
    address: splitList(endpoint.address),
    private_key: endpoint.privateKey.trim(),
    listen_port: optionalPort(endpoint.listenPort),
    peers: parseJsonArray(endpoint.peersJson, "WireGuard Peers"),
    ...buildUdpNatFields(endpoint),
    workers: optionalPositiveInteger(endpoint.workers),
    ...buildDialFields(endpoint)
  });
}

function buildOpenConnect(endpoint) {
  const extra = advanced(endpoint);
  const token = compact({
    mode: endpoint.tokenMode,
    secret: endpoint.tokenSecret,
    secret_path: endpoint.tokenSecretPath,
    pin: endpoint.tokenPin,
    password: endpoint.tokenPassword,
    device_id: endpoint.tokenDeviceId,
    counter: endpoint.tokenCounter === "" ? undefined : Number(endpoint.tokenCounter)
  });
  const uiTls = compact({
    insecure: endpoint.tlsInsecure || undefined,
    server_name: endpoint.tlsServerName?.trim(),
    peer_fingerprint: splitList(endpoint.tlsPeerFingerprint),
    system_trust_disabled: endpoint.tlsSystemTrustDisabled || undefined,
    certificate_authority: buildTlsContent(endpoint.tlsCertificateAuthority),
    certificate_authority_path: endpoint.tlsCertificateAuthorityPath?.trim(),
    client_certificate: buildTlsContent(endpoint.tlsClientCertificate),
    client_certificate_path: endpoint.tlsClientCertificatePath?.trim(),
    client_key: buildTlsContent(endpoint.tlsClientKey),
    client_key_path: endpoint.tlsClientKeyPath?.trim(),
    client_key_password: endpoint.tlsClientKeyPassword
  });
  return compact({
    ...extra,
    type: "openconnect",
    tag: endpoint.tag.trim(),
    system: endpoint.system || undefined,
    name: endpoint.name?.trim(),
    ...buildUdpNatFields(endpoint),
    server: endpoint.server.trim(),
    flavor: endpoint.flavor || undefined,
    username: endpoint.username?.trim(),
    password: endpoint.password,
    auth_group: endpoint.authGroup?.trim(),
    cookie: endpoint.cookie,
    token: mergeDeep(extra.token, token),
    reported_os: endpoint.reportedOs,
    user_agent: endpoint.userAgent,
    local_hostname: endpoint.localHostname,
    no_udp: endpoint.noUdp || undefined,
    ipv6_disabled: endpoint.ipv6Disabled || undefined,
    pfs: endpoint.pfs || undefined,
    mtu: optionalPositiveInteger(endpoint.mtu),
    base_mtu: optionalPositiveInteger(endpoint.baseMtu),
    tls: mergeDeep(extra.tls, uiTls),
    ...buildDialFields(endpoint)
  });
}

function buildOpenVpnClient(endpoint) {
  const extra = advanced(endpoint);
  const servers = parseJsonArray(endpoint.serversJson, "备用服务器");
  const uiTls = compact({
    server_name: endpoint.tlsServerName?.trim(),
    server_name_type: endpoint.tlsServerName ? endpoint.tlsServerNameType : undefined,
    certificate: buildTlsContent(endpoint.tlsCertificate),
    certificate_path: endpoint.tlsCertificatePath?.trim(),
    client_certificate: buildTlsContent(endpoint.tlsClientCertificate),
    client_certificate_path: endpoint.tlsClientCertificatePath?.trim(),
    client_key: buildTlsContent(endpoint.tlsClientKey),
    client_key_path: endpoint.tlsClientKeyPath?.trim(),
    peer_fingerprint: splitList(endpoint.tlsPeerFingerprint)
  });
  return compact({
    ...extra,
    type: "openvpn-client",
    tag: endpoint.tag.trim(),
    mode: "tls",
    server: servers.length ? undefined : endpoint.server?.trim(),
    server_port: servers.length ? undefined : optionalPort(endpoint.serverPort),
    servers,
    remote_random: servers.length && endpoint.remoteRandom ? true : undefined,
    network: endpoint.network || undefined,
    address: splitList(endpoint.address),
    topology: endpoint.topology || undefined,
    username: endpoint.username?.trim(),
    password: endpoint.password,
    auth_retry: endpoint.authRetry || undefined,
    tls: mergeDeep(extra.tls, uiTls),
    cipher: endpoint.cipher?.trim(),
    data_ciphers: splitList(endpoint.dataCiphers),
    data_ciphers_fallback: endpoint.dataCiphersFallback?.trim(),
    auth: endpoint.auth?.trim(),
    route_no_pull: endpoint.routeNoPull || undefined,
    routes: splitList(endpoint.routes),
    redirect_gateway: endpoint.redirectGateway || undefined,
    redirect_gateway_flags: splitList(endpoint.redirectGatewayFlags),
    redirect_private: endpoint.redirectPrivate || undefined,
    block_ipv6: endpoint.blockIpv6 || undefined,
    system: endpoint.system || undefined,
    name: endpoint.name?.trim(),
    mtu: optionalPositiveInteger(endpoint.mtu),
    ...buildUdpNatFields(endpoint),
    ...buildDialFields(endpoint)
  });
}

function buildOpenVpnServer(endpoint) {
  const extra = advanced(endpoint);
  const uiTls = compact({
    certificate: buildTlsContent(endpoint.tlsCertificate),
    certificate_path: endpoint.tlsCertificatePath?.trim(),
    key: buildTlsContent(endpoint.tlsKey),
    key_path: endpoint.tlsKeyPath?.trim(),
    client_certificate: buildTlsContent(endpoint.tlsClientCertificate),
    client_certificate_path: endpoint.tlsClientCertificatePath?.trim(),
    verify_client_certificate: endpoint.tlsVerifyClientCertificate || undefined,
    peer_fingerprint: splitList(endpoint.tlsPeerFingerprint)
  });
  const uiPush = compact({
    routes: splitList(endpoint.pushRoutes),
    dns_servers: splitList(endpoint.pushDnsServers),
    search_domains: splitList(endpoint.pushSearchDomains),
    redirect_gateway: endpoint.pushRedirectGateway || undefined,
    redirect_gateway_flags: splitList(endpoint.pushRedirectGatewayFlags),
    block_outside_dns: endpoint.pushBlockOutsideDns || undefined
  });
  return compact({
    ...extra,
    type: "openvpn-server",
    tag: endpoint.tag.trim(),
    ...buildListenFields(endpoint),
    system: endpoint.system || undefined,
    name: endpoint.name?.trim(),
    mtu: optionalPositiveInteger(endpoint.mtu),
    mode: "tls",
    network: endpoint.network || undefined,
    max_clients: optionalPositiveInteger(endpoint.maxClients),
    address: splitList(endpoint.address),
    topology: endpoint.topology || undefined,
    duplicate_cn: endpoint.duplicateCn || undefined,
    users: parseJsonArray(endpoint.usersJson, "OpenVPN 用户"),
    tls: mergeDeep(extra.tls, uiTls),
    push: mergeDeep(extra.push, uiPush),
    ...buildUdpNatFields(endpoint)
  });
}

const BUILDERS = {
  wireguard: buildWireGuard,
  openconnect: buildOpenConnect,
  "openvpn-client": buildOpenVpnClient,
  "openvpn-server": buildOpenVpnServer
};

export function normalizeStandardEndpoint(endpoint = {}) {
  const type = STANDARD_TYPES.has(endpoint.type) ? endpoint.type : "wireguard";
  return { ...DEFAULTS[type], ...endpoint, type };
}

export function buildStandardEndpoint(source) {
  const endpoint = normalizeStandardEndpoint(source);
  return BUILDERS[endpoint.type](endpoint);
}

function validatePort(value, label, required = false) {
  if (value === "" || value === undefined) return required ? `请填写${label}` : "";
  return Number.isInteger(Number(value)) && Number(value) >= 1 && Number(value) <= 65535 ? "" : `${label}必须在 1–65535 之间`;
}

function validateAdvanced(endpoint) {
  let extra;
  try {
    extra = advanced(endpoint);
  } catch (error) {
    return error.message;
  }
  const forbidden = hasForbiddenKeys(extra, new Set(["domain_strategy", "static_key", "static_key_path", "key_direction"]));
  if (forbidden) return `附加参数包含已弃用或不提供的字段：${forbidden}`;
  const unknown = Object.keys(extra).find((key) => !EXTRA_KEYS[endpoint.type].has(key));
  if (unknown) return `附加参数不是 ${ENDPOINT_TYPE_META[endpoint.type].label} 1.14 字段：${unknown}`;
  return "";
}

function validateTag(endpoint, endpoints, outboundTags) {
  if (!endpoint.tag?.trim()) return "请填写端点标签";
  if (endpoints.some((item) => item.id !== endpoint.id && item.tag?.trim() === endpoint.tag.trim()) || outboundTags.includes(endpoint.tag.trim())) {
    return "端点标签必须唯一，且不能与出站标签重复";
  }
  return "";
}

function validateWireGuard(endpoint) {
  if (!splitList(endpoint.address).length) return "请填写至少一个 WireGuard 接口地址";
  if (!endpoint.privateKey?.trim()) return "请填写 WireGuard 私钥";
  let peers;
  try {
    peers = parseJsonArray(endpoint.peersJson, "WireGuard Peers");
  } catch (error) {
    return error.message;
  }
  if (!peers.length) return "至少需要一个 WireGuard Peer";
  for (let index = 0; index < peers.length; index += 1) {
    const peer = peers[index];
    if (!peer || typeof peer !== "object" || Array.isArray(peer)) return `Peer ${index + 1} 必须是对象`;
    if (!String(peer.public_key || "").trim()) return `Peer ${index + 1} 缺少 public_key`;
    if (!splitList(peer.allowed_ips).length) return `Peer ${index + 1} 缺少 allowed_ips`;
    if (peer.port !== undefined && validatePort(peer.port, `Peer ${index + 1} 端口`)) return validatePort(peer.port, `Peer ${index + 1} 端口`);
    if (peer.reserved !== undefined && (!Array.isArray(peer.reserved) || peer.reserved.length !== 3 || peer.reserved.some((item) => !Number.isInteger(item) || item < 0 || item > 255))) return `Peer ${index + 1} 的 reserved 必须是 3 个 0–255 整数`;
  }
  const portError = validatePort(endpoint.listenPort, "WireGuard 监听端口");
  if (portError) return portError;
  return "";
}

function validateOpenConnect(endpoint) {
  if (!endpoint.server?.trim()) return "请填写 OpenConnect 服务器";
  try {
    new URL(/^https?:\/\//i.test(endpoint.server) ? endpoint.server : `https://${endpoint.server}`);
  } catch {
    return "OpenConnect 服务器必须是有效的 HTTPS 地址";
  }
  if (endpoint.tokenMode && !endpoint.tokenSecret && !endpoint.tokenSecretPath) return "启用令牌后必须填写 secret 或 secret_path";
  if (endpoint.tokenSecret && endpoint.tokenSecretPath) return "令牌 secret 与 secret_path 不能同时设置";
  return "";
}

function validateFingerprintList(value, label) {
  const invalid = splitList(value).find((item) => !/^[0-9a-f]{64}$/.test(item));
  return invalid ? `${label}必须是 64 位小写十六进制 SHA-256` : "";
}

function validateOpenVpnClient(endpoint) {
  const extraTls = advanced(endpoint).tls || {};
  let servers;
  try {
    servers = parseJsonArray(endpoint.serversJson, "备用服务器");
  } catch (error) {
    return error.message;
  }
  if (!endpoint.server?.trim() && !servers.length) return "请填写主服务器或备用服务器数组";
  if (endpoint.server && servers.length) return "主服务器与备用服务器数组只能选择一种";
  if (endpoint.server) {
    const error = validatePort(endpoint.serverPort, "服务器端口", true);
    if (error) return error;
  }
  for (const [index, server] of servers.entries()) {
    if (!server?.server) return `备用服务器 ${index + 1} 缺少 server`;
    const error = validatePort(server.server_port, `备用服务器 ${index + 1} 端口`, true);
    if (error) return error;
    if (server.network && !["udp", "tcp"].includes(server.network)) return `备用服务器 ${index + 1} 的 network 只能是 udp 或 tcp`;
  }
  const certificate = endpoint.tlsCertificate || extraTls.certificate;
  const certificatePath = endpoint.tlsCertificatePath || extraTls.certificate_path;
  const fingerprints = splitList(endpoint.tlsPeerFingerprint).length ? splitList(endpoint.tlsPeerFingerprint) : splitList(extraTls.peer_fingerprint);
  if (!certificate && !certificatePath && !fingerprints.length) return "OpenVPN Client 需要 CA 证书、证书路径或服务端指纹之一";
  if (certificate && certificatePath) return "CA 证书内容与路径不能同时设置";
  const clientCertificate = endpoint.tlsClientCertificate || endpoint.tlsClientCertificatePath || extraTls.client_certificate || extraTls.client_certificate_path;
  const clientKey = endpoint.tlsClientKey || endpoint.tlsClientKeyPath || extraTls.client_key || extraTls.client_key_path;
  if (Boolean(clientCertificate) !== Boolean(clientKey)) return "客户端证书和私钥必须同时设置";
  return validateFingerprintList(fingerprints, "服务端指纹");
}

function validateOpenVpnServer(endpoint) {
  const extraTls = advanced(endpoint).tls || {};
  const listenError = validatePort(endpoint.listenPort, "监听端口", true);
  if (listenError) return listenError;
  if (!splitList(endpoint.address).length) return "请填写至少一个 OpenVPN 服务端地址段";
  const certificate = endpoint.tlsCertificate || extraTls.certificate;
  const certificatePath = endpoint.tlsCertificatePath || extraTls.certificate_path;
  const key = endpoint.tlsKey || extraTls.key;
  const keyPath = endpoint.tlsKeyPath || extraTls.key_path;
  const clientCertificate = endpoint.tlsClientCertificate || extraTls.client_certificate;
  const clientCertificatePath = endpoint.tlsClientCertificatePath || extraTls.client_certificate_path;
  const fingerprints = splitList(endpoint.tlsPeerFingerprint).length ? splitList(endpoint.tlsPeerFingerprint) : splitList(extraTls.peer_fingerprint);
  const verifyPolicy = endpoint.tlsVerifyClientCertificate || extraTls.verify_client_certificate || "require";
  if (!certificate && !certificatePath) return "OpenVPN Server 需要 TLS 服务端证书或证书路径";
  if (!key && !keyPath) return "OpenVPN Server 需要 TLS 私钥或私钥路径";
  if (certificate && certificatePath) return "服务端证书内容与路径不能同时设置";
  if (key && keyPath) return "服务端私钥内容与路径不能同时设置";
  if (verifyPolicy !== "none" && !clientCertificate && !clientCertificatePath && !fingerprints.length) return "当前客户端证书策略需要 CA、CA 路径或客户端指纹";
  let users;
  try {
    users = parseJsonArray(endpoint.usersJson, "OpenVPN 用户");
  } catch (error) {
    return error.message;
  }
  if (users.some((user) => !user?.username || !user?.password)) return "OpenVPN 用户数组中的每项都需要 username 与 password";
  return validateFingerprintList(fingerprints, "客户端指纹");
}

export function validateStandardEndpoint(source, { endpoints = [], outboundTags = [] } = {}) {
  const endpoint = normalizeStandardEndpoint(source);
  const tagError = validateTag(endpoint, endpoints, outboundTags);
  if (tagError) return tagError;
  const advancedError = validateAdvanced(endpoint);
  if (advancedError) return advancedError;
  const udpError = validateUdpNatFields(endpoint);
  if (udpError) return udpError;
  const sharedError = endpoint.type === "openvpn-server" ? validateListenFields(endpoint, outboundTags) : validateDialFields(endpoint, outboundTags);
  if (sharedError) return sharedError;
  if (endpoint.type === "wireguard") return validateWireGuard(endpoint);
  if (endpoint.type === "openconnect") return validateOpenConnect(endpoint);
  if (endpoint.type === "openvpn-client") return validateOpenVpnClient(endpoint);
  return validateOpenVpnServer(endpoint);
}

export const endpointFamilyModule = {
  key: "standard-endpoints",
  extendConfig(config, state) {
    const endpoints = (state.endpoints || []).filter((item) => STANDARD_TYPES.has(item.type));
    if (!endpoints.length) return config;
    config.endpoints = [...(config.endpoints || []), ...endpoints.map(buildStandardEndpoint)];
    return config;
  }
};
