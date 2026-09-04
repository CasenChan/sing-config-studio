import {
  DURATION_PATTERN,
  LISTEN_DEFAULTS,
  buildListenFields,
  compact,
  hasForbiddenKeys,
  mergeDeep,
  optionalPort,
  optionalPositiveInteger,
  parseJsonArray,
  parseJsonObject,
  splitLines,
  splitList,
  validateListenFields
} from "./shared.js";

export const SERVICE_TYPE_META = Object.freeze({
  api: { label: "sing-box API", note: "官方 API 与面板", prefix: "api", listen: true },
  derp: { label: "DERP", note: "Tailscale DERP 中继", prefix: "derp", listen: true, tls: true },
  resolved: { label: "Resolved", note: "对外提供 systemd-resolved 接口", prefix: "resolved", listen: true },
  "ssm-api": { label: "SSM API", note: "Shadowsocks 服务器管理 API", prefix: "ssm", listen: true },
  ccm: { label: "CCM", note: "Clash 配置管理", prefix: "ccm", listen: true },
  ocm: { label: "OCM", note: "Outbound 配置管理", prefix: "ocm", listen: true },
  "hysteria-realm": { label: "Hysteria Realm", note: "Hysteria 端口跳跃中继", prefix: "realm", listen: true, tls: true },
  "usbip-server": { label: "USB/IP Server", note: "共享本机 USB 设备", prefix: "usbip-server", listen: true },
  "usbip-client": { label: "USB/IP Client", note: "挂载远端 USB 设备", prefix: "usbip-client" }
});

export const SERVICE_TYPES = Object.keys(SERVICE_TYPE_META);

const TLS_DEFAULTS = Object.freeze({
  tlsEnabled: false,
  tlsServerName: "",
  tlsCertificate: "",
  tlsCertificatePath: "",
  tlsKey: "",
  tlsKeyPath: ""
});

const BASE_DEFAULTS = Object.freeze({ tag: "", enabled: true, advancedJson: "" });

const TYPE_DEFAULTS = {
  api: { ...LISTEN_DEFAULTS, listen: "127.0.0.1", listenPort: "9090", secret: "", allowOrigin: "", allowPrivateNetwork: false, dashboardEnabled: false, dashboardPath: "", dashboardDownloadUrl: "", dashboardUpdateInterval: "" },
  derp: { ...LISTEN_DEFAULTS, ...TLS_DEFAULTS, listenPort: "443", configPath: "", home: "", meshPsk: "", meshPskFile: "", verifyClientEndpoint: "", verifyClientUrl: "", stunListen: "", stunListenPort: "" },
  resolved: { ...LISTEN_DEFAULTS, listen: "127.0.0.1", listenPort: "53" },
  "ssm-api": { ...LISTEN_DEFAULTS, listen: "127.0.0.1", listenPort: "8080", serversJson: "", cachePath: "" },
  ccm: { ...LISTEN_DEFAULTS, listen: "127.0.0.1", listenPort: "8081", credentialPath: "", usersJson: "", headersJson: "", detour: "", usagesPath: "" },
  ocm: { ...LISTEN_DEFAULTS, listen: "127.0.0.1", listenPort: "8082", credentialPath: "", usersJson: "", headersJson: "", detour: "", usagesPath: "" },
  "hysteria-realm": { ...LISTEN_DEFAULTS, ...TLS_DEFAULTS, listenPort: "443", usersJson: "" },
  "usbip-server": { ...LISTEN_DEFAULTS, listenPort: "3240", provider: "", devicesJson: "" },
  "usbip-client": { server: "", serverPort: "3240", devicesJson: "" }
};

const LISTEN_KEYS = [
  "listen", "listen_port", "bind_interface", "routing_mark", "reuse_addr", "netns", "tcp_fast_open", "tcp_multi_path",
  "disable_tcp_keep_alive", "tcp_keep_alive", "tcp_keep_alive_interval", "udp_fragment", "udp_timeout", "detour"
];

const EXTRA_KEYS = {
  api: new Set([...LISTEN_KEYS, "secret", "access_control_allow_origin", "access_control_allow_private_network", "dashboard"]),
  derp: new Set([...LISTEN_KEYS, "tls", "config_path", "verify_client_endpoint", "verify_client_url", "home", "mesh_with", "mesh_psk", "mesh_psk_file", "stun"]),
  resolved: new Set([...LISTEN_KEYS]),
  "ssm-api": new Set([...LISTEN_KEYS, "servers", "cache_path", "tls"]),
  ccm: new Set([...LISTEN_KEYS, "credential_path", "users", "headers", "detour", "usages_path", "tls"]),
  ocm: new Set([...LISTEN_KEYS, "credential_path", "users", "headers", "detour", "usages_path", "tls"]),
  "hysteria-realm": new Set([...LISTEN_KEYS, "tls", "users", "http2"]),
  "usbip-server": new Set([...LISTEN_KEYS, "provider", "devices"]),
  "usbip-client": new Set(["server", "server_port", "devices", "detour", "bind_interface", "connect_timeout"])
};

const FORBIDDEN_KEYS = new Set(["store_rdrc", "cache_file", "cache_id", "store_mode", "store_selected", "store_fakeip", "acme"]);

export function normalizeService(service = {}) {
  const type = SERVICE_TYPE_META[service.type] ? service.type : "api";
  return { ...BASE_DEFAULTS, ...TYPE_DEFAULTS[type], ...service, type };
}

function buildTls(service) {
  if (!SERVICE_TYPE_META[service.type].tls || !service.tlsEnabled) return undefined;
  return compact({
    enabled: true,
    server_name: String(service.tlsServerName || "").trim(),
    certificate: String(service.tlsCertificate || "").trim(),
    certificate_path: String(service.tlsCertificatePath || "").trim(),
    key: String(service.tlsKey || "").trim(),
    key_path: String(service.tlsKeyPath || "").trim()
  });
}

const BUILDERS = {
  api: (service) => ({
    ...buildListenFields(service),
    secret: service.secret || undefined,
    access_control_allow_origin: splitList(service.allowOrigin),
    access_control_allow_private_network: service.allowPrivateNetwork || undefined,
    dashboard: service.dashboardEnabled
      ? compact({
          enabled: true,
          path: String(service.dashboardPath || "").trim(),
          download_url: String(service.dashboardDownloadUrl || "").trim(),
          update_interval: String(service.dashboardUpdateInterval || "").trim()
        })
      : undefined
  }),
  derp: (service) => ({
    ...buildListenFields(service),
    tls: buildTls(service),
    config_path: String(service.configPath || "").trim(),
    home: String(service.home || "").trim(),
    mesh_psk: service.meshPsk || undefined,
    mesh_psk_file: String(service.meshPskFile || "").trim(),
    verify_client_endpoint: splitList(service.verifyClientEndpoint),
    verify_client_url: splitList(service.verifyClientUrl).map((url) => ({ url })),
    stun: service.stunListenPort
      ? compact({ listen: String(service.stunListen || "").trim(), listen_port: optionalPort(service.stunListenPort) })
      : undefined
  }),
  resolved: (service) => ({ ...buildListenFields(service) }),
  "ssm-api": (service) => ({
    ...buildListenFields(service),
    servers: parseJsonObject(service.serversJson, "SSM 服务器映射"),
    cache_path: String(service.cachePath || "").trim()
  }),
  ccm: (service) => ({
    ...buildListenFields(service),
    credential_path: String(service.credentialPath || "").trim(),
    users: parseJsonArray(service.usersJson, "用户列表"),
    headers: parseJsonObject(service.headersJson, "附加请求头"),
    usages_path: String(service.usagesPath || "").trim()
  }),
  ocm: (service) => ({
    ...buildListenFields(service),
    credential_path: String(service.credentialPath || "").trim(),
    users: parseJsonArray(service.usersJson, "用户列表"),
    headers: parseJsonObject(service.headersJson, "附加请求头"),
    usages_path: String(service.usagesPath || "").trim()
  }),
  "hysteria-realm": (service) => ({
    ...buildListenFields(service),
    tls: buildTls(service),
    users: parseJsonArray(service.usersJson, "Realm 用户")
  }),
  "usbip-server": (service) => ({
    ...buildListenFields(service),
    provider: service.provider || undefined,
    devices: parseJsonArray(service.devicesJson, "设备列表")
  }),
  "usbip-client": (service) => ({
    server: String(service.server || "").trim(),
    server_port: optionalPort(service.serverPort),
    devices: parseJsonArray(service.devicesJson, "设备列表")
  })
};

export function buildService(source) {
  const service = normalizeService(source);
  const extra = parseJsonObject(service.advancedJson, "附加服务参数");
  const built = compact({ type: service.type, tag: String(service.tag || "").trim(), ...BUILDERS[service.type](service) });
  return mergeDeep(extra, built);
}

function validateDuration(value, label) {
  return value && !DURATION_PATTERN.test(String(value).trim()) ? `${label}不是有效的 Go Duration，例如 300ms、10s 或 5m` : "";
}

export function validateService(source, { services = [], outboundTags = [] } = {}) {
  const service = normalizeService(source);
  const meta = SERVICE_TYPE_META[service.type];
  const tag = String(service.tag || "").trim();
  if (!tag) return "请填写服务标签";
  if (services.some((item) => item.id !== service.id && String(item.tag || "").trim() === tag)) return "服务标签必须唯一";

  let extra;
  try {
    extra = parseJsonObject(service.advancedJson, "附加服务参数");
  } catch (error) {
    return error.message;
  }
  const forbidden = hasForbiddenKeys(extra, FORBIDDEN_KEYS);
  if (forbidden) return `附加参数包含已弃用或已移除的字段：${forbidden}`;
  const unknown = Object.keys(extra).find((key) => !EXTRA_KEYS[service.type].has(key));
  if (unknown) return `附加参数不是 ${meta.label} 1.14 字段：${unknown}`;

  if (meta.listen) {
    const listenError = validateListenFields(service, outboundTags);
    if (listenError) return listenError;
    if (!optionalPort(service.listenPort)) return "请填写有效的监听端口";
  }
  if (meta.tls && service.tlsEnabled) {
    if (!service.tlsCertificate && !service.tlsCertificatePath) return "启用 TLS 后需要证书内容或证书路径";
    if (!service.tlsKey && !service.tlsKeyPath) return "启用 TLS 后需要私钥内容或私钥路径";
  }
  if (service.type === "api") {
    if (service.dashboardEnabled && !String(service.dashboardPath || "").trim() && !String(service.dashboardDownloadUrl || "").trim()) {
      return "启用面板后需要填写本地路径或下载地址";
    }
    const durationError = validateDuration(service.dashboardUpdateInterval, "面板更新周期");
    if (durationError) return durationError;
    if (service.listen && !["127.0.0.1", "::1", "localhost"].includes(String(service.listen).trim()) && !service.secret) {
      return "监听在非本机地址时必须设置 secret";
    }
  }
  if (service.type === "ssm-api") {
    let servers;
    try {
      servers = parseJsonObject(service.serversJson, "SSM 服务器映射");
    } catch (error) {
      return error.message;
    }
    if (!Object.keys(servers).length) return "SSM API 需要至少一个服务器映射";
  }
  if (["ccm", "ocm"].includes(service.type)) {
    let users;
    try {
      users = parseJsonArray(service.usersJson, "用户列表");
    } catch (error) {
      return error.message;
    }
    if (users.some((user) => !user?.token)) return "每个用户都需要 token";
    if (service.detour && outboundTags.length && !outboundTags.includes(String(service.detour).trim())) {
      return `detour 出站不存在：${service.detour}`;
    }
  }
  if (service.type === "hysteria-realm") {
    let users;
    try {
      users = parseJsonArray(service.usersJson, "Realm 用户");
    } catch (error) {
      return error.message;
    }
    if (!users.length) return "Hysteria Realm 需要至少一个用户";
    if (users.some((user) => !user?.name || !user?.token)) return "Realm 用户需要 name 与 token";
    if (!service.tlsEnabled) return "Hysteria Realm 必须启用 TLS";
  }
  if (service.type === "usbip-client") {
    if (!String(service.server || "").trim()) return "请填写 USB/IP 服务器地址";
    if (!optionalPort(service.serverPort)) return "USB/IP 端口必须在 1–65535 之间";
  }
  if (["usbip-server", "usbip-client"].includes(service.type)) {
    try {
      parseJsonArray(service.devicesJson, "设备列表");
    } catch (error) {
      return error.message;
    }
  }
  return "";
}

export const BASE_DEFAULTS_STATE = Object.freeze({
  ntpEnabled: false,
  ntpServer: "time.apple.com",
  ntpServerPort: "123",
  ntpInterval: "",
  ntpWriteToSystem: false,
  ntpDetour: "",
  certificateStore: "",
  certificatePath: "",
  certificateDirectoryPath: "",
  cacheEnabled: true,
  cachePath: "",
  cacheId: "",
  cacheStoreFakeip: false,
  cacheStoreDns: false,
  cacheRdrcTimeout: "",
  clashEnabled: true,
  clashController: "127.0.0.1:9090",
  clashSecret: "",
  clashDefaultMode: "Rule",
  clashExternalUi: "",
  clashExternalUiDownloadUrl: "",
  clashAllowOrigin: "",
  clashAllowPrivateNetwork: false,
  v2rayEnabled: false,
  v2rayListen: "127.0.0.1:8080",
  v2rayStats: false,
  v2rayStatsInbounds: "",
  v2rayStatsOutbounds: "",
  v2rayStatsUsers: "",
  services: []
});

export function normalizeServiceState(state = {}) {
  return {
    ...BASE_DEFAULTS_STATE,
    ...state,
    services: (state.services || []).map(normalizeService)
  };
}

export function buildNtp(source) {
  const state = normalizeServiceState(source);
  if (!state.ntpEnabled) return undefined;
  return compact({
    enabled: true,
    server: String(state.ntpServer || "").trim(),
    server_port: optionalPort(state.ntpServerPort),
    interval: String(state.ntpInterval || "").trim(),
    write_to_system: state.ntpWriteToSystem || undefined,
    detour: String(state.ntpDetour || "").trim()
  });
}

export function buildCertificate(source) {
  const state = normalizeServiceState(source);
  return compact({
    store: state.certificateStore || undefined,
    certificate_path: splitLines(state.certificatePath),
    certificate_directory_path: splitLines(state.certificateDirectoryPath)
  });
}

export function buildExperimental(source, { clashApiEnabled = true } = {}) {
  const state = normalizeServiceState(source);
  const clash = clashApiEnabled && state.clashEnabled
    ? compact({
        external_controller: String(state.clashController || "").trim(),
        external_ui: String(state.clashExternalUi || "").trim(),
        external_ui_download_url: String(state.clashExternalUiDownloadUrl || "").trim(),
        secret: state.clashSecret || undefined,
        default_mode: state.clashDefaultMode || undefined,
        access_control_allow_origin: splitList(state.clashAllowOrigin),
        access_control_allow_private_network: state.clashAllowPrivateNetwork || undefined
      })
    : undefined;
  const cache = state.cacheEnabled
    ? compact({
        enabled: true,
        path: String(state.cachePath || "").trim(),
        cache_id: String(state.cacheId || "").trim(),
        store_fakeip: state.cacheStoreFakeip || undefined,
        store_dns: state.cacheStoreDns || undefined,
        rdrc_timeout: String(state.cacheRdrcTimeout || "").trim()
      })
    : undefined;
  const v2ray = state.v2rayEnabled
    ? compact({
        listen: String(state.v2rayListen || "").trim(),
        stats: state.v2rayStats
          ? compact({
              enabled: true,
              inbounds: splitList(state.v2rayStatsInbounds),
              outbounds: splitList(state.v2rayStatsOutbounds),
              users: splitList(state.v2rayStatsUsers)
            })
          : undefined
      })
    : undefined;
  return compact({ cache_file: cache, clash_api: clash, v2ray_api: v2ray });
}

export function validateServiceState(source, context = {}) {
  const state = normalizeServiceState(source);
  if (state.ntpEnabled) {
    if (!String(state.ntpServer || "").trim()) return "启用 NTP 后需要填写服务器";
    if (state.ntpServerPort && !optionalPort(state.ntpServerPort)) return "NTP 端口无效";
    const durationError = validateDuration(state.ntpInterval, "NTP 同步周期");
    if (durationError) return durationError;
    if (state.ntpDetour && context.outboundTags?.length && !context.outboundTags.includes(String(state.ntpDetour).trim())) {
      return `NTP detour 出站不存在：${state.ntpDetour}`;
    }
  }
  if (state.certificateStore && !["system", "mozilla", "chrome", "none"].includes(state.certificateStore)) return "证书存储无效";
  if (state.cacheEnabled) {
    const durationError = validateDuration(state.cacheRdrcTimeout, "RDRC 超时");
    if (durationError) return durationError;
  }
  if (state.clashEnabled) {
    if (!/^\S+:\d+$/.test(String(state.clashController || "").trim())) return "Clash API 控制地址必须是 地址:端口";
    const [host] = String(state.clashController).split(":");
    if (!["127.0.0.1", "::1", "localhost"].includes(host) && !state.clashSecret) {
      return "Clash API 监听在非本机地址时必须设置 secret";
    }
    if (state.clashDefaultMode && !["Rule", "Global", "Direct"].includes(state.clashDefaultMode)) return "Clash 默认模式无效";
  }
  if (state.v2rayEnabled && !/^\S+:\d+$/.test(String(state.v2rayListen || "").trim())) return "V2Ray API 监听地址必须是 地址:端口";
  const services = state.services.filter((service) => service.enabled !== false);
  for (const service of services) {
    const error = validateService(service, { ...context, services: state.services });
    if (error) return `服务「${service.tag || "未命名"}」：${error}`;
  }
  return "";
}

export const serviceModule = {
  key: "services",
  extendConfig(config, state, context = {}) {
    const services = normalizeServiceState(state.serviceState);
    const ntp = buildNtp(services);
    if (ntp) config.ntp = ntp;
    const certificate = buildCertificate(services);
    if (certificate) config.certificate = certificate;
    const experimental = buildExperimental(services, { clashApiEnabled: context.clashApiEnabled !== false });
    if (experimental) config.experimental = experimental;
    const list = services.services.filter((service) => service.enabled !== false).map(buildService);
    if (list.length) config.services = list;
    return config;
  }
};
