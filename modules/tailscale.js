import {
  DIAL_DEFAULTS,
  DURATION_PATTERN,
  buildDialFields,
  optionalPort,
  optionalPositiveInteger,
  splitList,
  validateDialFields
} from "./shared.js";

export const TAILSCALE_DEFAULTS = Object.freeze({
  type: "tailscale",
  tag: "tailscale",
  stateDirectory: "tailscale",
  authKey: "",
  controlUrl: "",
  ephemeral: false,
  hostname: "",
  acceptRoutes: false,
  exitNode: "",
  exitNodeAllowLanAccess: false,
  advertiseRoutes: "",
  advertiseExitNode: false,
  advertiseTags: "",
  listenPort: "",
  relayServerPort: "",
  relayServerStaticEndpoints: "",
  systemInterface: false,
  systemInterfaceName: "",
  systemInterfaceMtu: "",
  udpTimeout: "",
  sshServer: false,
  sshDisablePty: false,
  sshDisableSftp: false,
  sshDisableForwarding: false,
  taildropDirectory: "",
  magicDns: true,
  acceptDefaultResolvers: false,
  acceptSearchDomain: true,
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
  fallbackDelay: "",
  ...DIAL_DEFAULTS
});

export function normalizeTailscaleEndpoint(endpoint = {}) {
  return { ...TAILSCALE_DEFAULTS, ...endpoint, type: "tailscale" };
}

function buildSshServer(endpoint) {
  if (!endpoint.sshServer) return undefined;
  if (!endpoint.sshDisablePty && !endpoint.sshDisableSftp && !endpoint.sshDisableForwarding) return true;
  return {
    enabled: true,
    ...(endpoint.sshDisablePty ? { disable_pty: true } : {}),
    ...(endpoint.sshDisableSftp ? { disable_sftp: true } : {}),
    ...(endpoint.sshDisableForwarding ? { disable_forwarding: true } : {})
  };
}

export function buildTailscaleEndpoint(source) {
  const endpoint = normalizeTailscaleEndpoint(source);
  return {
    type: "tailscale",
    tag: endpoint.tag.trim(),
    ...(endpoint.stateDirectory && endpoint.stateDirectory !== "tailscale" ? { state_directory: endpoint.stateDirectory.trim() } : {}),
    ...(endpoint.authKey ? { auth_key: endpoint.authKey } : {}),
    ...(endpoint.controlUrl ? { control_url: endpoint.controlUrl.trim() } : {}),
    ...(endpoint.ephemeral ? { ephemeral: true } : {}),
    ...(endpoint.hostname ? { hostname: endpoint.hostname.trim() } : {}),
    ...(endpoint.acceptRoutes ? { accept_routes: true } : {}),
    ...(endpoint.exitNode ? { exit_node: endpoint.exitNode.trim() } : {}),
    ...(endpoint.exitNode && endpoint.exitNodeAllowLanAccess ? { exit_node_allow_lan_access: true } : {}),
    ...(splitList(endpoint.advertiseRoutes).length ? { advertise_routes: splitList(endpoint.advertiseRoutes) } : {}),
    ...(endpoint.advertiseExitNode ? { advertise_exit_node: true } : {}),
    ...(splitList(endpoint.advertiseTags).length ? { advertise_tags: splitList(endpoint.advertiseTags) } : {}),
    ...(optionalPort(endpoint.listenPort) ? { listen_port: optionalPort(endpoint.listenPort) } : {}),
    ...(optionalPort(endpoint.relayServerPort) ? { relay_server_port: optionalPort(endpoint.relayServerPort) } : {}),
    ...(splitList(endpoint.relayServerStaticEndpoints).length ? { relay_server_static_endpoints: splitList(endpoint.relayServerStaticEndpoints) } : {}),
    ...(endpoint.systemInterface ? { system_interface: true } : {}),
    ...(endpoint.systemInterface && endpoint.systemInterfaceName ? { system_interface_name: endpoint.systemInterfaceName.trim() } : {}),
    ...(endpoint.systemInterface && optionalPositiveInteger(endpoint.systemInterfaceMtu) ? { system_interface_mtu: optionalPositiveInteger(endpoint.systemInterfaceMtu) } : {}),
    ...(endpoint.udpTimeout ? { udp_timeout: endpoint.udpTimeout.trim() } : {}),
    ...(buildSshServer(endpoint) !== undefined ? { ssh_server: buildSshServer(endpoint) } : {}),
    ...(endpoint.taildropDirectory ? { taildrop_directory: endpoint.taildropDirectory.trim() } : {}),
    ...buildDialFields(endpoint)
  };
}

export function validateTailscaleEndpoint(source, { endpoints = [], outboundTags = [] } = {}) {
  const endpoint = normalizeTailscaleEndpoint(source);
  if (!endpoint.tag.trim()) return "请填写端点标签";
  const collision = endpoints.some((item) => item.id !== endpoint.id && item.tag?.trim() === endpoint.tag.trim());
  if (collision || outboundTags.includes(endpoint.tag.trim())) return "端点标签必须唯一，且不能与出站标签重复";
  const stateDirectory = endpoint.stateDirectory?.trim() || "tailscale";
  if (endpoints.some((item) => item.id !== endpoint.id && (item.stateDirectory?.trim() || "tailscale") === stateDirectory)) return "多个 Tailscale 端点不能共用同一个状态目录";
  for (const [value, name] of [[endpoint.listenPort, "监听端口"], [endpoint.relayServerPort, "中继端口"]]) {
    if (value !== "" && (!Number.isInteger(Number(value)) || Number(value) < 1 || Number(value) > 65535)) return `${name}必须在 1–65535 之间`;
  }
  if (endpoint.systemInterfaceMtu !== "" && (!Number.isInteger(Number(endpoint.systemInterfaceMtu)) || Number(endpoint.systemInterfaceMtu) < 576)) return "系统接口 MTU 必须是大于等于 576 的整数";
  const invalidTag = splitList(endpoint.advertiseTags).find((item) => !item.startsWith("tag:"));
  if (invalidTag) return `发布标签必须以 tag: 开头：${invalidTag}`;
  for (const [value, name] of [[endpoint.udpTimeout, "UDP NAT 超时"]]) {
    if (value && !DURATION_PATTERN.test(value.trim())) return `${name}不是有效的 Go Duration，例如 300ms、10s 或 5m`;
  }
  return validateDialFields(endpoint, outboundTags);
}

export const tailscaleModule = {
  key: "tailscale-endpoints",
  extendConfig(config, state) {
    const endpoints = (state.endpoints || []).filter((item) => item.type === "tailscale");
    if (!endpoints.length) return config;

    config.endpoints = [...(config.endpoints || []), ...endpoints.map(buildTailscaleEndpoint)];
    const magicDnsEndpoints = endpoints.filter((item) => item.magicDns);
    if (magicDnsEndpoints.length) {
      config.dns.servers.push(...magicDnsEndpoints.map((item) => ({
        type: "tailscale",
        tag: `${item.tag.trim()}-dns`,
        endpoint: item.tag.trim(),
        ...(item.acceptDefaultResolvers ? { accept_default_resolvers: true } : {}),
        ...(item.acceptSearchDomain ? { accept_search_domain: true } : {})
      })));
      config.dns.rules.unshift(...magicDnsEndpoints.map((item) => ({
        preferred_by: `${item.tag.trim()}-dns`,
        action: "route",
        server: `${item.tag.trim()}-dns`
      })));
    }
    return config;
  }
};
