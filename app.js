import { ConfigModuleRegistry } from "./modules/registry.js";
import { normalizeTailscaleEndpoint, validateTailscaleEndpoint, tailscaleModule } from "./modules/tailscale.js";
import { ENDPOINT_TYPE_META, endpointFamilyModule, normalizeStandardEndpoint, validateStandardEndpoint } from "./modules/endpoints.js";
import {
  INBOUND_GROUP_LABELS,
  INBOUND_TYPE_META,
  buildInbound,
  hasTunInbound,
  inboundTags as activeInboundTags,
  inboundModule,
  normalizeInbound,
  userSample,
  validateInbound,
  validateInbounds
} from "./modules/inbound.js";
import { detectConflicts, hasBlockingConflicts, summarizeConflicts } from "./modules/conflicts.js";
import { importConfig } from "./modules/importer.js";
import { dedupeNodes, diffNodes, exportShareLinks, filterNodes, renameNodes } from "./modules/sharelink.js";
import {
  SERVICE_TYPE_META,
  normalizeService,
  normalizeServiceState,
  serviceModule,
  validateService,
  validateServiceState
} from "./modules/services.js";
import {
  GROUP_TYPE_META,
  OUTBOUND_GROUP_LABELS,
  OUTBOUND_TYPE_META,
  buildOutbound,
  detectDetourCycles,
  groupMembers,
  normalizeGroup,
  normalizeOutbound,
  outboundIsComplete,
  outboundModule,
  validateGroup,
  validateOutbound
} from "./modules/outbound.js";
import {
  HEADLESS_RULE_DEFAULTS,
  ROUTE_ACTION_META,
  RULE_SET_TYPE_META,
  SNIFFERS,
  normalizeHeadlessRule,
  normalizeRouteRule,
  normalizeRouteState,
  normalizeRuleSet,
  routeModule,
  skippedRouteRules,
  validateHeadlessRule,
  validateRouteRule,
  validateRouteState,
  validateRuleSet
} from "./modules/route.js";
import {
  DNS_RULE_ACTION_META,
  DNS_SERVER_TYPE_META,
  defaultDomainResolverTag,
  dnsModule,
  normalizeDnsRule,
  normalizeDnsServer,
  normalizeDnsState,
  validateDnsRule,
  validateDnsServer,
  validateDnsState
} from "./modules/dns.js";

const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];

const configModules = new ConfigModuleRegistry()
  .register(outboundModule)
  .register(inboundModule)
  .register(dnsModule)
  .register(routeModule)
  .register(tailscaleModule)
  .register(endpointFamilyModule)
  .register(serviceModule);

const STORAGE_KEY = "sing-config-studio:v1";
const defaultState = {
  settings: {
    profileName: "My Sing Profile",
    logLevel: "info"
  },
  serviceState: {
    ntpEnabled: false,
    ntpServer: "time.apple.com",
    ntpServerPort: "123",
    cacheEnabled: true,
    clashEnabled: true,
    clashController: "127.0.0.1:9090",
    clashDefaultMode: "Rule",
    services: []
  },
  groups: [
    {
      id: "group-auto",
      type: "urltest",
      tag: "auto",
      enabled: true,
      includeAllNodes: true,
      url: "https://www.gstatic.com/generate_204",
      interval: "3m",
      tolerance: "50"
    },
    {
      id: "group-proxy",
      type: "selector",
      tag: "proxy",
      enabled: true,
      includeAllNodes: true,
      includeDirect: true,
      members: "auto",
      defaultMember: "auto"
    }
  ],
  inbounds: [
    {
      id: "inbound-tun",
      type: "tun",
      tag: "tun-in",
      enabled: true,
      address: "172.19.0.1/30, fdfe:dcba:9876::1/126",
      autoRoute: true,
      strictRoute: true,
      stack: "mixed"
    }
  ],
  subscriptions: [],
  endpoints: [],
  dns: {
    final: "remote-dns",
    strategy: "prefer_ipv4",
    defaultDomainResolver: "local-dns",
    disableCache: false,
    disableExpire: false,
    cacheCapacity: "",
    optimistic: false,
    optimisticTimeout: "",
    timeout: "",
    reverseMapping: false,
    clientSubnet: "",
    servers: [
      { id: "dns-local", type: "local", tag: "local-dns", enabled: true },
      {
        id: "dns-remote",
        type: "https",
        tag: "remote-dns",
        enabled: true,
        server: "1.1.1.1",
        serverPort: "",
        path: "/dns-query",
        tlsServerName: "cloudflare-dns.com",
        detour: "proxy"
      }
    ],
    rules: [
      { id: "dns-rule-lan", enabled: true, domainSuffix: ".lan, .local", action: "route", server: "local-dns" },
      { id: "dns-rule-clash", enabled: true, clashMode: "Direct", action: "route", server: "local-dns" }
    ]
  },
  route: {
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
    rules: [
      { id: "route-sniff", enabled: true, action: "sniff" },
      { id: "route-hijack-dns", enabled: true, protocol: "dns", action: "hijack-dns" },
      { id: "route-private", enabled: true, ipIsPrivate: true, action: "route", outbound: "direct" },
      { id: "route-clash-direct", enabled: true, clashMode: "Direct", action: "route", outbound: "direct" },
      { id: "route-clash-global", enabled: true, clashMode: "Global", action: "route", outbound: "proxy" }
    ],
    ruleSets: []
  },
  nodes: [
    {
      id: "demo-vless",
      type: "vless",
      tag: "HK · Edge 01",
      server: "hk-edge.example.com",
      port: 443,
      uuid: "17f6f870-6f59-4c91-a4dc-46cfe797c241",
      transport: "tcp",
      tls: true,
      insecure: false,
      sni: "www.microsoft.com",
      fingerprint: "chrome",
      reality: true,
      publicKey: "8niEk2nJcK_RzyhynytRYLxerTUs8vfuZJorj-jbliw",
      shortId: "6ba85179e30d4fc2",
      flow: "xtls-rprx-vision"
    },
    {
      id: "demo-hy2",
      type: "hysteria2",
      tag: "JP · Aurora 02",
      server: "jp-aurora.example.com",
      port: 443,
      password: "REPLACE_WITH_PASSWORD",
      transport: "tcp",
      tls: true,
      insecure: false,
      sni: "jp-aurora.example.com",
      fingerprint: "chrome"
    },
    {
      id: "demo-trojan",
      type: "trojan",
      tag: "US · Transit 03",
      server: "us-transit.example.com",
      port: 443,
      password: "REPLACE_WITH_PASSWORD",
      transport: "ws",
      path: "/gateway",
      host: "us-transit.example.com",
      tls: true,
      insecure: false,
      sni: "us-transit.example.com",
      fingerprint: "chrome"
    }
  ]
};

let state = loadState();
let toastTimer;

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function normalizeEndpointEntry(endpoint = {}) {
  return endpoint.type === "tailscale" ? normalizeTailscaleEndpoint(endpoint) : normalizeStandardEndpoint(endpoint);
}

function migrateDnsState(parsed) {
  if (parsed?.dns?.servers?.length) return normalizeDnsState(parsed.dns);
  const legacy = parsed?.settings || {};
  const dns = clone(defaultState.dns);
  const remote = dns.servers.find((server) => server.tag === "remote-dns");
  if (legacy.dohServer) remote.server = legacy.dohServer;
  if (legacy.dohSni) remote.tlsServerName = legacy.dohSni;
  if (legacy.dnsStrategy) dns.strategy = legacy.dnsStrategy;
  if (legacy.clashApi === false) dns.rules = dns.rules.filter((rule) => !rule.clashMode);
  return normalizeDnsState(dns);
}

function migrateServiceState(parsed) {
  if (parsed?.serviceState) return normalizeServiceState(parsed.serviceState);
  const legacy = parsed?.settings || {};
  return normalizeServiceState({ ...clone(defaultState.serviceState), clashEnabled: legacy.clashApi !== false });
}

function migrateGroups(parsed) {
  if (Array.isArray(parsed?.groups) && parsed.groups.length) return parsed.groups.map(normalizeGroup);
  const legacy = parsed?.settings || {};
  const groups = clone(defaultState.groups);
  if (legacy.testInterval) groups[0].interval = legacy.testInterval;
  if (legacy.autoSelect === false) {
    return [normalizeGroup({ ...groups[1], members: "", defaultMember: "" })];
  }
  return groups.map(normalizeGroup);
}

function migrateInbounds(parsed) {
  if (Array.isArray(parsed?.inbounds) && parsed.inbounds.length) return parsed.inbounds.map(normalizeInbound);
  const legacy = parsed?.settings || {};
  if (legacy.inboundType === "mixed") {
    return [normalizeInbound({
      id: "inbound-mixed",
      type: "mixed",
      tag: "mixed-in",
      listen: "127.0.0.1",
      listenPort: String(legacy.mixedPort || 7890)
    })];
  }
  return [normalizeInbound({
    ...clone(defaultState.inbounds[0]),
    address: `${legacy.tunAddress4 || "172.19.0.1/30"}, fdfe:dcba:9876::1/126`
  })];
}

function migrateRouteState(parsed) {
  if (parsed?.route?.rules?.length) return normalizeRouteState(parsed.route);
  const legacy = parsed?.settings || {};
  const route = clone(defaultState.route);
  if (legacy.privateDirect === false) route.rules = route.rules.filter((rule) => !rule.ipIsPrivate);
  if (legacy.clashApi === false) route.rules = route.rules.filter((rule) => !rule.clashMode);
  return normalizeRouteState(route);
}

function loadState() {
  try {
    const parsed = JSON.parse(localStorage.getItem(STORAGE_KEY));
    if (parsed?.settings && Array.isArray(parsed.nodes)) {
      return {
        settings: { ...defaultState.settings, ...parsed.settings },
        subscriptions: Array.isArray(parsed.subscriptions) ? parsed.subscriptions : [],
        endpoints: Array.isArray(parsed.endpoints) ? parsed.endpoints.map(normalizeEndpointEntry) : [],
        serviceState: migrateServiceState(parsed),
        groups: migrateGroups(parsed),
        inbounds: migrateInbounds(parsed),
        dns: migrateDnsState(parsed),
        route: migrateRouteState(parsed),
        nodes: parsed.nodes.map(normalizeOutbound)
      };
    }
  } catch {}
  return clone(defaultState);
}

function saveState() {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(state));
}

function makeId() {
  return crypto.randomUUID?.() || `node-${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

function cleanObject(value) {
  if (Array.isArray(value)) return value.map(cleanObject);
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(
    Object.entries(value)
      .filter(([, child]) => child !== "" && child !== undefined && child !== null)
      .map(([key, child]) => [key, cleanObject(child)])
  );
}

function nodeIsComplete(node) {
  return outboundIsComplete(node) && node.enabled !== false;
}

function generateConfig() {
  const settings = state.settings;
  const hasProxy = state.nodes.some(nodeIsComplete);
  const baseConfig = {
    $schema: "https://sing-box.sagernet.org/schema.json",
    log: { level: settings.logLevel, timestamp: true },
    dns: { servers: [], rules: [] },
    inbounds: [],
    outbounds: [],
    route: { rules: [] }
  };
  const config = configModules.build(baseConfig, state, {
    hasProxy,
    outboundTags: availableOutboundTags(),
    inboundTags: activeInboundTags(state.inbounds || []),
    tunEnabled: hasTunInbound(state.inbounds || []),
    fallbackFinal: defaultFinalOutbound(),
    defaultDomainResolver: defaultDomainResolverTag(state.dns)
  });
  return cleanObject(config);
}

function detectDeprecated(config) {
  const deprecatedKeys = new Set([
    "inet4_address", "inet6_address", "inet4_route_address", "inet6_route_address",
    "inet4_route_exclude_address", "inet6_route_exclude_address", "geosite", "geoip",
    "source_geoip", "rule_set_ipcidr_match_source", "rule_set_ip_cidr_accept_empty",
    "download_detour", "independent_cache", "store_rdrc", "recv_window_conn", "recv_window",
    "disable_mtu_discovery", "gso", "domain_strategy", "address_resolver", "address_strategy",
    "address_fallback_delay", "rule_set_ip_cidr_accept_empty"
  ]);
  const found = [];
  function walk(value, path = "$") {
    if (Array.isArray(value)) return value.forEach((item, index) => walk(item, `${path}[${index}]`));
    if (!value || typeof value !== "object") return;
    for (const [key, child] of Object.entries(value)) {
      if (deprecatedKeys.has(key)) found.push(`${path}.${key}`);
      walk(child, `${path}.${key}`);
    }
  }
  walk(config);
  return found;
}

function validateConfigText(text) {
  try {
    const config = JSON.parse(text);
    if (!config || typeof config !== "object" || Array.isArray(config)) throw new Error("顶层必须是 JSON 对象");
    if (!Array.isArray(config.inbounds) || !config.inbounds.length) throw new Error("至少需要一个 inbound");
    if (!Array.isArray(config.outbounds) || !config.outbounds.length) throw new Error("至少需要一个 outbound");
    const tags = config.outbounds.map((item) => item.tag).filter(Boolean);
    if (new Set(tags).size !== tags.length) throw new Error("outbound tag 不能重复");
    const endpointTags = Array.isArray(config.endpoints) ? config.endpoints.map((item) => item.tag).filter(Boolean) : [];
    if (new Set(endpointTags).size !== endpointTags.length) throw new Error("endpoint tag 不能重复");
    if (endpointTags.some((tag) => tags.includes(tag))) throw new Error("endpoint tag 不能与 outbound tag 重复");
    const dnsTags = config.dns?.servers?.map((item) => item.tag).filter(Boolean) || [];
    if (new Set(dnsTags).size !== dnsTags.length) throw new Error("DNS server tag 不能重复");
    if (!Array.isArray(config.dns?.servers) || !config.dns.servers.length) throw new Error("至少需要一个 DNS server");
    if (config.dns.final && !dnsTags.includes(config.dns.final)) throw new Error(`dns.final 引用的服务器不存在：${config.dns.final}`);
    if (config.route?.default_domain_resolver && !dnsTags.includes(config.route.default_domain_resolver)) {
      throw new Error(`默认域名解析器不存在：${config.route.default_domain_resolver}`);
    }
    const missingDnsServer = (config.dns.rules || []).find((rule) => rule.server && !dnsTags.includes(rule.server));
    if (missingDnsServer) throw new Error(`DNS 规则引用的服务器不存在：${missingDnsServer.server}`);
    const missingPreferred = (config.dns.rules || []).flatMap((rule) => rule.preferred_by || []).find((tag) => !dnsTags.includes(tag));
    if (missingPreferred) throw new Error(`preferred_by 引用的服务器不存在：${missingPreferred}`);
    const routableTags = [...tags, ...endpointTags];
    const ruleSetTags = (config.route?.rule_set || []).flatMap((item) => (Array.isArray(item.tag) ? item.tag : [item.tag])).filter(Boolean);
    if (new Set(ruleSetTags).size !== ruleSetTags.length) throw new Error("rule-set tag 不能重复");
    if (config.route?.final && !routableTags.includes(config.route.final)) throw new Error(`route.final 引用的出站不存在：${config.route.final}`);
    const missingOutbound = (config.route?.rules || []).find((rule) => rule.outbound && !routableTags.includes(rule.outbound));
    if (missingOutbound) throw new Error(`路由规则引用的出站不存在：${missingOutbound.outbound}`);
    const missingRuleSet = [...(config.route?.rules || []), ...(config.dns.rules || [])]
      .flatMap((rule) => (Array.isArray(rule.rule_set) ? rule.rule_set : rule.rule_set ? [rule.rule_set] : []))
      .find((tag) => !ruleSetTags.includes(tag));
    if (missingRuleSet) throw new Error(`规则引用的规则集不存在：${missingRuleSet}`);
    const missingResolveServer = (config.route?.rules || []).find((rule) => rule.action === "resolve" && rule.server && !dnsTags.includes(rule.server));
    if (missingResolveServer) throw new Error(`resolve 动作引用的 DNS Server 不存在：${missingResolveServer.server}`);
    const deprecated = detectDeprecated(config);
    if (deprecated.length) throw new Error(`发现弃用字段：${deprecated[0]}`);
    return { valid: true, config, deprecated };
  } catch (error) {
    return { valid: false, error: error.message };
  }
}

function syncInputsFromState() {
  const s = state.settings;
  $("#profileName").value = s.profileName;
  $("#logLevel").value = s.logLevel;
  syncDnsInputs();
  syncRouteInputs();
  syncServiceInputs();
}

function readSettings() {
  state.settings = {
    profileName: $("#profileName").value.trim() || "Sing Profile",
    logLevel: $("#logLevel").value
  };
}

function protocolShort(type) {
  return ({
    vless: "VL", vmess: "VM", trojan: "TR", shadowsocks: "SS", hysteria: "HY", hysteria2: "H2", tuic: "TU",
    anytls: "AT", shadowtls: "ST", snell: "SN", naive: "NA", socks: "S5", http: "HT", ssh: "SSH", tor: "TOR",
    direct: "DIR", bridge: "BR"
  })[type] || "PX";
}

function escapeHtml(value) {
  return String(value).replace(/[&<>'"]/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;" })[char]);
}

function subscriptionDisplayUrl(value) {
  try {
    const url = new URL(value);
    return `${url.origin}${url.pathname}`;
  } catch {
    return value;
  }
}

function renderSubscriptions() {
  const container = $("#subscriptionSources");
  const subscriptions = state.subscriptions || [];
  container.classList.toggle("hidden", !subscriptions.length);
  container.innerHTML = subscriptions.map((subscription) => {
    const count = state.nodes.filter((node) => node.subscriptionId === subscription.id).length;
    const updated = subscription.lastUpdated
      ? new Intl.DateTimeFormat("zh-CN", { month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit" }).format(new Date(subscription.lastUpdated))
      : "尚未更新";
    const diff = subscription.lastDiff && (subscription.lastDiff.added || subscription.lastDiff.removed)
      ? ` · 上次 +${subscription.lastDiff.added}/-${subscription.lastDiff.removed}`
      : "";
    const status = subscription.lastError
      ? `<span class="subscription-source-meta is-error">更新失败：${escapeHtml(subscription.lastError)}</span>`
      : `<span class="subscription-source-meta">${count} 个节点 · ${escapeHtml(updated)}${escapeHtml(diff)}</span>`;
    return `<article class="subscription-source${subscription.lastError ? " has-error" : ""}">
      <div class="subscription-source-icon"><svg><use href="#i-link"/></svg></div>
      <div class="subscription-source-copy">
        <strong>${escapeHtml(subscription.name)}</strong>
        <small title="${escapeHtml(subscription.url)}">${escapeHtml(subscriptionDisplayUrl(subscription.url))}</small>
      </div>
      ${status}
      <div class="subscription-source-actions">
        <button class="refresh-subscription" data-subscription-id="${escapeHtml(subscription.id)}" title="刷新订阅" aria-label="刷新 ${escapeHtml(subscription.name)}">↻</button>
        <button class="delete-subscription" data-subscription-id="${escapeHtml(subscription.id)}" title="删除订阅" aria-label="删除 ${escapeHtml(subscription.name)}"><svg><use href="#i-trash"/></svg></button>
      </div>
    </article>`;
  }).join("");
}

function renderNodes() {
  const list = $("#nodeList");
  renderSubscriptions();
  $("#nodeCount").textContent = state.nodes.length;
  const sideCount = $(".main-nav button[data-scroll='nodes'] i");
  if (sideCount) sideCount.textContent = state.nodes.length;
  const readyCount = state.nodes.filter(nodeIsComplete).length;
  const readyText = $("#nodeReadyText");
  if (readyText) readyText.textContent = `${readyCount} 个节点可生成`;
  if (!state.nodes.length) {
    list.innerHTML = `<div class="empty-nodes"><div><svg><use href="#i-activity"/></svg><strong>还没有代理节点</strong><small>添加节点，或批量粘贴分享链接</small></div></div>`;
    return;
  }
  list.innerHTML = state.nodes.map((node) => {
    const meta = OUTBOUND_TYPE_META[node.type] || { label: node.type };
    const issue = validateOutbound(node, { skipReferences: true });
    const secure = node.tls;
    const address = meta.server === false ? meta.label : `${node.server || "待填写"}:${Number(node.port) || "—"}`;
    const detail = issue || `${address} · ${secure ? "TLS" : "PLAIN"}${meta.transport && node.transport && node.transport !== "tcp" ? ` · ${node.transport.toUpperCase()}` : ""}${node.detour ? ` · detour ${node.detour}` : ""}`;
    return `<article class="node-item${issue ? " has-issue" : ""}" data-id="${escapeHtml(node.id)}">
      <div class="protocol-icon" style="${issue ? "color:var(--danger)" : ""}">${protocolShort(node.type)}</div>
      <div class="node-main">
        <div class="node-name"><strong>${escapeHtml(node.tag || "未命名节点")}</strong><span class="type-tag">${escapeHtml(meta.label)}</span></div>
        <div class="node-meta"><span>${escapeHtml(detail)}</span></div>
      </div>
      <div class="node-actions">
        <button class="icon-btn duplicate-node" title="复制节点" data-id="${escapeHtml(node.id)}"><svg><use href="#i-copy"/></svg></button>
        <button class="icon-btn danger delete-node" title="删除节点" data-id="${escapeHtml(node.id)}"><svg><use href="#i-trash"/></svg></button>
        <button class="icon-btn edit-node" title="编辑节点" data-id="${escapeHtml(node.id)}"><svg><use href="#i-chevron"/></svg></button>
      </div>
    </article>`;
  }).join("");
}

function endpointFeatureText(endpoint) {
  if (endpoint.type === "wireguard") {
    let peerCount = 0;
    try { peerCount = JSON.parse(endpoint.peersJson || "[]").length; } catch {}
    return `${endpoint.address || "待填写地址"} · ${peerCount} 个 Peer`;
  }
  if (endpoint.type === "openconnect") return `${endpoint.flavor || "anyconnect"} · ${endpoint.server || "待填写服务器"}`;
  if (endpoint.type === "openvpn-client") return `${(endpoint.network || "udp").toUpperCase()} · ${endpoint.server || "备用服务器组"}`;
  if (endpoint.type === "openvpn-server") return `${endpoint.listen || "0.0.0.0"}:${endpoint.listenPort || "—"} · ${endpoint.address || "待填写地址池"}`;
  const features = [];
  if (endpoint.acceptRoutes) features.push("接受路由");
  if (endpoint.advertiseExitNode) features.push("出口节点");
  if (endpoint.systemInterface) features.push("系统接口");
  if (endpoint.magicDns) features.push("MagicDNS");
  if (endpoint.sshServer) features.push("SSH");
  return features.length ? features.join(" · ") : "基础端点";
}

function renderEndpoints() {
  const endpoints = state.endpoints || [];
  const list = $("#endpointList");
  $("#endpointCount").textContent = endpoints.length;
  $("#endpointReadyText").textContent = `${endpoints.length} 个端点已启用`;
  const sideCount = $(".main-nav button[data-scroll='endpoints'] i");
  if (sideCount) sideCount.textContent = endpoints.length;
  if (!endpoints.length) {
    list.innerHTML = `<div class="empty-endpoints"><div><svg><use href="#i-network"/></svg><strong>还没有端点</strong><small>可添加 WireGuard、Tailscale、OpenConnect 或 OpenVPN</small></div><button class="secondary-button" id="emptyAddEndpoint" type="button">添加端点</button></div>`;
    return;
  }
  list.innerHTML = endpoints.map((endpoint) => {
    const meta = ENDPOINT_TYPE_META[endpoint.type] || { label: endpoint.type || "Endpoint" };
    return `<article class="endpoint-item" data-id="${escapeHtml(endpoint.id)}">
    <div class="endpoint-glyph"><svg><use href="#i-network"/></svg></div>
    <div class="endpoint-main">
      <div><strong>${escapeHtml(endpoint.tag || "未命名端点")}</strong><span>${escapeHtml(meta.label)}</span></div>
      <small>${escapeHtml(endpointFeatureText(endpoint))}</small>
    </div>
    <div class="endpoint-actions">
      <button type="button" class="icon-btn danger delete-endpoint" title="删除端点" data-id="${escapeHtml(endpoint.id)}"><svg><use href="#i-trash"/></svg></button>
      <button type="button" class="icon-btn edit-endpoint" title="编辑端点" data-id="${escapeHtml(endpoint.id)}"><svg><use href="#i-chevron"/></svg></button>
    </div>
  </article>`;
  }).join("");
}

function showGenerationError(message) {
  const status = $(".code-status");
  const bar = $("#validationBar");
  status.classList.add("invalid");
  status.lastChild.textContent = "生成失败";
  bar.classList.add("invalid");
  $("span", bar).textContent = message;
  $("#deprecatedCount").textContent = "—";
}

function renderConfig() {
  readSettings();
  readDnsSettings();
  readRouteSettings();
  readServiceSettings();
  let config;
  try {
    config = generateConfig();
  } catch (error) {
    showGenerationError(error.message);
    updateDnsSummary();
    updateRouteSummary();
    renderConflicts([{ level: "error", scope: "生成", message: error.message }]);
    currentConflicts = [{ level: "error", scope: "生成", message: error.message }];
    saveState();
    return;
  }
  $("#configOutput").value = JSON.stringify(config, null, 2);
  validateOutput();
  $("#summaryNodes").textContent = state.nodes.filter(nodeIsComplete).length;
  $("#summaryEndpoints").textContent = state.endpoints.length;
  $("#summaryInbounds").textContent = (config.inbounds || []).length;
  $("#summaryRules").textContent = config.route.rules.length + config.dns.rules.length;
  $("#deprecatedCount").textContent = detectDeprecated(config).length;
  updateDnsSummary();
  updateRouteSummary();
  syncRouteOutboundOptions();
  syncServiceInputs();
  refreshConflicts(config);
  saveState();
}

function validateOutput() {
  const result = validateConfigText($("#configOutput").value);
  const status = $(".code-status");
  const bar = $("#validationBar");
  status.classList.toggle("invalid", !result.valid);
  status.lastChild.textContent = result.valid ? "JSON 有效" : "JSON 无效";
  bar.classList.toggle("invalid", !result.valid);
  $("span", bar).textContent = result.valid ? "结构检查通过" : result.error;
  $("#deprecatedCount").textContent = result.valid ? result.deprecated.length : "—";
  return result;
}

function showToast(message, error = false) {
  clearTimeout(toastTimer);
  const toast = $("#toast");
  $("span", toast).textContent = message;
  toast.classList.toggle("error", error);
  toast.classList.add("show");
  toastTimer = setTimeout(() => toast.classList.remove("show"), 2200);
}

async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    const input = document.createElement("textarea");
    input.value = text;
    input.style.position = "fixed";
    input.style.opacity = "0";
    document.body.append(input);
    input.select();
    document.execCommand("copy");
    input.remove();
  }
  showToast("已复制到剪贴板");
}

function downloadText(text, filename) {
  const blob = new Blob([text], { type: "application/json;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function safeFilename(name) {
  return (name || "sing-box-profile").replace(/[^\p{L}\p{N}._-]+/gu, "-").replace(/^-+|-+$/g, "").slice(0, 80) || "sing-box-profile";
}

const selectOptions = {
  udpMode: [["", "使用内核默认值"], ["endpoint_independent", "Endpoint Independent"], ["address_dependent", "Address Dependent"], ["address_and_port_dependent", "Address + Port Dependent"]],
  udpFragment: [["", "使用内核默认值"], ["true", "启用"], ["false", "显式关闭"]],
  networkStrategy: [["", "系统默认"], ["default", "Default"], ["hybrid", "Hybrid"], ["fallback", "Fallback"]],
  transport: [["udp", "UDP"], ["tcp", "TCP"]]
};

const udpNatGroup = {
  key: "udpNat",
  title: "UDP NAT",
  badge: "1.14",
  fields: [
    { key: "udpTimeout", label: "UDP NAT 超时", placeholder: "默认 5m" },
    { key: "udpNatMax", label: "最大 UDP 会话数", type: "number", placeholder: "由内核按内存决定", min: 0 },
    { key: "udpMapping", label: "UDP 映射行为", type: "select", options: selectOptions.udpMode },
    { key: "udpFiltering", label: "UDP 过滤行为", type: "select", options: selectOptions.udpMode }
  ]
};

const dialGroup = {
  key: "dial",
  title: "高级拨号字段",
  details: true,
  note: "不提供已在 1.14 移除的 domain_strategy。设置 detour 后，请勿同时设置绑定接口或网络策略。",
  fields: [
    { key: "detour", label: "上游出站 detour", placeholder: "例如 direct" },
    { key: "netns", label: "网络命名空间", placeholder: "名称、路径或 namespace 标签", badge: "1.14" },
    { key: "bindInterface", label: "绑定接口", placeholder: "例如 en0" },
    { key: "routingMark", label: "路由标记", placeholder: "1234 或 0x1234" },
    { key: "inet4BindAddress", label: "IPv4 绑定地址", placeholder: "192.0.2.10" },
    { key: "inet6BindAddress", label: "IPv6 绑定地址", placeholder: "2001:db8::10" },
    { key: "connectTimeout", label: "连接超时", placeholder: "例如 10s" },
    { key: "tcpKeepAlive", label: "TCP Keep Alive", placeholder: "默认 5m" },
    { key: "tcpKeepAliveInterval", label: "Keep Alive 间隔", placeholder: "默认 75s" },
    { key: "udpFragment", label: "UDP 分片", type: "select", options: selectOptions.udpFragment },
    { key: "domainResolver", label: "域名解析器", placeholder: "route.default_domain_resolver" },
    { key: "networkStrategy", label: "网络策略", type: "select", options: selectOptions.networkStrategy },
    { key: "networkType", label: "首选网络类型", placeholder: "wifi, cellular" },
    { key: "fallbackNetworkType", label: "回退网络类型", placeholder: "ethernet, other" },
    { key: "fallbackDelay", label: "回退延迟", placeholder: "默认 300ms" }
  ],
  switches: [
    { key: "bindAddressNoPort", label: "绑定地址不占用端口", note: "Linux · bind_address_no_port" },
    { key: "reuseAddr", label: "复用监听地址", note: "reuse_addr" },
    { key: "tcpFastOpen", label: "TCP Fast Open", note: "tcp_fast_open" },
    { key: "tcpMultiPath", label: "TCP Multi Path", note: "tcp_multi_path" },
    { key: "disableTcpKeepAlive", label: "禁用 TCP Keep Alive", note: "disable_tcp_keep_alive" }
  ]
};

const listenGroup = {
  key: "listen",
  title: "高级监听字段",
  details: true,
  note: "不提供已弃用的 sniff、sniff_override_destination、sniff_timeout、domain_strategy 与 udp_disable_domain_unmapping。",
  fields: [
    { key: "bindInterface", label: "绑定接口", placeholder: "例如 eth0" },
    { key: "routingMark", label: "路由标记", placeholder: "1234 或 0x1234" },
    { key: "netns", label: "网络命名空间", placeholder: "名称、路径或 namespace 标签", badge: "1.14" },
    { key: "tcpKeepAlive", label: "TCP Keep Alive", placeholder: "默认 5m" },
    { key: "tcpKeepAliveInterval", label: "Keep Alive 间隔", placeholder: "默认 75s" },
    { key: "udpFragment", label: "UDP 分片", type: "select", options: selectOptions.udpFragment },
    { key: "detour", label: "监听 detour", placeholder: "例如 direct" }
  ],
  switches: [
    { key: "reuseAddr", label: "复用监听地址", note: "reuse_addr" },
    { key: "tcpFastOpen", label: "TCP Fast Open", note: "tcp_fast_open" },
    { key: "tcpMultiPath", label: "TCP Multi Path", note: "tcp_multi_path" },
    { key: "disableTcpKeepAlive", label: "禁用 TCP Keep Alive", note: "disable_tcp_keep_alive" }
  ]
};

const extraGroup = {
  key: "extra",
  title: "完整 1.14 高级参数",
  details: true,
  note: "填写官方字段组成的 JSON 对象。表单字段优先；未知字段、domain_strategy 与 OpenVPN static_key 会被拒绝。",
  fields: [{ key: "advancedJson", label: "附加参数 JSON", type: "textarea", rows: 7, full: true, className: "json-field", placeholder: "{}" }]
};

const endpointEditorSchemas = {
  wireguard: {
    title: "WireGuard 端点",
    intro: "生成 1.14 顶层 WireGuard Endpoint；不会生成旧的 WireGuard outbound。",
    groups: [
      { title: "基础", fields: [
        { key: "tag", label: "端点标签", required: true, placeholder: "wireguard" },
        { key: "name", label: "接口名称", placeholder: "系统接口启用时可设置" },
        { key: "address", label: "接口地址", required: true, full: true, placeholder: "10.0.0.2/32, fd00::2/128" },
        { key: "privateKey", label: "私钥", type: "password", required: true, full: true, placeholder: "Base64 编码 WireGuard 私钥" },
        { key: "mtu", label: "MTU", type: "number", min: 576, placeholder: "1408" },
        { key: "listenPort", label: "监听端口", type: "number", min: 1, max: 65535, placeholder: "自动" },
        { key: "workers", label: "Worker 数量", type: "number", min: 1, placeholder: "CPU 数量" }
      ], switches: [{ key: "system", label: "使用系统接口", note: "需要系统权限，接口名不能冲突" }] },
      { title: "Peers", fields: [{ key: "peersJson", label: "Peer 数组", type: "textarea", rows: 10, full: true, className: "json-field", required: true, placeholder: "[{\"address\":\"vpn.example.com\",\"port\":51820,\"public_key\":\"...\",\"allowed_ips\":[\"0.0.0.0/0\"]}]" }] },
      udpNatGroup,
      dialGroup,
      extraGroup
    ]
  },
  openconnect: {
    title: "OpenConnect Client",
    intro: "适用于 AnyConnect、GlobalProtect、Fortinet、F5、Pulse 与 Network Connect，首次加入 sing-box 1.14。",
    groups: [
      { title: "连接与认证", fields: [
        { key: "tag", label: "端点标签", required: true, placeholder: "openconnect" },
        { key: "server", label: "服务器 HTTPS URL", required: true, placeholder: "vpn.example.com" },
        { key: "flavor", label: "协议风格", type: "select", options: [["anyconnect", "AnyConnect"], ["gp", "GlobalProtect"], ["fortinet", "Fortinet"], ["f5", "F5"], ["pulse", "Pulse"], ["nc", "Network Connect"]] },
        { key: "authGroup", label: "认证组 / Realm", placeholder: "可选" },
        { key: "username", label: "用户名", placeholder: "可交互认证" },
        { key: "password", label: "密码", type: "password", placeholder: "可交互认证" },
        { key: "cookie", label: "已有会话 Cookie", type: "password", full: true, placeholder: "可直接复用已认证会话" }
      ] },
      { title: "令牌 / MFA", fields: [
        { key: "tokenMode", label: "令牌类型", type: "select", options: [["", "不自动提供"], ["totp", "TOTP"], ["hotp", "HOTP"], ["stoken", "RSA SecurID"], ["oidc", "OIDC Bearer Token"]] },
        { key: "tokenCounter", label: "HOTP 初始计数", type: "number", min: 0, placeholder: "0" },
        { key: "tokenSecret", label: "令牌 Secret", type: "password", placeholder: "与 Secret Path 二选一" },
        { key: "tokenSecretPath", label: "令牌 Secret Path", placeholder: "/path/to/token" },
        { key: "tokenPin", label: "SecurID PIN", type: "password" },
        { key: "tokenPassword", label: "令牌解密密码", type: "password" },
        { key: "tokenDeviceId", label: "设备 ID", placeholder: "设备绑定令牌" }
      ] },
      { title: "TLS", fields: [
        { key: "tlsServerName", label: "Server Name", placeholder: "vpn.example.com" },
        { key: "tlsPeerFingerprint", label: "服务端证书指纹", placeholder: "SHA-256，可多个" },
        { key: "tlsCertificateAuthorityPath", label: "CA 证书路径", placeholder: "/path/to/ca.pem" },
        { key: "tlsCertificateAuthority", label: "CA 证书内容", type: "textarea", rows: 4, full: true, className: "certificate-field", placeholder: "-----BEGIN CERTIFICATE-----" },
        { key: "tlsClientCertificatePath", label: "客户端证书路径", placeholder: "/path/to/client.pem" },
        { key: "tlsClientKeyPath", label: "客户端私钥路径", placeholder: "/path/to/client.key" },
        { key: "tlsClientCertificate", label: "客户端证书内容", type: "textarea", rows: 4, full: true, className: "certificate-field" },
        { key: "tlsClientKey", label: "客户端私钥内容", type: "textarea", rows: 4, full: true, className: "certificate-field" },
        { key: "tlsClientKeyPassword", label: "客户端私钥密码", type: "password" }
      ], switches: [
        { key: "tlsInsecure", label: "跳过 TLS 证书验证", note: "仅用于受控测试环境" },
        { key: "tlsSystemTrustDisabled", label: "禁用系统信任库", note: "只使用显式配置的 CA" }
      ] },
      { title: "设备与隧道", fields: [
        { key: "name", label: "系统接口名称", placeholder: "自动生成 oc 接口名" },
        { key: "reportedOs", label: "上报操作系统", placeholder: "linux-64 / win / mac-intel" },
        { key: "userAgent", label: "User Agent", placeholder: "使用 flavor 默认值" },
        { key: "localHostname", label: "本机名称", placeholder: "使用系统主机名" },
        { key: "mtu", label: "MTU", type: "number", min: 576, placeholder: "服务器协商" },
        { key: "baseMtu", label: "Base MTU", type: "number", min: 576, placeholder: "自动" }
      ], switches: [
        { key: "system", label: "使用系统接口", note: "否则使用 sing-box 内部网络栈" },
        { key: "noUdp", label: "禁用 DTLS / UDP", note: "仅使用 TLS 隧道" },
        { key: "ipv6Disabled", label: "禁用 IPv6", note: "不请求 IPv6 地址" },
        { key: "pfs", label: "要求前向保密", note: "pfs" }
      ] },
      udpNatGroup,
      dialGroup,
      extraGroup
    ]
  },
  "openvpn-client": {
    title: "OpenVPN Client",
    intro: "仅生成推荐的 TLS 模式；已弃用、无前向保密的 static_key 模式不会提供。",
    groups: [
      { title: "服务器", fields: [
        { key: "tag", label: "端点标签", required: true, placeholder: "openvpn-client" },
        { key: "network", label: "默认传输", type: "select", options: selectOptions.transport },
        { key: "server", label: "主服务器", placeholder: "vpn.example.com" },
        { key: "serverPort", label: "服务器端口", type: "number", min: 1, max: 65535, placeholder: "1194" },
        { key: "serversJson", label: "备用服务器数组", type: "textarea", rows: 5, full: true, className: "json-field", placeholder: "[{\"server\":\"vpn-a.example.com\",\"server_port\":1194,\"network\":\"udp\"}]" }
      ], switches: [{ key: "remoteRandom", label: "随机备用服务器顺序", note: "仅 servers 数组生效" }] },
      { title: "隧道与认证", fields: [
        { key: "address", label: "本地隧道地址", placeholder: "通常由服务器下发" },
        { key: "topology", label: "拓扑", type: "select", options: [["", "由服务器下发"], ["subnet", "Subnet"], ["p2p", "P2P"], ["net30", "Net30"]] },
        { key: "username", label: "用户名", placeholder: "可选" },
        { key: "password", label: "密码", type: "password", placeholder: "可选" },
        { key: "authRetry", label: "认证失败行为", type: "select", options: [["none", "停止"], ["nointeract", "非交互重试"], ["interact", "交互重试"]] },
        { key: "name", label: "系统接口名称", placeholder: "自动生成 ovpn 接口名" },
        { key: "mtu", label: "MTU", type: "number", min: 576, placeholder: "1500" }
      ], switches: [{ key: "system", label: "使用系统接口", note: "否则使用 sing-box 内部网络栈" }] },
      { title: "TLS", fields: [
        { key: "tlsServerName", label: "服务端证书名称", placeholder: "vpn.example.com" },
        { key: "tlsServerNameType", label: "名称匹配方式", type: "select", options: [["name", "Common Name"], ["name-prefix", "Common Name Prefix"], ["subject", "完整 Subject"]] },
        { key: "tlsPeerFingerprint", label: "服务端证书指纹", placeholder: "64 位小写 SHA-256，可多个" },
        { key: "tlsCertificatePath", label: "CA 证书路径", placeholder: "/path/to/ca.pem" },
        { key: "tlsCertificate", label: "CA 证书内容", type: "textarea", rows: 4, full: true, className: "certificate-field", placeholder: "-----BEGIN CERTIFICATE-----" },
        { key: "tlsClientCertificatePath", label: "客户端证书路径", placeholder: "/path/to/client.pem" },
        { key: "tlsClientKeyPath", label: "客户端私钥路径", placeholder: "/path/to/client.key" },
        { key: "tlsClientCertificate", label: "客户端证书内容", type: "textarea", rows: 4, full: true, className: "certificate-field" },
        { key: "tlsClientKey", label: "客户端私钥内容", type: "textarea", rows: 4, full: true, className: "certificate-field" }
      ] },
      { title: "加密与路由", fields: [
        { key: "dataCiphers", label: "Data Ciphers", placeholder: "AES-256-GCM, CHACHA20-POLY1305" },
        { key: "dataCiphersFallback", label: "Cipher Fallback", placeholder: "旧服务端兼容项" },
        { key: "cipher", label: "Cipher", placeholder: "控制通道或兼容密码" },
        { key: "auth", label: "Auth Digest", placeholder: "例如 SHA256" },
        { key: "routes", label: "静态路由", full: true, placeholder: "10.0.0.0/8, 192.168.0.0/16" },
        { key: "redirectGatewayFlags", label: "Redirect Gateway Flags", full: true, placeholder: "def1, bypass-dhcp" }
      ], switches: [
        { key: "routeNoPull", label: "不拉取服务端路由", note: "route_no_pull" },
        { key: "redirectGateway", label: "将默认路由导向 VPN", note: "redirect_gateway" },
        { key: "redirectPrivate", label: "重定向私有网络", note: "redirect_private" },
        { key: "blockIpv6", label: "阻止 IPv6", note: "block_ipv6" }
      ] },
      udpNatGroup,
      dialGroup,
      extraGroup
    ]
  },
  "openvpn-server": {
    title: "OpenVPN Server",
    intro: "生成 1.14 OpenVPN TLS 服务端。证书可填写内容或运行环境中的文件路径。",
    groups: [
      { title: "监听与地址池", fields: [
        { key: "tag", label: "端点标签", required: true, placeholder: "openvpn-server" },
        { key: "network", label: "传输协议", type: "select", options: selectOptions.transport },
        { key: "listen", label: "监听地址", placeholder: "0.0.0.0" },
        { key: "listenPort", label: "监听端口", type: "number", min: 1, max: 65535, required: true, placeholder: "1194" },
        { key: "address", label: "服务端地址段", required: true, full: true, placeholder: "10.8.0.1/24, fd00:8::1/64" },
        { key: "topology", label: "拓扑", type: "select", options: [["subnet", "Subnet"], ["p2p", "P2P"], ["net30", "Net30"]] },
        { key: "maxClients", label: "最大客户端数", type: "number", min: 1, max: 16777215, placeholder: "1024" },
        { key: "name", label: "系统接口名称", placeholder: "自动生成 ovpn 接口名" },
        { key: "mtu", label: "MTU", type: "number", min: 576, placeholder: "1500" }
      ], switches: [
        { key: "system", label: "使用系统接口", note: "否则使用 sing-box 内部网络栈" },
        { key: "duplicateCn", label: "允许重复身份连接", note: "duplicate_cn" }
      ] },
      { title: "服务端 TLS", fields: [
        { key: "tlsCertificatePath", label: "服务端证书路径", placeholder: "/path/to/server.pem" },
        { key: "tlsKeyPath", label: "服务端私钥路径", placeholder: "/path/to/server.key" },
        { key: "tlsCertificate", label: "服务端证书内容", type: "textarea", rows: 4, full: true, className: "certificate-field", placeholder: "-----BEGIN CERTIFICATE-----" },
        { key: "tlsKey", label: "服务端私钥内容", type: "textarea", rows: 4, full: true, className: "certificate-field", placeholder: "-----BEGIN PRIVATE KEY-----" },
        { key: "tlsVerifyClientCertificate", label: "客户端证书策略", type: "select", options: [["require", "必须验证"], ["optional", "提供时验证"], ["none", "不请求证书"]] },
        { key: "tlsPeerFingerprint", label: "允许的客户端指纹", placeholder: "64 位小写 SHA-256，可多个" },
        { key: "tlsClientCertificatePath", label: "客户端 CA 路径", placeholder: "/path/to/client-ca.pem" },
        { key: "tlsClientCertificate", label: "客户端 CA 内容", type: "textarea", rows: 4, full: true, className: "certificate-field" }
      ] },
      { title: "用户与下发选项", fields: [
        { key: "usersJson", label: "用户名密码数组", type: "textarea", rows: 5, full: true, className: "json-field", placeholder: "[{\"username\":\"alice\",\"password\":\"strong-password\"}]" },
        { key: "pushRoutes", label: "下发路由", placeholder: "10.0.0.0/8, 192.168.0.0/16" },
        { key: "pushDnsServers", label: "下发 DNS 服务器", placeholder: "1.1.1.1, 2606:4700:4700::1111" },
        { key: "pushSearchDomains", label: "下发搜索域", placeholder: "corp.example.com" },
        { key: "pushRedirectGatewayFlags", label: "默认路由 Flags", placeholder: "def1, bypass-dhcp" }
      ], switches: [
        { key: "pushRedirectGateway", label: "下发默认路由", note: "push.redirect_gateway" },
        { key: "pushBlockOutsideDns", label: "阻止 VPN 外部 DNS", note: "push.block_outside_dns" }
      ] },
      udpNatGroup,
      listenGroup,
      extraGroup
    ]
  }
};

function schemaFields(schema) {
  return schema.groups.flatMap((group) => [...(group.fields || []), ...(group.switches || []).map((field) => ({ ...field, type: "checkbox" }))]);
}

function fieldOptions(field, context) {
  return typeof field.options === "function" ? field.options(context) : field.options || [];
}

function renderSchemaField(field, value, context) {
  const badge = field.badge ? ` <em>${escapeHtml(field.badge)}</em>` : "";
  const required = field.required ? " required" : "";
  const bounds = `${field.min !== undefined ? ` min="${field.min}"` : ""}${field.max !== undefined ? ` max="${field.max}"` : ""}`;
  const classes = ["field", field.full ? "full" : "", field.className || ""].filter(Boolean).join(" ");
  const wrap = `class="${classes}" data-field-key="${field.key}"`;
  if (field.type === "textarea") return `<label ${wrap}><span>${escapeHtml(field.label)}${badge}</span><textarea data-field="${field.key}" rows="${field.rows || 4}" placeholder="${escapeHtml(field.placeholder || "")}"${required}>${escapeHtml(value ?? "")}</textarea></label>`;
  if (field.type === "select") {
    const options = fieldOptions(field, context).map(([optionValue, label]) => `<option value="${escapeHtml(optionValue)}"${String(value ?? "") === String(optionValue) ? " selected" : ""}>${escapeHtml(label)}</option>`).join("");
    return `<label ${wrap}><span>${escapeHtml(field.label)}${badge}</span><select data-field="${field.key}"${required}>${options}</select></label>`;
  }
  return `<label ${wrap}><span>${escapeHtml(field.label)}${badge}</span><input data-field="${field.key}" type="${field.type || "text"}" value="${escapeHtml(value ?? "")}" placeholder="${escapeHtml(field.placeholder || "")}" autocomplete="off"${required}${bounds} /></label>`;
}

function renderSchemaSwitch(field, value) {
  return `<label class="setting-row" data-field-key="${field.key}"><div><strong>${escapeHtml(field.label)}</strong><small>${escapeHtml(field.note || field.key)}</small></div><input data-field="${field.key}" type="checkbox"${value ? " checked" : ""} /><span class="switch"></span></label>`;
}

function renderSchemaGroup(group, value, context) {
  const title = `${escapeHtml(group.title)}${group.badge ? ` <span class="new-badge">${escapeHtml(group.badge)}</span>` : ""}`;
  const body = `${group.fields?.length ? `<div class="form-grid two modal-fields compact-section">${group.fields.map((field) => renderSchemaField(field, value[field.key], context)).join("")}</div>` : ""}${group.switches?.length ? `<div class="settings-list modal-switches dynamic-switches">${group.switches.map((field) => renderSchemaSwitch(field, value[field.key])).join("")}</div>` : ""}${group.note ? `<p class="dynamic-field-note">${escapeHtml(group.note)}</p>` : ""}`;
  const inner = group.details
    ? `<details class="advanced-fields"><summary><span><strong>${title}</strong><small>按需展开</small></span><svg><use href="#i-chevron"/></svg></summary><div class="advanced-body">${body}</div></details>`
    : group.plain
      ? body
      : `<div class="modal-section${group.title === "基础" ? " section-first" : ""}">${title}</div>${body}`;
  return `<div class="schema-group" data-group="${escapeHtml(group.key || group.title)}">${inner}</div>`;
}

function renderSchemaForm(schema, value, context = {}) {
  return schema.groups.map((group) => renderSchemaGroup(group, value, context)).join("");
}

function readSchemaForm(schema, container) {
  const result = {};
  for (const field of schemaFields(schema)) {
    const input = $(`[data-field="${field.key}"]`, container);
    if (!input) continue;
    result[field.key] = field.type === "checkbox" ? input.checked : input.value.trim();
  }
  return result;
}

function nextEndpointTag(type) {
  const prefix = ENDPOINT_TYPE_META[type]?.prefix || "endpoint";
  const used = new Set((state.endpoints || []).map((item) => item.tag));
  let tag = prefix;
  let index = 2;
  while (used.has(tag)) tag = `${prefix}-${index++}`;
  return tag;
}

function openStandardEndpointModal(type, endpoint = null) {
  const schema = endpointEditorSchemas[type];
  if (!schema) return;
  const value = normalizeStandardEndpoint(endpoint || { type, tag: nextEndpointTag(type) });
  $("#standardEndpointForm").reset();
  $("#standardEndpointFormError").textContent = "";
  $("#standardEndpointType").value = type;
  $("#standardEndpointId").value = endpoint?.id || "";
  $("#standardEndpointModalTitle").textContent = `${endpoint ? "编辑" : "添加"} ${schema.title}`;
  $("#standardEndpointIntro").textContent = schema.intro;
  $("#standardEndpointFields").innerHTML = renderSchemaForm(schema, value);
  $("#standardEndpointModal").showModal();
  $('[data-field="tag"]', $("#standardEndpointFields"))?.focus();
}

function readStandardEndpointForm() {
  const type = $("#standardEndpointType").value;
  const schema = endpointEditorSchemas[type];
  const endpoint = { type, id: $("#standardEndpointId").value || makeId(), ...readSchemaForm(schema, $("#standardEndpointFields")) };
  return normalizeStandardEndpoint(endpoint);
}

function openEndpointModal(endpoint) {
  if (endpoint.type === "tailscale") return openTailscaleModal(endpoint);
  return openStandardEndpointModal(endpoint.type, endpoint);
}

const tailscaleTextFields = {
  tag: "#tailscaleTag",
  hostname: "#tailscaleHostname",
  stateDirectory: "#tailscaleStateDirectory",
  controlUrl: "#tailscaleControlUrl",
  authKey: "#tailscaleAuthKey",
  udpTimeout: "#tailscaleUdpTimeout",
  listenPort: "#tailscaleListenPort",
  exitNode: "#tailscaleExitNode",
  advertiseTags: "#tailscaleAdvertiseTags",
  advertiseRoutes: "#tailscaleAdvertiseRoutes",
  systemInterfaceName: "#tailscaleSystemInterfaceName",
  systemInterfaceMtu: "#tailscaleSystemInterfaceMtu",
  relayServerPort: "#tailscaleRelayServerPort",
  relayServerStaticEndpoints: "#tailscaleRelayStaticEndpoints",
  taildropDirectory: "#tailscaleTaildropDirectory",
  detour: "#tailscaleDetour",
  netns: "#tailscaleNetns",
  bindInterface: "#tailscaleBindInterface",
  routingMark: "#tailscaleRoutingMark",
  inet4BindAddress: "#tailscaleInet4BindAddress",
  inet6BindAddress: "#tailscaleInet6BindAddress",
  connectTimeout: "#tailscaleConnectTimeout",
  tcpKeepAlive: "#tailscaleTcpKeepAlive",
  tcpKeepAliveInterval: "#tailscaleTcpKeepAliveInterval",
  udpFragment: "#tailscaleUdpFragment",
  domainResolver: "#tailscaleDomainResolver",
  networkStrategy: "#tailscaleNetworkStrategy",
  networkType: "#tailscaleNetworkType",
  fallbackNetworkType: "#tailscaleFallbackNetworkType",
  fallbackDelay: "#tailscaleFallbackDelay"
};

const tailscaleBooleanFields = {
  ephemeral: "#tailscaleEphemeral",
  acceptRoutes: "#tailscaleAcceptRoutes",
  exitNodeAllowLanAccess: "#tailscaleExitNodeAllowLan",
  advertiseExitNode: "#tailscaleAdvertiseExitNode",
  magicDns: "#tailscaleMagicDns",
  acceptDefaultResolvers: "#tailscaleAcceptDefaultResolvers",
  acceptSearchDomain: "#tailscaleAcceptSearchDomain",
  systemInterface: "#tailscaleSystemInterface",
  sshServer: "#tailscaleSshServer",
  sshDisablePty: "#tailscaleSshDisablePty",
  sshDisableSftp: "#tailscaleSshDisableSftp",
  sshDisableForwarding: "#tailscaleSshDisableForwarding",
  bindAddressNoPort: "#tailscaleBindAddressNoPort",
  reuseAddr: "#tailscaleReuseAddr",
  tcpFastOpen: "#tailscaleTcpFastOpen",
  tcpMultiPath: "#tailscaleTcpMultiPath",
  disableTcpKeepAlive: "#tailscaleDisableTcpKeepAlive"
};

function setDependentRows(selector, enabled) {
  $$(selector).forEach((row) => {
    row.classList.toggle("is-disabled", !enabled);
    $$('input, select', row).forEach((input) => { input.disabled = !enabled; });
  });
}

function updateTailscaleFormVisibility() {
  const hasExitNode = Boolean($("#tailscaleExitNode").value.trim());
  const magicDns = $("#tailscaleMagicDns").checked;
  const systemInterface = $("#tailscaleSystemInterface").checked;
  const sshServer = $("#tailscaleSshServer").checked;
  const fallback = $("#tailscaleNetworkStrategy").value === "fallback";
  const keepAliveDisabled = $("#tailscaleDisableTcpKeepAlive").checked;

  setDependentRows(".dependent-exit", hasExitNode);
  setDependentRows(".magicdns-dependent", magicDns);
  setDependentRows(".ssh-dependent", sshServer);
  $(".system-interface-dependent").classList.toggle("is-disabled", !systemInterface);
  $$('.system-interface-dependent input').forEach((input) => { input.disabled = !systemInterface; });
  $("#tailscaleFallbackNetworkType").disabled = !fallback;
  $("#tailscaleFallbackNetworkType").closest(".field").classList.toggle("is-disabled", !fallback);
  $("#tailscaleTcpKeepAlive").disabled = keepAliveDisabled;
  $("#tailscaleTcpKeepAliveInterval").disabled = keepAliveDisabled;
  $("#tailscaleTcpKeepAlive").closest(".field").classList.toggle("is-disabled", keepAliveDisabled);
  $("#tailscaleTcpKeepAliveInterval").closest(".field").classList.toggle("is-disabled", keepAliveDisabled);
}

function nextTailscaleTag() {
  const used = new Set((state.endpoints || []).map((item) => item.tag));
  let tag = "tailscale";
  let index = 2;
  while (used.has(tag)) tag = `tailscale-${index++}`;
  return tag;
}

function openTailscaleModal(endpoint = null) {
  $("#tailscaleForm").reset();
  $("#tailscaleFormError").textContent = "";
  $("#tailscaleForm details").open = false;
  const value = normalizeTailscaleEndpoint(endpoint || { tag: nextTailscaleTag() });
  $("#editEndpointId").value = endpoint?.id || "";
  $("#tailscaleModalTitle").textContent = endpoint ? "编辑 Tailscale 端点" : "添加 Tailscale 端点";
  for (const [key, selector] of Object.entries(tailscaleTextFields)) $(selector).value = value[key] ?? "";
  for (const [key, selector] of Object.entries(tailscaleBooleanFields)) $(selector).checked = Boolean(value[key]);
  updateTailscaleFormVisibility();
  $("#tailscaleModal").showModal();
  $("#tailscaleTag").focus();
}

function readTailscaleForm() {
  const endpoint = { type: "tailscale", id: $("#editEndpointId").value || makeId() };
  for (const [key, selector] of Object.entries(tailscaleTextFields)) endpoint[key] = $(selector).value.trim();
  for (const [key, selector] of Object.entries(tailscaleBooleanFields)) endpoint[key] = $(selector).checked;
  return normalizeTailscaleEndpoint(endpoint);
}

function validateEndpoint(endpoint) {
  const outboundTags = ["proxy", "auto", "direct", ...state.nodes.filter(nodeIsComplete).map((node) => node.tag.trim())];
  const error = endpoint.type === "tailscale"
    ? validateTailscaleEndpoint(endpoint, { endpoints: state.endpoints || [], outboundTags })
    : validateStandardEndpoint(endpoint, { endpoints: state.endpoints || [], outboundTags });
  if (error) return error;
  if (endpoint.type !== "tailscale") return "";
  const dnsTag = `${endpoint.tag.trim()}-dns`;
  const otherDnsTags = (state.endpoints || []).filter((item) => item.id !== endpoint.id && item.magicDns).map((item) => `${item.tag.trim()}-dns`);
  const configuredDnsTags = (state.dns?.servers || []).map((server) => String(server.tag || "").trim());
  if (endpoint.magicDns && [...configuredDnsTags, ...otherDnsTags].includes(dnsTag)) return "该端点生成的 MagicDNS 标签与现有 DNS Server 标签重复";
  return "";
}

function decodeBase64(value) {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/").replace(/\s/g, "");
  const padded = normalized + "=".repeat((4 - normalized.length % 4) % 4);
  const bytes = Uint8Array.from(atob(padded), (char) => char.charCodeAt(0));
  return new TextDecoder().decode(bytes);
}

function nameFromHash(hash, fallback) {
  try { return decodeURIComponent((hash || "").replace(/^#/, "")) || fallback; } catch { return fallback; }
}

function parseTransport(params) {
  return {
    transport: params.get("type") || "tcp",
    path: params.get("serviceName") || params.get("path") || "",
    host: params.get("host") || ""
  };
}

function parseStandardUrl(line, type) {
  const url = new URL(line);
  const params = url.searchParams;
  const security = params.get("security");
  const tlsRequired = ["hysteria2", "tuic", "anytls"].includes(type);
  const credentials = {};
  if (["vless", "vmess"].includes(type)) credentials.uuid = decodeURIComponent(url.username);
  else if (type === "tuic") {
    credentials.uuid = decodeURIComponent(url.username);
    credentials.password = decodeURIComponent(url.password);
  } else credentials.password = decodeURIComponent(url.username || url.password);
  return {
    id: makeId(), type, tag: nameFromHash(url.hash, `${type.toUpperCase()} · Imported`),
    server: url.hostname, port: Number(url.port || 443), ...credentials, ...parseTransport(params),
    tls: tlsRequired || security === "tls" || security === "reality" || params.get("tls") === "1",
    insecure: params.get("allowInsecure") === "1" || params.get("insecure") === "1",
    sni: params.get("sni") || params.get("peer") || url.hostname,
    fingerprint: params.get("fp") || "chrome",
    reality: security === "reality",
    publicKey: params.get("pbk") || params.get("publicKey") || "",
    shortId: params.get("sid") || params.get("shortId") || "",
    flow: params.get("flow") || "",
    obfsType: type === "hysteria2" ? params.get("obfs") || "" : "",
    obfs: type === "hysteria" ? params.get("obfs") || "" : "",
    obfsPassword: params.get("obfs-password") || params.get("obfsPassword") || "",
    congestionControl: params.get("congestion_control") || params.get("congestion-control") || "bbr",
    udpRelayMode: params.get("udp_relay_mode") || params.get("udp-relay-mode") || "native"
  };
}

function parseShadowsocks(line) {
  const raw = line.slice(5);
  const hashIndex = raw.indexOf("#");
  const hash = hashIndex >= 0 ? raw.slice(hashIndex) : "";
  const body = (hashIndex >= 0 ? raw.slice(0, hashIndex) : raw).split("?")[0];
  let userInfo;
  let hostPart;
  if (body.includes("@")) {
    const at = body.lastIndexOf("@");
    userInfo = body.slice(0, at);
    hostPart = body.slice(at + 1);
    if (!userInfo.includes(":")) userInfo = decodeBase64(userInfo);
  } else {
    const decoded = decodeBase64(body);
    const at = decoded.lastIndexOf("@");
    if (at < 0) throw new Error("Shadowsocks 链接缺少服务器地址");
    userInfo = decoded.slice(0, at);
    hostPart = decoded.slice(at + 1);
  }
  const split = userInfo.indexOf(":");
  if (split < 0) throw new Error("Shadowsocks 链接缺少加密方法或密码");
  const hostUrl = new URL(`http://${hostPart}`);
  return {
    id: makeId(), type: "shadowsocks", tag: nameFromHash(hash, "SS · Imported"),
    server: hostUrl.hostname, port: Number(hostUrl.port),
    method: decodeURIComponent(userInfo.slice(0, split)), password: decodeURIComponent(userInfo.slice(split + 1)),
    transport: "tcp", tls: false, insecure: false, fingerprint: ""
  };
}

function parseVmess(line) {
  const json = JSON.parse(decodeBase64(line.slice("vmess://".length)));
  return {
    id: makeId(), type: "vmess", tag: json.ps || "VMess · Imported",
    server: json.add, port: Number(json.port), uuid: json.id, security: json.scy || "auto",
    transport: json.net || "tcp", path: json.path || "", host: json.host || "",
    tls: json.tls === "tls" || json.tls === true, insecure: false,
    sni: json.sni || json.host || json.add, fingerprint: json.fp || "chrome"
  };
}

function nodeFromOutbound(outbound) {
  const supported = new Set(Object.keys(OUTBOUND_TYPE_META).filter((type) => !["direct", "bridge", "tor"].includes(type)));
  if (!outbound || !supported.has(outbound.type) || !outbound.server || !outbound.server_port) return null;
  const tls = outbound.tls || {};
  const transport = outbound.transport || {};
  const headerHost = Object.entries(transport.headers || {}).find(([key]) => key.toLowerCase() === "host")?.[1];
  const node = {
    id: makeId(),
    type: outbound.type,
    tag: outbound.tag || `${outbound.type.toUpperCase()} · Subscription`,
    server: outbound.server,
    port: Number(outbound.server_port),
    transport: transport.type || "tcp",
    path: transport.type === "grpc" ? transport.service_name || "" : transport.path || "",
    host: headerHost || transport.host || "",
    tls: Boolean(tls.enabled) || ["hysteria2", "tuic", "anytls"].includes(outbound.type),
    insecure: Boolean(tls.insecure),
    sni: tls.server_name || outbound.server,
    fingerprint: tls.utls?.enabled === false ? "" : tls.utls?.fingerprint || "",
    reality: Boolean(tls.reality?.enabled),
    publicKey: tls.reality?.public_key || "",
    shortId: tls.reality?.short_id || ""
  };
  if (["vless", "vmess", "tuic"].includes(outbound.type)) node.uuid = outbound.uuid || "";
  if (["trojan", "shadowsocks", "hysteria2", "tuic", "anytls"].includes(outbound.type)) node.password = outbound.password || "";
  if (outbound.type === "vless") node.flow = outbound.flow || "";
  if (outbound.type === "vmess") node.security = outbound.security || "auto";
  if (outbound.type === "shadowsocks") node.method = outbound.method || "";
  if (outbound.type === "hysteria2") {
    node.obfsType = outbound.obfs?.type || "";
    node.obfsPassword = outbound.obfs?.password || "";
    node.upMbps = outbound.up_mbps ?? "";
    node.downMbps = outbound.down_mbps ?? "";
  }
  if (outbound.type === "hysteria") {
    node.authString = outbound.auth_str || "";
    node.up = outbound.up || "";
    node.down = outbound.down || "";
    node.obfs = outbound.obfs || "";
  }
  if (outbound.type === "tuic") {
    node.congestionControl = outbound.congestion_control || "bbr";
    node.udpRelayMode = outbound.udp_relay_mode || "native";
  }
  if (["socks", "http", "naive", "ssh"].includes(outbound.type)) {
    node.username = outbound.username || "";
    node.user = outbound.user || "";
    node.password = outbound.password || "";
  }
  if (["shadowtls", "snell"].includes(outbound.type)) {
    node.version = String(outbound.version || (outbound.type === "snell" ? 4 : 3));
    node.password = outbound.password || "";
    node.psk = outbound.psk || "";
  }
  if (outbound.type === "anytls") node.password = outbound.password || "";
  if (outbound.network) node.network = outbound.network;
  if (outbound.detour) node.detour = outbound.detour;
  if (outbound.multiplex?.enabled) {
    node.multiplexEnabled = true;
    node.multiplexProtocol = outbound.multiplex.protocol || "";
    node.maxConnections = outbound.multiplex.max_connections ?? "";
  }
  return normalizeOutbound(node);
}

function parseSubscriptionContent(content, allowBase64 = true) {
  const text = String(content || "").replace(/^\uFEFF/, "").trim();
  if (!text) throw new Error("订阅内容为空");

  try {
    const parsed = JSON.parse(text);
    const outbounds = Array.isArray(parsed) ? parsed : parsed?.outbounds;
    if (Array.isArray(outbounds)) {
      const nodes = outbounds.map(nodeFromOutbound).filter(Boolean);
      if (!nodes.length) throw new Error("sing-box 配置中没有可导入的代理出站");
      return { nodes, rejected: outbounds.length - nodes.length };
    }
  } catch (error) {
    if (error.message.includes("没有可导入")) throw error;
  }

  const lines = text.split(/\r?\n/).map((line) => line.trim()).filter((line) => /^(vless|vmess|trojan|ss|hysteria2|hy2|tuic|anytls):\/\//i.test(line));
  if (lines.length) {
    const nodes = [];
    let rejected = 0;
    for (const line of lines) {
      try { nodes.push(parseShareLink(line)); } catch { rejected += 1; }
    }
    if (nodes.length) return { nodes, rejected };
  }

  if (allowBase64) {
    try {
      const decoded = decodeBase64(text);
      if (decoded && decoded !== text) return parseSubscriptionContent(decoded, false);
    } catch {}
  }
  throw new Error("未识别订阅格式；请使用 sing-box JSON 或明文/Base64 分享链接订阅");
}

async function readRemoteSubscription(url) {
  const response = await fetch("/api/fetch-subscription", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ url })
  });
  let result;
  try { result = await response.json(); } catch { throw new Error("订阅读取服务返回了无效响应"); }
  if (!response.ok) throw new Error(result.error || `读取订阅失败（HTTP ${response.status}）`);
  return parseSubscriptionContent(result.content);
}

function ensureUniqueTag(node, reserved = []) {
  const existing = new Set([...state.nodes.map((item) => item.tag), ...reserved]);
  const base = node.tag || `${node.type.toUpperCase()} · Imported`;
  let tag = base;
  let index = 2;
  while (existing.has(tag)) tag = `${base} (${index++})`;
  return { ...node, tag };
}

function prepareSubscriptionNodes(nodes, subscriptionId, replacingSubscriptionId = null) {
  const usedTags = new Set(
    state.nodes
      .filter((node) => node.subscriptionId !== replacingSubscriptionId)
      .map((node) => node.tag)
  );
  const prepared = [];
  for (const sourceNode of nodes) {
    if (!nodeIsComplete(sourceNode) || (sourceNode.reality && !sourceNode.publicKey)) continue;
    const baseTag = sourceNode.tag || `${sourceNode.type.toUpperCase()} · Subscription`;
    let tag = baseTag;
    let index = 2;
    while (usedTags.has(tag)) tag = `${baseTag} (${index++})`;
    usedTags.add(tag);
    prepared.push({ ...sourceNode, id: makeId(), tag, subscriptionId });
  }
  return prepared;
}

function defaultSubscriptionName(value) {
  try { return new URL(value).hostname; } catch { return "节点订阅"; }
}

async function refreshRemoteSubscription(subscription) {
  try {
    const parsed = await readRemoteSubscription(subscription.url);
    const nodes = prepareSubscriptionNodes(parsed.nodes, subscription.id, subscription.id);
    if (!nodes.length) throw new Error("订阅中没有完整且受支持的节点");
    const previous = state.nodes.filter((node) => node.subscriptionId === subscription.id);
    const diff = diffNodes(previous, nodes);
    state.nodes = state.nodes.filter((node) => node.subscriptionId !== subscription.id);
    state.nodes.push(...nodes.map(normalizeOutbound));
    subscription.lastUpdated = Date.now();
    subscription.nodeCount = nodes.length;
    subscription.lastError = "";
    subscription.lastDiff = { added: diff.added.length, removed: diff.removed.length };
    refreshOutbounds();
    return { count: nodes.length, rejected: parsed.rejected + (parsed.nodes.length - nodes.length), diff: subscription.lastDiff };
  } catch (error) {
    subscription.lastError = error.message;
    subscription.lastCheck = Date.now();
    renderNodes();
    throw error;
  }
}

function parseShareLink(line) {
  const match = line.match(/^([a-zA-Z0-9+.-]+):\/\//);
  const scheme = match?.[1]?.toLowerCase();
  if (!scheme) throw new Error("无法识别链接协议");
  if (scheme === "ss") return parseShadowsocks(line);
  if (scheme === "vmess") return parseVmess(line);
  const typeMap = { vless: "vless", trojan: "trojan", hysteria2: "hysteria2", hy2: "hysteria2", tuic: "tuic", anytls: "anytls" };
  if (!typeMap[scheme]) throw new Error(`暂不支持 ${scheme} 协议`);
  return parseStandardUrl(line.replace(/^hy2:/i, "hysteria2:"), typeMap[scheme]);
}

function encodeBase64Url(value) {
  const bytes = new TextEncoder().encode(value);
  let binary = "";
  for (let i = 0; i < bytes.length; i += 0x8000) binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function defaultPublicBase() {
  if (location.protocol === "http:" || location.protocol === "https:") return `${location.origin}${location.pathname.replace(/\/[^/]*$/, "/")}`;
  return "http://127.0.0.1:4173/";
}

function buildSubscriptionUrl() {
  const validation = validateConfigText($("#configOutput").value);
  if (!validation.valid) throw new Error(validation.error);
  let base = $("#publicBaseUrl").value.trim() || defaultPublicBase();
  if (!/^https?:\/\//i.test(base)) base = `https://${base}`;
  if (!base.endsWith("/")) base += "/";
  const endpoint = new URL("subscription", base);
  endpoint.searchParams.set("data", encodeBase64Url(JSON.stringify(validation.config)));
  endpoint.searchParams.set("name", safeFilename(state.settings.profileName));
  endpoint.searchParams.set("interval", "60");
  const token = $("#subscriptionToken")?.value.trim();
  if (token) endpoint.searchParams.set("token", token);
  const days = Number($("#subscriptionExpiry")?.value || 0);
  if (days) endpoint.searchParams.set("expires", String(Math.floor(Date.now() / 1000) + days * 86400));
  return endpoint.toString();
}

function updateSubscriptionFields() {
  try {
    const url = buildSubscriptionUrl();
    $("#subscriptionUrl").value = url;
    $("#openSubscriptionBtn").href = url;
    $("#importClientBtn").href = `sing-box://import-remote-profile?url=${encodeURIComponent(url)}#${encodeURIComponent(state.settings.profileName || "Sing Profile")}`;

  } catch (error) {
    $("#subscriptionUrl").value = "";
    showToast(error.message, true);
  }
}

function handleSettingsChange() {
  updateDnsDependentFields();
  updateRouteDependentFields();
  renderConfig();
}

$$('input, select', $("#profiles")).forEach((input) => input.addEventListener("input", handleSettingsChange));
$("#configOutput").addEventListener("input", validateOutput);
$("#tailscaleExitNode").addEventListener("input", updateTailscaleFormVisibility);
$("#tailscaleMagicDns").addEventListener("change", updateTailscaleFormVisibility);
$("#tailscaleSystemInterface").addEventListener("change", updateTailscaleFormVisibility);
$("#tailscaleSshServer").addEventListener("change", updateTailscaleFormVisibility);
$("#tailscaleNetworkStrategy").addEventListener("change", updateTailscaleFormVisibility);
$("#tailscaleDisableTcpKeepAlive").addEventListener("change", updateTailscaleFormVisibility);
$$('.dialog-close').forEach((button) => button.addEventListener("click", () => button.closest("dialog")?.close()));
$("#addNodeBtn").addEventListener("click", () => openNodeTypeModal());
$("#inlineAddBtn").addEventListener("click", () => openNodeTypeModal());
$("#addEndpointBtn").addEventListener("click", () => $("#endpointTypeModal").showModal());
$("#endpointTypeModal").addEventListener("click", (event) => {
  const button = event.target.closest("button[data-endpoint-type]");
  if (!button) return;
  $("#endpointTypeModal").close();
  if (button.dataset.endpointType === "tailscale") openTailscaleModal();
  else openStandardEndpointModal(button.dataset.endpointType);
});
$("#addSubscriptionBtn").addEventListener("click", () => {
  $("#remoteSubscriptionForm").reset();
  $("#remoteSubscriptionError").textContent = "";
  $("#remoteSubscriptionModal").showModal();
});
$("#importBtn").addEventListener("click", () => {
  $("#importForm").reset();
  $("#importError").textContent = "";
  $("#importModal").showModal();
});
$("#inlineImportBtn").addEventListener("click", () => $("#importBtn").click());

$("#remoteSubscriptionForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  const url = $("#remoteSubscriptionUrl").value.trim();
  const name = $("#remoteSubscriptionName").value.trim() || defaultSubscriptionName(url);
  const button = $("#fetchSubscriptionBtn");
  const originalLabel = button.textContent;
  $("#remoteSubscriptionError").textContent = "";
  button.disabled = true;
  button.textContent = "正在读取…";
  try {
    const subscription = { id: makeId(), name, url, lastUpdated: 0, nodeCount: 0 };
    state.subscriptions.push(subscription);
    try {
      const result = await refreshRemoteSubscription(subscription);
      $("#remoteSubscriptionModal").close();
      showToast(`已从订阅添加 ${result.count} 个节点${result.rejected ? `，忽略 ${result.rejected} 项` : ""}`, Boolean(result.rejected));
    } catch (error) {
      state.subscriptions = state.subscriptions.filter((item) => item.id !== subscription.id);
      throw error;
    }
  } catch (error) {
    $("#remoteSubscriptionError").textContent = error.message;
  } finally {
    button.disabled = false;
    button.textContent = originalLabel;
  }
});

$("#subscriptionSources").addEventListener("click", async (event) => {
  const button = event.target.closest("button[data-subscription-id]");
  if (!button) return;
  const subscription = state.subscriptions.find((item) => item.id === button.dataset.subscriptionId);
  if (!subscription) return;
  if (button.classList.contains("delete-subscription")) {
    if (!confirm(`删除订阅“${subscription.name}”及其节点吗？`)) return;
    state.subscriptions = state.subscriptions.filter((item) => item.id !== subscription.id);
    state.nodes = state.nodes.filter((node) => node.subscriptionId !== subscription.id);
    renderNodes();
    renderConfig();
    return showToast("订阅已删除");
  }
  if (button.classList.contains("refresh-subscription")) {
    button.disabled = true;
    try {
      const result = await refreshRemoteSubscription(subscription);
      const diffText = result.diff && (result.diff.added || result.diff.removed) ? `，新增 ${result.diff.added} 个、移除 ${result.diff.removed} 个` : "";
      showToast(`订阅已更新：${result.count} 个节点${diffText}${result.rejected ? `，忽略 ${result.rejected} 项` : ""}`, Boolean(result.rejected));
    } catch (error) {
      showToast(error.message, true);
    } finally {
      button.disabled = false;
    }
  }
});

$("#tailscaleForm").addEventListener("submit", (event) => {
  event.preventDefault();
  const endpoint = readTailscaleForm();
  const error = validateEndpoint(endpoint);
  if (error) return $("#tailscaleFormError").textContent = error;
  const index = state.endpoints.findIndex((item) => item.id === endpoint.id);
  if (index >= 0) state.endpoints[index] = endpoint;
  else state.endpoints.push(endpoint);
  $("#tailscaleModal").close();
  renderEndpoints();
  renderDns();
  renderRoute();
  renderConfig();
  showToast(index >= 0 ? "Tailscale 端点已更新" : "Tailscale 端点已添加");
});

$("#standardEndpointForm").addEventListener("submit", (event) => {
  event.preventDefault();
  const endpoint = readStandardEndpointForm();
  const error = validateEndpoint(endpoint);
  if (error) return $("#standardEndpointFormError").textContent = error;
  const index = state.endpoints.findIndex((item) => item.id === endpoint.id);
  if (index >= 0) state.endpoints[index] = endpoint;
  else state.endpoints.push(endpoint);
  $("#standardEndpointModal").close();
  renderEndpoints();
  renderDns();
  renderRoute();
  renderConfig();
  const label = ENDPOINT_TYPE_META[endpoint.type]?.label || "端点";
  showToast(index >= 0 ? `${label} 已更新` : `${label} 已添加`);
});

$("#endpointList").addEventListener("click", (event) => {
  if (event.target.closest("#emptyAddEndpoint")) return $("#endpointTypeModal").showModal();
  const button = event.target.closest("button");
  const item = event.target.closest(".endpoint-item");
  const id = button?.dataset.id || item?.dataset.id;
  if (!id) return;
  const endpoint = state.endpoints.find((entry) => entry.id === id);
  if (!endpoint) return;
  if (button?.classList.contains("delete-endpoint")) {
    event.stopPropagation();
    const label = ENDPOINT_TYPE_META[endpoint.type]?.label || "端点";
    if (!confirm(`删除 ${label}“${endpoint.tag}”吗？`)) return;
    state.endpoints = state.endpoints.filter((entry) => entry.id !== id);
    renderEndpoints();
    renderDns();
    renderRoute();
    renderConfig();
    return showToast(`${label} 已删除`);
  }
  openEndpointModal(endpoint);
});

$("#nodeList").addEventListener("click", (event) => {
  const button = event.target.closest("button");
  const item = event.target.closest(".node-item");
  const id = button?.dataset.id || item?.dataset.id;
  if (!id) return;
  const node = state.nodes.find((entry) => entry.id === id);
  if (!node) return;
  if (button?.classList.contains("delete-node")) {
    event.stopPropagation();
    state.nodes = state.nodes.filter((entry) => entry.id !== id);
    refreshOutbounds();
    return showToast("节点已删除");
  }
  if (button?.classList.contains("duplicate-node")) {
    event.stopPropagation();
    const copy = { ...clone(node), id: makeId(), tag: `${node.tag} Copy` };
    delete copy.subscriptionId;
    state.nodes.push(ensureUniqueTag(copy));
    refreshOutbounds();
    return showToast("已复制节点");
  }
  openNodeModal(node);
});

$("#clearNodesBtn").addEventListener("click", () => {
  if (!state.nodes.length || !confirm("确定清空所有节点吗？此操作会同步更新配置预览。")) return;
  state.nodes = [];
  state.subscriptions = [];
  refreshOutbounds();
});

$("#importForm").addEventListener("submit", (event) => {
  if (event.submitter?.value === "cancel") return;
  event.preventDefault();
  const lines = $("#importText").value.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
  if (!lines.length) return $("#importError").textContent = "请至少粘贴一个分享链接";
  const imported = [];
  const errors = [];
  for (const [index, line] of lines.entries()) {
    try {
      const node = ensureUniqueTag(parseShareLink(line), imported.map((item) => item.tag));
      const validation = validateOutbound({ ...node, id: `temp-${index}` }, { skipReferences: true });
      if (validation && !validation.includes("标签必须唯一")) throw new Error(validation);
      imported.push(node);
    } catch (error) {
      errors.push(`第 ${index + 1} 行：${error.message}`);
    }
  }
  if (!imported.length) return $("#importError").textContent = errors.join("；");
  state.nodes.push(...imported.map(normalizeOutbound));
  $("#importModal").close();
  refreshOutbounds();
  showToast(`已导入 ${imported.length} 个节点${errors.length ? `，${errors.length} 个失败` : ""}`, Boolean(errors.length));
});

$("#kernelCheckBtn").addEventListener("click", async () => {
  const validation = validateOutput();
  if (!validation.valid) return showToast(validation.error, true);
  const button = $("#kernelCheckBtn");
  button.disabled = true;
  showToast("正在调用本机 sing-box 检查…");
  try {
    const response = await fetch("/api/check", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(validation.config)
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || `HTTP ${response.status}`);
    if (!result.available) {
      renderConflicts([...currentConflicts, { level: "warning", scope: "内核", message: result.error }]);
      return showToast(result.error, true);
    }
    const issue = { level: result.ok ? "warning" : "error", scope: "内核检查", message: result.output };
    renderConflicts([...currentConflicts.filter((item) => item.scope !== "内核检查"), issue]);
    focusConflicts();
    showToast(result.ok ? "sing-box 内核检查通过" : "sing-box 内核检查未通过", !result.ok);
  } catch (error) {
    showToast(`内核检查失败：${error.message}`, true);
  } finally {
    button.disabled = false;
  }
});

$("#copyConfigBtn").addEventListener("click", () => copyText($("#configOutput").value));
$("#downloadConfigBtn").addEventListener("click", () => {
  const validation = validateOutput();
  if (!validation.valid) return showToast("请先修正 JSON 配置", true);
  downloadText(JSON.stringify(validation.config, null, 2) + "\n", `${safeFilename(state.settings.profileName)}.json`);
  if (hasBlockingConflicts(currentConflicts)) {
    focusConflicts();
    showToast(`已下载，但仍有 ${summarizeConflicts(currentConflicts).errors} 项冲突需要修正`, true);
  }
});
$("#formatBtn").addEventListener("click", () => {
  const validation = validateConfigText($("#configOutput").value);
  if (!validation.valid) return showToast(validation.error, true);
  $("#configOutput").value = JSON.stringify(validation.config, null, 2);
  validateOutput();
  showToast("JSON 已格式化");
});

function focusConflicts() {
  document.getElementById("preview")?.scrollIntoView({ behavior: "smooth", block: "start" });
  const block = $("#conflictBlock");
  block.classList.remove("flash");
  void block.offsetWidth;
  block.classList.add("flash");
}

$("#generateBtn").addEventListener("click", () => {
  renderConfig();
  const validation = validateOutput();
  if (!validation.valid) return showToast(validation.error, true);
  if (hasBlockingConflicts(currentConflicts)) {
    focusConflicts();
    return showToast(`存在 ${summarizeConflicts(currentConflicts).errors} 项配置冲突，请先修正后再生成链接`, true);
  }
  if (!state.nodes.some(nodeIsComplete)) return showToast("请先添加至少一个完整节点", true);
  $("#publicBaseUrl").value = defaultPublicBase();
  updateSubscriptionFields();
  const exposed = state.nodes.filter(nodeIsComplete).length;
  const warning = $("#linkWarning");
  if (warning) {
    const url = $("#subscriptionUrl").value;
    warning.textContent = url.length >= 8000
      ? `链接较长（${Math.round(url.length / 1024)} KB），节点较多时建议接入持久化存储。`
      : `链接内包含 ${exposed} 个节点的完整凭据，部署到公网时请配合 SUBSCRIPTION_TOKEN 与有效期使用。`;
    warning.classList.remove("hidden");
  }
  $("#subscriptionModal").showModal();
});
$("#publicBaseUrl").addEventListener("input", updateSubscriptionFields);
$("#subscriptionToken").addEventListener("input", updateSubscriptionFields);
$("#subscriptionExpiry").addEventListener("change", updateSubscriptionFields);
$("#copySubscriptionBtn").addEventListener("click", () => copyText($("#subscriptionUrl").value));
$("#closeSubscription").addEventListener("click", () => $("#subscriptionModal").close());

$("#resetBtn").addEventListener("click", () => {
  if (!confirm("恢复演示配置？当前浏览器内保存的节点会被覆盖。")) return;
  saveSnapshot("恢复示例前");
  state = clone(defaultState);
  syncInputsFromState();
  renderNodes();
  renderGroups();
  renderEndpoints();
  renderInbounds();
  renderDns();
  renderRoute();
  renderServices();
  renderConfig();
  showToast("已恢复演示配置");
});

const tlsVersionOptions = [["", "内核默认"], ["1.0", "1.0"], ["1.1", "1.1"], ["1.2", "1.2"], ["1.3", "1.3"]];
const utlsOptions = [["", "关闭"], ["chrome", "Chrome"], ["firefox", "Firefox"], ["safari", "Safari"], ["edge", "Edge"], ["ios", "iOS"], ["android", "Android"], ["random", "Random"]];
const rcodeOptions = [["", "NOERROR（默认）"], ["NOERROR", "NOERROR"], ["FORMERR", "FORMERR"], ["SERVFAIL", "SERVFAIL"], ["NXDOMAIN", "NXDOMAIN"], ["NOTIMP", "NOTIMP"], ["REFUSED", "REFUSED"]];

function dnsServerOptions(current = "", placeholder = "请选择 DNS Server") {
  const tags = (state.dns.servers || []).filter((server) => server.enabled !== false).map((server) => String(server.tag || "").trim()).filter(Boolean);
  if (current && !tags.includes(current)) tags.unshift(current);
  return [["", placeholder], ...tags.map((tag) => [tag, tag])];
}

function dnsEndpointOptions(types, current = "") {
  const tags = (state.endpoints || []).filter((endpoint) => types.includes(endpoint.type)).map((endpoint) => String(endpoint.tag || "").trim()).filter(Boolean);
  if (current && !tags.includes(current)) tags.unshift(current);
  return [["", tags.length ? "请选择端点" : "请先在端点面板添加"], ...tags.map((tag) => [tag, tag])];
}

const dnsTlsGroup = {
  key: "tls",
  title: "TLS",
  fields: [
    { key: "tlsServerName", label: "SNI 服务器名", placeholder: "证书上的域名" },
    { key: "tlsAlpn", label: "ALPN", placeholder: "h2, http/1.1" },
    { key: "tlsMinVersion", label: "最低 TLS 版本", type: "select", options: tlsVersionOptions },
    { key: "tlsMaxVersion", label: "最高 TLS 版本", type: "select", options: tlsVersionOptions },
    { key: "tlsCertificatePath", label: "CA 证书路径", placeholder: "/etc/ssl/cert.pem" },
    { key: "tlsUtlsFingerprint", label: "uTLS 指纹", type: "select", options: utlsOptions }
  ],
  switches: [
    { key: "tlsInsecure", label: "跳过证书验证", note: "insecure · 仅用于自签名证书" },
    { key: "tlsDisableSni", label: "不发送 SNI", note: "disable_sni" }
  ]
};

const dnsExtraGroup = {
  key: "extra",
  title: "完整 1.14 高级参数",
  details: true,
  note: "填写官方字段组成的 JSON 对象。表单字段优先；未知字段与旧版 address、address_resolver、address_strategy 会被拒绝。",
  fields: [{ key: "advancedJson", label: "附加参数 JSON", type: "textarea", rows: 6, full: true, className: "json-field", placeholder: "{}" }]
};

const DNS_SERVER_FIELDS = {
  local: {
    fields: [{ key: "neighborDomain", label: "邻居域", badge: "1.14", full: true, placeholder: "., .lan（每项以 . 开头，仅匹配单标签主机名）" }],
    switches: [{ key: "preferGo", label: "优先内置解析", note: "prefer_go · 关闭平台解析接口（1.13+）" }]
  },
  hosts: {
    fields: [
      { key: "path", label: "hosts 文件路径", type: "textarea", rows: 3, full: true, placeholder: "留空使用系统默认，每行一个路径" },
      { key: "predefinedJson", label: "预定义记录", type: "textarea", rows: 5, full: true, className: "json-field", placeholder: '{\n  "router.lan": "192.168.1.1",\n  "localhost": ["127.0.0.1", "::1"]\n}' }
    ]
  },
  tcp: { fields: [] },
  udp: { fields: [] },
  tls: { fields: [] },
  quic: { fields: [] },
  https: {
    fields: [
      { key: "path", label: "请求路径", placeholder: "默认 /dns-query" },
      { key: "headersJson", label: "附加请求头", type: "textarea", rows: 3, full: true, className: "json-field", placeholder: '{"User-Agent": "sing-box"}' }
    ]
  },
  h3: {
    fields: [
      { key: "path", label: "请求路径", placeholder: "默认 /dns-query" },
      { key: "headersJson", label: "附加请求头", type: "textarea", rows: 3, full: true, className: "json-field", placeholder: '{"User-Agent": "sing-box"}' }
    ]
  },
  dhcp: { fields: [{ key: "interface", label: "监听接口", placeholder: "留空使用默认接口" }] },
  mdns: { fields: [{ key: "interface", label: "查询接口", full: true, placeholder: "留空使用全部可用接口，例如 en0, en1" }] },
  fakeip: {
    fields: [
      { key: "inet4Range", label: "IPv4 段", required: true, placeholder: "198.18.0.0/15" },
      { key: "inet6Range", label: "IPv6 段", placeholder: "fc00::/18" }
    ]
  },
  resolved: {
    fields: [{ key: "service", label: "Resolved 服务标签", required: true, placeholder: "resolved" }],
    switches: [{ key: "acceptDefaultResolvers", label: "接受默认解析器", note: "未匹配查询回退到默认解析器，否则返回 NXDOMAIN" }]
  }
};

const DNS_SERVER_INTRO = {
  local: "使用系统解析能力，支持 hosts、邻居解析与 mDNS；配合 preferred_by 规则可只处理本地域名。",
  hosts: "只读取 hosts 文件与预定义记录，通常配合 preferred_by 规则在最前面命中。",
  tcp: "明文 DNS over TCP。服务器填域名时必须设置域名解析器。",
  udp: "明文 DNS over UDP。服务器填域名时必须设置域名解析器。",
  tls: "DNS over TLS，默认端口 853。",
  quic: "DNS over QUIC，默认端口 853。",
  https: "DNS over HTTPS，默认端口 443、路径 /dns-query。",
  h3: "DNS over HTTP/3，默认端口 443、路径 /dns-query。",
  dhcp: "跟随接口上 DHCP 下发的上游解析器。",
  mdns: "sing-box 1.14 新增；Local 已内置 *.local 处理，需要单独引用时才添加。",
  fakeip: "为查询分配虚拟地址，需要配合路由与 route.default_domain_resolver 使用。",
  tailscale: "从 Tailscale 端点获取 MagicDNS，可配合 preferred_by 只解析 Tailnet 域名。",
  openconnect: "sing-box 1.14 新增；使用 OpenConnect 端点下发的解析器，不会写入操作系统。",
  openvpn: "sing-box 1.14 新增；使用 OpenVPN Client 端点下发的解析器，不会写入操作系统。",
  resolved: "读取 systemd-resolved 服务的链路 DNS 设置，需要先配置 Resolved 服务。"
};

function dnsServerSchema(type) {
  const meta = DNS_SERVER_TYPE_META[type];
  const custom = DNS_SERVER_FIELDS[type] || {};
  const basic = {
    key: "basic",
    title: "基础",
    fields: [{ key: "tag", label: "Server 标签", required: true, placeholder: meta.prefix }],
    switches: [...(custom.switches || [])]
  };
  if (["tcp", "udp", "tls", "quic", "https", "h3"].includes(type)) {
    basic.fields.push(
      { key: "server", label: "服务器地址", required: true, placeholder: "1.1.1.1 或 dns.example.com" },
      { key: "serverPort", label: "服务器端口", type: "number", min: 1, max: 65535, placeholder: `默认 ${meta.port}` }
    );
  }
  if (meta.endpointTypes) {
    basic.fields.push({
      key: "endpoint",
      label: "关联端点",
      type: "select",
      options: (context) => dnsEndpointOptions(meta.endpointTypes, context.value?.endpoint)
    });
    basic.switches.push(
      { key: "acceptDefaultResolvers", label: "接受默认解析器", note: "未匹配查询使用下发的通用解析器，否则返回 NXDOMAIN" },
      { key: "acceptSearchDomain", label: "接受搜索域", note: "单标签查询依次尝试搜索域", badge: "1.14" }
    );
  }
  basic.fields.push(...(custom.fields || []));
  const groups = [basic];
  if (meta.tls) groups.push(dnsTlsGroup);
  if (meta.dial) groups.push(dialGroup);
  groups.push(dnsExtraGroup);
  return { type, title: `${meta.label} DNS Server`, intro: DNS_SERVER_INTRO[type] || meta.note, groups };
}

const dnsRuleSchema = {
  groups: [
    {
      key: "action",
      title: "基础",
      fields: [
        { key: "ruleType", label: "规则类型", type: "select", options: [["default", "普通规则"], ["logical", "逻辑规则"]] },
        { key: "action", label: "动作", type: "select", options: Object.entries(DNS_RULE_ACTION_META).map(([value, meta]) => [value, meta.label]) },
        { key: "server", label: "目标 DNS Server", type: "select", options: (context) => dnsServerOptions(context.value?.server) },
        { key: "evaluateTag", label: "求值结果标签", badge: "1.14", placeholder: "供后续 match_response 引用" }
      ],
      switches: [
        { key: "race", label: "并行竞速 race", note: "与后续规则并行判定，需要 match_response", badge: "1.14" },
        { key: "speculative", label: "推测执行 speculative", note: "在 race 未判定前先发出查询", badge: "1.14" },
        { key: "invert", label: "反转匹配结果", note: "invert" }
      ]
    },
    {
      key: "logical",
      title: "逻辑规则",
      fields: [
        { key: "mode", label: "组合方式", type: "select", options: [["and", "全部满足 and"], ["or", "任一满足 or"]] },
        { key: "rulesJson", label: "子规则数组", type: "textarea", rows: 8, full: true, className: "json-field", placeholder: '[{"domain_suffix": ".cn"}, {"rule_set": "geosite-cn"}]' }
      ]
    },
    {
      key: "routeOptions",
      title: "查询选项",
      fields: [
        { key: "rewriteTtl", label: "重写 TTL", type: "number", min: 0, placeholder: "保持上游 TTL" },
        { key: "timeout", label: "查询超时", badge: "1.14", placeholder: "覆盖 dns.timeout，例如 3s" },
        { key: "clientSubnet", label: "客户端子网", placeholder: "覆盖 dns.client_subnet，例如 1.2.3.0/24" }
      ],
      switches: [
        { key: "disableCache", label: "禁用缓存", note: "disable_cache" },
        { key: "disableOptimisticCache", label: "禁用乐观缓存", note: "disable_optimistic_cache", badge: "1.14" },
        { key: "removeClientSubnet", label: "移除客户端子网", note: "remove_client_subnet，与客户端子网互斥", badge: "1.14" }
      ]
    },
    {
      key: "reject",
      title: "拒绝方式",
      fields: [{ key: "rejectMethod", label: "拒绝方式", type: "select", options: [["", "默认 REFUSED"], ["default", "回复 REFUSED"], ["drop", "直接丢弃"]] }],
      switches: [{ key: "rejectNoDrop", label: "不自动降级为丢弃", note: "no_drop · method 为 drop 时不可用" }]
    },
    {
      key: "predefined",
      title: "预定义响应",
      fields: [
        { key: "predefinedRcode", label: "响应码", type: "select", options: rcodeOptions },
        { key: "predefinedAnswer", label: "Answer 记录", type: "textarea", rows: 3, full: true, placeholder: "localhost. IN A 127.0.0.1" },
        { key: "predefinedNs", label: "NS 记录", type: "textarea", rows: 2, full: true },
        { key: "predefinedExtra", label: "Extra 记录", type: "textarea", rows: 2, full: true }
      ]
    },
    {
      key: "matchDomain",
      title: "域名匹配",
      fields: [
        { key: "domain", label: "完整域名", full: true, placeholder: "example.com, test.com" },
        { key: "domainSuffix", label: "域名后缀", full: true, placeholder: ".cn, .example.com" },
        { key: "domainKeyword", label: "域名关键字", full: true, placeholder: "google, cdn" },
        { key: "domainRegex", label: "域名正则", type: "textarea", rows: 2, full: true, placeholder: "每行一个正则，例如 ^stun\\..+" },
        { key: "preferredBy", label: "服务器偏好域", badge: "1.14", full: true, placeholder: "hosts, local, ts-dns（匹配这些服务器的偏好域名）" }
      ]
    },
    {
      key: "matchQuery",
      title: "查询匹配",
      fields: [
        { key: "queryType", label: "查询类型", placeholder: "A, AAAA, HTTPS 或数字" },
        { key: "ipVersion", label: "IP 版本", type: "select", options: [["", "不限制"], ["4", "IPv4 · A"], ["6", "IPv6 · AAAA"]] },
        { key: "queryClientSubnet", label: "查询客户端子网", badge: "1.14", placeholder: "10.0.0.0/24" },
        { key: "network", label: "传输网络", type: "select", options: [["", "不限制"], ["tcp", "TCP"], ["udp", "UDP"]] },
        { key: "inbound", label: "入站标签", placeholder: "tun-in, mixed-in" },
        { key: "clashMode", label: "Clash 模式", placeholder: "Direct / Global / Rule" },
        { key: "protocol", label: "嗅探协议", placeholder: "tls, http, quic" },
        { key: "authUser", label: "认证用户", placeholder: "usera, userb" }
      ],
      switches: [{ key: "queryDnssec", label: "仅匹配 DNSSEC 查询", note: "query_dnssec · DO 位已置位", badge: "1.14" }]
    },
    {
      key: "matchSource",
      title: "来源与端口",
      details: true,
      fields: [
        { key: "sourceIpCidr", label: "来源 IP CIDR", full: true, placeholder: "192.168.1.0/24" },
        { key: "sourcePort", label: "来源端口", placeholder: "12345" },
        { key: "sourcePortRange", label: "来源端口范围", placeholder: "1000:2000, :3000" },
        { key: "port", label: "目标端口", placeholder: "80, 443" },
        { key: "portRange", label: "目标端口范围", placeholder: "1000:2000" },
        { key: "sourceMacAddress", label: "来源 MAC", badge: "1.14", placeholder: "00:11:22:33:44:55" },
        { key: "sourceHostname", label: "来源主机名", badge: "1.14", placeholder: "来自 DHCP 租约" }
      ],
      switches: [{ key: "sourceIpIsPrivate", label: "来源为私有地址", note: "source_ip_is_private" }],
      note: "MAC 与主机名匹配需要在支持的平台上启用邻居解析。"
    },
    {
      key: "matchProcess",
      title: "进程与用户",
      details: true,
      fields: [
        { key: "processName", label: "进程名", type: "textarea", rows: 2, full: true, placeholder: "每行一个，例如 curl" },
        { key: "processPath", label: "进程路径", type: "textarea", rows: 2, full: true, placeholder: "/usr/bin/curl" },
        { key: "processPathRegex", label: "进程路径正则", type: "textarea", rows: 2, full: true },
        { key: "packageName", label: "Android 包名", placeholder: "com.termux" },
        { key: "packageNameRegex", label: "包名正则", badge: "1.14", placeholder: "^com\\.termux.*" },
        { key: "user", label: "用户名", placeholder: "Linux only" },
        { key: "userId", label: "用户 ID", placeholder: "1000" }
      ],
      note: "进程匹配仅在 Linux、Windows 与 macOS 生效；包名匹配仅在 Android 生效。"
    },
    {
      key: "matchNetwork",
      title: "网络环境",
      details: true,
      fields: [
        { key: "networkType", label: "网络类型", placeholder: "wifi, cellular, ethernet, other" },
        { key: "wifiSsid", label: "Wi-Fi SSID", type: "textarea", rows: 2, full: true, placeholder: "每行一个 SSID" },
        { key: "wifiBssid", label: "Wi-Fi BSSID", placeholder: "00:00:00:00:00:00" }
      ],
      switches: [
        { key: "networkIsExpensive", label: "按流量计费网络", note: "network_is_expensive" },
        { key: "networkIsConstrained", label: "低数据模式", note: "network_is_constrained · Apple" }
      ],
      note: "网络类型与计费状态仅在 Android、Apple 图形客户端生效。"
    },
    {
      key: "matchRuleSet",
      title: "规则集",
      details: true,
      fields: [{ key: "ruleSet", label: "规则集标签", full: true, placeholder: "geosite-cn, geoip-cn" }],
      switches: [{ key: "ruleSetIpCidrMatchSource", label: "规则集 IP 匹配来源", note: "rule_set_ip_cidr_match_source" }],
      note: "规则集需要在路由模块中定义；不提供已弃用的 rule_set_ip_cidr_accept_empty。"
    },
    {
      key: "matchResponse",
      title: "响应匹配",
      badge: "1.14",
      details: true,
      fields: [
        { key: "matchResponse", label: "匹配响应", placeholder: "填 true 匹配最近一次 evaluate，或填求值标签" },
        { key: "responseRcode", label: "响应码", type: "select", options: rcodeOptions },
        { key: "ipCidr", label: "响应 IP CIDR", full: true, placeholder: "10.0.0.0/8" },
        { key: "responseAnswer", label: "Answer 匹配", type: "textarea", rows: 2, full: true },
        { key: "responseNs", label: "NS 匹配", type: "textarea", rows: 2, full: true },
        { key: "responseExtra", label: "Extra 匹配", type: "textarea", rows: 2, full: true }
      ],
      switches: [
        { key: "ipIsPrivate", label: "响应为私有地址", note: "ip_is_private" },
        { key: "ipAcceptAny", label: "响应包含任意地址", note: "ip_accept_any" }
      ],
      note: "1.14 起地址过滤必须配合 match_response 与前置 evaluate 规则；旧的直接地址过滤已弃用。"
    },
    {
      key: "extra",
      title: "完整 1.14 高级参数",
      details: true,
      note: "填写官方 DNS 规则字段组成的 JSON 对象，例如 interface_address。geoip、geosite、outbound 等已移除字段会被拒绝。",
      fields: [{ key: "advancedJson", label: "附加参数 JSON", type: "textarea", rows: 5, full: true, className: "json-field", placeholder: "{}" }]
    }
  ]
};

const DNS_MATCH_GROUPS = ["matchDomain", "matchQuery", "matchSource", "matchProcess", "matchNetwork", "matchRuleSet", "matchResponse"];

function setGroupVisible(container, key, visible) {
  $(`[data-group="${key}"]`, container)?.classList.toggle("hidden", !visible);
}

function setFieldVisible(container, key, visible) {
  $(`[data-field-key="${key}"]`, container)?.classList.toggle("hidden", !visible);
}

function updateDnsRuleFormVisibility() {
  const container = $("#dnsRuleFields");
  if (!container) return;
  const ruleType = $('[data-field="ruleType"]', container)?.value || "default";
  const action = $('[data-field="action"]', container)?.value || "route";
  const logical = ruleType === "logical";
  setGroupVisible(container, "logical", logical);
  DNS_MATCH_GROUPS.forEach((key) => setGroupVisible(container, key, !logical));
  setGroupVisible(container, "routeOptions", ["route", "evaluate", "route-options"].includes(action));
  setGroupVisible(container, "reject", action === "reject");
  setGroupVisible(container, "predefined", action === "predefined");
  setFieldVisible(container, "server", Boolean(DNS_RULE_ACTION_META[action]?.server));
  setFieldVisible(container, "evaluateTag", action === "evaluate");
  setFieldVisible(container, "speculative", ["route", "evaluate"].includes(action));
  setFieldVisible(container, "race", ["route", "respond", "reject", "predefined"].includes(action));
}

function nextDnsTag(type) {
  const prefix = DNS_SERVER_TYPE_META[type]?.prefix || "dns";
  const used = new Set((state.dns.servers || []).map((server) => String(server.tag || "").trim()));
  let tag = prefix;
  let index = 2;
  while (used.has(tag)) tag = `${prefix}-${index++}`;
  return tag;
}

function openDnsServerModal(type, server = null) {
  const schema = dnsServerSchema(type);
  const value = normalizeDnsServer(server || { type, tag: nextDnsTag(type) });
  $("#dnsServerForm").reset();
  $("#dnsServerFormError").textContent = "";
  $("#dnsServerType").value = type;
  $("#dnsServerId").value = server?.id || "";
  $("#dnsServerModalTitle").textContent = `${server ? "编辑" : "添加"} ${schema.title}`;
  $("#dnsServerModalVersion").textContent = `sing-box 1.14.0 · type: ${type}`;
  $("#dnsServerIntro").textContent = schema.intro;
  $("#dnsServerFields").innerHTML = renderSchemaForm(schema, value, { value });
  $("#dnsServerModal").showModal();
  $('[data-field="tag"]', $("#dnsServerFields"))?.focus();
}

function readDnsServerForm() {
  const type = $("#dnsServerType").value;
  const schema = dnsServerSchema(type);
  return normalizeDnsServer({
    type,
    id: $("#dnsServerId").value || makeId(),
    enabled: state.dns.servers.find((server) => server.id === $("#dnsServerId").value)?.enabled !== false,
    ...readSchemaForm(schema, $("#dnsServerFields"))
  });
}

function openDnsRuleModal(rule = null) {
  const value = normalizeDnsRule(rule || {});
  $("#dnsRuleForm").reset();
  $("#dnsRuleFormError").textContent = "";
  $("#dnsRuleId").value = rule?.id || "";
  $("#dnsRuleModalTitle").textContent = rule ? "编辑 DNS 规则" : "添加 DNS 规则";
  $("#dnsRuleFields").innerHTML = renderSchemaForm(dnsRuleSchema, value, { value });
  updateDnsRuleFormVisibility();
  $("#dnsRuleModal").showModal();
}

function readDnsRuleForm() {
  const id = $("#dnsRuleId").value || makeId();
  return normalizeDnsRule({
    id,
    enabled: state.dns.rules.find((rule) => rule.id === id)?.enabled !== false,
    ...readSchemaForm(dnsRuleSchema, $("#dnsRuleFields"))
  });
}

function dnsValidationContext() {
  return {
    endpoints: state.endpoints || [],
    outboundTags: ["proxy", "auto", "direct", ...state.nodes.filter(nodeIsComplete).map((node) => node.tag.trim())],
    servers: state.dns.servers || [],
    serverTags: (state.dns.servers || []).filter((server) => server.enabled !== false).map((server) => String(server.tag || "").trim())
  };
}

function dnsServerSummary(server) {
  const detour = server.detour ? ` · detour ${server.detour}` : "";
  if (["tcp", "udp", "tls", "quic", "https", "h3"].includes(server.type)) {
    const port = server.serverPort || DNS_SERVER_TYPE_META[server.type].port;
    return `${server.server || "待填写地址"}:${port}${server.path ? server.path : ""}${detour}`;
  }
  if (server.type === "local") return `${server.preferGo ? "内置解析" : "系统解析"}${server.neighborDomain ? ` · 邻居域 ${server.neighborDomain}` : ""}${detour}`;
  if (server.type === "hosts") return server.path ? `文件 ${server.path.split(/\n/)[0]}` : "系统 hosts 与预定义记录";
  if (server.type === "fakeip") return `${server.inet4Range || "—"} · ${server.inet6Range || "—"}`;
  if (server.type === "resolved") return `服务 ${server.service || "resolved"}`;
  if (DNS_SERVER_TYPE_META[server.type]?.endpointTypes) return `端点 ${server.endpoint || "未选择"}${server.acceptDefaultResolvers ? " · 接受默认解析器" : ""}`;
  if (["dhcp", "mdns"].includes(server.type)) return `${server.interface || "自动选择接口"}${detour}`;
  return DNS_SERVER_TYPE_META[server.type]?.note || server.type;
}

function dnsRuleSummary(rule) {
  if (rule.ruleType === "logical") {
    let count = 0;
    try { count = JSON.parse(rule.rulesJson || "[]").length; } catch {}
    return `逻辑 ${rule.mode === "or" ? "或" : "与"} · ${count} 条子规则`;
  }
  const conditions = [
    ["域名", rule.domain], ["后缀", rule.domainSuffix], ["关键字", rule.domainKeyword], ["正则", rule.domainRegex],
    ["偏好", rule.preferredBy], ["类型", rule.queryType], ["规则集", rule.ruleSet], ["Clash", rule.clashMode],
    ["入站", rule.inbound], ["来源", rule.sourceIpCidr], ["进程", rule.processName], ["响应", rule.matchResponse]
  ].filter(([, value]) => String(value || "").trim()).map(([label, value]) => `${label} ${String(value).split(/[\n,]/)[0].trim()}`);
  if (rule.queryDnssec) conditions.push("DNSSEC");
  if (rule.ipIsPrivate) conditions.push("私有响应");
  return conditions.length ? conditions.slice(0, 3).join(" · ") + (conditions.length > 3 ? ` +${conditions.length - 3}` : "") : "匹配全部查询";
}

function dnsActionSummary(rule) {
  const meta = DNS_RULE_ACTION_META[rule.action] || DNS_RULE_ACTION_META.route;
  const label = meta.label.split(" · ")[0];
  if (meta.server) return `${label} → ${rule.server || "未选择"}`;
  if (rule.action === "reject") return `${label} · ${rule.rejectMethod === "drop" ? "丢弃" : "REFUSED"}`;
  if (rule.action === "predefined") return `${label} · ${rule.predefinedRcode || "NOERROR"}`;
  return label;
}

function sortableRowActions(id, enabled) {
  return `<div class="endpoint-actions sortable-actions">
    <button type="button" class="icon-btn entry-move-up" data-id="${escapeHtml(id)}" title="上移" aria-label="上移">↑</button>
    <button type="button" class="icon-btn entry-move-down" data-id="${escapeHtml(id)}" title="下移" aria-label="下移">↓</button>
    <button type="button" class="icon-btn entry-toggle${enabled ? " is-on" : ""}" data-id="${escapeHtml(id)}" title="${enabled ? "停用" : "启用"}" aria-label="${enabled ? "停用" : "启用"}"><svg><use href="#i-check"/></svg></button>
    <button type="button" class="icon-btn entry-duplicate" data-id="${escapeHtml(id)}" title="复制" aria-label="复制"><svg><use href="#i-copy"/></svg></button>
    <button type="button" class="icon-btn danger entry-delete" data-id="${escapeHtml(id)}" title="删除" aria-label="删除"><svg><use href="#i-trash"/></svg></button>
    <button type="button" class="icon-btn entry-edit" data-id="${escapeHtml(id)}" title="编辑" aria-label="编辑"><svg><use href="#i-chevron"/></svg></button>
  </div>`;
}

function renderDnsServers() {
  const list = $("#dnsServerList");
  const servers = state.dns.servers || [];
  $("#dnsServerCount").textContent = servers.length;
  if (!servers.length) {
    list.innerHTML = `<div class="empty-endpoints"><div><svg><use href="#i-shield"/></svg><strong>还没有 DNS Server</strong><small>至少需要一个 Server，配置才能通过检查</small></div><button class="secondary-button" data-empty-add type="button">添加 Server</button></div>`;
    return;
  }
  list.innerHTML = servers.map((server) => {
    const meta = DNS_SERVER_TYPE_META[server.type] || { label: server.type };
    const enabled = server.enabled !== false;
    return `<article class="endpoint-item sortable-item${enabled ? "" : " is-off"}" data-id="${escapeHtml(server.id)}" draggable="true">
      <div class="endpoint-glyph"><svg><use href="#i-shield"/></svg></div>
      <div class="endpoint-main">
        <div><strong>${escapeHtml(server.tag || "未命名 Server")}</strong><span>${escapeHtml(meta.label)}</span>${meta.badge ? `<span class="new-badge">${escapeHtml(meta.badge)}</span>` : ""}</div>
        <small>${escapeHtml(dnsServerSummary(server))}</small>
      </div>
      ${sortableRowActions(server.id, enabled)}
    </article>`;
  }).join("");
}

function renderDnsRules() {
  const list = $("#dnsRuleList");
  const rules = state.dns.rules || [];
  $("#dnsRuleCount").textContent = rules.length;
  if (!rules.length) {
    list.innerHTML = `<div class="empty-endpoints"><div><svg><use href="#i-sliders"/></svg><strong>还没有 DNS 规则</strong><small>所有查询都会交给默认 Server</small></div><button class="secondary-button" data-empty-add type="button">添加规则</button></div>`;
    return;
  }
  list.innerHTML = rules.map((rule, index) => {
    const enabled = rule.enabled !== false;
    return `<article class="endpoint-item sortable-item${enabled ? "" : " is-off"}" data-id="${escapeHtml(rule.id)}" draggable="true">
      <div class="endpoint-glyph sortable-order">${index + 1}</div>
      <div class="endpoint-main">
        <div><strong>${escapeHtml(dnsActionSummary(rule))}</strong>${rule.race ? '<span>race</span>' : ""}${rule.ruleType === "logical" ? '<span>logical</span>' : ""}</div>
        <small>${escapeHtml(dnsRuleSummary(rule))}</small>
      </div>
      ${sortableRowActions(rule.id, enabled)}
    </article>`;
  }).join("");
}

function syncDnsInputs() {
  const dns = state.dns;
  const serverTags = (dns.servers || []).filter((server) => server.enabled !== false).map((server) => String(server.tag || "").trim()).filter(Boolean);
  const fillSelect = (selector, value, placeholder) => {
    const select = $(selector);
    const options = [`<option value="">${placeholder}</option>`, ...serverTags.map((tag) => `<option value="${escapeHtml(tag)}">${escapeHtml(tag)}</option>`)];
    select.innerHTML = options.join("");
    select.value = serverTags.includes(value) ? value : "";
  };
  fillSelect("#dnsFinal", String(dns.final || "").trim(), "使用第一个 Server");
  fillSelect("#dnsDefaultResolver", String(dns.defaultDomainResolver || "").trim(), "自动选择 Local Server");
  $("#dnsStrategy").value = dns.strategy || "";
  $("#dnsTimeout").value = dns.timeout || "";
  $("#dnsCacheCapacity").value = dns.cacheCapacity || "";
  $("#dnsOptimisticTimeout").value = dns.optimisticTimeout || "";
  $("#dnsClientSubnet").value = dns.clientSubnet || "";
  $("#dnsOptimistic").checked = Boolean(dns.optimistic);
  $("#dnsDisableCache").checked = Boolean(dns.disableCache);
  $("#dnsDisableExpire").checked = Boolean(dns.disableExpire);
  $("#dnsReverseMapping").checked = Boolean(dns.reverseMapping);
  updateDnsDependentFields();
}

function readDnsSettings() {
  state.dns = {
    ...state.dns,
    final: $("#dnsFinal").value,
    defaultDomainResolver: $("#dnsDefaultResolver").value,
    strategy: $("#dnsStrategy").value,
    timeout: $("#dnsTimeout").value.trim(),
    cacheCapacity: $("#dnsCacheCapacity").value.trim(),
    optimistic: $("#dnsOptimistic").checked,
    optimisticTimeout: $("#dnsOptimisticTimeout").value.trim(),
    clientSubnet: $("#dnsClientSubnet").value.trim(),
    disableCache: $("#dnsDisableCache").checked,
    disableExpire: $("#dnsDisableExpire").checked,
    reverseMapping: $("#dnsReverseMapping").checked
  };
}

function updateDnsSummary() {
  const servers = state.dns.servers || [];
  const rules = state.dns.rules || [];
  const sideCount = $(".main-nav button[data-scroll='dns'] i");
  if (sideCount) sideCount.textContent = servers.length + rules.length;
  const issue = validateDnsState(state.dns, dnsValidationContext());
  const summary = $("#dnsSummaryText");
  if (!summary) return;
  summary.textContent = issue || `${servers.length} 个 Server · ${rules.length} 条规则`;
  summary.closest(".node-foot")?.classList.toggle("has-issue", Boolean(issue));
}

function updateDnsDependentFields() {
  const optimistic = $("#dnsOptimistic").checked;
  $("#dnsOptimisticTimeout").disabled = !optimistic;
  $("#dnsOptimisticTimeout").closest(".field").classList.toggle("is-disabled", !optimistic);
}

function renderDns() {
  renderDnsServers();
  renderDnsRules();
  syncDnsInputs();
  updateDnsSummary();
}

function moveListEntry(collection, id, offset) {
  const index = collection.findIndex((item) => item.id === id);
  const target = index + offset;
  if (index < 0 || target < 0 || target >= collection.length) return false;
  collection.splice(target, 0, ...collection.splice(index, 1));
  return true;
}

let dragEntryId = null;

function setupSortableList(selector, getCollection, { onOpen, onDuplicate, onDelete, onAdd, onChange }) {
  const list = $(selector);
  list.addEventListener("click", (event) => {
    if (event.target.closest("[data-empty-add]")) return onAdd();
    const button = event.target.closest("button[data-id]");
    const item = event.target.closest(".sortable-item");
    const id = button?.dataset.id || item?.dataset.id;
    if (!id) return;
    const collection = getCollection();
    const entry = collection.find((candidate) => candidate.id === id);
    if (!entry) return;
    if (button?.classList.contains("entry-delete")) return onDelete(entry);
    if (button?.classList.contains("entry-duplicate")) return onDuplicate(entry);
    if (button?.classList.contains("entry-toggle")) {
      entry.enabled = entry.enabled === false;
      return onChange();
    }
    if (button?.classList.contains("entry-move-up") || button?.classList.contains("entry-move-down")) {
      if (!moveListEntry(collection, id, button.classList.contains("entry-move-up") ? -1 : 1)) return;
      return onChange();
    }
    onOpen(entry);
  });
  list.addEventListener("dragstart", (event) => {
    const item = event.target.closest(".sortable-item");
    if (!item) return;
    dragEntryId = item.dataset.id;
    item.classList.add("is-dragging");
    event.dataTransfer.effectAllowed = "move";
    try { event.dataTransfer.setData("text/plain", dragEntryId); } catch {}
  });
  list.addEventListener("dragend", () => {
    dragEntryId = null;
    $$(".is-dragging, .is-drop-target", list).forEach((item) => item.classList.remove("is-dragging", "is-drop-target"));
  });
  list.addEventListener("dragover", (event) => {
    if (!dragEntryId) return;
    event.preventDefault();
    const item = event.target.closest(".sortable-item");
    $$(".is-drop-target", list).forEach((entry) => entry.classList.remove("is-drop-target"));
    if (item && item.dataset.id !== dragEntryId) item.classList.add("is-drop-target");
  });
  list.addEventListener("drop", (event) => {
    const item = event.target.closest(".sortable-item");
    if (!dragEntryId || !item || item.dataset.id === dragEntryId) return;
    event.preventDefault();
    const collection = getCollection();
    const from = collection.findIndex((entry) => entry.id === dragEntryId);
    const to = collection.findIndex((entry) => entry.id === item.dataset.id);
    dragEntryId = null;
    if (from < 0 || to < 0) return;
    collection.splice(to, 0, ...collection.splice(from, 1));
    onChange();
  });
}

function refreshDns() {
  renderDns();
  renderConfig();
}

setupSortableList("#dnsServerList", () => state.dns.servers, {
  onAdd: () => $("#dnsServerTypeModal").showModal(),
  onChange: refreshDns,
  onOpen: (server) => openDnsServerModal(server.type, server),
  onDuplicate: (server) => {
    const copy = { ...clone(server), id: makeId(), tag: nextDnsTag(server.type) };
    state.dns.servers.splice(state.dns.servers.indexOf(server) + 1, 0, copy);
    renderDns();
    renderConfig();
    showToast("DNS Server 已复制");
  },
  onDelete: (server) => {
    const tag = String(server.tag || "").trim();
    const used = (state.dns.rules || []).some((rule) => rule.server === tag || splitTagList(rule.preferredBy).includes(tag));
    if (!confirm(used ? `DNS Server“${tag}”仍被规则引用，仍要删除吗？` : `删除 DNS Server“${tag}”吗？`)) return;
    state.dns.servers = state.dns.servers.filter((entry) => entry.id !== server.id);
    renderDns();
    renderConfig();
    showToast("DNS Server 已删除");
  }
});

setupSortableList("#dnsRuleList", () => state.dns.rules, {
  onAdd: () => openDnsRuleModal(),
  onChange: refreshDns,
  onOpen: (rule) => openDnsRuleModal(rule),
  onDuplicate: (rule) => {
    const copy = { ...clone(rule), id: makeId() };
    state.dns.rules.splice(state.dns.rules.indexOf(rule) + 1, 0, copy);
    renderDns();
    renderConfig();
    showToast("DNS 规则已复制");
  },
  onDelete: (rule) => {
    if (!confirm("删除这条 DNS 规则吗？")) return;
    state.dns.rules = state.dns.rules.filter((entry) => entry.id !== rule.id);
    renderDns();
    renderConfig();
    showToast("DNS 规则已删除");
  }
});

function splitTagList(value) {
  return String(value || "").split(/[\n,]+/).map((item) => item.trim()).filter(Boolean);
}

function openDnsServerTypeModal() {
  $("#dnsServerTypeList").innerHTML = Object.entries(DNS_SERVER_TYPE_META).map(([type, meta]) => `
    <button type="button" data-dns-type="${escapeHtml(type)}">
      <span class="endpoint-type-icon"><svg><use href="#i-shield"/></svg></span>
      <span><strong>${escapeHtml(meta.label)}${meta.badge ? ` · ${escapeHtml(meta.badge)}` : ""}</strong><small>${escapeHtml(meta.note)}</small></span>
      <svg><use href="#i-chevron"/></svg>
    </button>`).join("");
  $("#dnsServerTypeModal").showModal();
}

$("#addDnsServerBtn").addEventListener("click", openDnsServerTypeModal);
$("#addDnsServerInline").addEventListener("click", openDnsServerTypeModal);
$("#addDnsRuleBtn").addEventListener("click", () => openDnsRuleModal());
$("#addDnsRuleInline").addEventListener("click", () => openDnsRuleModal());
$("#dnsServerTypeModal").addEventListener("click", (event) => {
  const button = event.target.closest("button[data-dns-type]");
  if (!button) return;
  $("#dnsServerTypeModal").close();
  openDnsServerModal(button.dataset.dnsType);
});

$("#dnsRuleFields").addEventListener("change", (event) => {
  if (event.target.matches('[data-field="action"], [data-field="ruleType"]')) updateDnsRuleFormVisibility();
});

$("#dnsServerForm").addEventListener("submit", (event) => {
  event.preventDefault();
  const server = readDnsServerForm();
  const error = validateDnsServer(server, dnsValidationContext());
  if (error) return $("#dnsServerFormError").textContent = error;
  const index = state.dns.servers.findIndex((entry) => entry.id === server.id);
  if (index >= 0) state.dns.servers[index] = server;
  else state.dns.servers.push(server);
  $("#dnsServerModal").close();
  renderDns();
  renderConfig();
  showToast(index >= 0 ? "DNS Server 已更新" : "DNS Server 已添加");
});

$("#dnsRuleForm").addEventListener("submit", (event) => {
  event.preventDefault();
  const rule = readDnsRuleForm();
  const error = validateDnsRule(rule, dnsValidationContext());
  if (error) return $("#dnsRuleFormError").textContent = error;
  const index = state.dns.rules.findIndex((entry) => entry.id === rule.id);
  if (index >= 0) state.dns.rules[index] = rule;
  else state.dns.rules.push(rule);
  $("#dnsRuleModal").close();
  renderDns();
  renderConfig();
  showToast(index >= 0 ? "DNS 规则已更新" : "DNS 规则已添加");
});

function nodeTagList() {
  return state.nodes.filter(nodeIsComplete).map((node) => String(node.tag || "").trim()).filter(Boolean);
}

function activeGroups() {
  const nodeTags = nodeTagList();
  const groupTags = (state.groups || []).filter((group) => group.enabled !== false).map((group) => String(group.tag || "").trim());
  return (state.groups || [])
    .filter((group) => group.enabled !== false)
    .filter((group) => groupMembers(group, { nodeTags, groupTags }).length);
}

function defaultFinalOutbound() {
  const groups = activeGroups();
  if (groups.length) return String(groups[0].tag || "").trim();
  const nodes = nodeTagList();
  return nodes.length ? nodes[0] : "direct";
}

function availableOutboundTags() {
  return [
    ...activeGroups().map((group) => String(group.tag || "").trim()),
    ...nodeTagList(),
    "direct",
    ...(state.endpoints || []).map((endpoint) => String(endpoint.tag || "").trim()).filter(Boolean)
  ];
}

function availableDnsServerTags() {
  const configured = (state.dns.servers || []).filter((server) => server.enabled !== false).map((server) => String(server.tag || "").trim());
  const magic = (state.endpoints || []).filter((endpoint) => endpoint.type === "tailscale" && endpoint.magicDns).map((endpoint) => `${String(endpoint.tag || "").trim()}-dns`);
  return [...configured, ...magic].filter(Boolean);
}

function availableRuleSetTags() {
  return (state.route.ruleSets || []).filter((set) => set.enabled !== false).flatMap((set) => splitTagList(set.tag));
}

function availableInboundTags() {
  return activeInboundTags(state.inbounds || []);
}

function routeValidationContext() {
  return {
    outboundTags: availableOutboundTags(),
    dnsServerTags: availableDnsServerTags(),
    ruleSetTags: availableRuleSetTags(),
    inboundTags: availableInboundTags(),
    ruleSets: state.route.ruleSets || []
  };
}

function tagSelectOptions(tags, current = "", placeholder = "请选择") {
  const list = [...tags];
  if (current && !list.includes(current)) list.unshift(current);
  return [["", placeholder], ...list.map((tag) => [tag, tag])];
}

const routeRuleSchema = {
  groups: [
    {
      key: "action",
      title: "基础",
      fields: [
        { key: "ruleType", label: "规则类型", type: "select", options: [["default", "普通规则"], ["logical", "逻辑规则"]] },
        { key: "action", label: "动作", type: "select", options: Object.entries(ROUTE_ACTION_META).map(([value, meta]) => [value, meta.label]) },
        { key: "outbound", label: "目标出站", type: "select", options: (context) => tagSelectOptions(availableOutboundTags(), context.value?.outbound, "请选择出站") }
      ],
      switches: [{ key: "invert", label: "反转匹配结果", note: "invert" }]
    },
    {
      key: "logical",
      title: "逻辑规则",
      fields: [
        { key: "mode", label: "组合方式", type: "select", options: [["and", "全部满足 and"], ["or", "任一满足 or"]] },
        { key: "rulesJson", label: "子规则数组", type: "textarea", rows: 8, full: true, className: "json-field", placeholder: '[{"domain_suffix": ".cn"}, {"rule_set": "geosite-cn"}]' }
      ],
      note: "子规则只写匹配条件，动作由外层规则决定。"
    },
    {
      key: "routeOptions",
      title: "路由选项",
      fields: [
        { key: "overrideAddress", label: "覆盖目标地址", placeholder: "例如 1.1.1.1" },
        { key: "overridePort", label: "覆盖目标端口", type: "number", min: 1, max: 65535, placeholder: "不覆盖" },
        { key: "networkStrategy", label: "网络策略", type: "select", options: selectOptions.networkStrategy },
        { key: "udpTimeout", label: "UDP 超时", placeholder: "例如 30s" },
        { key: "tlsFragmentFallbackDelay", label: "TLS 分片回退延迟", placeholder: "默认 500ms" },
        { key: "tlsSpoof", label: "伪造 SNI", badge: "1.14", placeholder: "需要管理员权限" },
        { key: "tlsSpoofMethod", label: "伪造拒绝方式", badge: "1.14", type: "select", options: [["", "内核默认"], ["wrong-sequence", "wrong-sequence"], ["wrong-checksum", "wrong-checksum"], ["wrong-ack", "wrong-ack"], ["wrong-md5", "wrong-md5"], ["wrong-timestamp", "wrong-timestamp"]] }
      ],
      switches: [
        { key: "udpConnect", label: "UDP 连接模式", note: "udp_connect" },
        { key: "udpDisableDomainUnmapping", label: "禁用 UDP 域名还原", note: "兼容 Surge 等客户端" },
        { key: "tlsFragment", label: "TLS 分片", note: "tls_fragment · 性能较差，建议先试 TLS 记录分片" },
        { key: "tlsRecordFragment", label: "TLS 记录分片", note: "tls_record_fragment" }
      ],
      note: "网络策略只在出站为 direct 且未设置绑定接口时生效；route-options 的 network_type 等长尾字段请写在附加参数里。"
    },
    {
      key: "reject",
      title: "拒绝方式",
      fields: [{ key: "rejectMethod", label: "拒绝方式", type: "select", options: [["", "默认"], ["default", "TCP RST / ICMP 不可达"], ["drop", "直接丢弃"], ["reply", "回复 ICMP echo（仅 ping）"]] }],
      switches: [{ key: "rejectNoDrop", label: "不自动降级为丢弃", note: "no_drop · method 为 drop 时不可用" }]
    },
    {
      key: "sniff",
      title: "嗅探",
      fields: [
        { key: "sniffer", label: "启用的嗅探器", full: true, placeholder: `留空启用全部：${SNIFFERS.join(", ")}` },
        { key: "sniffTimeout", label: "嗅探超时", placeholder: "默认 300ms" }
      ]
    },
    {
      key: "resolve",
      title: "解析",
      fields: [
        { key: "resolveServer", label: "指定 DNS Server", type: "select", options: (context) => tagSelectOptions(availableDnsServerTags(), context.value?.resolveServer, "按 DNS 路由决定") },
        { key: "resolveStrategy", label: "解析策略", type: "select", options: [["", "跟随 dns.strategy"], ["prefer_ipv4", "优先 IPv4"], ["prefer_ipv6", "优先 IPv6"], ["ipv4_only", "仅 IPv4"], ["ipv6_only", "仅 IPv6"]] },
        { key: "resolveRewriteTtl", label: "重写 TTL", type: "number", min: 0, placeholder: "保持上游 TTL" },
        { key: "resolveTimeout", label: "解析超时", badge: "1.14", placeholder: "覆盖 dns.timeout" },
        { key: "resolveClientSubnet", label: "客户端子网", placeholder: "例如 1.2.3.0/24" }
      ],
      switches: [
        { key: "resolveDisableCache", label: "禁用缓存", note: "disable_cache" },
        { key: "resolveDisableOptimisticCache", label: "禁用乐观缓存", note: "disable_optimistic_cache", badge: "1.14" }
      ]
    },
    {
      key: "matchDomain",
      title: "域名匹配",
      fields: [
        { key: "domain", label: "完整域名", full: true, placeholder: "example.com, test.com" },
        { key: "domainSuffix", label: "域名后缀", full: true, placeholder: ".cn, .example.com" },
        { key: "domainKeyword", label: "域名关键字", full: true, placeholder: "google, cdn" },
        { key: "domainRegex", label: "域名正则", type: "textarea", rows: 2, full: true, placeholder: "每行一个正则" }
      ]
    },
    {
      key: "matchTraffic",
      title: "流量匹配",
      fields: [
        { key: "inbound", label: "入站标签", type: "select", options: (context) => tagSelectOptions(availableInboundTags(), context.value?.inbound, "不限制") },
        { key: "network", label: "网络", placeholder: "tcp, udp, icmp" },
        { key: "ipVersion", label: "IP 版本", type: "select", options: [["", "不限制"], ["4", "IPv4"], ["6", "IPv6"]] },
        { key: "protocol", label: "嗅探协议", placeholder: "tls, http, quic" },
        { key: "client", label: "嗅探客户端", placeholder: "chromium, safari, firefox, quic-go" },
        { key: "clashMode", label: "Clash 模式", placeholder: "Direct / Global / Rule" },
        { key: "authUser", label: "认证用户", placeholder: "usera, userb" },
        { key: "preferredBy", label: "出站偏好路由", badge: "1.13", placeholder: "tailscale, wireguard, bridge" }
      ]
    },
    {
      key: "matchAddress",
      title: "地址与端口",
      details: true,
      fields: [
        { key: "ipCidr", label: "目标 IP CIDR", full: true, placeholder: "10.0.0.0/8, 1.1.1.1" },
        { key: "sourceIpCidr", label: "来源 IP CIDR", full: true, placeholder: "192.168.1.0/24" },
        { key: "port", label: "目标端口", placeholder: "80, 443" },
        { key: "portRange", label: "目标端口范围", placeholder: "1000:2000" },
        { key: "sourcePort", label: "来源端口", placeholder: "12345" },
        { key: "sourcePortRange", label: "来源端口范围", placeholder: ":3000" }
      ],
      switches: [
        { key: "ipIsPrivate", label: "目标为私有地址", note: "ip_is_private" },
        { key: "sourceIpIsPrivate", label: "来源为私有地址", note: "source_ip_is_private" }
      ]
    },
    {
      key: "matchProcess",
      title: "进程与用户",
      details: true,
      fields: [
        { key: "processName", label: "进程名", type: "textarea", rows: 2, full: true, placeholder: "每行一个，例如 curl" },
        { key: "processPath", label: "进程路径", type: "textarea", rows: 2, full: true },
        { key: "processPathRegex", label: "进程路径正则", type: "textarea", rows: 2, full: true },
        { key: "packageName", label: "Android 包名", placeholder: "com.termux" },
        { key: "packageNameRegex", label: "包名正则", badge: "1.14", placeholder: "^com\\.termux.*" },
        { key: "user", label: "用户名", placeholder: "Linux only" },
        { key: "userId", label: "用户 ID", placeholder: "1000" }
      ],
      note: "进程匹配仅在 Linux、Windows 与 macOS 生效；包名匹配仅在 Android 生效。"
    },
    {
      key: "matchNetwork",
      title: "网络环境与设备",
      details: true,
      fields: [
        { key: "networkType", label: "网络类型", placeholder: "wifi, cellular, ethernet, other" },
        { key: "wifiSsid", label: "Wi-Fi SSID", type: "textarea", rows: 2, full: true },
        { key: "wifiBssid", label: "Wi-Fi BSSID", placeholder: "00:00:00:00:00:00" },
        { key: "defaultInterfaceAddress", label: "默认接口地址", placeholder: "2000::/3" },
        { key: "sourceMacAddress", label: "来源 MAC", badge: "1.14", placeholder: "00:11:22:33:44:55" },
        { key: "sourceHostname", label: "来源主机名", badge: "1.14", placeholder: "来自 DHCP 租约" }
      ],
      switches: [
        { key: "networkIsExpensive", label: "按流量计费网络", note: "network_is_expensive" },
        { key: "networkIsConstrained", label: "低数据模式", note: "network_is_constrained · Apple" }
      ],
      note: "接口地址映射类字段（interface_address、network_interface_address）请写在附加参数里。"
    },
    {
      key: "matchRuleSet",
      title: "规则集",
      details: true,
      fields: [{ key: "ruleSet", label: "规则集标签", type: "select", options: (context) => tagSelectOptions(availableRuleSetTags(), context.value?.ruleSet, "不使用规则集") }],
      switches: [{ key: "ruleSetIpCidrMatchSource", label: "规则集 IP 匹配来源", note: "rule_set_ip_cidr_match_source" }],
      note: "需要引用多个规则集时，可在附加参数里写 rule_set 数组。"
    },
    {
      key: "extra",
      title: "完整 1.14 高级参数",
      details: true,
      note: "填写官方路由规则字段组成的 JSON 对象。GeoIP、Geosite 与已弃用的 rule_set_ipcidr_match_source 会被拒绝。",
      fields: [{ key: "advancedJson", label: "附加参数 JSON", type: "textarea", rows: 5, full: true, className: "json-field", placeholder: "{}" }]
    }
  ]
};

const ROUTE_MATCH_GROUPS = ["matchDomain", "matchTraffic", "matchAddress", "matchProcess", "matchNetwork", "matchRuleSet"];

function updateRouteRuleFormVisibility() {
  const container = $("#routeRuleFields");
  if (!container) return;
  const ruleType = $('[data-field="ruleType"]', container)?.value || "default";
  const action = $('[data-field="action"]', container)?.value || "route";
  const logical = ruleType === "logical";
  setGroupVisible(container, "logical", logical);
  ROUTE_MATCH_GROUPS.forEach((key) => setGroupVisible(container, key, !logical));
  setGroupVisible(container, "routeOptions", Boolean(ROUTE_ACTION_META[action]?.options));
  setGroupVisible(container, "reject", action === "reject");
  setGroupVisible(container, "sniff", action === "sniff");
  setGroupVisible(container, "resolve", action === "resolve");
  setFieldVisible(container, "outbound", Boolean(ROUTE_ACTION_META[action]?.outbound));
}

function openRouteRuleModal(rule = null) {
  const value = normalizeRouteRule(rule || {});
  $("#routeRuleForm").reset();
  $("#routeRuleFormError").textContent = "";
  $("#routeRuleId").value = rule?.id || "";
  $("#routeRuleModalTitle").textContent = rule ? "编辑路由规则" : "添加路由规则";
  $("#routeRuleFields").innerHTML = renderSchemaForm(routeRuleSchema, value, { value });
  updateRouteRuleFormVisibility();
  $("#routeRuleModal").showModal();
}

function readRouteRuleForm() {
  const id = $("#routeRuleId").value || makeId();
  return normalizeRouteRule({
    id,
    enabled: state.route.rules.find((rule) => rule.id === id)?.enabled !== false,
    ...readSchemaForm(routeRuleSchema, $("#routeRuleFields"))
  });
}

const headlessRuleSchema = {
  groups: [
    {
      key: "headless",
      plain: true,
      fields: [
        { key: "ruleType", label: "规则项类型", type: "select", options: [["default", "普通规则"], ["logical", "逻辑规则"]] },
        { key: "mode", label: "逻辑组合", type: "select", options: [["and", "全部满足 and"], ["or", "任一满足 or"]] },
        { key: "rulesJson", label: "逻辑子规则", type: "textarea", rows: 4, full: true, className: "json-field", placeholder: '[{"domain_suffix": ".cn"}]' },
        { key: "domain", label: "完整域名", full: true, placeholder: "example.com" },
        { key: "domainSuffix", label: "域名后缀", full: true, placeholder: ".example.com" },
        { key: "domainKeyword", label: "域名关键字", full: true },
        { key: "domainRegex", label: "域名正则", type: "textarea", rows: 2, full: true },
        { key: "ipCidr", label: "IP CIDR", full: true, placeholder: "10.0.0.0/8" },
        { key: "sourceIpCidr", label: "来源 IP CIDR", full: true },
        { key: "queryType", label: "DNS 查询类型", placeholder: "A, AAAA, HTTPS" },
        { key: "network", label: "网络", placeholder: "tcp, udp, icmp" },
        { key: "port", label: "端口", placeholder: "80, 443" },
        { key: "portRange", label: "端口范围", placeholder: "1000:2000" },
        { key: "sourcePort", label: "来源端口" },
        { key: "sourcePortRange", label: "来源端口范围" },
        { key: "processName", label: "进程名", type: "textarea", rows: 2, full: true },
        { key: "processPath", label: "进程路径", type: "textarea", rows: 2, full: true },
        { key: "processPathRegex", label: "进程路径正则", type: "textarea", rows: 2, full: true },
        { key: "packageName", label: "Android 包名" },
        { key: "packageNameRegex", label: "包名正则", badge: "1.14" },
        { key: "networkType", label: "网络类型", placeholder: "wifi, cellular" },
        { key: "wifiSsid", label: "Wi-Fi SSID", type: "textarea", rows: 2, full: true },
        { key: "wifiBssid", label: "Wi-Fi BSSID" },
        { key: "defaultInterfaceAddress", label: "默认接口地址", placeholder: "2000::/3" }
      ],
      switches: [
        { key: "networkIsExpensive", label: "按流量计费网络", note: "network_is_expensive" },
        { key: "networkIsConstrained", label: "低数据模式", note: "network_is_constrained" },
        { key: "invert", label: "反转匹配结果", note: "invert" }
      ]
    }
  ]
};

let headlessDraft = [];

function headlessSummary(rule) {
  if (rule.ruleType === "logical") {
    let count = 0;
    try { count = JSON.parse(rule.rulesJson || "[]").length; } catch {}
    return `逻辑 ${rule.mode === "or" ? "或" : "与"} · ${count} 条子规则`;
  }
  const parts = [
    ["域名", rule.domain], ["后缀", rule.domainSuffix], ["关键字", rule.domainKeyword], ["正则", rule.domainRegex],
    ["IP", rule.ipCidr], ["端口", rule.port], ["进程", rule.processName], ["包名", rule.packageName], ["类型", rule.queryType]
  ].filter(([, value]) => String(value || "").trim()).map(([label, value]) => `${label} ${String(value).split(/[\n,]/)[0].trim()}`);
  return parts.length ? parts.slice(0, 3).join(" · ") : "尚未填写匹配条件";
}

function syncHeadlessDraft() {
  headlessDraft = $$(".headless-item", $("#headlessRuleList")).map((item) => normalizeHeadlessRule(readSchemaForm(headlessRuleSchema, item)));
}

function renderHeadlessRules() {
  const list = $("#headlessRuleList");
  if (!headlessDraft.length) {
    list.innerHTML = `<p class="dynamic-field-note">还没有规则项，至少需要一条。</p>`;
    return;
  }
  list.innerHTML = headlessDraft.map((rule, index) => `
    <details class="headless-item advanced-fields" data-index="${index}">
      <summary>
        <span><strong>规则项 ${index + 1}</strong><small>${escapeHtml(headlessSummary(rule))}</small></span>
        <span class="headless-summary-tools">
          <button type="button" class="icon-btn danger headless-delete" data-index="${index}" title="删除规则项" aria-label="删除规则项"><svg><use href="#i-trash"/></svg></button>
          <svg><use href="#i-chevron"/></svg>
        </span>
      </summary>
      <div class="advanced-body">${renderSchemaForm(headlessRuleSchema, rule, { value: rule })}</div>
    </details>`).join("");
}

function ruleSetSchema(type) {
  const meta = RULE_SET_TYPE_META[type];
  const basic = {
    key: "basic",
    title: "基础",
    fields: [{ key: "tag", label: "规则集标签", required: true, full: type !== "inline", placeholder: type === "inline" ? meta.prefix : "geosite-cn 或 geosite-cn, geoip-cn（1.14 多标签）" }]
  };
  if (type !== "inline") {
    basic.fields.push({ key: "format", label: "格式", type: "select", options: [["", "按扩展名判断"], ["source", "source · JSON"], ["binary", "binary · SRS"]] });
  }
  if (type === "local") {
    basic.fields.push({ key: "path", label: "文件路径", required: true, full: true, placeholder: "/etc/sing-box/geosite-cn.srs" });
  }
  if (type === "remote") {
    basic.fields.push(
      { key: "url", label: "下载地址", required: true, full: true, placeholder: "https://example.com/geosite-cn.srs" },
      { key: "updateInterval", label: "更新周期", placeholder: "默认 1d" },
      { key: "initialPath", label: "初始文件路径", badge: "1.14", placeholder: "启动时先读取本地副本" }
    );
  }
  const groups = [basic];
  if (type === "remote") {
    groups.push({
      key: "httpClient",
      title: "HTTP Client",
      badge: "1.14",
      fields: [
        { key: "httpClientMode", label: "下载客户端", type: "select", options: [["", "使用默认 HTTP Client"], ["tag", "引用顶层 http_clients 标签"], ["inline", "内联 HTTP Client 配置"]] },
        { key: "httpClientTag", label: "客户端标签", placeholder: "顶层 http_clients 中的标签" },
        { key: "httpClientJson", label: "内联客户端 JSON", type: "textarea", rows: 5, full: true, className: "json-field", placeholder: '{"detour": "direct"}' }
      ],
      note: "1.14 起隐式默认 HTTP Client 已弃用（1.16 移除），建议内联配置或引用顶层 http_clients；不提供已弃用的 download_detour。"
    });
  }
  groups.push({
    key: "extra",
    title: "完整 1.14 高级参数",
    details: true,
    note: "填写官方规则集字段组成的 JSON 对象；download_detour、geoip、geosite 会被拒绝。",
    fields: [{ key: "advancedJson", label: "附加参数 JSON", type: "textarea", rows: 4, full: true, className: "json-field", placeholder: "{}" }]
  });
  return { type, title: `${meta.label} 规则集`, intro: RULE_SET_INTRO[type], groups };
}

const RULE_SET_INTRO = {
  inline: "直接把 Headless 规则写进配置，适合少量自定义域名或 IP，不需要外部文件。",
  local: "读取本机的 source JSON 或 binary SRS 文件；1.10 起文件变更会自动重载。",
  remote: "从远程下载并按周期更新，启用 experimental.cache_file 后会缓存。AdGuard DNS Filter 需先转成 .srs。"
};

function nextRuleSetTag(type) {
  const prefix = RULE_SET_TYPE_META[type]?.prefix || "rule-set";
  const used = new Set(availableRuleSetTags());
  let tag = prefix;
  let index = 2;
  while (used.has(tag)) tag = `${prefix}-${index++}`;
  return tag;
}

function openRuleSetModal(type, set = null) {
  const schema = ruleSetSchema(type);
  const value = normalizeRuleSet(set || { type, tag: nextRuleSetTag(type) });
  $("#ruleSetForm").reset();
  $("#ruleSetFormError").textContent = "";
  $("#ruleSetType").value = type;
  $("#ruleSetId").value = set?.id || "";
  $("#ruleSetModalTitle").textContent = `${set ? "编辑" : "添加"} ${schema.title}`;
  $("#ruleSetModalVersion").textContent = `sing-box 1.14.0 · type: ${type}`;
  $("#ruleSetIntro").textContent = schema.intro;
  $("#ruleSetFields").innerHTML = renderSchemaForm(schema, value, { value });
  headlessDraft = type === "inline" ? value.headlessRules.map(normalizeHeadlessRule) : [];
  $("#headlessBlock").classList.toggle("hidden", type !== "inline");
  if (type === "inline") renderHeadlessRules();
  $("#ruleSetModal").showModal();
  $('[data-field="tag"]', $("#ruleSetFields"))?.focus();
}

function readRuleSetForm() {
  const type = $("#ruleSetType").value;
  const id = $("#ruleSetId").value || makeId();
  if (type === "inline") syncHeadlessDraft();
  return normalizeRuleSet({
    type,
    id,
    enabled: state.route.ruleSets.find((set) => set.id === id)?.enabled !== false,
    ...readSchemaForm(ruleSetSchema(type), $("#ruleSetFields")),
    headlessRules: type === "inline" ? headlessDraft : []
  });
}

function routeRuleSummary(rule) {
  if (rule.ruleType === "logical") {
    let count = 0;
    try { count = JSON.parse(rule.rulesJson || "[]").length; } catch {}
    return `逻辑 ${rule.mode === "or" ? "或" : "与"} · ${count} 条子规则`;
  }
  const conditions = [
    ["域名", rule.domain], ["后缀", rule.domainSuffix], ["关键字", rule.domainKeyword], ["正则", rule.domainRegex],
    ["规则集", rule.ruleSet], ["IP", rule.ipCidr], ["端口", rule.port], ["网络", rule.network], ["协议", rule.protocol],
    ["Clash", rule.clashMode], ["入站", rule.inbound], ["进程", rule.processName], ["偏好", rule.preferredBy]
  ].filter(([, value]) => String(value || "").trim()).map(([label, value]) => `${label} ${String(value).split(/[\n,]/)[0].trim()}`);
  if (rule.ipIsPrivate) conditions.push("私有地址");
  if (rule.sourceIpIsPrivate) conditions.push("来源私有");
  return conditions.length ? conditions.slice(0, 3).join(" · ") + (conditions.length > 3 ? ` +${conditions.length - 3}` : "") : "匹配全部流量";
}

function routeActionSummary(rule) {
  const meta = ROUTE_ACTION_META[rule.action] || ROUTE_ACTION_META.route;
  const label = meta.label.split(" · ")[0];
  if (meta.outbound && rule.outbound) return `${label} → ${rule.outbound}`;
  if (rule.action === "route") return `${label} → 未选择`;
  if (rule.action === "reject") return `${label} · ${rule.rejectMethod || "default"}`;
  if (rule.action === "resolve") return `${label}${rule.resolveServer ? ` · ${rule.resolveServer}` : ""}`;
  if (rule.action === "sniff") return `${label}${rule.sniffer ? ` · ${splitTagList(rule.sniffer).length} 个嗅探器` : " · 全部"}`;
  return label;
}

function ruleSetSummary(set) {
  const tags = splitTagList(set.tag);
  const multi = tags.length > 1 ? ` · ${tags.length} 个标签` : "";
  if (set.type === "inline") return `${set.headlessRules.length} 条规则项${multi}`;
  if (set.type === "local") return `${set.format || "按扩展名"} · ${set.path || "待填写路径"}`;
  const client = set.httpClientMode === "inline" ? " · 内联 HTTP Client" : set.httpClientMode === "tag" ? ` · ${set.httpClientTag}` : "";
  return `${set.format || "按扩展名"} · ${set.updateInterval || "1d"}${multi}${client}`;
}

function renderRouteRules() {
  const list = $("#routeRuleList");
  const rules = state.route.rules || [];
  const skipped = new Set(skippedRouteRules(state.route, availableOutboundTags()).map((rule) => rule.id));
  $("#routeRuleCount").textContent = rules.length;
  if (!rules.length) {
    list.innerHTML = `<div class="empty-endpoints"><div><svg><use href="#i-sliders"/></svg><strong>还没有路由规则</strong><small>所有流量都会走默认出站</small></div><button class="secondary-button" data-empty-add type="button">添加规则</button></div>`;
    return;
  }
  list.innerHTML = rules.map((rule, index) => {
    const enabled = rule.enabled !== false;
    const missing = skipped.has(rule.id);
    return `<article class="endpoint-item sortable-item${enabled ? "" : " is-off"}" data-id="${escapeHtml(rule.id)}" draggable="true">
      <div class="endpoint-glyph sortable-order">${index + 1}</div>
      <div class="endpoint-main">
        <div><strong>${escapeHtml(routeActionSummary(rule))}</strong>${rule.ruleType === "logical" ? '<span>logical</span>' : ""}${missing ? '<span class="warn-tag">出站缺失</span>' : ""}</div>
        <small>${escapeHtml(routeRuleSummary(rule))}</small>
      </div>
      ${sortableRowActions(rule.id, enabled)}
    </article>`;
  }).join("");
}

function renderRuleSets() {
  const list = $("#ruleSetList");
  const sets = state.route.ruleSets || [];
  $("#ruleSetCount").textContent = sets.length;
  if (!sets.length) {
    list.innerHTML = `<div class="empty-endpoints"><div><svg><use href="#i-shield"/></svg><strong>还没有规则集</strong><small>可添加 Inline、本地文件或远程规则集</small></div><button class="secondary-button" data-empty-add type="button">添加规则集</button></div>`;
    return;
  }
  list.innerHTML = sets.map((set) => {
    const meta = RULE_SET_TYPE_META[set.type] || { label: set.type };
    const enabled = set.enabled !== false;
    return `<article class="endpoint-item sortable-item${enabled ? "" : " is-off"}" data-id="${escapeHtml(set.id)}" draggable="true">
      <div class="endpoint-glyph"><svg><use href="#i-shield"/></svg></div>
      <div class="endpoint-main">
        <div><strong>${escapeHtml(splitTagList(set.tag).join(", ") || "未命名规则集")}</strong><span>${escapeHtml(meta.label)}</span></div>
        <small>${escapeHtml(ruleSetSummary(set))}</small>
      </div>
      ${sortableRowActions(set.id, enabled)}
    </article>`;
  }).join("");
}

function syncRouteOutboundOptions() {
  const select = $("#routeFinal");
  if (!select || document.activeElement === select) return;
  const tags = availableOutboundTags();
  const current = String(state.route.final || "").trim();
  select.innerHTML = [`<option value="">自动 · 有节点时用 proxy</option>`, ...tags.map((tag) => `<option value="${escapeHtml(tag)}">${escapeHtml(tag)}</option>`)].join("");
  select.value = tags.includes(current) ? current : "";
}

function syncRouteInputs() {
  const route = state.route;
  syncRouteOutboundOptions();
  $("#routeAutoDetect").value = route.autoDetectInterface || "auto";
  $("#routeDefaultInterface").value = route.defaultInterface || "";
  $("#routeDefaultMark").value = route.defaultMark || "";
  $("#routeNetworkStrategy").value = route.defaultNetworkStrategy || "";
  $("#routeNetworkType").value = route.defaultNetworkType || "";
  $("#routeFallbackNetworkType").value = route.defaultFallbackNetworkType || "";
  $("#routeFallbackDelay").value = route.defaultFallbackDelay || "";
  $("#routeDhcpLeaseFiles").value = route.dhcpLeaseFiles || "";
  $("#routeFindProcess").checked = Boolean(route.findProcess);
  $("#routeFindNeighbor").checked = Boolean(route.findNeighbor);
  $("#routeOverrideAndroidVpn").checked = Boolean(route.overrideAndroidVpn);
  updateRouteDependentFields();
}

function updateRouteDependentFields() {
  const fallback = $("#routeNetworkStrategy").value === "fallback";
  $("#routeFallbackNetworkType").disabled = !fallback;
  $("#routeFallbackNetworkType").closest(".field").classList.toggle("is-disabled", !fallback);
  const autoDetect = $("#routeAutoDetect").value === "on";
  $("#routeDefaultInterface").disabled = autoDetect;
  $("#routeDefaultInterface").closest(".field").classList.toggle("is-disabled", autoDetect);
}

function readRouteSettings() {
  state.route = {
    ...state.route,
    final: $("#routeFinal").value,
    autoDetectInterface: $("#routeAutoDetect").value,
    defaultInterface: $("#routeDefaultInterface").value.trim(),
    defaultMark: $("#routeDefaultMark").value.trim(),
    defaultNetworkStrategy: $("#routeNetworkStrategy").value,
    defaultNetworkType: $("#routeNetworkType").value.trim(),
    defaultFallbackNetworkType: $("#routeFallbackNetworkType").value.trim(),
    defaultFallbackDelay: $("#routeFallbackDelay").value.trim(),
    dhcpLeaseFiles: $("#routeDhcpLeaseFiles").value.trim(),
    findProcess: $("#routeFindProcess").checked,
    findNeighbor: $("#routeFindNeighbor").checked,
    overrideAndroidVpn: $("#routeOverrideAndroidVpn").checked
  };
}

function updateRouteSummary() {
  const rules = state.route.rules || [];
  const sets = state.route.ruleSets || [];
  // 出站暂时不存在的规则由生成器跳过，这里只当作提示，不算配置错误
  const issue = validateRouteState(state.route, { ...routeValidationContext(), outboundTags: [] });
  const skipped = skippedRouteRules(state.route, availableOutboundTags());
  const summary = $("#routeSummaryText");
  if (!summary) return;
  const skippedText = skipped.length ? ` · ${skipped.length} 条规则因出站缺失被跳过` : "";
  summary.textContent = issue || `${rules.length} 条规则 · ${sets.length} 个规则集${skippedText}`;
  summary.closest(".node-foot")?.classList.toggle("has-issue", Boolean(issue));
}

function renderRoute() {
  renderRouteRules();
  renderRuleSets();
  syncRouteInputs();
  updateRouteSummary();
}

function refreshRoute() {
  renderRoute();
  renderConfig();
}

setupSortableList("#routeRuleList", () => state.route.rules, {
  onAdd: () => openRouteRuleModal(),
  onChange: refreshRoute,
  onOpen: (rule) => openRouteRuleModal(rule),
  onDuplicate: (rule) => {
    const copy = { ...clone(rule), id: makeId() };
    state.route.rules.splice(state.route.rules.indexOf(rule) + 1, 0, copy);
    refreshRoute();
    showToast("路由规则已复制");
  },
  onDelete: (rule) => {
    if (!confirm("删除这条路由规则吗？")) return;
    state.route.rules = state.route.rules.filter((entry) => entry.id !== rule.id);
    refreshRoute();
    showToast("路由规则已删除");
  }
});

setupSortableList("#ruleSetList", () => state.route.ruleSets, {
  onAdd: () => openRuleSetTypeModal(),
  onChange: refreshRoute,
  onOpen: (set) => openRuleSetModal(set.type, set),
  onDuplicate: (set) => {
    const copy = { ...clone(set), id: makeId(), tag: nextRuleSetTag(set.type) };
    state.route.ruleSets.splice(state.route.ruleSets.indexOf(set) + 1, 0, copy);
    refreshRoute();
    showToast("规则集已复制");
  },
  onDelete: (set) => {
    const tags = splitTagList(set.tag);
    const used = (state.route.rules || []).some((rule) => splitTagList(rule.ruleSet).some((tag) => tags.includes(tag)))
      || (state.dns.rules || []).some((rule) => splitTagList(rule.ruleSet).some((tag) => tags.includes(tag)));
    if (!confirm(used ? `规则集“${tags.join(", ")}”仍被规则引用，仍要删除吗？` : `删除规则集“${tags.join(", ")}”吗？`)) return;
    state.route.ruleSets = state.route.ruleSets.filter((entry) => entry.id !== set.id);
    refreshRoute();
    renderDns();
    showToast("规则集已删除");
  }
});

function openRuleSetTypeModal() {
  $("#ruleSetTypeList").innerHTML = Object.entries(RULE_SET_TYPE_META).map(([type, meta]) => `
    <button type="button" data-rule-set-type="${escapeHtml(type)}">
      <span class="endpoint-type-icon"><svg><use href="#i-shield"/></svg></span>
      <span><strong>${escapeHtml(meta.label)}</strong><small>${escapeHtml(meta.note)}</small></span>
      <svg><use href="#i-chevron"/></svg>
    </button>`).join("");
  $("#ruleSetTypeModal").showModal();
}

$("#addRouteRuleBtn").addEventListener("click", () => openRouteRuleModal());
$("#addRouteRuleInline").addEventListener("click", () => openRouteRuleModal());
$("#addRuleSetBtn").addEventListener("click", openRuleSetTypeModal);
$("#addRuleSetInline").addEventListener("click", openRuleSetTypeModal);
$("#ruleSetTypeModal").addEventListener("click", (event) => {
  const button = event.target.closest("button[data-rule-set-type]");
  if (!button) return;
  $("#ruleSetTypeModal").close();
  openRuleSetModal(button.dataset.ruleSetType);
});

$("#routeRuleFields").addEventListener("change", (event) => {
  if (event.target.matches('[data-field="action"], [data-field="ruleType"]')) updateRouteRuleFormVisibility();
});

$("#addHeadlessRuleBtn").addEventListener("click", () => {
  syncHeadlessDraft();
  headlessDraft.push(normalizeHeadlessRule({}));
  renderHeadlessRules();
  $$(".headless-item", $("#headlessRuleList")).at(-1).open = true;
});

$("#headlessRuleList").addEventListener("click", (event) => {
  const button = event.target.closest(".headless-delete");
  if (!button) return;
  event.preventDefault();
  event.stopPropagation();
  syncHeadlessDraft();
  headlessDraft.splice(Number(button.dataset.index), 1);
  renderHeadlessRules();
});

$("#routeRuleForm").addEventListener("submit", (event) => {
  event.preventDefault();
  const rule = readRouteRuleForm();
  const error = validateRouteRule(rule, routeValidationContext());
  if (error) return $("#routeRuleFormError").textContent = error;
  const index = state.route.rules.findIndex((entry) => entry.id === rule.id);
  if (index >= 0) state.route.rules[index] = rule;
  else state.route.rules.push(rule);
  $("#routeRuleModal").close();
  refreshRoute();
  showToast(index >= 0 ? "路由规则已更新" : "路由规则已添加");
});

$("#ruleSetForm").addEventListener("submit", (event) => {
  event.preventDefault();
  const set = readRuleSetForm();
  const error = validateRuleSet(set, routeValidationContext());
  if (error) return $("#ruleSetFormError").textContent = error;
  const index = state.route.ruleSets.findIndex((entry) => entry.id === set.id);
  if (index >= 0) state.route.ruleSets[index] = set;
  else state.route.ruleSets.push(set);
  $("#ruleSetModal").close();
  refreshRoute();
  renderDns();
  showToast(index >= 0 ? "规则集已更新" : "规则集已添加");
});

const inboundUsersGroup = (type) => ({
  key: "users",
  title: "用户",
  fields: [{
    key: "usersJson",
    label: "用户列表 JSON",
    type: "textarea",
    rows: 5,
    full: true,
    className: "json-field",
    placeholder: userSample(type)
  }],
  note: "每个用户是一个对象，字段名必须与该协议一致；多出的字段会被拒绝。"
});

const inboundTlsGroup = {
  key: "tls",
  title: "TLS 服务端",
  fields: [
    { key: "tlsServerName", label: "证书域名 SNI", placeholder: "example.com" },
    { key: "tlsAlpn", label: "ALPN", placeholder: "h2, http/1.1" },
    { key: "tlsMinVersion", label: "最低 TLS 版本", type: "select", options: tlsVersionOptions },
    { key: "tlsMaxVersion", label: "最高 TLS 版本", type: "select", options: tlsVersionOptions },
    { key: "tlsCertificatePath", label: "证书路径", placeholder: "/etc/ssl/fullchain.pem" },
    { key: "tlsKeyPath", label: "私钥路径", placeholder: "/etc/ssl/privkey.pem" },
    { key: "tlsCertificate", label: "证书内容 PEM", type: "textarea", rows: 4, full: true, className: "certificate-field", placeholder: "与证书路径二选一" },
    { key: "tlsKey", label: "私钥内容 PEM", type: "textarea", rows: 4, full: true, className: "certificate-field", placeholder: "与私钥路径二选一" }
  ],
  switches: [{ key: "tlsEnabled", label: "启用 TLS", note: "QUIC 类协议必须启用" }],
  note: "ACME 已在 1.14 弃用，如需自动签发请在附加参数里使用 certificate_provider。"
};

const inboundMultiplexGroup = {
  key: "multiplex",
  title: "多路复用",
  fields: [
    { key: "brutalUp", label: "Brutal 上行 Mbps", type: "number", min: 1, placeholder: "启用 Brutal 后必填" },
    { key: "brutalDown", label: "Brutal 下行 Mbps", type: "number", min: 1, placeholder: "启用 Brutal 后必填" }
  ],
  switches: [
    { key: "multiplexEnabled", label: "启用 Multiplex", note: "multiplex.enabled" },
    { key: "multiplexPadding", label: "启用填充", note: "multiplex.padding" },
    { key: "brutalEnabled", label: "启用 TCP Brutal", note: "需要客户端同时启用" }
  ]
};

const inboundTransportGroup = {
  key: "transport",
  title: "V2Ray 传输层",
  fields: [
    { key: "transportType", label: "传输类型", type: "select", options: [["", "不使用"], ["ws", "WebSocket"], ["grpc", "gRPC"], ["http", "HTTP"], ["httpupgrade", "HTTPUpgrade"], ["quic", "QUIC"]] },
    { key: "transportPath", label: "Path", placeholder: "/path" },
    { key: "transportHost", label: "Host", placeholder: "cdn.example.com" },
    { key: "transportServiceName", label: "gRPC Service Name", placeholder: "TunService" },
    { key: "transportJson", label: "传输层附加 JSON", type: "textarea", rows: 4, full: true, className: "json-field", placeholder: "{}" }
  ]
};

const inboundExtraGroup = {
  key: "extra",
  title: "完整 1.14 高级参数",
  details: true,
  note: "填写官方入站字段组成的 JSON 对象。sniff、sniff_override_destination、domain_strategy 等已由规则动作取代的字段会被拒绝。",
  fields: [{ key: "advancedJson", label: "附加参数 JSON", type: "textarea", rows: 5, full: true, className: "json-field", placeholder: "{}" }]
};

const listenFieldPair = (port = "") => ([
  { key: "listen", label: "监听地址", placeholder: "127.0.0.1 或 0.0.0.0" },
  { key: "listenPort", label: "监听端口", type: "number", min: 1, max: 65535, placeholder: port || "必填" }
]);

const domainResolverField = {
  key: "domainResolver",
  label: "域名解析器",
  type: "select",
  options: (context) => tagSelectOptions(availableDnsServerTags(), context.value?.domainResolver, "跟随 route.default_domain_resolver")
};

const networkField = { key: "network", label: "网络", type: "select", options: [["", "TCP + UDP"], ["tcp", "仅 TCP"], ["udp", "仅 UDP"]] };

const INBOUND_FIELDS = {
  mixed: { fields: [...listenFieldPair("7890"), domainResolverField], switches: [{ key: "setSystemProxy", label: "设置为系统代理", note: "set_system_proxy · 需要系统权限" }] },
  socks: { fields: [...listenFieldPair("1080"), domainResolverField] },
  http: { fields: [...listenFieldPair("8080"), domainResolverField], switches: [{ key: "setSystemProxy", label: "设置为系统代理", note: "set_system_proxy · 需要系统权限" }] },
  direct: {
    fields: [
      ...listenFieldPair(),
      networkField,
      { key: "overrideAddress", label: "转发目标地址", placeholder: "1.1.1.1" },
      { key: "overridePort", label: "转发目标端口", type: "number", min: 1, max: 65535 }
    ]
  },
  tun: {
    fields: [
      { key: "interfaceName", label: "接口名称", placeholder: "自动，例如 tun0 / utun" },
      { key: "mtu", label: "MTU", type: "number", min: 576, placeholder: "9000" },
      { key: "address", label: "接口地址", required: true, full: true, placeholder: "172.19.0.1/30, fdfe:dcba:9876::1/126" },
      { key: "stack", label: "网络栈", type: "select", options: [["mixed", "Mixed"], ["system", "System"], ["gvisor", "gVisor"]] },
      { key: "dnsMode", label: "DNS 模式", badge: "1.14", type: "select", options: [["", "内核默认"], ["hijack", "劫持到 DNS 模块"], ["native", "使用系统解析"], ["disabled", "关闭"]] },
      { key: "dnsAddress", label: "TUN DNS 地址", placeholder: "例如 172.19.0.2" },
      { key: "netns", label: "网络命名空间", placeholder: "Linux only" }
    ],
    switches: [
      { key: "autoRoute", label: "自动配置路由", note: "auto_route" },
      { key: "strictRoute", label: "严格路由", note: "strict_route · 阻止流量绕过 TUN" },
      { key: "autoRedirect", label: "自动重定向", note: "auto_redirect · 仅 Linux，需要 auto_route" },
      { key: "excludeMptcp", label: "排除 MPTCP", note: "exclude_mptcp" }
    ]
  },
  redirect: { fields: listenFieldPair() },
  tproxy: { fields: [...listenFieldPair(), networkField] },
  shadowsocks: {
    fields: [
      ...listenFieldPair(),
      { key: "method", label: "加密方法", type: "select", options: [["2022-blake3-aes-128-gcm", "2022-blake3-aes-128-gcm"], ["2022-blake3-aes-256-gcm", "2022-blake3-aes-256-gcm"], ["2022-blake3-chacha20-poly1305", "2022-blake3-chacha20-poly1305"], ["aes-128-gcm", "aes-128-gcm"], ["aes-256-gcm", "aes-256-gcm"], ["chacha20-ietf-poly1305", "chacha20-ietf-poly1305"], ["none", "none"]] },
      { key: "password", label: "服务端密码", type: "password", full: true, placeholder: "2022 系列需要 Base64 密钥" },
      networkField
    ],
    switches: [{ key: "managed", label: "由 SSM API 托管", note: "managed" }]
  },
  vmess: { fields: listenFieldPair() },
  vless: { fields: listenFieldPair() },
  trojan: {
    fields: [
      ...listenFieldPair(),
      { key: "fallbackServer", label: "回落服务器", placeholder: "127.0.0.1" },
      { key: "fallbackPort", label: "回落端口", type: "number", min: 1, max: 65535 }
    ]
  },
  naive: {
    fields: [
      ...listenFieldPair(),
      networkField,
      { key: "quicCongestionControl", label: "QUIC 拥塞控制", type: "select", options: [["", "默认"], ["bbr", "BBR"], ["cubic", "Cubic"], ["reno", "Reno"]] }
    ]
  },
  hysteria: {
    fields: [
      ...listenFieldPair(),
      { key: "up", label: "上行带宽", placeholder: "100 Mbps" },
      { key: "down", label: "下行带宽", placeholder: "100 Mbps" },
      { key: "obfs", label: "混淆密码", full: true, placeholder: "可选" }
    ]
  },
  hysteria2: {
    fields: [
      ...listenFieldPair(),
      { key: "upMbps", label: "上行 Mbps", type: "number", min: 1 },
      { key: "downMbps", label: "下行 Mbps", type: "number", min: 1 },
      { key: "obfsType", label: "混淆类型", type: "select", options: [["", "不启用"], ["salamander", "Salamander"]] },
      { key: "obfsPassword", label: "混淆密码", type: "password" },
      { key: "masquerade", label: "伪装", full: true, placeholder: "https://example.com 或 file:///var/www 或 string:hello" },
      { key: "bbrProfile", label: "BBR 档位", type: "select", options: [["", "默认"], ["standard", "Standard"], ["conservative", "Conservative"], ["aggressive", "Aggressive"]] }
    ],
    switches: [
      { key: "ignoreClientBandwidth", label: "忽略客户端带宽", note: "ignore_client_bandwidth" },
      { key: "brutalDebug", label: "Brutal 调试日志", note: "brutal_debug" }
    ]
  },
  shadowtls: {
    fields: [
      ...listenFieldPair(),
      { key: "version", label: "协议版本", type: "select", options: [["3", "v3"], ["2", "v2"], ["1", "v1"]] },
      { key: "password", label: "v2 密码", type: "password", placeholder: "仅 v2 使用" },
      { key: "handshakeServer", label: "握手服务器", required: true, placeholder: "example.com" },
      { key: "handshakePort", label: "握手端口", type: "number", min: 1, max: 65535, placeholder: "443" },
      { key: "wildcardSni", label: "泛域名 SNI", type: "select", options: [["", "关闭"], ["off", "off"], ["authed", "authed"], ["all", "all"]] }
    ],
    switches: [{ key: "strictMode", label: "严格模式", note: "strict_mode · 仅 v3" }],
    note: "ShadowTLS 需要在下方监听字段里用 detour 指向真正处理流量的入站。"
  },
  tuic: {
    fields: [
      ...listenFieldPair(),
      { key: "congestionControl", label: "拥塞控制", type: "select", options: [["", "默认 cubic"], ["cubic", "Cubic"], ["new_reno", "New Reno"], ["bbr", "BBR"]] },
      { key: "authTimeout", label: "认证超时", placeholder: "默认 3s" },
      { key: "heartbeat", label: "心跳间隔", placeholder: "默认 10s" }
    ],
    switches: [{ key: "zeroRttHandshake", label: "0-RTT 握手", note: "zero_rtt_handshake · 有重放风险" }]
  },
  anytls: {
    fields: [
      ...listenFieldPair(),
      { key: "paddingScheme", label: "填充方案", type: "textarea", rows: 4, full: true, placeholder: "每行一条，留空使用默认方案" }
    ]
  },
  snell: {
    fields: [
      ...listenFieldPair(),
      { key: "version", label: "协议版本", type: "select", options: [["5", "v5"], ["6", "v6"]] },
      { key: "psk", label: "PSK", type: "password", placeholder: "与用户列表二选一" },
      { key: "obfsMode", label: "混淆模式", type: "select", options: [["", "不启用"], ["http", "HTTP"], ["tls", "TLS"]] },
      { key: "v6Mode", label: "v6 模式", type: "select", options: [["", "默认"], ["default", "default"], ["unshaped", "unshaped"], ["unsafe-raw", "unsafe-raw"]] }
    ]
  },
  cloudflared: {
    fields: [
      { key: "token", label: "Tunnel Token", required: true, full: true, type: "password", placeholder: "Cloudflare Zero Trust 生成的 token" },
      { key: "protocol", label: "传输协议", type: "select", options: [["", "自动"], ["auto", "auto"], ["quic", "QUIC"], ["http2", "HTTP/2"], ["h2mux", "h2mux"]] },
      { key: "haConnections", label: "高可用连接数", type: "number", min: 1, placeholder: "默认 4" },
      { key: "edgeIpVersion", label: "边缘 IP 版本", type: "select", options: [["", "自动"], ["4", "IPv4"], ["6", "IPv6"]] },
      { key: "datagramVersion", label: "Datagram 版本", type: "select", options: [["", "默认"], ["v2", "v2"], ["v3", "v3"]] },
      { key: "gracePeriod", label: "优雅退出时间", placeholder: "例如 30s" },
      { key: "region", label: "区域", placeholder: "可选" }
    ],
    switches: [{ key: "postQuantum", label: "后量子加密", note: "post_quantum" }]
  }
};

const TUN_ROUTE_GROUP = {
  key: "tunScope",
  title: "TUN 路由范围与应用过滤",
  details: true,
  fields: [
    { key: "routeAddress", label: "路由地址", full: true, placeholder: "0.0.0.0/1, 128.0.0.0/1" },
    { key: "routeExcludeAddress", label: "排除路由地址", full: true, placeholder: "192.168.0.0/16" },
    { key: "routeAddressSet", label: "路由规则集", placeholder: "规则集标签，需 auto_route" },
    { key: "routeExcludeAddressSet", label: "排除路由规则集", placeholder: "规则集标签" },
    { key: "includeInterface", label: "仅包含接口", placeholder: "en0" },
    { key: "excludeInterface", label: "排除接口", placeholder: "en1" },
    { key: "includeUid", label: "仅包含 UID", placeholder: "1000" },
    { key: "excludeUid", label: "排除 UID", placeholder: "0" },
    { key: "includeUidRange", label: "仅包含 UID 范围", placeholder: "1000:2000" },
    { key: "excludeUidRange", label: "排除 UID 范围", placeholder: "0:999" },
    { key: "includeAndroidUser", label: "包含 Android 用户", placeholder: "0" },
    { key: "includePackage", label: "仅包含应用包名", full: true, placeholder: "com.termux" },
    { key: "excludePackage", label: "排除应用包名", full: true, placeholder: "com.android.chrome" },
    { key: "includeMacAddress", label: "仅包含 MAC", placeholder: "00:11:22:33:44:55" },
    { key: "excludeMacAddress", label: "排除 MAC", placeholder: "00:11:22:33:44:66" },
    { key: "loopbackAddress", label: "回环地址", placeholder: "auto_redirect 使用" },
    { key: "iproute2TableIndex", label: "iproute2 表号", type: "number", min: 1 },
    { key: "iproute2RuleIndex", label: "iproute2 规则号", type: "number", min: 1 },
    { key: "platformJson", label: "平台参数 JSON", type: "textarea", rows: 4, full: true, className: "json-field", placeholder: '{"http_proxy": {"enabled": true, "server": "127.0.0.1", "server_port": 7890}}' }
  ],
  note: "UID、包名与 MAC 过滤只在对应平台生效；auto_redirect 相关字段仅 Linux 可用。"
};

const INBOUND_INTRO = {
  mixed: "同时提供 HTTP 与 SOCKS5 代理，最常用的本地入口。",
  socks: "仅提供 SOCKS5 代理。",
  http: "仅提供 HTTP 代理，可选启用 TLS。",
  direct: "把收到的连接转发到固定目标，常用于端口转发。",
  tun: "创建系统级虚拟网卡接管全部流量，需要管理员权限。",
  redirect: "Linux 透明代理，只处理 TCP。",
  tproxy: "Linux 透明代理，支持 TCP 与 UDP。",
  shadowsocks: "Shadowsocks 服务端，推荐使用 2022 系列加密。",
  vmess: "VMess 服务端，可搭配 TLS 与 V2Ray 传输层。",
  vless: "VLESS 服务端，可搭配 TLS、Vision 流控与传输层。",
  trojan: "Trojan 服务端，支持回落与传输层。",
  naive: "NaïveProxy 服务端，必须启用 TLS。",
  hysteria: "Hysteria v1 服务端，必须启用 TLS 并设置带宽。",
  hysteria2: "Hysteria v2 服务端，必须启用 TLS，可选 Salamander 混淆与伪装。",
  shadowtls: "为其它入站提供 TLS 握手伪装，本身不处理业务流量。",
  tuic: "TUIC v5 服务端，必须启用 TLS。",
  anytls: "AnyTLS 服务端，必须启用 TLS。",
  snell: "Snell v5 / v6 服务端。",
  cloudflared: "以 Cloudflare Tunnel 客户端接入，没有本地监听端口。"
};

function inboundSchema(type) {
  const meta = INBOUND_TYPE_META[type];
  const custom = INBOUND_FIELDS[type] || {};
  const basic = {
    key: "basic",
    title: "基础",
    fields: [{ key: "tag", label: "入站标签", required: true, placeholder: meta.prefix }, ...(custom.fields || [])],
    switches: custom.switches || [],
    note: custom.note
  };
  const groups = [basic];
  if (type === "tun") groups.push(TUN_ROUTE_GROUP);
  if (meta.users) groups.push(inboundUsersGroup(type));
  if (meta.tls) groups.push(inboundTlsGroup);
  if (meta.multiplex) groups.push(inboundMultiplexGroup);
  if (meta.transport) groups.push(inboundTransportGroup);
  if (meta.listen) groups.push(listenGroup);
  if (meta.udpNat) groups.push(udpNatGroup);
  groups.push(inboundExtraGroup);
  return { type, title: `${meta.label} 入站`, intro: INBOUND_INTRO[type] || meta.note, groups };
}

function nextInboundTag(type) {
  const prefix = INBOUND_TYPE_META[type]?.prefix || "inbound";
  const used = new Set((state.inbounds || []).map((item) => String(item.tag || "").trim()));
  let tag = prefix;
  let index = 2;
  while (used.has(tag)) tag = `${prefix}-${index++}`;
  return tag;
}

function inboundValidationContext() {
  return {
    inbounds: state.inbounds || [],
    outboundTags: availableOutboundTags(),
    dnsServerTags: availableDnsServerTags()
  };
}

function openInboundModal(type, inbound = null) {
  const schema = inboundSchema(type);
  const value = normalizeInbound(inbound || { type, tag: nextInboundTag(type) });
  $("#inboundForm").reset();
  $("#inboundFormError").textContent = "";
  $("#inboundType").value = type;
  $("#inboundId").value = inbound?.id || "";
  $("#inboundModalTitle").textContent = `${inbound ? "编辑" : "添加"} ${schema.title}`;
  $("#inboundModalVersion").textContent = `sing-box 1.14.0 · type: ${type}`;
  $("#inboundIntro").textContent = schema.intro;
  $("#inboundFields").innerHTML = renderSchemaForm(schema, value, { value });
  $("#inboundModal").showModal();
  $('[data-field="tag"]', $("#inboundFields"))?.focus();
}

function readInboundForm() {
  const type = $("#inboundType").value;
  const id = $("#inboundId").value || makeId();
  return normalizeInbound({
    type,
    id,
    enabled: (state.inbounds || []).find((item) => item.id === id)?.enabled !== false,
    ...readSchemaForm(inboundSchema(type), $("#inboundFields"))
  });
}

function inboundSummary(inbound) {
  if (inbound.type === "tun") return `${inbound.address || "待填写地址"} · ${inbound.stack || "mixed"}${inbound.autoRoute ? " · 自动路由" : ""}`;
  if (inbound.type === "cloudflared") return inbound.token ? "已配置 Tunnel Token" : "待填写 Token";
  const listen = `${inbound.listen || "::"}:${inbound.listenPort || "—"}`;
  const meta = INBOUND_TYPE_META[inbound.type];
  const parts = [listen];
  if (meta.tls && inbound.tlsEnabled) parts.push("TLS");
  if (inbound.detour) parts.push(`detour ${inbound.detour}`);
  if (meta.users) {
    let count = 0;
    try { count = JSON.parse(inbound.usersJson || "[]").length; } catch {}
    if (count) parts.push(`${count} 个用户`);
  }
  return parts.join(" · ");
}

function renderInbounds() {
  const list = $("#inboundList");
  const inbounds = state.inbounds || [];
  const sideCount = $(".main-nav button[data-scroll='inbounds'] i");
  if (sideCount) sideCount.textContent = inbounds.length;
  if (!inbounds.length) {
    list.innerHTML = `<div class="empty-endpoints"><div><svg><use href="#i-import"/></svg><strong>还没有入站</strong><small>至少需要一个入站，配置才能通过检查</small></div><button class="secondary-button" data-empty-add type="button">添加入站</button></div>`;
  } else {
    list.innerHTML = inbounds.map((inbound) => {
      const meta = INBOUND_TYPE_META[inbound.type] || { label: inbound.type };
      const enabled = inbound.enabled !== false;
      return `<article class="endpoint-item sortable-item${enabled ? "" : " is-off"}" data-id="${escapeHtml(inbound.id)}" draggable="true">
        <div class="endpoint-glyph"><svg><use href="#i-import"/></svg></div>
        <div class="endpoint-main">
          <div><strong>${escapeHtml(inbound.tag || "未命名入站")}</strong><span>${escapeHtml(meta.label)}</span>${meta.badge ? `<span class="new-badge">${escapeHtml(meta.badge)}</span>` : ""}</div>
          <small>${escapeHtml(inboundSummary(inbound))}</small>
        </div>
        ${sortableRowActions(inbound.id, enabled)}
      </article>`;
    }).join("");
  }
  const issue = validateInbounds(state.inbounds || [], inboundValidationContext());
  const summary = $("#inboundSummaryText");
  if (summary) {
    summary.textContent = issue || `${inbounds.length} 个入站 · ${activeInboundTags(inbounds).length} 个已启用`;
    summary.closest(".node-foot")?.classList.toggle("has-issue", Boolean(issue));
  }
}

function refreshInbounds() {
  renderInbounds();
  renderRoute();
  renderConfig();
}

function openInboundTypeModal() {
  const grouped = Object.entries(INBOUND_GROUP_LABELS).map(([group, label]) => {
    const items = Object.entries(INBOUND_TYPE_META).filter(([, meta]) => meta.group === group);
    if (!items.length) return "";
    return `<div class="type-group-label">${escapeHtml(label)}</div>` + items.map(([type, meta]) => `
      <button type="button" data-inbound-type="${escapeHtml(type)}">
        <span class="endpoint-type-icon"><svg><use href="#i-import"/></svg></span>
        <span><strong>${escapeHtml(meta.label)}${meta.badge ? ` · ${escapeHtml(meta.badge)}` : ""}</strong><small>${escapeHtml(meta.note)}</small></span>
        <svg><use href="#i-chevron"/></svg>
      </button>`).join("");
  }).join("");
  $("#inboundTypeList").innerHTML = grouped;
  $("#inboundTypeModal").showModal();
}

setupSortableList("#inboundList", () => state.inbounds, {
  onAdd: openInboundTypeModal,
  onChange: refreshInbounds,
  onOpen: (inbound) => openInboundModal(inbound.type, inbound),
  onDuplicate: (inbound) => {
    const copy = { ...clone(inbound), id: makeId(), tag: nextInboundTag(inbound.type) };
    state.inbounds.splice(state.inbounds.indexOf(inbound) + 1, 0, copy);
    refreshInbounds();
    showToast("入站已复制");
  },
  onDelete: (inbound) => {
    const tag = String(inbound.tag || "").trim();
    const used = (state.route.rules || []).some((rule) => splitTagList(rule.inbound).includes(tag))
      || (state.inbounds || []).some((item) => item.id !== inbound.id && String(item.detour || "").trim() === tag);
    if (!confirm(used ? `入站“${tag}”仍被规则或其它入站引用，仍要删除吗？` : `删除入站“${tag}”吗？`)) return;
    state.inbounds = state.inbounds.filter((item) => item.id !== inbound.id);
    refreshInbounds();
    showToast("入站已删除");
  }
});

$("#addInboundBtn").addEventListener("click", openInboundTypeModal);
$("#inboundTypeModal").addEventListener("click", (event) => {
  const button = event.target.closest("button[data-inbound-type]");
  if (!button) return;
  $("#inboundTypeModal").close();
  openInboundModal(button.dataset.inboundType);
});

$("#inboundForm").addEventListener("submit", (event) => {
  event.preventDefault();
  const inbound = readInboundForm();
  const error = validateInbound(inbound, inboundValidationContext());
  if (error) return $("#inboundFormError").textContent = error;
  const index = state.inbounds.findIndex((item) => item.id === inbound.id);
  if (index >= 0) state.inbounds[index] = inbound;
  else state.inbounds.push(inbound);
  $("#inboundModal").close();
  refreshInbounds();
  showToast(index >= 0 ? "入站已更新" : "入站已添加");
});

let currentConflicts = [];

function collectModuleIssues() {
  const issues = [];
  for (const node of state.nodes) {
    const error = validateOutbound(node, nodeValidationContext());
    if (error) issues.push({ level: "error", scope: "出站", message: `节点「${node.tag || "未命名"}」：${error}` });
  }
  for (const group of state.groups || []) {
    const error = validateGroup(group, groupValidationContext());
    if (error) issues.push({ level: "error", scope: "出站", message: `出站组「${group.tag || "未命名"}」：${error}` });
  }
  const inboundError = validateInbounds(state.inbounds || [], inboundValidationContext());
  if (inboundError) issues.push({ level: "error", scope: "入站", message: inboundError });
  const dnsError = validateDnsState(state.dns, dnsValidationContext());
  if (dnsError) issues.push({ level: "error", scope: "DNS", message: dnsError });
  const routeError = validateRouteState(state.route, { ...routeValidationContext(), outboundTags: [] });
  if (routeError) issues.push({ level: "error", scope: "路由", message: routeError });
  const serviceError = validateServiceState(state.serviceState, { outboundTags: availableOutboundTags() });
  if (serviceError) issues.push({ level: "error", scope: "服务", message: serviceError });
  return issues;
}

function renderConflicts(issues) {
  const block = $("#conflictBlock");
  const { errors, warnings } = summarizeConflicts(issues);
  block.classList.toggle("has-error", errors > 0);
  block.classList.toggle("has-warning", errors === 0 && warnings > 0);
  $("#conflictTitle").textContent = errors
    ? `发现 ${errors} 项冲突，修正后才能生成订阅链接`
    : warnings
      ? `${warnings} 项提醒，可以生成订阅链接`
      : "冲突检查通过";
  $("#conflictCounts").textContent = issues.length ? `错误 ${errors} · 提醒 ${warnings}` : "";
  $("#conflictList").innerHTML = issues.map((item) => `<li class="conflict-item is-${item.level}"><span class="conflict-scope">${escapeHtml(item.scope)}</span><span>${escapeHtml(item.message)}</span></li>`).join("");
  const count = $("#conflictCount");
  if (count) count.textContent = issues.length;
}

function refreshConflicts(config) {
  currentConflicts = detectConflicts(config, {
    moduleIssues: collectModuleIssues(),
    skippedRules: skippedRouteRules(state.route, availableOutboundTags()),
    clashApiAddress: config.experimental?.clash_api?.external_controller || "",
    detourCycles: detectDetourCycles(state.nodes, state.groups || [])
  });
  renderConflicts(currentConflicts);
  return currentConflicts;
}

const nodeTlsGroup = {
  key: "tls",
  title: "TLS 客户端",
  fields: [
    { key: "sni", label: "Server Name (SNI)", placeholder: "留空使用服务器地址" },
    { key: "alpn", label: "ALPN", placeholder: "h2, http/1.1" },
    { key: "fingerprint", label: "uTLS 指纹", type: "select", options: utlsOptions },
    { key: "tlsMinVersion", label: "最低 TLS 版本", type: "select", options: tlsVersionOptions },
    { key: "tlsMaxVersion", label: "最高 TLS 版本", type: "select", options: tlsVersionOptions },
    { key: "tlsCertificatePath", label: "CA 证书路径", placeholder: "/etc/ssl/cert.pem" },
    { key: "tlsCertificate", label: "CA 证书内容", type: "textarea", rows: 3, full: true, className: "certificate-field", placeholder: "与证书路径二选一" },
    { key: "tlsFragmentFallbackDelay", label: "分片回退延迟", placeholder: "默认 500ms" }
  ],
  switches: [
    { key: "tls", label: "启用 TLS", note: "QUIC 类协议必须启用" },
    { key: "insecure", label: "跳过证书验证", note: "insecure · 仅用于自签名证书" },
    { key: "disableSni", label: "不发送 SNI", note: "disable_sni" },
    { key: "tlsFragment", label: "TLS 分片", note: "tls fragment · 性能较差" },
    { key: "tlsRecordFragment", label: "TLS 记录分片", note: "record_fragment" }
  ]
};

const nodeRealityGroup = {
  key: "reality",
  title: "REALITY 与 ECH",
  details: true,
  fields: [
    { key: "publicKey", label: "REALITY Public Key", full: true },
    { key: "shortId", label: "REALITY Short ID" },
    { key: "echConfigPath", label: "ECH 配置路径" },
    { key: "echConfig", label: "ECH 配置内容", type: "textarea", rows: 3, full: true, className: "certificate-field", placeholder: "-----BEGIN ECH CONFIGS-----" }
  ],
  switches: [
    { key: "reality", label: "启用 REALITY", note: "仅 VLESS 支持，与 ECH 互斥" },
    { key: "echEnabled", label: "启用 ECH", note: "Encrypted Client Hello" }
  ]
};

const nodeEchGroup = {
  key: "ech",
  title: "ECH",
  details: true,
  fields: [
    { key: "echConfigPath", label: "ECH 配置路径" },
    { key: "echConfig", label: "ECH 配置内容", type: "textarea", rows: 3, full: true, className: "certificate-field", placeholder: "-----BEGIN ECH CONFIGS-----" }
  ],
  switches: [{ key: "echEnabled", label: "启用 ECH", note: "Encrypted Client Hello" }]
};

const nodeTransportGroup = {
  key: "transport",
  title: "V2Ray 传输层",
  fields: [
    { key: "transport", label: "传输类型", type: "select", options: [["tcp", "TCP / QUIC 默认"], ["ws", "WebSocket"], ["grpc", "gRPC"], ["http", "HTTP"], ["httpupgrade", "HTTPUpgrade"], ["quic", "QUIC"]] },
    { key: "path", label: "Path / Service name", placeholder: "/path" },
    { key: "host", label: "Host", placeholder: "cdn.example.com" },
    { key: "transportMethod", label: "HTTP Method", placeholder: "GET" },
    { key: "maxEarlyData", label: "WS 最大早期数据", type: "number", min: 0 },
    { key: "earlyDataHeaderName", label: "WS 早期数据头", placeholder: "Sec-WebSocket-Protocol" },
    { key: "transportJson", label: "传输层附加 JSON", type: "textarea", rows: 4, full: true, className: "json-field", placeholder: "{}" }
  ]
};

const nodeMultiplexGroup = {
  key: "multiplex",
  title: "多路复用",
  details: true,
  fields: [
    { key: "multiplexProtocol", label: "协议", type: "select", options: [["", "默认 h2mux"], ["h2mux", "h2mux"], ["smux", "smux"], ["yamux", "yamux"]] },
    { key: "maxConnections", label: "最大连接数", type: "number", min: 1 },
    { key: "minStreams", label: "最小流数", type: "number", min: 1 },
    { key: "maxStreams", label: "最大流数", type: "number", min: 1 },
    { key: "brutalUp", label: "Brutal 上行 Mbps", type: "number", min: 1 },
    { key: "brutalDown", label: "Brutal 下行 Mbps", type: "number", min: 1 }
  ],
  switches: [
    { key: "multiplexEnabled", label: "启用 Multiplex", note: "服务端也要开启" },
    { key: "multiplexPadding", label: "启用填充", note: "padding" },
    { key: "brutalEnabled", label: "启用 TCP Brutal", note: "需要内核模块与服务端支持" }
  ]
};

const nodeUotGroup = {
  key: "uot",
  title: "UDP over TCP",
  details: true,
  fields: [{ key: "uotVersion", label: "协议版本", type: "select", options: [["", "默认 2"], ["1", "v1"], ["2", "v2"]] }],
  switches: [{ key: "uotEnabled", label: "启用 UDP over TCP", note: "udp_over_tcp" }]
};

const nodeExtraGroup = {
  key: "extra",
  title: "完整 1.14 高级参数",
  details: true,
  note: "填写官方出站字段组成的 JSON 对象；domain_strategy 等已在 1.14 移除的字段会被拒绝。",
  fields: [{ key: "advancedJson", label: "附加参数 JSON", type: "textarea", rows: 5, full: true, className: "json-field", placeholder: "{}" }]
};

const networkOutField = { key: "network", label: "网络", type: "select", options: [["", "TCP + UDP"], ["tcp", "仅 TCP"], ["udp", "仅 UDP"]] };

const NODE_FIELDS = {
  direct: { fields: [] },
  bridge: {
    fields: [
      { key: "interface", label: "绑定接口", placeholder: "eth0" },
      { key: "bridgeName", label: "网桥名称", placeholder: "br-sing" },
      { key: "iproute2TableIndex", label: "iproute2 表号", type: "number", min: 1 },
      { key: "iproute2RuleIndex", label: "iproute2 规则号", type: "number", min: 1 }
    ]
  },
  socks: {
    fields: [
      { key: "version", label: "协议版本", type: "select", options: [["5", "SOCKS5"], ["4", "SOCKS4"], ["4a", "SOCKS4a"]] },
      { key: "username", label: "用户名" },
      { key: "password", label: "密码", type: "password" },
      networkOutField
    ]
  },
  http: {
    fields: [
      { key: "username", label: "用户名" },
      { key: "password", label: "密码", type: "password" },
      { key: "path", label: "请求路径", placeholder: "/" },
      { key: "headersJson", label: "附加请求头", type: "textarea", rows: 3, full: true, className: "json-field", placeholder: '{"User-Agent": "sing-box"}' }
    ]
  },
  shadowsocks: {
    fields: [
      { key: "method", label: "加密方法", type: "select", options: [["2022-blake3-aes-128-gcm", "2022-blake3-aes-128-gcm"], ["2022-blake3-aes-256-gcm", "2022-blake3-aes-256-gcm"], ["2022-blake3-chacha20-poly1305", "2022-blake3-chacha20-poly1305"], ["aes-128-gcm", "aes-128-gcm"], ["aes-256-gcm", "aes-256-gcm"], ["chacha20-ietf-poly1305", "chacha20-ietf-poly1305"], ["none", "none"]] },
      { key: "password", label: "密码", type: "password", full: true },
      { key: "plugin", label: "插件", placeholder: "obfs-local / v2ray-plugin" },
      { key: "pluginOpts", label: "插件参数", placeholder: "obfs=http;obfs-host=example.com" },
      networkOutField
    ]
  },
  vmess: {
    fields: [
      { key: "uuid", label: "UUID", required: true, full: true, placeholder: "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" },
      { key: "security", label: "加密方式", type: "select", options: [["auto", "auto"], ["none", "none"], ["zero", "zero"], ["aes-128-gcm", "aes-128-gcm"], ["chacha20-poly1305", "chacha20-poly1305"]] },
      { key: "alterId", label: "AlterId", type: "number", min: 0, placeholder: "0" },
      { key: "packetEncoding", label: "UDP 封装", type: "select", options: [["", "默认"], ["packetaddr", "packetaddr"], ["xudp", "xudp"]] },
      networkOutField
    ],
    switches: [
      { key: "globalPadding", label: "全局填充", note: "global_padding" },
      { key: "authenticatedLength", label: "认证长度", note: "authenticated_length" }
    ]
  },
  vless: {
    fields: [
      { key: "uuid", label: "UUID", required: true, full: true, placeholder: "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" },
      { key: "flow", label: "流控", type: "select", options: [["", "不使用"], ["xtls-rprx-vision", "xtls-rprx-vision"]] },
      { key: "packetEncoding", label: "UDP 封装", type: "select", options: [["", "默认"], ["packetaddr", "packetaddr"], ["xudp", "xudp"]] },
      networkOutField
    ]
  },
  trojan: { fields: [{ key: "password", label: "密码", type: "password", required: true, full: true }, networkOutField] },
  naive: {
    fields: [
      { key: "username", label: "用户名" },
      { key: "password", label: "密码", type: "password" },
      { key: "quicCongestionControl", label: "QUIC 拥塞控制", type: "select", options: [["", "默认"], ["bbr", "BBR"], ["bbr2", "BBR2"], ["cubic", "Cubic"], ["reno", "Reno"]] }
    ],
    switches: [{ key: "quic", label: "使用 QUIC", note: "quic" }]
  },
  hysteria: {
    fields: [
      { key: "authString", label: "认证字符串", required: true, full: true },
      { key: "up", label: "上行带宽", placeholder: "50 Mbps" },
      { key: "down", label: "下行带宽", placeholder: "100 Mbps" },
      { key: "obfs", label: "混淆密码" },
      { key: "serverPorts", label: "端口范围", placeholder: "443:8443" },
      { key: "hopInterval", label: "端口跳跃间隔", placeholder: "例如 30s" },
      networkOutField
    ]
  },
  hysteria2: {
    fields: [
      { key: "password", label: "密码", type: "password", required: true, full: true },
      { key: "upMbps", label: "上行 Mbps", type: "number", min: 1 },
      { key: "downMbps", label: "下行 Mbps", type: "number", min: 1 },
      { key: "obfsType", label: "混淆类型", type: "select", options: [["", "不启用"], ["salamander", "Salamander"]] },
      { key: "obfsPassword", label: "混淆密码", type: "password" },
      { key: "serverPorts", label: "端口范围", placeholder: "443:8443" },
      { key: "hopInterval", label: "端口跳跃间隔", placeholder: "例如 30s" },
      { key: "hopIntervalMax", label: "跳跃间隔上限", placeholder: "可选" },
      { key: "bbrProfile", label: "BBR 档位", type: "select", options: [["", "默认"], ["standard", "Standard"], ["conservative", "Conservative"], ["aggressive", "Aggressive"]] },
      networkOutField
    ],
    switches: [{ key: "brutalDebug", label: "Brutal 调试日志", note: "brutal_debug" }]
  },
  shadowtls: {
    fields: [
      { key: "version", label: "协议版本", type: "select", options: [["3", "v3"], ["2", "v2"], ["1", "v1"]] },
      { key: "password", label: "密码", type: "password", full: true }
    ],
    note: "ShadowTLS 通常配合另一个出站使用：把业务出站的 detour 指向本出站。"
  },
  tuic: {
    fields: [
      { key: "uuid", label: "UUID", required: true, full: true },
      { key: "password", label: "密码", type: "password", full: true },
      { key: "congestionControl", label: "拥塞控制", type: "select", options: [["bbr", "BBR"], ["cubic", "Cubic"], ["new_reno", "New Reno"]] },
      { key: "udpRelayMode", label: "UDP 中继模式", type: "select", options: [["native", "native"], ["quic", "quic"]] },
      { key: "heartbeat", label: "心跳间隔", placeholder: "默认 10s" },
      networkOutField
    ],
    switches: [
      { key: "udpOverStream", label: "UDP over Stream", note: "与 udp_relay_mode 互斥" },
      { key: "zeroRttHandshake", label: "0-RTT 握手", note: "有重放风险" }
    ]
  },
  anytls: {
    fields: [
      { key: "password", label: "密码", type: "password", required: true, full: true },
      { key: "idleSessionCheckInterval", label: "空闲检查间隔", placeholder: "默认 30s" },
      { key: "idleSessionTimeout", label: "空闲超时", placeholder: "默认 30s" },
      { key: "minIdleSession", label: "最小空闲会话", type: "number", min: 0 },
      { key: "clientMetadata", label: "客户端标识", placeholder: "可选" }
    ]
  },
  snell: {
    fields: [
      { key: "version", label: "协议版本", type: "select", options: [["4", "v4"], ["6", "v6"]] },
      { key: "psk", label: "PSK", type: "password", required: true, full: true },
      { key: "userKey", label: "User Key", type: "password" },
      { key: "obfsMode", label: "混淆模式", type: "select", options: [["", "不启用"], ["http", "HTTP"], ["tls", "TLS"]] },
      { key: "obfsHost", label: "混淆 Host", placeholder: "example.com" },
      { key: "v6Mode", label: "v6 模式", type: "select", options: [["", "默认"], ["default", "default"], ["unshaped", "unshaped"], ["unsafe-raw", "unsafe-raw"]] },
      networkOutField
    ],
    switches: [{ key: "reuse", label: "复用连接", note: "reuse" }]
  },
  tor: {
    fields: [
      { key: "executablePath", label: "Tor 可执行文件", placeholder: "留空使用内置" },
      { key: "dataDirectory", label: "数据目录", placeholder: "$HOME/.cache/sing-box-tor" },
      { key: "extraArgs", label: "额外参数", full: true, placeholder: "--HardwareAccel, 1" },
      { key: "torrcJson", label: "torrc 参数 JSON", type: "textarea", rows: 4, full: true, className: "json-field", placeholder: '{"UseBridges": "1"}' }
    ]
  },
  ssh: {
    fields: [
      { key: "user", label: "用户名", required: true },
      { key: "password", label: "密码", type: "password" },
      { key: "privateKeyPath", label: "私钥路径", placeholder: "~/.ssh/id_ed25519" },
      { key: "privateKeyPassphrase", label: "私钥口令", type: "password" },
      { key: "clientVersion", label: "客户端版本", placeholder: "SSH-2.0-OpenSSH_9.6" },
      { key: "hostKeyAlgorithms", label: "主机密钥算法", placeholder: "ssh-ed25519" },
      { key: "privateKey", label: "私钥内容", type: "textarea", rows: 4, full: true, className: "certificate-field" },
      { key: "hostKey", label: "已知主机密钥", type: "textarea", rows: 3, full: true, className: "certificate-field" }
    ]
  }
};

function nodeSchema(type) {
  const meta = OUTBOUND_TYPE_META[type];
  const custom = NODE_FIELDS[type] || {};
  const basic = {
    key: "basic",
    title: "基础",
    fields: [{ key: "tag", label: "出站标签", required: true, placeholder: meta.prefix }],
    switches: custom.switches || [],
    note: custom.note
  };
  if (meta.server !== false) {
    basic.fields.push(
      { key: "server", label: "服务器", required: true, placeholder: "example.com" },
      { key: "port", label: "端口", type: "number", min: 1, max: 65535, required: true }
    );
  }
  basic.fields.push(...(custom.fields || []));
  const groups = [basic];
  if (meta.tls) groups.push(nodeTlsGroup);
  if (meta.reality) groups.push(nodeRealityGroup);
  else if (meta.tls) groups.push(nodeEchGroup);
  if (meta.transport) groups.push(nodeTransportGroup);
  if (meta.multiplex) groups.push(nodeMultiplexGroup);
  if (meta.uot) groups.push(nodeUotGroup);
  groups.push(dialGroup, nodeExtraGroup);
  return { type, title: `${meta.label} 出站`, intro: meta.note, groups };
}

function nextNodeTag(type) {
  const prefix = OUTBOUND_TYPE_META[type]?.prefix || "outbound";
  const used = new Set(state.nodes.map((node) => String(node.tag || "").trim()));
  let tag = prefix;
  let index = 2;
  while (used.has(tag)) tag = `${prefix}-${index++}`;
  return tag;
}

function nodeValidationContext() {
  return {
    nodes: state.nodes,
    outboundTags: availableOutboundTags(),
    dnsServerTags: availableDnsServerTags()
  };
}

function openNodeTypeModal() {
  $("#nodeTypeList").innerHTML = Object.entries(OUTBOUND_GROUP_LABELS).map(([group, label]) => {
    const items = Object.entries(OUTBOUND_TYPE_META).filter(([, meta]) => meta.group === group);
    if (!items.length) return "";
    return `<div class="type-group-label">${escapeHtml(label)}</div>` + items.map(([type, meta]) => `
      <button type="button" data-node-type="${escapeHtml(type)}">
        <span class="endpoint-type-icon"><svg><use href="#i-activity"/></svg></span>
        <span><strong>${escapeHtml(meta.label)}${meta.badge ? ` · ${escapeHtml(meta.badge)}` : ""}</strong><small>${escapeHtml(meta.note)}</small></span>
        <svg><use href="#i-chevron"/></svg>
      </button>`).join("");
  }).join("");
  $("#nodeTypeModal").showModal();
}

function openNodeModal(node = null, forcedType = null) {
  const type = forcedType || node?.type || "trojan";
  const schema = nodeSchema(type);
  const value = normalizeOutbound(node || { type, tag: nextNodeTag(type) });
  $("#nodeForm").reset();
  $("#nodeFormError").textContent = "";
  $("#nodeTypeField").value = type;
  $("#editNodeId").value = node?.id || "";
  $("#nodeModalTitle").textContent = `${node ? "编辑" : "添加"} ${schema.title}`;
  $("#nodeModalVersion").textContent = `sing-box 1.14.0 · type: ${type}`;
  $("#nodeIntro").textContent = schema.intro;
  $("#nodeFields").innerHTML = renderSchemaForm(schema, value, { value });
  $("#nodeModal").showModal();
  $('[data-field="tag"]', $("#nodeFields"))?.focus();
}

function readNodeForm() {
  const type = $("#nodeTypeField").value;
  const id = $("#editNodeId").value || makeId();
  const existing = state.nodes.find((node) => node.id === id) || {};
  return normalizeOutbound({
    ...existing,
    type,
    id,
    enabled: existing.enabled !== false,
    ...readSchemaForm(nodeSchema(type), $("#nodeFields"))
  });
}

const groupSchema = {
  groups: [
    {
      key: "basic",
      title: "基础",
      fields: [
        { key: "type", label: "组类型", type: "select", options: Object.entries(GROUP_TYPE_META).map(([value, meta]) => [value, `${meta.label} · ${meta.note}`]) },
        { key: "tag", label: "组标签", required: true, placeholder: "proxy" },
        { key: "members", label: "手动成员", full: true, placeholder: "节点或其它出站组标签，逗号分隔" },
        { key: "defaultMember", label: "默认成员", placeholder: "仅 Selector 使用" }
      ],
      switches: [
        { key: "includeAllNodes", label: "自动包含全部节点", note: "新增节点会自动加入这个组" },
        { key: "includeDirect", label: "包含 direct", note: "允许在客户端里切换到直连" },
        { key: "interruptExistConnections", label: "切换时中断已有连接", note: "interrupt_exist_connections" }
      ]
    },
    {
      key: "urltest",
      title: "URLTest 选项",
      fields: [
        { key: "url", label: "测试地址", placeholder: "https://www.gstatic.com/generate_204" },
        { key: "interval", label: "测试间隔", placeholder: "默认 3m" },
        { key: "tolerance", label: "容差 ms", type: "number", min: 1, placeholder: "默认 50" },
        { key: "idleTimeout", label: "空闲超时", placeholder: "默认 30m" }
      ]
    },
    {
      key: "extra",
      title: "完整 1.14 高级参数",
      details: true,
      note: "填写官方出站组字段组成的 JSON 对象。",
      fields: [{ key: "advancedJson", label: "附加参数 JSON", type: "textarea", rows: 4, full: true, className: "json-field", placeholder: "{}" }]
    }
  ]
};

function updateGroupFormVisibility() {
  const container = $("#groupFields");
  if (!container) return;
  const type = $('[data-field="type"]', container)?.value || "selector";
  setGroupVisible(container, "urltest", type === "urltest");
  setFieldVisible(container, "defaultMember", type === "selector");
}

function nextGroupTag(type) {
  const prefix = GROUP_TYPE_META[type]?.prefix || "group";
  const used = new Set((state.groups || []).map((group) => String(group.tag || "").trim()));
  let tag = prefix;
  let index = 2;
  while (used.has(tag)) tag = `${prefix}-${index++}`;
  return tag;
}

function groupValidationContext() {
  return {
    groups: state.groups || [],
    nodeTags: nodeTagList(),
    groupTags: (state.groups || []).map((group) => String(group.tag || "").trim()).filter(Boolean)
  };
}

function openGroupModal(group = null) {
  const value = normalizeGroup(group || { type: "selector", tag: nextGroupTag("selector") });
  $("#groupForm").reset();
  $("#groupFormError").textContent = "";
  $("#groupId").value = group?.id || "";
  $("#groupModalTitle").textContent = group ? "编辑出站组" : "添加出站组";
  $("#groupFields").innerHTML = renderSchemaForm(groupSchema, value, { value });
  updateGroupFormVisibility();
  $("#groupModal").showModal();
}

function readGroupForm() {
  const id = $("#groupId").value || makeId();
  return normalizeGroup({
    id,
    enabled: (state.groups || []).find((group) => group.id === id)?.enabled !== false,
    ...readSchemaForm(groupSchema, $("#groupFields"))
  });
}

function groupSummary(group) {
  const members = groupMembers(group, groupValidationContext());
  const base = `${members.length} 个成员`;
  if (group.type === "urltest") return `${base} · ${group.interval || "3m"} 测试一次`;
  return `${base}${group.defaultMember ? ` · 默认 ${group.defaultMember}` : ""}`;
}

function renderGroups() {
  const list = $("#groupList");
  const groups = state.groups || [];
  $("#groupCount").textContent = groups.length;
  if (!groups.length) {
    list.innerHTML = `<div class="empty-endpoints"><div><svg><use href="#i-network"/></svg><strong>还没有出站组</strong><small>没有出站组时，路由默认出站会直接使用第一个节点</small></div><button class="secondary-button" data-empty-add type="button">添加出站组</button></div>`;
  } else {
    list.innerHTML = groups.map((group) => {
      const meta = GROUP_TYPE_META[group.type] || { label: group.type };
      const enabled = group.enabled !== false;
      const error = validateGroup(group, groupValidationContext());
      return `<article class="endpoint-item sortable-item${enabled ? "" : " is-off"}" data-id="${escapeHtml(group.id)}" draggable="true">
        <div class="endpoint-glyph"><svg><use href="#i-network"/></svg></div>
        <div class="endpoint-main">
          <div><strong>${escapeHtml(group.tag || "未命名组")}</strong><span>${escapeHtml(meta.label)}</span>${error ? '<span class="warn-tag">待修正</span>' : ""}</div>
          <small>${escapeHtml(error || groupSummary(group))}</small>
        </div>
        ${sortableRowActions(group.id, enabled)}
      </article>`;
    }).join("");
  }
  const cycles = detectDetourCycles(state.nodes, state.groups || []);
  const summary = $("#groupSummaryText");
  if (summary) {
    summary.textContent = cycles.length
      ? `检测到 detour 环路：${cycles[0].join(" → ")}`
      : `${groups.length} 个出站组 · 默认出站 ${defaultFinalOutbound()}`;
    summary.closest(".node-foot")?.classList.toggle("has-issue", cycles.length > 0);
  }
}

function refreshOutbounds() {
  renderNodes();
  renderGroups();
  renderRoute();
  renderConfig();
}

setupSortableList("#groupList", () => state.groups, {
  onAdd: () => openGroupModal(),
  onChange: refreshOutbounds,
  onOpen: (group) => openGroupModal(group),
  onDuplicate: (group) => {
    const copy = { ...clone(group), id: makeId(), tag: nextGroupTag(group.type) };
    state.groups.splice(state.groups.indexOf(group) + 1, 0, copy);
    refreshOutbounds();
    showToast("出站组已复制");
  },
  onDelete: (group) => {
    const tag = String(group.tag || "").trim();
    const used = (state.route.rules || []).some((rule) => String(rule.outbound || "").trim() === tag);
    if (!confirm(used ? `出站组“${tag}”仍被路由规则引用，仍要删除吗？` : `删除出站组“${tag}”吗？`)) return;
    state.groups = state.groups.filter((item) => item.id !== group.id);
    refreshOutbounds();
    showToast("出站组已删除");
  }
});

$("#addGroupBtn").addEventListener("click", () => openGroupModal());
$("#groupFields").addEventListener("change", (event) => {
  if (event.target.matches('[data-field="type"]')) updateGroupFormVisibility();
});

$("#nodeTypeModal").addEventListener("click", (event) => {
  const button = event.target.closest("button[data-node-type]");
  if (!button) return;
  $("#nodeTypeModal").close();
  openNodeModal(null, button.dataset.nodeType);
});

$("#nodeForm").addEventListener("submit", (event) => {
  event.preventDefault();
  const node = readNodeForm();
  const error = validateOutbound(node, nodeValidationContext());
  if (error) return $("#nodeFormError").textContent = error;
  const index = state.nodes.findIndex((item) => item.id === node.id);
  if (index >= 0) state.nodes[index] = node;
  else state.nodes.push(node);
  $("#nodeModal").close();
  refreshOutbounds();
  showToast(index >= 0 ? "出站已更新" : "出站已添加");
});

$("#groupForm").addEventListener("submit", (event) => {
  event.preventDefault();
  const group = readGroupForm();
  const error = validateGroup(group, groupValidationContext());
  if (error) return $("#groupFormError").textContent = error;
  const index = state.groups.findIndex((item) => item.id === group.id);
  if (index >= 0) state.groups[index] = group;
  else state.groups.push(group);
  $("#groupModal").close();
  refreshOutbounds();
  showToast(index >= 0 ? "出站组已更新" : "出站组已添加");
});

const SERVICE_FIELDS = {
  api: {
    fields: [
      { key: "listen", label: "监听地址", placeholder: "127.0.0.1" },
      { key: "listenPort", label: "监听端口", type: "number", min: 1, max: 65535, placeholder: "9090" },
      { key: "secret", label: "访问密钥", type: "password", placeholder: "监听非本机地址时必填" },
      { key: "allowOrigin", label: "允许来源", full: true, placeholder: "https://example.com" },
      { key: "dashboardPath", label: "面板本地目录", placeholder: "ui" },
      { key: "dashboardDownloadUrl", label: "面板下载地址", placeholder: "https://..." },
      { key: "dashboardUpdateInterval", label: "面板更新周期", placeholder: "例如 7d" }
    ],
    switches: [
      { key: "dashboardEnabled", label: "启用内置面板", note: "dashboard.enabled" },
      { key: "allowPrivateNetwork", label: "允许私有网络访问", note: "access_control_allow_private_network" }
    ]
  },
  derp: {
    fields: [
      { key: "listen", label: "监听地址", placeholder: "0.0.0.0" },
      { key: "listenPort", label: "监听端口", type: "number", min: 1, max: 65535, placeholder: "443" },
      { key: "configPath", label: "配置文件路径", placeholder: "derp.key" },
      { key: "home", label: "首页内容", placeholder: "留空使用默认页面" },
      { key: "meshPsk", label: "Mesh PSK", type: "password" },
      { key: "meshPskFile", label: "Mesh PSK 文件" },
      { key: "verifyClientEndpoint", label: "校验端点", full: true, placeholder: "Tailscale 端点标签" },
      { key: "verifyClientUrl", label: "校验 URL", full: true, placeholder: "https://controlplane.tailscale.com/verify" },
      { key: "stunListen", label: "STUN 监听地址", placeholder: "0.0.0.0" },
      { key: "stunListenPort", label: "STUN 端口", type: "number", min: 1, max: 65535, placeholder: "3478" }
    ]
  },
  resolved: {
    fields: [
      { key: "listen", label: "监听地址", placeholder: "127.0.0.1" },
      { key: "listenPort", label: "监听端口", type: "number", min: 1, max: 65535, placeholder: "53" }
    ]
  },
  "ssm-api": {
    fields: [
      { key: "listen", label: "监听地址", placeholder: "127.0.0.1" },
      { key: "listenPort", label: "监听端口", type: "number", min: 1, max: 65535, placeholder: "8080" },
      { key: "serversJson", label: "服务器映射", type: "textarea", rows: 4, full: true, className: "json-field", placeholder: '{"ss-in": "http://127.0.0.1:8080"}' },
      { key: "cachePath", label: "缓存路径", placeholder: "ssm.json" }
    ]
  },
  ccm: {
    fields: [
      { key: "listen", label: "监听地址", placeholder: "127.0.0.1" },
      { key: "listenPort", label: "监听端口", type: "number", min: 1, max: 65535 },
      { key: "credentialPath", label: "凭据路径", placeholder: "ccm.json" },
      { key: "usagesPath", label: "用量记录路径" },
      { key: "usersJson", label: "用户列表", type: "textarea", rows: 4, full: true, className: "json-field", placeholder: '[{"name": "u", "token": "t"}]' },
      { key: "headersJson", label: "附加请求头", type: "textarea", rows: 3, full: true, className: "json-field", placeholder: "{}" }
    ]
  },
  ocm: {
    fields: [
      { key: "listen", label: "监听地址", placeholder: "127.0.0.1" },
      { key: "listenPort", label: "监听端口", type: "number", min: 1, max: 65535 },
      { key: "credentialPath", label: "凭据路径", placeholder: "ocm.json" },
      { key: "usagesPath", label: "用量记录路径" },
      { key: "usersJson", label: "用户列表", type: "textarea", rows: 4, full: true, className: "json-field", placeholder: '[{"name": "u", "token": "t"}]' },
      { key: "headersJson", label: "附加请求头", type: "textarea", rows: 3, full: true, className: "json-field", placeholder: "{}" }
    ]
  },
  "hysteria-realm": {
    fields: [
      { key: "listen", label: "监听地址", placeholder: "0.0.0.0" },
      { key: "listenPort", label: "监听端口", type: "number", min: 1, max: 65535, placeholder: "443" },
      { key: "usersJson", label: "Realm 用户", type: "textarea", rows: 4, full: true, className: "json-field", placeholder: '[{"name": "u", "token": "t", "max_realms": 4}]' }
    ]
  },
  "usbip-server": {
    fields: [
      { key: "listen", label: "监听地址", placeholder: "127.0.0.1" },
      { key: "listenPort", label: "监听端口", type: "number", min: 1, max: 65535, placeholder: "3240" },
      { key: "provider", label: "设备来源", type: "select", options: [["", "默认"], ["default", "default · 固定列表"], ["dynamic", "dynamic · 自动发现"]] },
      { key: "devicesJson", label: "设备列表", type: "textarea", rows: 4, full: true, className: "json-field", placeholder: '[{"bus_id": "1-1"}]' }
    ]
  },
  "usbip-client": {
    fields: [
      { key: "server", label: "服务器地址", required: true, placeholder: "10.0.0.2" },
      { key: "serverPort", label: "服务器端口", type: "number", min: 1, max: 65535, placeholder: "3240" },
      { key: "devicesJson", label: "设备列表", type: "textarea", rows: 4, full: true, className: "json-field", placeholder: '[{"vendor_id": 1234, "product_id": 5678}]' }
    ]
  }
};

const serviceTlsGroup = {
  key: "tls",
  title: "TLS",
  fields: [
    { key: "tlsServerName", label: "证书域名", placeholder: "derp.example.com" },
    { key: "tlsCertificatePath", label: "证书路径", placeholder: "/etc/ssl/fullchain.pem" },
    { key: "tlsKeyPath", label: "私钥路径", placeholder: "/etc/ssl/privkey.pem" },
    { key: "tlsCertificate", label: "证书内容", type: "textarea", rows: 3, full: true, className: "certificate-field" },
    { key: "tlsKey", label: "私钥内容", type: "textarea", rows: 3, full: true, className: "certificate-field" }
  ],
  switches: [{ key: "tlsEnabled", label: "启用 TLS", note: "Hysteria Realm 必须启用；DERP 直接对外时也应启用" }]
};

const serviceExtraGroup = {
  key: "extra",
  title: "完整 1.14 高级参数",
  details: true,
  note: "填写官方服务字段组成的 JSON 对象；已迁移到全局 cache_file 的旧字段会被拒绝。",
  fields: [{ key: "advancedJson", label: "附加参数 JSON", type: "textarea", rows: 4, full: true, className: "json-field", placeholder: "{}" }]
};

function serviceSchema(type) {
  const meta = SERVICE_TYPE_META[type];
  const custom = SERVICE_FIELDS[type] || {};
  const basic = {
    key: "basic",
    title: "基础",
    fields: [{ key: "tag", label: "服务标签", required: true, placeholder: meta.prefix }, ...(custom.fields || [])],
    switches: custom.switches || []
  };
  const groups = [basic];
  if (meta.tls) groups.push(serviceTlsGroup);
  if (meta.listen) groups.push(listenGroup);
  groups.push(serviceExtraGroup);
  return { type, title: `${meta.label} 服务`, intro: meta.note, groups };
}

function serviceState() {
  return normalizeServiceState(state.serviceState);
}

function nextServiceTag(type) {
  const prefix = SERVICE_TYPE_META[type]?.prefix || "service";
  const used = new Set((state.serviceState.services || []).map((item) => String(item.tag || "").trim()));
  let tag = prefix;
  let index = 2;
  while (used.has(tag)) tag = `${prefix}-${index++}`;
  return tag;
}

function serviceValidationContext() {
  return { services: state.serviceState.services || [], outboundTags: availableOutboundTags() };
}

function openServiceTypeModal() {
  $("#serviceTypeList").innerHTML = Object.entries(SERVICE_TYPE_META).map(([type, meta]) => `
    <button type="button" data-service-type="${escapeHtml(type)}">
      <span class="endpoint-type-icon"><svg><use href="#i-terminal"/></svg></span>
      <span><strong>${escapeHtml(meta.label)}</strong><small>${escapeHtml(meta.note)}</small></span>
      <svg><use href="#i-chevron"/></svg>
    </button>`).join("");
  $("#serviceTypeModal").showModal();
}

function openServiceModal(type, service = null) {
  const schema = serviceSchema(type);
  const value = normalizeService(service || { type, tag: nextServiceTag(type) });
  $("#serviceForm").reset();
  $("#serviceFormError").textContent = "";
  $("#serviceType").value = type;
  $("#serviceId").value = service?.id || "";
  $("#serviceModalTitle").textContent = `${service ? "编辑" : "添加"} ${schema.title}`;
  $("#serviceModalVersion").textContent = `sing-box 1.14.0 · type: ${type}`;
  $("#serviceIntro").textContent = schema.intro;
  $("#serviceFields").innerHTML = renderSchemaForm(schema, value, { value });
  $("#serviceModal").showModal();
  $('[data-field="tag"]', $("#serviceFields"))?.focus();
}

function readServiceForm() {
  const type = $("#serviceType").value;
  const id = $("#serviceId").value || makeId();
  return normalizeService({
    type,
    id,
    enabled: (state.serviceState.services || []).find((item) => item.id === id)?.enabled !== false,
    ...readSchemaForm(serviceSchema(type), $("#serviceFields"))
  });
}

function serviceSummary(service) {
  const meta = SERVICE_TYPE_META[service.type];
  if (service.type === "usbip-client") return `${service.server || "待填写"}:${service.serverPort || 3240}`;
  const listen = `${service.listen || "::"}:${service.listenPort || "—"}`;
  return `${listen}${meta.tls && service.tlsEnabled ? " · TLS" : ""}`;
}

function renderServices() {
  const list = $("#serviceList");
  const services = state.serviceState.services || [];
  $("#serviceCount").textContent = services.length;
  const sideCount = $(".main-nav button[data-scroll='services'] i");
  if (sideCount) sideCount.textContent = services.length;
  if (!services.length) {
    list.innerHTML = `<div class="empty-endpoints"><div><svg><use href="#i-terminal"/></svg><strong>还没有服务</strong><small>可添加 sing-box API、DERP、Resolved、SSM API 等</small></div><button class="secondary-button" data-empty-add type="button">添加服务</button></div>`;
  } else {
    list.innerHTML = services.map((service) => {
      const meta = SERVICE_TYPE_META[service.type] || { label: service.type };
      const enabled = service.enabled !== false;
      const error = validateService(service, serviceValidationContext());
      return `<article class="endpoint-item sortable-item${enabled ? "" : " is-off"}" data-id="${escapeHtml(service.id)}" draggable="true">
        <div class="endpoint-glyph"><svg><use href="#i-terminal"/></svg></div>
        <div class="endpoint-main">
          <div><strong>${escapeHtml(service.tag || "未命名服务")}</strong><span>${escapeHtml(meta.label)}</span>${error ? '<span class="warn-tag">待修正</span>' : ""}</div>
          <small>${escapeHtml(error || serviceSummary(service))}</small>
        </div>
        ${sortableRowActions(service.id, enabled)}
      </article>`;
    }).join("");
  }
  const issue = validateServiceState(state.serviceState, { outboundTags: availableOutboundTags() });
  const summary = $("#serviceSummaryText");
  if (summary) {
    summary.textContent = issue || `${services.length} 个服务 · 缓存${state.serviceState.cacheEnabled ? "已启用" : "未启用"}`;
    summary.closest(".node-foot")?.classList.toggle("has-issue", Boolean(issue));
  }
}

const SERVICE_TEXT_FIELDS = [
  "ntpServer", "ntpServerPort", "ntpInterval", "certificatePath", "certificateDirectoryPath", "cachePath", "cacheId",
  "cacheRdrcTimeout", "clashController", "clashSecret", "clashExternalUi", "clashExternalUiDownloadUrl", "clashAllowOrigin",
  "v2rayListen", "v2rayStatsInbounds", "v2rayStatsOutbounds"
];
const SERVICE_SELECT_FIELDS = ["certificateStore", "clashDefaultMode"];
const SERVICE_SWITCH_FIELDS = [
  "ntpEnabled", "ntpWriteToSystem", "cacheEnabled", "cacheStoreFakeip", "cacheStoreDns", "clashEnabled",
  "clashAllowPrivateNetwork", "v2rayEnabled", "v2rayStats"
];

function syncServiceInputs() {
  const value = serviceState();
  for (const key of [...SERVICE_TEXT_FIELDS, ...SERVICE_SELECT_FIELDS]) {
    const input = $(`#${key}`);
    if (input) input.value = value[key] ?? "";
  }
  for (const key of SERVICE_SWITCH_FIELDS) {
    const input = $(`#${key}`);
    if (input) input.checked = Boolean(value[key]);
  }
  const detour = $("#ntpDetour");
  if (detour && document.activeElement !== detour) {
    const tags = availableOutboundTags();
    const current = String(value.ntpDetour || "").trim();
    detour.innerHTML = [`<option value="">默认出站</option>`, ...tags.map((tag) => `<option value="${escapeHtml(tag)}">${escapeHtml(tag)}</option>`)].join("");
    detour.value = tags.includes(current) ? current : "";
  }
}

function readServiceSettings() {
  const next = { ...state.serviceState };
  for (const key of [...SERVICE_TEXT_FIELDS, ...SERVICE_SELECT_FIELDS]) {
    const input = $(`#${key}`);
    if (input) next[key] = input.value.trim();
  }
  for (const key of SERVICE_SWITCH_FIELDS) {
    const input = $(`#${key}`);
    if (input) next[key] = input.checked;
  }
  const detour = $("#ntpDetour");
  if (detour) next.ntpDetour = detour.value;
  state.serviceState = next;
}

function refreshServices() {
  renderServices();
  renderConfig();
}

setupSortableList("#serviceList", () => state.serviceState.services, {
  onAdd: openServiceTypeModal,
  onChange: refreshServices,
  onOpen: (service) => openServiceModal(service.type, service),
  onDuplicate: (service) => {
    const copy = { ...clone(service), id: makeId(), tag: nextServiceTag(service.type) };
    state.serviceState.services.splice(state.serviceState.services.indexOf(service) + 1, 0, copy);
    refreshServices();
    showToast("服务已复制");
  },
  onDelete: (service) => {
    if (!confirm(`删除服务“${service.tag}”吗？`)) return;
    state.serviceState.services = state.serviceState.services.filter((item) => item.id !== service.id);
    refreshServices();
    showToast("服务已删除");
  }
});

$("#addServiceBtn").addEventListener("click", openServiceTypeModal);
$("#addServiceInline").addEventListener("click", openServiceTypeModal);
$("#serviceTypeModal").addEventListener("click", (event) => {
  const button = event.target.closest("button[data-service-type]");
  if (!button) return;
  $("#serviceTypeModal").close();
  openServiceModal(button.dataset.serviceType);
});

$("#serviceForm").addEventListener("submit", (event) => {
  event.preventDefault();
  const service = readServiceForm();
  const error = validateService(service, serviceValidationContext());
  if (error) return $("#serviceFormError").textContent = error;
  const services = state.serviceState.services || [];
  const index = services.findIndex((item) => item.id === service.id);
  if (index >= 0) services[index] = service;
  else services.push(service);
  state.serviceState.services = services;
  $("#serviceModal").close();
  refreshServices();
  showToast(index >= 0 ? "服务已更新" : "服务已添加");
});

function renderImportReport(container, notices, counts) {
  const summary = counts
    ? `<li class="conflict-item"><span class="conflict-scope">统计</span><span>${counts.inbounds} 入站 · ${counts.nodes} 节点 · ${counts.groups} 出站组 · ${counts.endpoints} 端点 · ${counts.dnsServers} DNS Server · ${counts.dnsRules} DNS 规则 · ${counts.routeRules} 路由规则 · ${counts.ruleSets} 规则集 · ${counts.services} 服务</span></li>`
    : "";
  container.innerHTML = `<ul class="conflict-list">${summary}${notices.map((item) => `<li class="conflict-item is-${item.level}"><span class="conflict-scope">${item.level === "error" ? "错误" : "提示"}</span><span>${escapeHtml(item.message)}</span></li>`).join("")}</ul>`;
  container.classList.remove("hidden");
}

let pendingImport = null;

function previewImport(text) {
  $("#importConfigError").textContent = "";
  pendingImport = null;
  if (!text.trim()) {
    $("#importReport").classList.add("hidden");
    return;
  }
  try {
    const result = importConfig(JSON.parse(text));
    pendingImport = result;
    renderImportReport($("#importReport"), result.notices, result.counts);
  } catch (error) {
    $("#importReport").classList.add("hidden");
    $("#importConfigError").textContent = error.message;
  }
}

$("#importConfigBtn").addEventListener("click", () => {
  $("#importConfigForm").reset();
  $("#importConfigError").textContent = "";
  $("#importReport").classList.add("hidden");
  pendingImport = null;
  $("#importConfigModal").showModal();
});

$("#importConfigText").addEventListener("input", (event) => previewImport(event.target.value));
$("#importConfigFile").addEventListener("change", async (event) => {
  const file = event.target.files?.[0];
  if (!file) return;
  const text = await file.text();
  $("#importConfigText").value = text;
  previewImport(text);
});

$("#importConfigForm").addEventListener("submit", (event) => {
  event.preventDefault();
  if (!pendingImport) {
    previewImport($("#importConfigText").value);
    if (!pendingImport) return;
  }
  if (!confirm("导入会覆盖当前浏览器里的全部配置，确定继续吗？")) return;
  const imported = pendingImport.state;
  state = {
    settings: { ...clone(defaultState.settings), ...imported.settings },
    subscriptions: [],
    nodes: imported.nodes,
    groups: imported.groups,
    endpoints: imported.endpoints,
    inbounds: imported.inbounds,
    dns: imported.dns,
    route: imported.route,
    serviceState: imported.serviceState
  };
  saveSnapshot("导入配置前");
  $("#importConfigModal").close();
  renderAllPanels();
  const warnings = pendingImport.notices.length;
  showToast(`已导入配置${warnings ? `，${warnings} 条提示` : ""}`, Boolean(warnings));
  pendingImport = null;
});

$("#exportLinksBtn").addEventListener("click", () => {
  const { links, skipped } = exportShareLinks(state.nodes);
  $("#exportLinksText").value = links.join("\n");
  $("#exportLinksMeta").textContent = `${links.length} 个节点可导出`;
  $("#exportLinksSkipped").textContent = skipped.length
    ? `${skipped.length} 个节点没有通用分享链接：${skipped.map((item) => item.tag).join("、")}`
    : "全部节点均可导出";
  $("#exportLinksModal").showModal();
});

$("#copyLinksBtn").addEventListener("click", () => copyText($("#exportLinksText").value));

function readTidyOptions() {
  return {
    include: $("#tidyInclude").value,
    exclude: $("#tidyExclude").value,
    prefix: $("#tidyPrefix").value,
    suffix: $("#tidySuffix").value,
    search: $("#tidySearch").value,
    replace: $("#tidyReplace").value,
    dedupe: $("#tidyDedupe").checked
  };
}

function applyTidy(nodes, options) {
  const filtered = filterNodes(nodes, options);
  let result = filtered.nodes;
  let removedByDedupe = 0;
  if (options.dedupe) {
    const deduped = dedupeNodes(result);
    result = deduped.nodes;
    removedByDedupe = deduped.removed;
  }
  const keptIds = new Set(result.map((node) => node.id));
  const removedTags = nodes.filter((node) => !keptIds.has(node.id)).map((node) => String(node.tag || ""));
  if (options.prefix || options.suffix || options.search) result = renameNodes(result, options);
  return { nodes: result, removedByFilter: filtered.removed, removedByDedupe, removedTags };
}

$("#tidyNodesBtn").addEventListener("click", () => {
  $("#tidyForm").reset();
  $("#tidyDedupe").checked = true;
  $("#tidyError").textContent = "";
  $("#tidyPreview").innerHTML = "";
  $("#tidyModal").showModal();
});

$("#tidyPreviewBtn").addEventListener("click", () => {
  const options = readTidyOptions();
  const result = applyTidy(state.nodes, options);
  const renamed = result.nodes.filter((node, index) => node.tag !== state.nodes.find((item) => item.id === node.id)?.tag).length;
  $("#tidyPreview").innerHTML = `<ul class="conflict-list">
    <li class="conflict-item"><span class="conflict-scope">结果</span><span>${state.nodes.length} → ${result.nodes.length} 个节点</span></li>
    ${result.removedByFilter ? `<li class="conflict-item is-warning"><span class="conflict-scope">过滤</span><span>移除 ${result.removedByFilter} 个</span></li>` : ""}
    ${result.removedByDedupe ? `<li class="conflict-item is-warning"><span class="conflict-scope">去重</span><span>移除 ${result.removedByDedupe} 个</span></li>` : ""}
    ${renamed ? `<li class="conflict-item"><span class="conflict-scope">重命名</span><span>${renamed} 个节点</span></li>` : ""}
    ${result.removedTags.length ? `<li class="conflict-item"><span class="conflict-scope">将删除</span><span>${escapeHtml(result.removedTags.slice(0, 8).join("、"))}${result.removedTags.length > 8 ? " …" : ""}</span></li>` : ""}
  </ul>`;
});

$("#tidyForm").addEventListener("submit", (event) => {
  event.preventDefault();
  const options = readTidyOptions();
  const result = applyTidy(state.nodes, options);
  if (!result.nodes.length) return $("#tidyError").textContent = "整理后没有剩下任何节点，请调整条件";
  state.nodes = result.nodes.map(normalizeOutbound);
  $("#tidyModal").close();
  refreshOutbounds();
  showToast(`整理完成：${result.nodes.length} 个节点`);
});

const SNAPSHOT_KEY = `${STORAGE_KEY}:snapshot`;

function saveSnapshot(reason) {
  try {
    localStorage.setItem(SNAPSHOT_KEY, JSON.stringify({ reason, savedAt: Date.now(), state }));
  } catch {}
}

function readSnapshot() {
  try {
    return JSON.parse(localStorage.getItem(SNAPSHOT_KEY));
  } catch {
    return null;
  }
}

function renderAllPanels() {
  syncInputsFromState();
  renderNodes();
  renderGroups();
  renderEndpoints();
  renderInbounds();
  renderDns();
  renderRoute();
  renderServices();
  renderConfig();
}

function currentBackup() {
  return JSON.stringify({ version: 1, exportedAt: new Date().toISOString(), state }, null, 2);
}

$("#backupBtn").addEventListener("click", () => {
  $("#backupForm").reset();
  $("#backupError").textContent = "";
  $("#backupText").value = currentBackup();
  const snapshot = readSnapshot();
  const restoreSnapshot = $("#restoreSnapshotBtn");
  if (snapshot) {
    restoreSnapshot.classList.remove("hidden");
    restoreSnapshot.textContent = `回到自动备份（${snapshot.reason} · ${new Intl.DateTimeFormat("zh-CN", { month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit" }).format(new Date(snapshot.savedAt))}）`;
  } else {
    restoreSnapshot.classList.add("hidden");
  }
  $("#backupModal").showModal();
});

$("#restoreSnapshotBtn").addEventListener("click", () => {
  const snapshot = readSnapshot();
  if (!snapshot?.state) return showToast("没有可用的自动备份", true);
  $("#backupText").value = JSON.stringify({ version: 1, exportedAt: new Date(snapshot.savedAt).toISOString(), state: snapshot.state }, null, 2);
  showToast("已载入自动备份，点击恢复应用");
});

$("#backupFile").addEventListener("change", async (event) => {
  const file = event.target.files?.[0];
  if (!file) return;
  $("#backupText").value = await file.text();
});

$("#downloadBackupBtn").addEventListener("click", () => {
  downloadText(currentBackup(), `${safeFilename(state.settings.profileName)}-backup.json`);
  showToast("备份已下载");
});

$("#backupForm").addEventListener("submit", (event) => {
  event.preventDefault();
  let parsed;
  try {
    parsed = JSON.parse($("#backupText").value);
  } catch (error) {
    return $("#backupError").textContent = `备份内容不是有效 JSON：${error.message}`;
  }
  const restored = parsed?.state || parsed;
  if (!restored?.settings || !Array.isArray(restored.nodes)) return $("#backupError").textContent = "备份内容不是本工具导出的状态";
  if (!confirm("恢复会覆盖当前浏览器里的全部配置，确定继续吗？")) return;
  saveSnapshot("恢复备份前");
  localStorage.setItem(STORAGE_KEY, JSON.stringify(restored));
  state = loadState();
  $("#backupModal").close();
  renderAllPanels();
  showToast("配置已恢复");
});

function setActiveSection(sectionId) {
  const activeButton = $(`.main-nav button[data-scroll="${sectionId}"]`);
  if (!activeButton) return;
  $$(".main-nav button").forEach((item) => {
    const active = item === activeButton;
    item.classList.toggle("active", active);
    if (active) item.setAttribute("aria-current", "page");
    else item.removeAttribute("aria-current");
  });
  $("#currentSectionTitle").textContent = activeButton.dataset.title;
}

$$('[data-scroll]').forEach((button) => button.addEventListener("click", () => {
  setActiveSection(button.dataset.scroll);
  document.getElementById(button.dataset.scroll)?.scrollIntoView({ behavior: "smooth", block: "start" });
  $(".sidebar").classList.remove("open");
}));

const navigableSections = $$('[data-scroll]').map((button) => document.getElementById(button.dataset.scroll)).filter(Boolean);
function updateActiveNavigation() {
  const marker = window.scrollY + 150;
  let current = navigableSections[0];
  for (const section of navigableSections) {
    if (section.offsetTop <= marker) current = section;
  }
  if (current) setActiveSection(current.id);
}
window.addEventListener("scroll", updateActiveNavigation, { passive: true });

$("#mobileMenu").addEventListener("click", () => $(".sidebar").classList.toggle("open"));
document.addEventListener("click", (event) => {
  if (innerWidth <= 820 && $(".sidebar").classList.contains("open") && !event.target.closest(".sidebar") && !event.target.closest("#mobileMenu")) {
    $(".sidebar").classList.remove("open");
  }
});

syncInputsFromState();
renderNodes();
renderGroups();
renderEndpoints();
renderInbounds();
renderDns();
renderRoute();
renderServices();
renderConfig();
updateActiveNavigation();
