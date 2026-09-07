// 跨模块冲突检查：把各模块自身的校验，与只有放在一起才能发现的冲突汇总成一份清单。
// level 为 error 的条目会阻止生成订阅链接。

const WILDCARD = new Set(["", "0.0.0.0", "::", "[::]"]);

function issue(level, scope, message) {
  return { level, scope, message };
}

function listenKey(inbound) {
  return `${String(inbound.listen ?? "")}|${inbound.listen_port ?? ""}`;
}

function listenerNetworks(inbound) {
  if (["direct", "tproxy", "shadowsocks"].includes(inbound.type)) return [].concat(inbound.network || ["tcp", "udp"]);
  if (["hysteria", "hysteria2", "tuic"].includes(inbound.type) || inbound.transport?.type === "quic") return ["udp"];
  if (["mixed", "socks", "http", "redirect", "vmess", "vless", "trojan", "naive", "shadowtls", "anytls", "snell"].includes(inbound.type)) return ["tcp"];
  return ["tcp", "udp"];
}

function conflictingListen(a, b) {
  if (!a.listen_port || !b.listen_port || a.listen_port !== b.listen_port) return false;
  if (!listenerNetworks(a).some(network => listenerNetworks(b).includes(network))) return false;
  const addressA = String(a.listen ?? "").replace(/^\[|\]$/g, "");
  const addressB = String(b.listen ?? "").replace(/^\[|\]$/g, "");
  if (addressA === addressB) return true;
  return WILDCARD.has(addressA) || WILDCARD.has(addressB);
}

function collectDuplicates(values) {
  const seen = new Set();
  const duplicates = new Set();
  for (const value of values) {
    if (seen.has(value)) duplicates.add(value);
    seen.add(value);
  }
  return [...duplicates];
}

function checkTags(config) {
  const issues = [];
  const inbounds = (config.inbounds || []).map((item) => item.tag).filter(Boolean);
  for (const tag of collectDuplicates(inbounds)) issues.push(issue("error", "入站", `入站标签重复：${tag}`));
  const outbounds = [...(config.outbounds || []), ...(config.endpoints || [])].map((item) => item.tag).filter(Boolean);
  for (const tag of collectDuplicates(outbounds)) issues.push(issue("error", "出站", `出站或端点标签重复：${tag}`));
  const dnsServers = (config.dns?.servers || []).map((item) => item.tag).filter(Boolean);
  for (const tag of collectDuplicates(dnsServers)) issues.push(issue("error", "DNS", `DNS Server 标签重复：${tag}`));
  const ruleSets = (config.route?.rule_set || []).flatMap((item) => (Array.isArray(item.tag) ? item.tag : [item.tag])).filter(Boolean);
  for (const tag of collectDuplicates(ruleSets)) issues.push(issue("error", "路由", `规则集标签重复：${tag}`));
  return issues;
}

function checkListen(config, { clashApiAddress = "" } = {}) {
  const issues = [];
  const listeners = (config.inbounds || []).filter((inbound) => inbound.listen_port);
  for (let i = 0; i < listeners.length; i += 1) {
    for (let j = i + 1; j < listeners.length; j += 1) {
      if (conflictingListen(listeners[i], listeners[j])) {
        issues.push(issue("error", "入站", `入站「${listeners[i].tag}」与「${listeners[j].tag}」监听地址冲突：${listenKey(listeners[i]).replace("|", ":")}`));
      }
    }
  }
  if (clashApiAddress) {
    const colon = clashApiAddress.lastIndexOf(":");
    const apiHost = clashApiAddress.slice(0, colon);
    const apiPort = clashApiAddress.slice(colon + 1);
    const clash = { type: "http", listen: apiHost, listen_port: Number(apiPort) };
    for (const inbound of listeners) {
      if (conflictingListen(inbound, clash)) {
        issues.push(issue("error", "入站", `入站「${inbound.tag}」占用了 Clash API 的 ${clashApiAddress}`));
      }
    }
  }
  return issues;
}

function checkTun(config) {
  const issues = [];
  const tuns = (config.inbounds || []).filter((inbound) => inbound.type === "tun");
  if (tuns.length > 1) {
    const names = tuns.map((inbound) => inbound.interface_name || "");
    const level = collectDuplicates(names).length || names.includes("") ? "error" : "warning";
    issues.push(issue(level, "入站", `配置了 ${tuns.length} 个 TUN 入站${level === "error" ? "，接口名相同或未指定会互相冲突" : "，请确认系统允许同时创建多个虚拟网卡"}`));
  }
  if (!tuns.length) return issues;

  const route = config.route || {};
  if (!route.auto_detect_interface && !route.default_interface) {
    issues.push(issue("error", "路由", "启用 TUN 时必须开启自动检测接口或指定固定默认接口，否则出站流量会被 TUN 再次接管造成路由环路"));
  }
  const redirects = (config.inbounds || []).filter((inbound) => ["redirect", "tproxy"].includes(inbound.type));
  if (redirects.length && tuns.some((inbound) => inbound.auto_redirect)) {
    issues.push(issue("warning", "入站", `TUN 已启用 auto_redirect，与 ${redirects.map((item) => item.tag).join("、")} 的透明代理可能重复接管同一批流量`));
  }
  const hijacksDns = (route.rules || []).some((rule) => rule.action === "hijack-dns");
  const tunHandlesDns = tuns.some((inbound) => inbound.dns_mode === "hijack" || inbound.dns_mode === "native");
  if (!hijacksDns && !tunHandlesDns) {
    issues.push(issue("warning", "路由", "TUN 下没有 hijack-dns 规则，客户端 DNS 请求不会进入 sing-box 的 DNS 模块"));
  }
  return issues;
}

function checkDns(config) {
  const issues = [];
  const servers = config.dns?.servers || [];
  const fakeip = servers.filter((server) => server.type === "fakeip");
  const fakeipTags = fakeip.map((server) => server.tag);
  if (!fakeipTags.length) return issues;
  if (fakeipTags.length > 1) issues.push(issue("error", "DNS", "sing-box 1.14 不支持同时启用多个 FakeIP Server，请只保留一个启用项"));

  const resolver = config.route?.default_domain_resolver;
  const resolverTag = typeof resolver === "object" ? resolver?.server : resolver;
  if (resolverTag && fakeipTags.includes(resolverTag)) {
    issues.push(issue("error", "DNS", `默认域名解析器不能指向 FakeIP 服务器「${resolverTag}」，出站连接会拿到虚拟地址`));
  }
  if (config.dns?.final && fakeipTags.includes(config.dns.final)) {
    issues.push(issue("warning", "DNS", `dns.final 指向 FakeIP 服务器「${config.dns.final}」，所有未命中规则的查询都会返回虚拟地址`));
  }
  const referenced = new Set([
    ...(config.dns?.rules || []).map((rule) => rule.server).filter(Boolean),
    ...(config.route?.rules || []).filter((rule) => rule.action === "resolve").map((rule) => rule.server).filter(Boolean),
    config.dns?.final
  ]);
  const unused = fakeipTags.filter((tag) => !referenced.has(tag));
  if (unused.length) {
    issues.push(issue("warning", "DNS", `FakeIP 服务器「${unused.join("、")}」没有被任何 DNS 规则或 dns.final 使用，不会生效`));
  }
  const inUse = fakeipTags.some((tag) => referenced.has(tag));
  if (inUse && config.dns?.reverse_mapping) {
    issues.push(issue("warning", "DNS", "FakeIP 与反向映射同时启用时，反向映射不会带来额外效果"));
  }
  return issues;
}

function checkRoute(config, { skippedRules = [] } = {}) {
  const issues = [];
  if (config.route?.auto_detect_interface && config.route?.default_interface) issues.push(issue("error", "路由", "自动检测接口与固定默认接口只能选择一个"));
  const inboundTags = (config.inbounds || []).map((item) => item.tag).filter(Boolean);
  const routableTags = [...(config.outbounds || []), ...(config.endpoints || [])].map((item) => item.tag).filter(Boolean);
  const dnsTags = (config.dns?.servers || []).map((item) => item.tag).filter(Boolean);
  const ruleSetTags = (config.route?.rule_set || []).flatMap((item) => (Array.isArray(item.tag) ? item.tag : [item.tag])).filter(Boolean);

  function nestedRules(rules = [], scope) {
    if (!Array.isArray(rules)) {
      issues.push(issue("error", scope, "逻辑子规则必须是对象数组"));
      return [];
    }
    return rules.flatMap((rule) => {
      if (!rule || typeof rule !== "object" || Array.isArray(rule)) {
        issues.push(issue("error", scope, "逻辑子规则必须是对象数组"));
        return [];
      }
      return [rule, ...nestedRules(rule.rules, scope)];
    });
  }
  for (const rule of nestedRules(config.route?.rules, "路由")) {
    for (const tag of [].concat(rule.inbound || [])) {
      if (!inboundTags.includes(tag)) issues.push(issue("error", "路由", `路由规则引用了不存在的入站：${tag}`));
    }
    if (rule.outbound && !routableTags.includes(rule.outbound)) {
      issues.push(issue("error", "路由", `路由规则引用了不存在的出站：${rule.outbound}`));
    }
    if (rule.action === "resolve" && rule.server && !dnsTags.includes(rule.server)) {
      issues.push(issue("error", "路由", `resolve 动作引用了不存在的 DNS Server：${rule.server}`));
    }
    for (const tag of [].concat(rule.rule_set || [])) {
      if (!ruleSetTags.includes(tag)) issues.push(issue("error", "路由", `路由规则引用了不存在的规则集：${tag}`));
    }
  }
  for (const rule of nestedRules(config.dns?.rules, "DNS")) {
    if (rule.server && !dnsTags.includes(rule.server)) issues.push(issue("error", "DNS", `DNS 规则引用了不存在的服务器：${rule.server}`));
    for (const tag of [].concat(rule.preferred_by || [])) {
      if (!dnsTags.includes(tag)) issues.push(issue("error", "DNS", `preferred_by 引用了不存在的服务器：${tag}`));
    }
    for (const tag of [].concat(rule.rule_set || [])) {
      if (!ruleSetTags.includes(tag)) issues.push(issue("error", "DNS", `DNS 规则引用了不存在的规则集：${tag}`));
    }
  }
  // 拨号解析器可以出现在节点、端点、DNS Server 或嵌套的高级字段中。
  function checkResolvers(value) {
    if (!value || typeof value !== "object") return;
    for (const [key, child] of Object.entries(value)) {
      if (["domain_resolver", "default_domain_resolver"].includes(key)) {
        const tag = typeof child === "string" ? child : child?.server;
        if (tag && !dnsTags.includes(tag)) issues.push(issue("error", "DNS", `域名解析器引用了不存在的服务器：${tag}`));
        else if (tag && (config.dns?.servers || []).some((item) => item.tag === tag && item.type === "fakeip")) issues.push(issue("error", "DNS", `域名解析器不能指向 FakeIP 服务器「${tag}」`));
      }
      checkResolvers(child);
    }
  }
  checkResolvers(config);
  if (config.route?.final && !routableTags.includes(config.route.final)) {
    issues.push(issue("error", "路由", `默认出站不存在：${config.route.final}`));
  }
  if (skippedRules.length) {
    issues.push(issue("warning", "路由", `${skippedRules.length} 条路由规则因为引用的出站当前不存在而没有写入配置`));
  }
  const remote = (config.route?.rule_set || []).filter((set) => set.type === "remote");
  if (remote.length && !config.experimental?.cache_file?.enabled) {
    issues.push(issue("warning", "路由", "远程规则集没有启用 experimental.cache_file，每次启动都会重新下载"));
  }
  return issues;
}

function checkOutbounds(config) {
  const issues = [];
  const groups = (config.outbounds || []).filter((outbound) => ["selector", "urltest"].includes(outbound.type));
  const tags = [...(config.outbounds || []), ...(config.endpoints || [])].map((item) => item.tag).filter(Boolean);
  for (const group of groups) {
    for (const member of group.outbounds || []) {
      if (!tags.includes(member)) issues.push(issue("error", "出站", `出站组「${group.tag}」引用了不存在的成员：${member}`));
    }
    if (group.default && !(group.outbounds || []).includes(group.default)) {
      issues.push(issue("error", "出站", `出站组「${group.tag}」的默认成员不在成员列表里：${group.default}`));
    }
    if (!(group.outbounds || []).length) issues.push(issue("error", "出站", `出站组「${group.tag}」没有成员`));
  }
  return issues;
}

function checkHttpClients(config) {
  const issues = [];
  const clients = config.http_clients || [];
  if (!Array.isArray(clients)) return [issue("error", "HTTP Client", "http_clients 必须是对象数组")];
  const tags = new Set();
  for (const client of clients) {
    if (!client || Array.isArray(client) || typeof client !== "object" || typeof client.tag !== "string" || !client.tag.trim()) {
      issues.push(issue("error", "HTTP Client", "共享 HTTP Client 必须是含 tag 的对象"));
      continue;
    }
    if (tags.has(client.tag)) issues.push(issue("error", "HTTP Client", "共享 HTTP Client 标签重复：" + client.tag));
    tags.add(client.tag);
  }
  const outbounds = [...(config.outbounds || []), ...(config.endpoints || [])];
  const check = client => {
    if (typeof client === "string") {
      if (!tags.has(client)) issues.push(issue("error", "HTTP Client", "引用的 HTTP Client 不存在：" + client));
    } else if (!client || Array.isArray(client) || typeof client !== "object") {
      issues.push(issue("error", "HTTP Client", "HTTP Client 必须是标签或对象"));
    } else if (client.detour) {
      const outbound = outbounds.find(item => item.tag === client.detour);
      if (!outbound) issues.push(issue("error", "HTTP Client", "HTTP Client detour 出站不存在：" + client.detour));
      else if (outbound.type === "direct" && Object.keys(outbound).every(key => ["type", "tag"].includes(key))) {
        issues.push(issue("error", "HTTP Client", "HTTP Client 直连下载应省略 detour，不能指向空 Direct 出站：" + client.detour));
      }
    }
  };
  clients.forEach(check);
  const walk = value => {
    if (!value || typeof value !== "object") return;
    for (const [key, child] of Object.entries(value)) {
      if (["headers", "predefined"].includes(key)) continue;
      if (["http_client", "default_http_client"].includes(key)) check(child);
      walk(child);
    }
  };
  walk(config);
  return issues;
}

function configDetourCycles(config) {
  const entries = [...(config.outbounds || []), ...(config.endpoints || [])];
  const edges = new Map(entries.map(item => [item.tag, [item.detour, ...(["selector", "urltest"].includes(item.type) ? item.outbounds || [] : [])].filter(Boolean)]));
  const visited = new Set(), visiting = new Set(), cycles = [];
  const walk = (tag, path) => {
    if (visiting.has(tag)) { cycles.push([...path.slice(path.indexOf(tag)), tag]); return; }
    if (visited.has(tag)) return;
    visiting.add(tag);
    for (const next of edges.get(tag) || []) walk(next, [...path, tag]);
    visiting.delete(tag);
    visited.add(tag);
  };
  for (const tag of edges.keys()) walk(tag, []);
  return cycles;
}

function checkDetourCycles(cycles = []) {
  return cycles.map((cycle) => issue("error", "出站", `detour 或出站组存在环路：${cycle.join(" → ")}`));
}

export function detectConflicts(config, context = {}) {
  const { moduleIssues = [], skippedRules = [], clashApiAddress = "", detourCycles = [] } = context;
  const issues = [
    ...moduleIssues,
    ...checkTags(config),
    ...checkListen(config, { clashApiAddress }),
    ...checkTun(config),
    ...checkDns(config),
    ...checkRoute(config, { skippedRules }),
    ...checkOutbounds(config),
    ...checkHttpClients(config),
    ...checkDetourCycles([...detourCycles, ...configDetourCycles(config)])
  ];
  const seen = new Set();
  return issues.filter((item) => {
    const key = `${item.level}|${item.scope}|${item.message}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

export function hasBlockingConflicts(issues = []) {
  return issues.some((item) => item.level === "error");
}

export function summarizeConflicts(issues = []) {
  const errors = issues.filter((item) => item.level === "error").length;
  const warnings = issues.length - errors;
  return { errors, warnings, total: issues.length };
}
