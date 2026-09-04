// 跨模块冲突检查：把各模块自身的校验，与只有放在一起才能发现的冲突汇总成一份清单。
// level 为 error 的条目会阻止生成订阅链接。

const WILDCARD = new Set(["", "0.0.0.0", "::", "[::]"]);

function issue(level, scope, message) {
  return { level, scope, message };
}

function listenKey(inbound) {
  return `${String(inbound.listen ?? "")}|${inbound.listen_port ?? ""}`;
}

function conflictingListen(a, b) {
  if (!a.listen_port || !b.listen_port || a.listen_port !== b.listen_port) return false;
  const addressA = String(a.listen ?? "");
  const addressB = String(b.listen ?? "");
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
    const [apiHost, apiPort] = clashApiAddress.split(":");
    const clash = { listen: apiHost, listen_port: Number(apiPort) };
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
  if (inUse && !(config.route?.rules || []).some((rule) => rule.action === "sniff")) {
    issues.push(issue("warning", "路由", "使用 FakeIP 时建议保留 sniff 规则，否则无法从虚拟地址还原出域名"));
  }
  if (inUse && config.dns?.reverse_mapping) {
    issues.push(issue("warning", "DNS", "FakeIP 与反向映射同时启用时，反向映射不会带来额外效果"));
  }
  return issues;
}

function checkRoute(config, { skippedRules = [] } = {}) {
  const issues = [];
  const inboundTags = (config.inbounds || []).map((item) => item.tag).filter(Boolean);
  const routableTags = [...(config.outbounds || []), ...(config.endpoints || [])].map((item) => item.tag).filter(Boolean);
  const dnsTags = (config.dns?.servers || []).map((item) => item.tag).filter(Boolean);
  const ruleSetTags = (config.route?.rule_set || []).flatMap((item) => (Array.isArray(item.tag) ? item.tag : [item.tag])).filter(Boolean);

  for (const rule of config.route?.rules || []) {
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
  for (const rule of config.dns?.rules || []) {
    if (rule.server && !dnsTags.includes(rule.server)) issues.push(issue("error", "DNS", `DNS 规则引用了不存在的服务器：${rule.server}`));
    for (const tag of [].concat(rule.rule_set || [])) {
      if (!ruleSetTags.includes(tag)) issues.push(issue("error", "DNS", `DNS 规则引用了不存在的规则集：${tag}`));
    }
  }
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
    ...checkDetourCycles(detourCycles)
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
