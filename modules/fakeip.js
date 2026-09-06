// FakeIP 预设只生成候选状态；界面确认后才保存。关联记录不会进入内核配置。
import { buildDnsRule, buildDnsServer, dnsModule, normalizeDnsRule, normalizeDnsServer, normalizeDnsState, defaultDomainResolverTag, validateDnsState } from "./dns.js";
import { buildInbound, inboundModule, normalizeInbound, validateInbounds } from "./inbound.js";
import { buildRouteRule, normalizeRouteRule, normalizeRouteState, routeModule, validateRouteState } from "./route.js";
import { normalizeServiceState, serviceModule, validateServiceState } from "./services.js";
import { outboundModule, detectDetourCycles } from "./outbound.js";
import { tailscaleModule } from "./tailscale.js";
import { endpointFamilyModule } from "./endpoints.js";
import { detectConflicts } from "./conflicts.js";
import { splitList } from "./shared.js";

const COLLECTIONS = ["dns.servers", "dns.rules", "route.rules", "inbounds"];
const FIELDS = {
  dns: ["final", "defaultDomainResolver"],
  route: ["autoDetectInterface"],
  serviceState: ["cacheEnabled", "cacheStoreFakeip"],
  inbounds: ["autoRoute", "dnsMode"]
};
const ROLE_IDS = { "本地解析器": "local", TUN: "tun", "FakeIP 兜底规则": "fallback", "局域网 DNS 例外": "lan", "DNS 接管规则": "hijack" };
const copy = (value) => value === undefined ? undefined : JSON.parse(JSON.stringify(value));
const stable = (value) => JSON.stringify(value && typeof value === "object"
  ? Array.isArray(value) ? value.map((entry) => JSON.parse(stable(entry)))
    : Object.fromEntries(Object.keys(value).sort().filter((key) => value[key] !== undefined).map((key) => [key, JSON.parse(stable(value[key]))]))
  : value ?? null);
const same = (a, b) => stable(a) === stable(b);
const enabled = (entry) => entry.enabled !== false;
const listAt = (state, path) => path.split(".").reduce((value, key) => value?.[key], state);
const targetAt = (state, resource) => resource.id
  ? listAt(state, resource.path)?.find((entry) => entry.id === resource.id)
  : listAt(state, resource.path);

function prepare(source) {
  const state = copy(source);
  state.inbounds ||= [];
  state.nodes ||= [];
  state.groups ||= [];
  state.endpoints ||= [];
  state.dns = normalizeDnsState(state.dns);
  state.route = normalizeRouteState(state.route);
  state.serviceState = normalizeServiceState(state.serviceState);
  // 备份中的记录只允许操作预设实际会涉及的集合和字段。
  const saved = state.dns.fakeipPresets;
  const profiles = saved?.version === 1 && Array.isArray(saved.profiles) ? saved.profiles.filter((item) => typeof item?.serverId === "string") : [];
  const resources = saved?.version === 1 && Array.isArray(saved.resources) ? saved.resources.filter((item) =>
    Array.isArray(item?.owners) &&
    (item.kind === "object" ? COLLECTIONS.includes(item.path) && typeof item.id === "string" && item.after?.id === item.id
      : item.kind === "field" && FIELDS[item.path]?.includes(item.field) && (item.path !== "inbounds" || typeof item.id === "string"))
  ) : [];
  state.dns.fakeipPresets = { version: 1, profiles, resources };
  return state;
}

export function hasFakeipPreset(state, serverId) {
  return state.dns?.fakeipPresets?.version === 1 && Boolean(state.dns.fakeipPresets.profiles?.some((item) => item.serverId === serverId));
}

function unique(state, prefix, property = "tag") {
  const used = new Set(COLLECTIONS.flatMap((path) => listAt(state, path) || []).map((item) => item[property]));
  for (const item of [...state.nodes, ...state.groups, ...state.endpoints]) used.add(item[property]);
  let value = prefix;
  for (let suffix = 2; used.has(value); suffix += 1) value = `${prefix}-${suffix}`;
  return value;
}

function notice(result, level, message) {
  if (!result[level].includes(message)) result[level].push(message);
}

function share(resource, owner) {
  if (resource && !resource.owners.includes(owner)) resource.owners.push(owner);
}

function trackObject(state, owner, role, path, desired, equivalent, result, beforeId, refresh = false) {
  const ledger = state.dns.fakeipPresets;
  const list = listAt(state, path);
  let resource = ledger.resources.find((item) => item.kind === "object" && item.path === path && item.role === role && item.owners.includes(owner));
  let entry = resource && targetAt(state, resource);
  if (entry) {
    if (!same(entry, resource.after)) notice(result, "warnings", `保留手动修改：${resource.label}`);
    else if (refresh && !same(entry, { ...desired, id: entry.id })) {
      // 共享项目变更目标时另建一项，不能替另一份预设改写引用。
      if (resource.owners.some((id) => id !== owner)) {
        resource.owners = resource.owners.filter((id) => id !== owner);
        resource = undefined;
        entry = undefined;
      } else {
        Object.assign(entry, desired, { id: entry.id });
        resource.after = copy(entry);
        notice(result, "changes", `更新${resource.label}`);
      }
    }
    if (entry) return entry;
  }
  // 手工创建的等价项目可以复用，但不能因此取得它的删除权限。
  entry = list.find((item) => enabled(item) && equivalent(item));
  if (entry) {
    const shared = ledger.resources.find((item) => item.kind === "object" && item.path === path && item.id === entry.id);
    share(shared, owner);
    if (resource && resource !== shared) {
      resource.owners = resource.owners.filter((id) => id !== owner);
      ledger.resources = ledger.resources.filter((item) => item !== resource || item.owners.length);
    }
    return entry;
  }
  const id = resource?.id || unique(state, `fakeip-${ROLE_IDS[role]}`, "id");
  entry = { ...desired, id };
  if (entry.tag) entry.tag = unique(state, entry.tag);
  const index = beforeId ? list.findIndex((item) => item.id === beforeId) : -1;
  list.splice(index < 0 ? list.length : index, 0, entry);
  if (resource) resource.after = copy(entry);
  else {
    resource = { kind: "object", path, id, role, label: entry.tag ? `${role}「${entry.tag}」` : role, after: copy(entry), owners: [owner] };
    ledger.resources.push(resource);
  }
  notice(result, "changes", `新增${resource.label}`);
  return entry;
}

function useObject(state, owner, path, entry) {
  share(state.dns.fakeipPresets.resources.find((item) => item.kind === "object" && item.path === path && item.id === entry.id), owner);
}

function setField(state, owner, path, id, field, value, label, result) {
  const ledger = state.dns.fakeipPresets;
  const target = targetAt(state, { path, id });
  let resource = ledger.resources.find((item) => item.kind === "field" && item.path === path && item.id === id && item.field === field);
  const object = ledger.resources.find((item) => item.kind === "object" && item.path === path && item.id === id);
  if (object) {
    share(object, owner);
    if (!same(target, object.after)) {
      notice(result, "warnings", `保留手动修改：${object.label}`);
      return;
    }
  }
  if (resource) {
    share(resource, owner);
    if (!same(target[field], resource.after)) {
      notice(result, "warnings", `保留手动修改：${label}`);
      return;
    }
  }
  const unchanged = same(target[field], value);
  if (!resource && !object) {
    // 已符合要求的字段也记录使用关系，后续补齐时才能识别用户手改，
    // 并防止另一份预设单独撤销仍在共用的设置。
    resource = { kind: "field", path, ...(id ? { id } : {}), field, label, before: { present: Object.hasOwn(target, field), value: copy(target[field]) }, after: copy(value), ...(unchanged ? { unchanged: true } : {}), owners: [owner] };
    ledger.resources.push(resource);
  }
  if (unchanged) return;
  target[field] = copy(value);
  if (resource) { resource.after = copy(value); delete resource.unchanged; }
  if (object) object.after = copy(target);
  notice(result, "changes", value === true || value === "on" ? `开启${label}` : value === false || value === "off" ? `关闭${label}` : `设置${label}：${value === "hijack" ? "接管 DNS" : String(value)}`);
}

function ipv4(text) {
  const parts = text.split(".");
  if (parts.length !== 4 || parts.some((part) => !/^(0|[1-9]\d{0,2})$/.test(part) || Number(part) > 255)) throw new Error(`无效 IPv4：${text}`);
  return parts.reduce((value, part) => (value << 8n) | BigInt(part), 0n);
}

function cidr(text) {
  const [address, prefix, ...rest] = String(text).split("/");
  if (rest.length || prefix === undefined || !/^\d+$/.test(prefix)) throw new Error(`无效 CIDR：${text}`);
  const family = address.includes(":") ? 6 : 4;
  const bits = family === 4 ? 32 : 128;
  const size = Number(prefix);
  if (size > bits) throw new Error(`无效 CIDR：${text}`);
  let number;
  if (family === 4) number = ipv4(address);
  else {
    let expanded = address;
    if (expanded.includes(".")) {
      const at = expanded.lastIndexOf(":");
      const v4 = ipv4(expanded.slice(at + 1));
      expanded = `${expanded.slice(0, at)}:${(v4 >> 16n).toString(16)}:${(v4 & 65535n).toString(16)}`;
    }
    const halves = expanded.split("::");
    if (halves.length > 2) throw new Error(`无效 CIDR：${text}`);
    const left = halves[0] ? halves[0].split(":") : [];
    const right = halves[1] ? halves[1].split(":") : [];
    const missing = 8 - left.length - right.length;
    if (halves.length === 1 ? missing !== 0 : missing < 1) throw new Error(`无效 CIDR：${text}`);
    const parts = [...left, ...Array(halves.length === 2 ? missing : 0).fill("0"), ...right];
    if (parts.some((part) => !/^[0-9a-f]{1,4}$/i.test(part))) throw new Error(`无效 CIDR：${text}`);
    number = parts.reduce((value, part) => (value << 16n) | BigInt(`0x${part}`), 0n);
  }
  const hostBits = BigInt(bits - size);
  const start = (number >> hostBits) << hostBits;
  return { family, start, end: start + (1n << hostBits) - 1n, text };
}

const overlaps = (a, b) => a.family === b.family && a.start <= b.end && b.start <= a.end;
function covered(pool, ranges) {
  let cursor = pool.start;
  for (const range of ranges.filter((item) => item.family === pool.family).sort((a, b) => a.start < b.start ? -1 : a.start > b.start ? 1 : 0)) {
    if (range.start > cursor) break;
    if (range.end >= cursor) cursor = range.end + 1n;
    if (cursor > pool.end) return true;
  }
  return false;
}

function addressChecks(state, server, tun, result) {
  try {
    const builtTun = buildInbound(tun);
    tun = { ...tun, address: builtTun.address, routeAddress: builtTun.route_address, routeExcludeAddress: builtTun.route_exclude_address, routeAddressSet: builtTun.route_address_set, routeExcludeAddressSet: builtTun.route_exclude_address_set };
    const pools = [];
    if (server.inet4Range) {
      const pool = cidr(server.inet4Range);
      if (pool.family !== 4) throw new Error("FakeIP IPv4 段必须是 IPv4 CIDR");
      pools.push(pool);
    }
    if (server.inet6Range) {
      const pool = cidr(server.inet6Range);
      if (pool.family !== 6) throw new Error("FakeIP IPv6 段必须是 IPv6 CIDR");
      pools.push(pool);
    }
    for (const other of state.dns.servers.filter((item) => enabled(item) && item.type === "fakeip" && item.id !== server.id)) {
      for (const range of [other.inet4Range, other.inet6Range].filter(Boolean).map(cidr)) {
        if (pools.some((pool) => overlaps(pool, range))) notice(result, "errors", `地址池与 FakeIP「${other.tag}」重叠：${range.text}`);
      }
    }
    const interfaces = [...state.inbounds.filter((item) => enabled(item) && item.type === "tun"), ...state.endpoints.filter(enabled)];
    for (const item of interfaces) {
      for (const range of splitList(item.address).map(cidr)) {
        if (pools.some((pool) => overlaps(pool, range))) notice(result, "errors", `FakeIP 地址池与接口「${item.tag}」地址重叠：${range.text}`);
      }
    }
    const families = new Set(splitList(tun.address).map(cidr).map((range) => range.family));
    const available = pools.filter((pool) => families.has(pool.family) && (state.dns.strategy !== "ipv4_only" || pool.family === 4) && (state.dns.strategy !== "ipv6_only" || pool.family === 6));
    if (!available.length) notice(result, "errors", "DNS 策略、TUN 地址族和 FakeIP 地址池没有共同可用的地址族");
    const excluded = splitList(tun.routeExcludeAddress).map(cidr);
    const included = splitList(tun.routeAddress).map(cidr);
    for (const pool of available) {
      if (excluded.some((range) => overlaps(pool, range))) notice(result, "errors", `TUN「${tun.tag}」路由排除范围覆盖 FakeIP 地址池：${pool.text}`);
      if (included.length && !covered(pool, included)) notice(result, "errors", `TUN「${tun.tag}」自定义路由未完整覆盖 FakeIP 地址池：${pool.text}`);
    }
    if (tun.routeAddressSet || tun.routeExcludeAddressSet) notice(result, "warnings", "TUN 使用路由规则集，请确认其中没有排除 FakeIP 地址池；预设不会下载或改写规则集");
    if (Object.entries(tun).some(([key, value]) => /^(include|exclude)(Interface|Uid|Package|Mac|Android)/.test(key) && value)) notice(result, "warnings", "TUN 的接口／应用过滤保持不变，只有被接管的流量使用此预设");
    return available.map((pool) => pool.family === 4 ? "A" : "AAAA");
  } catch (error) {
    notice(result, "errors", error.message);
    return [];
  }
}

const ACTION_KEYS = new Set(["action", "server", "query_type", "invert", "disable_cache", "disable_optimistic_cache", "rewrite_ttl", "timeout", "client_subnet", "remove_client_subnet", "method", "no_drop", "rcode", "answer", "ns", "extra", "speculative"]);
function blocksQuery(rule, type) {
  if (rule.type === "logical") {
    const children = (rule.rules || []).map((child) => blocksQuery(child, type));
    if (!children.length) return null;
    const matches = rule.mode === "or"
      ? children.includes(true) ? true : children.every((value) => value === false) ? false : null
      : children.includes(false) ? false : children.every((value) => value === true) ? true : null;
    return matches === null ? null : rule.invert ? !matches : matches;
  }
  if (Object.keys(rule).some((key) => !ACTION_KEYS.has(key))) return null;
  const queryTypes = [].concat(rule.query_type || []).map((entry) => String(entry).toUpperCase()).map((entry) => entry === "1" ? "A" : entry === "28" ? "AAAA" : entry);
  const matches = !queryTypes.length || queryTypes.includes(type);
  return rule.invert ? !matches : matches;
}

function checkDnsOrder(state, fallback, types, result) {
  const rules = state.dns.rules.filter(enabled);
  const end = rules.findIndex((item) => item.id === fallback.id);
  for (const rule of rules.slice(0, end)) {
    const built = buildDnsRule(rule);
    if (["route", "reject", "predefined", "respond"].includes(built.action) && types.some((type) => blocksQuery(built, type))) {
      notice(result, "errors", `DNS 规则「${rule.id}」（第 ${state.dns.rules.indexOf(rule) + 1} 条）会遮挡 FakeIP 兜底，请先调整该规则的匹配范围或顺序`);
    } else if (built.type === "logical" || built.match_response || built.race) {
      notice(result, "warnings", "已有复杂 DNS 规则仍优先，命中它们的查询可能不会使用 FakeIP");
    }
  }
}

function checkCandidate(state, result) {
  try {
    let config = { inbounds: [], outbounds: [], dns: { servers: [], rules: [] }, route: { rules: [] } };
    outboundModule.extendConfig(config, state);
    const outboundTags = [...config.outbounds, ...state.endpoints].map((item) => item.tag);
    const context = {
      outboundTags,
      tunEnabled: state.inbounds.some((item) => enabled(item) && item.type === "tun"),
      fallbackFinal: (config.outbounds.find((item) => item.type === "selector") || config.outbounds[0])?.tag || "direct",
      defaultDomainResolver: defaultDomainResolverTag(state.dns)
    };
    for (const module of [inboundModule, dnsModule, routeModule, tailscaleModule, endpointFamilyModule, serviceModule]) config = module.extendConfig(config, state, context);
    const ruleSetTags = (config.route.rule_set || []).flatMap((item) => [].concat(item.tag || []));
    const validation = { outboundTags, inboundTags: config.inbounds.map((item) => item.tag), endpoints: state.endpoints, ruleSetTags, dnsServerTags: config.dns.servers.map((item) => item.tag) };
    for (const error of [validateDnsState(state.dns, validation), validateInbounds(state.inbounds, validation), validateRouteState(state.route, validation), validateServiceState(state.serviceState, validation)]) if (error) notice(result, "errors", error);
    for (const issue of detectConflicts(config, { detourCycles: detectDetourCycles(state.nodes, state.groups) })) notice(result, issue.level === "error" ? "errors" : "warnings", issue.message);
  } catch (error) {
    notice(result, "errors", error.message);
  }
}

// 改名只同步仍保持预设原样的引用；用户自行创建或修改的规则不自动改写。
export function planFakeipServerSave(source, sourceServer) {
  const state = prepare(source);
  const server = normalizeDnsServer(copy(sourceServer));
  server.tag = String(server.tag || "").trim();
  const result = { state, changes: [], warnings: [], errors: [] };
  const index = state.dns.servers.findIndex((item) => item.id === server.id);
  const previous = state.dns.servers[index];
  if (previous && previous.tag !== server.tag && hasFakeipPreset(state, server.id)) {
    for (const resource of state.dns.fakeipPresets.resources.filter((item) => item.owners.includes(server.id) && item.kind === "object" && item.path === "dns.rules")) {
      const current = targetAt(state, resource);
      if (current?.server !== previous.tag) continue;
      if (same(current, resource.after)) {
        current.server = server.tag;
        resource.after = copy(current);
        notice(result, "changes", `更新预设规则引用：${previous.tag} → ${server.tag}`);
      } else notice(result, "warnings", `规则「${current.id}」已手动修改，保留旧引用 ${previous.tag}，请自行修正`);
    }
  }
  if (index < 0) state.dns.servers.push(server);
  else state.dns.servers[index] = server;
  return result;
}

export function planFakeipPreset(source, sourceServer, options = {}) {
  try { return createPreset(source, sourceServer, options); }
  catch (error) { return { state: copy(source), changes: [], warnings: [], errors: [error.message] }; }
}

function createPreset(source, sourceServer, { tunId = "" } = {}) {
  const result = planFakeipServerSave(source, sourceServer);
  const { state } = result;
  const server = state.dns.servers.find((item) => item.id === sourceServer.id);
  const owner = server.id;
  if (server.type !== "fakeip" || !owner || !server.tag.trim() || !enabled(server)) {
    notice(result, "errors", "请选择一个启用且标签完整的 FakeIP Server");
    return result;
  }
  const ledger = state.dns.fakeipPresets;
  let profile = ledger.profiles.find((item) => item.serverId === owner);
  if (!profile) {
    profile = { serverId: owner };
    ledger.profiles.push(profile);
  }
  const local = trackObject(state, owner, "本地解析器", "dns.servers", normalizeDnsServer({ type: "local", tag: "local-dns", detour: "direct" }),
    (item) => { const built = buildDnsServer(item); return item.type === "local" && (!built.detour || built.detour === "direct"); }, result);
  if (!enabled(local) || local.type !== "local" || ![undefined, "", "direct"].includes(buildDnsServer(local).detour)) {
    notice(result, "errors", `局域网解析器「${local.tag}」已手动修改，请恢复为启用且直连的 Local DNS`);
  }
  const real = state.dns.servers.find((item) => enabled(item) && item.type !== "fakeip" && item.tag === state.dns.final) || local;
  useObject(state, owner, "dns.servers", real);
  const resolver = state.dns.servers.find((item) => enabled(item) && item.type !== "fakeip" && item.tag === state.dns.defaultDomainResolver) || local;
  useObject(state, owner, "dns.servers", resolver);
  setField(state, owner, "dns", undefined, "final", real.tag, "默认真实 DNS", result);
  setField(state, owner, "dns", undefined, "defaultDomainResolver", resolver.tag, "节点域名解析器", result);
  for (const field of ["final", "defaultDomainResolver"]) {
    if (!state.dns.servers.some((item) => enabled(item) && item.type !== "fakeip" && item.tag === state.dns[field])) {
      notice(result, "errors", `${field === "final" ? "默认 DNS" : "节点域名解析器"}的手动设置未指向有效真实 DNS，请先修正`);
    }
  }

  const tuns = state.inbounds.filter((item) => enabled(item) && item.type === "tun");
  let tun = tuns.find((item) => item.id === (tunId || profile.tunId));
  if (!tun && tuns.length > 1) {
    notice(result, "errors", "存在多个启用的 TUN，请选择此预设使用的目标 TUN");
    return result;
  }
  tun ||= tuns[0];
  if (!tun) tun = trackObject(state, owner, "TUN", "inbounds", normalizeInbound({ type: "tun", tag: "tun-in", dnsMode: "hijack" }), () => false, result);
  profile.tunId = tun.id;
  useObject(state, owner, "inbounds", tun);
  setField(state, owner, "inbounds", tun.id, "autoRoute", true, `TUN「${tun.tag}」自动路由`, result);
  setField(state, owner, "inbounds", tun.id, "dnsMode", "hijack", `TUN「${tun.tag}」DNS 接管`, result);
  if (!tun.autoRoute || tun.dnsMode !== "hijack") notice(result, "errors", `TUN「${tun.tag}」的手动设置关闭了自动路由或 DNS 接管，请先在入站编辑器中调整`);
  const fixedInterface = state.route.defaultInterface || JSON.parse(state.route.advancedJson || "{}").default_interface;
  setField(state, owner, "route", undefined, "autoDetectInterface", fixedInterface ? "off" : "on", "自动检测出口接口", result);
  const types = addressChecks(state, server, tun, result);
  if (!types.length) return result;
  result.summary = `${types.join(" / ")} 查询使用 FakeIP；其他查询使用真实 DNS「${state.dns.final}」。目标 TUN：${tun.tag}。已有 DNS 规则继续优先匹配。`;

  const fallbackRule = normalizeDnsRule({ queryType: types.join(", "), action: "route", server: server.tag });
  const fallback = trackObject(state, owner, "FakeIP 兜底规则", "dns.rules", fallbackRule, (item) => same(buildDnsRule(item), buildDnsRule(fallbackRule)), result, undefined, true);
  if (fallback.server !== server.tag || !enabled(fallback)) notice(result, "errors", "FakeIP 兜底规则已手动改为其他服务器或停用，请先修正该规则");
  const queries = [].concat(buildDnsRule(fallback).query_type || []).map((type) => String(type).toUpperCase());
  if (!same([...queries].sort(), [...types].sort())) notice(result, "errors", `FakeIP 兜底的查询类型需与可用地址族一致（${types.join("、")}），请修正手动修改的规则`);
  const localRule = normalizeDnsRule({ domain: "localhost", domainSuffix: ".lan, .local, .home.arpa", action: "route", server: local.tag });
  const exception = trackObject(state, owner, "局域网 DNS 例外", "dns.rules", localRule, (item) => same(buildDnsRule(item), buildDnsRule(localRule)), result, fallback.id, true);
  if (!enabled(exception) || state.dns.rules.indexOf(exception) > state.dns.rules.indexOf(fallback)) notice(result, "errors", "局域网 DNS 例外需启用并位于 FakeIP 兜底之前，请修正规则顺序");
  const hijack = normalizeRouteRule({ inbound: tun.tag, port: "53", action: "hijack-dns" });
  const hijackRule = trackObject(state, owner, "DNS 接管规则", "route.rules", hijack,
    (item) => same(buildRouteRule(item), buildRouteRule(hijack)) && state.route.rules.indexOf(item) === 0,
    result, state.route.rules[0]?.id, true);
  if (!enabled(hijackRule) || !same(buildRouteRule(hijackRule), buildRouteRule(hijack)) || state.route.rules.indexOf(hijackRule) !== 0) notice(result, "errors", `请将目标 TUN「${tun.tag}」的端口 53 DNS 接管规则放在普通分流规则之前，并移除额外匹配限制`);
  setField(state, owner, "serviceState", undefined, "cacheEnabled", true, "缓存文件", result);
  setField(state, owner, "serviceState", undefined, "cacheStoreFakeip", true, "FakeIP 映射持久化", result);
  if (!state.serviceState.cacheEnabled || !state.serviceState.cacheStoreFakeip) notice(result, "errors", "缓存或 FakeIP 映射持久化已手动关闭，请先在服务设置中开启");
  checkDnsOrder(state, fallback, types, result);
  checkCandidate(state, result);
  if (!result.changes.length) notice(result, "changes", "配套设置已齐全，无需重复添加");
  return result;
}

function references(value, tag, kind, dnsRule = false) {
  const keys = kind === "dns" ? new Set(["preferredBy", "preferred_by", "domainResolver", "domain_resolver", "defaultDomainResolver", "default_domain_resolver", "resolveServer"])
    : new Set(["inbound", "inbounds"]);
  function walk(item, serverReference = dnsRule) {
    if (Array.isArray(item)) return item.some((child) => walk(child, serverReference));
    if (!item || typeof item !== "object") return false;
    return Object.entries(item).some(([key, child]) => {
      if (key === "fakeipPresets") return false;
      const referenceKey = keys.has(key) || kind === "dns" && key === "server" && (serverReference || item.action === "resolve");
      if (referenceKey && (typeof child === "string" ? splitList(child).includes(tag) : Array.isArray(child) && child.includes(tag))) return true;
      if (key.endsWith("Json") && child) {
        try { return walk(JSON.parse(child), serverReference); } catch { return true; } // 无法确认的高级参数保守保留
      }
      return walk(child, serverReference || /^(default_?domain_?resolver|domain_?resolver)$/i.test(key));
    });
  }
  return walk(value);
}

function referrers(state, resource) {
  const current = targetAt(state, resource);
  const tag = current?.tag || resource.after?.tag;
  const kind = resource.path === "dns.servers" ? "dns" : resource.path === "inbounds" ? "inbound" : "";
  if (!kind || !tag) return [];
  const found = [];
  if (kind === "dns" && state.dns.final === tag) found.push("默认 DNS");
  const objects = [
    ...COLLECTIONS.flatMap((path) => (listAt(state, path) || []).map((entry) => ({ path, entry }))),
    ...["nodes", "groups", "endpoints"].flatMap((path) => (state[path] || []).map((entry) => ({ path, entry }))),
    { path: "dns", entry: { defaultDomainResolver: state.dns.defaultDomainResolver } },
    { path: "route", entry: { advancedJson: state.route.advancedJson, ruleSets: state.route.ruleSets } },
    { path: "serviceState", entry: state.serviceState }
  ];
  for (const { path, entry } of objects) {
    if (path === resource.path && entry.id === resource.id) continue;
    if (references(entry, tag, kind, path === "dns.rules")) found.push(`${path}「${entry.tag || entry.id || "全局设置"}」`);
  }
  return found;
}

export function planFakeipRemoval(source, serverId, { cleanup = true } = {}) {
  const state = prepare(source);
  const result = { state, changes: [], warnings: [], errors: [], preserved: [] };
  const server = state.dns.servers.find((item) => item.id === serverId);
  if (!server) { notice(result, "errors", "FakeIP Server 已不存在"); return result; }
  state.dns.servers = state.dns.servers.filter((item) => item.id !== serverId);
  notice(result, "changes", `删除 FakeIP「${server.tag}」`);
  const ledger = state.dns.fakeipPresets;
  ledger.profiles = ledger.profiles.filter((item) => item.serverId !== serverId);
  const released = [];
  for (const resource of ledger.resources) {
    if (!resource.owners.includes(serverId)) continue;
    resource.owners = resource.owners.filter((owner) => owner !== serverId);
    if (!cleanup) resource.keep = true;
    if (resource.owners.length) notice(result, "preserved", `${resource.label}：其他预设仍在使用`);
    else released.push(resource);
  }
  const candidates = [];
  for (const resource of released.filter((item) => item.kind === "object")) {
    const current = targetAt(state, resource);
    if (!current) continue;
    if (resource.keep || !same(current, resource.after)) {
      notice(result, "preserved", `${resource.label}：${resource.keep ? "选择保留配套设置" : "已手动修改"}`);
      continue;
    }
    const list = listAt(state, resource.path);
    const index = list.indexOf(current);
    candidates.push({ resource, current, index });
    list.splice(index, 1);
  }
  // 先移除自有规则，再恢复字段，最后检查被用户配置引用的资源。
  const fields = released.filter((item) => item.kind === "field").sort((a, b) => (a.field === "cacheEnabled" ? 1 : 0) - (b.field === "cacheEnabled" ? 1 : 0));
  const infrastructure = new Set(["autoDetectInterface", "cacheEnabled", "cacheStoreFakeip"]);
  function restoreField(resource) {
    const target = targetAt(state, resource);
    if (!target) return;
    if (resource.unchanged && same(target[resource.field], resource.after)) {
      notice(result, "preserved", `${resource.label}：原有设置未被预设修改`);
      return;
    }
    const needed = resource.field === "cacheStoreFakeip" && state.dns.servers.some((item) => enabled(item) && item.type === "fakeip")
      || resource.field === "cacheEnabled" && (state.serviceState.cacheStoreFakeip || state.route.ruleSets.some((item) => enabled(item) && item.type === "remote"))
      || resource.field === "autoDetectInterface" && resource.before?.value === "off" && !state.route.defaultInterface && state.inbounds.some((item) => enabled(item) && item.type === "tun" && item.autoRoute);
    if (resource.keep || !same(target[resource.field], resource.after) || needed) {
      notice(result, "preserved", `${resource.label}：${resource.keep ? "选择保留配套设置" : needed ? "其他配置仍需使用" : "已手动修改"}`);
      return;
    }
    if (resource.before?.present) target[resource.field] = copy(resource.before.value);
    else delete target[resource.field];
    notice(result, "changes", `还原${resource.label}`);
  }
  fields.filter((item) => !infrastructure.has(item.field)).forEach(restoreField);
  // 保留一项可能导致另一项重新被引用，因此迭代到依赖关系稳定。
  let changed = true;
  while (changed) {
    changed = false;
    for (const candidate of candidates.filter((item) => !item.retained)) {
      const used = referrers(state, candidate.resource);
      if (!used.length) continue;
      const list = listAt(state, candidate.resource.path);
      list.splice(Math.min(candidate.index, list.length), 0, candidate.current);
      candidate.retained = true;
      notice(result, "preserved", `${candidate.resource.label}：仍被 ${used.join("、")} 引用`);
      changed = true;
    }
  }
  fields.filter((item) => infrastructure.has(item.field)).forEach(restoreField);
  for (const candidate of candidates.filter((item) => !item.retained)) notice(result, "changes", `移除${candidate.resource.label}`);
  ledger.resources = ledger.resources.filter((item) => item.owners.length);
  const dangling = referrers(state, { path: "dns.servers", id: serverId, after: server });
  if (dangling.length) notice(result, "warnings", `删除后仍有引用需要修正：${dangling.join("、")} → ${server.tag}；修正前不能生成订阅`);
  return result;
}
