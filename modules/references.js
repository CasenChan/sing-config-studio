import { splitList } from "./shared.js";

// 只改写出站命名空间的引用，不替换域名、凭据、HTTP 头或 DNS 标签。
// 所有映射同时应用，支持批量改名中的交换名称；源状态保持不变。
export function rewriteOutboundReferences(source, replacements = []) {
  const tags = new Map(replacements.filter(([from, to]) => from && to && from !== to).map(([from, to]) => [String(from).trim(), String(to).trim()]));
  const state = JSON.parse(JSON.stringify(source));
  if (!tags.size) return state;
  const ref = value => typeof value === "string" ? tags.get(value.trim()) ?? value : value;
  const list = value => {
    const before = splitList(value), after = before.map(ref);
    if (before.every((tag, index) => tag === after[index])) return value;
    return Array.isArray(value) ? after : after.join(", ");
  };
  const raw = (value, scope) => {
    if (Array.isArray(value)) return value.map(item => raw(item, scope));
    if (!value || typeof value !== "object") return value;
    const result = { ...value };
    if ("detour" in result) result.detour = ref(result.detour);
    if (scope === "rule" && "outbound" in result) result.outbound = ref(result.outbound);
    if (scope === "route" && "final" in result) result.final = ref(result.final);
    if (scope === "group" || ["selector", "urltest"].includes(result.type)) {
      if ("outbounds" in result) result.outbounds = list(result.outbounds);
      if ("default" in result) result.default = ref(result.default);
    }
    if (["route", "rule"].includes(scope) && result.rules) result.rules = raw(result.rules, "rule");
    for (const key of ["http_client", "default_http_client"]) {
      if (result[key] && typeof result[key] === "object") result[key] = raw(result[key], "client");
    }
    if (result.dashboard && typeof result.dashboard === "object") result.dashboard = raw(result.dashboard, "client");
    return result;
  };
  const json = (value, scope) => {
    if (!value || !String(value).trim()) return value;
    let parsed;
    try { parsed = JSON.parse(value); }
    catch { throw new Error("无法同步出站引用：请先修正相关附加参数中的 JSON"); }
    const updated = raw(parsed, scope);
    return JSON.stringify(parsed) === JSON.stringify(updated) ? value : JSON.stringify(updated, null, 2);
  };
  const dial = (entry, scope = "dial") => {
    if (entry.detour) entry.detour = ref(entry.detour);
    if (entry.advancedJson) entry.advancedJson = json(entry.advancedJson, scope);
  };
  for (const node of state.nodes || []) dial(node);
  for (const endpoint of state.endpoints || []) dial(endpoint);
  for (const server of state.dns?.servers || []) dial(server);
  for (const group of state.groups || []) {
    group.members = list(group.members);
    group.defaultMember = ref(group.defaultMember);
    if (group.includeDirect && tags.has("direct")) {
      group.includeDirect = false;
      group.members = [...new Set([...splitList(group.members), tags.get("direct")])].join(", ");
    }
    dial(group, "group");
  }
  if (state.route) {
    state.route.final = ref(state.route.final);
    if (state.route.advancedJson) state.route.advancedJson = json(state.route.advancedJson, "route");
    if (String(state.route.defaultHttpClient || "").trim().startsWith("{")) state.route.defaultHttpClient = json(state.route.defaultHttpClient, "client");
    for (const rule of state.route.rules || []) {
      rule.outbound = ref(rule.outbound);
      if (rule.rulesJson) rule.rulesJson = json(rule.rulesJson, "rule");
      if (rule.advancedJson) rule.advancedJson = json(rule.advancedJson, "rule");
    }
    for (const set of state.route.ruleSets || []) {
      if (set.httpClientJson) set.httpClientJson = json(set.httpClientJson, "client");
      if (set.advancedJson) set.advancedJson = json(set.advancedJson, "rule-set");
    }
  }
  if (state.serviceState) {
    state.serviceState.ntpDetour = ref(state.serviceState.ntpDetour);
    state.serviceState.v2rayStatsOutbounds = list(state.serviceState.v2rayStatsOutbounds);
    if (state.serviceState.httpClientsJson) state.serviceState.httpClientsJson = json(state.serviceState.httpClientsJson, "client");
    for (const service of state.serviceState.services || []) dial(service, "service");
  }
  return state;
}
