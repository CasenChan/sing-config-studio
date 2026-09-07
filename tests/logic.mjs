import assert from "node:assert/strict";
import { dedupeNodes, outboundConnectionKey } from "../modules/sharelink.js";
import { importConfig, importOutbound } from "../modules/importer.js";
import { buildDefaultDomainResolver, domainResolverServer, normalizeDnsState, validateDnsState } from "../modules/dns.js";
import { buildRouteSection, validateRouteState } from "../modules/route.js";
import { buildHttpClients, validateServiceState } from "../modules/services.js";
import { planChinaRouting } from "../modules/china-routing.js";
import { planFakeipPreset, planFakeipRemoval } from "../modules/fakeip.js";
import { detectConflicts, hasBlockingConflicts } from "../modules/conflicts.js";
import { rewriteOutboundReferences } from "../modules/references.js";
import { emptyState, fakeServer, configFromState } from "./fakeip-fixtures.mjs";

const minimal = {
  inbounds: [{ type: "mixed", tag: "mixed", listen: "127.0.0.1", listen_port: 18891 }],
  outbounds: [{ type: "direct", tag: "direct" }],
  dns: { servers: [{ type: "local", tag: "local" }], final: "local" },
  route: { final: "direct", default_domain_resolver: "local" }
};
const remote = { type: "trojan", tag: "node-a", server: "remote.example.com", server_port: 443, password: "test-password", tls: { enabled: true, server_name: "remote.example.com" } };

// 实际传输、TLS、拨号、高级参数和启用状态不同，不能误去重。
const variants = [
  remote,
  { ...remote, transport: { type: "ws", path: "/first" } },
  { ...remote, transport: { type: "ws", path: "/second" } },
  { ...remote, tls: { ...remote.tls, server_name: "other.example.com" } },
  { ...remote, tls: { ...remote.tls, insecure: true } },
  { ...remote, detour: "upstream" },
  { ...remote, multiplex: { enabled: true, protocol: "h2mux" } },
  { ...remote, connect_timeout: "7s" }
].map((item, index) => importOutbound({ ...item, tag: "variant-" + index }, index));
assert.equal(dedupeNodes(variants).removed, 0);
assert.equal(dedupeNodes([variants[0], { ...variants[0], enabled: false }]).removed, 0);
const copy = { ...variants[0], tag: "copy", id: "different-id", subscriptionId: "different-source" };
assert.equal(outboundConnectionKey(copy), outboundConnectionKey(variants[0]));
assert.deepEqual(dedupeNodes([variants[0], copy]).tagReplacements, [["copy", variants[0].tag]]);
const advanced = [
  { ...variants[0], advancedJson: '{"connect_timeout":"5s","tcp_fast_open":true}' },
  { ...copy, advancedJson: '{"tcp_fast_open":true,"connect_timeout":"5s"}' }
];
assert.equal(dedupeNodes(advanced).removed, 1, "JSON 对象的键顺序不应影响等价判断");
const reality = { ...variants[0], type: "vless", uuid: "17f6f870-6f59-4c91-a4dc-46cfe797c241", reality: true, publicKey: "key-a", shortId: "abcd" };
assert.equal(dedupeNodes([reality, { ...reality, publicKey: "key-b" }]).removed, 0);

// 字符串、对象形式的默认解析器都必须完整保留，不能丢策略或缓存选项。
const resolver = { server: "local", strategy: "ipv4_only", disable_cache: true, disable_optimistic_cache: false, rewrite_ttl: 0 };
const source = {
  ...structuredClone(minimal),
  outbounds: [{ type: "selector", tag: "proxy", outbounds: ["node-a"], default: "node-a" }, remote, { type: "direct", tag: "direct" }],
  http_clients: [{ tag: "rules-client", detour: "proxy", domain_resolver: { server: "local", strategy: "prefer_ipv4" }, headers: { "X-Test": "keep" } }],
  route: {
    final: "proxy", default_domain_resolver: resolver, default_http_client: "rules-client",
    rule_set: [{ type: "remote", tag: "test-set", format: "source", url: "https://example.com/rules.json", http_client: "rules-client" }],
    rules: [{ domain: ["example.com"], action: "route", outbound: "node-a" }]
  }
};
const imported = importConfig(source);
const built = configFromState(imported.state);
assert.deepEqual(imported.notices, []);
assert.deepEqual(built.http_clients, source.http_clients);
assert.equal(built.route.default_http_client, "rules-client");
assert.equal(built.route.rule_set[0].http_client, "rules-client");
assert.deepEqual(built.route.default_domain_resolver, resolver);
assert.deepEqual(buildHttpClients(imported.state.serviceState), source.http_clients);
assert.equal(validateDnsState(imported.state.dns), "");
assert.deepEqual(buildDefaultDomainResolver(imported.state.dns), resolver);
assert.equal(domainResolverServer(resolver), "local");
assert.deepEqual(buildDefaultDomainResolver({ ...imported.state.dns, defaultDomainResolver: JSON.stringify(resolver) }), resolver);
assert.match(validateDnsState({ ...imported.state.dns, defaultDomainResolver: { strategy: "ipv4_only" } }), /需要 server/);
assert.match(validateDnsState({ ...imported.state.dns, defaultDomainResolver: { server: "missing" } }), /不存在/);
const inline = importConfig({ ...source, route: { ...source.route, default_http_client: { detour: "proxy", domain_resolver: "local" } } });
assert.deepEqual(configFromState(inline.state).route.default_http_client, { detour: "proxy", domain_resolver: "local" });
assert.ok(importConfig({ ...minimal, unsupported_top_level: true }).notices.some(item => /unsupported_top_level/.test(item.message)));
assert.match(validateServiceState({ httpClientsJson: "[" }), /有效 JSON/);
assert.match(validateServiceState({ httpClientsJson: '[{"tag":"same"},{"tag":"same"}]' }), /重复/);
assert.match(validateServiceState({ httpClientsJson: '[null]' }), /含 tag/);

// 共享和内联 HTTP Client 引用都应校验；内核 check 不会完整检查下载初始化。
assert.equal(hasBlockingConflicts(detectConflicts(built)), false);
const missingClient = structuredClone(built);
delete missingClient.http_clients;
assert.ok(detectConflicts(missingClient).some(item => item.level === "error" && /HTTP Client 不存在/.test(item.message)));
const danglingClient = structuredClone(built);
danglingClient.http_clients[0].detour = "missing";
assert.ok(detectConflicts(danglingClient).some(item => /detour 出站不存在/.test(item.message)));
const emptyDirect = structuredClone(built);
emptyDirect.route.default_http_client = { detour: "direct" };
assert.ok(detectConflicts(emptyDirect).some(item => /空 Direct/.test(item.message)));

// 无代理的大陆预设直连下载不写 detour；自定义 Direct 的拨号设置仍可复用。
const china = planChinaRouting(emptyState());
assert.deepEqual(china.errors, []);
assert.ok(configFromState(china.state).route.rule_set.every(set => !set.http_client.detour));
const customized = emptyState();
customized.nodes = [{ type: "direct", tag: "direct", bindInterface: "en0" }];
assert.ok(configFromState(planChinaRouting(customized).state).route.rule_set.every(set => set.http_client.detour === "direct"));
const withResolver = emptyState();
withResolver.dns = normalizeDnsState({ servers: [{ type: "local", tag: "local" }], defaultDomainResolver: resolver, final: "local" });
assert.deepEqual(planChinaRouting(withResolver).state.dns.defaultDomainResolver, resolver);
const fakeipWithResolver = planFakeipPreset(withResolver, fakeServer());
assert.deepEqual(fakeipWithResolver.errors, []);
assert.deepEqual(fakeipWithResolver.state.dns.defaultDomainResolver, resolver);
const withClientReference = planFakeipPreset(emptyState(), fakeServer()).state;
const localTag = domainResolverServer(withClientReference.dns.defaultDomainResolver);
withClientReference.route.defaultHttpClient = JSON.stringify({ domain_resolver: localTag });
const cleaned = planFakeipRemoval(withClientReference, "fake-test").state;
assert.ok(cleaned.dns.servers.some(server => server.tag === localTag), "默认 HTTP Client 仍引用的解析器不能被 FakeIP 清理删除");

// auto 模式优先尊重用户填写的固定接口；显式 on 与固定接口仍提示冲突。
const routeState = { autoDetectInterface: "auto", defaultInterface: "en0", rules: [], ruleSets: [] };
const routeContext = { tunEnabled: true, outboundTags: ["direct"], fallbackFinal: "direct" };
const fixed = buildRouteSection(routeState, routeContext);
assert.equal(fixed.auto_detect_interface, undefined);
assert.equal(fixed.default_interface, "en0");
assert.equal(validateRouteState(routeState, routeContext), "");
assert.equal(buildRouteSection({ ...routeState, defaultInterface: "" }, routeContext).auto_detect_interface, true);
assert.match(validateRouteState({ ...routeState, autoDetectInterface: "on" }, routeContext), /只能选择一个/);
assert.ok(detectConflicts({ ...minimal, route: { auto_detect_interface: true, default_interface: "en0" } }).some(item => /只能选择一个/.test(item.message)));

// 相同地址/端口只有实际监听协议有交集时才冲突，UDP 代理也不能占用 TCP API。
const listener = network => ({ type: "direct", tag: network, network, listen: "127.0.0.1", listen_port: 18901 });
const listenConfig = { ...minimal, inbounds: [listener("tcp"), listener("udp")] };
assert.deepEqual(detectConflicts(listenConfig), []);
assert.ok(detectConflicts({ ...listenConfig, inbounds: [listener("tcp"), { ...listener("udp"), network: "tcp" }] }).some(item => /监听地址冲突/.test(item.message)));
assert.ok(detectConflicts({ ...listenConfig, inbounds: [listener("tcp"), { ...listener("udp"), network: undefined }] }).some(item => /监听地址冲突/.test(item.message)));
assert.deepEqual(detectConflicts({ ...minimal, inbounds: [listener("udp")] }, { clashApiAddress: "127.0.0.1:18901" }), []);
assert.ok(detectConflicts({ ...minimal, inbounds: [{ ...listener("tcp"), listen: "::1" }] }, { clashApiAddress: "[::1]:18901" }).some(item => /Clash API/.test(item.message)));
assert.deepEqual(detectConflicts({ ...minimal, inbounds: [{ ...listener("tcp"), type: "http" }, { ...listener("udp"), type: "hysteria2" }] }), []);

// 在最终配置检测组和 detour 环路，手写 JSON 不能绕过检查。
const cycle = { ...minimal, outbounds: [...minimal.outbounds, { type: "selector", tag: "a", outbounds: ["b"] }, { type: "selector", tag: "b", outbounds: ["a"] }] };
assert.ok(detectConflicts(cycle).some(item => item.level === "error" && /环路/.test(item.message)));

// 引用迁移涵盖手工成员/默认值、分流、默认出口、拨号和 HTTP Client；不改同名凭据/域名。
const references = structuredClone(imported.state);
references.nodes.push({ id: "chain", type: "trojan", tag: "chain", detour: "node-a", advancedJson: '{"detour":"node-a","tls":{"server_name":"node-a"},"transport":{"headers":{"detour":"node-a","outbound":"node-a"}}}' });
references.endpoints = [{ type: "tailscale", tag: "tail", detour: "node-a" }];
references.dns.servers[0].detour = "node-a";
references.route.rules[0].rulesJson = '[{"type":"logical","mode":"and","rules":[{"outbound":"node-a","domain":["node-a"]}]}]';
references.route.advancedJson = '{"final":"node-a","default_http_client":{"detour":"node-a"}}';
references.route.defaultHttpClient = '{"detour":"node-a"}';
references.route.ruleSets[0].httpClientJson = '{"detour":"node-a","headers":{"detour":"node-a"}}';
references.serviceState.ntpDetour = "node-a";
references.serviceState.v2rayStatsOutbounds = "node-a, proxy";
references.serviceState.httpClientsJson = '[{"tag":"client","detour":"node-a","headers":{"detour":"node-a"}}]';
const untouched = structuredClone(references);
const migrated = rewriteOutboundReferences(references, [["node-a", "renamed"], ["proxy", "new-proxy"]]);
assert.deepEqual(references, untouched);
assert.equal(migrated.groups[0].members, "renamed");
assert.equal(migrated.groups[0].defaultMember, "renamed");
assert.equal(migrated.route.final, "new-proxy");
assert.equal(migrated.route.rules[0].outbound, "renamed");
assert.equal(JSON.parse(migrated.route.rules[0].rulesJson)[0].rules[0].outbound, "renamed");
assert.deepEqual(JSON.parse(migrated.route.rules[0].rulesJson)[0].rules[0].domain, ["node-a"]);
assert.equal(migrated.nodes[1].detour, "renamed");
const extra = JSON.parse(migrated.nodes[1].advancedJson);
assert.equal(extra.detour, "renamed");
assert.equal(extra.tls.server_name, "node-a");
assert.deepEqual(extra.transport.headers, { detour: "node-a", outbound: "node-a" });
assert.equal(migrated.endpoints[0].detour, "renamed");
assert.equal(migrated.dns.servers[0].detour, "renamed");
assert.equal(JSON.parse(migrated.route.advancedJson).final, "renamed");
assert.equal(JSON.parse(migrated.route.defaultHttpClient).detour, "renamed");
assert.equal(JSON.parse(migrated.route.ruleSets[0].httpClientJson).detour, "renamed");
assert.equal(migrated.serviceState.ntpDetour, "renamed");
assert.equal(migrated.serviceState.v2rayStatsOutbounds, "renamed, new-proxy");
assert.equal(JSON.parse(migrated.serviceState.httpClientsJson)[0].detour, "renamed");
assert.equal(JSON.parse(migrated.serviceState.httpClientsJson)[0].headers.detour, "node-a");
const swap = rewriteOutboundReferences({ groups: [{ members: "a, b", defaultMember: "a" }], route: { final: "b" } }, [["a", "b"], ["b", "a"]]);
assert.equal(swap.groups[0].members, "b, a");
assert.equal(swap.groups[0].defaultMember, "b");
assert.equal(swap.route.final, "a");
assert.throws(() => rewriteOutboundReferences({ nodes: [{ advancedJson: "{" }] }, [["a", "b"]]), /修正.*JSON/);
console.log("basic logic regression tests passed: dedupe, resolver/HTTP round trips, references, mainland downloads, interfaces and listeners");
