import assert from "node:assert/strict";
import {
  OUTBOUND_TYPES,
  buildGroup,
  buildOutbound,
  detectDetourCycles,
  groupMembers,
  normalizeGroup,
  normalizeOutbound,
  outboundIsComplete,
  outboundModule,
  validateGroup,
  validateOutbound
} from "../modules/outbound.js";

const uuid = "17f6f870-6f59-4c91-a4dc-46cfe797c241";
const ob = (overrides) => normalizeOutbound({ id: overrides.tag, server: "example.com", port: 443, ...overrides });

const minimal = {
  direct: ob({ type: "direct", tag: "direct-out" }),
  bridge: ob({ type: "bridge", tag: "bridge-out", interface: "eth0" }),
  socks: ob({ type: "socks", tag: "socks-out" }),
  http: ob({ type: "http", tag: "http-out" }),
  shadowsocks: ob({ type: "shadowsocks", tag: "ss-out", password: "pass" }),
  vmess: ob({ type: "vmess", tag: "vmess-out", uuid }),
  vless: ob({ type: "vless", tag: "vless-out", uuid }),
  trojan: ob({ type: "trojan", tag: "trojan-out", password: "pass" }),
  naive: ob({ type: "naive", tag: "naive-out", username: "u", password: "p" }),
  hysteria: ob({ type: "hysteria", tag: "hy-out", authString: "auth", up: "50 Mbps", down: "100 Mbps" }),
  hysteria2: ob({ type: "hysteria2", tag: "hy2-out", password: "pass" }),
  shadowtls: ob({ type: "shadowtls", tag: "stls-out", password: "pass" }),
  tuic: ob({ type: "tuic", tag: "tuic-out", uuid, password: "pass" }),
  anytls: ob({ type: "anytls", tag: "anytls-out", password: "pass" }),
  snell: ob({ type: "snell", tag: "snell-out", psk: "psk" }),
  tor: ob({ type: "tor", tag: "tor-out" }),
  ssh: ob({ type: "ssh", tag: "ssh-out", port: 22, user: "root", password: "pass" })
};

assert.deepEqual(Object.keys(minimal).sort(), [...OUTBOUND_TYPES].sort(), "所有出站类型都应有最小模板");

for (const [type, node] of Object.entries(minimal)) {
  assert.equal(validateOutbound(node, { nodes: Object.values(minimal) }), "", `${type} 应通过校验`);
  const built = buildOutbound(node);
  assert.equal(built.type, type);
  assert.equal(built.tag, node.tag);
  assert.ok(!("advancedJson" in built) && !("tlsCertificate" in built), `${type} 不应输出界面内部字段`);
  assert.equal(outboundIsComplete(node), true);
}

// 无服务器地址的类型不会写出 server 字段
assert.equal("server" in buildOutbound(minimal.direct), false);
assert.equal("server" in buildOutbound(minimal.tor), false);
assert.equal(buildOutbound(minimal.ssh).server_port, 22);

// TLS 客户端共享对象：uTLS / ECH / REALITY / 分片
const reality = ob({ type: "vless", tag: "reality", uuid, tls: true, sni: "www.microsoft.com", reality: true, publicKey: "key", shortId: "abcd", fingerprint: "chrome" });
assert.equal(validateOutbound(reality, {}), "");
const realityBuilt = buildOutbound(reality);
assert.deepEqual(realityBuilt.tls.reality, { enabled: true, public_key: "key", short_id: "abcd" });
assert.deepEqual(realityBuilt.tls.utls, { enabled: true, fingerprint: "chrome" });
assert.equal(realityBuilt.flow, "xtls-rprx-vision");
assert.match(validateOutbound({ ...reality, echEnabled: true }, {}), /REALITY 与 ECH/);
assert.match(validateOutbound({ ...reality, tls: false }, {}), /REALITY 需要同时启用 TLS/);
assert.match(validateOutbound(ob({ type: "shadowtls", tag: "t", password: "p", tls: true, reality: true, publicKey: "k" }), {}), /不支持 REALITY/);

const ech = ob({ type: "vmess", tag: "ech", uuid, tls: true, echEnabled: true, echConfig: "-----BEGIN ECH CONFIGS-----\nabc\n-----END ECH CONFIGS-----" });
assert.equal(validateOutbound(ech, {}), "");
assert.equal(buildOutbound(ech).tls.ech.enabled, true);
assert.equal(buildOutbound(ech).tls.ech.config.length, 3);

const fragment = ob({ type: "trojan", tag: "frag", password: "p", tls: true, tlsFragment: true, tlsFragmentFallbackDelay: "500ms", tlsRecordFragment: true });
assert.equal(validateOutbound(fragment, {}), "");
assert.equal(buildOutbound(fragment).tls.fragment, true);
assert.equal(buildOutbound(fragment).tls.record_fragment, true);

// 传输层、多路复用与 UDP over TCP
const ws = ob({ type: "vmess", tag: "ws", uuid, tls: true, transport: "ws", path: "/ray", host: "cdn.example.com", maxEarlyData: "2048", earlyDataHeaderName: "Sec-WebSocket-Protocol" });
assert.deepEqual(buildOutbound(ws).transport, { type: "ws", path: "/ray", headers: { Host: "cdn.example.com" }, max_early_data: 2048, early_data_header_name: "Sec-WebSocket-Protocol" });
const mux = ob({ type: "trojan", tag: "mux", password: "p", multiplexEnabled: true, multiplexProtocol: "h2mux", maxConnections: "4", brutalEnabled: true, brutalUp: "50", brutalDown: "100" });
assert.equal(validateOutbound(mux, {}), "");
assert.deepEqual(buildOutbound(mux).multiplex, { enabled: true, protocol: "h2mux", max_connections: 4, brutal: { enabled: true, up_mbps: 50, down_mbps: 100 } });
assert.match(validateOutbound({ ...mux, brutalDown: "" }, {}), /上下行带宽/);
const uot = ob({ type: "shadowsocks", tag: "uot", password: "p", uotEnabled: true, uotVersion: "2" });
assert.deepEqual(buildOutbound(uot).udp_over_tcp, { enabled: true, version: 2 });

// 协议内约束
assert.match(validateOutbound(ob({ type: "vmess", tag: "v", uuid: "not-a-uuid" }), {}), /UUID 格式无效/);
assert.match(validateOutbound(ob({ type: "tuic", tag: "t", uuid, password: "" }), {}), /需要填写密码/);
assert.match(validateOutbound(ob({ type: "hysteria", tag: "h" }), {}), /认证字符串/);
assert.match(validateOutbound(ob({ type: "hysteria2", tag: "h", password: "p", serverPorts: "443-500" }), {}), /端口范围无效/);
assert.equal(validateOutbound(ob({ type: "hysteria2", tag: "h", password: "p", serverPorts: "443:500", hopInterval: "30s" }), {}), "");
assert.match(validateOutbound(ob({ type: "ssh", tag: "s", user: "root" }), {}), /密码或私钥/);
assert.match(validateOutbound(ob({ type: "snell", tag: "s", psk: "p", version: "6", obfsMode: "http" }), {}), /v6 不支持 obfs/);
assert.match(validateOutbound(ob({ type: "anytls", tag: "a", password: "p", tls: false }), {}), /必须启用 TLS/);
assert.match(validateOutbound(ob({ type: "vmess", tag: "v", uuid, advancedJson: '{"domain_strategy":"prefer_ipv4"}' }), {}), /已弃用|已移除/);
assert.match(validateOutbound(ob({ type: "vmess", tag: "v", uuid, advancedJson: '{"nope":1}' }), {}), /不是 VMess 1.14 字段/);
assert.equal(validateOutbound(ob({ type: "vmess", tag: "v", uuid, advancedJson: '{"global_padding":true}' }), {}), "");

// 拨号字段与引用
assert.match(validateOutbound(ob({ type: "trojan", tag: "t", password: "p", detour: "ghost" }), { outboundTags: ["direct"] }), /上游出站不存在/);
assert.equal(validateOutbound(ob({ type: "trojan", tag: "t", password: "p", detour: "direct" }), { outboundTags: ["direct"] }), "");

// 出站组
const nodeTags = ["node-a", "node-b"];
const urltest = normalizeGroup({ id: "g1", type: "urltest", tag: "auto", includeAllNodes: true, url: "https://www.gstatic.com/generate_204", interval: "3m", tolerance: "50" });
const selector = normalizeGroup({ id: "g2", type: "selector", tag: "proxy", includeAllNodes: true, includeDirect: true, members: "auto", defaultMember: "auto" });
assert.equal(validateGroup(urltest, { nodeTags, groups: [urltest, selector] }), "");
assert.equal(validateGroup(selector, { nodeTags, groupTags: ["auto"], groups: [urltest, selector] }), "");
assert.deepEqual(buildGroup(urltest, { nodeTags }), { type: "urltest", tag: "auto", outbounds: nodeTags, url: "https://www.gstatic.com/generate_204", interval: "3m", tolerance: 50 });
assert.deepEqual(buildGroup(selector, { nodeTags, groupTags: ["auto"] }), { type: "selector", tag: "proxy", outbounds: ["auto", "node-a", "node-b", "direct"], default: "auto" });
assert.match(validateGroup(normalizeGroup({ id: "g3", tag: "empty", includeAllNodes: false }), { nodeTags }), /至少需要一个成员/);
assert.match(validateGroup(normalizeGroup({ id: "g4", tag: "x", members: "ghost" }), { nodeTags }), /成员不存在/);
assert.match(validateGroup(normalizeGroup({ id: "g5", tag: "self", members: "self" }), { nodeTags }), /不能把自己作为成员/);
assert.match(validateGroup(normalizeGroup({ id: "g6", type: "urltest", tag: "u", includeAllNodes: true, interval: "3 minutes" }), { nodeTags }), /Duration/);
assert.match(validateGroup(normalizeGroup({ id: "g7", tag: "d", includeAllNodes: true, defaultMember: "ghost" }), { nodeTags }), /默认成员/);
assert.deepEqual(groupMembers(normalizeGroup({ tag: "g", members: "node-a, ghost", includeAllNodes: false }), { nodeTags }), ["node-a"]);

// detour 环路检测
assert.deepEqual(detectDetourCycles([{ tag: "a", detour: "b" }, { tag: "b", detour: "a" }]).length, 1);
assert.deepEqual(detectDetourCycles([{ tag: "a", detour: "b" }, { tag: "b" }]), []);
const selfGroup = normalizeGroup({ tag: "proxy", includeAllNodes: true });
assert.equal(detectDetourCycles([{ tag: "node-a", detour: "proxy" }], [selfGroup]).length, 1);

// 模块产物：组在前、节点在后、始终带 direct
const config = {};
outboundModule.extendConfig(config, {
  nodes: [ob({ type: "trojan", tag: "node-a", password: "p" }), { ...ob({ type: "trojan", tag: "node-b", password: "p" }), enabled: false }],
  groups: [urltest, selector]
});
assert.deepEqual(config.outbounds.map((item) => item.tag), ["auto", "proxy", "node-a", "direct"]);
assert.deepEqual(config.outbounds[0].outbounds, ["node-a"]);
assert.equal(config.outbounds.at(-1).type, "direct");

// 没有可用成员的组不会写进配置
const emptyConfig = {};
outboundModule.extendConfig(emptyConfig, { nodes: [], groups: [urltest] });
assert.deepEqual(emptyConfig.outbounds.map((item) => item.tag), ["direct"]);

console.log("outbound module tests passed");

// REALITY：内核的 TLS 层是协议无关的，TCP 类 TLS 出站都可用；QUIC 类不可用
const anytlsReality = ob({ type: "anytls", tag: "anytls-reality", password: "p", tls: true, sni: "www.microsoft.com", reality: true, publicKey: "pk", shortId: "abcd" });
assert.equal(validateOutbound(anytlsReality, {}), "");
assert.deepEqual(buildOutbound(anytlsReality).tls.reality, { enabled: true, public_key: "pk", short_id: "abcd" });
assert.equal(buildOutbound(anytlsReality).flow, undefined, "flow 只属于 VLESS");
assert.equal(validateOutbound(ob({ type: "trojan", tag: "t", password: "p", tls: true, reality: true, publicKey: "pk" }), {}), "");
assert.match(validateOutbound(ob({ type: "hysteria2", tag: "h", password: "p", tls: true, reality: true, publicKey: "pk" }), {}), /QUIC/);
assert.match(validateOutbound(ob({ type: "tuic", tag: "t", uuid, password: "p", tls: true, reality: true, publicKey: "pk" }), {}), /QUIC/);
console.log("outbound reality coverage test passed");
