import assert from "node:assert/strict";
import {
  INBOUND_TYPES,
  buildInbound,
  hasTunInbound,
  inboundTags,
  normalizeInbound,
  validateInbound,
  validateInbounds
} from "../modules/inbound.js";

const inb = (overrides) => normalizeInbound({ id: overrides.tag, ...overrides });

// 每种类型都能生成最小有效配置
const minimal = {
  mixed: inb({ type: "mixed", tag: "mixed-in", listenPort: "7890" }),
  socks: inb({ type: "socks", tag: "socks-in", listenPort: "1080" }),
  http: inb({ type: "http", tag: "http-in", listenPort: "8080" }),
  direct: inb({ type: "direct", tag: "direct-in", listenPort: "5353", overrideAddress: "1.1.1.1", overridePort: "53" }),
  tun: inb({ type: "tun", tag: "tun-in" }),
  redirect: inb({ type: "redirect", tag: "redirect-in", listenPort: "1081" }),
  tproxy: inb({ type: "tproxy", tag: "tproxy-in", listenPort: "1082" }),
  shadowsocks: inb({ type: "shadowsocks", tag: "ss-in", listenPort: "8388", password: "3+HRDrTkYQQyfLLbLndCJA==" }),
  vmess: inb({ type: "vmess", tag: "vmess-in", listenPort: "8443", usersJson: '[{"name":"u","uuid":"17f6f870-6f59-4c91-a4dc-46cfe797c241"}]' }),
  vless: inb({ type: "vless", tag: "vless-in", listenPort: "8444", usersJson: '[{"name":"u","uuid":"17f6f870-6f59-4c91-a4dc-46cfe797c241","flow":"xtls-rprx-vision"}]' }),
  trojan: inb({ type: "trojan", tag: "trojan-in", listenPort: "8445", usersJson: '[{"name":"u","password":"p"}]', tlsEnabled: true, tlsCertificatePath: "/c.pem", tlsKeyPath: "/k.pem" }),
  naive: inb({ type: "naive", tag: "naive-in", listenPort: "8446", usersJson: '[{"username":"u","password":"p"}]', tlsCertificatePath: "/c.pem", tlsKeyPath: "/k.pem" }),
  hysteria: inb({ type: "hysteria", tag: "hy-in", listenPort: "8447", usersJson: '[{"name":"u","auth_str":"p"}]', up: "100 Mbps", down: "100 Mbps", tlsCertificatePath: "/c.pem", tlsKeyPath: "/k.pem" }),
  hysteria2: inb({ type: "hysteria2", tag: "hy2-in", listenPort: "8448", usersJson: '[{"name":"u","password":"p"}]', tlsCertificatePath: "/c.pem", tlsKeyPath: "/k.pem" }),
  shadowtls: inb({ type: "shadowtls", tag: "stls-in", listenPort: "8449", usersJson: '[{"name":"u","password":"p"}]', handshakeServer: "example.com", detour: "ss-in" }),
  tuic: inb({ type: "tuic", tag: "tuic-in", listenPort: "8450", usersJson: '[{"name":"u","uuid":"17f6f870-6f59-4c91-a4dc-46cfe797c241","password":"p"}]', tlsCertificatePath: "/c.pem", tlsKeyPath: "/k.pem" }),
  anytls: inb({ type: "anytls", tag: "anytls-in", listenPort: "8451", usersJson: '[{"name":"u","password":"p"}]', tlsCertificatePath: "/c.pem", tlsKeyPath: "/k.pem" }),
  snell: inb({ type: "snell", tag: "snell-in", listenPort: "8452", psk: "psk" }),
  cloudflared: inb({ type: "cloudflared", tag: "cf-in", token: "token" })
};

assert.deepEqual(Object.keys(minimal).sort(), [...INBOUND_TYPES].sort(), "所有 1.14 入站类型都应有最小模板");

const allTags = Object.values(minimal).map((item) => item.tag);
for (const [type, inbound] of Object.entries(minimal)) {
  const context = { inbounds: Object.values(minimal), outboundTags: ["direct"], dnsServerTags: ["local-dns"] };
  assert.equal(validateInbound(inbound, context), "", `${type} 应通过校验`);
  const built = buildInbound(inbound);
  assert.equal(built.type, type);
  assert.equal(built.tag, inbound.tag);
  assert.ok(!("enabled" in built) && !("usersJson" in built) && !("advancedJson" in built), `${type} 不应输出界面内部字段`);
}
assert.equal(allTags.length, new Set(allTags).size);

// 监听与转发
assert.equal(buildInbound(minimal.mixed).listen, "127.0.0.1");
assert.equal(buildInbound(minimal.mixed).listen_port, 7890);
assert.deepEqual(buildInbound(minimal.direct), { type: "direct", tag: "direct-in", listen_port: 5353, override_address: "1.1.1.1", override_port: 53 });

// TUN：地址、1.14 dns_mode、auto_redirect 依赖
const tun = buildInbound(minimal.tun);
assert.deepEqual(tun.address, ["172.19.0.1/30", "fdfe:dcba:9876::1/126"]);
assert.equal(tun.auto_route, true);
assert.equal(tun.stack, "mixed");
assert.equal(JSON.stringify(tun).includes("inet4_address"), false);
assert.equal(validateInbound(inb({ type: "tun", tag: "t", dnsMode: "hijack" }), {}), "");
assert.match(validateInbound(inb({ type: "tun", tag: "t", dnsMode: "hijacked" }), {}), /DNS 模式无效/);
assert.match(validateInbound(inb({ type: "tun", tag: "t", autoRedirect: true, autoRoute: false }), {}), /auto_redirect 需要同时启用 auto_route/);
assert.match(validateInbound(inb({ type: "tun", tag: "t", address: "172.19.0.1" }), {}), /必须是 CIDR/);
assert.match(validateInbound(inb({ type: "tun", tag: "t", includeMacAddress: "zz:11" }), {}), /MAC 地址无效/);
assert.equal(buildInbound(inb({ type: "tun", tag: "t", dnsMode: "hijack", udpTimeout: "5m" })).udp_timeout, "5m");

// 用户列表按协议校验
assert.match(validateInbound(inb({ type: "vmess", tag: "v", usersJson: '[{"name":"u"}]' }), {}), /缺少 uuid/);
assert.match(validateInbound(inb({ type: "vmess", tag: "v", usersJson: '[{"name":"u","uuid":"x","password":"p"}]' }), {}), /不支持的字段：password/);
assert.match(validateInbound(inb({ type: "trojan", tag: "t", tlsEnabled: true, tlsCertificatePath: "/c", tlsKeyPath: "/k" }), {}), /需要至少一个用户/);
assert.match(validateInbound(inb({ type: "hysteria2", tag: "h", tlsCertificatePath: "/c", tlsKeyPath: "/k" }), {}), /需要至少一个用户/);

// TLS 必备项
assert.match(validateInbound(inb({ type: "tuic", tag: "t", usersJson: '[{"uuid":"x","password":"p"}]' }), {}), /证书/);
assert.match(validateInbound(inb({ type: "anytls", tag: "a", usersJson: '[{"password":"p"}]', tlsEnabled: false }), {}), /必须启用 TLS/);
assert.match(validateInbound(inb({ type: "vmess", tag: "v", usersJson: '[{"name":"u","uuid":"x"}]', tlsEnabled: true, tlsCertificate: "PEM", tlsCertificatePath: "/c", tlsKeyPath: "/k" }), {}), /不能同时设置/);
assert.equal(buildInbound(minimal.trojan).tls.enabled, true);
assert.equal(buildInbound(minimal.trojan).tls.certificate_path, "/c.pem");

// ShadowTLS / Snell / Shadowsocks 的协议内约束
assert.match(validateInbound(inb({ type: "shadowtls", tag: "s", version: "3", usersJson: '[{"password":"p"}]', handshakeServer: "e.com" }), {}), /detour/);
assert.match(validateInbound(inb({ type: "shadowtls", tag: "s", version: "2", handshakeServer: "e.com", detour: "ss-in" }), { inbounds: [minimal.shadowsocks] }), /v2 需要填写密码/);
assert.match(validateInbound(inb({ type: "shadowtls", tag: "s", version: "3", usersJson: '[{"password":"p"}]', handshakeServer: "e.com", detour: "ghost" }), { inbounds: [minimal.shadowsocks] }), /监听 detour 入站不存在/);
assert.equal(buildInbound(minimal.shadowtls).handshake.server, "example.com");
assert.equal(buildInbound(minimal.shadowtls).version, 3);
assert.match(validateInbound(inb({ type: "snell", tag: "s", version: "6", psk: "p", obfsMode: "http" }), {}), /v6 不支持 obfs/);
assert.match(validateInbound(inb({ type: "shadowsocks", tag: "s", password: "" }), {}), /服务端密码或至少一个用户/);

// Hysteria 2 混淆与伪装
assert.match(validateInbound(inb({ type: "hysteria2", tag: "h", usersJson: '[{"password":"p"}]', tlsCertificatePath: "/c", tlsKeyPath: "/k", obfsType: "salamander" }), {}), /混淆密码/);
assert.match(validateInbound(inb({ type: "hysteria2", tag: "h", usersJson: '[{"password":"p"}]', tlsCertificatePath: "/c", tlsKeyPath: "/k", masquerade: "example.com" }), {}), /伪装地址/);
assert.deepEqual(buildInbound(inb({ type: "hysteria2", tag: "h", usersJson: '[{"password":"p"}]', tlsCertificatePath: "/c", tlsKeyPath: "/k", obfsType: "salamander", obfsPassword: "x" })).obfs, { type: "salamander", password: "x" });

// 传输层与多路复用
const wsVmess = inb({ type: "vmess", tag: "v", usersJson: '[{"name":"u","uuid":"x"}]', transportType: "ws", transportPath: "/ray", transportHost: "cdn.example.com", multiplexEnabled: true, brutalEnabled: true, brutalUp: "100", brutalDown: "100" });
assert.equal(validateInbound(wsVmess, {}), "");
assert.deepEqual(buildInbound(wsVmess).transport, { type: "ws", path: "/ray", headers: { Host: "cdn.example.com" } });
assert.deepEqual(buildInbound(wsVmess).multiplex, { enabled: true, brutal: { enabled: true, up_mbps: 100, down_mbps: 100 } });
assert.match(validateInbound(inb({ type: "vless", tag: "v", usersJson: '[{"name":"u","uuid":"x"}]', transportType: "grpc" }), {}), /Service Name/);

// 拒绝 1.11 起被规则动作取代的旧入站字段
assert.match(validateInbound(inb({ type: "mixed", tag: "m", advancedJson: '{"sniff":true}' }), {}), /已弃用|已移除/);
assert.match(validateInbound(inb({ type: "tun", tag: "t", advancedJson: '{"inet4_address":["172.19.0.1/30"]}' }), {}), /已弃用|已移除/);
assert.match(validateInbound(inb({ type: "mixed", tag: "m", advancedJson: '{"nope":1}' }), {}), /不是 Mixed 1.14 字段/);
assert.equal(validateInbound(inb({ type: "tun", tag: "t", advancedJson: '{"auto_redirect_input_mark":"0x2023"}' }), {}), "");

// 标签唯一与整体校验
assert.match(validateInbounds([minimal.mixed, { ...minimal.socks, tag: "mixed-in" }], {}), /标签必须唯一/);
assert.match(validateInbounds([], {}), /至少需要一个启用的入站/);
assert.equal(validateInbounds([minimal.mixed, minimal.tun], {}), "");
assert.deepEqual(inboundTags([minimal.mixed, { ...minimal.tun, enabled: false }]), ["mixed-in"]);
assert.equal(hasTunInbound([minimal.mixed, minimal.tun]), true);
assert.equal(hasTunInbound([minimal.mixed, { ...minimal.tun, enabled: false }]), false);

console.log("inbound module tests passed");
