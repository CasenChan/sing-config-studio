import assert from "node:assert/strict";
import { dedupeNodes, diffNodes, exportShareLinks, filterNodes, renameNodes, toShareLink } from "../modules/sharelink.js";
import { normalizeOutbound } from "../modules/outbound.js";

const uuid = "17f6f870-6f59-4c91-a4dc-46cfe797c241";
const node = (overrides) => normalizeOutbound({ server: "example.com", port: 443, ...overrides });

const vless = toShareLink(node({ type: "vless", tag: "HK 01", uuid, tls: true, sni: "www.microsoft.com", reality: true, publicKey: "pk", shortId: "sid", flow: "xtls-rprx-vision", fingerprint: "chrome" }));
assert.equal(vless.ok, true);
assert.match(vless.link, /^vless:\/\/17f6f870-6f59-4c91-a4dc-46cfe797c241@example\.com:443\?/);
assert.match(vless.link, /security=reality/);
assert.match(vless.link, /pbk=pk/);
assert.match(vless.link, /#HK%2001$/);

const trojan = toShareLink(node({ type: "trojan", tag: "TR", password: "p@ss word", tls: true, transport: "ws", path: "/ws", host: "cdn.example.com" }));
assert.match(trojan.link, /^trojan:\/\/p%40ss%20word@/);
assert.match(trojan.link, /type=ws/);
assert.match(trojan.link, /path=%2Fws/);

const ss = toShareLink(node({ type: "shadowsocks", tag: "SS", method: "aes-128-gcm", password: "pass" }));
assert.match(ss.link, /^ss:\/\/[A-Za-z0-9+/]+@example\.com:443#SS$/);
assert.equal(Buffer.from(ss.link.slice(5).split("@")[0], "base64").toString(), "aes-128-gcm:pass");

const hy2 = toShareLink(node({ type: "hysteria2", tag: "HY2", password: "pw", sni: "example.com", obfsType: "salamander", obfsPassword: "ob" }));
assert.match(hy2.link, /^hysteria2:\/\/pw@example\.com:443\?/);
assert.match(hy2.link, /obfs=salamander/);

const tuic = toShareLink(node({ type: "tuic", tag: "TUIC", uuid, password: "pw", congestionControl: "bbr", udpRelayMode: "native" }));
assert.match(tuic.link, /^tuic:\/\/17f6f870-6f59-4c91-a4dc-46cfe797c241:pw@/);
assert.match(tuic.link, /congestion_control=bbr/);

const anytls = toShareLink(node({ type: "anytls", tag: "AT", password: "pw", sni: "example.com" }));
assert.match(anytls.link, /^anytls:\/\/pw@example\.com:443\?sni=example\.com#AT$/);

const vmess = toShareLink(node({ type: "vmess", tag: "VM", uuid, transport: "ws", path: "/ray", host: "cdn.example.com", tls: true }));
assert.match(vmess.link, /^vmess:\/\//);
const payload = JSON.parse(Buffer.from(vmess.link.slice(8), "base64").toString());
assert.equal(payload.id, uuid);
assert.equal(payload.net, "ws");
assert.equal(payload.tls, "tls");

// 不支持的类型有明确原因
const ssh = toShareLink(node({ type: "ssh", tag: "SSH", user: "root", password: "p" }));
assert.equal(ssh.ok, false);
assert.match(ssh.reason, /没有通用分享链接格式/);
assert.equal(toShareLink(node({ type: "trojan", tag: "x", password: "p", server: "" })).ok, false);

// 批量导出
const result = exportShareLinks([
  node({ type: "trojan", tag: "A", password: "p" }),
  node({ type: "ssh", tag: "B", user: "root", password: "p" })
]);
assert.equal(result.links.length, 1);
assert.deepEqual(result.skipped.map((item) => item.tag), ["B"]);

// 去重 / 过滤 / 重命名 / 差异
const nodes = [
  { tag: "HK 01", type: "trojan", server: "a", port: 443, password: "p" },
  { tag: "HK 01 copy", type: "trojan", server: "a", port: 443, password: "p" },
  { tag: "JP 02", type: "trojan", server: "b", port: 443, password: "p" },
  { tag: "试用 03", type: "trojan", server: "c", port: 443, password: "p" }
];
assert.equal(dedupeNodes(nodes).removed, 1);
assert.deepEqual(dedupeNodes(nodes).nodes.map((item) => item.tag), ["HK 01", "JP 02", "试用 03"]);
assert.deepEqual(filterNodes(nodes, { include: "HK" }).nodes.map((item) => item.tag), ["HK 01", "HK 01 copy"]);
assert.deepEqual(filterNodes(nodes, { exclude: "试用" }).nodes.length, 3);
assert.deepEqual(renameNodes(nodes.slice(0, 1), { prefix: "[A] ", search: "HK", replace: "香港" })[0].tag, "[A] 香港 01");
assert.deepEqual(diffNodes(nodes.slice(0, 2), nodes.slice(1)), { added: ["JP 02", "试用 03"], removed: ["HK 01"], kept: ["HK 01 copy"] });

console.log("share link tests passed");
