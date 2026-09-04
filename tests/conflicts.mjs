import assert from "node:assert/strict";
import { detectConflicts, hasBlockingConflicts, summarizeConflicts } from "../modules/conflicts.js";

const baseConfig = () => ({
  inbounds: [
    { type: "tun", tag: "tun-in", address: ["172.19.0.1/30"], auto_route: true, stack: "mixed" },
    { type: "mixed", tag: "mixed-in", listen: "127.0.0.1", listen_port: 7890 }
  ],
  outbounds: [
    { type: "selector", tag: "proxy", outbounds: ["node-a", "direct"], default: "node-a" },
    { type: "trojan", tag: "node-a" },
    { type: "direct", tag: "direct" }
  ],
  dns: {
    servers: [{ type: "local", tag: "local-dns" }, { type: "https", tag: "remote-dns" }],
    rules: [{ domain_suffix: [".lan"], action: "route", server: "local-dns" }],
    final: "remote-dns"
  },
  route: {
    rules: [{ action: "sniff" }, { protocol: ["dns"], action: "hijack-dns" }, { ip_is_private: true, action: "route", outbound: "direct" }],
    final: "proxy",
    auto_detect_interface: true,
    default_domain_resolver: "local-dns"
  },
  experimental: { clash_api: { external_controller: "127.0.0.1:9090" } }
});

const messages = (issues) => issues.map((item) => item.message);

// 基线配置没有冲突
assert.deepEqual(detectConflicts(baseConfig()), []);
assert.equal(hasBlockingConflicts([]), false);

// 标签重复
const dupTags = baseConfig();
dupTags.inbounds.push({ type: "socks", tag: "mixed-in", listen: "127.0.0.1", listen_port: 1080 });
const dupIssues = detectConflicts(dupTags);
assert.ok(messages(dupIssues).some((m) => m.includes("入站标签重复：mixed-in")));
assert.equal(hasBlockingConflicts(dupIssues), true);

// 监听端口冲突：完全相同、以及通配地址与具体地址
const portClash = baseConfig();
portClash.inbounds.push({ type: "socks", tag: "socks-in", listen: "0.0.0.0", listen_port: 7890 });
assert.ok(messages(detectConflicts(portClash)).some((m) => m.includes("监听地址冲突")));

const noClash = baseConfig();
noClash.inbounds.push({ type: "socks", tag: "socks-in", listen: "127.0.0.1", listen_port: 1080 });
assert.deepEqual(detectConflicts(noClash), []);

// 与 Clash API 端口冲突
const apiClash = baseConfig();
apiClash.inbounds.push({ type: "socks", tag: "socks-in", listen: "127.0.0.1", listen_port: 9090 });
assert.ok(messages(detectConflicts(apiClash, { clashApiAddress: "127.0.0.1:9090" })).some((m) => m.includes("Clash API")));

// TUN 相关
const twoTun = baseConfig();
twoTun.inbounds.push({ type: "tun", tag: "tun-2", address: ["172.20.0.1/30"], auto_route: true });
const twoTunIssues = detectConflicts(twoTun);
assert.ok(messages(twoTunIssues).some((m) => m.includes("2 个 TUN 入站")));
assert.equal(hasBlockingConflicts(twoTunIssues), true);

const loop = baseConfig();
loop.route.auto_detect_interface = false;
const loopIssues = detectConflicts(loop);
assert.ok(messages(loopIssues).some((m) => m.includes("路由环路")));
assert.equal(hasBlockingConflicts(loopIssues), true);
const fixedLoop = baseConfig();
fixedLoop.route.auto_detect_interface = false;
fixedLoop.route.default_interface = "en0";
assert.deepEqual(detectConflicts(fixedLoop), []);

const noHijack = baseConfig();
noHijack.route.rules = [{ action: "sniff" }];
const noHijackIssues = detectConflicts(noHijack);
assert.ok(messages(noHijackIssues).some((m) => m.includes("hijack-dns")));
assert.equal(hasBlockingConflicts(noHijackIssues), false, "缺少 hijack-dns 只是提醒");

const redirectClash = baseConfig();
redirectClash.inbounds[0].auto_redirect = true;
redirectClash.inbounds.push({ type: "tproxy", tag: "tproxy-in", listen_port: 1082 });
assert.ok(messages(detectConflicts(redirectClash)).some((m) => m.includes("重复接管")));

// FakeIP 冲突
const fakeip = baseConfig();
fakeip.dns.servers.push({ type: "fakeip", tag: "fakeip", inet4_range: "198.18.0.0/15" });
fakeip.route.default_domain_resolver = "fakeip";
const fakeipIssues = detectConflicts(fakeip);
assert.ok(messages(fakeipIssues).some((m) => m.includes("默认域名解析器不能指向 FakeIP")));
assert.equal(hasBlockingConflicts(fakeipIssues), true);

const unusedFakeip = baseConfig();
unusedFakeip.dns.servers.push({ type: "fakeip", tag: "fakeip", inet4_range: "198.18.0.0/15" });
const unusedIssues = detectConflicts(unusedFakeip);
assert.ok(messages(unusedIssues).some((m) => m.includes("没有被任何 DNS 规则")));
assert.equal(hasBlockingConflicts(unusedIssues), false);

const usedFakeip = baseConfig();
usedFakeip.dns.servers.push({ type: "fakeip", tag: "fakeip", inet4_range: "198.18.0.0/15" });
usedFakeip.dns.rules.push({ query_type: ["A"], action: "route", server: "fakeip" });
usedFakeip.route.rules = [{ protocol: ["dns"], action: "hijack-dns" }];
assert.ok(messages(detectConflicts(usedFakeip)).some((m) => m.includes("sniff")));

// 引用检查
const missing = baseConfig();
missing.route.rules.push({ inbound: ["ghost-in"], action: "route", outbound: "ghost-out" });
missing.dns.rules.push({ action: "route", server: "ghost-dns" });
missing.route.rules.push({ rule_set: ["ghost-set"], action: "route", outbound: "direct" });
const missingIssues = detectConflicts(missing);
assert.ok(messages(missingIssues).some((m) => m.includes("不存在的入站：ghost-in")));
assert.ok(messages(missingIssues).some((m) => m.includes("不存在的出站：ghost-out")));
assert.ok(messages(missingIssues).some((m) => m.includes("不存在的服务器：ghost-dns")));
assert.ok(messages(missingIssues).some((m) => m.includes("不存在的规则集：ghost-set")));
assert.equal(hasBlockingConflicts(missingIssues), true);

// 出站组成员
const badGroup = baseConfig();
badGroup.outbounds[0].outbounds = ["ghost-node"];
badGroup.outbounds[0].default = "ghost-node";
assert.ok(messages(detectConflicts(badGroup)).some((m) => m.includes("不存在的成员：ghost-node")));

const emptyGroup = baseConfig();
emptyGroup.outbounds[0].outbounds = [];
delete emptyGroup.outbounds[0].default;
assert.ok(messages(detectConflicts(emptyGroup)).some((m) => m.includes("没有成员")));

// 远程规则集缓存提醒
const remoteSet = baseConfig();
remoteSet.route.rule_set = [{ type: "remote", tag: "geosite-cn", url: "https://example.com/geosite-cn.srs" }];
const remoteIssues = detectConflicts(remoteSet);
assert.ok(messages(remoteIssues).some((m) => m.includes("cache_file")));
assert.equal(hasBlockingConflicts(remoteIssues), false);

// 模块级错误与跳过的规则会并入清单
const withModule = detectConflicts(baseConfig(), {
  moduleIssues: [{ level: "error", scope: "DNS", message: "乐观缓存与禁用缓存冲突" }],
  skippedRules: [{ id: "x" }]
});
assert.equal(hasBlockingConflicts(withModule), true);
assert.deepEqual(summarizeConflicts(withModule), { errors: 1, warnings: 1, total: 2 });

// 去重
const duplicated = detectConflicts(baseConfig(), {
  moduleIssues: [
    { level: "error", scope: "DNS", message: "同一条" },
    { level: "error", scope: "DNS", message: "同一条" }
  ]
});
assert.equal(duplicated.length, 1);

console.log("conflict module tests passed");

// detour 环路
const cycleIssues = detectConflicts(baseConfig(), { detourCycles: [["node-a", "proxy", "node-a"]] });
assert.ok(cycleIssues.some((item) => item.message.includes("环路")));
assert.equal(hasBlockingConflicts(cycleIssues), true);

console.log("conflict detour cycle test passed");
