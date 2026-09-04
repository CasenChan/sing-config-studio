import assert from "node:assert/strict";
import {
  SERVICE_TYPES,
  buildCertificate,
  buildExperimental,
  buildNtp,
  buildService,
  normalizeService,
  normalizeServiceState,
  serviceModule,
  validateService,
  validateServiceState
} from "../modules/services.js";

const svc = (overrides) => normalizeService({ id: overrides.tag, ...overrides });

const minimal = {
  api: svc({ type: "api", tag: "api" }),
  derp: svc({ type: "derp", tag: "derp", tlsEnabled: true, tlsCertificatePath: "/c.pem", tlsKeyPath: "/k.pem" }),
  resolved: svc({ type: "resolved", tag: "resolved" }),
  "ssm-api": svc({ type: "ssm-api", tag: "ssm", serversJson: '{"ss-in":"http://127.0.0.1:8080"}' }),
  ccm: svc({ type: "ccm", tag: "ccm", usersJson: '[{"name":"u","token":"t"}]' }),
  ocm: svc({ type: "ocm", tag: "ocm", usersJson: '[{"name":"u","token":"t"}]' }),
  "hysteria-realm": svc({ type: "hysteria-realm", tag: "realm", tlsEnabled: true, tlsCertificatePath: "/c.pem", tlsKeyPath: "/k.pem", usersJson: '[{"name":"u","token":"t"}]' }),
  "usbip-server": svc({ type: "usbip-server", tag: "usbip-server" }),
  "usbip-client": svc({ type: "usbip-client", tag: "usbip-client", server: "10.0.0.2" })
};
assert.deepEqual(Object.keys(minimal).sort(), [...SERVICE_TYPES].sort(), "所有 1.14 服务类型都应有最小模板");

for (const [type, service] of Object.entries(minimal)) {
  assert.equal(validateService(service, { services: Object.values(minimal) }), "", `${type} 应通过校验`);
  const built = buildService(service);
  assert.equal(built.type, type);
  assert.ok(!("advancedJson" in built) && !("enabled" in built));
}

// API 安全约束
assert.match(validateService(svc({ type: "api", tag: "a", listen: "0.0.0.0", listenPort: "9090" }), {}), /必须设置 secret/);
assert.equal(validateService(svc({ type: "api", tag: "a", listen: "0.0.0.0", listenPort: "9090", secret: "s" }), {}), "");
assert.match(validateService(svc({ type: "api", tag: "a", dashboardEnabled: true }), {}), /本地路径或下载地址/);
assert.deepEqual(buildService(svc({ type: "api", tag: "a", dashboardEnabled: true, dashboardPath: "/ui" })).dashboard, { enabled: true, path: "/ui" });

// 其它服务约束
assert.match(validateService(svc({ type: "hysteria-realm", tag: "r", tlsEnabled: false, usersJson: '[{"name":"u","token":"t"}]' }), {}), /必须启用 TLS/);
assert.match(validateService(svc({ type: "ssm-api", tag: "s" }), {}), /至少一个服务器映射/);
assert.match(validateService(svc({ type: "ccm", tag: "c", usersJson: '[{"name":"u"}]' }), {}), /token/);
assert.match(validateService(svc({ type: "ccm", tag: "c", usersJson: '[{"token":"t"}]', detour: "ghost" }), { outboundTags: ["direct"] }), /detour 出站不存在/);
assert.match(validateService(svc({ type: "usbip-client", tag: "u" }), {}), /服务器地址/);
assert.match(validateService(svc({ type: "api", tag: "a", advancedJson: '{"cache_file":"x"}' }), {}), /已弃用|已移除/);
assert.match(validateService(svc({ type: "api", tag: "a", advancedJson: '{"nope":1}' }), {}), /不是 sing-box API 1.14 字段/);

// NTP / 证书 / experimental
assert.equal(buildNtp({}), undefined);
assert.deepEqual(buildNtp({ ntpEnabled: true, ntpServer: "time.apple.com", ntpServerPort: "123", ntpInterval: "30m", ntpWriteToSystem: true }), {
  enabled: true, server: "time.apple.com", server_port: 123, interval: "30m", write_to_system: true
});
assert.deepEqual(buildCertificate({ certificateStore: "mozilla", certificatePath: "/etc/ca.pem" }), { store: "mozilla", certificate_path: ["/etc/ca.pem"] });

const experimental = buildExperimental({ cacheEnabled: true, cacheStoreFakeip: true, clashEnabled: true, clashController: "127.0.0.1:9090", clashDefaultMode: "Rule" });
assert.deepEqual(experimental.cache_file, { enabled: true, store_fakeip: true });
assert.deepEqual(experimental.clash_api, { external_controller: "127.0.0.1:9090", default_mode: "Rule" });
assert.equal(JSON.stringify(experimental).includes("store_rdrc"), false);
assert.equal(buildExperimental({ cacheEnabled: false, clashEnabled: false }), undefined);
assert.equal(buildExperimental({ clashEnabled: true }, { clashApiEnabled: false }).clash_api, undefined);

const v2ray = buildExperimental({ cacheEnabled: false, clashEnabled: false, v2rayEnabled: true, v2rayListen: "127.0.0.1:8080", v2rayStats: true, v2rayStatsOutbounds: "proxy, direct" });
assert.deepEqual(v2ray.v2ray_api, { listen: "127.0.0.1:8080", stats: { enabled: true, outbounds: ["proxy", "direct"] } });

// 全局校验
assert.match(validateServiceState({ clashEnabled: true, clashController: "0.0.0.0:9090" }), /必须设置 secret/);
assert.equal(validateServiceState({ clashEnabled: true, clashController: "0.0.0.0:9090", clashSecret: "s" }), "");
assert.match(validateServiceState({ clashEnabled: true, clashController: "9090" }), /地址:端口/);
assert.match(validateServiceState({ ntpEnabled: true, ntpServer: "" }), /需要填写服务器/);
assert.match(validateServiceState({ ntpEnabled: true, ntpServer: "t", ntpDetour: "ghost" }, { outboundTags: ["direct"] }), /detour 出站不存在/);
assert.match(validateServiceState({ services: [svc({ type: "usbip-client", tag: "u" })] }), /服务「u」/);

// 模块产物
const config = {};
serviceModule.extendConfig(config, {
  serviceState: normalizeServiceState({
    ntpEnabled: true, ntpServer: "time.apple.com",
    cacheEnabled: true, clashEnabled: true, clashController: "127.0.0.1:9090",
    services: [minimal.api, { ...minimal.resolved, enabled: false }]
  })
}, {});
assert.equal(config.ntp.enabled, true);
assert.equal(config.experimental.cache_file.enabled, true);
assert.deepEqual(config.services.map((item) => item.tag), ["api"]);

console.log("services module tests passed");
