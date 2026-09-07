import assert from "node:assert/strict";
import { mkdtemp, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { deflateRawSync } from "node:zlib";
import { issueSignature, subscriptionDigest, verifySignature } from "../server/subscription-signing.mjs";
import { startTestServer } from "./server-helper.mjs";

const directory = await mkdtemp(join(tmpdir(), "sing-signing-test-"));
const settings = { STATE_DIRECTORY: directory, SUBSCRIPTION_SIGNING_KEY: "" };
let server = await startTestServer(settings);
const config = { log: { level: "info" }, inbounds: [{ type: "mixed", tag: "m", listen_port: 7890 }], outbounds: [{ type: "direct", tag: "direct" }], dns: { servers: [{ type: "local", tag: "l" }] } };
async function signed(fields, days = 0, token = "") {
  const body = { digest: subscriptionDigest(fields), days, token };
  const response = await fetch(`${server.base}/api/sign-subscription`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
  assert.equal(response.status, 200);
  return new URL(`${server.base}/subscription?${new URLSearchParams({ ...fields, ...await response.json(), ...(token ? { token } : {}) })}`);
}
try {
  const fields = { data: Buffer.from(JSON.stringify(config)).toString("base64url"), enc: "", name: "test", interval: "60" };
  const plainUrl = await signed(fields);
  assert.deepEqual(await (await fetch(plainUrl)).json(), config);
  const compressed = deflateRawSync(Buffer.from(JSON.stringify(config))).toString("base64url");
  const compressedUrl = await signed({ ...fields, data: compressed, enc: "deflate" }, 7);
  const response = await fetch(compressedUrl);
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), config);
  assert.equal(response.headers.get("profile-update-interval"), "60");
  assert.equal((await fetch(compressedUrl, { method: "HEAD" })).status, 200);
  assert.equal((await fetch(await signed({ ...fields, enc: "gzip" }))).status, 400);
  assert.equal((await fetch(await signed({ ...fields, data: Buffer.from('{"hello":1}').toString("base64url") }))).status, 400);

  // 仅端点配置可被订阅传递，但不能因此放宽数组形状检查。
  const endpointOnly = { ...config, endpoints: [{ type: "tailscale", tag: "tail" }] };
  delete endpointOnly.outbounds;
  const endpointUrl = await signed({ ...fields, data: Buffer.from(JSON.stringify(endpointOnly)).toString("base64url") });
  assert.deepEqual(await (await fetch(endpointUrl)).json(), endpointOnly);
  for (const invalid of [{ ...endpointOnly, outbounds: {} }, { ...config, endpoints: {} }, { inbounds: [], endpoints: [] }]) {
    assert.equal((await fetch(await signed({ ...fields, data: Buffer.from(JSON.stringify(invalid)).toString("base64url") }))).status, 400);
  }

  // 改、删、重复任一签名字段，以及退回无签名格式，都不能绕过有效期。
  for (const name of ["data", "enc", "name", "interval", "expires", "sig", "sigv"]) {
    for (const operation of ["change", "delete", "duplicate"]) {
      const changed = new URL(compressedUrl);
      if (operation === "change") changed.searchParams.set(name, name === "expires" ? "0" : "changed");
      if (operation === "delete") changed.searchParams.delete(name);
      if (operation === "duplicate") changed.searchParams.append(name, changed.searchParams.get(name));
      assert.equal((await fetch(changed)).status, 401, `${operation} ${name}`);
    }
  }
  assert.equal((await fetch(`${server.base}/subscription?data=${fields.data}`)).status, 401);
  const key = "unit-test-signing-key-not-for-production";
  const at = 1_700_000_000_000;
  const expiring = new URLSearchParams({ ...fields, ...issueSignature(key, { digest: subscriptionDigest(fields), days: 1 }, at) });
  assert.equal(verifySignature(key, expiring, at + 86_399_000), null);
  assert.equal(verifySignature(key, expiring, at + 86_400_000).status, 410);
  const permanent = new URLSearchParams({ ...fields, ...issueSignature(key, { digest: subscriptionDigest(fields), days: 0 }, at) });
  assert.equal(verifySignature(key, permanent, at + 86400000000), null);
  assert.throws(() => issueSignature(key, { digest: subscriptionDigest(fields), days: -1 }), /有效期/);
  const cors = await fetch(`${server.base}/api/sign-subscription`, { method: "OPTIONS", headers: { origin: "https://other.example", "access-control-request-method": "POST" } });
  assert.equal(cors.status, 204);
  assert.equal(cors.headers.get("access-control-allow-origin"), "*");
  assert.equal((await (await fetch(`${server.base}/api/status`)).json()).signatureVersion, 1);
  assert.equal((await stat(join(directory, "subscription-signing-key"))).mode & 0o777, 0o600);

  // 重启沿用磁盘密钥；独立 token 同时约束签发和读取。
  await server.close();
  server = await startTestServer(settings);
  assert.equal((await fetch(`${server.base}${compressedUrl.pathname}${compressedUrl.search}`)).status, 200);
  await server.close();
  server = await startTestServer({ ...settings, SUBSCRIPTION_TOKEN: "private-test-token" });
  const denied = await fetch(`${server.base}/api/sign-subscription`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ digest: subscriptionDigest(fields), days: 1 }) });
  assert.equal(denied.status, 401);
  const privateUrl = await signed(fields, 1, "private-test-token");
  assert.equal((await fetch(privateUrl)).status, 200);
  privateUrl.searchParams.delete("token");
  assert.equal((await fetch(privateUrl)).status, 401);
  console.log("signed subscription endpoint tests passed");
} finally { await server.close(); await rm(directory, { recursive: true, force: true }); }
