import assert from "node:assert/strict";
import { mkdtemp, readdir, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { issueSignature, subscriptionDigest } from "../server/subscription-signing.mjs";
import { shortSubscriptionStore } from "../server/short-subscriptions.mjs";
import { startTestServer } from "./server-helper.mjs";

const directory = await mkdtemp(join(tmpdir(), "sing-short-test-"));
const key = "short-link-test-signing-key-not-for-production";
const config = { inbounds: [], outbounds: [{ type: "direct", tag: "direct" }] };
const fields = { data: Buffer.from(JSON.stringify(config)).toString("base64url"), enc: "", name: "short-test", interval: "60" };
const signed = (days = 0, at = Date.now()) => ({ ...fields, ...issueSignature(key, { digest: subscriptionDigest(fields), days }, at) });
const permanent = signed();
let server;
async function create(value, token = "") {
  return fetch(`${server.base}/api/short-subscription`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ fields: value, token }) });
}
try {
  server = await startTestServer({ STATE_DIRECTORY: directory, SUBSCRIPTION_SIGNING_KEY: key, SHORT_LINK_MAX_ENTRIES: "2" });
  const response = await create(permanent);
  assert.equal(response.status, 200);
  const { id } = await response.json();
  assert.match(id, /^[A-Za-z0-9_-]{32}$/);
  assert.equal((await (await create(permanent)).json()).id, id, "重复请求复用记录");
  const url = `${server.base}/s/${id}`;
  const short = await fetch(url);
  assert.equal(short.status, 200);
  assert.equal(short.redirected, false, "短链接直接返回配置，不重定向到大 URL");
  assert.deepEqual(await short.json(), config);
  assert.equal(short.headers.get("profile-update-interval"), "60");
  assert.match(short.headers.get("cache-control"), /no-store/);
  const head = await fetch(url, { method: "HEAD" });
  assert.equal(head.status, 200);
  assert.equal(await head.text(), "");
  assert.match((await fetch(`${url}?download=1`)).headers.get("content-disposition"), /attachment/);
  for (const query of ["expires=0", "data=abc", "sig=abc", "token=a&token=b"]) assert.equal((await fetch(`${url}?${query}`)).status, 400);
  assert.equal((await fetch(`${server.base}/s/invalid`)).status, 404);
  assert.equal((await fetch(url, { method: "POST" })).status, 405);
  assert.equal((await fetch(`${server.base}/api/short-subscription`)).status, 405);
  assert.equal((await fetch(`${server.base}/api/short-subscription`, { method: "OPTIONS" })).headers.get("access-control-allow-origin"), "*");
  assert.equal((await create({ ...permanent, expires: "9999999999" })).status, 401);
  assert.equal((await create({ data: fields.data })).status, 400);
  assert.equal((await create(signed(1, Date.now() - 2 * 86400000))).status, 410);
  assert.equal((await stat(join(directory, "short-subscriptions", `${id}.json`))).mode & 0o777, 0o600);
  assert.equal((await fetch(`${server.base}/.data/short-subscriptions/${id}.json`)).status, 404);
  assert.equal((await create(signed(7))).status, 200);
  assert.equal((await create(signed(30))).status, 400, "限制磁盘记录数量");
  assert.equal((await fetch(`${server.base}/subscription?${new URLSearchParams(permanent)}`)).status, 200, "短链接容量满不影响长链接");
  await server.close();
  server = await startTestServer({ STATE_DIRECTORY: directory, SUBSCRIPTION_SIGNING_KEY: key, SUBSCRIPTION_TOKEN: "private-token" });
  assert.equal((await fetch(`${server.base}/s/${id}`)).status, 401);
  assert.deepEqual(await (await fetch(`${server.base}/s/${id}?token=private-token`)).json(), config, "重启后保留配置，并按当前 token 验证");
  assert.equal((await create(permanent)).status, 401);
  assert.equal((await (await create(permanent, "private-token")).json()).id, id);
  const store = shortSubscriptionStore(directory, key);
  const expiredId = await store.save(signed(1, Date.now() - 2 * 86400000));
  assert.equal((await fetch(`${server.base}/s/${expiredId}?token=private-token&download=1`)).status, 410);
  await server.close();
  // 写入失败时返回可读错误，不伪造短链接，长链接继续工作。
  const unavailable = join(directory, "not-a-directory");
  await writeFile(unavailable, "test");
  server = await startTestServer({ STATE_DIRECTORY: unavailable, SUBSCRIPTION_SIGNING_KEY: key });
  assert.equal((await create(permanent)).status, 400);
  assert.equal((await fetch(`${server.base}/subscription?${new URLSearchParams(permanent)}`)).status, 200);
  const compact = shortSubscriptionStore(join(directory, "cleanup"), key, { maxEntries: 1 });
  await compact.save(signed(1, Date.now() - 2 * 86400000));
  await compact.save(permanent);
  assert.equal((await readdir(join(directory, "cleanup", "short-subscriptions"))).length, 1, "容量不足时先清理过期记录");
  const ids = await Promise.all(Array.from({ length: 5 }, () => compact.save(permanent)));
  assert.equal(new Set(ids).size, 1, "并发重复保存不新增记录");
  console.log("persistent short subscription tests passed");
} finally {
  await server?.close();
  await rm(directory, { recursive: true, force: true });
}
