import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { subscriptionPayload } from "../modules/subscription-payload.js";

export async function loadSigningKey(directory, configuredKey = "") {
  if (configuredKey) {
    if (Buffer.byteLength(configuredKey) < 32) throw new Error("SUBSCRIPTION_SIGNING_KEY 至少需要 32 字节");
    return configuredKey;
  }
  await mkdir(directory, { recursive: true, mode: 0o700 });
  const path = join(directory, "subscription-signing-key");
  try { await writeFile(path, randomBytes(32).toString("base64url"), { flag: "wx", mode: 0o600 }); }
  catch (error) { if (error.code !== "EEXIST") throw error; }
  const key = (await readFile(path, "utf8")).trim();
  if (!/^[A-Za-z0-9_-]{43}$/.test(key)) throw new Error("订阅签名密钥文件无效，请检查状态目录");
  return key;
}

export const subscriptionDigest = (fields) => createHash("sha256").update(subscriptionPayload(fields)).digest("hex");
const sign = (key, digest, expires) => createHmac("sha256", key).update(JSON.stringify([1, digest, expires])).digest("base64url");

export function issueSignature(key, { digest, days = 0 }, now = Date.now()) {
  if (typeof digest !== "string" || !/^[0-9a-f]{64}$/.test(digest)) throw new Error("配置摘要无效");
  if (![0, 1, 7, 30].includes(days)) throw new Error("有效期只支持永久、1 天、7 天或 30 天");
  const expires = days ? Math.floor(now / 1000) + days * 86400 : 0;
  return { sigv: "1", expires: String(expires), sig: sign(key, digest, String(expires)) };
}

export function verifySignature(key, params, now = Date.now()) {
  const required = ["data", "enc", "name", "interval", "sigv", "expires", "sig"];
  if (required.some((field) => params.getAll(field).length !== 1) || params.getAll("token").length > 1 || params.get("sigv") !== "1") return { status: 401, error: "订阅链接缺少有效签名，请重新生成" };
  const expires = params.get("expires");
  const signature = params.get("sig");
  if (!/^(0|[1-9]\d{0,12})$/.test(expires) || !/^[A-Za-z0-9_-]{43}$/.test(signature)) return { status: 401, error: "订阅签名无效" };
  const fields = Object.fromEntries(required.map((field) => [field, params.get(field)]));
  const expected = sign(key, subscriptionDigest(fields), expires);
  if (!timingSafeEqual(Buffer.from(signature), Buffer.from(expected))) return { status: 401, error: "订阅链接已被修改，请重新生成" };
  if (Number(expires) && now / 1000 >= Number(expires)) return { status: 410, error: "订阅链接已过期" };
  return null;
}
