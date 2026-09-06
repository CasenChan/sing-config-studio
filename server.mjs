import { createServer } from "node:http";
import { execFile } from "node:child_process";
import { mkdtemp, readFile, realpath, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { inflateRawSync } from "node:zlib";
import { extname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { fetchRemoteSubscription } from "./server/remote-subscription.mjs";
import { issueSignature, loadSigningKey, verifySignature } from "./server/subscription-signing.mjs";

const root = await realpath(fileURLToPath(new URL(".", import.meta.url)));
const port = Number(process.env.PORT || 4173);
const host = process.env.HOST || "127.0.0.1";
// 公网部署时用于保护订阅端点：设置后 /subscription 必须带上正确的 token
const subscriptionToken = process.env.SUBSCRIPTION_TOKEN || "";
const rateLimitWindowMs = Number(process.env.RATE_LIMIT_WINDOW_MS || 60_000);
const rateLimitMax = Number(process.env.RATE_LIMIT_MAX || 60);
const maxSubscriptionBytes = 512 * 1024;
const maxRequestBytes = 16 * 1024;
const signingKey = await loadSigningKey(process.env.STATE_DIRECTORY || join(root, ".data"), process.env.SUBSCRIPTION_SIGNING_KEY || "");

const mimeTypes = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".ico": "image/x-icon"
};

const singBoxBinary = process.env.SING_BOX_BIN || "sing-box";

function runSingBoxCheck(configText) {
  return new Promise((resolve) => {
    mkdtemp(join(tmpdir(), "sing-config-")).then(async (dir) => {
      const file = join(dir, "config.json");
      try {
        await writeFile(file, configText, "utf8");
        execFile(singBoxBinary, ["check", "-c", file], { timeout: 20000 }, (error, stdout, stderr) => {
          rm(dir, { recursive: true, force: true }).catch(() => {});
          const output = `${stdout || ""}${stderr || ""}`.trim();
          if (error && (error.code === "ENOENT" || /not found/i.test(String(error.message)))) {
            resolve({ available: false, error: `未找到 sing-box 可执行文件（${singBoxBinary}），可用 SING_BOX_BIN 指定路径` });
            return;
          }
          if (error) {
            resolve({ available: true, ok: false, output: output || error.message });
            return;
          }
          resolve({ available: true, ok: true, output: output || "配置检查通过" });
        });
      } catch (error) {
        rm(dir, { recursive: true, force: true }).catch(() => {});
        resolve({ available: false, error: error.message });
      }
    }).catch((error) => resolve({ available: false, error: error.message }));
  });
}

const rateLimitBuckets = new Map();

function rateLimited(key) {
  if (!Number.isFinite(rateLimitMax) || rateLimitMax <= 0) return false;
  const now = Date.now();
  const bucket = rateLimitBuckets.get(key);
  if (!bucket || now - bucket.start >= rateLimitWindowMs) {
    rateLimitBuckets.set(key, { start: now, count: 1 });
    if (rateLimitBuckets.size > 10_000) {
      for (const [entry, value] of rateLimitBuckets) {
        if (now - value.start >= rateLimitWindowMs) rateLimitBuckets.delete(entry);
      }
    }
    return false;
  }
  bucket.count += 1;
  return bucket.count > rateLimitMax;
}

function clientKey(req) {
  return req.socket.remoteAddress || "unknown";
}

function timingSafeEqual(a, b) {
  const left = Buffer.from(String(a));
  const right = Buffer.from(String(b));
  if (left.length !== right.length) return false;
  let diff = 0;
  for (let index = 0; index < left.length; index += 1) diff |= left[index] ^ right[index];
  return diff === 0;
}

function send(res, status, body, headers = {}) {
  res.writeHead(status, {
    "content-type": "text/plain; charset=utf-8",
    "x-content-type-options": "nosniff",
    ...headers
  });
  res.end(body);
}

function decodeSubscription(value, encoding = "") {
  if (!value || value.length > maxSubscriptionBytes) {
    throw new Error("订阅数据为空或过大");
  }
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized + "=".repeat((4 - (normalized.length % 4)) % 4);
  let raw = Buffer.from(padded, "base64");
  if (encoding === "deflate") {
    raw = inflateRawSync(raw, { maxOutputLength: maxSubscriptionBytes * 8 });
  } else if (encoding) {
    throw new Error(`不支持的编码：${encoding}`);
  }
  const json = raw.toString("utf8");
  const config = JSON.parse(json);
  if (!config || typeof config !== "object" || Array.isArray(config)) {
    throw new Error("订阅内容不是 sing-box 配置对象");
  }
  // 只反射长得像 sing-box 配置的数据，避免端点被当成通用 JSON 托管
  if (!Array.isArray(config.outbounds) || !Array.isArray(config.inbounds)) {
    throw new Error("订阅内容缺少 inbounds / outbounds，不是 sing-box 配置");
  }
  return JSON.stringify(config, null, 2) + "\n";
}

function sendJson(res, status, value, headers = {}) {
  return send(res, status, JSON.stringify(value) + "\n", {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store",
    ...headers
  });
}

async function readJsonBody(req) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > maxRequestBytes) throw new Error("请求内容过大");
    chunks.push(chunk);
  }
  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf8"));
  } catch {
    throw new Error("请求内容不是有效 JSON");
  }
}

function parseRequestUrl(req) {
  const hosts = req.rawHeaders.filter((_, index) => index % 2 === 0 && req.rawHeaders[index].toLowerCase() === "host");
  const authority = req.headers.host || (req.httpVersion === "1.0" ? "localhost" : "");
  if (hosts.length > 1 || !/^(?:\[[a-fA-F0-9:.]+\]|[a-zA-Z0-9.-]+)(?::\d{1,5})?$/.test(authority)) throw new Error("Invalid Host header");
  const base = new URL(`http://${authority}`);
  const target = req.url || "/";
  if (!target.startsWith("/") || target.startsWith("//") || target.includes("\\")) throw new Error("Invalid request target");
  const url = new URL(target, base);
  if (url.origin !== base.origin) throw new Error("Invalid request target");
  return url;
}

async function handleRequest(req, res) {
  let requestUrl;
  try { requestUrl = parseRequestUrl(req); }
  catch { return send(res, 400, "Bad request\n", { "cache-control": "no-store" }); }

  if (requestUrl.pathname === "/health") {
    return send(res, 200, "ok\n", { "cache-control": "no-store" });
  }

  // 供生成页探测目标服务器的要求（不含任何秘密，允许跨域读取）
  if (requestUrl.pathname === "/api/status") {
    return send(res, 200, JSON.stringify({ tokenRequired: Boolean(subscriptionToken), signatureVersion: 1, rateLimit: { windowMs: rateLimitWindowMs, max: rateLimitMax } }) + "\n", {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      "access-control-allow-origin": "*"
    });
  }

  if (requestUrl.pathname === "/api/sign-subscription") {
    const cors = { "access-control-allow-origin": "*", "access-control-allow-methods": "POST, OPTIONS", "access-control-allow-headers": "Content-Type" };
    if (req.method === "OPTIONS") return send(res, 204, "", cors);
    if (req.method !== "POST") return send(res, 405, "Method not allowed\n", { ...cors, allow: "POST, OPTIONS" });
    if (rateLimited(`${clientKey(req)}:sign`)) return sendJson(res, 429, { error: "请求过于频繁，请稍后再试" }, cors);
    try {
      const body = await readJsonBody(req);
      if (!body || typeof body !== "object" || Array.isArray(body)) throw new Error("签名请求必须是 JSON 对象");
      if (subscriptionToken && !timingSafeEqual(body.token || "", subscriptionToken)) return sendJson(res, 401, { error: "请填写与 SUBSCRIPTION_TOKEN 一致的访问 token" }, cors);
      return sendJson(res, 200, issueSignature(signingKey, body), cors);
    } catch (error) { return sendJson(res, 400, { error: error.message }, cors); }
  }

  if (requestUrl.pathname === "/subscription") {
    if (rateLimited(clientKey(req))) {
      return send(res, 429, "Too many requests\n", { "retry-after": String(Math.ceil(rateLimitWindowMs / 1000)) });
    }
    if (subscriptionToken && !timingSafeEqual(requestUrl.searchParams.get("token") || "", subscriptionToken)) {
      return send(res, 401, "Unauthorized: this server requires a subscription token. Regenerate the link with the same token as SUBSCRIPTION_TOKEN.\n", { "cache-control": "no-store" });
    }
    if (!["GET", "HEAD"].includes(req.method)) return send(res, 405, "Method not allowed\n", { allow: "GET, HEAD" });
    if ((requestUrl.searchParams.get("data") || "").length > maxSubscriptionBytes) return sendJson(res, 400, { error: "订阅数据过大" });
    const signatureError = verifySignature(signingKey, requestUrl.searchParams);
    if (signatureError) return sendJson(res, signatureError.status, { error: signatureError.error });
    try {
      const body = decodeSubscription(requestUrl.searchParams.get("data"), requestUrl.searchParams.get("enc") || "");
      const filename = (requestUrl.searchParams.get("name") || "sing-box-profile")
        .replace(/[^a-zA-Z0-9._-]+/g, "-")
        .slice(0, 80);
      const disposition = requestUrl.searchParams.get("download") === "1"
        ? `attachment; filename="${filename || "sing-box-profile"}.json"`
        : "inline";
      return send(res, 200, body, {
        "content-type": "application/json; charset=utf-8",
        "cache-control": "no-store, private",
        "access-control-allow-origin": "*",
        "profile-update-interval": /^\d{1,5}$/.test(requestUrl.searchParams.get("interval") || "") ? requestUrl.searchParams.get("interval") : "60",
        "content-disposition": disposition
      });
    } catch (error) {
      return send(res, 400, JSON.stringify({ error: error.message }) + "\n", {
        "content-type": "application/json; charset=utf-8",
        "cache-control": "no-store"
      });
    }
  }

  if (requestUrl.pathname === "/api/check") {
    if (req.method !== "POST") return send(res, 405, "Method not allowed\n", { allow: "POST" });
    if (rateLimited(`${clientKey(req)}:check`)) return sendJson(res, 429, { error: "请求过于频繁，请稍后再试" });
    try {
      const origin = req.headers.origin;
      if (origin && new URL(origin).host !== requestUrl.host) return sendJson(res, 403, { error: "拒绝跨站请求" });
      const chunks = [];
      let size = 0;
      for await (const chunk of req) {
        size += chunk.length;
        if (size > maxSubscriptionBytes) throw new Error("配置内容过大");
        chunks.push(chunk);
      }
      const text = Buffer.concat(chunks).toString("utf8");
      JSON.parse(text);
      return sendJson(res, 200, await runSingBoxCheck(text));
    } catch (error) {
      return sendJson(res, 400, { error: error.message });
    }
  }

  if (requestUrl.pathname === "/api/fetch-subscription") {
    if (req.method !== "POST") return send(res, 405, "Method not allowed\n", { allow: "POST" });
    if (rateLimited(`${clientKey(req)}:fetch`)) return sendJson(res, 429, { error: "请求过于频繁，请稍后再试" });
    try {
      const origin = req.headers.origin;
      if (origin && new URL(origin).host !== requestUrl.host) return sendJson(res, 403, { error: "拒绝跨站请求" });
      const body = await readJsonBody(req);
      return sendJson(res, 200, await fetchRemoteSubscription(body.url));
    } catch (error) {
      const message = error.name === "TimeoutError" ? "读取订阅超时" : error.message;
      return sendJson(res, 400, { error: message });
    }
  }

  if (req.method !== "GET" && req.method !== "HEAD") {
    return send(res, 405, "Method not allowed\n", { allow: "GET, HEAD" });
  }

  let requestedPath;
  try { requestedPath = decodeURIComponent(requestUrl.pathname === "/" ? "/index.html" : requestUrl.pathname); }
  catch { return send(res, 400, "Bad request\n"); }
  // 只发布浏览器需要的资源，源码、测试、备份、密钥和仓库元数据不作为静态文件提供。
  const publicFiles = new Set(["/index.html", "/app.js", "/styles.css", "/favicon.svg"]);
  if (!publicFiles.has(requestedPath) && !/^\/modules\/[a-z][a-z0-9-]*\.js$/.test(requestedPath)) return send(res, 404, "Not found\n");
  const filePath = join(root, requestedPath);

  try {
    if (await realpath(filePath) !== filePath) return send(res, 404, "Not found\n");
    const info = await stat(filePath);
    if (!info.isFile()) throw new Error("not a file");
    const content = await readFile(filePath);
    res.writeHead(200, {
      "content-type": mimeTypes[extname(filePath)] || "application/octet-stream",
      "content-length": content.length,
      "cache-control": extname(filePath) === ".html" ? "no-cache" : "public, max-age=3600",
      "x-content-type-options": "nosniff"
    });
    if (req.method === "HEAD") return res.end();
    res.end(content);
  } catch {
    send(res, 404, "Not found\n");
  }
}

const server = createServer((req, res) => {
  handleRequest(req, res).catch(() => {
    if (res.headersSent) res.destroy();
    else send(res, 500, "Internal server error\n", { "cache-control": "no-store" });
  });
});

server.listen(port, host, () => {
  console.log(`Sing Config Studio running at http://${host}:${server.address().port}`);
  if (subscriptionToken) console.log("订阅端点已启用 token 鉴权");
  console.log(`限流：每 ${Math.round(rateLimitWindowMs / 1000)} 秒 ${rateLimitMax} 次`);
});
