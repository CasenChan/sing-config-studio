import { createServer } from "node:http";
import { execFile } from "node:child_process";
import { mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { lookup } from "node:dns/promises";
import { isIP } from "node:net";
import { extname, join, normalize } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL(".", import.meta.url));
const port = Number(process.env.PORT || 4173);
const host = process.env.HOST || "127.0.0.1";
// 公网部署时用于保护订阅端点：设置后 /subscription 必须带上正确的 token
const subscriptionToken = process.env.SUBSCRIPTION_TOKEN || "";
const rateLimitWindowMs = Number(process.env.RATE_LIMIT_WINDOW_MS || 60_000);
const rateLimitMax = Number(process.env.RATE_LIMIT_MAX || 60);
const maxSubscriptionBytes = 512 * 1024;
const maxRemoteSubscriptionBytes = 2 * 1024 * 1024;
const maxRequestBytes = 16 * 1024;

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

function decodeSubscription(value) {
  if (!value || value.length > maxSubscriptionBytes) {
    throw new Error("订阅数据为空或过大");
  }
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized + "=".repeat((4 - (normalized.length % 4)) % 4);
  const json = Buffer.from(padded, "base64").toString("utf8");
  const config = JSON.parse(json);
  if (!config || typeof config !== "object" || Array.isArray(config)) {
    throw new Error("订阅内容不是 sing-box 配置对象");
  }
  return JSON.stringify(config, null, 2) + "\n";
}

function sendJson(res, status, value) {
  return send(res, status, JSON.stringify(value) + "\n", {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store"
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

function isPrivateIPv4(address) {
  const parts = address.split(".").map(Number);
  if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) return true;
  const [a, b] = parts;
  return a === 0 || a === 10 || a === 127 ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && (b === 0 || b === 168)) ||
    a >= 224;
}

function isProxyFakeIPv4(address) {
  const [a, b] = address.split(".").map(Number);
  return a === 198 && (b === 18 || b === 19);
}

function isPrivateAddress(address) {
  if (isIP(address) === 4) return isPrivateIPv4(address);
  const normalized = address.toLowerCase();
  if (normalized.startsWith("::ffff:")) return isPrivateIPv4(normalized.slice(7));
  return normalized === "::" || normalized === "::1" ||
    normalized.startsWith("fc") || normalized.startsWith("fd") ||
    /^fe[89ab]/.test(normalized) || normalized.startsWith("ff") ||
    normalized.startsWith("2001:db8:");
}

async function validateRemoteUrl(value) {
  if (typeof value !== "string" || !value.trim() || value.length > 4096) throw new Error("订阅地址为空或过长");
  const url = new URL(value);
  if (!["http:", "https:"].includes(url.protocol)) throw new Error("订阅地址只支持 HTTP 或 HTTPS");
  if (url.username || url.password) throw new Error("订阅地址不能包含 URL 用户名或密码");
  if (["localhost", "localhost.localdomain"].includes(url.hostname.toLowerCase()) || url.hostname.endsWith(".local")) {
    throw new Error("为安全起见，不能读取本机或局域网地址");
  }
  const hostnameIsIpLiteral = isIP(url.hostname) !== 0;
  const addresses = await lookup(url.hostname, { all: true, verbatim: true });
  if (!addresses.length || addresses.some(({ address }) =>
    isPrivateAddress(address) || (hostnameIsIpLiteral && isProxyFakeIPv4(address))
  )) {
    throw new Error("为安全起见，不能读取本机或局域网地址");
  }
  return url;
}

async function fetchRemoteSubscription(value) {
  let url = await validateRemoteUrl(value);
  for (let redirects = 0; redirects <= 3; redirects += 1) {
    const response = await fetch(url, {
      redirect: "manual",
      signal: AbortSignal.timeout(12000),
      headers: {
        accept: "application/json, text/plain, */*",
        "user-agent": "sing-box/1.14.0"
      }
    });
    if (response.status >= 300 && response.status < 400 && response.headers.get("location")) {
      if (redirects === 3) throw new Error("订阅地址重定向次数过多");
      url = await validateRemoteUrl(new URL(response.headers.get("location"), url).toString());
      continue;
    }
    if (!response.ok) throw new Error(`订阅服务器返回 HTTP ${response.status}`);
    const chunks = [];
    let size = 0;
    for await (const chunk of response.body) {
      size += chunk.length;
      if (size > maxRemoteSubscriptionBytes) throw new Error("订阅内容超过 2 MiB 限制");
      chunks.push(chunk);
    }
    return {
      content: Buffer.concat(chunks).toString("utf8"),
      contentType: response.headers.get("content-type") || "",
      finalUrl: url.toString()
    };
  }
  throw new Error("无法读取订阅地址");
}

const server = createServer(async (req, res) => {
  const requestUrl = new URL(req.url || "/", `http://${req.headers.host || "localhost"}`);

  if (requestUrl.pathname === "/health") {
    return send(res, 200, "ok\n", { "cache-control": "no-store" });
  }

  // 供生成页探测目标服务器的要求（不含任何秘密，允许跨域读取）
  if (requestUrl.pathname === "/api/status") {
    return send(res, 200, JSON.stringify({ tokenRequired: Boolean(subscriptionToken), rateLimit: { windowMs: rateLimitWindowMs, max: rateLimitMax } }) + "\n", {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      "access-control-allow-origin": "*"
    });
  }

  if (requestUrl.pathname === "/subscription") {
    if (rateLimited(clientKey(req))) {
      return send(res, 429, "Too many requests\n", { "retry-after": String(Math.ceil(rateLimitWindowMs / 1000)) });
    }
    if (subscriptionToken && !timingSafeEqual(requestUrl.searchParams.get("token") || "", subscriptionToken)) {
      return send(res, 401, "Unauthorized: this server requires a subscription token. Regenerate the link with the same token as SUBSCRIPTION_TOKEN.\n", { "cache-control": "no-store" });
    }
    const expires = Number(requestUrl.searchParams.get("expires") || 0);
    if (expires && Number.isFinite(expires) && Date.now() / 1000 > expires) {
      return send(res, 410, "Subscription link expired\n", { "cache-control": "no-store" });
    }
    try {
      const body = decodeSubscription(requestUrl.searchParams.get("data"));
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
        "profile-update-interval": requestUrl.searchParams.get("interval") || "60",
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

  const requestedPath = requestUrl.pathname === "/" ? "/index.html" : requestUrl.pathname;
  const safePath = normalize(requestedPath).replace(/^(\.\.(\/|\\|$))+/, "");
  const filePath = join(root, safePath);
  if (!filePath.startsWith(root)) return send(res, 403, "Forbidden\n");

  try {
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
});

server.listen(port, host, () => {
  console.log(`Sing Config Studio running at http://${host}:${port}`);
  if (subscriptionToken) console.log("订阅端点已启用 token 鉴权");
  console.log(`限流：每 ${Math.round(rateLimitWindowMs / 1000)} 秒 ${rateLimitMax} 次`);
});
