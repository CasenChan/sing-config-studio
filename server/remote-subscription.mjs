import { lookup } from "node:dns/promises";
import { BlockList, isIP } from "node:net";
import { request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";
import { createGunzip, createInflate, createBrotliDecompress } from "node:zlib";

const blocked = new BlockList();
for (const [address, prefix] of [["0.0.0.0", 8], ["10.0.0.0", 8], ["100.64.0.0", 10], ["127.0.0.0", 8], ["169.254.0.0", 16], ["172.16.0.0", 12], ["192.0.0.0", 24], ["192.0.2.0", 24], ["192.88.99.0", 24], ["192.168.0.0", 16], ["198.18.0.0", 15], ["198.51.100.0", 24], ["203.0.113.0", 24], ["224.0.0.0", 3]]) blocked.addSubnet(address, prefix, "ipv4");
for (const [address, prefix] of [["2001::", 32], ["2001:db8::", 32], ["2001:10::", 28], ["2001:20::", 28], ["2002::", 16], ["3fff::", 20]]) blocked.addSubnet(address, prefix, "ipv6");
const globalIPv6 = new BlockList();
globalIPv6.addSubnet("2000::", 3, "ipv6");

export function isPublicAddress(address) {
  const family = isIP(address);
  if (family === 4) return !blocked.check(address, "ipv4");
  // 同时排除 IPv4-mapped、NAT64、链路本地、ULA、组播等特殊地址。
  return family === 6 && globalIPv6.check(address, "ipv6") && !blocked.check(address, "ipv6");
}

function withAbort(promise, signal) {
  signal.throwIfAborted();
  return new Promise((resolve, reject) => {
    const abort = () => reject(signal.reason);
    signal.addEventListener("abort", abort, { once: true });
    promise.then(resolve, reject).finally(() => signal.removeEventListener("abort", abort));
  });
}

export async function validateRemoteUrl(value, { resolve = lookup, signal = AbortSignal.timeout(12000) } = {}) {
  if (typeof value !== "string" || !value.trim() || value.length > 4096) throw new Error("订阅地址为空或过长");
  const url = new URL(value);
  if (!["http:", "https:"].includes(url.protocol)) throw new Error("订阅地址只支持 HTTP 或 HTTPS");
  if (url.username || url.password) throw new Error("订阅地址不能包含 URL 用户名或密码");
  const hostname = url.hostname.replace(/^\[|\]$/g, "");
  const name = hostname.toLowerCase().replace(/\.$/, "");
  if (name === "localhost" || name.endsWith(".localhost") || name === "localhost.localdomain" || name.endsWith(".local")) throw new Error("不能读取本机或局域网地址");
  const literalFamily = isIP(hostname);
  const addresses = literalFamily ? [{ address: hostname, family: literalFamily }] : await withAbort(resolve(hostname, { all: true, verbatim: true }), signal);
  if (!addresses.length || addresses.some(({ address }) => !isPublicAddress(address))) {
    if (addresses.some(({ address }) => /^198\.(18|19)\./.test(address))) throw new Error("订阅域名解析到了 FakeIP 地址，请为该域名添加真实 DNS 解析例外后重试");
    throw new Error("不能读取本机、局域网或保留地址");
  }
  return { url, addresses: addresses.map(({ address }) => ({ address, family: isIP(address) })) };
}

export function pinnedLookup(addresses) {
  const approved = addresses.map((entry) => ({ ...entry }));
  return (_hostname, options, callback) => {
    const family = typeof options === "number" ? options : options?.family;
    const available = approved.filter((entry) => !family || entry.family === family);
    if (!available.length) return callback(new Error("没有通过检查的目标地址"));
    if (options?.all) callback(null, available.map((entry) => ({ ...entry })));
    else callback(null, available[0].address, available[0].family);
  };
}

function requestResponse(url, options, request) {
  return new Promise((resolve, reject) => {
    const send = request || (url.protocol === "https:" ? httpsRequest : httpRequest);
    // 保留 URL 中的 Host、TLS SNI 和证书主机名，只替换底层 DNS 查询。
    const req = send(url, options, resolve);
    req.on("error", reject);
    req.end();
  });
}

async function readContent(response, maxBytes) {
  const encoding = String(response.headers["content-encoding"] || "identity").toLowerCase();
  const decoder = { gzip: createGunzip, deflate: createInflate, br: createBrotliDecompress }[encoding];
  if (!decoder && encoding !== "identity") throw new Error(`不支持的订阅内容编码：${encoding}`);
  const stream = decoder ? response.pipe(decoder()) : response;
  if (stream !== response) response.on("error", (error) => stream.destroy(error));
  const chunks = [];
  let size = 0;
  try {
    for await (const chunk of stream) {
      size += chunk.length;
      if (size > maxBytes) throw new Error("订阅内容超过 2 MiB 限制");
      chunks.push(chunk);
    }
    return Buffer.concat(chunks).toString("utf8");
  } finally { if (stream !== response) stream.destroy(); }
}

export async function fetchRemoteSubscription(value, { resolve = lookup, request, timeoutMs = 12000, maxBytes = 2 * 1024 * 1024 } = {}) {
  const signal = AbortSignal.timeout(timeoutMs);
  let next = value;
  try {
    for (let redirects = 0; redirects <= 3; redirects += 1) {
      const { url, addresses } = await validateRemoteUrl(next, { resolve, signal });
      const response = await requestResponse(url, {
        method: "GET", agent: false, lookup: pinnedLookup(addresses), signal,
        headers: { accept: "application/json, text/plain, */*", "accept-encoding": "gzip, deflate, br", "user-agent": "sing-box/1.14.0" }
      }, request);
      try {
        if (response.statusCode >= 300 && response.statusCode < 400 && response.headers.location) {
          if (redirects === 3) throw new Error("订阅地址重定向次数过多");
          next = new URL(response.headers.location, url).toString();
          continue;
        }
        if (response.statusCode < 200 || response.statusCode >= 300) throw new Error(`订阅服务器返回 HTTP ${response.statusCode}`);
        return { content: await readContent(response, maxBytes), contentType: response.headers["content-type"] || "", finalUrl: url.toString() };
      } finally { response.destroy(); }
    }
  } catch (error) {
    if (signal.aborted) throw new Error("读取订阅超时");
    throw error;
  }
}
