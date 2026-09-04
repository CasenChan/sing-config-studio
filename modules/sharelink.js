// 把出站节点导出成常见的分享链接格式；不支持导出的类型会明确返回原因。
import { normalizeOutbound } from "./outbound.js";

const SUPPORTED = new Set(["vless", "vmess", "trojan", "shadowsocks", "hysteria2", "tuic", "anytls"]);

function base64(value) {
  const bytes = new TextEncoder().encode(value);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return typeof btoa === "function" ? btoa(binary) : Buffer.from(value, "utf8").toString("base64");
}

function transportParams(node, params) {
  if (!node.transport || node.transport === "tcp") return;
  params.set("type", node.transport);
  if (node.transport === "grpc") {
    if (node.path) params.set("serviceName", String(node.path).replace(/^\//, ""));
    return;
  }
  if (node.path) params.set("path", node.path);
  if (node.host) params.set("host", node.host);
}

function tlsParams(node, params) {
  if (!node.tls) {
    params.set("security", "none");
    return;
  }
  params.set("security", node.reality ? "reality" : "tls");
  if (node.sni) params.set("sni", node.sni);
  if (node.fingerprint) params.set("fp", node.fingerprint);
  if (node.insecure) params.set("allowInsecure", "1");
  if (node.alpn) params.set("alpn", String(node.alpn).split(/[\n,]+/).map((item) => item.trim()).filter(Boolean).join(","));
  if (node.reality) {
    if (node.publicKey) params.set("pbk", node.publicKey);
    if (node.shortId) params.set("sid", node.shortId);
  }
}

export function toShareLink(source) {
  const node = normalizeOutbound(source);
  const tag = String(node.tag || "").trim();
  if (!SUPPORTED.has(node.type)) return { ok: false, reason: `${node.type} 没有通用分享链接格式` };
  const server = String(node.server || "").trim();
  const port = Number(node.port);
  if (!server || !port) return { ok: false, reason: "缺少服务器或端口" };
  const hash = `#${encodeURIComponent(tag)}`;
  const params = new URLSearchParams();

  if (node.type === "vmess") {
    const payload = {
      v: "2",
      ps: tag,
      add: server,
      port: String(port),
      id: node.uuid,
      aid: String(Number(node.alterId) || 0),
      scy: node.security || "auto",
      net: node.transport && node.transport !== "tcp" ? node.transport : "tcp",
      type: "none",
      host: node.host || "",
      path: node.transport === "grpc" ? String(node.path || "").replace(/^\//, "") : node.path || "",
      tls: node.tls ? "tls" : "",
      sni: node.sni || "",
      fp: node.fingerprint || ""
    };
    return { ok: true, link: `vmess://${base64(JSON.stringify(payload))}` };
  }

  if (node.type === "shadowsocks") {
    const userinfo = base64(`${node.method}:${node.password}`).replace(/=+$/, "");
    return { ok: true, link: `ss://${userinfo}@${server}:${port}${hash}` };
  }

  if (node.type === "vless") {
    tlsParams(node, params);
    transportParams(node, params);
    if (node.flow) params.set("flow", node.flow);
    if (node.packetEncoding) params.set("packetEncoding", node.packetEncoding);
    return { ok: true, link: `vless://${encodeURIComponent(node.uuid)}@${server}:${port}?${params}${hash}` };
  }

  if (node.type === "trojan") {
    tlsParams(node, params);
    transportParams(node, params);
    return { ok: true, link: `trojan://${encodeURIComponent(node.password)}@${server}:${port}?${params}${hash}` };
  }

  if (node.type === "hysteria2") {
    if (node.sni) params.set("sni", node.sni);
    if (node.insecure) params.set("insecure", "1");
    if (node.obfsType) {
      params.set("obfs", node.obfsType);
      if (node.obfsPassword) params.set("obfs-password", node.obfsPassword);
    }
    if (node.serverPorts) params.set("mport", node.serverPorts);
    const query = params.toString();
    return { ok: true, link: `hysteria2://${encodeURIComponent(node.password)}@${server}:${port}${query ? `?${query}` : ""}${hash}` };
  }

  if (node.type === "tuic") {
    if (node.sni) params.set("sni", node.sni);
    if (node.insecure) params.set("allow_insecure", "1");
    if (node.congestionControl) params.set("congestion_control", node.congestionControl);
    if (node.udpRelayMode) params.set("udp_relay_mode", node.udpRelayMode);
    if (node.alpn) params.set("alpn", String(node.alpn).split(/[\n,]+/).map((item) => item.trim()).filter(Boolean).join(","));
    return { ok: true, link: `tuic://${encodeURIComponent(node.uuid)}:${encodeURIComponent(node.password)}@${server}:${port}?${params}${hash}` };
  }

  // anytls
  if (node.sni) params.set("sni", node.sni);
  if (node.insecure) params.set("insecure", "1");
  const query = params.toString();
  return { ok: true, link: `anytls://${encodeURIComponent(node.password)}@${server}:${port}${query ? `?${query}` : ""}${hash}` };
}

export function exportShareLinks(nodes = []) {
  const links = [];
  const skipped = [];
  for (const node of nodes) {
    const result = toShareLink(node);
    if (result.ok) links.push(result.link);
    else skipped.push({ tag: node.tag, reason: result.reason });
  }
  return { links, skipped };
}

// 订阅节点整理：去重、按关键字过滤、批量重命名
export function dedupeNodes(nodes = []) {
  const seen = new Map();
  const kept = [];
  let removed = 0;
  for (const node of nodes) {
    const key = [node.type, node.server, node.port, node.uuid || "", node.password || "", node.method || ""].join("|");
    if (seen.has(key)) {
      removed += 1;
      continue;
    }
    seen.set(key, true);
    kept.push(node);
  }
  return { nodes: kept, removed };
}

export function filterNodes(nodes = [], { include = "", exclude = "" } = {}) {
  const includeList = String(include || "").split(/[\n,]+/).map((item) => item.trim()).filter(Boolean);
  const excludeList = String(exclude || "").split(/[\n,]+/).map((item) => item.trim()).filter(Boolean);
  const matches = (node, list) => list.some((keyword) => String(node.tag || "").toLowerCase().includes(keyword.toLowerCase()));
  const kept = nodes.filter((node) => {
    if (includeList.length && !matches(node, includeList)) return false;
    if (excludeList.length && matches(node, excludeList)) return false;
    return true;
  });
  return { nodes: kept, removed: nodes.length - kept.length };
}

export function renameNodes(nodes = [], { prefix = "", suffix = "", search = "", replace = "" } = {}) {
  return nodes.map((node) => {
    let tag = String(node.tag || "");
    if (search) tag = tag.split(search).join(replace);
    return { ...node, tag: `${prefix}${tag}${suffix}`.trim() };
  });
}

export function diffNodes(previous = [], next = []) {
  const previousTags = new Set(previous.map((node) => String(node.tag || "").trim()));
  const nextTags = new Set(next.map((node) => String(node.tag || "").trim()));
  const added = [...nextTags].filter((tag) => !previousTags.has(tag));
  const removed = [...previousTags].filter((tag) => !nextTags.has(tag));
  return { added, removed, kept: [...nextTags].filter((tag) => previousTags.has(tag)) };
}
