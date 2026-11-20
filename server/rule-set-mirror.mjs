// 订阅服务器自带的大陆规则集镜像：客户端第一次启动时不必依赖任何代理节点就能下载规则集。
// 定期从上游同步，原子写入；同步失败时保留上一份有效文件。
import { createHash, randomBytes } from "node:crypto";
import { mkdir, readFile, rename, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";

export const MIRRORED_RULE_SETS = Object.freeze({
  "geosite-cn": "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-cn.srs",
  "geoip-cn": "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-cn.srs"
});

const MAX_RULE_SET_BYTES = 16 * 1024 * 1024;
const SRS_MAGIC = Buffer.from("SRS");

export function isBinaryRuleSet(content) {
  return content.length > SRS_MAGIC.length && content.subarray(0, SRS_MAGIC.length).equals(SRS_MAGIC);
}

function entryFor(content, updatedAt) {
  const etag = `"${createHash("sha256").update(content).digest("base64url").slice(0, 32)}"`;
  return { content, etag, updatedAt };
}

async function readLimited(response) {
  const declared = Number(response.headers.get("content-length") || 0);
  if (declared > MAX_RULE_SET_BYTES) throw new Error("规则集过大");
  const chunks = [];
  let size = 0;
  for await (const chunk of response.body) {
    size += chunk.length;
    if (size > MAX_RULE_SET_BYTES) throw new Error("规则集过大");
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
}

export function ruleSetMirror(stateDirectory, {
  upstreamBase = "",
  intervalMs = 12 * 60 * 60 * 1000,
  sync: syncEnabled = true,
  fetchImpl = fetch,
  logger = console
} = {}) {
  const directory = join(stateDirectory, "rule-sets");
  const sources = Object.fromEntries(Object.entries(MIRRORED_RULE_SETS).map(([tag, url]) => [tag, upstreamBase ? new URL(`${tag}.srs`, upstreamBase).href : url]));
  const entries = new Map();
  let timer = null;
  let running = null;

  async function load() {
    for (const tag of Object.keys(sources)) {
      try {
        const content = await readFile(join(directory, `${tag}.srs`));
        if (isBinaryRuleSet(content)) entries.set(tag, entryFor(content, null));
      } catch {}
    }
  }

  async function syncOne(tag) {
    const response = await fetchImpl(sources[tag], { signal: AbortSignal.timeout(30_000), redirect: "follow" });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const content = await readLimited(response);
    if (!isBinaryRuleSet(content)) throw new Error("内容不是 binary 规则集");
    const target = join(directory, `${tag}.srs`);
    const temporary = join(directory, `.${tag}-${randomBytes(6).toString("hex")}.tmp`);
    try {
      await writeFile(temporary, content, { mode: 0o644 });
      await rename(temporary, target);
    } catch (error) {
      await rm(temporary, { force: true });
      throw error;
    }
    entries.set(tag, entryFor(content, Date.now()));
  }

  function sync() {
    running ||= Promise.allSettled(Object.keys(sources).map((tag) => syncOne(tag).catch((error) => {
      logger.warn?.(`规则集 ${tag} 同步失败（继续使用已有文件）：${error.message}`);
      throw error;
    }))).finally(() => { running = null; });
    return running;
  }

  return {
    async start() {
      // 镜像只是附加能力：目录不可写时照常启动，规则集保持未就绪，生成页会退回经代理下载
      try {
        await mkdir(directory, { recursive: true });
      } catch (error) {
        logger.warn?.(`规则集目录不可用，跳过镜像：${error.message}`);
        return;
      }
      await load();
      if (!syncEnabled) return;
      sync();
      timer = setInterval(sync, Math.max(60_000, intervalMs));
      timer.unref?.();
    },
    stop() {
      if (timer) clearInterval(timer);
      timer = null;
    },
    sync,
    get(tag) {
      return entries.get(tag) || null;
    },
    status() {
      return Object.fromEntries(Object.keys(sources).map((tag) => [tag, entries.has(tag)]));
    }
  };
}
