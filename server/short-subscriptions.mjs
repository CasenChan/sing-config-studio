import { createHmac, randomBytes } from "node:crypto";
import { mkdir, readFile, readdir, rename, unlink, writeFile } from "node:fs/promises";
import { join } from "node:path";

export function shortSubscriptionStore(directory, key, { maxEntries = 1000 } = {}) {
  if (!Number.isInteger(maxEntries) || maxEntries < 1) throw new Error("SHORT_LINK_MAX_ENTRIES 必须是正整数");
  const root = join(directory, "short-subscriptions");
  const validId = id => /^[A-Za-z0-9_-]{32}$/.test(id);
  let queue = Promise.resolve();
  async function read(id) {
    if (!validId(id)) return null;
    try {
      const record = JSON.parse(await readFile(join(root, `${id}.json`), "utf8"));
      if (record.version !== 1 || !record.fields) throw new Error("短链接记录格式无效");
      return record.fields;
    } catch (error) { if (error.code === "ENOENT") return null; throw error; }
  }
  async function save(fields) {
    // 带密钥的 192 位标识防止枚举；相同签名重复提交复用同一条记录。
    const id = createHmac("sha256", key).update("short-subscription:v1:").update(JSON.stringify(fields)).digest("base64url").slice(0, 32);
    await mkdir(root, { recursive: true, mode: 0o700 });
    if (await read(id)) return id;
    const files = (await readdir(root)).filter(name => /^[A-Za-z0-9_-]{32}\.json$/.test(name));
    let count = files.length;
    for (const file of count >= maxEntries ? files : []) {
      const record = await read(file.slice(0, -5));
      if (record?.expires !== "0" && Number(record?.expires) * 1000 <= Date.now()) {
        await unlink(join(root, file)).catch(error => { if (error.code !== "ENOENT") throw error; });
        count -= 1;
      }
    }
    if (count >= maxEntries) throw new Error("短链接存储已满，请清理旧记录或提高 SHORT_LINK_MAX_ENTRIES；长链接仍可使用");
    const target = join(root, `${id}.json`);
    const temporary = join(root, `.${id}-${randomBytes(8).toString("hex")}.tmp`);
    try {
      await writeFile(temporary, JSON.stringify({ version: 1, fields }), { flag: "wx", mode: 0o600 });
      await rename(temporary, target);
    } finally { await unlink(temporary).catch(error => { if (error.code !== "ENOENT") throw error; }); }
    return id;
  }
  return {
    read,
    save(fields) {
      const pending = queue.then(() => save(fields));
      queue = pending.catch(() => {});
      return pending;
    }
  };
}
