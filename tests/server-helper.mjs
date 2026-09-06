import { spawn } from "node:child_process";
import { once } from "node:events";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";

export async function startTestServer(env = {}) {
  const temporary = env.STATE_DIRECTORY ? null : await mkdtemp(join(tmpdir(), "sing-test-server-"));
  const child = spawn(process.execPath, ["server.mjs"], {
    env: { ...process.env, PORT: "0", HOST: "127.0.0.1", SUBSCRIPTION_TOKEN: "", SUBSCRIPTION_SIGNING_KEY: "server-test-signing-key-do-not-use-in-production", RATE_LIMIT_MAX: "1000", STATE_DIRECTORY: temporary, ...env },
    stdio: ["ignore", "pipe", "pipe"]
  });
  const base = await new Promise((resolve, reject) => {
    let output = "";
    const timer = setTimeout(() => { child.kill(); reject(new Error(`测试服务启动超时：${output}`)); }, 8000);
    child.stdout.on("data", (chunk) => {
      output += chunk;
      const match = output.match(/running at (http:\/\/\S+)/);
      if (match) { clearTimeout(timer); resolve(match[1]); }
    });
    child.stderr.on("data", (chunk) => { output += chunk; });
    child.once("error", (error) => { clearTimeout(timer); reject(error); });
    child.once("exit", (code) => { clearTimeout(timer); reject(new Error(`测试服务退出（${code}）：${output}`)); });
  });
  return { base, child, async close() {
    if (child.exitCode === null && child.signalCode === null) { const ended = once(child, "exit"); child.kill(); await ended; }
    if (temporary) await rm(temporary, { recursive: true, force: true });
  } };
}
