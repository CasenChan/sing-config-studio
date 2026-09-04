// 浏览器流程测试：添加、编辑、取消、删除、导入、冲突拦截与生成订阅。
// 需要 playwright-core 与一个本机 Chrome/Chromium；缺任一条件时跳过而不是失败。
import { spawn } from "node:child_process";
import { createRequire } from "node:module";
import { existsSync } from "node:fs";
import assert from "node:assert/strict";

const require = createRequire(import.meta.url);
const CHROME_CANDIDATES = [
  process.env.CHROME_PATH,
  "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
  "/Applications/Chromium.app/Contents/MacOS/Chromium",
  "/usr/bin/google-chrome",
  "/usr/bin/chromium",
  "/usr/bin/chromium-browser"
].filter(Boolean);

let chromium;
try {
  ({ chromium } = require("playwright-core"));
} catch {
  console.log("skip: 未安装 playwright-core（npm i -D playwright-core 后可运行浏览器流程测试）");
  process.exit(0);
}
const executablePath = CHROME_CANDIDATES.find((path) => existsSync(path));
if (!executablePath) {
  console.log("skip: 未找到 Chrome/Chromium，可用 CHROME_PATH 指定");
  process.exit(0);
}

const port = Number(process.env.TEST_PORT || 4199);
const server = spawn(process.execPath, ["server.mjs"], { env: { ...process.env, PORT: String(port) }, stdio: "ignore" });
const base = `http://127.0.0.1:${port}/`;
const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
for (let attempt = 0; attempt < 40; attempt += 1) {
  try {
    await fetch(`${base}health`);
    break;
  } catch {
    await wait(100);
  }
}

const browser = await chromium.launch({ executablePath, headless: true });
const page = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
const errors = [];
page.on("pageerror", (error) => errors.push(`pageerror: ${error.message}`));
page.on("console", (message) => { if (message.type() === "error") errors.push(`console: ${message.text()}`); });
page.on("dialog", (dialog) => dialog.accept().catch(() => {}));
const config = async () => JSON.parse(await page.locator("#configOutput").inputValue());
const conflicts = () => page.locator("#conflictList .conflict-item").allTextContents();

try {
  await page.goto(base, { waitUntil: "networkidle" });

  // 默认档案可以直接生成
  assert.equal(await page.locator("#conflictTitle").textContent(), "冲突检查通过");
  assert.equal((await page.locator("#validationBar span").first().textContent()).trim(), "结构检查通过");
  const initial = await config();
  assert.ok(initial.inbounds.length && initial.outbounds.length && initial.dns.servers.length && initial.route.rules.length);

  // 添加出站：必填校验 -> 保存 -> 出现在配置里
  await page.click("#addNodeBtn");
  await page.click('button[data-node-type="trojan"]');
  await page.fill('#nodeFields [data-field="server"]', "t.example.com");
  await page.click("#nodeForm .primary-button");
  assert.equal(await page.locator("#nodeModal").evaluate((el) => el.open), true, "缺少必填项时不应保存");
  await page.fill('#nodeFields [data-field="password"]', "pass");
  await page.click("#nodeForm .primary-button");
  await wait(200);
  assert.ok((await config()).outbounds.some((item) => item.tag === "trojan"));

  // 取消按钮不触发必填校验，也不会保存
  await page.click("#addNodeBtn");
  await page.click('button[data-node-type="vless"]');
  await page.click("#nodeModal .secondary-button.dialog-close");
  assert.equal(await page.locator("#nodeModal").evaluate((el) => el.open), false);
  assert.equal((await config()).outbounds.some((item) => item.type === "vless" && item.tag === "vless"), false);

  // 编辑与删除
  await page.locator("#nodeList .node-item").last().click();
  await page.fill('#nodeFields [data-field="tag"]', "trojan-edited");
  await page.click("#nodeForm .primary-button");
  await wait(200);
  assert.ok((await config()).outbounds.some((item) => item.tag === "trojan-edited"));
  await page.locator("#nodeList .node-item").last().locator(".delete-node").click();
  await wait(200);
  assert.equal((await config()).outbounds.some((item) => item.tag === "trojan-edited"), false);

  // 导入分享链接
  await page.click("#importBtn");
  await page.fill("#importText", "hysteria2://pw@hy2.example.com:8443?sni=hy2.example.com#Imported");
  await page.click("#parseImportBtn");
  await wait(250);
  assert.ok((await config()).outbounds.some((item) => item.tag === "Imported"));

  // 冲突拦截：端口冲突时不能生成订阅
  await page.click("#addInboundBtn");
  await page.click('button[data-inbound-type="mixed"]');
  await page.fill('#inboundFields [data-field="listenPort"]', "7890");
  await page.click("#inboundForm .primary-button");
  await wait(150);
  await page.click("#addInboundBtn");
  await page.click('button[data-inbound-type="socks"]');
  await page.fill('#inboundFields [data-field="listenPort"]', "7890");
  await page.click("#inboundForm .primary-button");
  await wait(250);
  assert.ok((await conflicts()).some((text) => text.includes("监听地址冲突")));
  await page.click("#generateBtn");
  await wait(250);
  assert.equal(await page.locator("#subscriptionModal").evaluate((el) => el.open), false, "有冲突时不应生成订阅链接");

  // 修正冲突后可以生成
  await page.locator("#inboundList .sortable-item").last().click();
  await page.fill('#inboundFields [data-field="listenPort"]', "1080");
  await page.click("#inboundForm .primary-button");
  await wait(250);
  assert.equal(await page.locator("#conflictTitle").textContent(), "冲突检查通过");
  await page.click("#generateBtn");
  await wait(350);
  assert.equal(await page.locator("#subscriptionModal").evaluate((el) => el.open), true);
  assert.match(await page.locator("#subscriptionUrl").inputValue(), /\/subscription\?data=/);
  // 订阅二维码：有 BarcodeDetector 时真解码，内容必须等于客户端导入链接
  assert.equal(await page.locator("#subscriptionQr svg").count(), 1, "应渲染出二维码");
  const decoded = await page.evaluate(async () => {
    if (!("BarcodeDetector" in window)) return "skip";
    const svg = document.querySelector("#subscriptionQr svg");
    const img = new Image();
    await new Promise((resolve) => { img.onload = resolve; img.src = "data:image/svg+xml;charset=utf-8," + encodeURIComponent(svg.outerHTML); });
    const canvas = document.createElement("canvas"); canvas.width = img.width; canvas.height = img.height;
    canvas.getContext("2d").drawImage(img, 0, 0);
    const found = await new BarcodeDetector({ formats: ["qr_code"] }).detect(canvas);
    return found[0]?.rawValue || "未识别";
  });
  if (decoded !== "skip") assert.equal(decoded, await page.locator("#importClientBtn").getAttribute("href"), "二维码内容应与客户端导入链接一致");
  await page.click("#closeSubscription");

  // 配置导入往返
  const before = await config();
  await page.click("#importConfigBtn");
  await page.fill("#importConfigText", JSON.stringify(before));
  await wait(300);
  await page.click("#applyImportBtn");
  await wait(500);
  const after = await config();
  for (const key of ["log", "dns", "inbounds", "outbounds", "route", "experimental"]) {
    assert.deepEqual(after[key], before[key], `${key} 往返后应保持一致`);
  }

  assert.deepEqual(errors, [], "页面不应有 JS 错误");
  console.log("browser flow tests passed");
} finally {
  await browser.close();
  server.kill();
}
