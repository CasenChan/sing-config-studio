import assert from "node:assert/strict";
import { createServer } from "node:http";
import { mkdir } from "node:fs/promises";
import { STORAGE_KEY, UI_MODE_KEY, replaceDemoNodes } from "./browser-helpers.mjs";
import { startTestServer } from "./server-helper.mjs";

const visible = (page, selector) => page.locator(selector).first().isVisible();
const config = async (page) => JSON.parse(await page.locator("#configOutput").inputValue());
const toastText = (page) => page.locator("#toast span").innerText();

async function openGenerate(page) {
  await page.click("#generateBtn");
  await page.waitForFunction(() => document.querySelector("#shortSubscriptionUrl").value.includes("/s/"));
}

export async function testSimpleMode(browser, base) {
  await mkdir("output/playwright", { recursive: true });
  const errors = [];
  const watch = (page) => {
    page.on("pageerror", (error) => errors.push(`pageerror: ${error.message}`));
    page.on("console", (message) => { if (message.type() === "error" && !message.text().startsWith("Failed to load resource")) errors.push(`console: ${message.text()}`); });
  };

  // 新用户：默认简洁模式，只显示节点、分流与生成订阅；隐藏的模块仍参与生成
  const page = await browser.newPage({ viewport: { width: 1280, height: 900 } });
  watch(page);
  try {
    await page.goto(base, { waitUntil: "networkidle" });
    assert.equal(await page.evaluate(() => document.documentElement.dataset.mode), "simple");
    for (const selector of ["#nodes", "#routingMode", "#generateBtn", "#conflictBlock", "#chinaPresetEnabled + .switch"]) {
      assert.equal(await visible(page, selector), true, `简洁模式应显示 ${selector}`);
    }
    for (const selector of ["#endpoints", "#inbounds", "#dns", "#settings", "#services", "#configOutput", "#groupList", "#logLevel", "#materializeChinaBtn", "#resetBtn"]) {
      assert.equal(await visible(page, selector), false, `简洁模式应隐藏 ${selector}`);
    }
    const height = await page.evaluate(() => document.documentElement.scrollHeight);
    assert.ok(height < 1600, `简洁模式页面应明显变短（实际 ${height}px）`);
    const full = await config(page);
    assert.ok(full.inbounds.some((item) => item.type === "tun") && full.dns.servers.length && full.route.rule_set.length === 2, "隐藏的 TUN、DNS 与大陆规则集仍然生成");
    await page.screenshot({ path: "output/playwright/simple-mode.png", fullPage: true });

    // 示例节点：不能直接生成订阅；导入第一个真实节点时自动移除
    await page.click("#generateBtn");
    assert.match(await toastText(page), /示例节点/);
    assert.equal(await page.locator("#subscriptionModal").evaluate((el) => el.open), false);
    await page.click("#importBtn");
    await page.fill("#importText", "trojan://secret@my-node.example.net:443?sni=my-node.example.net#我的节点");
    await page.locator("#importModal .primary-button").click();
    await page.waitForFunction(() => document.querySelectorAll("#nodeList .node-item").length === 1);
    assert.match(await toastText(page), /已移除 3 个示例节点/);
    const imported = await config(page);
    assert.deepEqual(imported.outbounds.find((item) => item.tag === "auto").outbounds, ["我的节点"]);

    // 简洁模式下的订阅弹窗：短链接为主，高级选项（长链接、地址、token）折叠
    await openGenerate(page);
    assert.equal(await visible(page, "#shortSubscriptionUrl"), true);
    assert.equal(await page.locator("#subscriptionAdvanced").evaluate((el) => el.open), false);
    assert.equal(await visible(page, "#subscriptionUrl"), false, "长链接收在高级选项里");
    assert.match(await page.locator("#ruleSetHostingNote").innerText(), /首次启动需要默认节点可用/, "测试服务器未同步规则集时明确提示");
    await page.screenshot({ path: "output/playwright/simple-subscription.png" });
    await page.click("#subscriptionAdvanced summary");
    assert.equal(await visible(page, "#subscriptionUrl"), true);
    await page.click("#closeSubscription");

    // 切到高级模式：全部模块出现，选择会记住
    await page.click('.mode-switch [data-ui-mode="advanced"]');
    for (const selector of ["#endpoints", "#dns", "#settings", "#services", "#configOutput", "#materializeChinaBtn"]) {
      assert.equal(await visible(page, selector), true, `高级模式应显示 ${selector}`);
    }
    await page.reload({ waitUntil: "networkidle" });
    assert.equal(await page.evaluate(() => document.documentElement.dataset.mode), "advanced");
    await openGenerate(page);
    assert.equal(await page.locator("#subscriptionAdvanced").evaluate((el) => el.open), true, "高级模式下默认展开");
    await page.click("#closeSubscription");

    // 已有用户：改过高级设置的默认进高级模式；与默认相同的进简洁模式
    const saved = await page.evaluate((key) => JSON.parse(localStorage.getItem(key)), STORAGE_KEY);
    for (const [label, state, expected] of [
      ["已自定义入站", { ...saved, inbounds: [...saved.inbounds, { id: "extra", type: "mixed", tag: "mixed-in", enabled: true, listenPort: "7890" }] }, "advanced"],
      ["未自定义", saved, "simple"]
    ]) {
      await page.evaluate(({ key, modeKey, state }) => { localStorage.setItem(key, JSON.stringify(state)); localStorage.removeItem(modeKey); }, { key: STORAGE_KEY, modeKey: UI_MODE_KEY, state });
      await page.reload({ waitUntil: "networkidle" });
      assert.equal(await page.evaluate(() => document.documentElement.dataset.mode), expected, label);
    }

    // 移动端简洁模式
    await page.setViewportSize({ width: 390, height: 844 });
    await page.screenshot({ path: "output/playwright/simple-mobile.png", fullPage: true });
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), true, "移动端不应横向溢出");
  } finally {
    await page.close();
  }

  // 订阅服务器已同步规则集：订阅里的大陆规则集改为从该服务器直连下载
  const srs = Buffer.concat([Buffer.from("SRS"), Buffer.from([1]), Buffer.from("rules")]);
  const upstream = createServer((req, res) => res.end(srs));
  await new Promise((resolve) => upstream.listen(0, "127.0.0.1", resolve));
  const hosting = await startTestServer({ RULE_SET_SYNC: "on", RULE_SET_UPSTREAM: `http://127.0.0.1:${upstream.address().port}/` });
  const hostedPage = await browser.newPage({ viewport: { width: 1280, height: 900 } });
  watch(hostedPage);
  try {
    for (let attempt = 0; attempt < 50; attempt += 1) {
      const status = await (await fetch(`${hosting.base}/api/status`)).json();
      if (status.ruleSets?.["geosite-cn"] && status.ruleSets?.["geoip-cn"]) break;
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
    await hostedPage.goto(hosting.base, { waitUntil: "networkidle" });
    await replaceDemoNodes(hostedPage);
    const preview = await config(hostedPage);
    assert.ok(preview.route.rule_set.every((set) => set.url.startsWith("https://raw.githubusercontent.com/") && set.http_client.detour === "proxy"), "预览与下载保持可移植的 GitHub 地址");
    await openGenerate(hostedPage);
    assert.match(await hostedPage.locator("#ruleSetHostingNote").innerText(), /由订阅服务器提供/);
    const shortUrl = await hostedPage.locator("#shortSubscriptionUrl").inputValue();
    const longUrl = await hostedPage.locator("#subscriptionUrl").inputValue();
    for (const url of [shortUrl, longUrl]) {
      const delivered = await (await fetch(url)).json();
      assert.deepEqual(delivered.route.rule_set.map((set) => [set.url, set.http_client]), [
        [`${hosting.base}/rule-sets/geosite-cn.srs`, { domain_resolver: "local-dns" }],
        [`${hosting.base}/rule-sets/geoip-cn.srs`, { domain_resolver: "local-dns" }]
      ], "长短链接内容一致，均从订阅服务器直连下载");
      assert.deepEqual({ ...delivered, route: { ...delivered.route, rule_set: preview.route.rule_set } }, preview, "除规则集地址外与预览一致");
    }
    const downloaded = await fetch(`${hosting.base}/rule-sets/geoip-cn.srs`);
    assert.equal(downloaded.status, 200);
    assert.deepEqual(Buffer.from(await downloaded.arrayBuffer()), srs);
  } finally {
    await hostedPage.close();
    await hosting.close();
    upstream.close();
  }

  // 私有部署：服务器要求 token 时自动展开高级选项
  const privateServer = await startTestServer({ SUBSCRIPTION_TOKEN: "simple-mode-token" });
  const privatePage = await browser.newPage({ viewport: { width: 1280, height: 900 } });
  watch(privatePage);
  try {
    await privatePage.goto(privateServer.base, { waitUntil: "networkidle" });
    await replaceDemoNodes(privatePage);
    await privatePage.click("#generateBtn");
    await privatePage.waitForFunction(() => document.querySelector("#subscriptionAdvanced").open);
    assert.match(await privatePage.locator("#subscriptionGuard").innerText(), /token[\s\S]*高级选项/);
    assert.equal(await visible(privatePage, "#subscriptionToken"), true);
  } finally {
    await privatePage.close();
    await privateServer.close();
  }

  assert.deepEqual(errors, [], "页面不应有 JS 错误");
  console.log("simple mode browser tests passed: defaults, demo nodes, folded modal, mode memory, customized users, hosted rule-sets, private token");
}
