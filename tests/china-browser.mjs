import assert from "node:assert/strict";
import { writeFile } from "node:fs/promises";

export async function testChinaRouting(browser, base) {
  const page = await browser.newPage();
  const key = "sing-config-studio:v1";
  const stored = () => page.evaluate(key => JSON.parse(localStorage.getItem(key)), key);
  const config = async () => JSON.parse(await page.locator("#configOutput").inputValue());
  const errors = [];
  page.on("pageerror", error => errors.push(error.message));
  try {
    await page.goto(base, { waitUntil: "networkidle" });
    assert.equal((await config()).route.final, "proxy");
    assert.equal((await config()).route.rule_set.length, 2, "新默认模板必须包含大陆规则集");
    await writeFile("output/playwright/china-default-config.json", JSON.stringify(await config(), null, 2));
    // 模拟升级前的用户配置；刷新时保持原样，用户从补齐入口应用。
    const old = await stored();
    old.route.ruleSets = [];
    old.route.rules = old.route.rules.filter(rule => !rule.id.startsWith("route-cn-"));
    old.dns.rules = old.dns.rules.filter(rule => rule.id !== "dns-cn-domain");
    await page.evaluate(({ key, state }) => localStorage.setItem(key, JSON.stringify(state)), { key, state: old });
    await page.reload({ waitUntil: "networkidle" });
    const before = await stored();
    assert.equal((await config()).route.rule_set, undefined);
    await page.click("#configureChinaRoutingBtn");
    assert.match(await page.locator("#chinaRoutingPreview").innerText(), /大陆域名/);
    assert.deepEqual(await stored(), before);
    await page.keyboard.press("Escape");
    assert.deepEqual(await stored(), before);
    await page.click("#configureChinaRoutingBtn");
    await page.evaluate(key => {
      window.setItemOriginal = Storage.prototype.setItem;
      Storage.prototype.setItem = function (k, v) { if (k === key) throw new DOMException("test quota", "QuotaExceededError"); return window.setItemOriginal.call(this, k, v); };
    }, key);
    await page.click("#applyChinaRoutingBtn");
    assert.match(await page.locator("#chinaRoutingError").innerText(), /当前配置未覆盖/);
    assert.deepEqual(await stored(), before);
    await page.evaluate(() => { Storage.prototype.setItem = window.setItemOriginal; });
    await page.click("#applyChinaRoutingBtn");
    assert.equal((await config()).route.rule_set.length, 2);
    assert.deepEqual((await stored()).nodes, before.nodes);
    assert.deepEqual((await stored()).groups, before.groups);
    assert.deepEqual(await page.evaluate(key => JSON.parse(localStorage.getItem(`${key}:snapshot`)).state, key), before);
    assert.equal(await page.locator("#conflictTitle").innerText(), "冲突检查通过");
    await page.reload({ waitUntil: "networkidle" });
    const applied = await stored();
    await page.click("#configureChinaRoutingBtn");
    assert.match(await page.locator("#chinaRoutingPreview").innerText(), /无需重复添加/);
    await page.click("#applyChinaRoutingBtn");
    assert.deepEqual(await stored(), applied);
    assert.deepEqual(errors, []);
    console.log("mainland routing browser tests passed: defaults, existing state, cancel, snapshot, quota and repeat");
  } finally { await page.close(); }
}
