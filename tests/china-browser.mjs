import assert from "node:assert/strict";
import { writeFile } from "node:fs/promises";
import { planChinaRouting } from "../modules/china-routing.js";
import { pinAdvancedMode, replaceDemoNodes } from "./browser-helpers.mjs";

// 旧版本把预设展开写进列表，且下载设置带 domain_resolver
function legacyMaterialized(state) {
  const { presets: _ignored, ...rest } = state;
  const materialized = planChinaRouting(rest).state;
  materialized.route.ruleSets = materialized.route.ruleSets.map((set) => ({ ...set, httpClientJson: JSON.stringify({ detour: "proxy", domain_resolver: "local-dns" }) }));
  return JSON.parse(JSON.stringify(materialized));
}

export async function testChinaRouting(browser, base) {
  const page = await browser.newPage();
  await pinAdvancedMode(page);
  const key = "sing-config-studio:v1";
  const stored = () => page.evaluate(key => JSON.parse(localStorage.getItem(key)), key);
  const setStored = (state) => page.evaluate(({ key, state }) => localStorage.setItem(key, JSON.stringify(state)), { key, state });
  const config = async () => JSON.parse(await page.locator("#configOutput").inputValue());
  const errors = [];
  page.on("pageerror", error => errors.push(error.message));
  try {
    await page.goto(base, { waitUntil: "networkidle" });
    await replaceDemoNodes(page);

    // 默认：开关打开，规则只在生成时展开，不写进可编辑列表；经代理下载且不带 domain_resolver
    const defaults = await stored();
    assert.deepEqual(defaults.presets, { china: { enabled: true } });
    assert.deepEqual(defaults.route.ruleSets, []);
    assert.equal(defaults.route.rules.some(rule => rule.id.startsWith("route-cn-")), false);
    const defaultConfig = await config();
    assert.equal(defaultConfig.route.final, "proxy");
    assert.deepEqual(defaultConfig.route.rule_set.map(set => [set.tag, set.http_client]), [["geosite-cn", { detour: "proxy" }], ["geoip-cn", { detour: "proxy" }]]);
    assert.equal(await page.locator("#chinaPresetEnabled").isChecked(), true);
    await writeFile("output/playwright/china-default-config.json", JSON.stringify(defaultConfig, null, 2));

    // 关闭 / 打开开关：配置随之变化并持久化
    await page.locator("#chinaPresetEnabled").setChecked(false);
    assert.equal((await config()).route.rule_set, undefined);
    assert.equal((await config()).dns.rules.some(rule => JSON.stringify(rule).includes("geosite-cn")), false);
    await page.reload({ waitUntil: "networkidle" });
    assert.equal(await page.locator("#chinaPresetEnabled").isChecked(), false);
    assert.equal((await stored()).presets.china.enabled, false);
    await page.locator("#chinaPresetEnabled").setChecked(true);
    assert.deepEqual(await config(), defaultConfig);

    // 旧版未改动的展开规则：收回为开关，生成结果只修复 domain_resolver
    await setStored(legacyMaterialized(await stored()));
    await page.reload({ waitUntil: "networkidle" });
    const adopted = await stored();
    assert.deepEqual(adopted.presets, { china: { enabled: true } });
    assert.deepEqual(adopted.route.ruleSets, []);
    assert.deepEqual(await config(), defaultConfig);

    // 旧版改动过的展开规则：保持原样、开关关闭，只修复下载设置
    const modified = legacyMaterialized(await stored());
    const ipRule = modified.route.rules.find(rule => rule.id === "route-cn-ip");
    ipRule.outbound = "proxy";
    await setStored(modified);
    await page.reload({ waitUntil: "networkidle" });
    const kept = await stored();
    assert.equal(kept.presets.china.enabled, false);
    assert.equal(kept.route.rules.find(rule => rule.id === "route-cn-ip").outbound, "proxy");
    assert.deepEqual(kept.route.ruleSets.map(set => JSON.parse(set.httpClientJson)), [{ detour: "proxy" }, { detour: "proxy" }]);
    assert.equal(await page.locator("#chinaPresetEnabled").isChecked(), false);
    assert.equal((await config()).route.rule_set.length, 2);

    // 转为自定义规则：预览、取消不改动、存储失败不覆盖、应用后开关关闭且生成结果不变
    await setStored({ ...kept, presets: { china: { enabled: true } }, route: defaults.route, dns: defaults.dns });
    await page.reload({ waitUntil: "networkidle" });
    const before = await stored();
    const beforeConfig = await config();
    await page.click("#materializeChinaBtn");
    assert.match(await page.locator("#chinaRoutingPreview").innerText(), /大陆域名/);
    await page.keyboard.press("Escape");
    assert.deepEqual(await stored(), before);
    await page.click("#materializeChinaBtn");
    await page.evaluate(key => {
      window.setItemOriginal = Storage.prototype.setItem;
      Storage.prototype.setItem = function (k, v) { if (k === key) throw new DOMException("test quota", "QuotaExceededError"); return window.setItemOriginal.call(this, k, v); };
    }, key);
    await page.click("#applyChinaRoutingBtn");
    assert.match(await page.locator("#chinaRoutingError").innerText(), /当前配置未覆盖/);
    assert.deepEqual(await stored(), before);
    await page.evaluate(() => { Storage.prototype.setItem = window.setItemOriginal; });
    await page.click("#applyChinaRoutingBtn");
    const materialized = await stored();
    assert.equal(materialized.presets.china.enabled, false);
    assert.equal(materialized.route.ruleSets.length, 2);
    assert.ok(materialized.route.rules.some(rule => rule.id === "route-cn-domain"));
    assert.deepEqual(materialized.nodes, before.nodes);
    assert.deepEqual(await config(), beforeConfig, "转为自定义规则不改变生成结果");
    assert.deepEqual(await page.evaluate(key => JSON.parse(localStorage.getItem(`${key}:snapshot`)).state, key), before);
    assert.equal(await page.locator("#conflictTitle").innerText(), "冲突检查通过");

    // 已有同样的自定义规则时再打开开关，不会重复展开
    await page.locator("#chinaPresetEnabled").setChecked(true);
    assert.deepEqual(await config(), beforeConfig);
    assert.deepEqual(errors, []);
    console.log("mainland routing browser tests passed: toggle, legacy adoption, modified legacy, convert to custom rules, quota and no duplicates");
  } finally { await page.close(); }
}
