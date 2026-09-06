import assert from "node:assert/strict";
import { mkdir, writeFile } from "node:fs/promises";
import { emptyState } from "./fakeip-fixtures.mjs";
import { normalizeInbound } from "../modules/inbound.js";

export async function testFakeipFlows(browser, base) {
  const page = await browser.newPage({ viewport: { width: 1280, height: 1000 } });
  const key = "sing-config-studio:v1";
  const errors = [];
  page.on("pageerror", (error) => errors.push(error.message));
  page.on("dialog", (dialog) => dialog.accept().catch(() => {}));
  const stored = () => page.evaluate((key) => JSON.parse(localStorage.getItem(key)), key);
  const config = async () => JSON.parse(await page.locator("#configOutput").inputValue());
  const field = (name) => page.locator(`#dnsServerFields [data-field="${name}"]`);
  const row = (id) => page.locator(`#dnsServerList .sortable-item[data-id="${id}"]`);
  const openAdd = async (type = "fakeip") => {
    await page.click("#addDnsServerBtn");
    await page.click(`button[data-dns-type="${type}"]`);
  };
  const openEdit = async (id) => { await row(id).locator(".entry-edit").click(); };
  const reset = async (state) => {
    await page.evaluate(({ key, state }) => { localStorage.setItem(key, JSON.stringify(state)); }, { key, state });
    await page.reload({ waitUntil: "networkidle" });
  };
  try {
    await page.goto(base, { waitUntil: "networkidle" });
    await page.reload({ waitUntil: "networkidle" });
    const original = await stored();
    await openAdd("https");
    assert.equal(await page.locator("#fakeipPresetControls").isVisible(), false);
    await page.keyboard.press("Escape");

    // 三种退出方式都丢弃候选状态，预览期间不会提前创建服务器或快照。
    for (const cancel of ["button", "close", "escape"]) {
      await openAdd();
      assert.equal(await page.locator("#configureFakeipBtn").isVisible(), true);
      await page.click("#configureFakeipBtn");
      assert.match(await page.locator("#fakeipPresetPreview").innerText(), /FakeIP 兜底/);
      assert.equal(await page.locator("#saveDnsServerBtn").innerText(), "保存并应用");
      assert.deepEqual(await stored(), original);
      assert.equal(await page.evaluate((key) => localStorage.getItem(`${key}:snapshot`), key), null);
      if (cancel === "escape") await page.keyboard.press("Escape");
      else await page.click(cancel === "button" ? "#dnsServerModal .secondary-button.dialog-close" : "#dnsServerModal .modal-icon.dialog-close");
      assert.equal(await page.locator("#dnsServerModal").evaluate((element) => element.open), false);
      assert.deepEqual(await stored(), original);
    }

    // 普通保存只增加服务器；随后从编辑弹窗应用。
    await openAdd();
    await field("tag").fill("my-fakeip");
    await field("inet4Range").fill("198.18.0.0/16");
    await page.click("#saveDnsServerBtn");
    const plain = await stored();
    const serverId = plain.dns.servers.find((item) => item.type === "fakeip").id;
    assert.deepEqual(plain.dns.rules, original.dns.rules);
    assert.deepEqual(plain.inbounds, original.inbounds);
    assert.equal(plain.dns.fakeipPresets.profiles.length, 0);
    await openEdit(serverId);
    await page.click("#configureFakeipBtn");
    assert.equal(await page.locator("#fakeipPresetPreview .is-error").count(), 0);
    await mkdir("output/playwright", { recursive: true });
    await page.locator("#fakeipPresetControls").scrollIntoViewIfNeeded();
    await page.screenshot({ path: "output/playwright/fakeip-preview.png", animations: "disabled" });
    await page.click("#saveDnsServerBtn");
    const applied = await stored();
    assert.equal(applied.dns.fakeipPresets.profiles[0].serverId, serverId);
    assert.equal((await config()).dns.servers.find((item) => item.type === "fakeip").inet4_range, "198.18.0.0/16");
    assert.equal((await config()).route.final, "proxy", "FakeIP 预设不能绕过 Selector");
    assert.deepEqual((await config()).outbounds, (await configFromBackup(page, original)).outbounds);
    await writeFile("output/playwright/fakeip-default-config.json", JSON.stringify(await config(), null, 2));
    assert.deepEqual(await page.evaluate((key) => JSON.parse(localStorage.getItem(`${key}:snapshot`)).state, key), plain);
    assert.equal(JSON.stringify(await config()).includes("fakeipPresets"), false);

    await page.reload({ waitUntil: "networkidle" });
    await openEdit(serverId);
    assert.match(await page.locator("#fakeipPresetStatus").innerText(), /已有关联/);
    // 普通保存修改地址池，不隐式重设其他设置；改名更新未手改的预设引用。
    await field("tag").fill("renamed-fakeip");
    await page.click("#saveDnsServerBtn");
    assert.ok((await config()).dns.rules.some((rule) => rule.server === "renamed-fakeip"));
    const beforeRepeat = await stored();
    await openEdit(serverId);
    await page.click("#configureFakeipBtn");
    assert.match(await page.locator("#fakeipPresetPreview").innerText(), /无需重复添加/);
    await page.click("#saveDnsServerBtn");
    assert.deepEqual(await stored(), beforeRepeat);

    // 复制不继承关联；其普通删除不会弹出清理窗口。
    await row(serverId).locator(".entry-duplicate").click();
    const copyId = (await stored()).dns.servers.find((item) => item.type === "fakeip" && item.id !== serverId).id;
    await openEdit(copyId);
    assert.match(await page.locator("#fakeipPresetStatus").innerText(), /尚未应用/);
    await page.keyboard.press("Escape");
    await row(copyId).locator(".entry-delete").click();
    assert.equal(await page.locator("#fakeipRemovalModal").evaluate((element) => element.open), false);

    // 导出工具备份，预览两种删除结果，取消后状态完整。
    await page.click("#backupBtn");
    const backup = await page.locator("#backupText").inputValue();
    assert.ok(JSON.parse(backup).state.dns.fakeipPresets.profiles.length);
    await page.keyboard.press("Escape");
    const beforeDelete = await stored();
    await row(serverId).locator(".entry-delete").click();
    assert.match(await page.locator("#fakeipRemovalPreview").innerText(), /移除FakeIP 兜底/);
    await page.click("#fakeipRemovalModal summary");
    assert.match(await page.locator("#fakeipOnlyRemovalPreview").innerText(), /仍有引用/);
    await page.keyboard.press("Escape");
    assert.deepEqual(await stored(), beforeDelete);
    await row(serverId).locator(".entry-delete").click();
    await page.click("#removeFakeipOnlyBtn");
    assert.deepEqual((await stored()).dns.rules, beforeDelete.dns.rules);
    assert.match(await page.locator("#conflictList").innerText(), /renamed-fakeip/);
    await page.click("#generateBtn");
    assert.equal(await page.locator("#subscriptionModal").evaluate((element) => element.open), false);
    await page.reload({ waitUntil: "networkidle" });
    assert.deepEqual((await stored()).dns.rules, beforeDelete.dns.rules);

    await page.click("#backupBtn");
    await page.fill("#backupText", backup);
    await page.click("#backupForm .primary-button");
    await page.reload({ waitUntil: "networkidle" });
    await row(serverId).locator(".entry-delete").click();
    assert.equal(await page.locator("#fakeipRemovalModal").evaluate((element) => element.open), true);
    await page.click("#removeFakeipPresetBtn");
    const cleaned = await stored();
    assert.deepEqual(cleaned.dns.rules, original.dns.rules);
    assert.deepEqual(cleaned.route.rules, original.route.rules);
    assert.deepEqual(cleaned.inbounds, original.inbounds);
    await page.reload({ waitUntil: "networkidle" });
    assert.deepEqual((await stored()).dns.rules, original.dns.rules);

    // 空状态可补建所有依赖；预览阻断时不能保存；两个存储步骤任一失败都不覆盖。
    await reset(emptyState());
    const empty = await stored();
    await openAdd();
    await field("inet4Range").fill("172.19.0.0/16");
    await page.click("#configureFakeipBtn");
    await page.click("#saveDnsServerBtn");
    assert.match(await page.locator("#dnsServerFormError").innerText(), /重叠/);
    assert.deepEqual(await stored(), empty);
    await field("inet4Range").fill("198.18.0.0/15");
    for (const failedKey of [`${key}:snapshot`, key]) {
      await page.evaluate((failedKey) => {
        window.savedSetItem = Storage.prototype.setItem;
        Storage.prototype.setItem = function (key, value) { if (key === failedKey) throw new DOMException("test quota", "QuotaExceededError"); return window.savedSetItem.call(this, key, value); };
      }, failedKey);
      await page.click("#saveDnsServerBtn");
      assert.match(await page.locator("#dnsServerFormError").innerText(), /当前配置未覆盖/);
      assert.deepEqual(await stored(), empty);
      await page.evaluate(() => { Storage.prototype.setItem = window.savedSetItem; });
    }
    await page.click("#saveDnsServerBtn");
    const newId = (await stored()).dns.servers.find((item) => item.type === "fakeip").id;
    await row(newId).locator(".entry-delete").click();
    await page.setViewportSize({ width: 390, height: 844 });
    assert.equal(await page.locator("#fakeipRemovalModal").evaluate((element) => element.scrollWidth <= element.clientWidth), true);
    await page.screenshot({ path: "output/playwright/fakeip-removal-mobile.png", animations: "disabled" });
    await page.click("#removeFakeipPresetBtn");
    await page.reload({ waitUntil: "networkidle" });
    for (const name of ["inbounds", "groups"]) assert.deepEqual((await stored())[name], []);
    assert.deepEqual((await stored()).dns.servers, []);
    assert.deepEqual((await stored()).dns.rules, []);
    assert.deepEqual((await stored()).route.rules, []);
    // 自动备份可撤销清理，关联记录恢复后仍能进行安全清理。
    await page.click("#backupBtn");
    await page.click("#restoreSnapshotBtn");
    await page.click("#backupForm .primary-button");
    assert.equal((await stored()).dns.fakeipPresets.profiles[0].serverId, newId);
    await page.setViewportSize({ width: 1280, height: 1000 });

    // 多 TUN 必须在同一窗口选择目标；选择不影响原状态直至保存。
    const multi = emptyState();
    multi.inbounds = [
      normalizeInbound({ type: "tun", id: "a", tag: "tun-a", interfaceName: "utun20", address: "172.19.0.1/30" }),
      normalizeInbound({ type: "tun", id: "b", tag: "tun-b", interfaceName: "utun21", address: "172.20.0.1/30" })
    ];
    await reset(multi);
    await openAdd();
    await page.click("#configureFakeipBtn");
    assert.match(await page.locator("#fakeipPresetPreview").innerText(), /请选择/);
    await page.selectOption("#fakeipTunSelect", "b");
    assert.equal(await page.locator("#fakeipPresetPreview .is-error").count(), 0);
    await page.click("#saveDnsServerBtn");
    assert.deepEqual((await config()).route.rules[0].inbound, ["tun-b"]);
    assert.deepEqual(errors, [], "FakeIP 流程不能出现页面异常");
    console.log("fakeip browser flow tests passed");
  } finally { await page.close(); }
}

async function configFromBackup(page, state) {
  // 在页面当前版本模块中构建用于比较的出站，不影响 UI 和 localStorage。
  return page.evaluate(async (state) => {
    const { outboundModule } = await import("/modules/outbound.js");
    return outboundModule.extendConfig({}, state);
  }, state);
}
