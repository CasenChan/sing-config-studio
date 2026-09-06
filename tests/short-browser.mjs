import assert from "node:assert/strict";
import { mkdir } from "node:fs/promises";

export async function testShortSubscription(browser, base) {
  const page = await browser.newPage({ viewport: { width: 1280, height: 1000 } });
  const errors = [];
  page.on("pageerror", error => errors.push(error.message));
  let fail = true;
  let delayed = false;
  let release;
  const held = new Promise(resolve => { release = resolve; });
  let started;
  const requestStarted = new Promise(resolve => { started = resolve; });
  const longUrl = () => page.locator("#subscriptionUrl").inputValue();
  const shortUrl = () => page.locator("#shortSubscriptionUrl").inputValue();
  const waitShort = () => page.waitForFunction(() => document.querySelector("#shortSubscriptionUrl").value.includes("/s/"));
  try {
    await page.route("**/api/short-subscription", async route => {
      if (fail) return route.fulfill({ status: 503, json: { error: "测试存储不可用" } });
      const body = route.request().postDataJSON();
      if (delayed && Number(body.fields.expires) - Date.now() / 1000 < 2 * 86400) {
        const response = await route.fetch();
        started();
        await held;
        return route.fulfill({ response });
      }
      await route.continue();
    });
    await page.goto(base, { waitUntil: "networkidle" });
    await page.click("#generateBtn");
    await page.waitForFunction(() => document.querySelector("#shortSubscriptionStatus").textContent.includes("测试存储不可用"));
    const originalLong = await longUrl();
    assert.equal(await shortUrl(), "");
    assert.equal(await page.locator("#openSubscriptionBtn").getAttribute("href"), originalLong);
    assert.equal(await page.locator("#copySubscriptionBtn").isEnabled(), true);
    assert.equal(await page.locator("#copyShortSubscriptionBtn").isDisabled(), true);
    assert.equal((await fetch(originalLong)).status, 200);
    fail = false;
    await page.click("#retryShortSubscriptionBtn");
    await waitShort();
    const permanent = await shortUrl();
    assert.equal(await longUrl(), originalLong);
    assert.ok(permanent.length < originalLong.length);
    assert.deepEqual(await (await fetch(permanent)).json(), await (await fetch(originalLong)).json());
    assert.equal(await page.locator("#openSubscriptionBtn").getAttribute("href"), permanent);
    assert.equal(new URL(await page.locator("#importClientBtn").getAttribute("href")).searchParams.get("url"), permanent);
    await page.click('[data-qr-mode="raw"]');
    assert.match(await page.locator("#subscriptionQrMeta").innerText(), new RegExp(`^${new TextEncoder().encode(permanent).length} 字节`));
    await page.click("#copyShortSubscriptionBtn");
    await page.setViewportSize({ width: 390, height: 844 });
    assert.equal(await page.locator("#subscriptionModal").evaluate(element => element.scrollWidth <= element.clientWidth), true);
    await mkdir("output/playwright", { recursive: true });
    await page.screenshot({ path: "output/playwright/short-subscription-mobile.png" });
    await page.setViewportSize({ width: 1280, height: 1000 });
    // 旧短链接响应晚到时不能覆盖用户后来选择的有效期。
    delayed = true;
    await page.selectOption("#subscriptionExpiry", "1");
    assert.equal(await shortUrl(), "");
    await requestStarted;
    await page.selectOption("#subscriptionExpiry", "7");
    await waitShort();
    const sevenDays = await shortUrl();
    const currentLong = await longUrl();
    release();
    await page.waitForLoadState("networkidle");
    assert.equal(await shortUrl(), sevenDays);
    assert.equal(await longUrl(), currentLong);
    assert.equal((await fetch(sevenDays)).status, 200);
    assert.notEqual(sevenDays, permanent);
    assert.equal(new URL(await page.locator("#importClientBtn").getAttribute("href")).searchParams.get("url"), sevenDays);
    assert.deepEqual(errors, []);
    console.log("short subscription browser tests passed: dual links, fallback, retry, QR, mobile and stale responses");
  } finally { release(); await page.close(); }
}
