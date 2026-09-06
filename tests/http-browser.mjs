import assert from "node:assert/strict";

export async function testHttpSubscription(browser, base) {
  const page = await browser.newPage();
  const errors = [];
  page.on("pageerror", error => errors.push(error.message));
  const address = new URL(base);
  // Chrome 把这个普通域名映射到测试服务；它不享有 localhost 的安全上下文例外。
  address.hostname = "sing-http.test";
  const bodies = [];
  page.on("request", request => {
    if (new URL(request.url()).pathname === "/api/sign-subscription") bodies.push(request.postDataJSON());
  });
  try {
    await page.goto(address.toString(), { waitUntil: "networkidle" });
    assert.deepEqual(await page.evaluate(() => ({ secure: isSecureContext, subtle: Boolean(crypto.subtle) })), { secure: false, subtle: false });
    await page.click("#generateBtn");
    await page.waitForFunction(() => document.querySelector("#subscriptionUrl").value.includes("sig="));
    const permanent = new URL(await page.locator("#subscriptionUrl").inputValue());
    assert.equal(permanent.origin, address.origin);
    assert.equal(permanent.searchParams.get("expires"), "0");
    const result = await page.evaluate(async url => {
      const response = await fetch(url);
      return { status: response.status, config: await response.json() };
    }, permanent.toString());
    assert.equal(result.status, 200);
    assert.deepEqual(result.config, JSON.parse(await page.locator("#configOutput").inputValue()));
    await page.evaluate(() => {
      const copy = document.execCommand.bind(document);
      document.execCommand = command => {
        const selected = document.activeElement?.value;
        const success = copy(command);
        window.copyAttempt = { selected, success };
        return success;
      };
    });
    await page.click("#copySubscriptionBtn");
    assert.deepEqual(await page.evaluate(() => window.copyAttempt), { selected: permanent.toString(), success: true });
    await page.selectOption("#subscriptionExpiry", "7");
    await page.waitForFunction(() => {
      const value = document.querySelector("#subscriptionUrl").value;
      return value && Number(new URL(value).searchParams.get("expires")) > 0;
    });
    const expiring = await page.locator("#subscriptionUrl").inputValue();
    assert.equal(await page.evaluate(async url => (await fetch(url)).status, expiring), 200);
    const changed = new URL(expiring);
    changed.searchParams.set("expires", "0");
    assert.equal(await page.evaluate(async url => (await fetch(url)).status, changed.toString()), 401);
    assert.equal(await page.locator("#subscriptionQr svg").count(), 1);
    assert.ok(bodies.length >= 2);
    for (const body of bodies) {
      assert.deepEqual(Object.keys(body).sort(), ["days", "digest", "token"]);
      assert.match(body.digest, /^[a-f0-9]{64}$/);
    }
    assert.deepEqual(errors, []);
    console.log("non-secure HTTP browser test passed: local digest, signed links, copy, expiry and QR");
  } finally { await page.close(); }
}
