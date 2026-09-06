import assert from "node:assert/strict";

export async function testReviewFlows(browser, base) {
  const page = await browser.newPage();
  const key = "sing-config-studio:v1";
  const errors = [];
  page.on("pageerror", error => errors.push(error.message));
  page.on("dialog", dialog => dialog.accept().catch(() => {}));
  const stored = () => page.evaluate(key => JSON.parse(localStorage.getItem(key)), key);
  const snapshot = () => page.evaluate(key => localStorage.getItem(`${key}:snapshot`), key);
  const config = async () => JSON.parse(await page.locator("#configOutput").inputValue());
  const importJson = async value => {
    await page.click("#importConfigBtn");
    await page.fill("#importConfigText", JSON.stringify(value));
    await page.click("#applyImportBtn");
  };
  const restoreSnapshot = async () => {
    await page.click("#backupBtn");
    await page.click("#restoreSnapshotBtn");
    await page.click("#backupForm .primary-button");
  };
  try {
    await page.goto(base, { waitUntil: "networkidle" });
    await page.reload({ waitUntil: "networkidle" });
    const original = await stored();
    const originalConfig = await config();
    // 两个写入步骤任意失败，都保留导入前配置及原来的快照。
    await page.click("#importConfigBtn");
    await page.fill("#importConfigText", "{}");
    for (const failedKey of [`${key}:snapshot`, key]) {
      const oldSnapshot = await snapshot();
      await page.evaluate(failedKey => {
        window.originalSetItem = Storage.prototype.setItem;
        Storage.prototype.setItem = function (key, value) {
          if (key === failedKey) throw new DOMException("test quota", "QuotaExceededError");
          return window.originalSetItem.call(this, key, value);
        };
      }, failedKey);
      await page.click("#applyImportBtn");
      assert.match(await page.locator("#importConfigError").innerText(), /当前配置未覆盖/);
      assert.deepEqual(await stored(), original);
      assert.deepEqual(await config(), originalConfig);
      assert.equal(await snapshot(), oldSnapshot);
      await page.evaluate(() => { Storage.prototype.setItem = window.originalSetItem; });
    }
    await page.click("#applyImportBtn");
    assert.deepEqual(JSON.parse(await snapshot()).state, original, "快照必须是导入前的配置");
    await page.reload({ waitUntil: "networkidle" });
    const empty = await stored();
    for (const field of ["nodes", "groups", "inbounds", "subscriptions"]) assert.deepEqual(empty[field], []);
    for (const section of ["dns", "route"]) assert.deepEqual(empty[section].rules, []);
    assert.deepEqual(empty.dns.servers, []);
    await restoreSnapshot();
    assert.deepEqual(await config(), originalConfig);
    await page.reload({ waitUntil: "networkidle" });
    assert.deepEqual(await stored(), original);

    const custom = structuredClone(originalConfig);
    const direct = custom.outbounds.find(item => item.tag === "direct");
    Object.assign(direct, { bind_interface: "en0", connect_timeout: "7s", domain_resolver: { server: custom.dns.final, strategy: "prefer_ipv4" } });
    await importJson(custom);
    await page.reload({ waitUntil: "networkidle" });
    assert.deepEqual((await config()).outbounds.filter(item => item.tag === "direct"), [direct]);
    assert.deepEqual((await stored()).dns.fakeipPresets?.profiles || [], []);
    assert.ok((await config()).outbounds.find(item => item.type === "selector").outbounds.includes("direct"));

    // 远程 JSON 节点的添加与刷新都走完整反序列化，不能丢失高级参数。
    let remote = { type: "trojan", tag: "remote-advanced", server: "remote.example.com", server_port: 443, password: "test-password", connect_timeout: "9s", tcp_fast_open: true, tls: { enabled: true, server_name: "remote.example.com", alpn: ["h2"], utls: { enabled: true, fingerprint: "chrome" }, fragment: true }, transport: { type: "ws", path: "/ws", headers: { Host: "cdn.example.com" }, max_early_data: 2048, early_data_header_name: "Sec-WebSocket-Protocol" }, multiplex: { enabled: true, protocol: "h2mux", max_connections: 4, padding: true } };
    await page.route("**/api/fetch-subscription", route => route.fulfill({ json: { content: JSON.stringify({ outbounds: [remote] }), contentType: "application/json", finalUrl: "https://remote.example.com/feed" } }));
    await page.click("#addSubscriptionBtn");
    await page.fill("#remoteSubscriptionUrl", "https://remote.example.com/feed");
    await page.click("#fetchSubscriptionBtn");
    await page.waitForFunction(() => !document.querySelector("#remoteSubscriptionModal").open);
    assert.deepEqual((await config()).outbounds.find(item => item.tag === remote.tag), remote);
    remote = { ...remote, tls: { ...remote.tls, alpn: ["http/1.1"], record_fragment: true }, connect_timeout: "11s" };
    await page.click(".refresh-subscription");
    await page.waitForFunction(() => JSON.parse(document.querySelector("#configOutput").value).outbounds.some(item => item.tag === "remote-advanced" && item.connect_timeout === "11s"));
    assert.deepEqual((await config()).outbounds.find(item => item.tag === remote.tag), remote);
    await page.reload({ waitUntil: "networkidle" });
    assert.deepEqual((await config()).outbounds.find(item => item.tag === remote.tag), remote);

    // 签名 API 只接收摘要；待签名时清空旧链接，较早返回的请求不能覆盖新选项。
    await page.click("#resetBtn");
    const signingBodies = [];
    let release;
    const held = new Promise(resolve => { release = resolve; });
    let failed = false;
    await page.route("**/api/sign-subscription", async route => {
      const body = route.request().postDataJSON();
      signingBodies.push(body);
      if (failed) return route.fulfill({ status: 401, json: { error: "测试签名失败" } });
      if (body.days === 1) await held;
      await route.continue();
    });
    await page.click("#generateBtn");
    await page.waitForFunction(() => document.querySelector("#subscriptionUrl").value.includes("sig="));
    const permanent = new URL(await page.locator("#subscriptionUrl").inputValue());
    assert.equal(permanent.searchParams.get("expires"), "0");
    assert.deepEqual(await (await fetch(permanent)).json(), await config());
    await page.selectOption("#subscriptionExpiry", "1");
    assert.equal(await page.locator("#subscriptionUrl").inputValue(), "");
    assert.equal(await page.locator("#openSubscriptionBtn").getAttribute("href"), null);
    assert.equal(await page.locator("#copySubscriptionBtn").isDisabled(), true);
    await page.selectOption("#subscriptionExpiry", "7");
    await page.waitForFunction(() => document.querySelector("#subscriptionUrl").value.includes("sig="));
    const sevenDays = await page.locator("#subscriptionUrl").inputValue();
    assert.ok(Number(new URL(sevenDays).searchParams.get("expires")) - Date.now() / 1000 > 6 * 86400);
    release();
    await page.waitForLoadState("networkidle");
    assert.equal(await page.locator("#subscriptionUrl").inputValue(), sevenDays);
    const changed = new URL(sevenDays);
    changed.searchParams.delete("expires");
    assert.equal((await fetch(changed)).status, 401);
    for (const body of signingBodies) {
      assert.deepEqual(Object.keys(body).sort(), ["days", "digest", "token"]);
      assert.match(body.digest, /^[a-f0-9]{64}$/);
    }
    failed = true;
    await page.selectOption("#subscriptionExpiry", "30");
    await page.waitForFunction(() => document.querySelector("#subscriptionGuard").textContent === "测试签名失败");
    assert.equal(await page.locator("#subscriptionUrl").inputValue(), "");
    assert.equal(await page.locator("#importClientBtn").getAttribute("href"), null);
    assert.deepEqual(errors, []);
    console.log("review browser tests passed: snapshots, empty arrays, custom direct, remote fields and signed links");
  } finally { await page.close(); }
}
