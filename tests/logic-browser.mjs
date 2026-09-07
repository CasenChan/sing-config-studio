import assert from "node:assert/strict";
import { mkdir, readFile } from "node:fs/promises";
import { resolve } from "node:path";

export async function testBasicLogicFlows(browser, base) {
  const page = await browser.newPage();
  page.setDefaultTimeout(10000);
  await page.setViewportSize({ width: 1440, height: 1000 });
  await mkdir("output/playwright", { recursive: true });
  const key = "sing-config-studio:v1";
  const errors = [];
  page.on("pageerror", error => errors.push(error.message));
  page.on("dialog", dialog => dialog.accept().catch(() => {}));
  const stored = () => page.evaluate(key => JSON.parse(localStorage.getItem(key)), key);
  const config = async () => JSON.parse(await page.locator("#configOutput").inputValue());
  const importJson = async value => {
    await page.click("#importConfigBtn");
    await page.fill("#importConfigText", JSON.stringify(value));
    await page.click("#applyImportBtn");
    await page.waitForFunction(() => !document.querySelector("#importConfigModal").open);
  };
  const generate = async () => {
    await page.click("#generateBtn");
    await page.waitForFunction(() => document.querySelector("#subscriptionModal").open && document.querySelector("#subscriptionUrl").value.includes("/subscription?"));
    const url = await page.locator("#subscriptionUrl").inputValue();
    const response = await fetch(url);
    assert.equal(response.status, 200);
    return response.json();
  };
  const minimal = {
    dns: { servers: [{ type: "local", tag: "local" }], final: "local" },
    inbounds: [{ type: "mixed", tag: "mixed", listen: "127.0.0.1", listen_port: 18891 }],
    outbounds: [{ type: "direct", tag: "direct" }],
    route: { final: "direct", default_domain_resolver: "local" }
  };
  const remote = { type: "trojan", tag: "node-a", server: "remote.example.com", server_port: 443, password: "test-password", tls: { enabled: true, server_name: "remote.example.com" } };
  const referenced = {
    ...structuredClone(minimal),
    outbounds: [{ type: "selector", tag: "proxy", outbounds: ["node-a"], default: "node-a" }, remote, ...minimal.outbounds],
    route: { ...minimal.route, final: "proxy", rules: [{ domain: ["example.com"], action: "route", outbound: "node-a" }] }
  };
  try {
    await page.goto(base, { waitUntil: "networkidle" });
    const original = await config();
    const manual = structuredClone(original);
    manual.route.final = "direct";
    await page.fill("#configOutput", JSON.stringify(manual));
    assert.equal(await page.locator("#validationBar span").first().innerText(), "结构检查通过");
    assert.equal(await page.locator("#editorSourceNote").isVisible(), true);
    const downloadEvent = page.waitForEvent("download");
    await page.click("#downloadConfigBtn");
    const download = await downloadEvent;
    assert.deepEqual(JSON.parse(await readFile(await download.path(), "utf8")), manual);
    assert.deepEqual(await generate(), manual, "生成订阅不能重建表单并覆盖手动 JSON");
    assert.deepEqual(await config(), manual);
    await page.waitForFunction(() => document.querySelector("#shortSubscriptionUrl").value.includes("/s/"));
    assert.deepEqual(await (await fetch(await page.locator("#shortSubscriptionUrl").inputValue())).json(), manual);

    // 弹窗内重新签名继续使用已确认快照，不受随后编辑器变化影响。
    await page.evaluate(value => {
      const editor = document.querySelector("#configOutput");
      editor.value = JSON.stringify(value);
      editor.dispatchEvent(new Event("input", { bubbles: true }));
    }, original);
    const previousUrl = await page.locator("#subscriptionUrl").inputValue();
    await page.selectOption("#subscriptionExpiry", "7");
    await page.waitForFunction(previous => document.querySelector("#subscriptionUrl").value.includes("/subscription?") && document.querySelector("#subscriptionUrl").value !== previous, previousUrl);
    assert.deepEqual(await (await fetch(await page.locator("#subscriptionUrl").inputValue())).json(), manual);
    await page.click("#closeSubscription");

    // 手写 JSON 的引用错误须按编辑器内容检查，而不是沿用表单的旧检查结果。
    const invalid = structuredClone(original);
    invalid.route.default_http_client = "missing-client";
    await page.fill("#configOutput", JSON.stringify(invalid));
    await page.click("#generateBtn");
    assert.equal(await page.locator("#subscriptionModal").evaluate(el => el.open), false);
    assert.match(await page.locator("#conflictList").innerText(), /HTTP Client 不存在/);

    // 完整 JSON 中的错误形状要给出检查提示，不能让编辑器事件抛出异常。
    for (const malformed of [
      { ...original, inbounds: [null] },
      { ...original, outbounds: [{ type: "selector", tag: "proxy", outbounds: {} }, { type: "direct", tag: "direct" }] }
    ]) {
      await page.fill("#configOutput", JSON.stringify(malformed));
      await page.click("#generateBtn");
      assert.equal(await page.locator("#subscriptionModal").evaluate(el => el.open), false);
      assert.match(await page.locator("#validationBar span").first().innerText(), /配置对象|配置结构无效/);
    }

    // 纯直连无需普通代理节点，也可以生成订阅。
    await importJson(minimal);
    assert.equal((await stored()).nodes.length, 0);
    assert.equal(await page.locator("#conflictTitle").innerText(), "冲突检查通过");
    assert.deepEqual(await generate(), await config());
    await page.click("#closeSubscription");

    // 原始 JSON 只包含端点、没有 outbounds 时同样是有效配置。
    const endpointOnly = {
      ...structuredClone(minimal),
      endpoints: [{ type: "wireguard", tag: "wg-test", address: ["10.7.0.2/32"], private_key: "QEkbUOD7+9ROtG4HRvsWG8ddIp8tQZg8nVq6UBLdk1o=", peers: [{ address: "127.0.0.1", port: 51820, public_key: "sLupvbHfve+mEfOCiTG7CXp3xvV52YRDZZsj1RLA/SU=", allowed_ips: ["0.0.0.0/0"] }] }],
      route: { ...minimal.route, final: "wg-test" }
    };
    delete endpointOnly.outbounds;
    await page.fill("#configOutput", JSON.stringify(endpointOnly));
    assert.deepEqual(await generate(), endpointOnly);
    await page.waitForFunction(() => document.querySelector("#shortSubscriptionUrl").value.includes("/s/"));
    assert.deepEqual(await (await fetch(await page.locator("#shortSubscriptionUrl").inputValue())).json(), endpointOnly);
    await page.click("#closeSubscription");

    // 导入、表单设置、刷新后，客户端定义和解析器对象仍完整保留。
    const resolver = { server: "local", strategy: "ipv4_only", disable_cache: true, rewrite_ttl: 0 };
    const advanced = {
      ...structuredClone(referenced),
      experimental: { cache_file: { enabled: true } },
      http_clients: [{ tag: "rules-client", detour: "proxy", domain_resolver: "local", headers: { "X-Test": "keep" } }],
      route: { ...referenced.route, default_domain_resolver: resolver, default_http_client: "rules-client", rule_set: [{ type: "remote", tag: "set", format: "source", url: "https://example.com/rules.json", http_client: "rules-client" }] }
    };
    await importJson(advanced);
    await page.selectOption("#logLevel", "debug");
    await page.reload({ waitUntil: "networkidle" });
    assert.deepEqual((await config()).http_clients, advanced.http_clients);
    assert.deepEqual((await config()).route.default_domain_resolver, resolver);
    assert.equal((await config()).route.default_http_client, "rules-client");
    assert.equal(await page.locator("#routeDefaultHttpClient").inputValue(), "rules-client");
    assert.match(await page.locator("#dnsResolverDetails").innerText(), /ipv4_only/);
    assert.deepEqual(JSON.parse(await page.locator("#httpClientsJson").inputValue()), advanced.http_clients);
    await page.locator("#dnsDefaultResolver").scrollIntoViewIfNeeded();
    await page.evaluate(() => window.scrollBy({ top: -120, behavior: "instant" }));
    await page.screenshot({ path: resolve("output/playwright/logic-resolver-desktop.png") });
    await page.locator("#services details.advanced-fields summary").click();
    await page.locator("#httpClientsJson").scrollIntoViewIfNeeded();
    await page.evaluate(() => window.scrollBy({ top: -120, behavior: "instant" }));
    await page.screenshot({ path: resolve("output/playwright/logic-http-clients-desktop.png") });
    await page.setViewportSize({ width: 390, height: 844 });
    await page.waitForFunction(() => document.querySelector(".sidebar").getBoundingClientRect().right <= 1);
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true, "新增 JSON 字段不能造成移动端横向溢出");
    await page.locator("#services details.advanced-fields").scrollIntoViewIfNeeded();
    await page.evaluate(() => window.scrollBy({ top: -96, behavior: "instant" }));
    await page.locator("#services details.advanced-fields").screenshot({ path: resolve("output/playwright/logic-http-clients-mobile.png") });
    await page.setViewportSize({ width: 1440, height: 1000 });

    // 改名与引用迁移一次提交；持久化失败不能只改掉其中一半。
    const beforeRename = await stored();
    const beforeRenameConfig = await config();
    await page.click("#nodeList .edit-node");
    await page.fill('#nodeFields [data-field="tag"]', "renamed-node");
    await page.evaluate(key => {
      window.originalSetItem = Storage.prototype.setItem;
      Storage.prototype.setItem = function (name, value) {
        if (name === key) throw new DOMException("test quota", "QuotaExceededError");
        return window.originalSetItem.call(this, name, value);
      };
    }, key);
    await page.click("#nodeForm .primary-button");
    assert.match(await page.locator("#nodeFormError").innerText(), /当前配置未覆盖/);
    assert.deepEqual(await stored(), beforeRename);
    assert.deepEqual(await config(), beforeRenameConfig);
    await page.evaluate(() => { Storage.prototype.setItem = window.originalSetItem; });
    await page.click("#nodeForm .primary-button");
    await page.waitForFunction(() => !document.querySelector("#nodeModal").open);
    let changed = await config();
    assert.equal(changed.route.rules[0].outbound, "renamed-node");
    assert.deepEqual(changed.outbounds.find(item => item.tag === "proxy").outbounds, ["renamed-node"]);
    assert.equal(changed.outbounds.find(item => item.tag === "proxy").default, "renamed-node");
    assert.equal(changed.outbounds.find(item => item.tag === "renamed-node").server, remote.server);
    assert.equal(await page.locator("#conflictTitle").innerText(), "冲突检查通过");

    await page.click("#groupList .sortable-item");
    await page.fill('#groupFields [data-field="tag"]', "new-proxy");
    await page.click("#groupForm .primary-button");
    await page.waitForFunction(() => !document.querySelector("#groupModal").open);
    changed = await config();
    assert.equal(changed.route.final, "new-proxy");
    assert.equal(changed.http_clients[0].detour, "new-proxy");
    await page.reload({ waitUntil: "networkidle" });
    assert.deepEqual(await config(), changed);

    // 去重移除的是被引用的副本时，应把引用迁移到保留项，再应用批量改名。
    const duplicate = { ...remote, tag: "node-copy" };
    const tidy = { ...structuredClone(referenced), outbounds: [{ type: "selector", tag: "proxy", outbounds: ["node-copy"], default: "node-copy" }, remote, duplicate, ...minimal.outbounds] };
    tidy.route.rules[0].outbound = "node-copy";
    await importJson(tidy);
    await page.click("#tidyNodesBtn");
    await page.fill("#tidyPrefix", "T-");
    await page.click("#tidyForm .primary-button");
    await page.waitForFunction(() => !document.querySelector("#tidyModal").open);
    assert.equal((await stored()).nodes.length, 1);
    changed = await config();
    assert.equal(changed.route.rules[0].outbound, "T-node-a");
    assert.deepEqual(changed.outbounds.find(item => item.tag === "proxy").outbounds, ["T-node-a"]);
    assert.equal(changed.outbounds.find(item => item.tag === "proxy").default, "T-node-a");
    assert.equal(await page.locator("#conflictTitle").innerText(), "冲突检查通过");

    // 故意让传输层忽略 AbortSignal，确保迟到响应仍由版本/身份校验拦截。
    let held = false, arrived, release;
    let barrier;
    await page.route("**/api/fetch-subscription", async route => {
      if (held) { arrived(); await barrier; }
      await route.fulfill({ json: { content: JSON.stringify({ outbounds: [remote] }) } }).catch(() => {});
    });
    const addSubscription = async () => {
      await page.click("#addSubscriptionBtn");
      await page.fill("#remoteSubscriptionUrl", "https://remote.example.com/feed");
      await page.click("#fetchSubscriptionBtn");
      await page.waitForFunction(() => !document.querySelector("#remoteSubscriptionModal").open);
    };
    const ignoreAbort = () => page.evaluate(() => {
      const originalFetch = window.fetch.bind(window);
      window.completedRemoteBodies = 0;
      window.fetch = async (url, options) => {
        if (!String(url).includes("/api/fetch-subscription")) return originalFetch(url, options);
        const response = await originalFetch(url, { ...options, signal: undefined });
        const json = response.json.bind(response);
        response.json = async () => {
          try { return await json(); }
          finally { window.completedRemoteBodies += 1; }
        };
        return response;
      };
    });
    for (const action of ["delete", "import"]) {
      held = false;
      await importJson(minimal);
      await page.reload({ waitUntil: "networkidle" });
      await addSubscription();
      await ignoreAbort();
      held = true;
      barrier = new Promise(resolve => { release = resolve; });
      const requested = new Promise(resolve => { arrived = resolve; });
      await page.click(".refresh-subscription");
      await requested;
      if (action === "delete") await page.click(".delete-subscription");
      else await importJson(minimal);
      const expected = await stored();
      assert.equal(expected.subscriptions.length, 0);
      assert.equal(expected.nodes.length, 0);
      release();
      await page.waitForFunction(() => window.completedRemoteBodies === 1);
      await page.evaluate(() => new Promise(resolve => setTimeout(resolve, 0)));
      assert.deepEqual(await stored(), expected, action + " 后迟到结果不能改写新状态");
      await page.reload({ waitUntil: "networkidle" });
      assert.deepEqual(await stored(), expected);
    }
    assert.deepEqual(errors, []);
    console.log("basic logic browser tests passed: editor snapshot, direct/endpoint-only, import preservation, atomic rename, dedupe references and stale refresh");
  } finally { await page.close(); }
}
