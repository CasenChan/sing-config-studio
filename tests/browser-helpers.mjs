export const STORAGE_KEY = "sing-config-studio:v1";
export const UI_MODE_KEY = "sing-config-studio:ui-mode";

// 现有流程测试覆盖全部模块，固定在高级模式下运行；简洁模式由 simple-browser.mjs 单独覆盖
export async function pinAdvancedMode(page) {
  await page.addInitScript((key) => {
    if (!localStorage.getItem(key)) localStorage.setItem(key, "advanced");
  }, UI_MODE_KEY);
}

// 示例节点会阻止生成订阅：流程测试改用不带示例标记的节点（类型、标签与顺序不变）
export async function replaceDemoNodes(page) {
  await page.evaluate((key) => {
    const saved = JSON.parse(localStorage.getItem(key));
    saved.nodes = saved.nodes.map((node, index) => ({
      ...node,
      server: String(node.server || "").replace(/\.example\.com$/, ".example.net"),
      ...(node.password === "REPLACE_WITH_PASSWORD" ? { password: `test-password-${index + 1}` } : {})
    }));
    localStorage.setItem(key, JSON.stringify(saved));
  }, STORAGE_KEY);
  await page.reload({ waitUntil: "networkidle" });
}
