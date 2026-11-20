import { CHINA_RULE_SETS } from "./china-routing.js";
import { domainResolverServer } from "./dns.js";

// 生成订阅链接时，把大陆规则集换成订阅服务器上的镜像并直连下载：
// 客户端刚从这台服务器取到配置，必然连得上，首次启动就不再依赖任何代理节点。
// 只在服务器 /api/status 报告文件已就绪时替换；预览和下载的 JSON 保持可移植的 GitHub 地址。
export function hostRuleSetsOnServer(config, base, status) {
  const available = status?.ruleSets || {};
  const resolver = config?.route?.default_domain_resolver;
  const ruleSets = config?.route?.rule_set;
  if (!Array.isArray(ruleSets) || !domainResolverServer(resolver)) return { config, hosted: [] };
  const hosted = [];
  const next = ruleSets.map((set) => {
    const preset = CHINA_RULE_SETS.find((item) => item.url === set?.url);
    if (!preset || set.type !== "remote" || available[preset.tag] !== true) return set;
    hosted.push(preset.tag);
    const { http_client: _ignored, ...rest } = set;
    // 非空且不带 detour 的 http_client 才是直连；空对象会走默认出站（即代理）
    return { ...rest, url: new URL(`rule-sets/${preset.tag}.srs`, base).href, http_client: { domain_resolver: structuredClone(resolver) } };
  });
  if (!hosted.length) return { config, hosted };
  return { config: { ...config, route: { ...config.route, rule_set: next } }, hosted };
}
