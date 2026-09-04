# sing-box 配置订阅生成器

一个本地优先的 sing-box 1.14.0 配置与订阅链接生成页面。界面沿用官方 sing-box for Desktop 的浅色视觉语言，所有配置能力按官方模块拆分，生成的配置只使用 1.14.0 的现代写法。

后续规划与验收标准见 [ROADMAP.md](./ROADMAP.md)。

## 运行

需要 Node.js 20 或更高版本，运行本身不需要第三方依赖。

```bash
npm start
```

打开 `http://127.0.0.1:4173`。

## 功能

### 出站与节点

- 17 种出站类型：Direct、Bridge、SOCKS、HTTP、Shadowsocks、VMess、VLESS、Trojan、Naive、Hysteria、Hysteria 2、ShadowTLS、TUIC、AnyTLS、Snell、Tor、SSH
- 完整 TLS 客户端：uTLS 指纹、ECH、REALITY、TLS 分片与记录分片、ALPN、版本范围、自定义 CA
- V2Ray 传输层、Multiplex、TCP Brutal、UDP over TCP 与全部非弃用 Dial Fields
- Selector / URLTest 出站组，成员可自动包含全部节点或手动指定，支持默认成员与测试参数
- detour 与出站组环路检测
- 批量解析分享链接、导出分享链接、节点去重 / 过滤 / 批量重命名
- 远程节点订阅：支持 sing-box JSON 与明文/Base64 链接列表，显示更新时间、失败原因与增删差异

### 入站

- 19 种入站类型：Mixed、SOCKS、HTTP、Direct、TUN、Redirect、TProxy、Shadowsocks、VMess、VLESS、Trojan、Naive、Hysteria、Hysteria 2、ShadowTLS、TUIC、AnyTLS、Snell、Cloudflared
- TLS 服务端、按协议校验的用户列表、Multiplex、TCP Brutal、V2Ray 传输层、UDP NAT
- TUN 完整平台字段：`dns_mode`(1.14)、auto_route / auto_redirect、路由范围、UID / 包名 / MAC / 接口过滤、iproute2、platform

### 端点

- WireGuard、Tailscale、OpenConnect Client、OpenVPN Client、OpenVPN Server
- Tailscale MagicDNS、SSH、Taildrop、出口节点与系统接口，自动生成对应 DNS Server 与 `preferred_by` 规则

### DNS

- 15 种 DNS Server：Local、Hosts、TCP、UDP、DoT、DoQ、DoH、DoH3、DHCP、mDNS、FakeIP、Tailscale、OpenConnect、OpenVPN、systemd-resolved
- DNS 规则编辑器：域名、查询、来源、进程、网络环境、规则集与响应匹配条件，支持逻辑规则与取反
- 1.14 新增能力：`evaluate`、`respond`、`race`、`speculative`、乐观缓存、查询超时、`preferred_by`

### 路由与规则集

- 路由全局字段、`route` / `bypass` / `reject` / `hijack-dns` / `route-options` / `sniff` / `resolve` 动作
- 规则集支持 Inline、本地文件与远程下载，source JSON 与 binary SRS 双格式，含 1.14 的 `http_client`、`initial_path` 与多标签 `{tag}` 占位符
- Inline 规则集提供逐字段的 Headless 规则编辑器

### 服务与实验性

- NTP、全局证书存储、Cache File、Clash API、V2Ray API
- 9 种 Service：sing-box API、DERP、Resolved、SSM API、CCM、OCM、Hysteria Realm、USB/IP Server、USB/IP Client

### 生成、导入与校验

- 实时 JSON 预览、格式化、复制、下载
- 生成可直接返回 JSON 的 `/subscription` 链接与官方 `sing-box://import-remote-profile` 导入链接
- 导入完整 sing-box JSON 配置并反序列化为表单状态，界面未建模的字段保留在「附加参数」中，往返无损
- 导入时识别弃用字段并给出迁移说明
- 备份 / 恢复全部配置状态，破坏性操作前自动留一份快照
- 可调用本机 sing-box 执行正式 `check`（配置预览工具栏的盾牌按钮）

## 冲突检查

配置预览上方会列出跨模块冲突，**错误级别的冲突必须修正后才能生成订阅链接与客户端导入链接**：

- 标签重复：入站、出站与端点、DNS Server、规则集
- 监听冲突：同端口入站、与 Clash API 控制端口冲突
- TUN：多个 TUN 入站、`auto_redirect` 缺少 `auto_route`、启用 TUN 却没有自动检测接口或固定默认接口造成的路由环路
- FakeIP 被用作默认域名解析器
- detour 与出站组环路
- 路由与 DNS 规则引用了不存在的入站、出站、DNS Server 或规则集，出站组成员不存在
- Clash API / sing-box API 监听非本机地址却没有设置 secret

提醒级别（不阻止生成）包括：缺少 hijack-dns 规则、FakeIP 没有被任何规则使用、远程规则集未启用缓存、因出站缺失被跳过的规则等。

## 部署

订阅链接是无状态的，配置以 Base64URL 编码放在 URL 中。部署到公网时：

```bash
# 必须设置 token；限流默认每分钟 60 次
SUBSCRIPTION_TOKEN=$(openssl rand -hex 24) \
HOST=127.0.0.1 PORT=4173 \
RATE_LIMIT_WINDOW_MS=60000 RATE_LIMIT_MAX=60 \
npm start
```

反向代理示例（Caddy）：

```caddyfile
sub.example.com {
    reverse_proxy 127.0.0.1:4173
}
```

Nginx：

```nginx
location / {
    proxy_pass http://127.0.0.1:4173;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
}
```

### 生产安全清单

1. 只监听 `127.0.0.1`，由反向代理提供 HTTPS。
2. 设置 `SUBSCRIPTION_TOKEN`，并在生成订阅时填写同样的 token。
3. 为链接设置有效期（生成弹窗里的「有效期」），过期后端点返回 410。
4. 保留默认限流，或按需调整 `RATE_LIMIT_WINDOW_MS` / `RATE_LIMIT_MAX`。
5. 订阅 URL 与备份文件都包含节点凭据，按密码保管，不要放进版本库或聊天记录。
6. `/api/fetch-subscription` 拒绝读取本机与局域网地址，`/api/check` 只在设置了可用的 `SING_BOX_BIN` 时工作。

### 环境变量

| 变量 | 说明 |
| --- | --- |
| `HOST` / `PORT` | 监听地址与端口，默认 `127.0.0.1:4173` |
| `SUBSCRIPTION_TOKEN` | 设置后 `/subscription` 必须带 `token` 参数 |
| `RATE_LIMIT_WINDOW_MS` / `RATE_LIMIT_MAX` | 限流窗口与上限，默认 60 秒 60 次 |
| `SING_BOX_BIN` | 本机 sing-box 可执行文件路径，用于 `/api/check` |

## 1.14.0 兼容性

生成器只输出 1.14.0 的现代写法，以下内容不会出现在结果里：

- 旧 DNS 特殊出站、旧版 DNS Server 格式（`address` / `address_resolver` / `address_strategy`）与 `dns.fakeip` 旧块
- GeoIP / Geosite、`rule_set_ipcidr_match_source`、`rule_set_ip_cidr_accept_empty`
- DNS 规则的直接地址过滤（`ip_cidr` / `ip_is_private` / `ip_accept_any` 未配 `match_response`）、规则动作 `strategy`、已移除的 DNS 规则 `outbound` 项
- 入站的 `sniff`、`sniff_override_destination`、`sniff_timeout`、`domain_strategy`、`udp_disable_domain_unmapping`、`proxy_protocol`
- TUN 的 `inet4_address` 等已合并字段、`gso`、`endpoint_independent_nat`
- WireGuard outbound、OpenVPN `static_key` 模式、`independent_cache`、`store_rdrc`、`download_detour`、旧 Hysteria 调优字段
- 已在 1.14 移除的 Dial Field `domain_strategy`

各模块的「附加参数」会按类型校验字段名：不属于该类型的 1.14 字段、以及上面这些弃用字段都会被拒绝。

## 项目结构

```
modules/
  registry.js    配置模块注册器
  shared.js      Dial / Listen / UDP NAT 等共享字段与工具
  outbound.js    出站与出站组
  inbound.js     入站
  endpoints.js   WireGuard / OpenConnect / OpenVPN 端点
  tailscale.js   Tailscale 端点与 MagicDNS 联动
  dns.js         DNS Server、规则与全局选项
  route.js       路由规则、规则集与全局字段
  services.js    NTP、证书、Experimental 与 Service
  conflicts.js   跨模块冲突检查
  importer.js    完整配置反序列化
  sharelink.js   分享链接导出与节点整理
```

浏览器里保存的旧配置会自动迁移：入口模式、TUN 地址、Mixed 端口转成入站；DoH 服务器与 DNS 策略转成 DNS Server 与全局选项；「局域网直连」「Clash API 控制」「自动选择低延迟节点」转成路由规则、服务设置与出站组。

## 检查

```bash
npm run check      # 语法检查 + 模块单元测试 + 浏览器流程测试
npm run test:browser
```

浏览器流程测试需要 `playwright-core` 与本机 Chrome/Chromium（可用 `CHROME_PATH` 指定），缺少时会自动跳过。

上线前建议再用目标平台的正式内核复核一次：

```bash
sing-box check -c config.json
```
