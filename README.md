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
- REALITY 对 TCP 类 TLS 协议开放（VLESS / VMess / Trojan / AnyTLS / HTTP，出站与入站两侧），QUIC 类协议（Hysteria / Hysteria 2 / TUIC）会被明确拒绝——内核的 REALITY 客户端无法提供 QUIC 所需的标准 TLS 配置
- V2Ray 传输层、Multiplex、TCP Brutal、UDP over TCP 与全部非弃用 Dial Fields
- Selector / URLTest 出站组，成员可自动包含全部节点或手动指定，支持默认成员与测试参数
- 路由默认出站选择「自动」时，优先使用第一个启用且有成员的 Selector（默认档案为 `proxy`），以便客户端手动切换节点；没有可用 Selector 时依次回退到 URLTest、节点和 direct。明确指定的默认出站保持优先
- detour 与出站组环路检测
- 批量解析分享链接、导出分享链接、节点去重 / 过滤 / 批量重命名
- 远程节点订阅：支持 sing-box JSON 与明文/Base64 链接列表，显示更新时间、失败原因与增删差异；JSON 节点与完整导入共用反序列化器，保留 TLS、传输、多路复用及拨号字段

### 入站

- 19 种入站类型：Mixed、SOCKS、HTTP、Direct、TUN、Redirect、TProxy、Shadowsocks、VMess、VLESS、Trojan、Naive、Hysteria、Hysteria 2、ShadowTLS、TUIC、AnyTLS、Snell、Cloudflared
- TLS 服务端（含 REALITY 服务端：握手目标、私钥、Short ID）、按协议校验的用户列表、Multiplex、TCP Brutal、V2Ray 传输层、UDP NAT
- TUN 完整平台字段：`dns_mode`(1.14)、auto_route / auto_redirect、路由范围、UID / 包名 / MAC / 接口过滤、iproute2、platform

### 端点

- WireGuard、Tailscale、OpenConnect Client、OpenVPN Client、OpenVPN Server
- Tailscale MagicDNS、SSH、Taildrop、出口节点与系统接口，自动生成对应 DNS Server 与 `preferred_by` 规则

### DNS

- 15 种 DNS Server：Local、Hosts、TCP、UDP、DoT、DoQ、DoH、DoH3、DHCP、mDNS、FakeIP、Tailscale、OpenConnect、OpenVPN、systemd-resolved
- DNS 规则编辑器：域名、查询、来源、进程、网络环境、规则集与响应匹配条件，支持逻辑规则与取反
- 1.14 新增能力：`evaluate`、`respond`、`race`、`speculative`、乐观缓存、查询超时、`preferred_by`
- 在添加／编辑 FakeIP 的窗口内一键补齐配套配置，先预览再保存；删除时可选择是否清理关联设置

#### FakeIP 一键配置

在 DNS 面板添加 FakeIP，或编辑已有 FakeIP Server，填写标签和地址池后点击「一键配置 FakeIP」。同一窗口会列出变更、使用的地址族、目标 TUN 和需要修正的问题；有多个启用的 TUN 时先选择目标。点击「保存并应用」才会一起保存，取消、关闭和 Esc 都会放弃预览。直接点击「保存 Server」只保存服务器；已关联的服务器改名时还会更新未被手动修改的预设引用。

预设保留节点、出站组、分流和已有 DNS 规则的优先级，补充 `localhost`、`.lan`、`.local`、`.home.arpa` 的真实 DNS 例外，再把支持的 A / AAAA 查询交给 FakeIP。其他查询使用真实默认 DNS，缺少默认 DNS 或节点解析器时使用直连 Local DNS。Tailscale 的 MagicDNS 仍优先匹配。预设根据 DNS 策略、TUN 地址族和地址池决定 A / AAAA；IPv4 和 IPv6 地址池可以只填其中一个。

预设复用启用的 TUN，或按项目默认双栈地址与 `mixed` 栈补建，开启自动路由、DNS 接管及映射缓存，并保留缓存路径和固定出口接口。地址池重叠、TUN 路由排除范围、无共同地址族、缺失引用及完全遮挡 FakeIP 的前置终止规则会阻止应用。复杂 DNS 条件和外部路由规则集会提示需要核对。

再次点击一键配置可补齐被删除的项目，不重复添加，也不覆盖手动修改。删除已关联的 FakeIP 时，可以预览并选择「删除并清理关联配置」「仅删除 FakeIP」或「取消」。清理只删除仍保持预设原样且无其他引用的新增项目，并还原仍等于预设应用值的字段；手动修改、原有项目和仍被其他预设使用的资源会保留。最后一份关联解除时才考虑清理共享资源；选择「仅删除」保留的共享资源也不会随后被另一份预设清掉。残留引用会显示在冲突检查中，修正前不能生成订阅。

关联历史按服务器 ID 保存在本地 `dns.fakeipPresets`（版本 1）中，包含字段原值、应用值和共享关系，只随本工具备份保存，不进入 sing-box JSON。复制服务器不继承清理权限；普通 sing-box JSON 导入没有关联历史，不会根据标签推断归属。应用和删除前都会保存旧状态快照，存储失败时不覆盖当前配置；可在「备份」中载入自动备份后恢复。显式空列表在刷新、撤销和备份恢复后继续保持为空。

sing-box 1.14 同一配置只支持一个启用的 FakeIP Server，因此多个同时启用会被冲突检查拦截。可以保留停用服务器的预设记录，切换使用时需同步调整对应 DNS 规则。

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
- 同时生成长链接和 `/s/…` 短链接，各自可复制；二维码、预览和客户端导入优先使用短链接，创建失败时保留长链接并提供重试
- 订阅二维码：移动端 sing-box 客户端「扫码添加」可直接识别；内置 QR 编码器（Byte 模式、版本 1–40、纠错 L/M），不依赖第三方库。链接经 deflate 压缩后通常缩到原来的 1/2–1/4，典型档案可放进二维码；超出 2953 字节容量时给出提示
- 导入完整 sing-box JSON 配置并反序列化为表单状态，界面未建模的字段保留在「附加参数」中，往返无损
- 名为 `direct` 且包含自定义拨号设置的出站会保留，生成时不再追加同名默认对象
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

长链接先用 deflate 压缩配置，再以 Base64URL 编码放在 URL 中（`data=…&enc=deflate`）；也支持带签名的未压缩链接。浏览器将配置载荷、名称、编码及更新间隔的 SHA-256 摘要发送给 `/api/sign-subscription`，由服务器把摘要和有效期一起签名；签名接口不接收配置或节点凭据。`/subscription` 验证签名与有效期后解码返回，长链接本身不需要保存配置。

随后浏览器自动将已签名配置提交给当前订阅服务器的 `/api/short-subscription`，保存后生成 `/s/…` 短链接。**短链接会在你的服务器保存完整配置（含节点凭据）**，不使用第三方短链服务。短链接直接返回 JSON，沿用有效期、token、签名校验、限流和下载行为，不重定向到长 URL。每份配置与有效期独立保存，修改后生成新链接；原链接继续指向原配置。重复提交同一签名复用记录。

记录保存在 `STATE_DIRECTORY/short-subscriptions/`（默认 `.data/short-subscriptions/`，文件权限 `0600`），服务重启后仍可使用。容器部署必须持久化此目录及签名密钥；多实例需要共享记录目录和密钥。浏览器的配置备份不包含这些服务端记录。默认最多保存 1000 条记录，空间不足时先清理过期项；已清理的短链接返回 404，尚未清理的过期链接返回 410。可调整 `SHORT_LINK_MAX_ENTRIES` 或在停服后删除不再需要的记录文件，删除后对应短链接失效。服务版本过旧、写入失败或容量已满时，弹窗仍提供长链接和短链接重试入口。

**升级后旧的无签名链接需要重新生成一次**。删除、修改或重复签名覆盖的参数会返回 401；合法签名过期后返回 410。无签名链接不提供兼容回退，避免通过删除有效期绕过校验。生成页面支持 HTTPS、localhost 和普通 HTTP（包括局域网 IP），目标服务必须升级到支持签名的版本。浏览器没有 Web Crypto 时使用本地 SHA-256 兼容实现。HTTP 部署时「公开访问地址」填写完整的 `http://主机:端口/`；公网传输节点凭据仍建议使用 HTTPS。

部署时需要了解：

- **链接本身就是密钥**：拿到链接就能读到其中的节点凭据，请像密码一样分发。
- **`SUBSCRIPTION_TOKEN` 是可选的，保护的是服务器而不是订阅内容**。设置后签名接口和所有订阅链接都必须带同一个 token，适合私有部署；公开生成服务不设置它。
- 有效期约束现有链接在该服务上的访问，不会撤销已经取得的节点凭据或配置副本。公开签名服务允许任何人重新签发自己的配置；需要限制签发时使用私有部署。
- 默认签名密钥保存在 `.data/subscription-signing-key`（文件权限 `0600`），重启后复用。容器部署需持久化该目录，或通过 `SUBSCRIPTION_SIGNING_KEY` 配置固定密钥；多实例必须共用同一密钥。删除或轮换密钥会使原有链接失效。
- 对公开服务真正有效的保护是默认开启的限流与 512 KB 大小上限，以及端点只接受含 `inbounds` / `outbounds` 的 sing-box 配置。

```bash
# 公开服务：不设 token，保留默认限流
HOST=127.0.0.1 PORT=4173 npm start

# 私有部署：额外加上 token，生成链接时在弹窗里填同一个值
SUBSCRIPTION_TOKEN=$(openssl rand -hex 24) HOST=127.0.0.1 PORT=4173 npm start
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
2. 私有部署时设置 `SUBSCRIPTION_TOKEN`，并在生成订阅时填写同样的 token；公开服务不设置。
3. 为链接设置有效期（生成弹窗里的「有效期」），过期后端点返回 410。
4. 保留默认限流，或按需调整 `RATE_LIMIT_WINDOW_MS` / `RATE_LIMIT_MAX`。
5. 订阅 URL 与备份文件都包含节点凭据，按密码保管，不要放进版本库或聊天记录。
6. `/api/fetch-subscription` 拒绝读取本机、局域网和保留地址；连接锁定已审核的 DNS 结果，每次重定向重新审核，并限制解压后内容大小与总耗时。若订阅域名解析到 `198.18.0.0/15` FakeIP 地址，需要先为该域名添加真实 DNS 解析例外。
7. 静态服务只发布页面、样式及浏览器模块，拒绝仓库元数据、后台源码、测试、备份、输出目录和符号链接；`/api/check` 需要本机可用的 sing-box，可用 `SING_BOX_BIN` 指定。

### 环境变量

| 变量 | 说明 |
| --- | --- |
| `HOST` / `PORT` | 监听地址与端口，默认 `127.0.0.1:4173` |
| `SUBSCRIPTION_TOKEN` | 可选。设置后签名接口和 `/subscription` 必须带相同 token，仅适合私有部署 |
| `STATE_DIRECTORY` | 服务端签名密钥和短链接记录目录，默认项目下的 `.data`；容器部署需持久化 |
| `SUBSCRIPTION_SIGNING_KEY` | 可选固定签名密钥，至少 32 字节，建议随机生成；设置后不使用目录中的密钥 |
| `SHORT_LINK_MAX_ENTRIES` | 短链接最多保存的记录数，默认 1000；容量不足时先清理过期记录 |
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
  fakeip.js      FakeIP 候选预设、关联历史与保守清理
  route.js       路由规则、规则集与全局字段
  services.js    NTP、证书、Experimental 与 Service
  conflicts.js   跨模块冲突检查
  importer.js    完整配置反序列化
  sharelink.js   分享链接导出与节点整理
  qrcode.js      自包含 QR Code 编码器
```

浏览器里保存的旧配置会自动迁移：入口模式、TUN 地址、Mixed 端口转成入站；DoH 服务器与 DNS 策略转成 DNS Server 与全局选项；「局域网直连」「Clash API 控制」「自动选择低延迟节点」转成路由规则、服务设置与出站组。

## 检查

```bash
npm run check      # 语法检查 + 模块单元测试 + 浏览器流程测试
npm run test:browser
npm run test:security # 静态隔离、异常请求、DNS 锁定、订阅签名与重启
npm run test:fakeip # 预设、清理、共享资源与配置边界测试
SING_BOX_BIN=/path/to/sing-box npm run test:fakeip:kernel
```

浏览器流程测试需要 `playwright-core` 与本机 Chrome/Chromium（可用 `CHROME_PATH` 指定），缺少时会自动跳过。

回归测试覆盖导入前快照、两个存储步骤失败时保留配置、空列表刷新、定制 `direct`、远程节点高级字段的添加与刷新，以及签名生成、有效期切换、异步响应顺序和错误提示。服务端测试覆盖参数篡改／删除／重复、精确过期边界、私有 token、密钥重启复用、非法 Host、静态路径穿越与符号链接、混合 DNS 地址、重绑定、重定向、解压大小限制和超时。

短链接测试覆盖长短配置一致、重启持久化、私有 token、过期、参数覆盖拦截、重复与并发创建、容量和过期清理、磁盘写入失败，以及浏览器同时生成、失败回退、重试、二维码切换、HTTP 复制、移动端布局和迟到响应。

FakeIP 浏览器测试覆盖弹窗入口、普通保存、保存并应用、取消／关闭／Esc、重复应用、改名／复制、两种删除、清理预览、存储失败、刷新、空列表、多 TUN 和备份恢复。截图保存在 `output/playwright/`。内核测试要求 sing-box 1.14，检查双栈、IPv4、IPv6、已有真实 DNS、MagicDNS，以及浏览器测试输出的默认示例；配置和结果写入 `output/fakeip-kernel/`。该测试只执行 `check`，不创建 TUN；真实 DNS 回答、域名分流及重启后的映射持久化需在有 TUN 权限的目标环境另行验证。

上线前建议再用目标平台的正式内核复核一次：

```bash
sing-box check -c config.json
```
