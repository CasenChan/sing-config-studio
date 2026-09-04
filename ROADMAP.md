# sing-box 1.14.0 配置生成器路线图

本文记录当前完成情况、后续开发顺序和每个阶段的验收标准。目标是逐步覆盖 sing-box 1.14.0 的现代配置模块，同时保持现有官方客户端风格，并避免生成已经弃用、即将移除或仅用于旧版迁移的配置。

## 状态说明

- `[x]` 已完成并经过基础验证
- `[ ]` 尚未完成
- `[~]` 已有基础实现，但仍需扩展

## 当前基线

- [x] 官方客户端风格的桌面与移动端响应式布局
- [x] 本地配置状态保存、实时 JSON 预览、复制和下载
- [x] 无状态订阅 URL 与官方客户端导入链接
- [x] 手动代理节点、分享链接批量导入和远程节点订阅
- [x] 远程订阅的公网访问限制与 `198.18.0.0/15` Fake-IP 代理环境兼容
- [x] 可扩展配置模块注册器
- [x] 顶层 Endpoint：WireGuard、Tailscale、OpenConnect Client、OpenVPN Client、OpenVPN Server
- [x] Tailscale MagicDNS、SSH、Taildrop、出口节点和系统接口
- [x] 非弃用 Dial Fields、Listen Fields 和 sing-box 1.14 UDP NAT Fields 基础组件
- [x] 所有弹窗取消、关闭和 Esc 不触发表单必填验证
- [x] 当前 Endpoint 生成结果通过 sing-box 1.14.0 内核检查
- [x] 独立 DNS 模块：15 种 1.14 Server 类型、规则编辑器与全局选项
- [x] 独立路由模块：全局字段、路由规则编辑器与 Rule Set 管理
- [x] 独立入站模块：19 种 1.14 入站类型与多入站管理
- [x] 独立出站模块：17 种出站类型、Selector / URLTest 出站组与共享客户端对象
- [x] 服务模块：NTP、证书、Cache File、Clash API、V2Ray API 与 9 种 Service
- [x] 完整配置导入与往返、分享链接导出、备份恢复
- [x] 跨模块冲突检查：错误会阻止生成订阅链接
- [x] 通用 Schema 表单渲染器与可排序列表组件，端点、DNS、路由编辑器共用

## 阶段 1：完整 DNS 模块（已完成，待内核复核）

### DNS 全局设置

- [x] DNS 独立管理面板，不再只保留基础配置中的少量快捷选项
- [x] 默认服务器、解析策略、缓存、反向映射和客户端子网设置
- [x] 1.14 新增的 `optimistic` 乐观缓存与全局 `timeout`
- [x] DNS Server 标签管理和跨模块标签冲突检查
- [x] DNS Server 拖动排序、复制、启用和删除
- [x] 旧配置自动迁移：基础配置里的 DoH 快捷项转成 DNS Server

### DNS Server 类型

- [x] Local（含 1.13 `prefer_go` 与 1.14 `neighbor_domain`）
- [x] Hosts
- [x] TCP
- [x] UDP
- [x] TLS
- [x] QUIC
- [x] HTTPS
- [x] HTTP/3
- [x] DHCP
- [x] mDNS（1.14 新增）
- [x] FakeIP
- [x] Tailscale（含 1.14 `accept_search_domain`）
- [x] OpenConnect（1.14 新增）
- [x] OpenVPN（1.14 新增）
- [x] systemd-resolved

不新增旧版 DNS 特殊出站，也不以旧格式生成 DNS Server；`address`、`address_resolver`、`address_strategy` 会被高级参数校验拒绝。

### DNS 规则与动作

- [x] DNS Rule 可视化编辑器，规则可排序、复制、启用和删除
- [x] 域名、后缀、关键字、正则、查询类型、网络、进程和入站等匹配条件
- [x] 1.14 新增匹配项：`preferred_by`、`query_client_subnet`、`query_dnssec`、`source_mac_address`、`source_hostname`、`package_name_regex`
- [x] `route`、`route-options`、`reject`、`predefined` 等当前动作
- [x] 1.14 新增动作与选项：`evaluate`、`respond`、`race`、`speculative`、`disable_optimistic_cache`、`remove_client_subnet`、规则级 `timeout`
- [x] 逻辑规则和规则取反
- [x] Endpoint 专用 DNS 路由联动（Tailscale MagicDNS 自动生成 Server 与 `preferred_by` 规则）
- [~] DNS Rule Set 引用：可引用并校验标签，规则集本体在阶段 2 定义
- [~] FakeIP 地址段、过滤规则和真实解析回退：Server 与地址段已完成，过滤与回退依赖阶段 2 的路由规则

### 验收

- [x] 每类 DNS Server 至少生成一份最小有效配置（`tests/dns.mjs`）
- [x] FakeIP、真实 DNS 和 Endpoint DNS 可组合使用
- [x] 1.14 已弃用写法被拦截：直接地址过滤、`independent_cache`、规则动作 `strategy`、`outbound` 规则项
- [ ] 所有示例通过 sing-box 1.14.0 `check`（本机未安装内核，仍需人工复核）

## 跨模块冲突检查（已完成）

生成配置时会把各模块自身的校验，与只有放在一起才能发现的冲突汇总成一份清单，显示在配置预览上方。
`error` 级别会阻止生成订阅链接与客户端导入链接，`warning` 级别只提示。

- [x] 标签重复：入站、出站与端点、DNS Server、规则集
- [x] 监听冲突：同端口的入站（含 `0.0.0.0` 与具体地址的重叠）、与 Clash API 控制端口冲突
- [x] TUN：多个 TUN 入站、`auto_redirect` 缺少 `auto_route`、与 Redirect/TProxy 重复接管
- [x] 路由环路：启用 TUN 但既没有自动检测接口也没有固定默认接口
- [x] FakeIP：被用作默认域名解析器、被 `dns.final` 引用、定义了却没有规则使用、缺少 sniff 规则
- [x] 引用检查：路由与 DNS 规则引用的入站、出站、DNS Server、规则集
- [x] 出站组：成员或默认成员不存在、成员为空
- [x] 提醒：缺少 hijack-dns 规则、远程规则集未启用缓存、因出站缺失被跳过的规则

## 阶段 2：完整路由与 Rule Set（已完成，待内核复核）

### Route 全局设置

- [x] 默认出站、自动检测接口、固定接口、默认路由标记等全局字段
- [x] 默认域名解析器（由 DNS 模块统一提供，避免两处配置漂移）
- [x] 默认网络策略、网络类型、回退网络类型与回退延迟
- [x] 1.14 新增的 `find_neighbor` 与 `dhcp_lease_files`
- [x] 可视化规则排序（拖拽与上下移动）、复制、启用和删除
- [x] 入站、出站、Endpoint、DNS Server 与规则集之间的引用校验

### Route Rule

- [x] 域名、IP、端口、网络、协议、嗅探客户端、用户、进程、Wi-Fi、接口等匹配条件
- [x] 1.14 新增匹配项：`source_mac_address`、`source_hostname`、`package_name_regex`；1.13 的 `preferred_by` 与 `icmp` 网络
- [x] `route`、`route-options`、`reject`、`hijack-dns`、`sniff`、`resolve` 等当前规则动作
- [x] 1.13 的 `bypass` 动作与 1.14 的 `tls_spoof`、`tls_spoof_method`、`resolve.timeout`、`resolve.disable_optimistic_cache`
- [x] 逻辑规则、取反和多条件组合
- [x] Clash Mode 联动
- [x] 私有地址、局域网和常用直连场景预设（默认档案内置 sniff、hijack-dns、私有地址直连与 Clash 模式规则）

### Rule Set

- [x] Inline Rule Set（1.10+）
- [x] Local Rule Set
- [x] Remote Rule Set
- [x] Source JSON 格式
- [x] Binary SRS 格式
- [x] Headless Rule 编辑器（逐字段表单，可增删多条规则项，支持逻辑子规则）
- [x] AdGuard DNS Filter 规则集：按 binary SRS 引用，界面提示先用 `sing-box rule-set convert --type adguard` 转换
- [x] 更新周期与 1.14 的 `http_client`、`initial_path`、多标签 `{tag}` 占位符
- [x] 规则集依赖与重复标签检查
- [~] 缓存策略：远程规则集缓存依赖 `experimental.cache_file`，随阶段 6 一起提供

不会重新加入 GeoIP、Geosite、已弃用的顶层 `outbound` 规则项、`rule_set_ipcidr_match_source` 或 1.14 弃用的 `download_detour`。

### 验收

- [x] 常用分流场景可完全通过界面完成
- [x] DNS Rule 与 Route Rule 的引用关系正确，缺失出站的规则不会写进配置
- [x] 规则集标签冲突、多标签占位符与 Headless 字段白名单均有校验（`tests/route.mjs`）
- [ ] 本地和远程 Rule Set 均通过 1.14.0 内核检查（本机未安装内核，仍需人工复核）

## 阶段 3：完整 Inbound（已完成，待内核复核）

### Inbound 类型

- [x] Direct
- [x] Mixed
- [x] SOCKS
- [x] HTTP
- [x] Shadowsocks
- [x] VMess
- [x] Trojan
- [x] Naive
- [x] Hysteria
- [x] ShadowTLS
- [x] VLESS
- [x] TUIC
- [x] Hysteria 2
- [x] AnyTLS
- [x] Snell
- [x] TUN（含 1.14 的 `dns_mode`）
- [x] Redirect
- [x] TProxy
- [x] Cloudflared

### 公共能力

- [x] 多 Inbound 管理、排序、复制和启用状态
- [x] 完整非弃用 Listen Fields
- [x] TLS Server、用户列表和认证字段，用户字段按协议校验
- [x] V2Ray Transport、Multiplex、UDP NAT 与 TCP Brutal
- [x] TUN 平台相关字段（UID、包名、MAC、接口过滤、iproute2、platform）与操作系统提示
- [~] 需要系统权限的能力已在界面说明；需要特定构建标签的能力提示待补

### 验收

- [x] 每类 Inbound 都有最小有效配置模板（`tests/inbound.mjs`）
- [x] 必填项和协议条件字段会动态切换，用户列表按协议校验字段名
- [x] 已由规则动作取代的旧入站字段（`sniff`、`sniff_override_destination`、`domain_strategy`、`udp_disable_domain_unmapping`）与 `inet4_address` 等旧字段会被拒绝
- [~] 平台限制以界面说明为准，不会自动隐藏其它平台的字段
- [ ] 每类 Inbound 通过 1.14.0 内核检查（本机未安装内核，仍需人工复核）

## 阶段 4：完整 Outbound 与代理节点（已完成，待内核复核）

### Outbound 类型

- [x] Direct
- [x] Bridge
- [x] SOCKS
- [x] HTTP
- [x] Shadowsocks
- [x] VMess
- [x] Trojan
- [x] Naive
- [x] Hysteria
- [x] ShadowTLS
- [x] VLESS
- [x] TUIC
- [x] Hysteria 2
- [x] AnyTLS
- [x] Snell
- [x] Tor
- [x] SSH
- [x] Selector
- [x] URLTest

Block 与 DNS 出站已在 1.11 弃用、1.13 移除，改用 `reject` 与 `hijack-dns` 规则动作，因此不提供；WireGuard 只使用顶层 Endpoint。

### 公共能力

- [x] 完整非弃用 Dial Fields
- [x] TLS Client、uTLS、ECH 与 REALITY
- [x] V2Ray Transport、Multiplex、UDP over TCP 与 TCP Brutal
- [x] Selector、URLTest 的可视化成员管理（自动包含全部节点或手动指定）
- [x] Detour 链路循环检测（含出站组成环）
- [x] 节点标签自动去重、批量重命名与过滤
- [x] 常见协议的分享链接导入与导出
- [x] sing-box JSON outbound 导入时保留未被界面修改的现代字段

### 验收

- [x] 所有支持的 Outbound 都有独立编辑器（`tests/outbound.mjs`）
- [x] 分享链接导入、手工编辑和 JSON 生成可往返（`tests/sharelink.mjs`、`tests/importer.mjs`）
- [x] 组合后的 Selector、URLTest 与 Detour 引用均有效，无效引用会进入冲突清单
- [ ] 全部出站通过 1.14.0 内核检查（本机未安装内核，界面已提供一键调用）

## 阶段 5：共享配置对象（已完成）

- [x] Dial Fields
- [x] Listen Fields
- [x] TLS Client / Server
- [x] ECH
- [x] uTLS
- [x] REALITY（客户端与服务端，按内核实际支持范围开放给全部 TCP 类 TLS 协议，QUIC 类拒绝）
- [~] ACME 与证书提供器：不生成已弃用的 `acme`，`certificate_provider` 需在附加参数中填写
- [x] HTTP Client（远程规则集内联或引用顶层标签）
- [~] HTTP/2 Fields：随 Hysteria Realm 等对象通过附加参数提供
- [~] QUIC Fields：随协议编辑器的对应字段提供
- [x] Multiplex
- [x] V2Ray Transport
- [x] UDP over TCP
- [x] UDP NAT Fields
- [x] TCP Brutal
- [x] Wi-Fi State（路由与 DNS 规则的 SSID / BSSID 匹配）
- [x] Neighbor Resolution（`find_neighbor`、`dhcp_lease_files`、MAC 与主机名匹配）
- [x] Network Namespace（各模块的 `netns` 字段）

共享对象由统一组件渲染、统一构建器输出：`modules/shared.js` 提供 Dial / Listen / UDP NAT，其余共享块由各模块复用同一套 Schema 表单渲染器。

## 阶段 6：NTP、证书、Experimental 与 Service（已完成，待内核复核）

### 基础服务

- [x] NTP
- [x] 全局证书配置
- [x] Cache File
- [x] Clash API
- [x] V2Ray API

### Service

- [x] sing-box API
- [x] DERP
- [x] Resolved
- [x] SSM API
- [x] CCM
- [x] OCM
- [x] Hysteria Realm
- [x] USB/IP Server
- [x] USB/IP Client
- [~] 需要特殊构建标签的 Service 已在界面标注用途与权限要求，构建标签清单待补

### 验收

- [x] Service 标签与其它顶层标签统一校验
- [x] API 监听地址默认保持本地安全范围，监听非本机地址时强制要求 secret
- [x] 需要证书、权限的服务有明确提示
- [ ] 服务配置通过 1.14.0 内核检查（本机未安装内核）

## 阶段 7：导入、订阅和配置往返（已完成）

- [x] 导入完整 sing-box JSON 配置
- [x] 按模块反序列化为表单状态
- [x] 未修改字段无损保留（界面未建模的字段进入对应条目的附加参数）
- [x] 导入时识别弃用字段并给出迁移建议
- [x] 分享链接导出（VLESS、VMess、Trojan、Shadowsocks、Hysteria 2、TUIC、AnyTLS）
- [x] 订阅节点去重、重命名、过滤
- [x] 多订阅更新状态、失败原因与更新时间显示
- [x] 订阅内容差异预览（刷新后显示新增 / 移除数量）
- [~] 大配置短链接或服务端持久化：仍是无状态链接，超长时给出提示
- [x] 公网部署时的鉴权、过期时间和速率限制
- [x] 订阅二维码（自包含编码器，浏览器测试用 BarcodeDetector 真解码校验）
- [x] 凭据字段的显示、复制与暴露风险提示

### 验收

- [x] 生成的配置导入回界面后重新生成，结果逐字节一致（`tests/importer.mjs`、`tests/browser.mjs`）

## 阶段 8：验证、兼容性与发布（基本完成）

- [~] 浏览器内 JSON Schema 校验：提供结构校验、模块字段校验与跨模块冲突检查，未引入完整 JSON Schema 校验器
- [x] 可选调用本机 sing-box 1.14.0 执行正式 `check`（配置预览工具栏，服务端 `/api/check`）
- [x] 显示错误对应的模块与字段（冲突清单带模块标签，内核输出带配置路径）
- [x] 为每种配置类型补充单元测试（8 个模块测试套件）
- [x] 为添加、编辑、取消、删除、导入和生成流程补充浏览器测试（`tests/browser.mjs`）
- [~] 桌面、平板和移动端视觉回归：有响应式布局与人工截图，未接入自动视觉比对
- [x] 平台差异提示（Linux / Android / Apple 限制在对应字段说明中标注）
- [x] 配置自动备份、恢复和版本迁移（破坏性操作前自动快照，旧版本状态自动迁移）
- [x] 导出前的凭据与公网暴露风险检查
- [x] 完整用户文档和部署说明、反向代理示例与生产安全清单

## 开发原则

1. 只以 sing-box 1.14.0 正式文档和正式内核行为为准。
2. 不新增已弃用、准备移除或仅用于旧版迁移的字段。
3. 每个顶层配置类别使用独立模块注册，不把所有生成逻辑堆回 `app.js`。
4. 常用字段使用官方客户端风格的可视化表单；长尾字段可以折叠，但不能因此丢失配置能力。
5. 所有取消按钮必须是非提交按钮，不能被 HTML 必填验证阻止。
6. 每完成一个阶段，都要同时通过静态检查、浏览器流程检查和 sing-box 1.14.0 内核检查。
7. 涉及系统权限、平台限制、证书、构建标签或公网暴露时，界面必须明确说明风险与适用范围。

## 推荐执行顺序

1. ~~完整 DNS~~（已完成）
2. ~~Route Rule 与 Rule Set~~（已完成）
3. ~~完整 Inbound~~（已完成）
4. ~~完整 Outbound~~（已完成）
5. ~~补齐共享配置对象~~（已完成）
6. ~~NTP、证书、Experimental 与 Service~~（已完成）
7. ~~完整配置导入、订阅管理和往返编辑~~（已完成）
8. ~~全量验证、兼容性测试、文档与发布~~（基本完成）

## 仍待处理

- 用装有 sing-box 1.14.0 的环境跑一遍各模块示例的 `sing-box check`，把各阶段验收里的内核检查项勾掉（界面已提供一键调用，只需设置 `SING_BOX_BIN`）
- `certificate_provider`、HTTP/2 与 QUIC 长尾字段目前依赖附加参数，可按需补成表单
- 自动视觉回归与需要特殊构建标签的能力清单

