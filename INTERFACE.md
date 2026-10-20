# Surge CC 0.2.2 接口合约

## OAuth 打开器

`launch code` 的非 Terminal 分支创建 `OAuthSession`，仅向自己的 CLI 注入 `BROWSER` 绝对可执行路径。`guard.run_guarded(..., on_started=...)` 将真实 `Popen` 句柄交给该会话，故回调监听归属可以绑定当前 CLI。Terminal 分支仍只创建重新检查并启动 CLI 的脚本。

打开器通过短路径 AF_UNIX socket 与父进程交换单条带随机令牌的内存消息。目录 0700、socket 0600、hook 0700；URL 不写入工具配置或状态回执。关闭父会话后 socket/hook 被删除，过期 hook 不会回退系统浏览器。

`oauth.validate_authorization_url` 只接受明确的官方 HTTPS authorize 端点，保留原 URL；要求 code/S256/state/PKCE，拒绝重复查询键、用户信息、fragment、控制字符和非 loopback callback。`callback_owned_by` 以活 CLI 进程句柄及 lsof 验证精确端口仅绑定回环地址。

`cli.oauth_checks` 执行完整检查，随后 `oauth_gate.verify_proxy_exit` 经实际专用 HTTP 入口访问固定 HTTPS 回显服务。超时、重定向、非 200、未知或不一致 IP 均失败；打开前还复核当前线路状态。只在成功后创建独立授权浏览器，打开后再次检查。

授权浏览器使用 `workspace/data/OAuthBrowser` 与 `.oauth.lock`。它与普通网页资料分别存储；共享工作区锁阻止备份/恢复，授权专属锁防止并发占用。回调 bypass 是 `<-loopback>` 后追加精确 HTTP host:port，其他连接仍走原专用代理。`OAuthSession` 关闭时只停止它持有的授权浏览器，未修改系统默认浏览器、Surge 配置或其他策略组。

此文档对应 `src/surge_cc/` 当前实现。CLI 入口为 `scripts/surge-cc`；原生 GUI 为 `app/main.swift`，通过子进程调用后端并读取 JSON。参考上游 `yoursjeyo/claude-switcher` 提交 `74ea09e2e7db14968548a5fab7b97e96b4b1b330` 的主要功能思路，独立实现 Surge 适配，并不保证与上游所有行为一致。

## 设置

全局参数 `--config PATH` 必须放在子命令前，默认路径：

```text
~/Library/Application Support/Surge CC/config.json
```

`core.validate_config` 接受的字段如下。未知字段拒绝保存；保存采用原子替换和 `600` 权限，拒绝经符号链接访问的目标位置。

| 字段 | 类型、默认值与约束 |
| --- | --- |
| `schema` | `1` |
| `group`、`policy` | 必填，1–160 字符，无控制字符；`policy` 必须是实际代理节点名称，拒绝 DIRECT、REJECT 等内置策略 |
| `expected_ip` | 必填，合法 IPv4 或 IPv6，保存时规范化 |
| `proxy_url` | 必填，HTTP、字面回环 IP、有效端口；拒绝用户名、密码、查询、片段和非根路径 |
| `profile_path` | 默认空字符串；非空须为绝对路径，用于核对当前 Surge 配置，也是修复功能的前提 |
| `hosts` | 默认 10 个 Claude/Anthropic 基线域名；输入最多 100 项小写域名，合并去重，基线不会被移除 |
| `expected_timezone`、`expected_locale` | 默认空字符串；非空作为只读比较的预期值，不改系统设置 |
| `expected_country` | 默认空字符串，非空须为两位大写国家代码，如 `CA` |
| `expected_asn` | 默认空字符串，非空须为 `AS` 加数字，如 `AS64500` |
| `browser_language` | 默认空字符串；非空须为语言标签，如 `zh-CN`、`en-US`，仅设置工具自有浏览器资料并检验回执 |
| `browser_path` | 默认空字符串；非空须为独立 Chrome 应用内可执行文件的绝对路径，不含控制字符或逗号，不得指向个人 Chrome。范围检查进一步要求 `Surge CC Browser.app/Contents/MacOS/Google Chrome`、无路径符号链接、可执行文件与包内有效 Helper |
| `privacy_strict` | 布尔值，默认 `true`；控制部分未知/提示隐私检查是否参与启动判定 |
| `guard_interval` | 整数，默认 `10`，范围 `2–60` 秒 |
| `workspace` | 默认 `A`；1–32 位字母、数字、下划线或连字符，GUI 仅提供 A/B |

不将时区、语言、GeoIP 或 ASN 解释为身份或实际居住地证明。浏览器已有扩展、系统钥匙串与服务端关联不在工作区隔离范围。

## 公共 CLI

下列所有子命令都接受 `--json`，否则输出摘要与检查行。

| 命令 | 行为与副作用 |
| --- | --- |
| `configure --group NAME --policy NAME --expected-ip IP --proxy-url URL [--profile PATH]` | 校验后保存本工具设置，不改 Surge；另接受上述预期环境参数、`--browser-path PATH`、`--privacy-strict true\|false` 和 `--guard-interval N`。未提供的扩展参数保留原值，`--profile` 未提供则置空 |
| `check` / `status` / `checkdetail` | 三者都执行完整即时检查；基础线路通过后启动临时检测 Chrome，完成后结束它，不打开 Claude 登录页 |
| `pin` | 仅在现有单节点手动组中选择配置的节点，再执行完整检查；不改 Surge 配置文本 |
| `workspace list` | 返回 A、B、当前及已存在工作区和快照列表；可创建本工具的工作区根目录，不启动应用 |
| `workspace create --name NAME [--label TEXT]` | 初始化指定工作区的本地数据目录 |
| `workspace use --name NAME` | 初始化工作区并保存当前选择；不迁移已运行会话或登录账号 |
| `workspace snapshot [--name NAME] [--label TEXT]` | 默认当前工作区；要求独占锁且无 Chrome 运行锁，复制数据并核对清单与 SHA-256 |
| `workspace restore [--name NAME] --snapshot ID` | 校验归属及完整性，先保存恢复前快照，再替换数据；保留替换前目录；GUI 有确认，CLI 命令本身表示执行 |
| `repair-plan` | 只读观察 Surge 当前状态，返回公开动作和 `plan_id`，不写配置、不重载 |
| `repair --plan-id ID` | 核对原计划仍匹配后执行；配置改写先备份与语法验证，失败时尝试回滚可确认的本次改动 |
| `launch web` | 完整检查后启动所选工作区的独立 Chrome 和专属监控进程；不复用个人 Chrome |
| `launch code --terminal` | 完整检查后打开私有 `.command`；终端内再次执行完整检查，然后启动受监控 CLI |
| `launch code -- CLAUDE_ARGS...` | 在当前项目目录同步运行受监控 Claude Code；显式代理与工作区 `CLAUDE_CONFIG_DIR`；不对参数做 shell 求值 |
| `guard-status` | 读取现有状态文件并计算最近回执是否有效，不执行新的网络检查、不证明当前进程存活 |

网页入口不接受额外参数。CLI 额外参数必须放在 `--` 后；拒绝 `--settings`、`--setting-sources` 及其 `=VALUE` 形式。启动前检查工作区、项目祖先目录与文件形式的托管 settings，拒绝冲突代理和其他模型服务设置。

CLI 成功返回 `0`；阻止启动、已捕获的 `Blocked` 和受监控 CLI 非零结束返回 `2`；已捕获的系统操作错误返回 `1`。参数解析错误也可返回 `2`。实际子进程退出码位于 `child_exit_code`，公共 CLI 不保证直接转发该非零值。内部 `surge_cc.guard` 进程另返回其监控会话退出码，不是公共 GUI 控制 API。

## JSON 与启动判定

公共响应使用 `schema:1`，基本字段如下；以下是结构示例，省略了多数检查行与设置字段：

```json
{
  "schema": 1,
  "ok": false,
  "summary": "检查未通过，已阻止启动",
  "checked_at": "2026-01-01T00:00:00+00:00",
  "checks": [
    {"id": "surge", "title": "Surge 连接", "status": "pass", "detail": "已连接"},
    {"id": "browser_webrtc", "title": "浏览器 WebRTC ICE 实测", "status": "unknown", "detail": "未取得完整回执", "required": true},
    {"id": "dns_egress", "title": "递归 DNS 外部出口", "status": "unknown", "detail": "未验证", "required": false}
  ],
  "settings": {
    "schema": 1,
    "group": "Claude",
    "policy": "Home",
    "expected_ip": "203.0.113.7",
    "proxy_url": "http://127.0.0.1:62919",
    "browser_path": "/absolute/path/Surge CC Browser.app/Contents/MacOS/Google Chrome",
    "workspace": "A"
  }
}
```

检查行字段为 `id`、`title`、`status`、`detail`，可带 `required`。状态允许 `pass`、`fail`、`warn`、`unknown`、`info`；缺省 `required` 等价于 `true`。兼容新增可选 `evidence:[String]` 与 `evidence_scope:String`，仅用于显示依据与观测范围，不参与启动判定。GUI 缺省为空；字段类型错误时拒绝整份无效回执，不推断为已通过。

GUI 每行默认显示短摘要，长说明和可选证据折叠在「查看完整说明」或「查看依据与范围」中。按必需行、补充待确认行（非必需且非 `pass`/`info`）、补充信息行分组。`unknown` 统一显示「未确认」：既可能未完成检测，也可能已有观测但无法得出结论。非必需的 `dns_egress:info` 显示「已实测」，其余 `info` 显示「信息」。顶部显示必需项通过数量与补充待确认数量，不重复响应摘要。

`core.result` 的检查通过条件：检查非空、ID 不重复、包含全部基础检查 ID（`surge`、`mode`、`group`、`definition`、`route`、`proxy`、`exit`、`stable`），且所有必需行均为 `pass`。非必需的 `unknown`/`warn`/`fail` 会使摘要提示仍有待确认项目。保存、工作区、修复及读取保护状态属于操作回执，可返回 `ok:true` 与空 `checks`；这只表示该操作完成，不是线路检查通过。GUI 不应将这类操作回执转为绿色启动状态。

默认严格模式让 DNS 接管、浏览器 ICE 等无法确认项阻止启动。已观察到预期出口之外的公网 ICE 地址始终是必需 `fail`，关闭严格模式也不放行。浏览器有显式语言或时区预期时，其回执行始终必需；缺失为 `unknown`，不一致为 `warn`。系统环境和 GeoIP/ASN 的显式预期同样产生必需比较。

0.2.3 的 `dns_egress` 经固定专用 HTTP 入口执行 dnsleak.dev 随机域名权威观测。完整、有效、前后保护与实际出口一致且服务分类为 `no_leak` 的回执显示非必需 `info`；`split` 为非必需 `warn`；不完整、超时、限流、无结论为非必需 `unknown`。专用范围、实际出口或配置稳定性核验失败是必需 `fail`，撤回启动资格。快速检查与 OAuth 内部复核不执行此补充检测，保留 `unknown` 而非复用缓存。递归器 IP 不必等于住宅代理 IP；`info` 仅为本次专用代理链的观测，不证明全系统无泄漏。FakeIP 接管与权威观测分别展示。

IPv6 清单将地址区分为公网单播、链路本地、ULA（`fc00::/7`）、回环与其他，并依据接口名称／标记区分物理、utun 隧道、回环与其他接口。非 utun、非回环接口存在公网单播地址或默认路由时保留非必需 `warn`；未知接口类别按非 utun 保守处理。仅本地地址、utun 路由或无可见路径时为非必需 `info`，不称作无旁路证明。无法完整读取或解析接口／路由时仍为 `unknown`，按 `privacy_strict` 决定必需性。系统路径清单不替代 IPv6 HTTP/UDP 或浏览器实测，也不确认 utun 属于 Surge。

STUN 错误、超时、缺少完整回执或格式损坏始终为 `unknown`。无公网 ICE 候选或只有本地/mDNS 候选，仅在调用方独立核验专用范围后才有条件通过，具体合约如下。

`settings` 含本地名称、配置路径、实际预期 IP 等私有信息，输出供本地界面读取；分享前需脱敏。不能因为数据来自工具就将其视为非敏感。

## 独立浏览器与 WebRTC 合约

`core.browser_executable(config)` 在 `browser_path` 非空时选择该二进制，否则回退到原 `/Applications/Google Chrome.app` 路径。独立浏览器应是官方 Chrome 应用的完整副本，包名为 `Surge CC Browser.app`；没有自动下载、复制或更新操作。只使用另一个 `--user-data-dir` 而仍运行个人 Chrome 二进制，不能得到进程路径隔离。

`containment.validate_scope` 是只读验证。非空 `browser_path` 启用必需的 `browser_containment` 检查：要求 Surge `mode=rule`、`enhanced-mode=true`，当前配置路径匹配（如果已指定），固定组只有一个指定节点且已选中。专用 HTTP 入口必须监听字面回环地址，端口不能为原有 `6152/6153`，不能带入口认证或同端口公开监听。生效规则前两条必须依次为：

```text
IN-PORT,<专用端口>,<固定组>
PROCESS-NAME,<Surge CC Browser.app 绝对路径加尾随斜杠>,REJECT
```

范围核验确认副本主程序及包内 Helper，调用 Surge 路由解释检查原始 TCP/UDP、STUN、QUIC 和 IPv6 的拒绝判定，以及专用端口的 HTTP/HTTPS 固定路由；核验结束再比较配置与组状态。个人 Chrome 路径不在这个拒绝范围内。CLI 使用相同专用代理入口和监控，但没有因此获得面向任意子进程的包路径拒绝规则。

正常网页启动和临时 Chrome 探针均传入 `--webrtc-ip-handling-policy=disable_non_proxied_udp`，不使用带 `force-` 的参数。自有 `Default/Preferences` 写入：

```json
{"webrtc": {"ip_handling_policy": "disable_non_proxied_udp", "ip_handling_url": []}}
```

URL 覆盖键是单数 `ip_handling_url`。语言留空也会应用这些偏好；写入动作本身不证明运行时策略生效。

`chrome_probe_check(..., *, containment_verified=False)` 与 `assess_ice(..., *, containment_verified=False)` 只接受调用方另行提供的核验结果，不能从启动参数、写入偏好或无响应自行推断为 `true`。额外公网候选始终为必需 `fail`。没有公网候选时，只有参数严格等于布尔 `True`、ICE 完整结束、没有错误且候选记录有效，才可返回 `pass`；文案说明非代理 UDP 限制与 Surge 旁路拒绝已核验、本次无额外公网候选，并注明未测得 WebRTC 公网出口，不声称出口匹配。

`audit_checks` 在探针前后分别执行 `validate_scope`。后置复核失败会将 `browser_containment` 置为必需 `fail`，将 WebRTC 的非失败结果撤回为必需 `unknown`；已观测的额外地址 `fail` 不会被覆盖。两次核验仍是时点观测，不能证明探针期间每个瞬间的状态。

规则解释的 IPv6 拒绝结果不证明所有系统 IPv6 已被 VIF 接管。Surge 关闭、增强模式失效或实际 IPv6 接管未知时，不提供 OS 防火墙级即时断网保证；`browser_path` 为空时也不提供此独立应用范围核验。

## 命令附加字段

- `launch` 可带 `launched:true`、`target:web|code-terminal|code`；直接 CLI 会话还返回 `child_exit_code`。Terminal 的 `launched:true` 仅表示终端启动器已打开，不确认内部 Claude 已通过后续复核。
- 工作区响应包含 `current_workspace` 和 `workspaces` 数组，每项为 `name`、`label`、`snapshots`；快照项为 `id`、`label`、`created_at`。
- 保存快照另带 `snapshot:{id,name,label,created_at}`；恢复另带 `restored` 和自动备份快照 ID `backup`。
- 修复预览返回 `plan_id` 和 `actions:[{id,title,detail}]`。`plan_id` 绑定配置、源文件、生效配置、模式、组状态和动作；执行前重算，变化则拒绝。公开回执不含完整配置文本。
- `browser_path` 非空时，修复计划额外绑定增强模式状态；`scope` 动作恢复独立监听及置顶范围规则，`enhanced-required` 表示增强模式前提不满足，应用在任何写入前拒绝执行，不自动切换该全局开关。
- 修复执行返回 `actions`、`backup_created`；操作完成不意味着完整线路检查通过，需重新 `check`。
- `guard-status` 返回 `guard:{running,interval,last_checked_at,detail}` 和按时间倒序的 `guards`。这里的 `running` 是“收到近期有效运行回执”的兼容字段，**不是已验证的当前进程存活状态**。

## 运行监控合约

`guard.run_guarded` 在启动前持有工作区共享锁，执行基础线路复核、建立运行基线并再次检查出口。它只持有自己 `Popen` 创建的独立会话子进程，不根据保存的 PID 或通用进程名终止其他程序。网页子进程若立即退出或交接而无法持续持有，不算已建立监控会话。

`RuntimeChecker` 保存配置路径、组状态和生效配置摘要，周期复核：规则模式、单节点拓扑、选中节点、完整配置摘要、本地端口属于 Surge、所有基线域名的该目标程序路由，并在规定周期核对实际出口。`browser_path` 非空时额外要求增强模式有效，并逐轮调用 `validate_scope`；异步路由/出口检查结束后复读配置基线。它不周期重跑 DNS、WebRTC、语言、时区、GeoIP/ASN 或所有项目文件审计。

默认巡检目标间隔为 `guard_interval=10` 秒；出口复查为 `max(30, guard_interval)` 秒。每次检查完成后再计算下一轮，检测耗时会增加实际间隔。检查错误或未知异常触发清理；停止先 TERM，必要时核对仍属于自身后 KILL。清理失败使用 `stop_failed`，不会报告已确认停止。

私有状态/回执字段：`schema`、`target`、`state`、`ok`、`checked_at`、`detail`，不存 PID、CLI 参数或配置明文。可能状态为 `starting`、`running`、`exited`、`blocked`、`stopped`、`stop_failed`。首次 `running` 回执确认启动；后续状态文件记录监控进展。`guard-status` 仅在 `state=running` 且时间差处于 `0..max(90, guard_interval*3)` 秒时视为近期回执，负时间差或过期不计入。

网页使用独立监控进程，GUI 退出不自动停止它。CLI 监控在终端前台生命周期内同步执行。SIGINT/窗口大小变化可转发给子进程，正常停止会清理自有子进程；外部强杀、崩溃、系统问题或子进程脱离不构成可保证的即时网络阻断。

## 工作区、修复与安全边界

工作区是本工具拥有的目录分离：`workspaces/<name>/data/Browser` 与 `data/Claude`，不是独立系统用户、设备身份或钥匙串。快照只复制这些目录并校验清单，不复制工作区外项目。快照和恢复要求独占锁；活动会话持共享锁。恢复前自动备份，并保留 `previous-*` 数据。数据可能包含登录状态，必须私下保存。

`workspaces.prepare_browser_language` 保留旧函数名，实际在自有工作区未运行时总是更新上述 WebRTC 偏好并清空 URL 覆盖，保留其他字段。仅显式浏览器语言非空时才更新 `intl.accept_languages`；空语言不改原语言值。检测进程使用新的临时空白资料和同样的 WebRTC、显式语言设置，没有复制已有工作区的扩展、策略或其他偏好，回执不能声称完全代表已保存浏览器。

修复只针对当前明确路径下的普通本地 Surge 配置，拒绝托管配置。修改前私有备份并语法校验，执行前重核计划；失败尝试回滚，不覆盖观察到的并发修改。修复可能重载 Surge、改变规则模式或指定组选择，不能描述为只读动作。系统时区、地区、IPv6 和其他无关系统设置不由修复工具自动改动。

`containment.patch_profile` 本身只生成配置文本；`repair-plan`/`repair` 在 `browser_path` 非空时将它接入候选生成，保证专用 `IN-PORT` 与包路径 `PROCESS-NAME REJECT` 排在域名修复之前。范围缺失、错序或当前生效核验失败产生 `scope` 动作，保留原监听入口与无关规则；应用后调用完整 `validate_scope`，失败尝试回滚。发生重载时先进行有界就绪等待（最多约 5 秒的等待间隔，另加查询耗时），确认规则模式、增强模式及首两条规则恢复，再核验完整范围。这个等待不把失败自动转为通过。

无 `browser_path` 时维持常规修复行为。浏览器副本安装和增强模式开启不由修复器自动完成；增强模式未确认时计划包含 `enhanced-required`，写入前阻止执行。规则模式切换仍作为独立动作显示在预览中。模块或临时规则覆盖若没有被本次配置修改解决，应用后的范围核验仍会失败，不能沿用此前通过结果。

后端不需要 Surge HTTP API 密钥，不安装 root 守护服务。GUI 使用动态检查行，不缓存启动许可；打开 GUI 不自动启动 Claude。所有保护均为有限观测与进程管理，不是系统防火墙、完整防泄漏证明、身份隔离保证或账号封禁保证。实际验证记录由 [VALIDATION.md](VALIDATION.md) 单独维护。
