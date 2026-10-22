# Surge CC 0.4.0 接口合约

本文对应 **v0.4.0 / Build 14**。接口约定与实现范围如下；自动化及实机验收范围见 [VALIDATION.md](VALIDATION.md)。

## 终端入口

`terminal.install` 接管当前用户已有的 `~/.local/bin/claude` 官方符号链接。先验证路径、文件权限、原始可执行文件与版本，再将原链接及清单保存在默认 Application Support 下的 `terminal/`，通过原子交换替换入口。已有普通文件、其他用户可写路径、不一致或未完成的清单均拒绝覆盖。`terminal uninstall` 仅在当前包装器仍与记录一致时原子恢复原链接，不移除 Surge 规则、工作区或账号资料。

包装器调用固定 Python、固定后端和固定配置的 `launch code --passthrough -- ...`，不使用 shell 求值传递 Claude 参数；依赖缺失、入口改变或校验失败时没有原版 CLI 回退。`core.default_claude` 经 `terminal.original_claude` 找回校验后的原生程序，避免递归调用包装器。原生路径及 stat 身份固定在安装记录中，原始文件变化后拒绝继续运行，需要通过卸载、维护、重新安装流程更新。

精确单参数 `claude --version` 或 `claude -v` 转到 `terminal version`，只在验证清单、入口和原始文件身份后输出缓存版本，不运行原生程序或网络检测。它用于终端和编辑器的版本发现，不能证明当前线路通过。`--passthrough` 把包装器的检查/错误写到 stderr，成功结束时不在 stdout 追加操作回执；stdin/stdout 保留给 CLI。安装的 shell 入口依赖缺失返回 `78`，进入后端后的退出码约定见下文。

0.2.6 开始，持久化原生程序身份比较只使用 inode、大小和纳秒修改时间，仍检查规范路径、所有者、权限与可执行性。`original_stat` 保持四项记录格式兼容旧数据，但首项 `st_dev` 是挂载期间的设备编号，不用于跨重启身份比较；短期原子交换和并发检查继续比较设备号。该 stat 检查不是对同 inode、同大小、同修改时间的内容篡改进行密码学鉴定。

安装入口前要求 `cli_process_paths` 非空、覆盖当前原生程序，并通过 `containment.validate_scope`。运行入口和 GUI 启动共用代理检查、工作区、`OAuthSession` 与受控进程监控。GUI 不需要保持打开，但后端、Python 和配置仍须位于安装记录中的位置；应先把应用放到最终位置，再安装接管。包装器固定后端路径，不固定后端文件摘要，因此正常结束受控会话后，在同路径替换应用包内后端即可加载新版，无需重建登记。移动后端则需使用新版 `terminal uninstall` 撤销旧入口，再从新位置安装；旧版因 `st_dev` 误报无法卸载时也使用新版维护命令。独立后端不会随 GUI 替换自动更新。

当前使用范围为本机终端命令，包括 Ghostty 与 Orca 终端/TUI 通过该路径执行的 `claude`。Orca Native Chat 与 managed accounts 的账号目录、父子进程 transcript 读取及恢复流程尚未验收；包装器会使用 Surge CC 所选工作区的 `CLAUDE_CONFIG_DIR`，不宣称兼容 Orca 的其他账号目录。已在接管前运行的会话不会被收编，其他二进制副本和远端主机也不会自动接管。

Devin CLI 等其他客户端使用 Claude 模型，不等于调用被接管的原生 `claude`。终端入口不拦截它们，也不根据模型名称推断保护范围。

包装器设置 `SURGE_CC_TERMINAL_ENTRY=1`。该入口仍执行所有启动必需检查，但调用 `full_checks(..., external_dns=False)` 跳过可选外部 DNS 测量；GUI 完整检查与公共 `check` 不因此改变。

每个受控 CLI 子进程设置 `DISABLE_UPDATES=1` 与 `DISABLE_AUTOUPDATER=1`；拒绝 `update`、`upgrade`、`install` 更新入口，避免安装器覆盖包装器。这不是全局环境变更。维护需先正常结束会话、卸载入口、更新官方程序，再校验范围并重新安装接管。

维护代码可调用内部 `terminal.update_backend(entrypoint, python_executable=None, *, state_dir=None)`，将完整且可验证的受控入口重新绑定到独立后端；当前没有 `terminal update` 公共命令或自动更新界面。它保留原生程序、配置与原始符号链接备份，先原子交换包装器，再交换清单。中间不一致状态会拒绝启动，不短暂恢复原生入口；失败尝试按已核实的文件身份回滚，并保留无法安全恢复的私有副本。此操作不修改 GUI bundle、Surge 配置或系统权限，不保证系统权限以后不会变化。新后端与 Python 路径仍须长期保留。

## OAuth 打开器

`launch code` 的非 Terminal 分支创建 `OAuthSession`，仅向自己的 CLI 注入 `BROWSER` 绝对可执行路径。`guard.run_guarded(..., on_started=...)` 将真实 `Popen` 句柄交给该会话，故回调监听归属可以绑定当前 CLI。Terminal 分支仍只创建重新检查并启动 CLI 的脚本。

打开器通过短路径 AF_UNIX socket 与父进程交换单条带随机令牌的内存消息。目录 0700、socket 0600、hook 0700；URL 不写入工具配置或状态回执。关闭父会话后 socket/hook 被删除，过期 hook 不会回退系统浏览器。

`oauth.validate_authorization_url` 只接受明确的官方 HTTPS authorize 端点，保留原 URL；要求 code/S256/state/PKCE，拒绝重复查询键、用户信息、fragment、控制字符和非 loopback callback。`callback_owned_by` 以活 CLI 进程句柄及 lsof 验证精确端口仅绑定回环地址。

`cli.oauth_checks` 执行完整检查，随后 `oauth_gate.verify_proxy_exit` 经实际专用 HTTP 入口访问固定 HTTPS 回显服务。超时、重定向、非 200、未知或不一致 IP 均失败；打开前还复核当前线路状态。只在成功后创建独立授权浏览器，打开后再次检查。

网页与授权浏览器统一使用 `workspace/data/Browser`，启动参数明确指定 `--profile-directory=Default`。共享工作区锁阻止备份/恢复，共同的 `.browser.lock` 排他锁覆盖偏好准备至浏览器退出；OAuth 仍持有 `.oauth.lock`。已有窗口占用时拒绝 Chrome 进程转交，提示先关闭再重试，不改用另一资料。旧 `OAuthBrowser` 保留供备份/恢复，不再作为启动路径。回调 bypass 是 `<-loopback>` 后追加精确 HTTP host:port，其他连接仍走原专用代理。`OAuthSession` 关闭时只停止它持有的授权浏览器，未修改系统默认浏览器、Surge 配置或其他策略组。

此文档对应 `src/surge_cc/` 当前实现。CLI 入口为 `scripts/surge-cc`；原生 GUI 为 `app/main.swift`，通过子进程调用后端并读取 JSON。参考上游 `yoursjeyo/claude-switcher` 提交 `74ea09e2e7db14968548a5fab7b97e96b4b1b330` 的主要功能思路，独立实现 Surge 适配，并不保证与上游所有行为一致。

## 专用浏览器恢复与锁修复

`browser-locks recover --workspace A --json` 与 `browser-locks repair --workspace A --json` 仅接受配置中当前工作区，防止界面过期后操作错误的目标。两个命令都不运行线路检查、启动程序、登录或修改代理。

`recover` 先持有 `.browser-recovery.lock`，读取 `Browser` 与 `OAuthBrowser` 的 Chromium 运行锁。锁里的 PID 只是候选：必须匹配当前用户、配置中的专用浏览器可执行程序、进程启动身份及精确 `--user-data-dir`，并在发送信号前复核。仅向核验通过的专用浏览器主进程请求 `SIGTERM` 正常退出，不按进程名批量关闭，不向个人 Chrome、另一个工作区、CLI、终端或监控进程发信号；退出超时不升级为强杀，也不清锁。PID 核验不是针对同用户恶意并发的操作系统安全边界。

窗口退出后等待原持有者释放 session/OAuth 锁，再复用离线 `repair`。若受控 CLI、授权或备份操作仍占用工作区，会拒绝清理并要求用户正常结束该操作，不会强制终止 CLI。

`repair` 本身不结束任何进程，仍可离线独立调用。它按 session → OAuth 顺序取得排他锁，复核专用 profile 进程、SingletonLock 的本机 PID 和 SingletonSocket 状态，再将确认过期的三个顶层符号链接归档到工作区 data 以外的私有目录。权限/路径异常、活跃或无法确认的状态均拒绝操作；不处理登录资料、其他锁文件或外部 socket 目标。

浏览器占用类错误返回 `recovery_action:"recover-browser"`；`recover` 的拒绝结果保留该动作供重试，传统 `repair` 的拒绝结果可返回 `recovery_action:"repair-browser-locks"`。GUI 只识别这两个固定白名单动作，不执行任意后端命令，也不从摘要猜测动作。非当前工作区的快照/恢复错误不提供当前工作区动作。工作区页常驻提供恢复按钮及次要的仅清锁按钮，目标为已应用的当前工作区，而非尚未生效的选择器值。

成功返回 `recovery:{status,workspace,removed_count,backup_path,message}`。离线 `repair` 的 `status` 为 `repaired` 或 `no_stale_locks`；`recover` 还附 `stopped_profiles`，实际关闭窗口时状态为 `recovered`。归档路径是本地私密信息，公开分享前需脱敏。操作成功只表示恢复完成，`checks:[]`，不代表线路或保护已经通过。

GUI 调用任一命令成功后清除旧错误并自动执行新的 `check`；仅消费新检查的线路结论，不自动启动网页、CLI 或登录。失败显示具体原因并保留重试，执行期间禁用操作按钮，新检查清除上次恢复动作。CLI 使用者需自行运行 `check`。

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
| `cli_process_paths` | 默认 `[]`；最多 16 个无重复的规范化绝对原生 Claude 路径。目录前缀仅允许当前用户的 `.local/share/claude/versions/`，必须保留尾随 `/`；不接受终端、Node、Python 等共享进程范围。文件有效性及实际程序覆盖在范围检查时进一步验证；当前通过配置文件设置 |
| `privacy_strict` | 布尔值，默认 `true`；控制部分未知/提示隐私检查是否参与启动判定 |
| `guard_interval` | 整数，默认 `10`，范围 `2–60` 秒 |
| `workspace` | 默认 `A`；1–32 位字母、数字、下划线或连字符，GUI 仅提供 A/B |

线路与预期环境字段按工作区保存在 `workspaces/<name>/settings.json`：`group`、`policy`、`expected_ip`、`proxy_url`、`hosts`、`expected_timezone`、`expected_locale`、`expected_country`、`expected_asn`、`browser_language`、`privacy_strict`、`guard_interval`。`profile_path`、`browser_path`、`cli_process_paths` 是共享机器配置，切换账号不复制应用或新增系统代理。根目录 `config.json` 是当前账号的有效运行配置。

不将时区、语言、GeoIP 或 ASN 解释为身份或实际居住地证明。浏览器已有扩展和服务端关联不在本地工作区分离的保证范围；认证采用下面限定的每工作区存储，并非创建独立系统钥匙串。

## 公共 CLI

下列子命令接受 `--json`，否则输出摘要与检查行；`terminal version` 特例始终输出单行缓存版本文本。

| 命令 | 行为与副作用 |
| --- | --- |
| `configure --group NAME --policy NAME --expected-ip IP --proxy-url URL [--profile PATH] [--expected-workspace NAME]` | 校验后保存当前工作区及共享机器设置，不改 Surge；GUI 带工作区预期值，过期则拒绝。另接受预期环境参数、`--browser-path PATH`、`--privacy-strict true\|false` 和 `--guard-interval N`；未提供的扩展参数保留原值，`--profile` 未提供则置空 |
| `check` / `status` / `checkdetail` | 三者都执行完整即时检查；基础线路通过后启动临时检测 Chrome，完成后结束它，不打开 Claude 登录页 |
| `pin` | 仅在现有单节点手动组中选择配置的节点，再执行完整检查；不改 Surge 配置文本 |
| `workspace list` | 返回 A、B、当前及已存在工作区、线路、浏览器资料是否存在、认证模式与快照列表；可建立私有根目录及首次旧引用迁移，不读取 Token，不启动应用 |
| `workspace create --name NAME [--label TEXT]` | 初始化指定工作区的本地数据目录 |
| `workspace use --name NAME [--close-sessions]` | 独占账号启动门，初始化并保存目标账号；提供 `--close-sessions` 时先通知当前与目标新版受控会话退出。应用目标专用线路后才提交选择；不自动登录或重新启动任务。没有该参数时活动会话仍阻止切换 |
| `workspace-auth status --workspace NAME` | 返回模式与配置是否存在；不读取 Token，不证明已登录 |
| `workspace-auth store --workspace NAME --stdin` | 在账号变更锁及工作区独占锁内，从标准输入读取 Token 并写入该账号钥匙串项；不接受 Token 参数 |
| `workspace-auth oauth --workspace NAME` | 选择该工作区 OAuth 模式；不发起授权、不删除旧钥匙串值 |
| `workspace snapshot [--name NAME] [--label TEXT]` | 默认当前工作区；要求独占锁且无 Chrome 运行锁，复制数据并核对清单与 SHA-256 |
| `workspace restore [--name NAME] --snapshot ID` | 校验归属及完整性，先保存恢复前快照，再替换数据；保留替换前目录；GUI 有确认，CLI 命令本身表示执行 |
| `repair-plan` | 只读观察 Surge 当前状态，返回公开动作和 `plan_id`，不写配置、不重载 |
| `repair --plan-id ID` | 核对原计划仍匹配后执行；配置改写先备份与语法验证，失败时尝试回滚可确认的本次改动 |
| `browser-locks repair --workspace NAME` | 离线检查当前工作区的专用浏览器运行锁，仅归档可确认过期的锁链接；不结束进程或执行线路检查 |
| `browser-locks recover --workspace NAME` | 请求经过核验的当前专用窗口正常退出，再归档过期锁；不强杀 CLI，不执行线路检查或启动 |
| `launch web` | 完整检查后启动所选工作区的独立 Chrome 和专属监控进程；不复用个人 Chrome |
| `launch code --terminal` | 完整检查后打开私有 `.command`；终端内再次执行完整检查，然后启动受监控 CLI |
| `launch code -- CLAUDE_ARGS...` | 在当前项目目录同步运行受监控 Claude Code；显式代理与工作区 `CLAUDE_CONFIG_DIR`；不对参数做 shell 求值 |
| `launch code --passthrough -- CLAUDE_ARGS...` | 与上述启动检查相同，但不污染子进程 stdout；检查失败回执写入 stderr，供终端包装器使用 |
| `terminal install` | 先确认 Claude 原生程序的 Surge 旁路拒绝范围，再可逆接管 `~/.local/bin/claude`；不自行修改 Surge 规则 |
| `terminal status` | 检查清单、入口、备份、原始程序与后端，返回终端接管状态；不执行线路检查 |
| `terminal uninstall` | 核对后恢复原始符号链接，保留工作区和 Surge 规则；不覆盖外部改动 |
| `terminal version` | 验证安装记录并输出缓存的原生 CLI 版本，不执行原生程序 |
| `guard-status` | 读取现有状态文件并计算最近回执是否有效，不执行新的网络检查、不证明当前进程存活 |

网页入口不接受额外参数。CLI 额外参数必须放在 `--` 后。`--settings VALUE` / `--settings=VALUE` 只接受通过 `launch_settings_safe` 的内联 JSON，不接受文件路径，避免检查后文件变化；`--setting-sources` 的两种形式只接受 `user`、`project`、`local` 的非空、无重复组合。内联及磁盘 settings 均拒绝覆盖 `BROWSER`、`CLAUDE_CONFIG_DIR`，不允许解除更新禁用、设置非专用代理或非空绕过列表，也拒绝其他模型服务与远端启动冲突。Orca 命令发现使用的 `{"disableAllHooks":true}` 可以通过语义检查。启动前仍检查工作区、项目祖先目录与文件形式的托管 settings；检查不会运行其中的 hooks。

`remoteControlAtStartup` 的用户/项目原设置保持不变；受保护启动只在该子进程的内联 settings 中合并 `remoteControlAtStartup:false`。CLI 同时设置 `forceLoginMethod:claudeai`，只支持订阅 OAuth / setup-token，阻止项目或参数改用 Console 和其他认证来源。显式 CLI 远端入口、内联 settings 要求开启，或企业托管 settings 强制开启时仍拒绝，不能通过覆盖用户文件绕过托管策略。

CLI 成功返回 `0`；阻止启动、已捕获的 `Blocked` 返回 `2`；已捕获的系统操作错误返回 `1`。参数解析错误也可返回 `2`。普通报告模式将受监控 CLI 的非零结束映射为 `2`，实际退出码保留在 `child_exit_code`。终端使用的 `--passthrough` 模式会直接转发已启动子进程的退出码；信号退出转换为 `128 + 信号编号`。内部 `surge_cc.guard` 进程另返回其监控会话退出码，不是公共 GUI 控制 API。

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

v0.3.0 在已确认 `Surge.mode=proxy`（全局代理）时返回挂起报告：`ok:false`、必需 `mode` 行 `status:"fail"`，并包含 `paused:true`、`pause_reason:"surge-global-mode"`、`surge_mode:"proxy"`、`launch_allowed:true`、`protection_active:false`。`check` 仍退出 `2`，不执行后续浏览器/DNS 探针；但 `launch` 可按明确的全局代理分支启动。成功的 GUI 网页/Terminal 启动回执保持这些挂起字段，改为 `ok:true`、`launched:true`、`target:"web"` 或 `"code-terminal"`，退出 `0`。同步 CLI 非零结束不得当作启动成功或检查通过。全局模式流量依 Surge 全局策略，固定出口与断线阻断暂停，工作区与已登记文件隔离保留。

GUI 只有在全部全局挂起字段类型和值一致、检查行非空且 ID 唯一、状态有效、必需 `surge:pass` 和 `mode:fail` 存在且其他必需项全部通过时识别「保护已挂起」。检查回执须为 `ok:false` / 退出 `2` / 未启动；成功启动须为 `ok:true` / 退出 `0` / `launched:true` / 已知 GUI 目标。缺字段、未知原因、直连冒用全局标记、矛盾退出码或其他必需失败均按阻止处理，不能变为绿色检查通过。

`direct`（直连）保留 `paused:true`、`pause_reason:"surge-mode"`、`surge_mode:"direct"` 的阻止启动报告；未知或不可读取模式是一般失败。切回规则模式后重新检查恢复保护；没有自动切换 Surge 模式的命令。

默认严格模式让 DNS 接管、浏览器 ICE 等无法确认项阻止启动。已观察到预期出口之外的公网 ICE 地址始终是必需 `fail`，关闭严格模式也不放行。浏览器有显式语言或时区预期时，其回执行始终必需；缺失为 `unknown`，不一致为 `warn`。系统环境和 GeoIP/ASN 的显式预期同样产生必需比较。

0.2.3 的 `dns_egress` 经固定专用 HTTP 入口执行 dnsleak.dev 随机域名权威观测。完整、有效、前后保护与实际出口一致且服务分类为 `no_leak` 的回执显示非必需 `info`；`split` 为非必需 `warn`；不完整、超时、限流、无结论为非必需 `unknown`。专用范围、实际出口或配置稳定性核验失败是必需 `fail`，撤回启动资格。快速检查与 OAuth 内部复核不执行此补充检测，保留 `unknown` 而非复用缓存。递归器 IP 不必等于住宅代理 IP；`info` 仅为本次专用代理链的观测，不证明全系统无泄漏。FakeIP 接管与权威观测分别展示。

IPv6 清单将地址区分为公网单播、链路本地、ULA（`fc00::/7`）、回环与其他，并依据接口名称／标记区分物理、utun 隧道、回环与其他接口。非 utun、非回环接口存在公网单播地址或默认路由时保留非必需 `warn`；未知接口类别按非 utun 保守处理。仅本地地址、utun 路由或无可见路径时为非必需 `info`，不称作无旁路证明。无法完整读取或解析接口／路由时仍为 `unknown`，按 `privacy_strict` 决定必需性。系统路径清单不替代 IPv6 HTTP/UDP 或浏览器实测，也不确认 utun 属于 Surge。

STUN 错误、超时、缺少完整回执或格式损坏始终为 `unknown`。无公网 ICE 候选或只有本地/mDNS 候选，仅在调用方独立核验专用范围后才有条件通过，具体合约如下。

`settings` 含本地名称、配置路径、实际预期 IP 等私有信息，输出供本地界面读取；分享前需脱敏。不能因为数据来自工具就将其视为非敏感。

## 独立浏览器与 WebRTC 合约

`core.browser_executable(config)` 在 `browser_path` 非空时选择该二进制，否则回退到原 `/Applications/Google Chrome.app` 路径。独立浏览器应是官方 Chrome 应用的完整副本，包名为 `Surge CC Browser.app`；没有自动下载、复制或更新操作。只使用另一个 `--user-data-dir` 而仍运行个人 Chrome 二进制，不能得到进程路径隔离。

`containment.validate_scope` 是只读验证。非空 `browser_path` 启用必需的 `browser_containment` 检查：要求 Surge `mode=rule`、`enhanced-mode=true`，当前配置路径匹配（如果已指定），固定组只有一个指定节点且已选中。专用 HTTP 入口必须监听字面回环地址，端口不能为原有 `6152/6153`，不能带入口认证或同端口公开监听。生效规则开头必须依次为：

```text
IN-PORT,<专用端口>,<固定组>
PROCESS-NAME,<Surge CC Browser.app 绝对路径加尾随斜杠>,REJECT
PROCESS-NAME,<cli_process_paths 中的第一项>,REJECT
…其余已配置 CLI 路径逐项排列…
```

`cli_process_paths` 为空时不生成后续 CLI 路径行。范围核验确认副本主程序及包内 Helper，以及配置范围内的原生 Claude 程序，调用 Surge 路由解释检查原始 TCP/UDP、STUN、QUIC 和 IPv6 的拒绝判定，以及专用端口的 HTTP/HTTPS 固定路由；核验结束再比较配置与组状态。个人 Chrome、Ghostty、Orca 及共享 Node/Python 路径不在拒绝范围内。CLI 路径匹配仅拒绝该范围内被 Surge 接管的旁路连接，不继承到任意 MCP 或其他子进程，也不保证阻止原始二进制启动。

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
- 工作区响应包含 `current_workspace` 和 `workspaces` 数组，每项含 `name`、`label`、`snapshots`、`route`、`route_configured`、`auth:{workspace,mode,configured,legacy_reference}`、`browser:{has_profile}`；快照项为 `id`、`label`、`created_at`。新工作区未使用时 `route` 可为 `null`。认证模式 `oauth` 的 `configured:true` 只代表显式方式记录存在，`browser.has_profile` 只代表目录存在，两者均不证明已登录。成功回执中的 `settings` 是当前有效配置；GUI 不把目标缺失设置替换为旧账号配置。
- 保存快照另带 `snapshot:{id,name,label,created_at}`；恢复另带 `restored` 和自动备份快照 ID `backup`。
- 修复预览返回 `plan_id` 和 `actions:[{id,title,detail}]`。`plan_id` 绑定配置、源文件、生效配置、模式、组状态和动作；执行前重算，变化则拒绝。公开回执不含完整配置文本。
- `browser_path` 非空时，修复计划额外绑定增强模式状态；`scope` 动作恢复独立监听及置顶范围规则，`enhanced-required` 表示增强模式前提不满足，应用在任何写入前拒绝执行，不自动切换该全局开关。
- 修复执行返回 `actions`、`backup_created`；操作完成不意味着完整线路检查通过，需重新 `check`。
- `guard-status` 返回 `guard` 汇总和按时间倒序的 `guards`。`guard` 含 `running`、`interval`、`last_checked_at`、`detail`；挂起汇总包含 `state:"suspended"`、`running:false`、`protection_active:false`、`suspended:true` 和 `suspended_sessions`。保护与挂起会话混合时分别说明，不能将挂起会话显示成受保护。`running` 是“收到近期有效运行回执”的兼容字段，**不是已验证的当前进程存活状态**。
- `terminal install` / `status` / `uninstall` 的操作回执含 `terminal:{ok,installed,summary}`；安装有效时还带本机 `command_path` 与 `original_path`，公开分享前需脱敏。`installed:true` 与 `ok:false` 表示存在但无法验证的集成，不表示可安全启动。

## 运行监控合约

`guard.run_guarded` 在启动前持有工作区共享锁，执行基础线路复核、建立运行基线并再次检查出口。它只持有自己 `Popen` 创建的独立会话子进程，不根据保存的 PID 或通用进程名终止其他程序。网页子进程若立即退出或交接而无法持续持有，不算已建立监控会话。

`RuntimeChecker` 保存配置路径、组状态和生效配置摘要，周期复核：规则模式、单节点拓扑、选中节点、完整配置摘要、本地端口属于 Surge、所有基线域名的该目标程序路由，并在规定周期核对实际出口。`browser_path` 非空时额外要求增强模式有效，并逐轮调用 `validate_scope`；异步路由/出口检查结束后复读配置基线。它不周期重跑 DNS、WebRTC、语言、时区、GeoIP/ASN 或所有项目文件审计。

默认巡检目标间隔为 `guard_interval=10` 秒；出口复查为 `max(30, guard_interval)` 秒。每次检查完成后再计算下一轮，检测耗时会增加实际间隔。检查错误或未知异常触发清理；停止先 TERM，必要时核对仍属于自身后 KILL。清理失败使用 `stop_failed`，不会报告已确认停止。

运行期间，监控在轮询识别到全局代理模式后挂起固定出口与断线阻断，允许已持有会话继续运行，并记录 `suspended` 状态。切回规则模式后，监控在轮询识别到变化后重新核验保护前提，通过后恢复运行保护，失败则停止对应受控程序；直连和未知模式仍触发停止。模式切换与监控响应之间存在轮询延迟，不是切换瞬间的原子防火墙操作。挂起不修改 Surge 模式、策略或个人 Chrome，也不移除已登记文件隔离。

私有状态/回执字段：`schema`、`target`、`state`、`ok`、`checked_at`、`detail`，不存 PID、CLI 参数或配置明文。可能状态为 `starting`、`running`、`suspended`、`exited`、`blocked`、`stopped`、`stop_failed`。首次有效 `running` 或 `suspended` 回执确认对应模式下的启动；`suspended` 不能作为保护已生效的证据。后续状态文件记录监控进展。`guard-status` 仅在 `state=running` 且时间差处于 `0..max(90, guard_interval*3)` 秒时视为近期回执，负时间差或过期不计入。

网页使用独立监控进程，GUI 退出不自动停止它。CLI 监控在终端前台生命周期内同步执行。SIGINT/窗口大小变化可转发给子进程，正常停止会清理自有子进程；外部强杀、崩溃、系统问题或子进程脱离不构成可保证的即时网络阻断。

## 工作区、修复与安全边界

工作区分别保存 `workspaces/<name>/data/Browser`、`data/Claude` 和 `data/Auth`，旧版 `data/OAuthBrowser` 原样保留。浏览器继续使用已有 `Browser/Default`，不复制 Cookie。OAuth 的原生安全存储路径由 `auth_directory` 确定：新账号使用本账号 `data/Auth`，迁移保留的旧非 Token 账号可使用 `data/Claude`。同一工作区的普通与隔离 CLI 共用此逻辑范围，其他账号不回退到它；原生钥匙串与沙箱内文件回退不会自动同步，可能需要分别授权。每工作区的 `keychain-auth.json` 保存在 `data` 外，只记录模式和钥匙串引用；新 Token 服务为 `surge-cc.workspace-oauth-token`，账号键从配置目录与工作区派生。具体安全输入与失败边界见 [TOKEN-AUTH.md](TOKEN-AUTH.md)。

`migrate_accounts` 在旧全局 Token 引用上记录一次归属：只绑定迁移时当前工作区，保留旧条目，不读取 Token、不复制登录资料。新工作区第一次使用仅将当前线路值复制为独立设置；B 不继承 A 的浏览器或凭据。首次迁移时未启用旧 Token 的原工作区会记录 `native_storage="Claude"`，保留旧 `data/Claude` 及其原生钥匙串命名空间；启用旧 Token 或已有迁移记录未包含该字段时使用 `data/Auth`。无关的全机或项目共享 OAuth 存储不复制、不删除。已有 Token 继续由启动器注入普通及隔离 CLI。

切换持有账号独占启动锁。新启动持有账号共享锁直到 CLI 监控已接管子进程（先 `oauth.set_child` 后释放启动锁）或网页监控已返回有效回执，防止在账号选择与实际启动之间切换。`--close-sessions` 写入私有停止代次，监控轮询时仅结束自己创建的程序；切换器不从回执 PID 批量杀进程。等旧及目标工作区 session 锁均可独占、确认浏览器锁无活动持有者后，才准备目标线路与账号提交。旧监控不响应、归属不明或锁未释放时拒绝切换。停止不保存网页草稿或恢复 CLI 任务，GUI 会先确认；失败时已退出的程序不自动重启。

线路变化经 `workspace_routes.activate` 处理本地配置的专用入口、对应组与 Claude 域名规则，保留其他节点及无关配置。先备份与语法校验，再重载、选中目标节点并核验；失败尝试撤回可确认的本次改动。观察到外部并发更改时不强行覆盖。全局模式维持 `proxy` 状态，固定出口保护仍挂起；直连/未知状态不切换。Surge 配置路径或模式在过程中变化会阻止提交。相同线路不用重载；重载可能使其他既有连接短暂重连。

快照只复制工作区 `data` 并校验清单，不包括根目录认证引用、线路设置、系统钥匙串 Token 或工作区外项目。原生 OAuth 在所选认证目录的明文回退文件（`data/Auth/.credentials.json` 或迁移保留的 `data/Claude/.credentials.json`）和浏览器登录资料可能包含在快照中，须私下保存。恢复不覆盖钥匙串引用，也不会切换另一账号；OAuth 在钥匙串中的原生值不会随文件快照恢复。快照和恢复要求工作区独占锁，恢复前自动备份并保留 `previous-*`。这些是本地账号数据分离，不是独立系统用户、设备身份或服务端不关联保证。

`launch code` 保留 `Path.cwd()`。对没有启用下述登记文件沙箱的普通项目，独立 `CLAUDE_CONFIG_DIR` 不限制 CLI 可读取的文件，不过滤 `CLAUDE.md`、项目 `.claude`、Git 历史、恢复会话或工具输出。`--resume`、`--continue` 等参数没有被统一禁止。普通项目先过滤已知的认证覆盖变量，再设置固定代理并清空绕过列表；启动分支以当前工作区覆盖继承的 `CLAUDE_CONFIG_DIR`、`CLAUDE_SECURESTORAGE_CONFIG_DIR`、`BROWSER` 与更新变量，原父进程环境保持不变。Orca 继承的旧账号目录不能选择子进程账号；内联和项目 settings 若试图覆盖这些受保护字段仍拒绝。其余环境不是完整白名单，也不构成文件内容过滤。`code_settings_ok` 检查已知冲突设置，不是项目内容审计或文件沙箱。

`workspaces.prepare_browser_language` 保留旧函数名，实际在共用浏览器租约内、专用浏览器未运行时更新上述 WebRTC 偏好并清空 URL 覆盖，保留其他字段。仅显式浏览器语言非空时才同时更新 `intl.accept_languages` 与 `intl.selected_languages`；空语言不改原语言值。兼容函数 `prepare_oauth_browser` 对同一份 `Browser/Default` 使用相同的偏好准备函数；真实授权和网页运行使用 `browser_session`，在进程整个生命周期持有租约。两类窗口复用同一份持久化资料，不复制 Cookie、localStorage 或登录信息；本工具不修改网站自己的语言设置。检测进程使用新的临时空白资料和同样的 WebRTC、显式语言设置，没有复制已有工作区的扩展、策略或其他偏好，回执不能声称完全代表已保存浏览器。

修复只针对当前明确路径下的普通本地 Surge 配置，拒绝托管配置。修改前私有备份并语法校验，执行前重核计划；失败尝试回滚，不覆盖观察到的并发修改。修复可能重载 Surge、改变规则模式或指定组选择，不能描述为只读动作。系统时区、地区、IPv6 和其他无关系统设置不由修复工具自动改动。

`containment.patch_profile` 本身只生成配置文本；`repair-plan`/`repair` 在 `browser_path` 非空时将它接入候选生成，保证专用 `IN-PORT`、浏览器包路径和已配置的 CLI 路径 `PROCESS-NAME REJECT` 排在域名修复之前。范围缺失、错序或当前生效核验失败产生 `scope` 动作，保留原监听入口与无关规则；应用后调用完整 `validate_scope`，失败尝试回滚。发生重载时先进行有界就绪等待（最多约 5 秒的等待间隔，另加查询耗时），确认规则模式、增强模式及置顶范围规则恢复，再核验完整范围。这个等待不把失败自动转为通过。

无 `browser_path` 时维持常规修复行为。浏览器副本安装和增强模式开启不由修复器自动完成；增强模式未确认时计划包含 `enhanced-required`，写入前阻止执行。规则模式切换仍作为独立动作显示在预览中。模块或临时规则覆盖若没有被本次配置修改解决，应用后的范围核验仍会失败，不能沿用此前通过结果。

后端不需要 Surge HTTP API 密钥，不安装 root 守护服务。GUI 使用动态检查行，不缓存启动许可；打开 GUI 不自动启动 Claude。所有保护均为有限观测与进程管理，不是系统防火墙、完整防泄漏证明、身份隔离保证或账号封禁保证。实际验证记录由 [VALIDATION.md](VALIDATION.md) 单独维护。

## 已登记项目文件沙箱

v0.2.5 的 `isolation` 模块是可选的高级功能。只有 `launch code` 的当前目录被登记或识别为登记项目的关联工作树时才启用。GUI 选择目录、终端入口接管及 A/B 工作区本身不完成登记；目前没有公开登记命令、迁移工具或设置界面。

维护者需在 `config.json` 同目录准备私有 `isolation.json`，并事先建立项目副本和主项目运行目录。下面仅展示格式；所有路径须替换为本机绝对路径，不展开 `~` 或环境变量：

```json
{
  "schema": 1,
  "root": "/Users/example/Documents/Codex/Claude-Isolated",
  "projects": [
    {
      "id": "demo",
      "path": "/Users/example/Documents/Codex/Claude-Isolated/projects/demo",
      "home": "/Users/example/Documents/Codex/Claude-Isolated/.runtime/demo/home"
    }
  ]
}
```

登记文件须由当前用户拥有、权限 `600`、普通单链接文件；项目 ID 匹配 `[a-z][a-z0-9-]{0,39}` 且不重复。`path` 与 `home` 必须严格对应 `root/projects/<id>` 和 `root/.runtime/<id>/home`，所有相关目录由当前用户拥有、不可由其他用户写入、路径不经过符号链接；运行目录采用私有 `700` 权限。登记过程不应把个人 HOME、原始项目或浏览器数据作为运行目录。

默认 `~/Documents/Codex/Claude-Isolated` 属于保留隔离范围。保留范围、已登记范围或带隔离标记的项目在登记缺失、路径不符、权限不安全时拒绝启动；不会因为无法核验而按普通项目启动。普通范围内没有登记或标记的项目仍沿用常规行为。

### Orca 关联工作树

自动识别仅支持 `~/orca/workspaces/<项目目录>/<工作树目录>` 两层布局。关联工作树根目录需保留以下标记，其中 `project` 对应登记 ID：

```json
{"schema":1,"project":"demo","requires_registered_launcher":true}
```

文件名为 `.surge-cc-isolated.json`。标记不构成授权凭据；启动器还必须核对工作树 `.git` 指向已登记主项目的 `.git/worktrees/<条目>`，该条目 `commondir` 指回同一主项目 `.git`，`gitdir` 指回当前工作树 `.git`。相对路径允许规范化，但任何链接穿越、其他项目关联、受保护目录重叠或缺失标记均拒绝。判断只读取受限大小的元数据，不为探测项目而运行 Git hooks。

工作树 HOME 位于 `root/.runtime/<id>/worktrees/<路径摘要>/home`，由启动器在核验后创建；它不会复制主项目 HOME、旧会话或凭据。每次启动在路径发现和生成沙箱策略前分别复核关联。主项目工作文件和其他工作树 HOME 不因此开放。

### 共享项目会话

此功能为已登记文件隔离项目的独立选择，默认关闭。管理程序先排空旧 Claude 写入进程，在 `workspaces.account_switch` 和受影响工作区独占会话锁内，为各项目与账号调用 `shared_history.initialize(bound_project)`。该方法仅复制现有隔离 HOME 的 UUID 会话 JSONL、对应 `subagents` 和 `tool-results`，包括已移除工作树留下的 HOME；不读取旧全局 `~/.claude`。原文件不改动，相同目标的内容冲突、链接、权限异常或迁移期间源变化均阻止发布。

全部目标初始化成功后，管理程序原子写入隔离根的私有 `.runtime/shared-history.json`：

```json
{"schema":1,"projects":[{"id":"vv","path":"/absolute/isolated/projects/vv"}]}
```

每个条目必须精确匹配登记文件，不能使用通配符或路径别名。会话库为 `.runtime/<id>/conversation-history/<workspace>/data`，初始化收据保存在 `data` 外；子进程只获得当前项目与账号 `data` 的读写权限。启用但缺少初始化收据时阻止启动。未来新增账号也必须先显式初始化，启动器不自动导入或回退。

每工作树仍有独立 `HOME` 和 `CLAUDE_CONFIG_DIR`。启动器将原生 `CLAUDE_CODE_PROJECT_DIR_NAME` 固定为 `surge-cc-<id>`，并只为 `.claude/projects/<该名称>` 建立指向上述库的精确链接；自动记忆通过内联 `autoMemoryDirectory` 保留在当前 HOME 的原主项目记忆目录。共享目录中的 `memory` 明确禁止访问。外部继承的 bucket 变量不能覆盖此选择。

共享会话包含已在对话中出现的内容，不代表能新读取其他工作树源码、HOME、凭据、日志或图片路径。`file-history`、计划和独立 HOME 内的图片不会随会话共享。原生 `/resume` 默认从固定 bucket 读取；`--fork-session` 可用于启动时分支，但不改变交互式 `/resume` 的行为。同一 ID 同时恢复可能交错写入，不保证并发同会话安全。

原 bucket 文件保留作为迁移时的副本，之后新增内容以共享库为准。撤销 opt-in 会回到各 HOME 原有历史视图，不会自动把共享库的新内容拆回去；需要先退出相关会话并备份共享库。此功能仍不包含在 A/B 的 `data` 快照内，需备份隔离根 `.runtime`。已安装的终端后端和 GUI 内置后端应分别核对版本；更新终端后端不会自动重新签名 GUI 安装包。

### 本机跨会话通信

`messaging` 是已登记文件隔离项目的独立 opt-in，默认关闭，与共享历史、默认目录信任分别配置。明确授权后，维护者在隔离根创建私有 `.runtime/messaging.json`：

```json
{"schema":1,"projects":[{"id":"vv","path":"/absolute/isolated/projects/vv"}]}
```

文件须为当前用户拥有、权限 `600` 的普通单链接文件。条目精确匹配 `isolation.json` 中的项目 ID 与规范主项目路径，不接受通配符、重复条目或路径别名。标记缺失或项目未列出时不准备通信空间；标记损坏、权限异常、项目关联或当前账号绑定无法验证时阻止启动。

`prepare_scope(bound_project)` 在 `/private/tmp/surge-cc-ipc-<uid>/<scope-hash>/` 准备私有短目录，其中 `scope-hash` 由登记主项目路径、启动器配置路径和当前工作区身份共同派生。同项目、同账号的主目录与关联 Orca 工作树使用同一空间；不同项目、账号或配置目录使用不同空间。父目录及子目录要求当前用户所有、权限 `700`，私有 `binding.json` 验证精确归属。启动器检查 Unix socket 路径长度，不能安全使用短路径时拒绝启动，不回退到其他共享临时目录。

子进程的 `XDG_RUNTIME_DIR` 固定为该短目录，原生 socket 位于其 `cc-socks/` 下。`prepare(bound_project)` 在完成当前独立 HOME 的准备后，仅把 `.claude/sessions` 精确链接到此空间的 `sessions/`，共享本地会话发现及握手元数据。它不共享整个 HOME、源码访问、账号登录凭据、设置、自动记忆或调试日志；历史对话是否共享仍由 `shared-history.json` 决定。继承环境中的其他 runtime、socket 或消息令牌不能选择通信空间。

首次切换前应正常退出相关旧 Claude 进程。若当前 HOME 已有原生 `sessions/` 目录，启动器检查其中 PID；任何活动进程、无法确认的进程状态、不认识的文件或不安全链接均阻止替换。确认失效的目录保留为同 HOME 下私有的 `sessions-before-messaging-<随机值>` 备份，不把旧发现记录或握手密钥导入新空间。更新不会热修改已运行进程；通信双方需要正常退出后通过新版受控入口重新启动。撤销项目条目只停止后续启动的通信授权，已有进程仍须正常退出。

Seatbelt 仅新增当前空间 `sessions/` 与 `cc-socks/` 的文件读写，以及 `cc-socks/` 路径下的 Unix socket 绑定、接收和发送。通信根目录、绑定文件、其他项目或账号空间不获得内容访问权限；其他工作树源码与 HOME 不因此开放。原有 `127.0.0.1:62919` 专用 TCP 出口、OAuth socket 及本机回调限制保持不变，不扩大 DNS、UDP、其他 TCP 出站或跨沙箱信号权限。它不是整机通用网络隔离，也不改变 Surge 的节点选择、轮询保护或全局模式边界。

本地通信启动设置包含 `isolatePeerMachines:true`、`disableRemoteControl:true`、`remoteControlAtStartup:false` 和 `autoUploadSessions:false`，不因本机消息授权而启用远端控制、跨机器会话发现或自动上传。Claude 原生消息权限确认及等待审批（permission hold）仍保留；Surge CC 不伪造授权或自动批准原生消息。消息中主动发送的内容会被接收方会话看到，但这不赋予接收方额外文件访问权限。此功能针对已接管的原生终端进程，不声明 Orca Native Chat 或未更新的 GUI 内置后端已支持。

### Orca 终端图片粘贴

已登记隔离项目的交互终端使用 PTY 粘贴通道。只有完整 `ESC[200~` / `ESC[201~`（bracketed paste）片段中、内容恰好为当前用户系统临时目录下 `orca-paste-<时间戳>-<UUID>.png` 路径时，才触发图片导入。通道不直接读取剪贴板，不扫描临时目录，也不处理子进程输出。普通键盘输入、其他粘贴内容、管道、`--print` / JSON 协议及认证和维护命令保留原处理方式。

可信启动器检查源文件身份、链接及 PNG 结构，单图最多 **20 MiB**，然后复制到当前隔离 HOME 内本次启动的私有目录，将粘贴片段中的路径替换为副本路径。导入失败时以固定错误文字替换该片段，保留之后的输入；终端转发异常交由现有守护停止受控进程。原 `/var/folders/…/T` 目录及其中其他文件仍不可读，文件沙箱和 SixtyNet 等现有线路保护不因导入而放宽，个人 Chrome 和其他代理服务不受影响。

副本随该项目或工作树的隔离 HOME 保留，以便恢复会话时继续读取；关闭终端不会删除已导入图片。更新后需退出并重新启动已有 Claude 会话才能使用该通道。此支持针对已接管的隔离终端入口，不表示 Orca Native Chat、直接剪贴板读取或 GUI 安装包均已部署、验收。

### 默认目录信任

默认不为新隔离 HOME 继承其他目录的信任。明确授权后，可在隔离根目录的 `.runtime/trust.json` 创建私有配置：

```json
{
  "schema": 1,
  "enabled": true,
  "projects": [
    {"id": "demo", "path": "/Users/example/Documents/Codex/Claude-Isolated/projects/demo"}
  ]
}
```

配置必须为当前用户拥有的普通单链接文件、权限 `600`；路径须规范化且不得经过符号链接。项目 ID 和主项目路径均精确匹配，不接受目录通配符。此文件位于子进程 HOME 外；普通目录启动不会读取它。缺失或 `{"schema":1,"enabled":false}` 表示关闭；配置损坏或权限异常会阻止隔离启动。

启动器在再次核对 Git 双向关联后，仅在当前 HOME 的 `.claude/.claude.json` 中补入 `projects[主项目绝对路径].hasTrustDialogAccepted=true`。Claude Code 2.1.296 对关联工作树使用主仓库路径作为信任键。已有的 `true`、明确的 `false` 及其他字段保持不变；不复制其他 HOME 的账号、凭据、项目条目、会话或日志。信任提示与工具权限、文件沙箱和线路保护独立，此功能不扩大任何文件或网络授权。

将配置设为关闭或移除项目条目，会停止之后的自动信任；已经写入当前 HOME 的信任标记会保留。若要撤销已经建立的信任，应在退出对应 Claude 会话后，将该 HOME 中对应项目的 `hasTrustDialogAccepted` 设为 `false`，启动器不会覆盖该明确选择。

### 实际限制与诊断

原生 Claude 及其子进程通过 `/usr/bin/sandbox-exec` 进入 macOS Seatbelt，可信启动器、线路监控及 OAuth 代理留在沙箱外。沙箱允许当前项目和独立 HOME 读写，以及指定系统工具和必要资源读取；拒绝文件硬链接。关联工作树仅允许共享 Git 对象、引用及少量元数据读取，允许本工作树 `index` / `index.lock` 写入。代码编辑、`git status`、`git diff`、查看历史在支持范围内；提交、推送及修改共享配置须在 Orca 或普通终端中完成，后者不受该沙箱约束。已允许读取的共享 Git 对象可能包含整个仓库历史，不是内容脱敏。

当前沙箱固定允许 TCP 专用入口 `127.0.0.1:62919` 及本次 OAuth 打开器的 Unix socket；配置中的 `proxy_url` 必须精确为 `http://127.0.0.1:62919`。启用本机跨会话通信时，仅额外开放上文指定项目与账号的 Unix socket 目录，不提供任意端口或通用网络授权设置。CLI 可建立本机回调监听，OAuth 代理仍独立核对精确回环端口和进程归属；这不是允许所有 localhost 出站连接。

隔离分支使用最小环境变量集和独立 `HOME`、临时目录及 `CLAUDE_CONFIG_DIR`，不继承原终端的认证令牌、SSH agent 或 IDE 句柄。CLI 配置来源置空、hooks 禁用、MCP 置空，并拒绝额外 settings、目录、插件和 IDE/Chrome 集成参数。系统服务、构建工具、登录与授权可能因此受限；本次只验证了明确列出的命令及边界，不承诺所有工程或交互式登录流程兼容。

在已登记目录可执行 `claude --surge-cc-isolation-check`（需已安装终端接管），或从该目录调用后端 `launch code --passthrough -- --surge-cc-isolation-check`。它先做基础线路检查，再用临时文件、Git 只读命令、原生 CLI `--help` 和网络边界探针返回诊断 JSON；不登录或向模型发送提示词。路径、项目名称及出口等回执信息分享前需脱敏。

常规报告模式的隔离 CLI 会话可带 `file_isolation:{project,root,home,backend,linked_worktree}`；这些字段描述启动方式，不是持续文件审计。文件隔离目录不在 A/B `data` 快照中，需另外备份。绑定迁移时原账号的项目 HOME 原位保留；其他账号使用该项目/工作树的独立 HOME，源码保留。账号的 OAuth 存储经 `auth_directory` 选择本账号 `data/Auth` 或迁移保留的 `data/Claude`，不再跨账号共用旧项目全局认证。普通 CLI 的原生钥匙串与隔离 CLI 的文件回退可能需要分别授权；工作区 Token 模式统一注入。浏览器仍按所选工作区管理，不随项目 HOME 复制。


## 0.4.0 通用配置入口

- `setup doctor --json`：只读依赖与已有节点/策略组名称，依赖缺失返回 `ok:false` 和退出码 2；不声明线路已通过。
- `setup plan` / `setup apply --plan-id`：审核后准备完整专用 Chrome 与当前工作区设置。应用前重复核对摘要；不在此命令隐式修改 Surge。`first-run.sh` 顺序编排后续 repair、终端和项目步骤。
- `project status`、`project plan --source --name`、`project apply --plan-id`：只读盘点、预览和建立隔离副本，原目录不写入；状态变化使计划失效。`--trust` 仅信任明确项目。
- `project enable-plan --name`：读取当前账号已登记隔离 HOME 的候选历史数量；`project enable --name` 在账号及会话排他锁内初始化历史并启用开关。其他项目/账号不混入，旧原始记录保留。`--no-shared-history` 与 `--no-messaging` 表示本次不新增对应功能，不撤销已经启用的功能。
- `shortcut install --name --workspace --start-page --app`：复制发布包的预编译模板并签名，保存安装路径引用，不复制后端。已存在目标拒绝覆盖。`shortcut open --launcher-config --json` 返回原始 `action=focus|needs_switch|blocked`，失败不回退普通浏览器。

配置新增 `default_model`（空字符串为原生默认）、`default_effort`（空或 low/medium/high/max）、`browser_start_page`（claude/newtab），按工作区保存。旧工作区缺字段时使用各自兼容默认，不继承其他账号的值。模型/effort通过JSON设置传给原生CLI，显式CLI参数保留；配置effort时仅在受控子进程移除冲突的继承环境变量。启动页由主启动器和守护共同核对，OAuth单独使用本次授权地址。

`configure --cli-process-path PATH` 可重复提供进程范围，不必手工编辑配置JSON；首次向导从已验证的原生安装生成范围。变更范围后须重新应用并验证Surge规则，保存字段本身不代表保护已生效。
