<img src="app/assets/SurgeCCIcon.png" alt="Surge CC 图标" width="96">

# Surge CC

**在 Mac 上用 Surge 为 Claude 网页和 Claude Code 管理固定线路。**

启动前核对节点和实际出口，检查 DNS 与 WebRTC，通过专用浏览器打开网页及 OAuth 授权，并在运行期间持续检查线路。提供原生 macOS 窗口和命令行。

当前版本：**0.2.3** · macOS 13+ · 发布包为 Apple Silicon · 界面以中文为主

Surge CC 是独立社区工具，与 Surge、Anthropic 或 Google 没有官方隶属关系。它管理本地连接和程序，不提供代理节点，也不保证账号状态或服务资格。

[下载最新版](https://github.com/jsjixu/surge-cc/releases/latest) · [安装与首次配置](#安装与首次配置) · [日常使用](#日常使用) · [检查结果怎么看](#检查结果怎么看) · [常见问题](#常见问题) · [更新记录](CHANGELOG.md) · [验证记录](VALIDATION.md) · [开发接口](INTERFACE.md)

## 能做什么

| 功能 | 行为 |
| --- | --- |
| 固定线路 | 核对单节点策略组、实际选中节点、规则和精确公网出口；不自动接受变化后的 IP |
| 专用网页窗口 | 使用独立 Chrome 应用副本及独立资料目录；通过专用 HTTP 入口访问，核对浏览器旁路拒绝规则 |
| Claude Code 启动 | 注入专用代理环境，启动前复核线路；保留项目目录及终端交互 |
| OAuth 授权 | 从受控 CLI 自动打开专用授权窗口；打开前检查线路，仅放行本次登录的精确本机回调端口 |
| DNS 检查 | 分别检查本机接管迹象和专用代理链的外部 DNS 观测；0.2.3 新增随机域名实测 |
| WebRTC 检查 | 通过临时 Chrome 收集真实 ICE 候选；发现额外公网地址时阻止启动 |
| 运行保护 | 定期复核线路；异常时尝试停止由本工具启动并持有的程序，显示停止结果 |
| 本地工作区 | A/B 浏览器与 CLI 数据目录、快照、恢复；不自动搬移个人 Chrome 或 `~/.claude` |
| 修复预览 | 先列出改动，确认后备份、校验并修复指定组及相关规则；保留无关配置 |

**“异常时停止”有明确范围：** 固定组不含备用节点，专用入口不会主动改走其他出口；进程监控仍有轮询间隔，依赖 Surge 的规则模式、增强模式和有效规则。它不是操作系统防火墙，也不能约束任意忽略代理的 CLI 子进程。完整边界见下文。

## 安装与首次配置

首次配置需要现成的 Surge 节点、本地配置文件和一个独立 Chrome 副本。**下载应用不会自动安装这些依赖，也不会自动修改 Surge。**

### 1. 准备依赖

| 依赖 | 要求 |
| --- | --- |
| macOS | 13 或更新版本 |
| Surge for Mac | 需要可用的 Surge CLI 接口；本版本在 **6.9.1** 上验证。应用应位于 `/Applications/Surge.app` |
| Python | **3.9+**，应用包不内置 Python；GUI 从 `/opt/homebrew/bin/python3`、`/usr/local/bin/python3`、`/usr/bin/python3` 查找 |
| Google Chrome | 官方 Chrome，以及为本工具准备的独立完整副本 |
| Claude Code | 官方本机 CLI；OAuth 打开器行为已针对 **2.1.296** 核对，升级后应重新验证 |
| 代理线路 | 已在 Surge 中可用的节点、已知且稳定的公网出口 IP |

Surge CC 的界面最低系统版本不代表各外部依赖都支持所有旧版 macOS，请同时满足它们的系统要求。

### 2. 安装应用

在 [Releases](https://github.com/jsjixu/surge-cc/releases/latest) 下载 `Surge-CC-0.2.3-arm64.zip`，核对同一版本提供的 SHA-256 校验值，解压后将 `Surge CC.app` 放入 `/Applications`。

发布包只包含 Surge CC，**不包含 Chrome、Python、Claude Code、Surge、节点配置或账号数据**。Intel Mac 可尝试从源码构建；当前发布包和真机验收为 Apple Silicon，不承诺 Intel 已验证。

此应用采用本地 **ad-hoc 签名，未经过 Apple 公证**。macOS 可能阻止首次打开：在核对下载来源和校验值后，可通过「系统设置 → 隐私与安全性」查看并使用系统提供的单个应用打开选项。没有相应选项或仍被系统阻止时，可从源码构建。无需关闭系统整体的 Gatekeeper 保护。

### 3. 准备专用 Chrome

在 Finder 中将官方 `Google Chrome.app` **完整复制**到自己的「应用程序」文件夹，将副本命名为：

```text
~/Applications/Surge CC Browser.app
```

这必须是完整应用副本，不能是快捷方式、符号链接，或仅在个人 Chrome 中新建一个 profile。工具通过不同的应用路径区分专用浏览器及其辅助进程。

不要直接双击这个副本进行日常浏览；完成设置后，从 Surge CC 的网页或授权入口打开。Surge CC 不负责下载、复制或更新 Chrome，使用者需要维护副本版本，并在更新后重新检查。

### 4. 准备 Surge，并保存本工具设置

在 Surge 中准备：

1. 一个已可用的实际代理节点，例如 `Home`。
2. 一个已有且可查询的手动策略组，例如 `Claude`，只包含该节点，不含 `DIRECT` 或备用节点。
3. 规则模式和增强模式保持开启。
4. 一份当前正在使用的普通本地配置文件。自动修复不支持托管订阅配置。

下面是**填写示例，不能原样执行**：将 `Home`、`Claude`、配置文件路径和 `203.0.113.7` 换成自己的值。`203.0.113.7` 是文档占位 IP，不是真实节点。`62919` 是示例专用本地端口，应选择一个未占用、不同于原有 `6152/6153` 的端口。

```sh
SURGE_CC="/Applications/Surge CC.app/Contents/Resources/scripts/surge-cc"

python3 "$SURGE_CC" configure \
  --group 'Claude' \
  --policy 'Home' \
  --expected-ip '203.0.113.7' \
  --proxy-url 'http://127.0.0.1:62919' \
  --profile '/absolute/path/to/surge.conf' \
  --browser-path "$HOME/Applications/Surge CC Browser.app/Contents/MacOS/Google Chrome" \
  --privacy-strict true \
  --guard-interval 10
```

`browser_path` 目前需通过上面的命令行设置；GUI 可以编辑其他线路设置。保存配置只写入 Surge CC 的本地设置，不会应用 Surge 改动，也不代表检查已经通过。

### 5. 预览专用入口规则，检查后启动

打开 Surge CC，进入「保护」中的修复功能，先查看修复计划，再确认应用。修复器可补充专用监听入口、固定域名规则及浏览器旁路拒绝规则；会备份并校验本地配置，重载可能造成短暂重连。

专用范围的核心规则形如下例，并应位于生效规则的前两条：

```ini
IN-PORT,62919,"Claude"
PROCESS-NAME,"/absolute/path/Surge CC Browser.app/",REJECT
```

第一条把专用入口固定到指定组；第二条拒绝被 Surge 接管、但绕过该入口的专用浏览器连接。尾部 `/` 使范围包含应用内的辅助进程。修复器保留原监听入口和无关规则，不需要为了使用本工具删除其他节点。

修复后点击 **「检查线路与隐私」**。展开未通过或未确认项查看依据。必需检查通过后，选择项目目录，再使用「打开 Claude 网页」或「启动 Claude Code」。每次启动都会重新检查，不能凭上一次的绿色状态跳过。

如果使用源码而非发布包，将上述 `python3 "$SURGE_CC"` 换成项目根目录中的 `./scripts/surge-cc`。

## 日常使用

### 网页与 CLI

- **网页：** 从 Surge CC 点击「打开 Claude 网页」，进入专用窗口。
- **CLI：** 先选择项目文件夹，再点击「启动 Claude Code」；Terminal 内部启动前会再次复核。
- **切换工作区：** 在「工作区」选择 A 或 B，只影响后续启动，不迁移正在运行的会话。
- **固定节点：** 「固定指定节点」选择已有单节点组中的目标并重新检查，不修改配置文本。
- **查看保护：** 刷新保护状态，查看最近心跳及时间。关闭 Surge CC 窗口不等于关闭独立网页监控。

个人 Chrome、直接运行的 `claude` 和其他入口不自动纳入保护。

### OAuth 登录

从 Surge CC 启动本机 Claude Code，按官方 CLI 的提示登录即可，无需先打开网页，也无需修改系统默认浏览器。

工具只向这个 CLI 注入私有 `BROWSER` 打开器。收到符合要求的官方授权链接后，核对线路与实际出口，再打开专用授权窗口。普通网页与 OAuth 使用同一独立 Chrome 应用的不同资料目录，首次授权可能需要重新登录。

仅本次授权的精确回调端口可直连，且须确认监听者是当前受控 CLI；不会开放整个 localhost 或局域网。检查失败时拒绝打开，CLI 结束时关闭它持有的授权窗口。

CLI 仍负责 state、PKCE、令牌交换及凭据保存。Surge CC 的启动脚本和状态回执不记录授权 URL、state 或授权码；浏览器登录资料仍由 Chrome 管理。远端、附着、桌面及后台等不支持的入口会被阻止；第三方 MCP OAuth 不在授权白名单中。

### 快照与恢复

先正常结束对应工作区的网页和 CLI，再保存快照。恢复会先校验快照、备份当前数据，并保留替换前目录。

快照可能包含登录状态和工作资料，应私下保存。它不自动备份项目源码目录或系统钥匙串。A/B 是本地目录分离，不是独立设备或身份；系统钥匙串、项目配置和组织设置仍可能共享。

## 检查结果怎么看

界面把结果分成「启动必需」「补充待确认」「补充信息」。**未确认不等于已发现泄漏，信息也不等于完整安全保证。**

| 检查 | 能说明什么 | 不能说明什么 |
| --- | --- | --- |
| 固定线路与出口 | 当前代理入口、规则、节点选择和精确公网 IP 符合配置 | 未来所有时刻都保持相同状态 |
| DNS 接管 | 系统与 Surge 对测试域名的解析存在接管迹象 | FakeIP 不能证明最终递归 DNS 公网出口 |
| 专用代理 DNS 出口 | 一次新建的 12 个随机域名测试，观察权威端收到的解析器查询，并前后核对线路 | 不是整台 Mac 的所有 DNS；解析器 IP 不必等于代理 IP |
| WebRTC | 临时 Chrome 的真实 ICE 候选、错误及完成情况 | 无候选本身不能证明没有旁路；已有资料中的扩展行为也不完全等同于临时探针 |
| IPv6 | 本机接口地址与默认路由的时点清单 | 出现 IPv6 或 utun 不等于泄漏；清单也不是完整 IPv6 外部测试 |
| 时区、语言、地区 | 展示本机或浏览器设置；可与显式预期比较 | 不证明实际所在地，也不会自动改变系统设置 |
| GeoIP 与 ASN | 查询保存的预期 IP 对应的数据库信息，实际出口另行核验 | 运营商品牌、国家标签或 ASN 不证明真实家庭宽带 |

默认开启严格隐私检查：相关必需项无法确认时阻止启动。发现额外公网 ICE 地址时，即使关闭严格检查也会阻止启动。预期时区、地区、国家、ASN 和浏览器语言留空时不作所在地推断；填写后相应比较会参与启动判断。

DNS 外部观测是补充诊断。服务返回完整有效结果且前后线路一致时，显示「已实测」，可展开查看时间、解析器与范围。`split` 提示核对分流；`inconclusive`、超时、限流、截断或结果不完整均保留未确认。观测过程中实际出口、保护范围或配置发生异常则为必需失败，撤回启动资格。

DNS 的地区及 Anycast 标签不单独作为泄漏依据。权威端看到解析器的 IPv6 地址，也不证明 Mac 的 IPv6 绕过了代理。

## 断线保护的范围

专用入口固定到只有一个节点的组，不配置自动备用出口；浏览器同时使用显式 HTTP 代理、禁用 QUIC、限制非代理 WebRTC UDP，并核验 Surge 对专用应用旁路连接的拒绝规则。

运行监控默认每 **10 秒**检查一次，实际出口目标复查间隔至少 **30 秒**，检测命令自身耗时会延长间隔。发现异常或无法确认时，尝试结束它持有的程序并记录结果，不通过进程名关闭个人 Chrome。

以下情况不能承诺即时断网：

- Surge 被关闭、增强模式失效，或实际流量没有被 Surge 接管。
- 轮询尚未发现变化，监控进程被强杀，或子进程自行脱离。
- CLI 的 MCP、外部脚本等忽略代理环境，或从其他入口启动的程序。

运行巡检不重复 DNS、WebRTC、时区或 ASN 全套测试，也不持续抓包。即使本次检查通过，也不是全系统防泄漏证明。详细实现约束见 [INTERFACE.md](INTERFACE.md)。

基线域名包括 `claude.ai`、`claude.com`、`platform.claude.com`、`code.claude.com`、`api.anthropic.com`、`console.anthropic.com`、`statsig.anthropic.com`、`claudeusercontent.com`、`claudemcpcontent.com`、`claude.app`。可扩展清单，不能移除基线；清单不能保证覆盖未来新增域名和第三方资源。

## 常见问题

**为什么提示 DNS 未确认？**

可能是外部服务限流、超时、回执不完整，或没有配置专用浏览器范围。展开该行查看原因，恢复条件后重新完整检查。不要用修改文案或关闭严格检查代替排查。递归器地址与代理出口不同本身正常。

**为什么提示专用窗口仍在运行或有锁？**

先正常关闭该工作区的网页和授权窗口，再重试。工具不会接管不明浏览器实例，也不自动删除未知锁。仍存在时，保留资料，核对对应进程是否退出。

**必须更改系统时区、语言或关闭 IPv6 吗？**

不需要。工具只读展示这些设置，修复器不会自动修改它们。填写预期值仅用于比较。

**会影响现有节点吗？**

检查本身不修改 Surge。确认修复后，会修改指定组、相关规则及专用监听入口，并可能重载配置；无关节点定义和规则会保留。应用前请核对计划。托管配置、模块或临时规则覆盖可能需要手动处理。

**代理 IP 变了怎么办？**

工具会阻止启动。先确认变化原因；确实更换了自己的出口后，更新预期 IP 并重新检查。工具不会自行把新地址视为可信出口。

**没有独立 Chrome 可以用吗？**

留空 `browser_path` 时存在普通 Chrome 兼容路径，但没有独立应用范围核验。专用浏览器保护、DNS 外部观测和受控 OAuth 按本 README 的完整配置使用，不应把兼容路径理解为同等保护。

## 数据与隐私

默认数据位于 `~/Library/Application Support/Surge CC/`。自定义配置路径时，数据使用其父目录。

| 位置 | 内容 |
| --- | --- |
| `config.json` | 本工具设置，文件权限 `600` |
| `workspaces/<名称>/data/` | 专用网页、OAuth 和 CLI 数据 |
| `workspaces/<名称>/snapshots/`、`previous-*` | 快照及恢复前保留数据 |
| `sessions/` | 会话配置副本、启动回执及监控状态 |
| `repair-backups/` | 修复前配置备份，可能含代理凭据 |
| `launchers/` | 用后清理的临时 Terminal 启动脚本 |

检查会在内存中读取可能包含节点凭据的 Surge 配置，不输出完整配置。JSON 诊断仍可能含本地路径、组名及真实出口 IP，分享前需要脱敏。不要将工作区、快照、配置、备份或 `.local/` 上传到公开仓库。

检查涉及以下外部服务：

| 服务 | 用途与披露的数据 |
| --- | --- |
| `api.ipify.org` | 测量公网出口，服务可见请求来源 IP |
| `api.anthropic.com/v1/models` | 无登录凭据的 HTTPS 连通性请求；401/403 只说明收到响应，不代表账号可用 |
| `ipwho.is` | Surge 数据库查询无有效结果时的备用 GeoIP/ASN 查询，查询保存的预期 IP |
| Google STUN | 浏览器 ICE 探测；可能发送 UDP，服务可见该次实验的来源地址 |
| `dnsleak.dev` / `*.t.dnsleak.dev` | 随机域名权威观测，可见代理出口及解析器查询；不发送 Claude 账号、会话或项目内容 |

DNS 观测每次新建测试，不复用旧报告，不直连回退、不跟随跳转、不跳过证书验证；快速检查、运行巡检和 OAuth 内部复核不重复此补充测量。第三方服务的处理方式见其 [API 文档](https://dnsleak.dev/api) 与 [隐私说明](https://dnsleak.dev/privacy)。

工具还会通过系统和 Surge 解析器查询 `claude.ai`，并用带随机令牌的本机回环服务接收临时浏览器检测回执。无需 Surge HTTP API 密钥，不安装 root 常驻服务，不自动清理个人账号或系统钥匙串。

## 命令行

以下命令在源码根目录运行。发布包用户可将 `./scripts/surge-cc` 替换成安装步骤中的 `python3 "$SURGE_CC"`。

```sh
./scripts/surge-cc check --json
./scripts/surge-cc pin --json
./scripts/surge-cc launch web --json
./scripts/surge-cc launch code --terminal --json
./scripts/surge-cc launch code -- --resume
./scripts/surge-cc guard-status --json

./scripts/surge-cc workspace list --json
./scripts/surge-cc workspace use --name B --json
./scripts/surge-cc workspace snapshot --name B --label '工作前备份' --json
./scripts/surge-cc workspace restore --name B --snapshot '返回的快照编号' --json

./scripts/surge-cc repair-plan --json
./scripts/surge-cc repair --plan-id '刚核对的计划编号' --json
```

`check`、`status` 和 `checkdetail` 都执行完整实时检查；`guard-status` 才是读取已有监控回执。全局 `--config PATH` 放在子命令前。CLI 在当前目录运行，GUI 使用所选项目目录。

`configure` 还支持 `--expected-timezone`、`--expected-locale`、`--expected-country`、`--expected-asn` 和 `--browser-language`，用空字符串清除预期值。再次配置时需继续传入要保留的 `--profile`，否则清空该路径；省略 `--browser-path` 保留旧值，显式空字符串则取消独立应用范围设置。

Claude Code 参数须位于 `--` 后，不允许临时 `--settings` 或 `--setting-sources` 绕过检查。成功退出码 `0`，检查阻止或受监控会话非零结束为 `2`，捕获的系统错误为 `1`；详细 JSON 和退出码约定见 [INTERFACE.md](INTERFACE.md)。

## 从源码构建

后端仅使用 Python 标准库，界面使用 SwiftUI / AppKit。构建另需 Apple Command Line Tools。

```sh
git clone https://github.com/jsjixu/surge-cc.git
cd surge-cc
python3 -m unittest discover -s tests -v
./scripts/test-gui.sh
SURGE_CC_APP_NAME='Surge CC 0.2.3.app' ./scripts/build-app.sh
```

输出为 `dist/Surge CC 0.2.3.app`，只构建当前机器架构，使用 ad-hoc 签名。构建不会安装、启动应用或修改代理。已有同名输出会被拒绝；用 `SURGE_CC_APP_NAME` 或 `SURGE_CC_DIST_DIR` 选择新文件名或目录，不会覆盖正在使用的应用。

0.2.3 的发布验收记录包括 **291 项 Python 测试**、Swift GUI 契约测试、构建及签名核验，以及专用线路 DNS 真机观测。测试条件和未覆盖范围见 [VALIDATION.md](VALIDATION.md)。

反馈问题时请提供版本、macOS / Surge / Chrome 版本、复现步骤和脱敏后的具体检查项；不要附登录令牌、完整代理配置、个人路径或工作区快照。参与开发请阅读 [贡献说明](CONTRIBUTING.md)。

## 致谢与参考

检查、工作区、修复和运行保护思路参考了 [yoursjeyo/claude-switcher 的 `74ea09e2` 版本](https://github.com/yoursjeyo/claude-switcher/tree/74ea09e2e7db14968548a5fab7b97e96b4b1b330)，Surge 适配为独立实现，行为并非完全一致。

- [Surge 规则文档](https://manual.nssurge.com/rules/overview.html)
- [Claude Code 网络配置](https://code.claude.com/docs/en/network-config)与[设置](https://code.claude.com/docs/en/settings)
- [Chromium 代理说明](https://github.com/chromium/chromium/blob/main/net/docs/proxy.md)
- [图标来源与说明](app/assets/ICON.md)：相关品牌名称和图形属于各自权利人，不表示官方认可。
