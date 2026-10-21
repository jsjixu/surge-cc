<img src="app/assets/SurgeCCIcon.png" alt="Surge CC 图标" width="96">

# Surge CC

**在 Mac 上用 Surge 为 Claude 网页和 Claude Code 管理固定线路。**

启动前核对节点和实际出口，检查 DNS 与 WebRTC，通过专用浏览器打开网页及 OAuth 授权，并在运行期间持续检查线路。提供原生 macOS 窗口和命令行。

当前版本：**0.2.6（Build 9）** · macOS 13+ · Apple Silicon 安装包 · 界面以中文为主

Surge CC 是独立社区工具，与 Surge、Anthropic 或 Google 没有官方隶属关系。它管理本地连接和程序，不提供代理节点，也不保证账号状态或服务资格。

[下载最新版](https://github.com/jsjixu/surge-cc/releases/latest) · [安装与首次配置](#安装与首次配置) · [日常使用](#日常使用) · [检查结果怎么看](#检查结果怎么看) · [常见问题](#常见问题) · [更新记录](CHANGELOG.md) · [验证记录](VALIDATION.md) · [开发接口](INTERFACE.md)

## 能做什么

| 功能 | 行为 |
| --- | --- |
| 固定线路 | 核对单节点策略组、实际选中节点、规则和精确公网出口；不自动接受变化后的 IP |
| 专用网页窗口 | 使用独立 Chrome 应用副本及独立资料目录；通过专用 HTTP 入口访问，核对浏览器旁路拒绝规则 |
| Claude Code 启动 | 注入专用代理环境，启动前复核线路；保留项目目录及终端交互 |
| 终端入口接管 | 可选安装到现有 `claude` 命令，供 Ghostty、Orca 终端和其他调用该入口的本机终端使用 |
| OAuth 授权 | 从受控 CLI 自动打开专用授权窗口；打开前检查线路，仅放行本次登录的精确本机回调端口 |
| DNS 检查 | 分别检查本机接管迹象和专用代理链的外部 DNS 观测；0.2.3 新增随机域名实测 |
| WebRTC 检查 | 通过临时 Chrome 收集真实 ICE 候选；发现额外公网地址时阻止启动 |
| 运行保护 | 定期复核线路；异常时尝试停止由本工具启动并持有的程序，显示停止结果 |
| 本地工作区 | A/B 浏览器与 CLI 数据目录、快照、恢复；不自动搬移个人 Chrome 或 `~/.claude` |
| 浏览器锁修复 | 在 App 内检查专用浏览器残留锁，确认已退出后归档锁链接；保留登录资料及个人 Chrome |
| 项目文件隔离 | 为已手动登记的项目及其 Orca 关联工作树提供独立 HOME 和文件沙箱；不默认启用，见[配置范围](#项目文件与旧会话的边界) |
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

在 [Releases](https://github.com/jsjixu/surge-cc/releases/latest) 下载对应版本的 `Surge-CC-<版本>-arm64.zip`，核对同一版本提供的 SHA-256 校验值，解压后将 `Surge CC.app` 放入 `/Applications`。源码版本与最新公开安装包可能不同，以 Release 页面为准。

**先放到最终安装位置，再配置终端接管。**接管记录会固定应用内后端、Python 和配置文件的绝对路径；不要从下载临时目录安装接管后再移动应用。使用其他安装位置时，后续命令中的 `/Applications/Surge CC.app` 也要相应替换。

发布包只包含 Surge CC，**不包含 Chrome、Python、Claude Code、Surge、节点配置或账号数据**。Intel Mac 可尝试从源码构建；当前发布包和真机验收为 Apple Silicon，不承诺 Intel 已验证。

此应用采用本地 **ad-hoc 签名，未经过 Apple 公证**。macOS 可能阻止首次打开：在核对下载来源和校验值后，可通过「系统设置 → 隐私与安全性」查看并使用系统提供的单个应用打开选项。没有相应选项或仍被系统阻止时，可从源码构建。无需关闭系统整体的 Gatekeeper 保护。

**从旧版升级时，新的 ad-hoc 包可能需要重新授予隐私权限。**构建与下载都不会自动替换本机正在使用的应用。固定证书构建选项已加入，但本次公开安装包仍是 ad-hoc；证书、签名连续性与公证的区别见 [SIGNING.md](SIGNING.md)。

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

下面是**填写示例，不能原样执行**：将 `Home`、`Claude`、配置文件路径和 `203.0.113.7` 换成自己的值。`203.0.113.7` 是文档占位 IP，不是真实节点。常规启动可选择未占用、不同于原有 `6152/6153` 的专用端口；本版本可选的项目文件沙箱目前固定要求 `127.0.0.1:62919`，使用该功能时不能改用其他端口。

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

专用范围的核心规则形如下例，并应位于生效规则的最前面：

```ini
IN-PORT,62919,"Claude"
PROCESS-NAME,"/absolute/path/Surge CC Browser.app/",REJECT
```

第一条把专用入口固定到指定组；第二条拒绝被 Surge 接管、但绕过该入口的专用浏览器连接。尾部 `/` 使范围包含应用内的辅助进程。修复器保留原监听入口和无关规则，不需要为了使用本工具删除其他节点。

安装终端接管时，还需在这两条后添加原生 Claude 程序的旁路拒绝范围，步骤见下文。

修复后点击 **「检查线路与隐私」**。展开未通过或未确认项查看依据。必需检查通过后，选择项目目录，再使用「打开 Claude 网页」或「启动 Claude Code」。每次启动都会重新检查，不能凭上一次的绿色状态跳过。

如果使用源码而非发布包，将上述 `python3 "$SURGE_CC"` 换成项目根目录中的 `./scripts/surge-cc`。

## 日常使用

### 网页与 CLI

- **网页：** 从 Surge CC 点击「打开 Claude 网页」，进入专用窗口。
- **CLI：** 先选择项目文件夹，再点击「启动 Claude Code」；Terminal 内部启动前会再次复核。
- **切换工作区：** 在「工作区」选择 A 或 B，只影响后续启动，不迁移正在运行的会话。
- **固定节点：** 「固定指定节点」选择已有单节点组中的目标并重新检查，不修改配置文本。
- **查看保护：** 刷新保护状态，查看最近心跳及时间。关闭 Surge CC 窗口不等于关闭独立网页监控。

个人 Chrome 不受这些启动规则影响。未安装终端接管时，直接运行 `claude` 不会经过启动检查；安装后，调用被接管的同一个命令入口才会自动检查。

### 在 Ghostty、Orca 等终端中直接运行

自 0.2.4 起提供可选的终端接管。它原子替换当前用户的 `~/.local/bin/claude` 符号链接入口，保存原链接和原始程序信息；不修改整个终端应用的代理，也不改变其他节点或普通浏览器。

安装前先正常结束已有 Claude Code 会话，并确认：

1. 使用官方原生安装，`~/.local/bin/claude` 目前是符号链接；其他安装布局会拒绝自动接管。
2. Surge CC 的 `config.json` 已设置 `cli_process_paths`。常见原生安装使用当前用户 `~/.local/share/claude/versions/` 的**完整绝对路径，并保留尾部 `/`**。不能填写 `~`，也不能把范围设成 Ghostty、Orca、Node、Python 或整个主目录。
3. 执行 `repair-plan` 查看新增的 Claude 程序路径 `PROCESS-NAME,...,REJECT` 规则，确认后执行 `repair`；随后检查通过。这个范围拒绝被 Surge 接管、却没有经过专用入口的原生 Claude 连接。

以发布包为例：

```sh
SURGE_CC="/Applications/Surge CC.app/Contents/Resources/scripts/surge-cc"
python3 "$SURGE_CC" terminal install --json
python3 "$SURGE_CC" terminal status --json
```

安装命令会先确认程序范围及生效规则，才替换命令入口。此后在项目目录正常执行 `claude`、`claude --resume` 或 `claude auth login`，会先经过 Surge CC 检查；登录使用专用 OAuth 浏览器。检查失败时不运行原版 CLI，也不回退到其他命令或浏览器。标准输入和输出保留给 Claude，接管提示及错误写入标准错误。

已实测 Orca 内置终端与交互式 zsh，以及已登记隔离项目的 Orca 工作树启动检查和原生 CLI 帮助命令。Ghostty 窗口因测试工具限制未操作，Orca 新建 Claude 按钮的完整交互流程未验收；接管按命令路径生效，不依赖终端窗口名称。Orca 若设置了其他 Claude 可执行路径，需要先改回被接管的入口；远端 Orca 不在这台 Mac 的接管范围。**Orca Native Chat 和 managed accounts 的账号目录、恢复历史及完整流程尚未验收，不应视作已支持。**普通项目使用所选 Surge CC 工作区的 Claude 数据目录，已登记隔离项目使用其独立 HOME；都不会自动导入原有 `~/.claude` 登录和会话。

**Devin CLI 等其他客户端即使用了 Claude 模型，也不会因此被这个 `claude` 入口接管。**本工具不通过模型名称识别或接管其他程序。

`claude --version` / `claude -v` 仅读取安装时记录并校验过的本地版本，不启动原生程序，也不表示线路检查通过。安装入口变动、备份缺失或原始二进制变化时会拒绝运行；不要手工覆盖包装器。

终端接管保留所有启动必需检查，但跳过可选的外部 DNS 测量，减少终端宿主等待时间。需要查看完整 DNS 观测时，从 GUI 执行「检查线路与隐私」或运行 `check`。

### 更新 Claude Code 或撤销终端接管

受控 CLI 子进程设置 `DISABLE_UPDATES=1` 与 `DISABLE_AUTOUPDATER=1`，并拒绝 `claude update`、`upgrade`、`install`，避免更新器覆盖受控入口。仅对该子进程生效，不修改全局环境。

需要更新 Claude Code 时，先正常结束受控会话，运行 `terminal uninstall` 恢复原始链接；按官方方式维护 Claude Code，再核对原生程序路径、重新检查规则，运行 `terminal install`。维护期间入口没有 Surge CC 启动保护。

```sh
python3 "$SURGE_CC" terminal uninstall --json
```

卸载只恢复自己接管且未被外部改写的入口，不删除工作区、登录资料或项目；不会自动删除 Surge 中的旁路拒绝规则。

### 升级 Surge CC 到 0.2.6

0.2.6 修复了 Mac 重启或卷重新挂载后可能出现的「原始 Claude 程序已变化」误报：原文件没有改变，但挂载设备编号可能变化。新版仍检查原生程序路径、inode、大小、修改时间、所有者和权限，以及原链接备份和包装器；这些检查不一致时仍阻止启动，不会自动更新登记来放行。

**终端接管指向应用包内后端时，可在相同安装路径升级，无需先卸载接管：**正常结束受控 CLI、专用网页和授权窗口，退出 Surge CC；保留旧 App 备份，将新 App 放回原来的完整路径。保持原有 Python 和配置文件路径不变，然后从新 App 执行 `terminal status --json`，再运行 `claude --version` 核对受控入口，最后在 GUI 执行「检查线路与隐私」。版本查询不启动原生 Claude，也不代替线路检查。

如果需要移动 App、改变后端位置，或终端接管指向另行维护的独立后端，单独替换 GUI 不会更新那个后端。将新 App 放到最终位置后，使用**新版**后端撤销旧接管，再安装到新后端。旧版若因设备编号误报而无法卸载，也使用这一流程：

```sh
SURGE_CC="/Applications/Surge CC.app/Contents/Resources/scripts/surge-cc"
python3 "$SURGE_CC" terminal uninstall --json
python3 "$SURGE_CC" terminal install --json
python3 "$SURGE_CC" terminal status --json
```

使用自定义配置路径时，在每条子命令前保留 `--config '/absolute/path/to/config.json'`。只有卸载成功后才继续安装；维护期间不要启动 Claude，安装成功且线路检查通过后再恢复使用。若新版仍报告原生程序或入口改变，应核对实际文件，不要手工修改登记来跳过检查。上述升级保留工作区及登录资料；ad-hoc 签名更新仍可能需要重新授予 macOS 隐私权限。

### OAuth 登录

从 Surge CC 启动本机 Claude Code，或在安装终端接管后执行 `claude auth login`，按官方 CLI 的提示登录即可，无需先打开网页，也无需修改系统默认浏览器。

工具只向这个 CLI 注入私有 `BROWSER` 打开器。收到符合要求的官方授权链接后，核对线路与实际出口，再打开专用授权窗口。普通网页与 OAuth 使用同一独立 Chrome 应用的不同资料目录，首次授权可能需要重新登录。

仅本次授权的精确回调端口可直连，且须确认监听者是当前受控 CLI；不会开放整个 localhost 或局域网。检查失败时拒绝打开，CLI 结束时关闭它持有的授权窗口。

CLI 仍负责 state、PKCE、令牌交换及凭据保存。Surge CC 的启动脚本和状态回执不记录授权 URL、state 或授权码；浏览器登录资料仍由 Chrome 管理。远端、附着、桌面及后台等不支持的入口会被阻止；第三方 MCP OAuth 不在授权白名单中。

如果用户或项目设置启用了 `remoteControlAtStartup`，受保护启动会仅为本次子进程合并 `remoteControlAtStartup:false`，不修改原设置文件。显式 CLI 参数要求远端启动，或企业托管设置强制开启时，仍拒绝启动。

### 专用浏览器语言

在设置中的「专用浏览器语言」填写 `en-US` 可选择美式英语；其他合法语言标签同样支持。正常关闭专用网页和授权窗口后，下次通过受控入口启动时会分别更新它们的浏览器语言。0.2.4 同时写入 Chrome 的语言列表和选中语言，避免旧选中值在重启后覆盖新设置。留空会保留各资料目录原有的语言偏好，不修改个人 Chrome 或系统语言。

**网站界面语言可能另有保存值。**浏览器使用英语并不保证 Claude 页面立即使用英语：网站自己的 Cookie、localStorage 或账号语言偏好可能继续生效。Surge CC 不会自动删除、改写或同步这些网站数据，也不会同步网页窗口和 OAuth 窗口的登录状态。需要时在对应窗口的站点语言设置中单独调整。

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

终端接管增加两层约束：被接管的命令先检查再启动；配置中的原生 Claude 程序路径在 Surge 内拒绝绕过专用入口的连接。直接执行原始版本二进制仍可能启动进程，但其被 Surge 接管的旁路流量应命中拒绝规则。命令接管不等于操作系统禁止运行原始程序，路径规则也不会自动覆盖复制到其他位置的二进制或共享解释器下的其他安装。

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

先正常关闭该工作区的专用网页、授权窗口及受控 CLI。关闭后仍提示有锁，可点击报错下的 **检查并修复浏览器锁**，或进入「工作区 → 当前工作区的浏览器锁」执行同一操作。

修复器会取得工作区独占锁，检查专用浏览器进程、锁中记录的本机 PID 和本地通信端点。确认已经退出才将 `Browser` / `OAuthBrowser` 根目录的三个 Chromium 运行时锁链接移到私有恢复目录，并记录清单。不会结束进程、清除登录资料、修改个人 Chrome 或更改代理。进程仍存在、正在使用工作区、锁来自其他主机或状态无法核实时会保留原文件，显示具体原因。

修复成功不代表线路检查通过；重新点击「检查线路与隐私」后再正常启动。此功能从 0.2.5 开始提供。

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
| `browser-lock-backups/` | 归档的专用浏览器运行时锁及修复清单 |
| `launchers/` | 用后清理的临时 Terminal 启动脚本 |
| `terminal/` | 终端接管清单、原始链接备份及锁；默认位于本工具的 Application Support 目录 |
| `isolation.json`（可选） | 手动登记的项目路径及独立运行目录；不是账号或会话数据 |

检查会在内存中读取可能包含节点凭据的 Surge 配置，不输出完整配置。JSON 诊断仍可能含本地路径、组名及真实出口 IP，分享前需要脱敏。不要将工作区、快照、配置、备份或 `.local/` 上传到公开仓库。

### 项目文件与旧会话的边界

**0.2.5 提供可选的已登记项目文件沙箱，以及 Orca 关联工作树支持。**它使用 macOS Seatbelt，仅限制受控原生 Claude 及其子进程。常规安装、创建 A/B 工作区或复制项目都不会自动启用它。当前没有 GUI 登记向导或公共登记命令，需由熟悉本机文件权限的维护者准备项目副本、私有运行目录及 `isolation.json`；登记格式和限制见 [接口合约](INTERFACE.md#已登记项目文件沙箱)。不要直接把未经审阅的原项目当成已脱敏副本。

启用后，主项目副本及独立 HOME 可读写，其他用户资料默认不开放；启动器使用最小环境变量集并禁用项目 hooks、额外 MCP、插件和 IDE/Chrome 集成。当前实现要求专用代理为 `http://127.0.0.1:62919`，不是任意端口的通用沙箱配置器。原生登录及依赖系统服务的工具也可能受到沙箱限制，未承诺完整交互兼容。

启动器核对 Orca 新工作树与已登记主项目之间的 Git 双向路径关系，为工作树建立独立 HOME。仅复制隔离标记、缺少登记或链接不匹配的目录会被拒绝，不会退回普通启动。

当前支持 Orca 默认 `~/orca/workspaces/<项目>/<工作树>` 目录布局。工作树的源码可读写，共享 Git 对象和引用只读，允许本工作树索引更新；`git status`、`git diff` 和查看历史属于支持范围。提交、推送及修改共享 Git 配置请通过 Orca 或普通终端完成。这些操作在文件沙箱之外执行，不受本工具的文件隔离约束。

工作树使用新运行目录，不自动复制主项目的登录资料、会话和记忆。独立运行目录在登记根目录的 `.runtime/` 下，不包含在 A/B 工作区快照中，应单独私下备份。共享 Git 对象仍可能包含该仓库保留的全部历史；文件沙箱不对已经允许读取的代码或 Git 历史脱敏。

在已登记的项目或关联工作树中，可用已接管的 `claude --surge-cc-isolation-check` 检查文件与网络边界。该诊断执行本机临时文件探针、Git 只读命令和原生 CLI `--help`，也执行基础线路检查；不登录、不向模型发送提示词，结果不等于所有实际工作流程均已验收。

对于未启用上述文件沙箱的普通项目，`CLAUDE_CONFIG_DIR` 只将原生 CLI 的默认数据位置指向所选工作区，**不是文件系统沙箱，也不是内容脱敏器**。CLI 仍在原项目目录运行，可能加载项目及上级目录的指令、设置或记忆，或通过工具读取源码、日志、Git 历史和可访问的其他文件。`--resume`、`--continue` 等参数没有被统一禁用；本工具不会筛除恢复会话中的资料。

普通项目启动器会继承终端环境并覆盖受保护的代理、浏览器打开器、工作区和更新变量；它不会清空所有环境变量，也不移除所有 API Key 或其他凭据。配置检查关注与受控启动冲突的设置，不等同于对 hooks、MCP、工程文件或数据内容完成安全审计。

需要减少旧资料进入新会话时，可另建经过审阅的工作副本，只保留源码、测试、必要文档和技术交接摘要，并使用新会话。需要阻止工具读取副本外的资料时，还应配置实际的文件访问限制；新文件夹、Git worktree、`.gitignore` 或 A/B 工作区本身不提供这一保证。提供给云端模型理解的代码和上下文仍会发送给模型服务。

### 外部检查服务

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
./scripts/surge-cc terminal install --json
./scripts/surge-cc terminal status --json
./scripts/surge-cc terminal uninstall --json
./scripts/surge-cc browser-locks repair --workspace A --json

./scripts/surge-cc workspace list --json
./scripts/surge-cc workspace use --name B --json
./scripts/surge-cc workspace snapshot --name B --label '工作前备份' --json
./scripts/surge-cc workspace restore --name B --snapshot '返回的快照编号' --json

./scripts/surge-cc repair-plan --json
./scripts/surge-cc repair --plan-id '刚核对的计划编号' --json
```

`check`、`status` 和 `checkdetail` 都执行完整实时检查；`guard-status` 才是读取已有监控回执。全局 `--config PATH` 放在子命令前。CLI 在当前目录运行，GUI 使用所选项目目录。

`configure` 还支持 `--expected-timezone`、`--expected-locale`、`--expected-country`、`--expected-asn` 和 `--browser-language`，用空字符串清除预期值。再次配置时需继续传入要保留的 `--profile`，否则清空该路径；省略 `--browser-path` 保留旧值，显式空字符串则取消独立应用范围设置。

Claude Code 参数须位于 `--` 后。`--settings` 只接受通过语义检查的内联 JSON，不接受临时设置文件路径；`--setting-sources` 只接受 `user`、`project`、`local` 的非空、无重复组合。不能覆盖专用代理、浏览器打开器、工作区或更新限制。成功退出码 `0`，检查阻止或普通报告模式的受监控会话非零结束为 `2`，捕获的系统错误为 `1`；终端的 `--passthrough` 模式保留已启动子进程的退出码。详细 JSON 和退出码约定见 [INTERFACE.md](INTERFACE.md)。

## 从源码构建

后端仅使用 Python 标准库，界面使用 SwiftUI / AppKit。构建另需 Apple Command Line Tools。

```sh
git clone https://github.com/jsjixu/surge-cc.git
cd surge-cc
python3 -m unittest discover -s tests -v
./scripts/test-gui.sh
SURGE_CC_APP_NAME='Surge CC 0.2.6.app' ./scripts/build-app.sh
```

输出为 `dist/Surge CC 0.2.6.app`，只构建当前机器架构。默认使用开发用 ad-hoc 签名，更新后可能需要重新授权 macOS 隐私权限。若要使用固定代码签名证书，设置 `SURGE_CC_SIGNING_IDENTITY` 为有效证书的 SHA-1 指纹或精确名称；证书缺失或签名失败会停止，不自动降级。证书申请、首次迁移、升级前连续性验证与公证边界见 [固定签名指南](SIGNING.md)。

构建不会安装、启动应用或修改代理。已有同名输出会被拒绝；用 `SURGE_CC_APP_NAME` 或 `SURGE_CC_DIST_DIR` 选择新文件名或目录，不会覆盖正在使用的应用。

各版本的测试数量、构建与真机验收条件，以及未覆盖的范围见 [VALIDATION.md](VALIDATION.md)。

反馈问题时请提供版本、macOS / Surge / Chrome 版本、复现步骤和脱敏后的具体检查项；不要附登录令牌、完整代理配置、个人路径或工作区快照。参与开发请阅读 [贡献说明](CONTRIBUTING.md)。

## 致谢与参考

检查、工作区、修复和运行保护思路参考了 [yoursjeyo/claude-switcher 的 `74ea09e2` 版本](https://github.com/yoursjeyo/claude-switcher/tree/74ea09e2e7db14968548a5fab7b97e96b4b1b330)，Surge 适配为独立实现，行为并非完全一致。

- [Surge 规则文档](https://manual.nssurge.com/rules/overview.html)
- [Claude Code 网络配置](https://code.claude.com/docs/en/network-config)与[设置](https://code.claude.com/docs/en/settings)
- [Chromium 代理说明](https://github.com/chromium/chromium/blob/main/net/docs/proxy.md)
- [图标来源与说明](app/assets/ICON.md)：相关品牌名称和图形属于各自权利人，不表示官方认可。
