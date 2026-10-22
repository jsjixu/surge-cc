# 首次配置与升级

安装包、GUI、终端入口和 Dock 都使用主应用中的同一套后端。首次准备由随包 `scripts/first-run.sh` 完成，不要求安装 AI skill。

## 开始之前

- 把 `Surge CC.app` 放到最终位置（推荐 `/Applications`）。
- 已安装 macOS 13+、Surge、官方 Chrome、官方原生 Claude Code、Python 3.9+。向导不替用户下载依赖。
- Surge 已运行，开启规则模式、增强模式；当前使用普通本地配置，不是托管订阅。先准备已有节点和已有手动策略组。
- 准备自己节点的准确公网出口 IP。它不是 VPS 中转入口或文档示例地址；动态 IP 改变后需重新核验。
- 对现有安装进行迁移时，先保存并正常退出受控 Claude 和专用网页窗口；不要结束普通浏览器或 Surge。

GUI 顶部点击「配置向导」，或运行：

```sh
/bin/bash "/Applications/Surge CC.app/Contents/Resources/scripts/first-run.sh"
```

脚本依次尝试 Homebrew、`/usr/local`、系统 Python 和开发工具 Python，验证版本至少 3.9。GUI 使用同样的候选路径。缺依赖会说明缺哪一项，不会自动放宽安全设置。

## 向导做什么

1. **只读检查。** 查看依赖、Surge 模式以及可用节点／策略组名称，不输出节点密码。
2. **准备计划。** 输入组、节点、出口；显示专用浏览器路径、端口、模型、Effort、语言和启动页。新配置推荐 `opus` / `high`、`en-US`、新标签页。`opus` 是原生模型别名，具体版本取决于账号；可在 GUI「启动偏好」填精确 ID。
3. **确认本机准备。** 完整复制并验证官方 Chrome 到 `~/Applications/Surge CC Browser.app`；已有副本复用，不覆盖个人 Chrome，不复制个人资料。保存当前工作区设置与原生 CLI 的进程范围。
4. **单独确认线路计划。** 展示现有 `repair-plan` 的修改和备份方案，再应用。限定本工具策略组、域名、专用 `127.0.0.1:62919` 入口及进程拒绝规则；其他节点和规则保持。Surge 重载可能短暂重连。
5. **终端接管。** 明确选择后，将本机 `claude` 接到本工具；已有有效接管更新到当前安装包后端，异常记录会停止处理。
6. **线路检查。** 没有通过就停止，不把文件准备完成误报为网络正常。
7. **可选项目。** 预览文件保留／排除清单，确认后创建副本、交接清单、独立 HOME；可默认信任精确项目，并启用同项目同账号历史和通信。详见 [PROJECTS.md](PROJECTS.md)。需要多个项目可再次运行向导，或用项目命令。
8. **可选 Dock。** 创建自定义名称的 `.app`，引用主应用当前后端。打开后可从 Dock 菜单选择「在程序坞中保留」。

确认前的准备计划含状态摘要。文件、节点配置或原生程序在预览后变化时必须重新预览。目录已存在时不覆盖。已完成的步骤在后续取消或失败时保留，报告指出未完成步骤；重复运行不会清空浏览器登录或已有项目。项目导入会新建 Git 仓库，不带原仓库历史或远端。

账号仍需自己授权：在 Surge CC「工作区」选择独立 OAuth，或通过应用安全输入保存本账号的 `claude setup-token`。Token 不放在命令参数、项目文件或向导配置中。向导不自动登录网页或发送模型请求。

## 只读与分步命令

```sh
APP='/Applications/Surge CC.app'
CC="$APP/Contents/Resources/scripts/surge-cc"
/bin/bash "$APP/Contents/Resources/scripts/first-run.sh" --doctor
python3 "$CC" setup doctor --json
```

以下为**占位示例，先替换节点、出口、配置路径**：

```sh
python3 "$CC" setup plan --group Claude --policy Home \
  --expected-ip 203.0.113.7 --profile /absolute/path/to/surge.conf \
  --default-model opus --default-effort high --browser-start-page newtab --json
```

核对计划后，以相同参数调用 `setup apply --plan-id <plan_id> ... --json`。这一步只准备应用与配置；随后仍需 `repair-plan`、`repair --plan-id`、`terminal install` 和 `check`。普通用户建议用向导，避免遗漏步骤。

## 模型、启动页和 Dock

GUI「设置 → 启动偏好」保存当前账号工作区的模型与 Effort。留空表示原生默认值；可用模型 ID 由实际 Claude 版本和账号决定，工具不承诺某个模型可用。保存后新进程生效，显式 `--model` / `--effort` 可覆盖默认值。

启动页可选 `claude` 或 `newtab`。网页和 Dock 使用同一保存值；OAuth 始终打开本次合法授权地址。已有 Dock 入口保存的页面选项与工作区发生冲突时会提示重新配置，不偷偷使用旧启动参数。

设置启动页后安装入口：

```sh
python3 "$CC" shortcut install --workspace A --name 'Claude Browser' \
  --start-page newtab --app "$APP" --json
```

已有同名入口不会被覆盖，请换名或先自行处理旧入口。它没有自己的后端副本；主应用保持原安装路径时，后续升级自动使用新代码。入口先核对线路；浏览器已运行时验证身份和守护状态后激活原窗口，不强制导航、不打开新的 Claude 标签。目标工作区不同时会提示切换，取消就保持原状。

## 从 0.3.x 升级

1. 保存并正常退出受控会话，保留旧 App 和本工具支持目录的私有备份。
2. 核对新包校验值，在原安装路径更新 App。不要删除浏览器资料、钥匙串或项目运行目录。ad-hoc 签名更新可能需要重新授予该应用权限。
3. 运行新包配置向导。已有线路与偏好保留、完整预览；终端接管可更新到该包。若使用开发者维护的独立终端后端，更新后会指向你本次选定的正式包。
4. GUI 保存希望的模型／Effort；旧配置缺这两个字段时保持原生默认，不擅自强制高成本模型。
5. 已登记项目用 `project enable-plan` 预览并在会话退出后 `project enable`；只处理当前工作区历史。切到另一个账号后需要为该账号单独初始化。
6. 私人定制的旧 Dock App 不自动改写，使用新的通用入口重新创建。
7. 检查路线、用新工作树验证 `/resume`、图片粘贴及通信。不要让两个进程同时写同一恢复会话；并行探索用 `--fork-session`。

## Orca 的 Setup 和使用范围

把隔离副本作为项目添加进 Orca，只有它衍生的、经过 Git 关系核对的工作树进入同一项目范围。副本中保留现有源码和文档，但向导不会复制旧 Orca 自动 setup 配置、运行项目 hook 或替所有工程执行 `pnpm install`。如果项目根目录没有 `package.json`，不要给该根目录配置 `pnpm install`；应使用实际子项目目录中的安装命令。不同项目的依赖初始化仍需按工程说明配置。

支持本机 Orca／Ghostty 调用被接管的原生 `claude` 终端入口；不等于 Orca Native Chat、第三方 CLI、远端机器都已被接管。规则模式下固定出口保护依赖有效规则和 Surge 增强模式；全局模式沿用已有「挂起保护、允许启动」行为。没有把整机权限或其他代理一并改成专用设置。
