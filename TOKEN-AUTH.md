# 每个工作区的 CLI 认证

本文对应 **v0.3.0 / Build 13**。支持 claude.ai 订阅 OAuth 与 `claude setup-token` 生成的长效订阅 Token，不支持 Anthropic Console 账号切换。Token 供 Claude Code 使用，不代替浏览器的 Google 或 Claude 网页登录。有效期和权限由官方服务决定。

## 在 App 内配置

进入「工作区」，先选择要配置的 A 或 B，再查看「Claude Code 凭据」：

- **使用独立 OAuth：** 选择此登录方式，再切换到该工作区并启动 Claude Code，自行完成官方授权。网页与 OAuth 共用该工作区的专用浏览器资料；不会打开个人 Chrome。
- **保存此账号的 Token：** 在安全输入框粘贴已有的订阅 Token，保存到当前选择工作区专属的 macOS 钥匙串条目。输入仅经后端标准输入传递，不进入命令参数、配置、临时文件或回执。此操作不会代你生成 Token、登录网页或验证订阅身份。

修改凭据要求该工作区没有活动会话。选择 OAuth 只改变登录方式，不删除旧钥匙串条目；重新选择 Token 时通过安全输入保存所需值。两种模式都不回退到其他工作区或全机旧凭据。请自行确认浏览器登录和 CLI Token 属于同一账号；应用不会读取邮箱来自动匹配。

## 保存位置与迁移

每个工作区在 `workspaces/<name>/keychain-auth.json` 保存认证方式和钥匙串引用，Token 文本保存在服务名 `surge-cc.workspace-oauth-token` 下；钥匙串账号标识由配置根目录与工作区派生。元数据不是 Token。目录及文件要求当前用户所有、私有权限，并拒绝符号链接等异常访问。

从旧版升级时，旧 `terminal/keychain-auth.json` 中的引用一次性归属升级时的当前工作区。迁移不读取 Token 值，不复制浏览器资料，也不允许 B 自动沿用 A 的旧引用。旧钥匙串条目保持可用；不要手工编辑迁移记录来换账号。

OAuth 的原生安全存储范围由 `auth_directory` 按工作区确定：新工作区使用 `workspaces/<name>/data/Auth`；首次迁移时未启用旧 Token 的原工作区，会记录 `native_storage="Claude"`，保留原有 `data/Claude` 路径及其钥匙串命名空间。已有 Token 的原工作区以及缺少该字段的早期迁移记录使用 `data/Auth`。这些路径不会跨账号回退，也不会把无关的全机或项目共享凭据复制进来。

同一工作区的普通 CLI 与已登记隔离项目使用相同逻辑认证范围，但原生 CLI 在普通环境可能使用 macOS 钥匙串，在文件沙箱内可能使用明文文件回退；两种存储不会自动同步，可能需要分别完成 OAuth 授权。工作区 Token 模式则由启动器统一注入，已有 Token 无需因这次迁移重新生成。

原生 OAuth 的明文回退文件位于所选目录的 `.credentials.json`，即 `data/Auth/.credentials.json` 或迁移保留的 `data/Claude/.credentials.json`，会随 `data` 快照保存。钥匙串 Token 文本、工作区根目录下的认证引用和线路设置不在快照内。

## 终端行为

终端接管必须实际指向包含此功能的后端。受控 CLI 在初始线路检查通过后读取当前工作区的 Token，放入子进程 `CLAUDE_CODE_OAUTH_TOKEN`；运行前仍进行最后一次保护复核。继承的其他认证变量会被过滤，项目和内联设置不能覆盖选定认证来源。Token 存在于 Claude 进程环境中，工具子进程可能继承，不能据此声称进程无法访问凭据。

已登记隔离项目继续各账号各自使用独立 HOME、会话、记忆和日志；源码保持原位置。Token 模式不开放旧 OAuth 凭据读取，原资料不删除、不复制。普通未登记项目没有项目文件沙箱边界。所有受控 CLI 限定 `forceLoginMethod=claudeai`，避免切入 Console 全局登录存储。

后端提供以下接口供 GUI 或安全调用方使用：

| 命令 | 行为 |
| --- | --- |
| `workspace-auth status --workspace NAME --json` | 返回认证模式和配置是否存在，不读取 Token、不证明已登录 |
| `workspace-auth store --workspace NAME --stdin --json` | 只从 stdin 读取 Token，保存钥匙串及工作区引用；不接受 Token 命令参数 |
| `workspace-auth oauth --workspace NAME --json` | 选择此工作区的原生 OAuth 模式，不发起登录 |

日常配置推荐使用 App 的安全输入框，避免把 Token 放入 shell 历史、脚本或剪贴板记录之外的额外文件。

## 失败和恢复

- 钥匙串缺失、锁定、访问被拒绝、读取超时或格式错误时停止启动，不改用 OAuth 或其他账号。
- Token 模式的授权打开器拒绝网页授权；`auth login`、`auth logout`、`setup-token` 和不支持此 Token 的 `--bare` 启动被阻止。需要授权时先显式切回该工作区的 OAuth 模式。
- 服务拒绝或 Token 到期时，由 Claude Code 报告认证失败；不会自动换凭据。
- A/B 切换会结束原受控会话；新启动的网页和 CLI 才使用目标账号。没有热迁移或任务自动重试。

认证方式本身不修改普通浏览器或 macOS 隐私授权。工作区线路切换只处理专用范围；既有规则模式、全局代理模式及文件沙箱限制保持。
