# Orca 启动方式与验收范围

Surge CC 接管的是本机 Claude 命令入口，不是 Orca 的整个应用。维护中心可以检查接管完整性和 Orca 本机连接，并使用确定的受控命令路径打开一个新终端。

## 推荐入口

1. 在 Surge CC 选择已登记到 Orca 的本机项目目录。
2. 在维护中心点击 **在 Orca 打开受控终端**。
3. 新终端先检查线路，再启动当前 Surge CC 工作区的 Claude Code。

该按钮使用已核验的绝对命令路径，所以不依赖 Orca 的自定义 Claude 路径或 shell alias。它只创建一个新终端，不向已有任务发送内容，不切换 Orca 的托管账号，也不改变 A/B 登录资料。

Orca 尚未运行时会先启动 Orca。项目目录未登记、属于远端环境、终端入口损坏或绑定其他 Surge CC 配置时，会停止并说明原因。若创建终端的回执丢失，软件不会自动重试，以免重复启动任务；请先检查 Orca 中是否已经出现新终端。

命令行接口：

```bash
./scripts/surge-cc orca status --json
./scripts/surge-cc orca open-terminal --project /absolute/path/to/orca-project --json
```

`orca status` 只读取接管记录和 Orca 本机状态，不启动 Claude，也不读账号凭据或聊天内容。`open-terminal` 的成功回执仅证明终端已经创建；实际线路检查和 Claude 启动结果以该终端内输出为准。

## 发布前实测

以下测试于 2026-10-22 在 macOS、Orca 1.4.237、Claude Code 2.1.296 环境完成。测试使用独立空项目，不向原有任务发送消息。

| 启动方式 | 结果与证据范围 |
| --- | --- |
| Orca 内置终端输入 `claude --version` | 返回版本，版本查询不会启动原生 Claude 或发起登录。 |
| Orca 内置终端输入 `claude --help` | 经过 Surge CC 线路检查，返回原生 Claude 帮助。 |
| 标准新建 Claude 终端路径 | 通过 `orca agent launch --agent claude --surface terminal` 进入受控检查，再到原生 Claude 项目信任界面。未向模型发送任务。 |
| 标准 Native Chat 新建聊天 | 通过 `orca agent launch --agent claude --surface chat` 发出一次“仅回复 OK、不读文件或调用工具”的最小请求；确认进程经过 Surge CC 包装器并启动流式 JSON 原生进程，聊天返回 OK、状态完成。 |
| 在 Orca 终端恢复上述测试历史 | 通过已核验的 Claude 命令入口执行 `--resume <测试会话 ID> --print`，先经过线路检查，再返回 OK。同一会话历史只存在于 A，恢复前后共两条 OK，未调用工具，B 未产生这份历史。此项验证的是 Claude Code 的历史恢复，不是 Native Chat 界面的继续操作。 |
| 维护中心的专用终端入口 | 使用精确受控命令路径创建新终端，经过线路检查并到达原生项目信任界面。 |

这些结果证明上述版本的标准新建流程和同工作区 CLI 历史恢复可以接入；不是对任意 Orca 版本、历史会话或自定义启动命令的保证。测试结束后，仅关闭测试创建的会话，并移除独立测试项目的 Orca 登记。

## 账号和恢复边界

- **Surge CC A/B 与 Orca 托管账号是两套独立选择。** 经过受控入口时，Claude 使用 Surge CC 当前工作区的数据目录和所选登录方式。更换 Orca 账号并不会自动切换 Surge CC A/B。
- Native Chat 的标准新建与最小请求、同工作区 CLI 的 `--resume` 已实测。**Native Chat 界面恢复或继续旧聊天、从其他账号导入历史、Orca 托管账号切换** 尚未完成端到端验收。Orca 1.4.237 的公开 CLI `agent launch` 只提供新建和启动回执重放，没有 Native Chat 恢复入口；`--retry-launch` 不能当作恢复聊天使用。遇到问题可使用维护中心的受控终端，并在 Surge CC 中明确选择 A 或 B 后恢复该工作区内的历史。
- Orca 自定义 Claude 可执行文件、shell alias/function 若直接指向原生版本文件，可能避开已接管的命令。维护中心的专用按钮始终调用已核验的受控入口。
- **远端 Orca、SSH、WSL 和其他机器不在本机接管范围内。** 需要在目标机器独立配置，不能依据本机绿色状态判断远端受保护。
- 规则模式按指定出口检查；用户主动使用 Surge 全局代理模式时，仍沿用保护挂起、允许启动的既有行为。

应用状态页只显示固定的诊断字段、版本和支持范围，不输出 Orca 账号列表、Token、完整原始错误、聊天记录或其他用户任务的命令行。
