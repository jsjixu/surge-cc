# 参与开发

需要 macOS、Python 3.9 或更新版本，以及 Apple Command Line Tools。核心代码仅使用 Python 标准库；Swift 界面使用 SwiftUI 与 AppKit。

## 本地验证

在项目根目录运行：

```bash
PYTHONPATH=src python3 -B -m unittest discover -s tests -p 'test_*.py'
./scripts/test-gui.sh
SURGE_CC_DIST_DIR="$PWD/build/review" ./scripts/build-app.sh
```

测试使用临时文件、测试进程及模拟 Surge 回执。部分 OAuth 测试需要临时 Unix socket 和本机回环 TCP 监听；不需要真实 Claude 登录、Surge 配置或代理凭据。受限执行环境可能拒绝这些本机端口，请在允许本机监听的开发环境运行。

构建只生成当前 Mac 架构的应用，不安装、启动或替换已有应用。输出目录已有同名应用时会停止，避免覆盖正在运行的版本。

## 修改原则

- 未能核验的状态保留 `unknown`，不把缺失观测当作成功。
- 固定出口发生变化时停止放行，不自动切换其他节点或直连。
- 区分模拟规则、真实请求和观测范围；不要把一次检查描述为长期保证。
- 修改配置前提供预览和备份；只处理工具负责的条目，保留其他策略。
- 为有实际风险的边界添加回归测试，例如回滚、并发、符号链接、无效回执和授权回调。
- 同步更新 [README](README.md)、[接口说明](INTERFACE.md) 和 [变更记录](CHANGELOG.md)。

## 提交问题

请提供应用、macOS、Surge、Chrome 和 Claude Code 的版本，以及最小复现步骤。截图和诊断应先去除真实出口、订阅链接、账号、完整本地路径及凭据。不要上传整个 `Application Support/Surge CC`、Chrome 资料目录、Surge 配置或 `.local/`。

GitHub Actions 在 macOS 上运行回归测试、界面契约和应用构建。CI 不执行真实外部 DNS 测量，也不代表已验证你的网络。
