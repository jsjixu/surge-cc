# 专用浏览器的网页链接

受控 Claude 会话可以打开普通 HTTP(S) 网页。`BROWSER` 打开器和会话内 `open URL` 在规则模式下检查线路，使用该会话所在工作区的专用浏览器；已有窗口复用，新窗口使用既有登录资料。不会在失败时改用个人 Chrome。全局代理模式仍允许专用网页打开，但固定出口与断线阻断挂起。

| 入口 | 所用工作区 | 生效方式 |
| --- | --- | --- |
| Orca 中点击交给系统的网页链接 | A | 安装并启用 Surge CC Links |
| Orca 普通交互式 zsh 的 `open URL`、`/usr/bin/open URL` | A | 安装同步入口后新建终端 |
| 受控 Claude 的 `BROWSER`、会话内私有 `open URL` | 该 Claude 会话所属的 A 或 B | 更新后正常重启 Claude 会话 |

系统分流器负责接收 macOS 网页事件；同步终端入口在命令仍运行时核验来源，避免系统 `open` 太快退出后丢失来源。两者可配合使用。

## Orca 中点击链接

Orca 将外部链接交给 macOS 默认网页入口。可选的 **Surge CC Links** 分流器负责这个入口：可确认的 Orca 来源进入 A 的专用浏览器，其他来源显式交给安装前保存的浏览器。它不修改、复制或清除个人 Chrome Profile。

分流器在接收 Apple Event 时记录系统提供的来源进程身份；不根据前台窗口或域名猜测来源。没有来源记录或与 Orca／受控 Claude 无关的请求使用原浏览器；已识别来源在排队期间失效时会阻止打开，不转交个人浏览器。Orca 的“在应用内打开链接”若开启，仍进入 Orca 内置浏览器，需要关闭这个选项才能使用系统分流。直接指定应用的调用不经过系统默认入口，因此不在自动分流范围内。

Orca 的独立终端托管进程也会核验：缓存位置、所有者、文件形式和程序内容必须与当前 Orca 安装包吻合。旧副本或无法验证的已识别来源会停止打开，不能仅凭程序名字选用 A。来源链允许经过当前用户由系统 `/usr/bin/login` 启动的终端，再追溯到经过核验的 Orca 宿主；`login` 本身不决定浏览器归属。对这个系统程序使用不需要管理员权限的内核身份查询，仍核对真实用户、有效用户、父进程和精确启动时间。普通终端、其他应用仍使用原浏览器。网页投递和窗口置前分别记录；网页已经被浏览器接受时，切换到其他窗口不会造成重复打开。

安装后，原默认浏览器保存在分流器私有配置中。以下命令的路径需要替换为本机实际安装位置：

```sh
"/Applications/Surge CC.app/Contents/Resources/scripts/surge-cc" links install --app "/Applications/Surge CC.app" --json
"/Applications/Surge CC.app/Contents/Resources/scripts/surge-cc" links enable --json
"/Applications/Surge CC.app/Contents/Resources/scripts/surge-cc" links status --json
```

系统可能要求确认修改默认浏览器。安装只保存配置和创建入口；`enable` 才应用默认入口。恢复使用：

```sh
"/Applications/Surge CC.app/Contents/Resources/scripts/surge-cc" links disable --json
```

恢复只处理仍指向分流器的 HTTP/HTTPS 协议，不覆盖用户后来选择的新浏览器。若也安装了下面的终端入口，先运行 `links shell-remove --json` 并新建终端，再停用或移除系统分流器。主应用须保留在安装位置。

## Claude 主动打开网页

新启动的受控 Claude 会话获得私有 `BROWSER` 和 `open`，普通网页通过账号门禁和线路检查后交给精确核对的专用 Chrome 进程。对 Artifact 打开器是否采用 `BROWSER` 的兼容性取决于原生 CLI 版本；当前本机版本的代码路径已核对。

`open` 接受单个 HTTP(S) 地址，也接受 `open -- URL`。文件、`-a` 指定程序、多地址和其他参数不自动转给系统。明确调用 `/usr/bin/open` 不受 PATH hook 拦截。它可能在系统分流器收到链接前已经退出，届时无法核验来源，仍会进入原浏览器。Orca 普通终端应使用下面的同步 zsh 入口，避免这个竞态。已在运行的 Claude 保留旧环境，正常退出后重新启动才能获得新打开器。

普通网页使用独立网页守护，CLI 退出不会顺带关闭网页。OAuth 继续使用严格授权入口；授权窗口占用同一资料时会明确提示关闭专用授权窗口，不会改用空白 Profile。

## Orca 普通终端的同步入口

在系统网页分流器已经安装后，运行：

```sh
"/Applications/Surge CC.app/Contents/Resources/scripts/surge-cc" links shell-install --json
"/Applications/Surge CC.app/Contents/Resources/scripts/surge-cc" links shell-status --json
```

它先备份 `~/.zshrc`，再添加一段受管理的加载代码。新开 Orca 的交互式 zsh 终端后，入口核验真实父进程链，只有确认来自 Orca 才定义 `open` 和 `/usr/bin/open` 函数。其他终端不定义这些函数；不替换系统二进制。已有同名函数或别名会保留，并显示未安装命令接管的提示。使用其他 shell、跳过 `.zshrc` 或自定义 `ZDOTDIR` 时，不属于自动启用范围。

在这样的终端中，输入 `open https://example.com/` 或 `/usr/bin/open https://example.com/` 会同步核验来源、检查 A 的线路并打开已有专用浏览器。参数经标准输入传递。网页保护失败不会退回个人浏览器；当前为 B 时提示切回 A，不自动结束 B 会话。文件打开、显式 `-a`／`-b` 指定应用等原有操作继续交给系统。多网址或 `-g URL` 等尚未支持的网页形式会提示并拒绝，不悄悄交给个人浏览器。

已打开的终端不会被注入命令；正常新建终端即可生效，不必结束正在工作的 Claude 会话。可用以下命令确认新终端中的入口：

```sh
whence -w open /usr/bin/open
```

正常情况下，两项均显示 `function`。若仍为系统命令，检查是否为新建的 Orca 交互式 zsh、是否加载了 `~/.zshrc`，以及启动时是否报告已有同名定义或来源无法核验。`links shell-status` 只确认磁盘安装完整，不能代表某个已打开终端已加载。

撤销使用：

```sh
"/Applications/Surge CC.app/Contents/Resources/scripts/surge-cc" links shell-remove --json
```

它只移除受管理区块，保留备份和其余 shell 配置。撤销后也需新建终端；旧终端里已载入的函数会阻止网页打开，不会因后端登记被移除而改用个人浏览器。

**范围：**这是 zsh 命令入口。`command /usr/bin/open`、`env /usr/bin/open`、程序直接执行系统二进制或其他未配置的 shell 可以绕过函数；这些调用仅依赖系统网页分流，不能保证识别已经退出的发送者。它不是系统级拦截器，也不根据前台应用猜测来源。

## 工作区与网络模式

受控 Claude 的网页随自己的 A/B 工作区，避免 B 会话借用 A 登录；同步终端脚本也会让受控 Claude 自己的私有入口优先生效。Orca 的通用链接入口固定 A：系统点击入口在当前为 B 时可提示确认切换，确认会按既有工作区流程结束相关受控会话；取消保留 B。同步终端入口不会弹窗或自动切换，会阻止该次打开并提示先在 Surge CC 手动切回 A。

规则模式检查指定出口；全局代理模式沿用既有“线路保护挂起”的语义，允许普通专用网页启动，固定出口与断线阻断暂停。已登记隔离开发项目仍要求规则模式。网页分流本身不改 Surge 节点、模式或配置；显式确认 A/B 线路切换时，仍适用已有工作区切换流程。

地址可能包含私人文档标识，因此不会写入 Surge CC 的结果与诊断日志；浏览器和 shell 自身仍正常记录历史记录。分流器不是系统级访问控制，不能接管明确指定其他浏览器的第三方应用。
