import AppKit
import Darwin
import Foundation

private struct LauncherConfiguration: Decodable {
    let schema: Int
    let python: String
    let name: String
    let workspace: String
    let start_page: String

    var backend: String { URL(fileURLWithPath: app).appendingPathComponent("Contents/Resources/scripts/surge-cc").path }
    let config: String
    let app: String

    static func load() throws -> LauncherConfiguration {
        guard let url = Bundle.main.url(forResource: "launcher", withExtension: "json") else {
            throw LauncherFailure("启动器配置缺失。请重新安装 Surge CC 快捷入口。")
        }
        let value = try JSONDecoder().decode(Self.self, from: Data(contentsOf: url))
        guard value.schema == 1,
              [value.python, value.config, value.app].allSatisfy({
                  ($0 as NSString).isAbsolutePath && !$0.contains("\0")
              }),
              FileManager.default.isExecutableFile(atPath: value.python),
              value.app.hasSuffix(".app"),
              value.workspace.range(of: "^[A-Za-z0-9_-]{1,32}$", options: .regularExpression) != nil,
              ["claude", "newtab"].contains(value.start_page),
              !value.name.isEmpty, value.name.count <= 60,
              value.name.rangeOfCharacter(from: .controlCharacters) == nil,
              FileManager.default.fileExists(atPath: value.backend) else {
            throw LauncherFailure("启动器配置无效。请重新安装 Surge CC 快捷入口。")
        }
        return value
    }
}

private enum HelperAction: String, Decodable {
    case focus, needsSwitch = "needs_switch", blocked
}

private struct HelperResult: Decodable {
    let schema: Int
    let action: HelperAction
    let message: String
    let pid: Int32?
    let started: [Int64]?
    let executable: String?
    let suspended: Bool?
    let launched: Bool?
    let current: String?
    let focused: Bool?
}

private struct LauncherFailure: LocalizedError {
    let message: String
    init(_ message: String) { self.message = message }
    var errorDescription: String? { message }
}

private struct FocusRequest: Decodable {
    let pid: Int32
    let started: [Int64]
    let executable: String
}

private func matchesKernelIdentity(_ request: FocusRequest) -> Bool {
    var info = proc_bsdinfo()
    let size = MemoryLayout<proc_bsdinfo>.size
    guard proc_pidinfo(request.pid, PROC_PIDTBSDINFO, 0, &info, Int32(size)) == size,
          info.pbi_pid == UInt32(request.pid),
          info.pbi_uid == getuid(), info.pbi_ruid == getuid(),
          info.pbi_start_tvsec == UInt64(request.started[0]),
          info.pbi_start_tvusec == UInt64(request.started[1]) else { return false }
    var path = [CChar](repeating: 0, count: 4096)
    guard proc_pidpath(request.pid, &path, UInt32(path.count)) > 0 else { return false }
    return String(cString: path) == request.executable
}

// The helper calls this mode while holding the account lock. It has no app
// lifecycle or windows and does not read configuration or credential files.
private func focusOnly(_ json: String) -> Bool {
    guard let bytes = json.data(using: .utf8),
          let request = try? JSONDecoder().decode(FocusRequest.self, from: bytes),
          request.pid > 0, request.pid != getpid(),
          request.started.count == 2, request.started[0] > 0,
          (0..<1_000_000).contains(request.started[1]),
          (request.executable as NSString).isAbsolutePath,
          !request.executable.contains("\0") else { return false }
    let expectedStart = Double(request.started[0]) + Double(request.started[1]) / 1_000_000
    var target: NSRunningApplication?
    for _ in 0..<50 {
        guard matchesKernelIdentity(request) else { return false }
        if let candidate = NSRunningApplication(processIdentifier: request.pid),
           !candidate.isTerminated,
           let executable = candidate.executableURL?.path {
            guard executable == request.executable else { return false }
            // Directly launched browsers have no LaunchServices launchDate.
            // Kernel start identity above is exact; use this date as a sanity
            // check only when macOS provides it.
            if let launchDate = candidate.launchDate,
               abs(launchDate.timeIntervalSince1970 - expectedStart) > 1.0 { return false }
            if candidate.isFinishedLaunching { target = candidate; break }
        }
        RunLoop.current.run(until: Date(timeIntervalSinceNow: 0.1))
    }
    guard let target = target, !target.isTerminated,
          target.executableURL?.path == request.executable,
          matchesKernelIdentity(request) else { return false }
    _ = target.unhide()
    guard target.activate(options: [.activateAllWindows]) else { return false }
    for _ in 0..<20 {
        if NSWorkspace.shared.frontmostApplication?.processIdentifier == request.pid { return true }
        RunLoop.current.run(until: Date(timeIntervalSinceNow: 0.1))
    }
    return false
}

// This object owns only the Python process it launched. It never signals Chrome,
// a process group, or any unrelated process. Output is capped and stderr is discarded.
private final class HelperInvocation: @unchecked Sendable {
    private let lock = NSLock()
    private var process: Process?
    private var expired = false

    private func expire() {
        lock.lock()
        guard !expired, let process = process, process.isRunning else {
            lock.unlock()
            return
        }
        expired = true
        process.terminate()
        lock.unlock()
    }

    func run(configuration: LauncherConfiguration, confirmedCurrent: String?,
             completion: @escaping (Result<HelperResult, Error>) -> Void) {
        DispatchQueue.global(qos: .userInitiated).async { [self] in
            let outcome: Result<HelperResult, Error>
            do {
                guard let launcherConfig = Bundle.main.url(forResource: "launcher", withExtension: "json") else {
                    throw LauncherFailure("启动器检查程序缺失。请重新安装 Surge CC 快捷入口。")
                }
                let child = Process()
                child.executableURL = URL(fileURLWithPath: configuration.python)
                child.arguments = ["-I", "-B", configuration.backend, "--config", configuration.config,
                                   "shortcut", "open", "--launcher-config", launcherConfig.path, "--json"]
                if let confirmedCurrent = confirmedCurrent {
                    child.arguments! += ["--confirm-switch-from", confirmedCurrent]
                }
                child.standardInput = FileHandle.nullDevice
                child.standardError = FileHandle.nullDevice
                let pipe = Pipe()
                child.standardOutput = pipe
                let descriptor = pipe.fileHandleForReading.fileDescriptor
                let flags = fcntl(descriptor, F_GETFL)
                guard flags >= 0, fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) == 0 else {
                    throw LauncherFailure("无法创建浏览器检查通道。")
                }
                try child.run()
                lock.lock()
                process = child
                lock.unlock()
                let deadline = DispatchWorkItem { [self] in expire() }
                DispatchQueue.global().asyncAfter(deadline: .now() + 180, execute: deadline)
                var bytes = Data()
                var tooLarge = false
                var readFailed = false
                var buffer = [UInt8](repeating: 0, count: 4096)
                while true {
                    let count = buffer.withUnsafeMutableBytes { raw in
                        Darwin.read(descriptor, raw.baseAddress!, raw.count)
                    }
                    if count > 0 {
                        if bytes.count + count <= 131_072 {
                            bytes.append(contentsOf: buffer.prefix(count))
                        } else if !tooLarge {
                            tooLarge = true
                            expire()
                        }
                    } else if count == 0 {
                        break
                    } else if errno == EINTR {
                        continue
                    } else if errno == EAGAIN || errno == EWOULDBLOCK {
                        if !child.isRunning { break }
                        var descriptorState = pollfd(fd: descriptor, events: Int16(POLLIN), revents: 0)
                        _ = Darwin.poll(&descriptorState, 1, 100)
                    } else {
                        readFailed = true
                        expire()
                        break
                    }
                }
                child.waitUntilExit()
                deadline.cancel()
                lock.lock()
                let timedOut = expired
                process = nil
                lock.unlock()
                try? pipe.fileHandleForReading.close()
                if tooLarge { throw LauncherFailure("浏览器检查返回了异常数据，已停止。") }
                if readFailed { throw LauncherFailure("无法读取浏览器检查结果。") }
                if timedOut { throw LauncherFailure("浏览器检查超过 3 分钟，已请求停止并等待检查程序完成必要收尾。请在 Surge CC 中查看当前状态。") }
                let result = try JSONDecoder().decode(HelperResult.self, from: bytes)
                guard result.schema == 1 else { throw LauncherFailure("浏览器检查程序版本不兼容。") }
                guard child.terminationReason == .exit,
                      child.terminationStatus == 0 || result.action == .blocked else {
                    throw LauncherFailure("浏览器检查未正常完成。请在 Surge CC 中查看当前状态。")
                }
                outcome = .success(result)
            } catch let failure as LauncherFailure {
                outcome = .failure(failure)
            } catch {
                outcome = .failure(LauncherFailure("无法完成浏览器检查。请在 Surge CC 中查看当前状态。"))
            }
            DispatchQueue.main.async { completion(outcome) }
        }
    }
}

private final class LauncherDelegate: NSObject, NSApplicationDelegate {
    private var displayName: String {
        configuration?.name ?? (Bundle.main.object(forInfoDictionaryKey: "CFBundleDisplayName") as? String ?? "Surge CC 浏览器")
    }
    private var busy = false
    private var configuration: LauncherConfiguration?
    private var invocation: HelperInvocation?
    private var progress: NSPanel?
    private var progressDetail: NSTextField?

    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.regular)
        let menu = NSMenu()
        let applicationItem = NSMenuItem()
        let applicationMenu = NSMenu(title: displayName)
        applicationMenu.addItem(withTitle: "退出 \(displayName)", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
        applicationItem.submenu = applicationMenu
        menu.addItem(applicationItem)
        NSApp.mainMenu = menu
        begin()
    }

    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        if !busy { begin() }
        return false
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { false }

    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        guard busy else { return .terminateNow }
        // Do not interrupt an in-flight profile switch halfway through its work.
        progressDetail?.stringValue = "正在完成当前操作；完成后即可退出。"
        NSSound.beep()
        return .terminateCancel
    }

    private func begin() {
        guard !busy else { return }
        busy = true
        showProgress()
        do {
            let configuration = try LauncherConfiguration.load()
            self.configuration = configuration
            invoke(configuration, confirmedCurrent: nil)
        } catch {
            showError(error.localizedDescription)
        }
    }

    private func invoke(_ configuration: LauncherConfiguration, confirmedCurrent: String?) {
        let operation = HelperInvocation()
        invocation = operation
        operation.run(configuration: configuration, confirmedCurrent: confirmedCurrent) { [weak self] outcome in
            guard let self = self else { return }
            self.invocation = nil
            switch outcome {
            case .success(let result): self.handle(result, configuration: configuration)
            case .failure(let error):
                self.showError(error.localizedDescription)
            }
        }
    }

    private func handle(_ result: HelperResult, configuration: LauncherConfiguration) {
        switch result.action {
        case .focus:
            guard result.focused == true else {
                showError("浏览器检查未确认窗口已显示，已停止后续操作。请重试。")
                return
            }
            closeProgress()
            busy = false
        case .blocked:
            showError(result.message.isEmpty ? "当前状态不允许打开 Surge CC 快捷入口。" : result.message)
        case .needsSwitch:
            closeProgress()
            guard let current = result.current, !current.isEmpty, current.count <= 64,
                  current.rangeOfCharacter(from: .controlCharacters) == nil else {
                showError("无法确认当前环境。请在 Surge CC 中检查后重试。")
                return
            }
            let alert = NSAlert()
            alert.alertStyle = .warning
            alert.messageText = "切换到 \(configuration.workspace) 工作区？"
            alert.informativeText = "当前激活的是 \(current) 环境。切换到 \(configuration.workspace) 将结束当前环境的专用 Web/OAuth 浏览器和 CLI 会话，然后打开指定工作区的浏览器。\n\n如需保留当前会话，请取消。"
            alert.addButton(withTitle: "取消").keyEquivalent = "\r"
            alert.addButton(withTitle: "切换到 \(configuration.workspace)").keyEquivalent = ""
            NSApp.activate(ignoringOtherApps: true)
            if alert.runModal() == .alertSecondButtonReturn {
                showProgress(detail: "正在切换到 \(configuration.workspace) 并检查浏览器…")
                invoke(configuration, confirmedCurrent: current)
            } else {
                busy = false
            }
        }
    }

    private func showProgress(detail: String = "正在确认工作区与现有浏览器进程…") {
        if let progress = progress {
            progressDetail?.stringValue = detail
            progress.orderFrontRegardless()
            return
        }
        let panel = NSPanel(contentRect: NSRect(x: 0, y: 0, width: 390, height: 130),
                            styleMask: [.titled], backing: .buffered, defer: false)
        panel.title = displayName
        panel.isReleasedWhenClosed = false
        panel.hidesOnDeactivate = false
        panel.isFloatingPanel = false
        let spinner = NSProgressIndicator(frame: NSRect(x: 26, y: 54, width: 28, height: 28))
        spinner.style = .spinning
        spinner.controlSize = .regular
        spinner.startAnimation(nil)
        let title = NSTextField(labelWithString: "正在检查 \(displayName)")
        title.font = .systemFont(ofSize: 16, weight: .semibold)
        title.frame = NSRect(x: 70, y: 70, width: 300, height: 24)
        let explanation = NSTextField(wrappingLabelWithString: detail)
        explanation.font = .systemFont(ofSize: 12)
        explanation.textColor = .secondaryLabelColor
        explanation.frame = NSRect(x: 70, y: 26, width: 296, height: 36)
        panel.contentView?.addSubview(spinner)
        panel.contentView?.addSubview(title)
        panel.contentView?.addSubview(explanation)
        progress = panel
        progressDetail = explanation
        panel.center()
        panel.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }

    private func closeProgress() {
        progress?.close()
        progress = nil
        progressDetail = nil
    }

    private func showError(_ message: String) {
        closeProgress()
        let alert = NSAlert()
        alert.alertStyle = .warning
        alert.messageText = "\(displayName) 未能打开"
        alert.informativeText = message
        alert.addButton(withTitle: "取消").keyEquivalent = "\r"
        if let configuration = configuration,
           FileManager.default.fileExists(atPath: configuration.app) {
            alert.addButton(withTitle: "打开 Surge CC").keyEquivalent = ""
        }
        NSApp.activate(ignoringOtherApps: true)
        let response = alert.runModal()
        busy = false
        if response == .alertSecondButtonReturn, let configuration = configuration {
            let options = NSWorkspace.OpenConfiguration()
            options.activates = true
            NSWorkspace.shared.openApplication(at: URL(fileURLWithPath: configuration.app),
                                               configuration: options, completionHandler: nil)
        }
    }


}

if CommandLine.arguments.dropFirst().contains("--focus-only") {
    let focused = CommandLine.arguments.count == 3 && CommandLine.arguments[1] == "--focus-only"
        && focusOnly(CommandLine.arguments[2])
    let reply = "{\"schema\":1,\"focused\":\(focused ? "true" : "false")}\n"
    FileHandle.standardOutput.write(Data(reply.utf8))
    exit(focused ? 0 : 2)
}

private let app = NSApplication.shared
private let delegate = LauncherDelegate()
app.delegate = delegate
app.run()
