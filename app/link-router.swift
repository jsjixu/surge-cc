import AppKit
import Carbon
import Darwin
import Foundation

private let routerIdentifier = "local.surgecc.link-router"
private struct RouterFailure: LocalizedError {
    let errorDescription: String?
    init(_ message: String) { errorDescription = message }
}
private struct AppIdentity: Codable {
    let app: String
    let bundle_id: String
    let executable: String
}
private struct RouterConfiguration: Decodable {
    let schema: Int
    let python: String
    let config: String
    let app: String
    let workspace: String
    let previous: [String: AppIdentity]
    let sources: [AppIdentity]
    var backend: String { app + "/Contents/Resources/scripts/surge-cc" }
    static func load() throws -> Self {
        guard let location = Bundle.main.url(forResource: "router", withExtension: "json") else {
            throw RouterFailure("链接分流器配置缺失，请重新安装。")
        }
        let values = try location.resourceValues(forKeys: [.isSymbolicLinkKey, .fileSizeKey])
        guard values.isSymbolicLink != true, (values.fileSize ?? 32_769) <= 32_768 else {
            throw RouterFailure("链接分流器配置无效。")
        }
        let result = try JSONDecoder().decode(Self.self, from: Data(contentsOf: location))
        guard result.schema == 1, result.workspace == "A",
              Set(result.previous.keys) == Set(["http", "https"]),
              [result.python, result.config, result.app].allSatisfy({
                  ($0 as NSString).isAbsolutePath && $0.rangeOfCharacter(from: .controlCharacters) == nil
              }), FileManager.default.isExecutableFile(atPath: result.python),
              FileManager.default.fileExists(atPath: result.backend),
              result.previous.values.allSatisfy({ $0.bundle_id != routerIdentifier }) else {
            throw RouterFailure("链接分流器配置无效。")
        }
        return result
    }
}

private struct SourceIdentity: Codable {
    let pid: Int32
    let started: [UInt64]
    let executable: String
    let parent: UInt32
}
private struct SourceTrace: Encodable {
    let chain: [SourceIdentity]
}
private func loginBridgeIdentity(_ pid: Int32) -> SourceIdentity? {
    // PROC_PIDTBSDINFO can deny a root-effective login even when its real
    // user is ours. KERN_PROC_PID exposes this stable identity without sudo.
    func snapshot() -> kinfo_proc? {
        var value = kinfo_proc()
        var size = MemoryLayout<kinfo_proc>.size
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, pid]
        guard sysctl(&mib, UInt32(mib.count), &value, &size, nil, 0) == 0,
              size == MemoryLayout<kinfo_proc>.size, value.kp_proc.p_pid == pid,
              value.kp_eproc.e_ucred.cr_uid == 0, value.kp_eproc.e_pcred.p_ruid == getuid() else { return nil }
        return value
    }
    guard let before = snapshot() else { return nil }
    var path = [CChar](repeating: 0, count: 4096)
    guard proc_pidpath(pid, &path, UInt32(path.count)) > 0,
          String(cString: path) == "/usr/bin/login", let after = snapshot() else { return nil }
    path = [CChar](repeating: 0, count: 4096)
    guard proc_pidpath(pid, &path, UInt32(path.count)) > 0,
          String(cString: path) == "/usr/bin/login" else { return nil }
    let started = before.kp_proc.p_un.__p_starttime
    let finished = after.kp_proc.p_un.__p_starttime
    guard before.kp_eproc.e_ppid == after.kp_eproc.e_ppid,
          started.tv_sec == finished.tv_sec, started.tv_usec == finished.tv_usec,
          started.tv_sec > 0, started.tv_usec >= 0, started.tv_usec < 1_000_000,
          before.kp_eproc.e_ppid >= 0 else { return nil }
    return SourceIdentity(pid: pid, started: [UInt64(started.tv_sec), UInt64(started.tv_usec)],
                          executable: "/usr/bin/login", parent: UInt32(before.kp_eproc.e_ppid))
}
private func sourceIdentity(_ pid: Int32, allowLoginBridge: Bool = false) -> SourceIdentity? {
    guard pid > 1 else { return nil }
    var before = proc_bsdinfo(), after = proc_bsdinfo()
    let size = MemoryLayout<proc_bsdinfo>.size
    guard proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &before, Int32(size)) == size else {
        return allowLoginBridge ? loginBridgeIdentity(pid) : nil
    }
    guard before.pbi_pid == UInt32(pid), before.pbi_ruid == getuid() else { return nil }
    var path = [CChar](repeating: 0, count: 4096)
    guard proc_pidpath(pid, &path, UInt32(path.count)) > 0,
          proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &after, Int32(size)) == size,
          before.pbi_pid == after.pbi_pid, before.pbi_ppid == after.pbi_ppid,
          before.pbi_uid == after.pbi_uid, before.pbi_ruid == after.pbi_ruid,
          before.pbi_start_tvsec == after.pbi_start_tvsec,
          before.pbi_start_tvusec == after.pbi_start_tvusec else { return nil }
    let executable = String(cString: path)
    // Orca's detached terminal host starts a root-effective login process
    // whose real user is still ours. This exact system binary is only an
    // ancestry bridge; Python must still verify a protected ancestor.
    guard before.pbi_uid == getuid() ||
          (allowLoginBridge && before.pbi_uid == 0 && executable == "/usr/bin/login") else { return nil }
    return SourceIdentity(pid: pid, started: [before.pbi_start_tvsec, before.pbi_start_tvusec],
                          executable: executable, parent: before.pbi_ppid)
}
private func captureSource(_ pid: Int32) -> SourceTrace? {
    var chain = [SourceIdentity]()
    var current = pid
    var seen = Set<Int32>()
    for _ in 0..<16 {
        guard !seen.contains(current), let item = sourceIdentity(current, allowLoginBridge: true) else { break }
        chain.append(item)
        seen.insert(current)
        current = Int32(item.parent)
    }
    return chain.isEmpty ? nil : SourceTrace(chain: chain)
}

private struct OpenRequest: Encodable {
    let url: String
    let source: SourceTrace?
    enum CodingKeys: String, CodingKey { case url, source }
    func encode(to encoder: Encoder) throws {
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(url, forKey: .url)
        if let source = source { try values.encode(source, forKey: .source) }
        else { try values.encodeNil(forKey: .source) }
    }
}
private struct OpenResult: Decodable {
    let schema: Int
    let action: String
    let message: String
    let app: String?
    let bundle_id: String?
    let current: String?
}

private func handlers() throws -> [String: [String: String]] {
    var result = [String: [String: String]]()
    for scheme in ["http", "https"] {
        guard let target = NSWorkspace.shared.urlForApplication(toOpen: URL(string: scheme + "://example.invalid/")!),
              let bundle = Bundle(url: target), let identifier = bundle.bundleIdentifier else {
            throw RouterFailure("无法读取系统默认浏览器。")
        }
        result[scheme] = ["app": target.path, "bundle_id": identifier]
    }
    return result
}
private func registerRouter() throws {
    guard Bundle.main.bundleIdentifier == routerIdentifier,
          LSRegisterURL(Bundle.main.bundleURL as CFURL, true) == noErr else {
        throw RouterFailure("系统未能登记链接分流器，请重新安装后在系统设置中选择默认浏览器。")
    }
}

// NSWorkspace's consent/completion flow requires the real application event
// loop. Do not synchronously spin a nested RunLoop waiting on a main-queue
// completion: it can stall both the completion and the system consent UI.
private final class DefaultHandlerOperation: @unchecked Sendable {
    private let restore: Bool
    private let completionLock = NSLock()
    private var finished = false
    private var configuration: RouterConfiguration?
    private var remaining = [String]()
    private var changed = [String]()
    private var originalFailure: String?
    init(restore: Bool) { self.restore = restore }

    private func finish(_ value: [String: Any], success: Bool) {
        completionLock.lock()
        guard !finished else { completionLock.unlock(); return }
        finished = true
        completionLock.unlock()
        printJSON(value)
        exit(success ? 0 : 1)
    }
    private func fail(_ message: String) { finish(["ok": false, "message": message], success: false) }

    func start() {
        // Runs off the main queue so even a stalled system API cannot leave a
        // command process hanging indefinitely. Python allows another 30 s.
        DispatchQueue.global().asyncAfter(deadline: .now() + 90) { [self] in
            fail("系统默认浏览器操作超时，当前状态尚未确认。请在“系统设置 → 桌面与程序坞 → 默认网页浏览器”中检查；没有绕过系统确认。")
        }
        do {
            let settings = try RouterConfiguration.load()
            guard Bundle.main.bundleIdentifier == routerIdentifier else { throw RouterFailure("请使用已安装的链接分流器。") }
            let before = try handlers()
            for scheme in ["http", "https"] {
                let saved = settings.previous[scheme]!
                guard Bundle(path: saved.app)?.bundleIdentifier == saved.bundle_id,
                      saved.bundle_id != routerIdentifier else {
                    throw RouterFailure("原浏览器已移动或被删除，未修改默认入口。")
                }
                if restore {
                    // Leave newer user choices alone, and skip already-restored entries.
                    if before[scheme]?["bundle_id"] == routerIdentifier { remaining.append(scheme) }
                } else {
                    guard before[scheme]?["bundle_id"] == saved.bundle_id || before[scheme]?["bundle_id"] == routerIdentifier else {
                        throw RouterFailure("默认浏览器已改变，未覆盖新的选择。请重新配置链接分流器。")
                    }
                    if before[scheme]?["bundle_id"] != routerIdentifier { remaining.append(scheme) }
                }
            }
            configuration = settings
            if !restore { try registerRouter() }
            next()
        } catch { fail((error as? RouterFailure)?.errorDescription ?? "无法准备系统默认浏览器操作。") }
    }

    private func next() {
        guard let settings = configuration else { fail("链接入口配置缺失。"); return }
        guard !remaining.isEmpty else {
            do {
                let after = try handlers()
                // Enabling must verify both schemes, including an idempotent
                // invocation that made no changes. A concurrent user change
                // must not be reported as an active router by an empty set.
                let requiredSchemes = restore ? changed : ["http", "https"]
                let verified = requiredSchemes.allSatisfy { scheme in
                    after[scheme]?["bundle_id"] == (restore ? settings.previous[scheme]!.bundle_id : routerIdentifier)
                }
                guard verified else { rollback("系统默认入口验证未完成，请在系统设置中检查。"); return }
                finish(["ok": true, "restored": restore, "handlers": after], success: true)
            } catch { rollback("无法读取操作后的默认浏览器，请在系统设置中检查。") }
            return
        }
        let scheme = remaining.removeFirst()
        let target = restore ? URL(fileURLWithPath: settings.previous[scheme]!.app) : Bundle.main.bundleURL
        NSWorkspace.shared.setDefaultApplication(at: target, toOpenURLsWithScheme: scheme) { error in
            DispatchQueue.main.async {
                guard error == nil else { self.rollback("系统未允许修改默认网页入口，请在系统设置中选择浏览器。"); return }
                self.changed.append(scheme)
                self.next()
            }
        }
    }

    private func rollback(_ message: String) {
        originalFailure = message
        guard !restore, !changed.isEmpty else { fail(message); return }
        restoreNextChanged()
    }
    private func restoreNextChanged() {
        guard let settings = configuration, let scheme = changed.popLast() else {
            fail(originalFailure ?? "系统默认浏览器操作未完成。"); return
        }
        // Restore only changes this invocation made that still point to us.
        guard (try? handlers()[scheme]?["bundle_id"]) == routerIdentifier else { restoreNextChanged(); return }
        let target = URL(fileURLWithPath: settings.previous[scheme]!.app)
        NSWorkspace.shared.setDefaultApplication(at: target, toOpenURLsWithScheme: scheme) { _ in
            DispatchQueue.main.async { self.restoreNextChanged() }
        }
    }
}

private func invoke(_ configuration: RouterConfiguration, request: OpenRequest, confirmed: String?) throws -> OpenResult {
    guard let routerConfig = Bundle.main.url(forResource: "router", withExtension: "json") else {
        throw RouterFailure("链接分流器配置缺失。")
    }
    let child = Process()
    child.executableURL = URL(fileURLWithPath: configuration.python)
    child.arguments = ["-I", "-B", configuration.backend, "--config", configuration.config,
                       "links", "open", "--router-config", routerConfig.path, "--json"]
    if let confirmed = confirmed { child.arguments! += ["--confirm-switch-from", confirmed] }
    let input = Pipe(), output = Pipe()
    child.standardInput = input
    child.standardOutput = output
    child.standardError = FileHandle.nullDevice
    let descriptor = output.fileHandleForReading.fileDescriptor
    let flags = fcntl(descriptor, F_GETFL)
    guard flags >= 0, fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) == 0 else {
        throw RouterFailure("无法创建链接检查通道。")
    }
    try child.run()
    try input.fileHandleForWriting.write(contentsOf: JSONEncoder().encode(request))
    try input.fileHandleForWriting.close()
    let deadline = Date(timeIntervalSinceNow: 180)
    var bytes = Data(), buffer = [UInt8](repeating: 0, count: 4096)
    var failed = false
    while true {
        let count = buffer.withUnsafeMutableBytes { Darwin.read(descriptor, $0.baseAddress!, $0.count) }
        if count > 0 {
            if bytes.count + count > 131_072 { failed = true; break }
            bytes.append(contentsOf: buffer.prefix(count))
        } else if count == 0 { break }
        else if errno == EINTR { continue }
        else if errno == EAGAIN || errno == EWOULDBLOCK {
            if !child.isRunning { break }
            if Date() >= deadline { failed = true; break }
            var state = pollfd(fd: descriptor, events: Int16(POLLIN), revents: 0)
            _ = Darwin.poll(&state, 1, 100)
        } else { failed = true; break }
    }
    if failed && child.isRunning { child.terminate() }
    child.waitUntilExit()
    try? output.fileHandleForReading.close()
    guard !failed, let result = try? JSONDecoder().decode(OpenResult.self, from: bytes), result.schema == 1,
          child.terminationReason == .exit,
          child.terminationStatus == 0 || result.action == "blocked" else {
        throw RouterFailure("链接检查未完成，未改用其他浏览器。请打开 Surge CC 检查线路。")
    }
    return result
}

private struct BrowserDelivery: Encodable {
    let pid: Int32
    let started: [UInt64]
    let executable: String
    let url: String
}
private struct BrowserDeliveryResult: Decodable {
    let schema: Int
    let opened: Bool
    let focused: Bool
}

// Personal Chrome and the dedicated browser share a bundle identifier. Never
// give LaunchServices a URL to forward by bundle ID: address the verified
// process instead, including after a URL-free cold start of the saved app.
private final class PersonalBrowserDelivery {
    private let saved: AppIdentity
    private let helper: URL
    private let webURL: String
    private let completion: (Bool) -> Void
    private var finished = false
    private let launchDeadline = Date(timeIntervalSinceNow: 15)

    init(saved: AppIdentity, application: String, url: String, completion: @escaping (Bool) -> Void) {
        self.saved = saved
        helper = URL(fileURLWithPath: application + "/Contents/Resources/SurgeCCShortcut")
        webURL = url
        self.completion = completion
    }
    private func finish(_ success: Bool) {
        guard !finished else { return }
        finished = true
        completion(success)
    }
    private func matches(_ application: NSRunningApplication) -> Bool {
        !application.isTerminated && application.bundleIdentifier == saved.bundle_id &&
            application.bundleURL?.path == saved.app && application.executableURL?.path == saved.executable
    }
    func start() {
        guard FileManager.default.isExecutableFile(atPath: helper.path),
              let bundle = Bundle(path: saved.app), bundle.bundleIdentifier == saved.bundle_id,
              bundle.executableURL?.path == saved.executable,
              saved.bundle_id != routerIdentifier else { finish(false); return }
        DispatchQueue.main.asyncAfter(deadline: .now() + 40) { self.finish(false) }
        let candidates = NSWorkspace.shared.runningApplications.filter { matches($0) }
        guard candidates.count <= 1 else { finish(false); return }
        if let application = candidates.first {
            begin(application)
            return
        }
        let options = NSWorkspace.OpenConfiguration()
        options.activates = false
        options.createsNewApplicationInstance = true
        // No URLs or request arguments are passed through LaunchServices.
        NSWorkspace.shared.openApplication(at: URL(fileURLWithPath: saved.app), configuration: options) { application, error in
            DispatchQueue.main.async {
                guard !self.finished else { return }
                guard error == nil, let application = application else { self.finish(false); return }
                self.begin(application)
            }
        }
    }
    private func begin(_ application: NSRunningApplication) {
        guard matches(application), let identity = sourceIdentity(application.processIdentifier),
              identity.executable == saved.executable else { finish(false); return }
        waitUntilReady(application, identity: identity)
    }
    private func waitUntilReady(_ application: NSRunningApplication, identity: SourceIdentity) {
        guard !finished else { return }
        guard Date() < launchDeadline, matches(application),
              let current = sourceIdentity(identity.pid), current.started == identity.started,
              current.executable == identity.executable else { finish(false); return }
        if !application.isFinishedLaunching {
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.1) {
                self.waitUntilReady(application, identity: identity)
            }
            return
        }
        let payload = BrowserDelivery(pid: identity.pid, started: identity.started,
                                      executable: identity.executable, url: webURL)
        DispatchQueue.global(qos: .userInitiated).async {
            let success = self.deliver(payload)
            DispatchQueue.main.async { self.finish(success) }
        }
    }
    private func deliver(_ payload: BrowserDelivery) -> Bool {
        let child = Process(), input = Pipe(), output = Pipe()
        child.executableURL = helper
        child.arguments = ["--open-url-stdin"]
        child.standardInput = input
        child.standardOutput = output
        child.standardError = FileHandle.nullDevice
        let descriptor = output.fileHandleForReading.fileDescriptor
        let flags = fcntl(descriptor, F_GETFL)
        guard flags >= 0, fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) == 0 else { return false }
        defer {
            try? input.fileHandleForWriting.close()
            try? output.fileHandleForReading.close()
        }
        do {
            try child.run()
            try input.fileHandleForWriting.write(contentsOf: JSONEncoder().encode(payload))
            try input.fileHandleForWriting.close()
        } catch {
            if child.isRunning { child.terminate() }
            return false
        }
        let childIdentity = sourceIdentity(child.processIdentifier)
        let deadline = Date(timeIntervalSinceNow: 20)
        var bytes = Data(), buffer = [UInt8](repeating: 0, count: 4096)
        var failed = false
        while true {
            let count = buffer.withUnsafeMutableBytes { Darwin.read(descriptor, $0.baseAddress!, $0.count) }
            if count > 0 {
                if bytes.count + count > 8192 { failed = true; break }
                bytes.append(contentsOf: buffer.prefix(count))
            } else if count == 0 { break }
            else if errno == EINTR { continue }
            else if errno == EAGAIN || errno == EWOULDBLOCK {
                if !child.isRunning { break }
                if Date() >= deadline { failed = true; break }
                var state = pollfd(fd: descriptor, events: Int16(POLLIN), revents: 0)
                _ = Darwin.poll(&state, 1, 100)
            } else { failed = true; break }
        }
        // Even an unexpected early stdout close must not make waitUntilExit
        // unbounded. Only this operation's helper may be terminated.
        while child.isRunning && Date() < deadline { Thread.sleep(forTimeInterval: 0.02) }
        if child.isRunning {
            failed = true
            if let original = childIdentity, let current = sourceIdentity(original.pid),
               current.started == original.started, current.executable == original.executable {
                _ = Darwin.kill(original.pid, SIGKILL)
            }
        }
        guard !child.isRunning else { return false }
        child.waitUntilExit()
        guard !failed, child.terminationReason == .exit, child.terminationStatus == 0,
              let result = try? JSONDecoder().decode(BrowserDeliveryResult.self, from: bytes) else { return false }
        // Chrome's accepted URL reply is the delivery result. The user may
        // switch focus meanwhile; that must not report failure or resend it.
        return result.schema == 1 && result.opened
    }
}

private final class RouterDelegate: NSObject, NSApplicationDelegate {
    private var queue = [OpenRequest]()
    private var busy = false
    private var ready = false
    func applicationWillFinishLaunching(_ notification: Notification) {
        NSAppleEventManager.shared().setEventHandler(self, andSelector: #selector(receive(_:reply:)),
                                                      forEventClass: AEEventClass(kInternetEventClass),
                                                      andEventID: AEEventID(kAEGetURL))
    }
    func applicationDidFinishLaunching(_ notification: Notification) { ready = true; next() }
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { false }
    @objc private func receive(_ event: NSAppleEventDescriptor, reply: NSAppleEventDescriptor) {
        // 'spid' is a read-only attribute supplied by the Apple Event manager,
        // not an HTTP parameter or application-supplied claimed bundle name.
        guard let url = event.paramDescriptor(forKeyword: AEKeyword(keyDirectObject))?.stringValue,
              url.utf8.count <= 16_384, queue.count < 32 else {
            alert("待打开的链接过多或格式无效，请稍后重试。")
            return
        }
        let pid = event.attributeDescriptor(forKeyword: AEKeyword(keySenderPIDAttr))?.int32Value ?? 0
        queue.append(OpenRequest(url: url, source: captureSource(pid)))
        next()
    }
    private func alert(_ message: String) {
        NSApp.activate(ignoringOtherApps: true)
        let panel = NSAlert()
        panel.messageText = "未打开网页"
        panel.informativeText = message
        panel.addButton(withTitle: "好")
        panel.runModal()
    }
    private func next() {
        guard ready, !busy, !queue.isEmpty else { return }
        busy = true
        run(queue.removeFirst(), confirmed: nil)
    }
    private func run(_ request: OpenRequest, confirmed: String?) {
        DispatchQueue.global(qos: .userInitiated).async {
            let result: Result<OpenResult, Error>
            do { result = .success(try invoke(RouterConfiguration.load(), request: request, confirmed: confirmed)) }
            catch { result = .failure(error) }
            DispatchQueue.main.async { self.complete(request, result: result) }
        }
    }
    private func finish() { busy = false; next() }
    private func complete(_ request: OpenRequest, result: Result<OpenResult, Error>) {
        switch result {
        case .failure(let error):
            alert((error as? RouterFailure)?.errorDescription ?? "无法验证链接入口，未打开网页。")
            finish()
        case .success(let value):
            switch value.action {
            case "focus", "opened": finish()
            case "needs_switch":
                let panel = NSAlert()
                panel.messageText = "切换到 A 的专用浏览器？"
                panel.informativeText = value.message
                panel.addButton(withTitle: "取消")
                panel.addButton(withTitle: "切换并打开")
                NSApp.activate(ignoringOtherApps: true)
                if panel.runModal() == .alertSecondButtonReturn, let current = value.current {
                    run(request, confirmed: current)
                } else { finish() }
            case "fallback":
                guard let target = value.app, let identifier = value.bundle_id,
                      identifier != routerIdentifier, let url = URL(string: request.url),
                      let scheme = url.scheme?.lowercased(), ["http", "https"].contains(scheme),
                      let configuration = try? RouterConfiguration.load(),
                      let saved = configuration.previous[scheme],
                      saved.app == target, saved.bundle_id == identifier else {
                    alert("原默认浏览器无法验证，未打开网页。")
                    finish(); return
                }
                PersonalBrowserDelivery(saved: saved, application: configuration.app, url: request.url) { success in
                    if !success { self.alert("未能确认网页已在原浏览器中打开。请检查自动化权限和原浏览器进程后重试；未转交专用浏览器或系统默认入口。") }
                    self.finish()
                }.start()
            default:
                alert(value.message)
                finish()
            }
        }
    }
}

private func printJSON(_ value: [String: Any]) {
    if let data = try? JSONSerialization.data(withJSONObject: value, options: [.sortedKeys]),
       let text = String(data: data, encoding: .utf8) { print(text) }
}
let arguments = CommandLine.arguments
if arguments.count == 2 && ["--defaults", "--register"].contains(arguments[1]) {
    do {
        if arguments[1] == "--defaults" { printJSON(["ok": true, "handlers": try handlers()]) }
        else { try registerRouter(); printJSON(["ok": true, "registered": true]) }
        exit(0)
    } catch {
        printJSON(["ok": false, "message": (error as? RouterFailure)?.errorDescription ?? "系统链接入口操作未完成。"])
        exit(1)
    }
}
if arguments.count == 2 && ["--set-default", "--restore-default"].contains(arguments[1]) {
    let application = NSApplication.shared
    application.setActivationPolicy(.accessory)
    let operation = DefaultHandlerOperation(restore: arguments[1] == "--restore-default")
    DispatchQueue.main.async { operation.start() }
    application.run()
    exit(1)
}
let app = NSApplication.shared
private let delegate = RouterDelegate()
app.delegate = delegate
app.setActivationPolicy(.accessory)
app.run()
