import AppKit
import Foundation
import SwiftUI

private struct CheckResult: Decodable, Identifiable, Sendable {
    let id: String
    let title: String
    let status: String
    let detail: String
    let required: Bool
    let evidence: [String]
    let evidenceScope: String?

    private enum CodingKeys: String, CodingKey {
        case id, title, status, detail, required, evidence
        case evidenceScope = "evidence_scope"
    }
    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = try c.decode(String.self, forKey: .id)
        title = try c.decode(String.self, forKey: .title)
        status = try c.decode(String.self, forKey: .status)
        detail = try c.decode(String.self, forKey: .detail)
        required = try c.decodeIfPresent(Bool.self, forKey: .required) ?? true
        evidence = try c.decodeIfPresent([String].self, forKey: .evidence) ?? []
        evidenceScope = try c.decodeIfPresent(String.self, forKey: .evidenceScope)
    }

    var statusLabel: String {
        switch status {
        case "pass": return "通过"
        case "fail": return "未通过"
        case "warn": return "需注意"
        case "info": return !required && id == "dns_egress" ? "已实测" : "信息"
        default: return "未确认"
        }
    }

    var summaryDetail: String {
        detail.count > 88 ? String(detail.prefix(84)) + "…" : detail
    }

    var hasEvidence: Bool {
        !evidence.isEmpty || !(evidenceScope ?? "").isEmpty
    }

    var hasExpandedDetail: Bool {
        hasEvidence || summaryDetail != detail
    }
}

private struct Settings: Codable, Equatable, Sendable {
    var group = ""
    var policy = ""
    var expected_ip = ""
    var proxy_url = "http://127.0.0.1:62919"
    var profile_path = ""
    var expected_timezone = ""
    var expected_locale = ""
    var expected_country = ""
    var expected_asn = ""
    var browser_language = ""
    var browser_path = ""
    var default_model = ""
    var default_effort = ""
    var browser_start_page = "claude"
    var workspace = "A"
    var privacy_strict = true
    var guard_interval = 10

    init(group: String = "", policy: String = "", expected_ip: String = "",
         proxy_url: String = "http://127.0.0.1:62919", profile_path: String = "") {
        self.group = group
        self.policy = policy
        self.expected_ip = expected_ip
        self.proxy_url = proxy_url
        self.profile_path = profile_path
    }

    private enum CodingKeys: String, CodingKey {
        case group, policy, expected_ip, proxy_url, profile_path
        case expected_timezone, expected_locale, expected_country, expected_asn
        case browser_language, browser_path, privacy_strict, guard_interval, workspace
        case default_model, default_effort, browser_start_page
    }

    init(from decoder: Decoder) throws {
        // Error responses can legitimately have settings:{} before a config exists.
        let container = try decoder.container(keyedBy: CodingKeys.self)
        group = try container.decodeIfPresent(String.self, forKey: .group) ?? ""
        policy = try container.decodeIfPresent(String.self, forKey: .policy) ?? ""
        expected_ip = try container.decodeIfPresent(String.self, forKey: .expected_ip) ?? ""
        proxy_url = try container.decodeIfPresent(String.self, forKey: .proxy_url) ?? "http://127.0.0.1:62919"
        profile_path = try container.decodeIfPresent(String.self, forKey: .profile_path) ?? ""
        expected_timezone = try container.decodeIfPresent(String.self, forKey: .expected_timezone) ?? ""
        expected_locale = try container.decodeIfPresent(String.self, forKey: .expected_locale) ?? ""
        expected_country = try container.decodeIfPresent(String.self, forKey: .expected_country) ?? ""
        expected_asn = try container.decodeIfPresent(String.self, forKey: .expected_asn) ?? ""
        browser_language = try container.decodeIfPresent(String.self, forKey: .browser_language) ?? ""
        browser_path = try container.decodeIfPresent(String.self, forKey: .browser_path) ?? ""
        default_model = try container.decodeIfPresent(String.self, forKey: .default_model) ?? ""
        default_effort = try container.decodeIfPresent(String.self, forKey: .default_effort) ?? ""
        browser_start_page = try container.decodeIfPresent(String.self, forKey: .browser_start_page) ?? "claude"
        workspace = try container.decodeIfPresent(String.self, forKey: .workspace) ?? "A"
        privacy_strict = try container.decodeIfPresent(Bool.self, forKey: .privacy_strict) ?? true
        guard_interval = try container.decodeIfPresent(Int.self, forKey: .guard_interval) ?? 10
    }

    var isComplete: Bool {
        [group, policy, expected_ip, proxy_url].allSatisfy {
            !$0.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
        }
    }
}

private indirect enum JSONValue: Decodable, Sendable {
    case object([String: JSONValue]), array([JSONValue]), string(String), number(Double), bool(Bool), null
    init(from decoder: Decoder) throws {
        let c = try decoder.singleValueContainer()
        if c.decodeNil() { self = .null }
        else if let v = try? c.decode(Bool.self) { self = .bool(v) }
        else if let v = try? c.decode(String.self) { self = .string(v) }
        else if let v = try? c.decode(Double.self) { self = .number(v) }
        else if let v = try? c.decode([JSONValue].self) { self = .array(v) }
        else { self = .object(try c.decode([String: JSONValue].self)) }
    }
    var object: [String: JSONValue] { if case .object(let v) = self { return v }; return [:] }
    var array: [JSONValue] { if case .array(let v) = self { return v }; return [] }
    var string: String? { if case .string(let v) = self { return v }; return nil }
    var bool: Bool? { if case .bool(let v) = self { return v }; return nil }
    var number: Double? { if case .number(let v) = self { return v }; return nil }
}

private enum BrowserRecoveryAction: String, Sendable {
    case repairBrowserLocks = "repair-browser-locks"
    case recoverDedicatedBrowser = "recover-browser"

    enum Completion: Equatable {
        case recheck, showFailure
    }

    func arguments(workspace: String) -> [String]? {
        guard ["A", "B"].contains(workspace) else { return nil }
        switch self {
        case .repairBrowserLocks:
            return ["browser-locks", "repair", "--workspace", workspace, "--json"]
        case .recoverDedicatedBrowser:
            return ["browser-locks", "recover", "--workspace", workspace, "--json"]
        }
    }

    var title: String {
        switch self {
        case .repairBrowserLocks: return "仅清理已退出窗口的残留锁"
        case .recoverDedicatedBrowser: return "关闭专用窗口并修复"
        }
    }

    var detail: String {
        switch self {
        case .repairBrowserLocks:
            return "仅处理当前专用工作区已退出窗口的残留锁，先备份再清理。保留登录资料和个人 Chrome；若仍有进程运行，会提示你先退出。修复后自动重新检查线路。"
        case .recoverDedicatedBrowser:
            return "会关闭当前工作区的专用浏览器，中断其中网页和授权，再备份并清理残留锁。保留登录资料，个人 Chrome 不受影响。完成后自动重新检查，不会自动打开网页或登录。"
        }
    }

    var progressMessage: String {
        switch self {
        case .repairBrowserLocks: return "正在确认专用浏览器已退出，并备份、清理残留锁…"
        case .recoverDedicatedBrowser: return "正在关闭当前工作区的专用浏览器，并备份、清理残留锁…"
        }
    }

    func completion(_ response: BackendResponse, exitCode: Int32) -> Completion {
        // Browser repair returns maintenance results, which must never pass the
        // route gate. Only a new complete check can establish the route status.
        return response.ok && exitCode == 0 ? .recheck : .showFailure
    }

    // Recovery is an explicit allowlist, never a backend-supplied command line.
    // A failed repair remains retryable even if its response has no action field.
    static func after(_ response: BackendResponse?, exitCode: Int32,
                      retrying previous: BrowserRecoveryAction? = nil) -> BrowserRecoveryAction? {
        guard let response else { return previous }
        guard !response.ok || exitCode != 0 else { return nil }
        return response.recoveryAction ?? previous
    }

    static func checksAfterRepair(_ response: BackendResponse, exitCode: Int32) -> [CheckResult] {
        // Success discards stale launch failures. A refusal keeps the current
        // reason visible, such as a live browser process or a permission error.
        response.ok && exitCode == 0 ? [] : (response.checks ?? [])
    }
}

private struct BackendResponse: Decodable, Sendable {
    let schema: Int
    let ok: Bool
    let summary: String
    let checked_at: String?
    let checks: [CheckResult]?
    let settings: Settings?
    let launched: Bool?
    let target: String?
    let recoveryAction: BrowserRecoveryAction?
    let paused: Bool?
    let pauseReason: String?
    let surgeMode: String?
    let launchAllowed: Bool?
    let protectionActive: Bool?
    let document: [String: JSONValue]

    private enum CodingKeys: String, CodingKey {
        case schema, ok, summary, checked_at, checks, settings, launched, target, paused
        case recoveryAction = "recovery_action"
        case pauseReason = "pause_reason"
        case surgeMode = "surge_mode"
        case launchAllowed = "launch_allowed"
        case protectionActive = "protection_active"
    }
    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        schema = try c.decode(Int.self, forKey: .schema)
        ok = try c.decode(Bool.self, forKey: .ok)
        summary = try c.decode(String.self, forKey: .summary)
        checked_at = try c.decodeIfPresent(String.self, forKey: .checked_at)
        checks = try c.decodeIfPresent([CheckResult].self, forKey: .checks)
        settings = try c.decodeIfPresent(Settings.self, forKey: .settings)
        launched = try c.decodeIfPresent(Bool.self, forKey: .launched)
        target = try c.decodeIfPresent(String.self, forKey: .target)
        recoveryAction = try c.decodeIfPresent(String.self, forKey: .recoveryAction)
            .flatMap(BrowserRecoveryAction.init(rawValue:))
        paused = try c.decodeIfPresent(Bool.self, forKey: .paused)
        pauseReason = try c.decodeIfPresent(String.self, forKey: .pauseReason)
        surgeMode = try c.decodeIfPresent(String.self, forKey: .surgeMode)
        launchAllowed = try c.decodeIfPresent(Bool.self, forKey: .launchAllowed)
        protectionActive = try c.decodeIfPresent(Bool.self, forKey: .protectionActive)
        document = try JSONValue(from: decoder).object
    }
}

private enum CheckAssessment: Equatable {
    case passed, caution, blocked, paused, suspended
    static func assess(_ response: BackendResponse, exitCode: Int32) -> CheckAssessment {
        let rows = response.checks ?? []
        let required = rows.filter(\.required)
        let knownStatuses = Set(["pass", "fail", "unknown", "warn", "info"])
        guard response.schema == 1, !rows.isEmpty, !required.isEmpty,
              Set(rows.map(\.id)).count == rows.count,
              rows.allSatisfy({ knownStatuses.contains($0.status) }) else { return .blocked }
        if response.paused == true {
            guard required.contains(where: { $0.id == "mode" && $0.status == "fail" }) else { return .blocked }
            if response.pauseReason == "surge-global-mode" {
                // Suspension is an explicit mode choice, not a successful route
                // check. Accept only this exact contract, including launch result.
                guard response.surgeMode == "proxy", response.launchAllowed == true,
                      response.protectionActive == false,
                      required.contains(where: { $0.id == "surge" && $0.status == "pass" }),
                      required.filter({ $0.id != "mode" }).allSatisfy({ $0.status == "pass" }) else { return .blocked }
                if response.ok {
                    guard exitCode == 0, response.launched == true,
                          ["web", "code-terminal"].contains(response.target ?? "") else { return .blocked }
                } else {
                    guard exitCode == 2, response.launched != true, response.target == nil else { return .blocked }
                }
                return .suspended
            }
            // Legacy/direct-mode pauses still block startup.
            guard !response.ok, exitCode != 0, response.pauseReason == "surge-mode",
                  response.surgeMode == nil || response.surgeMode == "direct",
                  response.launchAllowed != true, response.protectionActive != true,
                  response.launched != true else { return .blocked }
            return .paused
        }
        guard response.pauseReason == nil, response.surgeMode == nil, response.launchAllowed == nil,
              response.protectionActive == nil, response.ok, exitCode == 0,
              required.allSatisfy({ $0.status == "pass" }) else { return .blocked }
        return rows.contains { !$0.required && !["pass", "info"].contains($0.status) } ? .caution : .passed
    }
}

private struct CheckOverview {
    let rows: [CheckResult]
    var required: [CheckResult] { rows.filter(\.required) }
    var pending: [CheckResult] {
        rows.filter { !$0.required && !["pass", "info"].contains($0.status) }
    }
    var information: [CheckResult] {
        rows.filter { !$0.required && ["pass", "info"].contains($0.status) }
    }
    var summary: String {
        var parts = ["启动必需 \(required.filter { $0.status == "pass" }.count)/\(required.count) 项通过"]
        if !pending.isEmpty { parts.append("\(pending.count) 项补充待确认") }
        if !information.isEmpty { parts.append("\(information.count) 项补充信息") }
        return parts.joined(separator: "；") + "。"
    }
}

private struct Snapshot: Identifiable, Sendable {
    let id: String
    let label: String
    let date: String
}

// Only public status fields are decoded here; credentials never enter report models.
private struct WorkspaceSummary: Sendable {
    let name: String
    let policy: String
    let expectedIP: String
    let group: String
    let routeConfigured: Bool
    let hasBrowserProfile: Bool?
    let authMode: String
    let authConfigured: Bool

    init?(_ value: JSONValue) {
        let object = value.object
        guard let name = object["name"]?.string, ["A", "B"].contains(name) else { return nil }
        self.name = name
        let route = object["route"]?.object ?? [:]
        policy = route["policy"]?.string ?? ""
        expectedIP = route["expected_ip"]?.string ?? ""
        group = route["group"]?.string ?? ""
        routeConfigured = !policy.isEmpty && !expectedIP.isEmpty && !group.isEmpty
        hasBrowserProfile = object["browser"]?.object["has_profile"]?.bool
        let auth = object["auth"]?.object ?? [:]
        authMode = auth["mode"]?.string ?? "unconfigured"
        authConfigured = auth["configured"]?.bool ?? false
    }

    var browserDescription: String {
        switch hasBrowserProfile {
        case true: return "专用资料已保存；网页登录和 OAuth 共用此资料，登录状态以页面为准。"
        case false: return "尚未建立专用浏览器资料；首次打开时创建，不复制其他工作区登录。"
        case nil: return "浏览器状态尚未确认，请刷新工作区。"
        }
    }

    var authDescription: String {
        switch (authMode, authConfigured) {
        case ("token", true): return "本工作区已绑定钥匙串 Token；不会使用其他工作区的 Token。"
        case ("oauth", true): return "使用本工作区的 OAuth 登录；是否已登录，请在 Claude Code 内确认。"
        case ("oauth", false), ("unconfigured", _): return "尚未设置独立 CLI 凭据；可选择 OAuth 登录，或保存此账号的 Token。"
        case ("token", false): return "本工作区 Token 尚不可用，请重新保存或选择 OAuth。"
        default: return "CLI 凭据状态未确认，请刷新工作区。"
        }
    }
}

private enum WorkspaceCommand {
    static func use(_ name: String) -> [String]? {
        guard ["A", "B"].contains(name) else { return nil }
        return ["workspace", "use", "--name", name, "--close-sessions", "--json"]
    }
    static func auth(_ action: String, workspace: String) -> [String]? {
        guard ["A", "B"].contains(workspace), ["store", "oauth"].contains(action) else { return nil }
        var arguments = ["workspace-auth", action, "--workspace", workspace]
        if action == "store" { arguments.append("--stdin") }
        return arguments + ["--json"]
    }
    static func refreshedSettings(_ response: BackendResponse, exitCode: Int32) -> Settings? {
        guard response.ok, exitCode == 0, let settings = response.settings,
              let explicitWorkspace = response.document["settings"]?.object["workspace"]?.string,
              ["A", "B"].contains(explicitWorkspace), settings.workspace == explicitWorkspace else { return nil }
        return settings
    }
    static func tokenInput(_ text: String) -> Data? {
        let token = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !token.isEmpty, token.utf8.count <= 16_384,
              !token.contains(where: { $0.isWhitespace || $0.isNewline }) else { return nil }
        return Data((token + "\n").utf8)
    }
}

private struct RepairAction: Identifiable, Sendable {
    let id: String
    let title: String
    let detail: String
}

private struct CommandResult: Sendable {
    let response: BackendResponse?
    let exitCode: Int32
    let error: String?
}

private enum Backend {
    static var configURL: URL {
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Application Support/Surge CC/config.json")
    }

    static func initialSettings() -> Settings {
        guard let data = try? Data(contentsOf: configURL),
              let settings = try? JSONDecoder().decode(Settings.self, from: data) else {
            return Settings()
        }
        return settings
    }

    static func scriptURL() -> URL? {
        if let bundled = Bundle.main.resourceURL?.appendingPathComponent("scripts/surge-cc"),
           FileManager.default.fileExists(atPath: bundled.path) {
            return bundled
        }
        // Also permits running a locally compiled development binary.
        let development = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("scripts/surge-cc")
        return FileManager.default.fileExists(atPath: development.path) ? development : nil
    }

    static func run(_ arguments: [String], workingDirectory: URL, standardInput: Data? = nil) -> CommandResult {
        guard let script = scriptURL() else {
            return CommandResult(response: nil, exitCode: 1, error: "找不到配套程序，请重新构建或安装 Surge CC。")
        }
        let candidates = ["/opt/homebrew/bin/python3", "/usr/local/bin/python3", "/usr/bin/python3",
                          "/Applications/Xcode.app/Contents/Developer/Library/Frameworks/Python3.framework/Versions/Current/bin/python3",
                          "/Library/Developer/CommandLineTools/usr/bin/python3"]
        guard let python = candidates.first(where: { path in
            guard FileManager.default.isExecutableFile(atPath: path) else { return false }
            let probe = Process()
            probe.executableURL = URL(fileURLWithPath: path)
            probe.arguments = ["-I", "-c", "import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)"]
            probe.standardInput = FileHandle.nullDevice
            probe.standardOutput = FileHandle.nullDevice
            probe.standardError = FileHandle.nullDevice
            let timeout = DispatchWorkItem { if probe.isRunning { probe.terminate() } }
            do { try probe.run() } catch { return false }
            DispatchQueue.global().asyncAfter(deadline: .now() + 5, execute: timeout)
            probe.waitUntilExit()
            timeout.cancel()
            return probe.terminationStatus == 0
        }) else {
            return CommandResult(response: nil, exitCode: 1, error: "需要 Python 3.9 或更新版本；请运行配置向导检查依赖。")
        }
        let process = Process()
        process.executableURL = URL(fileURLWithPath: python)
        process.arguments = ["-B", script.path, "--config", configURL.path] + arguments
        // The backend resolves its own package by absolute path. A launched
        // terminal must never treat the signed app's Resources as a user project.
        process.currentDirectoryURL = workingDirectory
        let output = Pipe()
        process.standardOutput = output
        process.standardError = output
        // Token entry is passed through stdin, never process arguments, environment,
        // user defaults, reports, or a temporary file.
        let input = standardInput == nil ? nil : Pipe()
        process.standardInput = input?.fileHandleForReading ?? FileHandle.nullDevice

        let deadline: TimeInterval = 180
        let watchdog = DispatchWorkItem {
            // Only terminate this app's backend process, never a browser or proxy.
            if process.isRunning { process.terminate() }
        }
        do {
            try process.run()
        } catch {
            return CommandResult(response: nil, exitCode: 1, error: "无法启动检查程序：\(error.localizedDescription)")
        }
        DispatchQueue.global().asyncAfter(deadline: .now() + deadline, execute: watchdog)
        if let input, let standardInput {
            do {
                try input.fileHandleForWriting.write(contentsOf: standardInput)
                try input.fileHandleForWriting.close()
            } catch {
                try? input.fileHandleForWriting.close()
                if process.isRunning { process.terminate() }
            }
        }
        // Drain while the process runs, so a full pipe cannot deadlock waitUntilExit.
        let data = output.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        watchdog.cancel()
        try? output.fileHandleForReading.close()
        if process.terminationReason == .uncaughtSignal {
            return CommandResult(response: nil, exitCode: process.terminationStatus, error: "操作已中止或超时；没有可用的检查结果，请重试。")
        }
        guard data.count <= 5_000_000,
              let response = try? JSONDecoder().decode(BackendResponse.self, from: data),
              response.schema == 1 else {
            // Do not display raw stdout/stderr: it may contain private local details.
            return CommandResult(response: nil, exitCode: process.terminationStatus, error: "检查程序未返回有效结果；当前线路状态尚未确认。")
        }
        return CommandResult(response: response, exitCode: process.terminationStatus, error: nil)
    }
}

private enum DisplayState {
    case idle, busy, passed, caution, blocked, paused, suspended, saved, launched, message

    var title: String {
        switch self {
        case .idle: return "尚未检查"
        case .busy: return "处理中"
        case .passed: return "本次检查通过"
        case .caution: return "基础检查通过，部分项目待确认"
        case .blocked: return "尚未通过"
        case .paused: return "已暂停启动"
        case .suspended: return "保护已挂起"
        case .saved: return "配置已保存"
        case .launched: return "已启动"
        case .message: return "操作完成"
        }
    }

    var color: Color {
        switch self {
        case .passed, .launched: return .green
        case .busy: return .blue
        case .blocked, .caution, .paused, .suspended: return .orange
        case .saved, .idle, .message: return .secondary
        }
    }
}

private enum Operation: Equatable {
    case check, configure, workspaceList, workspaceUse, workspaceAuth, snapshot, restore, repairPlan, repair, guardStatus, recovery
}

@MainActor
private final class ViewModel: ObservableObject {
    @Published var settings = Backend.initialSettings()
    @Published var checks: [CheckResult] = []
    @Published var state: DisplayState = .idle
    @Published var summary = "先检查 Surge 与指定线路，再启动 Claude。"
    @Published var checkedAt = ""
    @Published var showingSettings = false
    @Published var settingsError = ""
    @Published var draft = Settings()
    @Published var projectDirectory = FileManager.default.homeDirectoryForCurrentUser
    @Published var selectedTab = 0
    @Published var selectedWorkspace = "A"
    @Published var currentWorkspace = ""
    @Published var workspaceSnapshots: [String: [Snapshot]] = [:]
    @Published var workspaceDetails: [String: WorkspaceSummary] = [:]
    @Published var confirmingWorkspaceSwitch = false
    @Published var pendingWorkspace = ""
    @Published var showingTokenEntry = false
    @Published var confirmingOAuth = false
    @Published var credentialWorkspace = ""
    @Published var tokenDraft = ""
    @Published var credentialError = ""
    @Published var selectedSnapshot = ""
    @Published var snapshotLabel = ""
    @Published var showingRepair = false
    @Published var repairActions: [RepairAction] = []
    @Published var repairPlanID = ""
    @Published var browserRecoveryAction: BrowserRecoveryAction?
    @Published var guardRunning: Bool?
    @Published var guardSuspended = false
    @Published var suspendedSessions = 0
    @Published var guardDetail = "尚未读取保护状态。"
    @Published var guardCheckedAt = ""
    @Published var guardInterval: Int?
    @Published var confirmingSnapshot = false
    @Published var confirmingRestore = false
    @Published var settingsPane = 0
    private var requestID = UUID()

    init() {
        selectedWorkspace = ["A", "B"].contains(settings.workspace) ? settings.workspace : "A"
    }

    var busy: Bool { state == .busy }
    var statusExplanation: String? {
        switch state {
        case .passed, .caution:
            return CheckOverview(rows: checks).summary
        default:
            return summary == state.title || summary.isEmpty ? nil : summary
        }
    }

    func openSettings() {
        draft = settings
        settingsError = ""
        showingSettings = true
    }

    var activeWorkspace: String { currentWorkspace.isEmpty ? settings.workspace : currentWorkspace }
    var selectedWorkspaceDetails: WorkspaceSummary? { workspaceDetails[selectedWorkspace] }
    var snapshots: [Snapshot] { workspaceSnapshots[selectedWorkspace] ?? [] }
    var selectedSnapshotLabel: String { snapshots.first { $0.id == selectedSnapshot }?.label ?? selectedSnapshot }

    func perform(_ arguments: [String], message: String, operation: Operation = .check,
                 workingDirectory: URL = FileManager.default.homeDirectoryForCurrentUser,
                 standardInput: Data? = nil) {
        guard !busy else { return }
        let id = UUID()
        requestID = id
        let retryingRecovery = operation == .recovery ? browserRecoveryAction : nil
        if operation != .recovery { browserRecoveryAction = nil }
        state = .busy
        summary = message
        checks = []
        checkedAt = ""
        settingsError = ""
        if operation == .guardStatus {
            guardRunning = nil
            guardSuspended = false
            suspendedSessions = 0
            guardDetail = "正在读取保护状态…"
            guardCheckedAt = ""
            guardInterval = nil
        }
        Task {
            let result = await Task.detached(priority: .userInitiated) {
                Backend.run(arguments, workingDirectory: workingDirectory, standardInput: standardInput)
            }.value
            guard self.requestID == id else { return }
            self.browserRecoveryAction = BrowserRecoveryAction.after(
                result.response, exitCode: result.exitCode, retrying: retryingRecovery)
            guard let response = result.response else {
                self.state = .blocked
                self.summary = result.error ?? "无法确认当前线路。"
                if operation == .configure { self.settingsError = self.summary }
                if operation == .workspaceAuth { self.credentialError = self.summary }
                if operation == .guardStatus { self.guardDetail = self.summary }
                return
            }
            if let settings = response.settings, settings.isComplete {
                self.settings = settings
                self.currentWorkspace = settings.workspace
            } else if [.workspaceList, .workspaceUse, .workspaceAuth].contains(operation),
                      let settings = WorkspaceCommand.refreshedSettings(response, exitCode: result.exitCode) {
                // An explicit, successful unconfigured target must replace the
                // previous route too. Error settings:{} must never reset it to A.
                self.settings = settings
                self.currentWorkspace = settings.workspace
            }
            self.summary = response.summary
            if operation == .configure {
                if response.ok && result.exitCode == 0 {
                    self.state = .saved
                    self.summary = "配置已保存，尚未检查。"
                    self.showingSettings = false
                    if self.selectedTab == 1 {
                        self.refreshWorkspaces()
                    }
                } else {
                    self.state = .blocked
                    self.settingsError = response.summary
                }
                return
            }
            if operation == .recovery, let action = retryingRecovery {
                switch action.completion(response, exitCode: result.exitCode) {
                case .recheck:
                    // Leave busy before starting the new check. It clears the old
                    // repair action and obtains fresh evidence without auto-launch.
                    self.state = .message
                    self.check()
                    return
                case .showFailure:
                    self.state = .blocked
                    self.checks = BrowserRecoveryAction.checksAfterRepair(response, exitCode: result.exitCode)
                    return
                }
            }
            if operation != .check && operation != .recovery {
                self.state = response.ok && result.exitCode == 0 ? .message : .blocked
                if operation == .guardStatus && self.state == .blocked { self.guardDetail = response.summary }
                if response.ok && result.exitCode == 0 {
                    switch operation {
                    case .workspaceList, .workspaceUse, .workspaceAuth, .snapshot, .restore:
                        self.consumeWorkspaces(response)
                        if operation == .workspaceUse {
                            self.selectedWorkspace = self.activeWorkspace
                            self.selectedSnapshot = ""
                            self.guardRunning = nil
                            self.guardDetail = "工作区已切换，请重新检查线路后启动。"
                        }
                        if operation == .workspaceAuth {
                            self.showingTokenEntry = false
                            self.credentialError = ""
                        }
                    case .repairPlan:
                        self.consumeRepairPlan(response)
                    case .repair:
                        self.showingRepair = false
                        self.repairActions = []
                        self.repairPlanID = ""
                    case .guardStatus:
                        self.consumeGuard(response)
                    default: break
                    }
                }
                if operation == .workspaceAuth && self.state == .blocked {
                    self.credentialError = response.summary
                }
                self.checks = response.checks ?? []
                return
            }
            let rows = response.checks ?? []
            let uniqueIDs = Set(rows.map(\.id)).count == rows.count
            self.checks = uniqueIDs ? rows : []
            self.checkedAt = Self.displayTime(response.checked_at)
            switch CheckAssessment.assess(response, exitCode: result.exitCode) {
            case .passed:
                self.state = response.launched == true ? .launched : .passed
            case .caution:
                self.state = .caution
            case .paused:
                self.state = .paused
            case .suspended:
                self.state = .suspended
            case .blocked:
                self.state = .blocked
                if !uniqueIDs || rows.isEmpty {
                    self.summary = "检查结果不完整，当前线路尚未确认。"
                }
            }
        }
    }

    func check() {
        perform(["check", "--json"], message: "正在检查线路、DNS 与浏览器 WebRTC…")
    }

    func pin() {
        perform(["pin", "--json"], message: "正在固定指定节点并重新检查…")
    }

    func launchWeb() {
        perform(["launch", "web", "--json"], message: "正在读取 Surge 模式并准备专用浏览器…")
    }

    func launchCode() {
        perform(["launch", "code", "--terminal", "--json"],
                message: "正在读取 Surge 模式并准备 Claude Code…",
                workingDirectory: projectDirectory)
    }

    func refreshWorkspaces() {
        perform(["workspace", "list", "--json"], message: "正在读取本地工作区…", operation: .workspaceList)
    }

    func requestWorkspaceSwitch() {
        guard !busy, WorkspaceCommand.use(selectedWorkspace) != nil,
              selectedWorkspace != activeWorkspace else { return }
        pendingWorkspace = selectedWorkspace
        confirmingWorkspaceSwitch = true
    }

    func useWorkspace() {
        guard let arguments = WorkspaceCommand.use(pendingWorkspace) else { return }
        perform(arguments, message: "正在结束当前专用会话并切换账号工作区…", operation: .workspaceUse)
    }

    func openTokenEntry() {
        guard !busy, WorkspaceCommand.auth("store", workspace: selectedWorkspace) != nil else { return }
        credentialWorkspace = selectedWorkspace
        tokenDraft = ""
        credentialError = ""
        showingTokenEntry = true
    }

    func storeToken() {
        guard let arguments = WorkspaceCommand.auth("store", workspace: credentialWorkspace),
              let input = WorkspaceCommand.tokenInput(tokenDraft) else {
            credentialError = "请输入有效的单行 Token。"
            return
        }
        tokenDraft = ""
        perform(arguments, message: "正在保存工作区 \(credentialWorkspace) 的独立钥匙串凭据…",
                operation: .workspaceAuth, standardInput: input)
    }

    func requestOAuth() {
        guard !busy, WorkspaceCommand.auth("oauth", workspace: selectedWorkspace) != nil else { return }
        credentialWorkspace = selectedWorkspace
        confirmingOAuth = true
    }

    func useOAuth() {
        guard let arguments = WorkspaceCommand.auth("oauth", workspace: credentialWorkspace) else { return }
        perform(arguments, message: "正在设置工作区 \(credentialWorkspace) 的独立 OAuth 登录…",
                operation: .workspaceAuth)
    }

    func snapshotWorkspace() {
        guard ["A", "B"].contains(selectedWorkspace) else { return }
        var args = ["workspace", "snapshot", "--name", selectedWorkspace]
        let label = snapshotLabel.trimmingCharacters(in: .whitespacesAndNewlines)
        if !label.isEmpty { args += ["--label", label] }
        perform(args + ["--json"], message: "正在保存工作区快照…", operation: .snapshot)
    }

    func restoreWorkspace() {
        guard ["A", "B"].contains(selectedWorkspace),
              snapshots.contains(where: { $0.id == selectedSnapshot }) else { return }
        perform(["workspace", "restore", "--name", selectedWorkspace,
                 "--snapshot", selectedSnapshot, "--json"],
                message: "正在备份当前数据并恢复所选快照…", operation: .restore)
    }

    func planRepair() {
        repairPlanID = ""
        repairActions = []
        perform(["repair-plan", "--json"], message: "正在生成修复计划…", operation: .repairPlan)
    }

    func applyRepair() {
        guard !repairPlanID.isEmpty, !repairActions.isEmpty else { return }
        perform(["repair", "--plan-id", repairPlanID, "--json"],
                message: "正在执行已确认的修复计划…", operation: .repair)
    }

    func refreshGuard() {
        perform(["guard-status", "--json"], message: "正在读取保护状态…", operation: .guardStatus)
    }

    func repairBrowserLocks() {
        recover(.repairBrowserLocks)
    }

    func recoverDedicatedBrowser() {
        recover(.recoverDedicatedBrowser)
    }

    func recover(_ action: BrowserRecoveryAction) {
        // The workspace maintenance entry remains available after an app restart,
        // without provoking a launch error or opening any authentication page.
        guard !busy, let arguments = action.arguments(workspace: settings.workspace) else { return }
        browserRecoveryAction = action
        perform(arguments, message: action.progressMessage, operation: .recovery)
    }

    private func consumeWorkspaces(_ response: BackendResponse) {
        if let current = response.document["current_workspace"]?.string, ["A", "B"].contains(current) {
            currentWorkspace = current
        }
        guard response.document["workspaces"] != nil else { return }
        var collected: [String: [Snapshot]] = [:]
        var details: [String: WorkspaceSummary] = [:]
        for item in response.document["workspaces"]?.array ?? [] {
            let object = item.object
            guard let name = object["name"]?.string, ["A", "B"].contains(name) else { continue }
            details[name] = WorkspaceSummary(item)
            var seen = Set<String>()
            collected[name] = (object["snapshots"]?.array ?? []).compactMap { value in
                let snapshot = value.object
                guard let id = snapshot["id"]?.string, !id.isEmpty, seen.insert(id).inserted else { return nil }
                let label = snapshot["label"]?.string ?? ""
                return Snapshot(id: id, label: label.isEmpty ? "工作区快照" : label,
                                date: snapshot["created_at"]?.string ?? "")
            }
        }
        workspaceSnapshots = collected
        workspaceDetails = details
        if !snapshots.contains(where: { $0.id == selectedSnapshot }) { selectedSnapshot = "" }
    }

    private func consumeRepairPlan(_ response: BackendResponse) {
        repairPlanID = response.document["plan_id"]?.string ?? ""
        repairActions = (response.document["actions"]?.array ?? []).enumerated().map { index, value in
            let action = value.object
            return RepairAction(id: action["id"]?.string ?? "\(index)",
                                title: action["title"]?.string ?? "待确认操作",
                                detail: action["detail"]?.string ?? "")
        }
        if !repairActions.isEmpty {
            if repairPlanID.isEmpty {
                state = .blocked
                summary = "修复计划缺少有效编号，不能执行。"
            } else { showingRepair = true }
        }
    }

    private func consumeGuard(_ response: BackendResponse) {
        let guardInfo = response.document["guard"]?.object ?? [:]
        guardRunning = guardInfo["running"]?.bool
        guardSuspended = guardInfo["state"]?.string == "suspended"
            && guardRunning == false && guardInfo["protection_active"]?.bool == false
            && guardInfo["suspended"]?.bool == true
        let reportedSessions = guardInfo["suspended_sessions"]?.number ?? 0
        suspendedSessions = reportedSessions.isFinite && reportedSessions >= 0
            && reportedSessions <= 100_000 ? Int(reportedSessions) : 0
        guardInterval = guardInfo["interval"]?.number.map(Int.init)
        guardDetail = guardInfo["detail"]?.string ?? response.summary
        guardCheckedAt = Self.displayTime(guardInfo["last_checked_at"]?.string)
    }

    func chooseProject() {
        let panel = NSOpenPanel()
        panel.title = "选择 Claude Code 的项目文件夹"
        panel.canChooseDirectories = true
        panel.canChooseFiles = false
        panel.canCreateDirectories = false
        panel.allowsMultipleSelection = false
        panel.directoryURL = projectDirectory
        if panel.runModal() == .OK, let url = panel.url {
            projectDirectory = url
            checks = []
            checkedAt = ""
            state = .idle
            summary = "已选择项目，启动时将读取 Surge 模式并核验项目设置。"
        }
    }

    func saveSettings() {
        var cleaned = draft
        cleaned.group = draft.group.trimmingCharacters(in: .whitespacesAndNewlines)
        cleaned.policy = draft.policy.trimmingCharacters(in: .whitespacesAndNewlines)
        cleaned.expected_ip = draft.expected_ip.trimmingCharacters(in: .whitespacesAndNewlines)
        cleaned.proxy_url = draft.proxy_url.trimmingCharacters(in: .whitespacesAndNewlines)
        cleaned.profile_path = draft.profile_path.trimmingCharacters(in: .whitespacesAndNewlines)
        guard cleaned.isComplete else {
            settingsError = "请填写策略组、指定节点、预期出口 IP 和本地代理地址。"
            return
        }
        var args = [
            "configure", "--expected-workspace", draft.workspace, "--group", cleaned.group, "--policy", cleaned.policy,
            "--expected-ip", cleaned.expected_ip, "--proxy-url", cleaned.proxy_url
        ]
        // Pass an empty optional path too, so clearing the field clears old configuration.
        args += ["--profile", cleaned.profile_path,
                 "--expected-timezone", cleaned.expected_timezone.trimmingCharacters(in: .whitespacesAndNewlines),
                 "--expected-locale", cleaned.expected_locale.trimmingCharacters(in: .whitespacesAndNewlines),
                 "--expected-country", cleaned.expected_country.trimmingCharacters(in: .whitespacesAndNewlines),
                 "--expected-asn", cleaned.expected_asn.trimmingCharacters(in: .whitespacesAndNewlines),
                 "--browser-language", cleaned.browser_language.trimmingCharacters(in: .whitespacesAndNewlines),
                 "--default-model", cleaned.default_model.trimmingCharacters(in: .whitespacesAndNewlines),
                 "--default-effort", cleaned.default_effort,
                 "--browser-start-page", cleaned.browser_start_page,
                 "--privacy-strict", cleaned.privacy_strict ? "true" : "false",
                 "--guard-interval", String(cleaned.guard_interval), "--json"]
        perform(args, message: "正在保存配置…", operation: .configure)
    }

    static func displayTime(_ raw: String?) -> String {
        guard let raw else { return "" }
        let parser = ISO8601DateFormatter()
        parser.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        let fractional = parser.date(from: raw)
        parser.formatOptions = [.withInternetDateTime]
        guard let date = fractional ?? parser.date(from: raw) else { return "" }
        return date.formatted(date: .omitted, time: .standard)
    }
}

private struct ContentView: View {
    private func openSetupWizard() {
        guard let backend = Backend.scriptURL() else { return }
        let script = backend.deletingLastPathComponent().appendingPathComponent("first-run.sh")
        let fm = FileManager.default
        guard fm.fileExists(atPath: script.path) else { return }
        let folder = Backend.configURL.deletingLastPathComponent().appendingPathComponent("launchers")
        let command = folder.appendingPathComponent("Setup-\(UUID().uuidString).command")
        func quoted(_ value: String) -> String { "'" + value.replacingOccurrences(of: "'", with: "'\\''") + "'" }
        let content = "#!/bin/bash\n/bin/bash \(quoted(script.path)) --config \(quoted(Backend.configURL.path))\n"
        do {
            try fm.createDirectory(at: folder, withIntermediateDirectories: true,
                                   attributes: [.posixPermissions: 0o700])
            try content.write(to: command, atomically: true, encoding: .utf8)
            try fm.setAttributes([.posixPermissions: 0o700], ofItemAtPath: command.path)
            NSWorkspace.shared.open([command],
                withApplicationAt: URL(fileURLWithPath: "/System/Applications/Utilities/Terminal.app"),
                configuration: NSWorkspace.OpenConfiguration())
        } catch {
            let alert = NSAlert()
            alert.messageText = "配置向导未启动"
            alert.informativeText = "无法写入启动入口。可按 README 从终端运行 first-run.sh。"
            alert.runModal()
        }
    }
    @StateObject private var vm = ViewModel()

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            HStack(spacing: 12) {
                Image(systemName: "waveform.path")
                    .font(.system(size: 28, weight: .semibold))
                    .foregroundStyle(.blue)
                    .frame(width: 48, height: 48)
                    .background(.blue.opacity(0.10), in: RoundedRectangle(cornerRadius: 12))
                VStack(alignment: .leading, spacing: 3) {
                    Text("Surge CC").font(.title2.bold())
                    Text("检查线路 · 固定节点 · 启动 Claude")
                        .font(.subheadline).foregroundStyle(.secondary)
                }
                Spacer()
                Button("配置向导") { openSetupWizard() }
                    .help("检查依赖、专用浏览器、终端、项目隔离与 Dock 入口")
                    .disabled(vm.busy)
                Button { vm.openSettings() } label: {
                    Image(systemName: "slider.horizontal.3")
                }
                .help("设置")
                .disabled(vm.busy)
            }

            GroupBox {
                VStack(alignment: .leading, spacing: 10) {
                    HStack {
                        Label(vm.state.title, systemImage: vm.busy ? "arrow.triangle.2.circlepath" : "circle.fill")
                            .font(.subheadline.weight(.semibold)).foregroundStyle(vm.state.color)
                        Spacer()
                        if !vm.checkedAt.isEmpty {
                            Text(vm.checkedAt).font(.caption).foregroundStyle(.secondary)
                        }
                    }
                    if let explanation = vm.statusExplanation {
                        Text(explanation).font(.callout).fixedSize(horizontal: false, vertical: true)
                    }
                    if vm.settings.isComplete {
                        Divider()
                        LabeledContent("策略组", value: vm.settings.group)
                        LabeledContent("指定节点", value: vm.settings.policy)
                        LabeledContent("预期出口", value: vm.settings.expected_ip)
                        LabeledContent("当前工作区", value: vm.currentWorkspace.isEmpty ? vm.settings.workspace : vm.currentWorkspace)
                    } else {
                        Button("设置 Claude 专用线路") { vm.openSettings() }
                            .disabled(vm.busy)
                    }
                }.padding(6)
            }

            if let action = vm.browserRecoveryAction {
                VStack(alignment: .leading, spacing: 7) {
                    Button { vm.recover(action) } label: {
                        Label(action.title, systemImage: "wrench.and.screwdriver")
                    }
                    .disabled(vm.busy || action.arguments(workspace: vm.settings.workspace) == nil)
                    Text(action.detail)
                        .font(.caption).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }

            TabView(selection: $vm.selectedTab) {
                checksTab.tabItem { Label("检查", systemImage: "checklist") }.tag(0)
                workspacesTab.tabItem { Label("工作区", systemImage: "square.stack.3d.up") }.tag(1)
                protectionTab.tabItem { Label("保护", systemImage: "shield.lefthalf.filled") }.tag(2)
            }
            .frame(minHeight: 320, maxHeight: .infinity)
            .onChange(of: vm.selectedTab) { tab in
                if tab == 1 && !vm.busy { vm.refreshWorkspaces() }
            }

            HStack(spacing: 10) {
                Image(systemName: "folder").foregroundStyle(.secondary)
                VStack(alignment: .leading, spacing: 2) {
                    Text("Claude Code 项目").font(.caption).foregroundStyle(.secondary)
                    Text(vm.projectDirectory.path).font(.caption)
                        .lineLimit(1).truncationMode(.middle)
                        .help(vm.projectDirectory.path)
                }
                Spacer(minLength: 8)
                Button("选择文件夹…") { vm.chooseProject() }.disabled(vm.busy)
            }

            HStack {
                Button { vm.launchWeb() } label: {
                    Label("打开专用浏览器", systemImage: "globe")
                        .frame(maxWidth: .infinity)
                }
                Button { vm.launchCode() } label: {
                    Label("启动 Claude Code", systemImage: "terminal")
                        .frame(maxWidth: .infinity)
                }
                .help("在所选项目中启动 Claude Code，OAuth 使用专用授权窗口。规则模式检查线路；全局代理模式挂起固定出口保护。")
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.large)
            .disabled(vm.busy || !vm.settings.isComplete)

            Text(vm.settings.browser_path.isEmpty
                 ? "启动时读取 Surge 模式。规则模式检查线路；全局代理模式挂起保护，允许启动。工作区分别保存本地 CLI 与浏览器数据，不代表身份隔离。"
                 : "规则模式按指定出口保护；全局代理模式允许网页和 Claude Code 启动，固定出口与断线阻断挂起，流量依 Surge 全局策略。已登记的文件隔离仍保留，个人 Chrome 不变。")
                .font(.caption).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            Text("OAuth 使用专用授权窗口。规则模式授权前检查线路；全局代理模式沿用挂起状态。切回规则模式后需重新检查，才能恢复保护。")
                .font(.caption).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(24)
        .frame(minWidth: 660, idealWidth: 700, minHeight: 790, idealHeight: 850)
        .sheet(isPresented: $vm.showingSettings) {
            SettingsView(vm: vm)
        }
        .sheet(isPresented: $vm.showingRepair) {
            RepairPlanView(vm: vm)
        }
        .sheet(isPresented: $vm.showingTokenEntry) {
            WorkspaceTokenView(vm: vm)
        }
        .alert("切换到工作区 \(vm.pendingWorkspace)？", isPresented: $vm.confirmingWorkspaceSwitch) {
            Button("取消", role: .cancel) {}
            Button("切换并结束当前工作区会话", role: .destructive) { vm.useWorkspace() }
        } message: {
            Text("请先保存专用网页中的草稿和 CLI 任务。切换会结束 Surge CC 管理的当前浏览器、授权和 CLI 会话，再一起切换浏览器资料、CLI 凭据与线路设置。不会自动登录或启动任务，个人 Chrome 和其他代理服务保持不变。无法安全结束的进程会阻止切换。")
        }
        .alert("工作区 \(vm.credentialWorkspace) 改用 OAuth 登录？", isPresented: $vm.confirmingOAuth) {
            Button("取消", role: .cancel) {}
            Button("使用独立 OAuth") { vm.useOAuth() }
        } message: {
            Text("下次启动此工作区的 Claude Code 时使用它自己的 OAuth 登录，不再使用 Token 模式。这里只更改登录方式；不会代你登录，其他工作区不受影响。")
        }
        .alert("保存工作区 \(vm.selectedWorkspace) 的快照？", isPresented: $vm.confirmingSnapshot) {
            Button("取消", role: .cancel) {}
            Button("保存快照") { vm.snapshotWorkspace() }
        } message: {
            Text("快照将保存此工作区的本地 CLI 与浏览器数据，不包含钥匙串 Token。请先正常关闭该工作区的窗口和任务；当前数据会保留。")
        }
        .alert("恢复工作区 \(vm.selectedWorkspace)？", isPresented: $vm.confirmingRestore) {
            Button("取消", role: .cancel) {}
            Button("备份并恢复", role: .destructive) { vm.restoreWorkspace() }
        } message: {
            Text("将恢复“\(vm.selectedSnapshotLabel)”。恢复前会备份当前数据；请先正常关闭该工作区的窗口和任务。")
        }
    }

    private var checksTab: some View {
        VStack(spacing: 12) {
            ScrollView {
                if vm.busy {
                    VStack(spacing: 10) {
                        ProgressView()
                        Text(vm.summary).font(.callout).foregroundStyle(.secondary)
                            .multilineTextAlignment(.center)
                    }.frame(maxWidth: .infinity, minHeight: 180)
                } else if vm.checks.isEmpty {
                    VStack(spacing: 10) {
                        Image(systemName: "list.bullet.clipboard").font(.system(size: 28)).foregroundStyle(.tertiary)
                        Text("启动必需项与补充诊断会分别显示。")
                            .font(.callout).foregroundStyle(.secondary)
                    }.frame(maxWidth: .infinity, minHeight: 180)
                } else {
                    LazyVStack(alignment: .leading, spacing: 0) {
                        checkSection(vm.state == .suspended ? "保护已挂起" : "启动必需",
                                     subtitle: vm.state == .suspended
                                        ? "全局代理模式允许启动；下方模式状态表示固定出口与断线阻断未生效，不是线路检查通过。"
                                        : "规则模式下这些检查全部通过后，才允许受保护启动。",
                                     rows: CheckOverview(rows: vm.checks).required)
                        checkSection("补充待确认", subtitle: "包含未实测或需注意的项目，展开可查看原因。",
                                     rows: CheckOverview(rows: vm.checks).pending)
                        checkSection("补充信息", subtitle: "展示当前设置与有限观测，不代表完整防泄漏证明。",
                                     rows: CheckOverview(rows: vm.checks).information)
                    }
                }
            }
            HStack {
                Button { vm.check() } label: {
                    Label("检查线路与隐私", systemImage: "arrow.clockwise").frame(maxWidth: .infinity)
                }.keyboardShortcut("r", modifiers: .command)
                Button { vm.pin() } label: {
                    Label("固定指定节点", systemImage: "pin").frame(maxWidth: .infinity)
                }.help("只选择已配置的 Claude 策略，不修改其他策略组。")
            }
            .controlSize(.large)
            .disabled(vm.busy || !vm.settings.isComplete)
        }.padding(14)
    }

    @ViewBuilder
    private func checkSection(_ title: String, subtitle: String, rows: [CheckResult]) -> some View {
        if !rows.isEmpty {
            HStack {
                Text(title).font(.callout.weight(.semibold))
                Spacer()
                Text("\(rows.count) 项").font(.caption).foregroundStyle(.secondary)
            }.padding(.top, 14)
            Text(subtitle).font(.caption).foregroundStyle(.secondary).padding(.top, 3).padding(.bottom, 4)
            ForEach(rows) { row in
                CheckRow(result: row)
                if row.id != rows.last?.id { Divider() }
            }
        }
    }

    private var workspacesTab: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                HStack {
                    Text("当前：\(vm.currentWorkspace.isEmpty ? "尚未读取" : vm.currentWorkspace)")
                        .font(.callout.weight(.medium))
                    Spacer()
                    Button("刷新工作区") { vm.refreshWorkspaces() }
                }
                HStack {
                    Picker("工作区", selection: $vm.selectedWorkspace) {
                        Text("A").tag("A")
                        Text("B").tag("B")
                    }.frame(width: 160)
                        .onChange(of: vm.selectedWorkspace) { _ in vm.selectedSnapshot = "" }
                    Button(vm.selectedWorkspace == vm.activeWorkspace ? "正在使用" : "切换到此工作区…") {
                        vm.requestWorkspaceSwitch()
                    }.disabled(vm.selectedWorkspace == vm.activeWorkspace)
                }
                Text("A / B 各自保存浏览器登录、Claude Code 凭据和线路设置。上方选择只预览；确认切换后，网页、OAuth 和新启动的 CLI 一起使用目标工作区。")
                    .font(.caption).foregroundStyle(.secondary)
                workspaceAccountDetails
                Divider()
                Text("当前工作区 \(vm.settings.workspace) 的专用浏览器").font(.headline)
                Button { vm.recoverDedicatedBrowser() } label: {
                    Label(BrowserRecoveryAction.recoverDedicatedBrowser.title, systemImage: "wrench.and.screwdriver")
                }
                .disabled(vm.busy || !["A", "B"].contains(vm.settings.workspace))
                Text(BrowserRecoveryAction.recoverDedicatedBrowser.detail)
                    .font(.caption).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                Button(BrowserRecoveryAction.repairBrowserLocks.title) { vm.repairBrowserLocks() }
                    .disabled(vm.busy || !["A", "B"].contains(vm.settings.workspace))
                Text("若你已经正常关闭专用窗口，也可只清理残留锁。此操作不会关闭仍在运行的浏览器。")
                    .font(.caption).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                Divider()
                Text("快照与恢复").font(.headline)
                HStack {
                    TextField("快照备注（可选）", text: $vm.snapshotLabel).textFieldStyle(.roundedBorder)
                    Button("保存工作区快照") { vm.confirmingSnapshot = true }
                }
                if vm.snapshots.isEmpty {
                    Text("尚无可选快照；可先刷新列表或保存一份。").font(.caption).foregroundStyle(.secondary)
                } else {
                    Picker("已有快照", selection: $vm.selectedSnapshot) {
                        Text("请选择要恢复的快照").tag("")
                        ForEach(vm.snapshots) { item in
                            Text("\(item.label) · \(item.date)").tag(item.id)
                        }
                    }
                    Button("恢复所选快照…") { vm.confirmingRestore = true }
                        .disabled(vm.selectedSnapshot.isEmpty || !vm.snapshots.contains { $0.id == vm.selectedSnapshot })
                }
                Text("快照可能包含网页登录和本地 CLI 资料，不包含钥匙串 Token。请只保存在你控制的设备上；恢复快照不会切换另一个工作区的凭据。")
                    .font(.caption).foregroundStyle(.secondary)
            }.padding(16)
        }.disabled(vm.busy)
    }

    private var workspaceAccountDetails: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("工作区 \(vm.selectedWorkspace) 的账号环境").font(.headline)
            if let detail = vm.selectedWorkspaceDetails {
                VStack(alignment: .leading, spacing: 5) {
                    Label("浏览器登录", systemImage: "person.crop.rectangle")
                        .font(.callout.weight(.medium))
                    Text(detail.browserDescription).font(.caption).foregroundStyle(.secondary)
                }
                VStack(alignment: .leading, spacing: 5) {
                    Label("Claude Code 凭据", systemImage: "key")
                        .font(.callout.weight(.medium))
                    Text(detail.authDescription).font(.caption).foregroundStyle(.secondary)
                    HStack {
                        Button("保存此账号的 Token…") { vm.openTokenEntry() }
                        Button("使用独立 OAuth…") { vm.requestOAuth() }
                    }
                    Text("浏览器登录与 CLI 凭据需要属于同一账号；Surge CC 不会自动复制登录或读取账号资料来匹配。")
                        .font(.caption).foregroundStyle(.secondary)
                }
                VStack(alignment: .leading, spacing: 5) {
                    Label("此工作区的线路", systemImage: "network")
                        .font(.callout.weight(.medium))
                    if detail.routeConfigured {
                        LabeledContent("策略组", value: detail.group)
                        LabeledContent("节点", value: detail.policy)
                        LabeledContent("预期出口", value: detail.expectedIP)
                    } else {
                        Text("尚未保存线路；首次使用时复制当前线路设置，此后独立保存。")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                    Button("编辑当前工作区线路…") { vm.openSettings() }
                        .disabled(vm.selectedWorkspace != vm.activeWorkspace)
                    if vm.selectedWorkspace != vm.activeWorkspace {
                        Text("先切换到此工作区，再编辑它的线路。")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                    Text("使用相同节点时出口仍相同。全局代理模式继续按 Surge 全局策略联网。")
                        .font(.caption).foregroundStyle(.secondary)
                }
            } else {
                Text("请刷新工作区，读取此环境的浏览器、凭据和线路状态。")
                    .font(.caption).foregroundStyle(.secondary)
            }
        }.frame(maxWidth: .infinity, alignment: .leading)
    }

    private var protectionTab: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                HStack {
                    Label(vm.guardSuspended ? "保护已挂起"
                          : (vm.guardRunning == true ? "最近收到保护心跳" : (vm.guardRunning == false ? "未收到有效保护心跳" : "保护状态未确认")),
                          systemImage: vm.guardSuspended ? "pause.circle" : (vm.guardRunning == true ? "shield.checkered" : "shield"))
                        .font(.headline)
                    Spacer()
                    Button("刷新保护状态") { vm.refreshGuard() }
                }
                Text(vm.guardDetail).font(.callout).fixedSize(horizontal: false, vertical: true)
                if vm.suspendedSessions > 0 {
                    Text("挂起的会话：\(vm.suspendedSessions)。这些会话当前没有固定出口或断线阻断保护。")
                        .font(.caption).foregroundStyle(.orange)
                }
                if let interval = vm.guardInterval {
                    Text("检查间隔：\(interval) 秒").font(.caption).foregroundStyle(.secondary)
                }
                if !vm.guardCheckedAt.isEmpty {
                    Text("最近检查：\(vm.guardCheckedAt)").font(.caption).foregroundStyle(.secondary)
                }
                Divider()
                Text("诊断与修复").font(.headline)
                Text("先预览再确认。此处修复 Claude 策略组、域名规则和出站模式；DNS、WebRTC、IPv6 问题需要单独处理。")
                    .font(.callout).foregroundStyle(.secondary)
                Button("查看修复计划…") { vm.planRepair() }
                Text("保护状态只说明本工具管理的进程。轮询保护存在检查间隔，不能证明所有系统流量都已被阻断。")
                    .font(.caption).foregroundStyle(.secondary)
            }.padding(16)
        }.disabled(vm.busy)
    }
}

private struct CheckRow: View {
    let result: CheckResult

    private var appearance: (String, Color) {
        switch result.status {
        case "pass": return ("checkmark.circle.fill", .green)
        case "fail": return ("xmark.circle.fill", .red)
        case "warn": return ("exclamationmark.triangle.fill", .orange)
        case "info": return ("info.circle.fill", .secondary)
        default: return ("questionmark.circle.fill", .orange)
        }
    }

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: appearance.0).foregroundStyle(appearance.1).padding(.top, 2)
            VStack(alignment: .leading, spacing: 4) {
                HStack {
                    Text(result.title).font(.callout.weight(.medium))
                    Spacer()
                    Text(result.statusLabel).font(.caption).foregroundStyle(appearance.1)
                }
                if !result.detail.isEmpty {
                    Text(result.summaryDetail).font(.caption).foregroundStyle(.secondary)
                        .textSelection(.enabled).fixedSize(horizontal: false, vertical: true)
                }
                if result.hasExpandedDetail {
                    DisclosureGroup {
                        VStack(alignment: .leading, spacing: 6) {
                            if result.summaryDetail != result.detail {
                                Text(result.detail)
                            }
                            ForEach(Array(result.evidence.enumerated()), id: \.offset) { _, item in
                                Text(item)
                            }
                            if let scope = result.evidenceScope, !scope.isEmpty {
                                Text(scope).foregroundStyle(.secondary)
                            }
                        }
                        .font(.caption)
                        .textSelection(.enabled)
                        .fixedSize(horizontal: false, vertical: true)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(.top, 6)
                    } label: {
                        Text(result.hasEvidence ? "查看依据与范围" : "查看完整说明")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                    .padding(.top, 3)
                }
            }
        }
        .padding(.vertical, 12)
        .padding(.horizontal, 4)
    }
}

private struct SettingsView: View {
    @ObservedObject var vm: ViewModel

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("工作区 \(vm.draft.workspace) · Claude 专用线路").font(.title2.bold())
            Text("线路与环境设置保存到工作区 \(vm.draft.workspace)。Surge 配置路径和程序安装位置供整机共用。名称需与 Surge 一致；保存后需重新检查线路。")
                .font(.callout).foregroundStyle(.secondary)
            TabView(selection: $vm.settingsPane) {
                Form {
                    TextField("策略组", text: $vm.draft.group)
                    TextField("指定节点", text: $vm.draft.policy)
                    TextField("预期出口 IP", text: $vm.draft.expected_ip)
                    TextField("本地代理地址", text: $vm.draft.proxy_url)
                    HStack {
                        TextField("Surge 配置路径（可选）", text: $vm.draft.profile_path)
                        Button("选择…") { chooseProfile() }
                    }
                    Text(vm.draft.browser_path.isEmpty
                         ? "首次安装请运行配置向导；文件隔离使用专用端口 62919。"
                         : "已使用独立浏览器与专用代理端口。请保留此入口；改为普通代理端口会使隔离检查失败。")
                        .font(.caption).foregroundStyle(.secondary)
                }
                .padding(18).tabItem { Text("线路") }.tag(0)
                Form {
                    TextField("预期时区（可选）", text: $vm.draft.expected_timezone)
                    TextField("预期地区格式（可选）", text: $vm.draft.expected_locale)
                    TextField("预期出口国家（可选）", text: $vm.draft.expected_country)
                    TextField("预期 ASN（可选）", text: $vm.draft.expected_asn)
                    TextField("专用浏览器语言（可选）", text: $vm.draft.browser_language)
                    Text("预期项留空时只展示信息。填写后用于检查差异，不会修改系统时区或地区。浏览器语言作用于专用网页和 OAuth 授权窗口；网站已保存的语言偏好可能需要单独调整。")
                        .font(.caption).foregroundStyle(.secondary)
                }
                .padding(18).tabItem { Text("预期环境") }.tag(1)
                Form {
                    Toggle("严格隐私检查", isOn: $vm.draft.privacy_strict)
                    Text("隐私检查无法确认时阻止启动。关闭后，这些未确认项仍会显示黄色提醒。")
                        .font(.caption).foregroundStyle(.secondary)
                    Stepper("保护检查间隔：\(vm.draft.guard_interval) 秒",
                            value: $vm.draft.guard_interval, in: 2...60, step: 1)
                    Text("较短间隔可更快发现变化，但轮询保护不能消除检测间隙，也不能代替网络防火墙。")
                        .font(.caption).foregroundStyle(.secondary)
                }
                .padding(18).tabItem { Text("隐私与保护") }.tag(2)
                Form {
                    TextField("默认模型（如 opus 或精确模型 ID）", text: $vm.draft.default_model)
                    Picker("默认 Effort", selection: $vm.draft.default_effort) {
                        Text("使用 Claude 默认值").tag("")
                        Text("Low").tag("low")
                        Text("Medium").tag("medium")
                        Text("High").tag("high")
                        Text("Max").tag("max")
                    }
                    Picker("浏览器启动页", selection: $vm.draft.browser_start_page) {
                        Text("Claude").tag("claude")
                        Text("新标签页").tag("newtab")
                    }
                    Text("只影响新启动会话。模型留空时使用原生默认值；显式 --model / --effort 优先。模型可用性与费用由账号决定。OAuth 仍打开本次授权地址。")
                        .font(.caption).foregroundStyle(.secondary)
                }
                .padding(18).tabItem { Text("启动偏好") }.tag(3)
            }
            .frame(height: 320)
            .textFieldStyle(.roundedBorder)
            .disabled(vm.busy)
            if !vm.settingsError.isEmpty {
                Text(vm.settingsError).font(.callout).foregroundStyle(.red)
                    .fixedSize(horizontal: false, vertical: true)
            }
            HStack {
                Spacer()
                Button("取消") { vm.showingSettings = false }
                    .keyboardShortcut(.cancelAction)
                Button(vm.busy ? "保存中…" : "保存") { vm.saveSettings() }
                    .buttonStyle(.borderedProminent)
                    .keyboardShortcut(.defaultAction)
            }.disabled(vm.busy)
        }
        .padding(24).frame(width: 660)
        .interactiveDismissDisabled(vm.busy)
    }

    private func chooseProfile() {
        let panel = NSOpenPanel()
        panel.title = "选择 Surge 配置文件"
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false
        if panel.runModal() == .OK, let url = panel.url {
            vm.draft.profile_path = url.path
        }
    }
}

private struct WorkspaceTokenView: View {
    @ObservedObject var vm: ViewModel

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("工作区 \(vm.credentialWorkspace) · 保存 CLI Token").font(.title2.bold())
            Text("粘贴属于此工作区账号的 Claude Code Token。它会保存到此工作区专属的 macOS 钥匙串项目；不会写入命令参数、配置文件或快照，也不会复制到另一个工作区。")
                .font(.callout).foregroundStyle(.secondary)
            SecureField("Claude Code Token", text: $vm.tokenDraft)
                .textFieldStyle(.roundedBorder)
                .disabled(vm.busy)
            Text("保存凭据不会替你登录网页。请确认它与这个工作区浏览器使用的账号一致。")
                .font(.caption).foregroundStyle(.secondary)
            if !vm.credentialError.isEmpty {
                Text(vm.credentialError).font(.callout).foregroundStyle(.red)
            }
            HStack {
                Spacer()
                Button("取消") {
                    vm.tokenDraft = ""
                    vm.showingTokenEntry = false
                }.keyboardShortcut(.cancelAction)
                Button(vm.busy ? "保存中…" : "保存到此工作区") { vm.storeToken() }
                    .buttonStyle(.borderedProminent)
                    .disabled(WorkspaceCommand.tokenInput(vm.tokenDraft) == nil)
            }.disabled(vm.busy)
        }
        .padding(24).frame(width: 590)
        .interactiveDismissDisabled(vm.busy)
        .onDisappear { vm.tokenDraft = "" }
    }
}

private struct RepairPlanView: View {
    @ObservedObject var vm: ViewModel

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("确认修复计划").font(.title2.bold())
            Text("请检查以下动作。执行前会核对计划是否变化；变化后需要重新生成并确认。")
                .font(.callout).foregroundStyle(.secondary)
            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    ForEach(Array(vm.repairActions.enumerated()), id: \.offset) { index, action in
                        VStack(alignment: .leading, spacing: 5) {
                            Text("\(index + 1). \(action.title)").font(.headline)
                            Text(action.detail).font(.callout).foregroundStyle(.secondary)
                                .fixedSize(horizontal: false, vertical: true)
                        }.frame(maxWidth: .infinity, alignment: .leading)
                    }
                }
            }.frame(minHeight: 160, maxHeight: 360)
            if vm.busy {
                HStack { ProgressView(); Text("正在执行已确认的计划…").font(.callout) }
            } else if vm.state == .blocked {
                Text(vm.summary).font(.callout).foregroundStyle(.red)
            }
            HStack {
                Spacer()
                Button("取消") { vm.showingRepair = false }.keyboardShortcut(.cancelAction)
                Button("确认执行 \(vm.repairActions.count) 项修复") { vm.applyRepair() }
                    .buttonStyle(.borderedProminent)
                    .disabled(vm.repairPlanID.isEmpty || vm.repairActions.isEmpty)
            }.disabled(vm.busy)
        }
        .padding(24).frame(width: 620)
        .interactiveDismissDisabled(vm.busy)
    }
}

private final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { true }
}

@main
private struct SurgeCCApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) var delegate

    var body: some Scene {
        WindowGroup("Surge CC") { ContentView() }
            .windowResizability(.contentMinSize)
            .commands {
                CommandGroup(replacing: .newItem) {}
            }
    }
}
