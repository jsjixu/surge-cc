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
    var proxy_url = "http://127.0.0.1:6152"
    var profile_path = ""
    var expected_timezone = ""
    var expected_locale = ""
    var expected_country = ""
    var expected_asn = ""
    var browser_language = ""
    var browser_path = ""
    var workspace = "A"
    var privacy_strict = true
    var guard_interval = 10

    init(group: String = "", policy: String = "", expected_ip: String = "",
         proxy_url: String = "http://127.0.0.1:6152", profile_path: String = "") {
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
    }

    init(from decoder: Decoder) throws {
        // Error responses can legitimately have settings:{} before a config exists.
        let container = try decoder.container(keyedBy: CodingKeys.self)
        group = try container.decodeIfPresent(String.self, forKey: .group) ?? ""
        policy = try container.decodeIfPresent(String.self, forKey: .policy) ?? ""
        expected_ip = try container.decodeIfPresent(String.self, forKey: .expected_ip) ?? ""
        proxy_url = try container.decodeIfPresent(String.self, forKey: .proxy_url) ?? "http://127.0.0.1:6152"
        profile_path = try container.decodeIfPresent(String.self, forKey: .profile_path) ?? ""
        expected_timezone = try container.decodeIfPresent(String.self, forKey: .expected_timezone) ?? ""
        expected_locale = try container.decodeIfPresent(String.self, forKey: .expected_locale) ?? ""
        expected_country = try container.decodeIfPresent(String.self, forKey: .expected_country) ?? ""
        expected_asn = try container.decodeIfPresent(String.self, forKey: .expected_asn) ?? ""
        browser_language = try container.decodeIfPresent(String.self, forKey: .browser_language) ?? ""
        browser_path = try container.decodeIfPresent(String.self, forKey: .browser_path) ?? ""
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

private struct BackendResponse: Decodable, Sendable {
    let schema: Int
    let ok: Bool
    let summary: String
    let checked_at: String?
    let checks: [CheckResult]?
    let settings: Settings?
    let launched: Bool?
    let target: String?
    let document: [String: JSONValue]

    private enum CodingKeys: String, CodingKey {
        case schema, ok, summary, checked_at, checks, settings, launched, target
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
        document = try JSONValue(from: decoder).object
    }
}

private enum CheckAssessment: Equatable {
    case passed, caution, blocked
    static func assess(_ response: BackendResponse, exitCode: Int32) -> CheckAssessment {
        let rows = response.checks ?? []
        let required = rows.filter(\.required)
        let knownStatuses = Set(["pass", "fail", "unknown", "warn", "info"])
        guard response.ok, exitCode == 0, !rows.isEmpty, !required.isEmpty,
              Set(rows.map(\.id)).count == rows.count,
              rows.allSatisfy({ knownStatuses.contains($0.status) }),
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

    static func run(_ arguments: [String], workingDirectory: URL) -> CommandResult {
        guard let script = scriptURL() else {
            return CommandResult(response: nil, exitCode: 1, error: "找不到配套程序，请重新构建或安装 Surge CC。")
        }
        let candidates = ["/opt/homebrew/bin/python3", "/usr/local/bin/python3", "/usr/bin/python3"]
        guard let python = candidates.first(where: FileManager.default.isExecutableFile(atPath:)) else {
            return CommandResult(response: nil, exitCode: 1, error: "未找到 Python 3，暂时无法执行检查。")
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
        process.standardInput = FileHandle.nullDevice

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
    case idle, busy, passed, caution, blocked, saved, launched, message

    var title: String {
        switch self {
        case .idle: return "尚未检查"
        case .busy: return "处理中"
        case .passed: return "本次检查通过"
        case .caution: return "基础检查通过，部分项目待确认"
        case .blocked: return "尚未通过"
        case .saved: return "配置已保存"
        case .launched: return "已启动"
        case .message: return "操作完成"
        }
    }

    var color: Color {
        switch self {
        case .passed, .launched: return .green
        case .busy: return .blue
        case .blocked, .caution: return .orange
        case .saved, .idle, .message: return .secondary
        }
    }
}

private enum Operation {
    case check, configure, workspaceList, workspaceUse, snapshot, restore, repairPlan, repair, guardStatus
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
    @Published var selectedSnapshot = ""
    @Published var snapshotLabel = ""
    @Published var showingRepair = false
    @Published var repairActions: [RepairAction] = []
    @Published var repairPlanID = ""
    @Published var guardRunning: Bool?
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

    var snapshots: [Snapshot] { workspaceSnapshots[selectedWorkspace] ?? [] }
    var selectedSnapshotLabel: String { snapshots.first { $0.id == selectedSnapshot }?.label ?? selectedSnapshot }

    func perform(_ arguments: [String], message: String, operation: Operation = .check,
                 workingDirectory: URL = FileManager.default.homeDirectoryForCurrentUser) {
        guard !busy else { return }
        let id = UUID()
        requestID = id
        state = .busy
        summary = message
        checks = []
        checkedAt = ""
        settingsError = ""
        if operation == .guardStatus {
            guardRunning = nil
            guardDetail = "正在读取保护状态…"
            guardCheckedAt = ""
            guardInterval = nil
        }
        Task {
            let result = await Task.detached(priority: .userInitiated) {
                Backend.run(arguments, workingDirectory: workingDirectory)
            }.value
            guard self.requestID == id else { return }
            guard let response = result.response else {
                self.state = .blocked
                self.summary = result.error ?? "无法确认当前线路。"
                if operation == .configure { self.settingsError = self.summary }
                if operation == .guardStatus { self.guardDetail = self.summary }
                return
            }
            if let settings = response.settings, settings.isComplete { self.settings = settings }
            self.summary = response.summary
            if operation == .configure {
                if response.ok && result.exitCode == 0 {
                    self.state = .saved
                    self.summary = "配置已保存，尚未检查。"
                    self.showingSettings = false
                } else {
                    self.state = .blocked
                    self.settingsError = response.summary
                }
                return
            }
            if operation != .check {
                self.state = response.ok && result.exitCode == 0 ? .message : .blocked
                if operation == .guardStatus && self.state == .blocked { self.guardDetail = response.summary }
                if response.ok && result.exitCode == 0 {
                    switch operation {
                    case .workspaceList, .workspaceUse, .snapshot, .restore:
                        self.consumeWorkspaces(response)
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
        perform(["launch", "web", "--json"], message: "重新检查后打开 Claude 专用浏览器…")
    }

    func launchCode() {
        perform(["launch", "code", "--terminal", "--json"],
                message: "重新检查后在终端启动 Claude Code…",
                workingDirectory: projectDirectory)
    }

    func refreshWorkspaces() {
        perform(["workspace", "list", "--json"], message: "正在读取本地工作区…", operation: .workspaceList)
    }

    func useWorkspace() {
        guard ["A", "B"].contains(selectedWorkspace) else { return }
        perform(["workspace", "use", "--name", selectedWorkspace, "--json"],
                message: "正在切换本地工作区…", operation: .workspaceUse)
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

    private func consumeWorkspaces(_ response: BackendResponse) {
        if let current = response.document["current_workspace"]?.string, ["A", "B"].contains(current) {
            currentWorkspace = current
        }
        var collected: [String: [Snapshot]] = [:]
        for item in response.document["workspaces"]?.array ?? [] {
            let object = item.object
            guard let name = object["name"]?.string, ["A", "B"].contains(name) else { continue }
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
            summary = "已选择项目，启动时将重新检查线路和项目设置。"
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
            "configure", "--group", cleaned.group, "--policy", cleaned.policy,
            "--expected-ip", cleaned.expected_ip, "--proxy-url", cleaned.proxy_url
        ]
        // Pass an empty optional path too, so clearing the field clears old configuration.
        args += ["--profile", cleaned.profile_path,
                 "--expected-timezone", cleaned.expected_timezone.trimmingCharacters(in: .whitespacesAndNewlines),
                 "--expected-locale", cleaned.expected_locale.trimmingCharacters(in: .whitespacesAndNewlines),
                 "--expected-country", cleaned.expected_country.trimmingCharacters(in: .whitespacesAndNewlines),
                 "--expected-asn", cleaned.expected_asn.trimmingCharacters(in: .whitespacesAndNewlines),
                 "--browser-language", cleaned.browser_language.trimmingCharacters(in: .whitespacesAndNewlines),
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

            TabView(selection: $vm.selectedTab) {
                checksTab.tabItem { Label("检查", systemImage: "checklist") }.tag(0)
                workspacesTab.tabItem { Label("工作区", systemImage: "square.stack.3d.up") }.tag(1)
                protectionTab.tabItem { Label("保护", systemImage: "shield.lefthalf.filled") }.tag(2)
            }
            .frame(minHeight: 320, maxHeight: .infinity)

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
                    Label("打开 Claude 网页", systemImage: "globe")
                        .frame(maxWidth: .infinity)
                }
                Button { vm.launchCode() } label: {
                    Label("启动 Claude Code", systemImage: "terminal")
                        .frame(maxWidth: .infinity)
                }
                .help("在所选项目中启动 Claude Code；登录授权会检查线路后自动进入专用授权窗口。")
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.large)
            .disabled(vm.busy || !vm.settings.isComplete)

            Text(vm.settings.browser_path.isEmpty
                 ? "每次启动都会重新检查。工作区分别保存本地 CLI 与浏览器数据，不代表身份隔离；启动检查和进程保护不能替代网络防火墙。"
                 : "可从这里启动 Claude；安装终端接管后，Ghostty / Orca 中的 claude 也会先检查线路。专用入口只走指定节点，保护需要 Surge 规则模式和增强模式保持开启。个人 Chrome 不受此隔离规则影响。")
                .font(.caption).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            Text("Claude Code 登录授权会自动打开专用授权窗口，先检查线路；仅本次登录的本机回调端口可绕过代理。")
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
        .alert("保存工作区 \(vm.selectedWorkspace) 的快照？", isPresented: $vm.confirmingSnapshot) {
            Button("取消", role: .cancel) {}
            Button("保存快照") { vm.snapshotWorkspace() }
        } message: {
            Text("快照将保存此工作区的本地 CLI 与浏览器数据。请先正常关闭该工作区的窗口和任务；当前数据会保留。")
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
                        checkSection("启动必需", subtitle: "这些检查全部通过后，才允许从本工具启动。",
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
                    Button("使用此工作区") { vm.useWorkspace() }
                }
                Text("网页和 Claude Code 将使用所选工作区各自的数据目录。切换不会登录账号，也不会改动个人 Chrome。")
                    .font(.caption).foregroundStyle(.secondary)
                Text("系统钥匙串和服务端账号身份不属于工作区的隔离范围。")
                    .font(.caption).foregroundStyle(.secondary)
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
                Text("快照可能包含登录状态和私人工作资料，应只保存在你控制的设备上。")
                    .font(.caption).foregroundStyle(.secondary)
            }.padding(16)
        }.disabled(vm.busy)
    }

    private var protectionTab: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                HStack {
                    Label(vm.guardRunning == true ? "最近收到保护心跳" : (vm.guardRunning == false ? "未收到有效保护心跳" : "保护状态未确认"),
                          systemImage: vm.guardRunning == true ? "shield.checkered" : "shield")
                        .font(.headline)
                    Spacer()
                    Button("刷新保护状态") { vm.refreshGuard() }
                }
                Text(vm.guardDetail).font(.callout).fixedSize(horizontal: false, vertical: true)
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
            Text("Claude 专用线路").font(.title2.bold())
            Text("名称需与 Surge 完全一致。保存配置只影响 Surge CC；切换节点需在主界面单独执行。")
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
                         ? "本地代理地址通常类似 http://127.0.0.1:6152，请以 Surge 当前设置为准。"
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
            }
            .frame(height: 280)
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
