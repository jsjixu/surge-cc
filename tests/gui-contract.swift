// This file is appended to the actual GUI model declarations by test-gui.sh.
// It never loads user settings, invokes the backend, or starts an application.
@main
private enum GUIContractTests {
    static func report(_ rows: [[String: Any]], ok: Bool = true,
                       recoveryAction: Any? = nil) throws -> BackendResponse {
        var document: [String: Any] = [
            "schema": 1, "ok": ok, "summary": "测试结果", "checks": rows, "settings": [:]
        ]
        if let recoveryAction { document["recovery_action"] = recoveryAction }
        let data = try JSONSerialization.data(withJSONObject: document)
        return try JSONDecoder().decode(BackendResponse.self, from: data)
    }

    static func check(_ id: String, _ status: String, required: Bool? = true) -> [String: Any] {
        var row: [String: Any] = ["id": id, "title": id, "status": status, "detail": ""]
        if let required { row["required"] = required }
        return row
    }

    static func expect(_ response: BackendResponse, _ expected: CheckAssessment, exitCode: Int32 = 0) {
        precondition(CheckAssessment.assess(response, exitCode: exitCode) == expected)
    }

    static func main() throws {
        let good = check("route", "pass")
        try expect(report([good]), .passed)
        for status in ["unknown", "warn", "fail"] {
            let response = try report([good, check("optional", status, required: false)])
            precondition(CheckAssessment.assess(response, exitCode: 0) == .caution)
            let requiredResponse = try report([good, check("required", status)])
            precondition(CheckAssessment.assess(requiredResponse, exitCode: 0) == .blocked)
        }
        try expect(report([good, check("note", "info", required: false)]), .passed)
        try expect(report([check("legacy", "unknown", required: nil)]), .blocked)
        try expect(report([good, good]), .blocked)
        try expect(report([]), .blocked)
        try expect(report([check("optional", "pass", required: false)]), .blocked)
        try expect(report([good], ok: false), .blocked)
        try expect(report([good]), .blocked, exitCode: 2)
        try expect(report([good, check("malformed", "surprise", required: false)]), .blocked)

        let legacy = try report([good]).checks!.first!
        precondition(legacy.evidence.isEmpty && legacy.evidenceScope == nil)
        precondition(!legacy.hasExpandedDetail && legacy.statusLabel == "通过")
        var dns = check("dns_egress", "unknown", required: false)
        dns["detail"] = "未配置权威 DNS 观测服务，递归出口尚未验证。"
        dns["evidence"] = ["递归器 IP 不必等于住宅代理出口。"]
        dns["evidence_scope"] = "此项未执行外部观测。"
        let augmented = try report([good, dns, check("ipv6_paths", "info", required: false)])
        expect(augmented, .caution)
        let dnsRow = augmented.checks![1]
        precondition(dnsRow.status == "unknown" && dnsRow.statusLabel == "未确认")
        precondition(dnsRow.hasEvidence && dnsRow.hasExpandedDetail)
        precondition(dnsRow.evidence.count == 1 && dnsRow.evidenceScope == "此项未执行外部观测。")
        let overview = CheckOverview(rows: augmented.checks!)
        precondition(overview.required.count == 1 && overview.pending.count == 1 && overview.information.count == 1)
        precondition(overview.summary == "启动必需 1/1 项通过；1 项补充待确认；1 项补充信息。")
        let requiredDNS = try report([check("dns_egress", "unknown")]).checks!.first!
        let otherUnknown = try report([check("other_unknown", "unknown", required: false)]).checks!.first!
        precondition(requiredDNS.statusLabel == "未确认" && otherUnknown.statusLabel == "未确认")
        let measuredDNS = try report([good, check("dns_egress", "info", required: false)])
        expect(measuredDNS, .passed)
        precondition(measuredDNS.checks![1].statusLabel == "已实测")
        var detailed = check("long_detail", "warn", required: false)
        detailed["detail"] = String(repeating: "保留完整检查依据。", count: 30)
        let longRow = try report([detailed]).checks!.first!
        precondition(longRow.hasExpandedDetail && longRow.summaryDetail.count < longRow.detail.count)
        precondition(longRow.summaryDetail.hasSuffix("…") && longRow.statusLabel == "需注意")
        var malformedEvidence = dns
        malformedEvidence["evidence"] = "not-an-array"
        do {
            _ = try report([good, malformedEvidence])
            preconditionFailure("Malformed evidence must not decode as an empty successful report")
        } catch is DecodingError {}

        let oldSettings = #"{"schema":1,"group":"Claude","policy":"Home","expected_ip":"203.0.113.7","proxy_url":"http://127.0.0.1:6152","profile_path":"","hosts":["claude.ai"]}"#
        let settings = try JSONDecoder().decode(Settings.self, from: Data(oldSettings.utf8))
        precondition(settings.isComplete && settings.privacy_strict && settings.guard_interval == 10)
        precondition(settings.expected_country.isEmpty && settings.expected_timezone.isEmpty)
        precondition(settings.browser_language.isEmpty && settings.workspace == "A")
        let empty = try JSONDecoder().decode(Settings.self, from: Data("{}".utf8))
        precondition(!empty.isComplete)

        let extras = #"{"schema":1,"ok":true,"summary":"工作区","checks":[],"current_workspace":"B","workspaces":[{"name":"B","label":"B","snapshots":[{"id":"snap-1","label":"before","created_at":"2026-01-01"}]}],"guard":{"running":false,"interval":10,"last_checked_at":"","detail":"未运行"},"actions":[{"id":"route","title":"补充规则","detail":"精确修复"}],"plan_id":"plan-1"}"#
        let envelope = try JSONDecoder().decode(BackendResponse.self, from: Data(extras.utf8))
        precondition(envelope.document["current_workspace"]?.string == "B")
        precondition(envelope.document["workspaces"]?.array.first?.object["name"]?.string == "B")
        precondition(envelope.document["guard"]?.object["running"]?.bool == false)
        precondition(envelope.document["plan_id"]?.string == "plan-1")

        // Only the named browser-lock operation can expose a repair button.
        let blockedLocks = try report([check("operation", "fail")], ok: false,
                                      recoveryAction: "repair-browser-locks")
        precondition(blockedLocks.recoveryAction == .repairBrowserLocks)
        let recovery = BrowserRecoveryAction.after(blockedLocks, exitCode: 1)
        precondition(recovery == .repairBrowserLocks)
        precondition(recovery?.arguments(workspace: "A") ==
                     ["browser-locks", "repair", "--workspace", "A", "--json"])
        precondition(recovery?.arguments(workspace: "B") ==
                     ["browser-locks", "repair", "--workspace", "B", "--json"])
        for invalidWorkspace in ["", "../A", "A --launch", "C"] {
            precondition(recovery?.arguments(workspace: invalidWorkspace) == nil)
        }
        let unknownAction = try report([], ok: false, recoveryAction: "launch web --json")
        precondition(unknownAction.recoveryAction == nil)
        precondition(BrowserRecoveryAction.after(unknownAction, exitCode: 1) == nil)
        precondition(envelope.recoveryAction == nil)
        // Maintenance is reachable without a previous failure, and targets the
        // configured workspace rather than a not-yet-applied picker selection.
        var maintenanceSettings = settings
        maintenanceSettings.workspace = "B"
        precondition(BrowserRecoveryAction.repairBrowserLocks.arguments(workspace: maintenanceSettings.workspace) ==
                     ["browser-locks", "repair", "--workspace", "B", "--json"])
        let repairFailed = try report([], ok: false)
        precondition(BrowserRecoveryAction.after(repairFailed, exitCode: 1,
                                                 retrying: recovery) == recovery)
        precondition(BrowserRecoveryAction.after(nil, exitCode: 1,
                                                 retrying: recovery) == recovery)
        let repaired = try report([], recoveryAction: "repair-browser-locks")
        precondition(BrowserRecoveryAction.after(repaired, exitCode: 0,
                                                 retrying: recovery) == nil)
        var liveBrowserFailure = check("operation", "fail")
        liveBrowserFailure["detail"] = "专用浏览器进程仍在运行，请先正常退出。"
        let refusedRepair = try report([liveBrowserFailure], ok: false)
        let visibleFailure = BrowserRecoveryAction.checksAfterRepair(refusedRepair, exitCode: 1)
        precondition(visibleFailure.count == 1)
        precondition(visibleFailure[0].detail == "专用浏览器进程仍在运行，请先正常退出。")
        precondition(BrowserRecoveryAction.after(refusedRepair, exitCode: 1,
                                                 retrying: recovery) == recovery)
        let repairWithOldRows = try report([liveBrowserFailure])
        precondition(BrowserRecoveryAction.checksAfterRepair(repairWithOldRows, exitCode: 0).isEmpty)
        precondition(BrowserRecoveryAction.checksAfterRepair(repairWithOldRows, exitCode: 1).count == 1)
        // A lock repair cannot become a passing network assessment or auto-launch.
        expect(repaired, .blocked)
        precondition(repaired.launched != true)
        do {
            _ = try report([], ok: false, recoveryAction: ["repair-browser-locks"])
            preconditionFailure("Malformed recovery metadata must not be interpreted as a command")
        } catch is DecodingError {}
        print("GUI contract: gating, evidence, summaries, settings, recovery allowlist and repair retry/reset passed")
    }
}
