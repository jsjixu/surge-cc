// This file is appended to the actual GUI model declarations by test-gui.sh.
// It never loads user settings, invokes the backend, or starts an application.
@main
private enum GUIContractTests {
    static func report(_ rows: [[String: Any]], ok: Bool = true,
                       recoveryAction: Any? = nil, paused: Any? = nil,
                       pauseReason: Any? = nil, metadata: [String: Any] = [:]) throws -> BackendResponse {
        var document: [String: Any] = [
            "schema": 1, "ok": ok, "summary": "测试结果", "checks": rows, "settings": [:]
        ]
        if let recoveryAction { document["recovery_action"] = recoveryAction }
        if let paused { document["paused"] = paused }
        if let pauseReason { document["pause_reason"] = pauseReason }
        for (key, value) in metadata { document[key] = value }
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

        let modeFailure = check("mode", "fail")
        let pausedMode = try report([good, modeFailure], ok: false, paused: true, pauseReason: "surge-mode")
        expect(pausedMode, .paused, exitCode: 1)
        precondition(pausedMode.paused == true && pausedMode.pauseReason == "surge-mode")
        precondition(pausedMode.launched != true && pausedMode.recoveryAction == nil)
        expect(pausedMode, .blocked, exitCode: 0)
        try expect(report([good, modeFailure], ok: false, paused: true, pauseReason: "unknown"), .blocked, exitCode: 1)
        try expect(report([good, modeFailure], ok: false, paused: true), .blocked, exitCode: 1)
        try expect(report([good, modeFailure], ok: false, pauseReason: "surge-mode"), .blocked, exitCode: 1)
        try expect(report([good], paused: true, pauseReason: "surge-mode"), .blocked)
        try expect(report([good, modeFailure], paused: true, pauseReason: "surge-mode"), .blocked, exitCode: 1)
        try expect(report([good], ok: false, paused: true, pauseReason: "surge-mode"), .blocked, exitCode: 1)
        try expect(report([good, check("mode", "fail", required: false)], ok: false,
                          paused: true, pauseReason: "surge-mode"), .blocked, exitCode: 1)
        try expect(report([modeFailure, modeFailure], ok: false,
                          paused: true, pauseReason: "surge-mode"), .blocked, exitCode: 1)
        do {
            _ = try report([modeFailure], ok: false, paused: "true", pauseReason: "surge-mode")
            preconditionFailure("Malformed pause metadata must not decode")
        } catch is DecodingError {}

        // Global mode allows launch without claiming a successful protected route.
        let globalGood = check("surge", "pass")
        let globalMetadata: [String: Any] = ["paused": true, "pause_reason": "surge-global-mode",
            "surge_mode": "proxy", "launch_allowed": true, "protection_active": false]
        let suspendedCheck = try report([globalGood, modeFailure], ok: false, metadata: globalMetadata)
        expect(suspendedCheck, .suspended, exitCode: 2)
        expect(suspendedCheck, .blocked, exitCode: 0)
        expect(suspendedCheck, .blocked, exitCode: 1)
        for target in ["web", "code-terminal"] {
            var launchMetadata = globalMetadata
            launchMetadata["launched"] = true
            launchMetadata["target"] = target
            let launchedSuspended = try report([globalGood, modeFailure], metadata: launchMetadata)
            expect(launchedSuspended, .suspended)
            expect(launchedSuspended, .blocked, exitCode: 2)
            try expect(report([globalGood, modeFailure], ok: false, metadata: launchMetadata), .blocked, exitCode: 2)
        }
        for missing in globalMetadata.keys {
            var incomplete = globalMetadata
            incomplete.removeValue(forKey: missing)
            try expect(report([globalGood, modeFailure], ok: false, metadata: incomplete), .blocked, exitCode: 2)
        }
        let invalidFields: [(String, Any)] = [("paused", false), ("pause_reason", "unknown"),
            ("surge_mode", "direct"), ("surge_mode", "rule"), ("surge_mode", "unknown"),
            ("launch_allowed", false), ("protection_active", true), ("schema", 2)]
        for (field, invalid) in invalidFields {
            var malformed = globalMetadata
            malformed[field] = invalid
            try expect(report([globalGood, modeFailure], ok: false, metadata: malformed), .blocked, exitCode: 2)
        }
        for field in ["paused", "launch_allowed", "protection_active"] {
            var malformed = globalMetadata
            malformed[field] = "true"
            do {
                _ = try report([globalGood, modeFailure], ok: false, metadata: malformed)
                preconditionFailure("Global protection metadata must have exact types")
            } catch is DecodingError {}
        }
        for rows in [[good], [modeFailure], [modeFailure, modeFailure],
                     [modeFailure, check("surge", "pass", required: false)],
                     [good, check("mode", "fail", required: false)],
                     [modeFailure, check("surge", "fail")],
                     [modeFailure, check("unknown", "surprise", required: false)]] {
            try expect(report(rows, ok: false, metadata: globalMetadata), .blocked, exitCode: 2)
        }
        // A paused result with ok:true needs an actual successful known launch.
        try expect(report([globalGood, modeFailure], metadata: globalMetadata), .blocked)
        for invalidTarget in ["", "code", "login", "unknown"] {
            var malformedLaunch = globalMetadata
            malformedLaunch["launched"] = true
            malformedLaunch["target"] = invalidTarget
            try expect(report([globalGood, modeFailure], metadata: malformedLaunch), .blocked)
        }
        try expect(report([good], metadata: ["launch_allowed": true]), .blocked)
        try expect(report([good], metadata: ["protection_active": false]), .blocked)
        for claimedMode in ["proxy", "direct", "rule", "unknown", ""] {
            try expect(report([good], metadata: ["surge_mode": claimedMode]), .blocked)
        }
        try expect(report([globalGood, modeFailure], ok: false, paused: true, pauseReason: "surge-mode",
                          metadata: ["surge_mode": "direct"]), .paused, exitCode: 2)
        try expect(report([globalGood, modeFailure], ok: false, paused: true, pauseReason: "surge-mode",
                          metadata: ["surge_mode": "proxy"]), .blocked, exitCode: 2)

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
        precondition(empty.default_model.isEmpty && empty.default_effort.isEmpty)
        precondition(empty.browser_start_page == "claude")
        let preferences = try JSONDecoder().decode(Settings.self, from: Data(
            #"{"default_model":"opus","default_effort":"high","browser_start_page":"newtab"}"#.utf8))
        precondition(preferences.default_model == "opus" && preferences.default_effort == "high")
        precondition(preferences.browser_start_page == "newtab")
        let roundtrip = try JSONDecoder().decode(Settings.self, from: JSONEncoder().encode(preferences))
        precondition(roundtrip == preferences)
        precondition(!empty.isComplete)

        let extras = #"{"schema":1,"ok":true,"summary":"工作区","checks":[],"current_workspace":"B","workspaces":[{"name":"B","label":"B","snapshots":[{"id":"snap-1","label":"before","created_at":"2026-01-01"}]}],"guard":{"running":false,"interval":10,"last_checked_at":"","detail":"未运行"},"actions":[{"id":"route","title":"补充规则","detail":"精确修复"}],"plan_id":"plan-1"}"#
        let envelope = try JSONDecoder().decode(BackendResponse.self, from: Data(extras.utf8))
        precondition(envelope.document["current_workspace"]?.string == "B")
        precondition(envelope.document["workspaces"]?.array.first?.object["name"]?.string == "B")
        precondition(envelope.document["guard"]?.object["running"]?.bool == false)
        precondition(envelope.document["plan_id"]?.string == "plan-1")

        // Workspace previews report route/auth separately and never claim an
        // OAuth mode selection proves an account is logged in.
        let accountResponse = try report([], metadata: ["workspaces": [
            ["name": "A", "route": ["group": "Claude A", "policy": "Home A", "expected_ip": "203.0.113.7"],
             "auth": ["mode": "token", "configured": true], "browser": ["has_profile": true]],
            ["name": "B", "route": NSNull(), "auth": ["mode": "oauth", "configured": false],
             "browser": ["has_profile": false]]
        ]])
        let accountItems = accountResponse.document["workspaces"]!.array
        let accountA = WorkspaceSummary(accountItems[0])!
        let accountB = WorkspaceSummary(accountItems[1])!
        precondition(accountA.routeConfigured && accountA.policy == "Home A" && accountA.authConfigured)
        precondition(accountA.hasBrowserProfile == true)
        precondition(!accountB.routeConfigured && accountB.policy.isEmpty && accountB.expectedIP.isEmpty)
        precondition(!accountB.authConfigured && accountB.hasBrowserProfile == false)
        precondition(accountB.authDescription.contains("尚未设置"))
        let oauthSelected = try report([], metadata: ["workspaces": [["name": "B",
            "auth": ["mode": "oauth", "configured": true]]]])
        let oauthSummary = WorkspaceSummary(oauthSelected.document["workspaces"]!.array[0])!
        precondition(oauthSummary.authDescription.contains("是否已登录"))
        precondition(oauthSummary.hasBrowserProfile == nil && !oauthSummary.routeConfigured)
        for name in ["A", "B"] {
            precondition(WorkspaceCommand.use(name) ==
                ["workspace", "use", "--name", name, "--close-sessions", "--json"])
            precondition(WorkspaceCommand.auth("store", workspace: name) ==
                ["workspace-auth", "store", "--workspace", name, "--stdin", "--json"])
            precondition(WorkspaceCommand.auth("oauth", workspace: name) ==
                ["workspace-auth", "oauth", "--workspace", name, "--json"])
        }
        for name in ["", "../A", "B --json", "C"] {
            precondition(WorkspaceCommand.use(name) == nil)
            precondition(WorkspaceCommand.auth("store", workspace: name) == nil)
        }
        precondition(WorkspaceCommand.auth("delete-all", workspace: "A") == nil)
        let unconfiguredB = try report([], metadata: ["settings": ["workspace": "B"]])
        precondition(WorkspaceCommand.refreshedSettings(unconfiguredB, exitCode: 0)?.workspace == "B")
        precondition(WorkspaceCommand.refreshedSettings(unconfiguredB, exitCode: 0)?.isComplete == false)
        precondition(WorkspaceCommand.refreshedSettings(unconfiguredB, exitCode: 1) == nil)
        let emptyErrorSettings = try report([], ok: false)
        precondition(WorkspaceCommand.refreshedSettings(emptyErrorSettings, exitCode: 1) == nil)
        let omittedWorkspace = try report([], metadata: ["settings": [:]])
        precondition(WorkspaceCommand.refreshedSettings(omittedWorkspace, exitCode: 0) == nil)
        let secretFixture = "token-fixture-never-in-arguments"
        precondition(WorkspaceCommand.tokenInput(" \(secretFixture)\n") == Data((secretFixture + "\n").utf8))
        precondition(!WorkspaceCommand.auth("store", workspace: "A")!.contains(secretFixture))
        for invalidToken in ["", " ", "line1\nline2", "has space", String(repeating: "x", count: 16_385)] {
            precondition(WorkspaceCommand.tokenInput(invalidToken) == nil)
        }

        // Only named, allowlisted operations can expose recovery buttons.
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
            precondition(BrowserRecoveryAction.recoverDedicatedBrowser.arguments(workspace: invalidWorkspace) == nil)
        }
        let liveBrowserRecovery = try report([check("operation", "fail")], ok: false,
                                            recoveryAction: "recover-browser")
        precondition(liveBrowserRecovery.recoveryAction == .recoverDedicatedBrowser)
        precondition(BrowserRecoveryAction.after(liveBrowserRecovery, exitCode: 1) == .recoverDedicatedBrowser)
        precondition(BrowserRecoveryAction.recoverDedicatedBrowser.arguments(workspace: "A") ==
                     ["browser-locks", "recover", "--workspace", "A", "--json"])
        precondition(BrowserRecoveryAction.recoverDedicatedBrowser.arguments(workspace: "B") ==
                     ["browser-locks", "recover", "--workspace", "B", "--json"])
        let wrongMode = try report([check("mode", "fail")], ok: false,
                                   recoveryAction: "restore-rule-mode")
        // Mode changes are not a recovery command; the app never switches Surge mode.
        precondition(wrongMode.recoveryAction == nil)
        precondition(BrowserRecoveryAction.after(wrongMode, exitCode: 1) == nil)
        let unknownAction = try report([], ok: false, recoveryAction: "launch web --json")
        precondition(unknownAction.recoveryAction == nil)
        precondition(BrowserRecoveryAction.after(unknownAction, exitCode: 1) == nil)
        let noMetadata = try JSONDecoder().decode(BackendResponse.self, from: Data(
            #"{"schema":1,"ok":false,"summary":"recover-browser restore-rule-mode","checks":[],"settings":{}}"#.utf8))
        precondition(BrowserRecoveryAction.after(noMetadata, exitCode: 1) == nil)
        // A fresh check does not retain an action from a previous failed repair.
        let freshFailure = try report([], ok: false)
        precondition(BrowserRecoveryAction.after(freshFailure, exitCode: 1) == nil)
        precondition(envelope.recoveryAction == nil)
        // Maintenance is reachable without a previous failure, and targets the
        // configured workspace rather than a not-yet-applied picker selection.
        var maintenanceSettings = settings
        maintenanceSettings.workspace = "B"
        precondition(BrowserRecoveryAction.repairBrowserLocks.arguments(workspace: maintenanceSettings.workspace) ==
                     ["browser-locks", "repair", "--workspace", "B", "--json"])
        precondition(BrowserRecoveryAction.recoverDedicatedBrowser.arguments(workspace: maintenanceSettings.workspace) ==
                     ["browser-locks", "recover", "--workspace", "B", "--json"])
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
        for action in [BrowserRecoveryAction.repairBrowserLocks, .recoverDedicatedBrowser] {
            precondition(action.completion(repaired, exitCode: 0) == .recheck)
            precondition(action.completion(repairWithOldRows, exitCode: 0) == .recheck)
            precondition(action.completion(repaired, exitCode: 1) == .showFailure)
            precondition(action.completion(refusedRepair, exitCode: 0) == .showFailure)
            precondition(BrowserRecoveryAction.after(refusedRepair, exitCode: 1, retrying: action) == action)
            precondition(BrowserRecoveryAction.after(nil, exitCode: 1, retrying: action) == action)
            precondition(BrowserRecoveryAction.after(repaired, exitCode: 0, retrying: action) == nil)
        }
        // A lock repair cannot become a passing network assessment or auto-launch.
        expect(repaired, .blocked)
        precondition(repaired.launched != true)
        do {
            _ = try report([], ok: false, recoveryAction: ["repair-browser-locks"])
            preconditionFailure("Malformed recovery metadata must not be interpreted as a command")
        } catch is DecodingError {}
        // General remediation is an exact enum allowlist. Neither backend prose
        // nor an arbitrary command line or URL can create an executable action.
        for action in RemediationAction.allCases {
            let failed = try report([], ok: false, metadata: ["remediation_action": action.rawValue])
            precondition(failed.remediationAction == action)
            precondition(RemediationAction.after(failed, exitCode: 1) == action)
            let successful = try report([], metadata: ["remediation_action": action.rawValue])
            precondition(RemediationAction.after(successful, exitCode: 0) == nil)
        }
        for untrusted in ["", "open https://evil.example", "repair-terminal --force", "rm -rf ~", "maintenance-terminal"] {
            let failed = try report([], ok: false, metadata: ["remediation_action": untrusted])
            precondition(failed.remediationAction == nil)
        }
        do {
            _ = try report([], ok: false, metadata: ["remediation_action": ["repair-terminal"]])
            preconditionFailure("Malformed remediation metadata must not decode")
        } catch is DecodingError {}

        // A maintenance plan needs successful status, a bound opaque ID, a known
        // operation, and a complete, unambiguous action list before apply exists.
        let maintenanceActions: [[String: Any]] = [
            ["id": "verify", "title": "Verify native program", "detail": "Signature and checksum"],
            ["id": "register", "title": "Register wrapper", "detail": "Retain workspace data"]
        ]
        let maintenanceMetadata: [String: Any] = ["plan_id": "plan_0123456789-abc",
            "operation": "repair-terminal", "actions": maintenanceActions]
        let maintenanceResponse = try report([], metadata: maintenanceMetadata)
        let plan = MaintenancePlan(maintenanceResponse, exitCode: 0)!
        precondition(plan.operation == .repairTerminal && plan.actions.count == 2)
        precondition(plan.arguments == ["maintenance", "apply", "--plan-id", "plan_0123456789-abc", "--json"])
        precondition(MaintenanceOperation.updateClaude.arguments == ["maintenance", "plan", "--operation", "update-claude", "--json"])
        precondition(MaintenancePlan(maintenanceResponse, exitCode: 1) == nil)
        let failedMaintenance = try report([], ok: false, metadata: maintenanceMetadata)
        precondition(MaintenancePlan(failedMaintenance, exitCode: 0) == nil)
        for invalidID in ["", "../../plan", "plan --force", String(repeating: "a", count: 129), "日本語", "plan\n"] {
            var metadata = maintenanceMetadata
            metadata["plan_id"] = invalidID
            let invalidPlan = MaintenancePlan(try report([], metadata: metadata), exitCode: 0)
            precondition(invalidPlan == nil)
        }
        for invalidOperation in ["install", "update-claude --force", "", "launch"] {
            var metadata = maintenanceMetadata
            metadata["operation"] = invalidOperation
            let invalidPlan = MaintenancePlan(try report([], metadata: metadata), exitCode: 0)
            precondition(invalidPlan == nil)
        }
        for invalidActions: Any in [[], [maintenanceActions[0], maintenanceActions[0]],
                                   [["id": "x", "title": "Incomplete"]],
                                   Array(repeating: maintenanceActions[0], count: 41), "shell"] {
            var metadata = maintenanceMetadata
            metadata["actions"] = invalidActions
            let invalidPlan = MaintenancePlan(try report([], metadata: metadata), exitCode: 0)
            precondition(invalidPlan == nil)
        }
        let maintenanceEntries = try report([], metadata: ["maintenance": ["entries": [
            ["id": "terminal", "title": "Terminal", "status": "warn", "detail": "Changed", "action": "repair-terminal"],
            ["id": "unknown", "title": "Other", "status": "info", "detail": "Info", "action": "launch web"],
            ["id": "bad", "title": "Bad", "status": "invalid", "detail": "Invalid"]
        ]]])
        let entryValues = maintenanceEntries.document["maintenance"]!.object["entries"]!.array
        precondition(MaintenanceEntry(entryValues[0])?.action == .repairTerminal)
        precondition(MaintenanceEntry(entryValues[1])?.action == nil)
        precondition(MaintenanceEntry(entryValues[2]) == nil)

        // Download and install form separate phases. UI only quits for a positive
        // installing acknowledgement, never merely for a fetched release.
        let updateMetadata: [String: Any] = ["state": "available", "current_version": "0.4.1",
            "latest_version": "0.5.0", "version": "0.5.0", "can_download": true,
            "release_url": "https://github.com/jsjixu/surge-cc/releases/tag/v0.5.0", "size": 2000000,
            "notes": "A maintenance release"]
        let available = UpdateInfo(try report([], metadata: ["update": updateMetadata]))!
        precondition(available.canDownload && !available.canInstall && available.releaseURL != nil)
        precondition(available.downloadArguments == ["updates", "download", "--version", "0.5.0", "--json"])
        precondition(available.installArguments == nil && available.size == 2000000)
        precondition(!available.shouldQuitForInstall(exitCode: 0, successful: true))
        var downloadedMetadata = updateMetadata
        downloadedMetadata["state"] = "downloaded"
        downloadedMetadata["can_install"] = true
        downloadedMetadata["package_path"] = "/tmp/Surge-CC-0.5.0-arm64.zip"
        downloadedMetadata["sha256"] = String(repeating: "a", count: 64)
        let downloaded = UpdateInfo(try report([], metadata: ["update": downloadedMetadata]))!
        precondition(downloaded.canInstall && !downloaded.canDownload)
        precondition(downloaded.installArguments == ["updates", "install", "--version", "0.5.0", "--json"])
        var installingMetadata = downloadedMetadata
        installingMetadata["state"] = "installing"
        let installing = UpdateInfo(try report([], metadata: ["update": installingMetadata]))!
        precondition(installing.shouldQuitForInstall(exitCode: 0, successful: true))
        precondition(!installing.shouldQuitForInstall(exitCode: 1, successful: true))
        precondition(!installing.shouldQuitForInstall(exitCode: 0, successful: false))
        for badVersion in ["", "v0.5.0", "0.5.0 --force", "../0.5.0", "0.5.0\n", "1", "1.2.3;open"] {
            var metadata = updateMetadata
            metadata["version"] = badVersion
            let update = UpdateInfo(try report([], metadata: ["update": metadata]))!
            precondition(update.downloadArguments == nil)
            precondition(update.installArguments == nil)
            precondition(!update.shouldQuitForInstall(exitCode: 0, successful: true))
        }
        for link in ["https://github.com.evil.example/jsjixu/surge-cc/releases/tag/v0.5.0",
                     "https://evil.example", "file:///Applications/Surge.app", "http://github.com/jsjixu/surge-cc/releases/latest",
                     "https://github.com/jsjixu/surge-cc/releases/tag/v9.9.9",
                     "https://user@github.com/jsjixu/surge-cc/releases/latest",
                     "https://github.com:443/jsjixu/surge-cc/releases/latest",
                     "https://github.com/jsjixu/surge-cc/releases/latest?next=evil",
                     "https://github.com/jsjixu/surge-cc/releases/latest#fragment"] {
            precondition(UpdateInfo.releaseURL(link, version: "0.5.0") == nil)
        }
        precondition(UpdateInfo.releaseURL("https://github.com/jsjixu/surge-cc/releases/latest", version: "") != nil)
        for state in ["current", "ahead", "unavailable"] {
            var metadata = downloadedMetadata
            metadata["state"] = state
            let update = UpdateInfo(try report([], metadata: ["update": metadata]))!
            precondition(!update.canDownload && !update.canInstall)
        }
        let failedUpdate = UpdateInfo(try report([], ok: false, metadata: ["update": updateMetadata]))!
        precondition(!failedUpdate.canDownload && !failedUpdate.canInstall)
        let missingUpdate = UpdateInfo(try report([]))
        let unknownUpdate = UpdateInfo(try report([], metadata: ["update": ["state": "execute"]]))
        precondition(missingUpdate == nil && unknownUpdate == nil)
        let orcaMetadata: [String: Any] = ["version": "1.0.0", "running": true, "launch_ready": true,
            "modes": [["id": "terminal", "title": "Terminal", "status": "pass", "detail": "Guarded wrapper"],
                      ["id": "managed", "title": "Managed account", "status": "warn", "detail": "Separate authentication"]]]
        let orcaResponse = try report([], metadata: ["orca": orcaMetadata])
        let orca = OrcaStatus(orcaResponse, exitCode: 0)!
        precondition(orca.running && orca.launchReady && orca.modes.count == 2)
        let projectURL = URL(fileURLWithPath: "/tmp/Project with spaces")
        precondition(orca.terminalArguments(project: projectURL) ==
                     ["orca", "open-terminal", "--project", "/tmp/Project with spaces", "--json"])
        precondition(orca.terminalArguments(project: URL(string: "https://example.com/project")!) == nil)
        precondition(orca.terminalArguments(project: URL(fileURLWithPath: "/tmp/project\ncommand")) == nil)
        let failedOrca = OrcaStatus(try report([], ok: false, metadata: ["orca": orcaMetadata]), exitCode: 0)!
        precondition(!failedOrca.launchReady && failedOrca.terminalArguments(project: projectURL) == nil)
        precondition(OrcaStatus(orcaResponse, exitCode: 1)?.launchReady == false)
        var unknownReadiness = orcaMetadata
        unknownReadiness["launch_ready"] = "true"
        let unknownOrca = OrcaStatus(try report([], metadata: ["orca": unknownReadiness]), exitCode: 0)!
        precondition(!unknownOrca.launchReady)
        for state in ["installed", "rolled-back", "failed"] {
            let receiptResponse = try report([], metadata: ["update": ["state": "current", "last_install": [
                "state": state, "version": "0.5.0", "summary": "Previous update result", "backup_available": true,
                "backup_path": "/private/local/backup", "app": "/private/local/application"
            ]]])
            let receipt = InstallReceipt(receiptResponse.document["update"]!.object["last_install"]!)!
            precondition(receipt.state == state && receipt.version == "0.5.0" && receipt.backupAvailable)
            precondition(receipt.summary == "Previous update result" && !receipt.title.isEmpty)
        }
        for invalidReceipt: [String: Any] in [
            ["state": "installing", "summary": "incomplete", "backup_available": true],
            ["state": "failed", "summary": "", "backup_available": false],
            ["state": "failed", "summary": "result", "backup_available": "true"],
            ["state": "failed", "summary": "result"]
        ] {
            let receiptResponse = try report([], metadata: ["receipt": invalidReceipt])
            precondition(InstallReceipt(receiptResponse.document["receipt"]!) == nil)
        }
        let receiptBounds = try report([], metadata: ["receipt": ["state": "failed", "version": "../../private",
            "summary": String(repeating: "x", count: 3000), "backup_available": false]])
        let boundedReceipt = InstallReceipt(receiptBounds.document["receipt"]!)!
        precondition(boundedReceipt.version == nil && boundedReceipt.summary.count == 2000 && !boundedReceipt.backupAvailable)
        print("GUI contract: gating, recovery, maintenance plans, update phases, and strict command/URL allowlists passed")
    }
}
