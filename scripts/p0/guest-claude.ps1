param([switch]$Elevated)
$ErrorActionPreference = 'Stop'
if (-not (Test-Path C:\P0Input\manifest.json) -or -not (Test-Path C:\P0Results)) { throw 'Disposable guest mappings required' }
$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) {
    if ($Elevated) { throw 'Guest elevation failed' }
    Start-Process powershell.exe -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File C:\P0Input\run-sandbox.ps1 -Elevated' -Verb RunAs -WindowStyle Hidden
    return
}

$root = 'C:\P0Lab'
$results = 'C:\P0Results'
$report = [ordered]@{schemaVersion = 1; scenarios = [ordered]@{}; cleanup = [ordered]@{}}
$helpers = @()
$pkg = $null
$provisioned = $null
$sessionFolder = $null
$guard = $null
$appFiles = 'C:\Program Files\ProxyHarborP0Claude'
$success = $false

function Read-Json($Path) {
    if (Test-Path -LiteralPath $Path) {
        try { Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json } catch { }
    }
}

function Wait-For($Seconds, [scriptblock]$Condition) {
    $clock = [Diagnostics.Stopwatch]::StartNew()
    do {
        if (& $Condition) { return $true }
        Start-Sleep -Milliseconds 200
    } while ($clock.Elapsed.TotalSeconds -lt $Seconds)
    return $false
}

function Write-Report {
    $path = Join-Path $results 'claude-validation.json'
    $json = $report | ConvertTo-Json -Depth 12
    for ($attempt = 0; ; $attempt++) {
        try { [IO.File]::WriteAllText($path, $json, [Text.Encoding]::UTF8); return }
        catch [IO.IOException] { if ($attempt -ge 24) { throw }; Start-Sleep -Milliseconds 200 }
    }
}

function Start-Helper($File, $Arguments, $Log) {
    Start-Process -FilePath (Join-Path $root $File) -ArgumentList $Arguments -WorkingDirectory $root -WindowStyle Hidden -PassThru `
        -RedirectStandardOutput (Join-Path $results ($Log + '.log')) -RedirectStandardError (Join-Path $results ($Log + '.stderr.log'))
}

function Set-Check($Row, $Name, [bool]$Passed) {
    $Row.checks[$Name] = $Passed
    if (-not $Passed) { Write-Report; throw "Claude check failed: $Name" }
}

try {
    $manifest = Read-Json C:\P0Input\manifest.json
    if ($manifest.publicBridgeRound -notmatch '^[a-f0-9]{8}$' -or (Test-Path $root)) { throw 'Fresh guest and explicit bridge lease required' }
    New-Item -ItemType Directory -Path $root | Out-Null
    foreach ($entry in $manifest.files) {
        if ($entry.path -notmatch '^[a-z0-9][a-z0-9.-]+$') { throw 'Invalid package member' }
        $src = Join-Path C:\P0Input $entry.path
        $dst = Join-Path $root $entry.path
        Copy-Item -LiteralPath $src -Destination $dst
        if ((Get-FileHash -LiteralPath $dst).Hash -ne $entry.sha256) { throw "Package hash mismatch: $($entry.path)" }
    }
    $report.expectedProxyIPv4 = $manifest.expectedProxyIPv4
    $report.layout = $manifest.layout
    $report.msixCandidate = [bool]$manifest.msixCandidate
    $report.packageSha256 = ($manifest.files | Where-Object path -eq 'Claude.msix').sha256
    $report.guardianSha256 = ($manifest.files | Where-Object path -eq 'guardian.exe').sha256
    $env:PROXY_HARBOR_P0_GUEST = 'offline-lab'
    Set-Location -LiteralPath $root
    $report.stage = 'installation'
    Write-Report
    if (Get-AppxPackage -Name Claude) { throw 'A fresh Claude installation is required' }
    $packageFile = Join-Path $root 'Claude.msix'
    if ($manifest.layout -eq 'provisioned') {
        if (Get-AppxProvisionedPackage -Online | Where-Object DisplayName -eq 'Claude') { throw 'A fresh provisioning state is required' }
        Add-AppxProvisionedPackage -Online -PackagePath $packageFile -SkipLicense -Regions all | Out-Null
        $provisioned = Get-AppxProvisionedPackage -Online | Where-Object DisplayName -eq 'Claude'
        if (-not $provisioned) { throw 'Provisioned package was not recorded' }
        $report.provisioned = $provisioned.PackageName
    }
    if (-not (Get-AppxPackage -Name Claude)) { Add-AppxPackage -Path $packageFile }
    $pkg = Get-AppxPackage -Name Claude
    if (-not $pkg -or $pkg.Publisher -notmatch '^CN="Anthropic, PBC",') { throw 'Installed package is missing the Anthropic publisher identity' }
    $pkgManifest = Get-AppxPackageManifest -Package $pkg.PackageFullName
    $entry = @($pkgManifest.Package.Applications.Application | Where-Object { $_.Executable -match '(^|\\)claude\.exe$' })
    if ($entry.Count -ne 1) { throw 'Claude desktop entry point not found in package manifest' }
    $image = [IO.Path]::GetFullPath((Join-Path $pkg.InstallLocation $entry[0].Executable))
    if (-not $image.StartsWith($pkg.InstallLocation + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'Invalid package entry point' }
    $report.installation = @{version = $pkg.Version.ToString(); publisher = $pkg.Publisher; entry = $entry[0].Executable;
        signatureKind = $pkg.SignatureKind.ToString(); status = $pkg.Status.ToString()}
    if ($manifest.desktopGuardian) {
        $discovered = & .\guardian.exe claude-image
        if ($LASTEXITCODE -ne 0 -or -not $discovered -or $discovered -isnot [string]) {
            throw 'The release guardian did not find the installed Claude package'
        }
        $report.desktopDiscovery = $discovered
        $image = $discovered
    }
    if ($manifest.layout -eq 'app-files') {
        $report.stage = 'stage_app_files'
        Write-Report
        if (Test-Path -LiteralPath $appFiles) { throw 'Fresh app files directory required' }
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        [IO.Compression.ZipFile]::ExtractToDirectory($packageFile, $appFiles)
        $image = Join-Path $appFiles $entry[0].Executable
        $report.appImageSha256 = (Get-FileHash -LiteralPath $image).Hash
    } elseif ($manifest.layout -notin @('installed','provisioned')) { throw 'Unknown guest app layout' }
    'ready' | Set-Content (Join-Path $results 'guest-ready.txt')
    $report.stage = 'transport'
    Write-Report
    $bridgeRoot = Join-Path $results ('proxy-bridge-' + $manifest.publicBridgeRound)
    if (-not (Wait-For 120 { Test-Path (Join-Path $bridgeRoot 'control.json') })) { throw 'Host transport readiness timeout' }
    $helpers += Start-Helper 'node.exe' @('codex-file-bridge.mjs','guest',$bridgeRoot,'900000','10809') 'claude-file-bridge'
    $helpers += Start-Helper 'node.exe' @('claude-guest-relay.mjs') 'claude-proxy'
    if (-not (Wait-For 20 { (Get-Content (Join-Path $results 'claude-file-bridge.log') -ErrorAction SilentlyContinue) -match '"event":"listening"' })) {
        throw 'Guest bridge did not start'
    }
    $config = @{log = @{level = 'warn'}; inbounds = @(@{type = 'tun'; tag = 'tun'; interface_name = 'singbox_tun'; address = @('172.19.0.1/30');
        auto_route = $true; strict_route = $true; dns_mode = 'disabled'; stack = 'gvisor'});
        outbounds = @(@{type = 'http'; tag = 'proxy'; server = '127.0.0.1'; server_port = 10808});
        route = @{final = 'proxy'; auto_detect_interface = $true}}
    $config | ConvertTo-Json -Depth 6 | Set-Content 'tun.json' -Encoding Ascii
    $tun = Start-Helper 'sing-box.exe' @('run','-c','tun.json') 'claude-tun'
    $helpers += $tun
    if (-not (Wait-For 20 { $probe = & .\guardian.exe check | ConvertFrom-Json; $probe.tunReady })) { throw 'Guest TUN route unavailable' }
    $relay = $helpers[1]
    $listener = Get-NetTCPConnection -LocalAddress 127.0.0.1 -LocalPort 10808 -State Listen
    if ($listener.OwningProcess -ne $relay.Id) { throw 'Guest relay identity mismatch' }
    $cases = [ordered]@{ normal = 'user_stopped'; transport_down = 'exit_unverified'; tun_down = 'tun_route_changed' }
    if ($manifest.scenarios -eq 'guardian-crash') { $cases = [ordered]@{ guardian_crash = 'recovered' } }
    if ($manifest.scenarios -eq 'complete') { $cases.Insert(2, 'guardian_crash', 'recovered') }
    if ($manifest.scenarios -eq 'tun') { $cases = [ordered]@{ tun_down = 'tun_route_changed' } }
    foreach ($case in $cases.Keys) {
        $report.stage = $case
        $row = [ordered]@{checks = [ordered]@{}; processes = @(); proxy = @()}
        $report.scenarios[$case] = $row
        Write-Report
        $id = [guid]::NewGuid().ToString()
        $sessionFolder = Join-Path $root ("sessions\" + $id)
        New-Item -ItemType Directory -Path $sessionFolder | Out-Null
        $firstLog = @(Get-Content (Join-Path $results 'claude-proxy.log')).Count
        $statusPath = Join-Path $sessionFolder 'status.json'
        $guard = Start-Helper 'proxy-harbor.exe' @($sessionFolder,$manifest.expectedProxyIPv4,$relay.Id,('"' + $image + '"')) ("guardian-" + $case)
        $observed = Wait-For 55 {
            $current = Read-Json $statusPath
            $current.state -eq 'monitoring' -or $guard.HasExited
        }
        $row.initial = Read-Json $statusPath
        $row.launch = Read-Json (Join-Path $sessionFolder 'claude-launch.json')
        $packageCleanup = Join-Path $sessionFolder 'claude-package-cleanup.log'
        if (Test-Path -LiteralPath $packageCleanup) { $row.packageCleanupLog = Get-Content -LiteralPath $packageCleanup -Raw -ErrorAction SilentlyContinue }
        $row.exitCheck = Read-Json (Join-Path $sessionFolder 'exit-check.json')
        $row.proxy = @(Get-Content (Join-Path $results 'claude-proxy.log') | Select-Object -Skip $firstLog | ForEach-Object { try { $_ | ConvertFrom-Json } catch { } })
        Set-Check $row 'managed_launch' ($observed -and $row.initial.state -eq 'monitoring' -and $row.initial.pid -gt 0)
        if ($manifest.msixCandidate -and $manifest.layout -ne 'app-files') {
            Set-Check $row 'official_package_in_guardian_job' ($row.launch.packageVerified -eq $true -and $row.launch.jobVerified -eq $true -and
                $row.launch.pid -eq $row.initial.pid)
        }
        Set-Check $row 'fixed_ipv4_and_tun' ($row.exitCheck.matchesExpected -eq $true -and $row.exitCheck.observed -eq $manifest.expectedProxyIPv4 -and $row.initial.tunIndex -gt 0)
        Set-Check $row 'application_and_system_dns_filters' ($row.initial.filterCount -eq 20 -and $row.initial.dns -eq 'system_blocked')
        Write-Report
        $main = Get-Process -Id $row.initial.pid -ErrorAction SilentlyContinue
        $appPids = @{}
        if ($main) { $appPids[$main.Id] = $main }
        $windowReady = Wait-For 35 {
            if ($guard.HasExited) { return $true }
            $app = @(Get-Process -Name Claude -ErrorAction SilentlyContinue)
            foreach ($proc in $app) { $appPids[$proc.Id] = $proc }
            return @($app | Where-Object MainWindowHandle -ne 0).Count -gt 0
        }
        if ($windowReady -and -not $guard.HasExited) {
            [void](Wait-For 15 {
                if ($guard.HasExited) { return $true }
                $data = Get-Content (Join-Path $results 'claude-proxy.log') | Select-Object -Skip $firstLog
                $data -match '"event":"tunnel_data","authority":"(?:[a-z0-9.-]+\.)?(?:claude\.ai|claude\.com|anthropic\.com):443"'
            })
        }
        foreach ($proc in @(Get-Process -Name Claude -ErrorAction SilentlyContinue)) { $appPids[$proc.Id] = $proc }
        $row.processes = @(foreach ($proc in $appPids.Values) {
            $proc.Refresh()
            if (-not $proc.HasExited) {
                $record = Get-CimInstance Win32_Process -Filter ('ProcessId=' + $proc.Id) -OperationTimeoutSec 3
                if (-not $record) { continue }
                $sid = Invoke-CimMethod -InputObject $record -MethodName GetOwnerSid -OperationTimeoutSec 3
                [pscustomobject]@{pid = $proc.Id; parent = $record.ParentProcessId; sid = $sid.Sid;
                    window = $proc.MainWindowHandle -ne 0; title = $proc.MainWindowTitle}
            }
        })
        $row.proxy = @(Get-Content (Join-Path $results 'claude-proxy.log') | Select-Object -Skip $firstLog | ForEach-Object { try { $_ | ConvertFrom-Json } catch { } })
        $row.final = Read-Json $statusPath
        $row.stopEvidence = Read-Json (Join-Path $sessionFolder 'claude-stop.json')
        if (Test-Path -LiteralPath $packageCleanup) { $row.packageCleanupLog = Get-Content -LiteralPath $packageCleanup -Raw -ErrorAction SilentlyContinue }
        Write-Report
        $row.processSID = @(Get-LocalUser | Where-Object Name -Match '^PH_[0-9a-f]{16}$' | ForEach-Object { $_.SID.Value })
        $peer = @(Get-NetTCPConnection -RemoteAddress 127.0.0.1 -RemotePort 10808 -State Established -ErrorAction SilentlyContinue |
            Where-Object { $appPids.ContainsKey([int]$_.OwningProcess) })
        $row.proxyPeers = @($peer | Select-Object OwningProcess,LocalPort,RemoteAddress,RemotePort)
        Set-Check $row 'visible_window' ($windowReady -and -not $guard.HasExited -and @($row.processes | Where-Object window).Count -gt 0)
        Set-Check $row 'same_session_sid' ($row.processSID.Count -eq 1 -and $row.processes.Count -gt 1 -and
            @($row.processes | Where-Object sid -ne $row.processSID[0]).Count -eq 0)
        if ($manifest.msixCandidate -and $manifest.layout -ne 'app-files') {
            $registeredUsers = (Get-AppxPackage -AllUsers -Name Claude).PackageUserInformation
            Set-Check $row 'temporary_package_registration_observed' (@($registeredUsers | Where-Object {
                $_.UserSecurityId.Sid -eq $row.processSID[0] -and [string]$_.InstallState -eq 'Installed'
            }).Count -eq 1)
        }
        $tunnel = @($row.proxy | Where-Object { $_.event -eq 'tunnel_data' -and $_.authority -match '(^|\.)(claude\.ai|claude\.com|anthropic\.com):443$' })
        Set-Check $row 'claude_tls_tunnel' (@($tunnel | Where-Object { $peer.LocalPort -contains $_.port }).Count -gt 0)
        $timer = [Diagnostics.Stopwatch]::StartNew()
        if ($case -eq 'guardian_crash') {
            $watchState = Join-Path $sessionFolder 'dns-watch.state'
            $native = Get-Process -Id $row.initial.guardianPid
            Set-Check $row 'owned_guardian_for_injection' ($native.Path -eq (Join-Path $root 'guardian.exe') -and
                $native.StartTime.ToFileTimeUtc() -eq [int64]$row.initial.guardianCreated -and -not (Test-Path -LiteralPath $watchState))
            Stop-Process -InputObject $native -Force
            $row.checks.crash_terminated_guardian = $native.WaitForExit(10000) -and $guard.WaitForExit(10000)
            $row.checks.crash_terminated_claude = Wait-For 20 {
                @($appPids.Values | Where-Object { -not $_.HasExited }).Count -eq 0 -and
                    @(Get-Process -Name Claude -ErrorAction SilentlyContinue).Count -eq 0
            }
            $row.crashToAppExitMs = $timer.ElapsedMilliseconds
            $row.checks.crash_watchdog_restored_dns = Wait-For 25 {
                (Test-Path -LiteralPath $watchState) -and (Get-Content -LiteralPath $watchState -Raw).Trim() -eq 'restored'
            }
            $row.crashInspection = & .\guardian.exe inspect $sessionFolder | ConvertFrom-Json
            Write-Report
            Set-Check $row 'crash_terminated_guardian' $row.checks.crash_terminated_guardian
            Set-Check $row 'crash_terminated_claude' $row.checks.crash_terminated_claude
            Set-Check $row 'crash_watchdog_restored_dns' $row.checks.crash_watchdog_restored_dns
            Set-Check $row 'application_rules_retained_after_crash' ($row.crashInspection.windowsError -eq 0 -and $row.crashInspection.rulesPresent -eq 14)
            $recover = Start-Helper 'guardian.exe' @('recover',$sessionFolder) 'guardian-recover'
            $null = $recover.Handle
            $recovered = $recover.WaitForExit(70000)
            $row.final = Read-Json $statusPath
            $row.recoveryGuard = Read-Json (Join-Path $sessionFolder 'claude-recovery.json')
            $row.recoveryInspection = & .\guardian.exe inspect $sessionFolder | ConvertFrom-Json
            $row.remainingRegistration = @((Get-AppxPackage -AllUsers -Name Claude).PackageUserInformation | Where-Object {
                $_.UserSecurityId.Sid -eq $row.processSID[0] -and [string]$_.InstallState -like 'Installed*'
            } | ForEach-Object InstallState)
            $row.recoveryExitCode = if ($recovered) { $recover.ExitCode } else { $null }
            Write-Report
            Set-Check $row 'recovery_completed' ($recovered -and $recover.ExitCode -eq 0 -and
                $row.final.state -eq 'stopped' -and $row.final.reason -eq 'recovered')
            Set-Check $row 'recovery_blocked_outbound_before_relogon' ($row.recoveryGuard.outboundBlockedBeforeReLogon -eq $true)
            Set-Check $row 'recovery_removed_rules_and_identity' ($row.recoveryInspection.windowsError -eq 0 -and
                $row.recoveryInspection.rulesPresent -eq 0 -and -not (Test-Path -LiteralPath (Join-Path $sessionFolder 'identity.txt')) -and
                @(Get-LocalUser | Where-Object { $_.SID.Value -eq $row.processSID[0] }).Count -eq 0)
            Set-Check $row 'recovery_removed_only_temporary_registration' ($row.remainingRegistration.Count -eq 0 -and
                (Get-AppxPackage -Name Claude).PackageFullName -eq $pkg.PackageFullName)
            Write-Report
            continue
        }
        if ($case -eq 'normal') { 'stop' | Set-Content (Join-Path $sessionFolder 'stop') }
        if ($case -eq 'transport_down') { 'down' | Set-Content (Join-Path $root 'transport-down') }
        if ($case -eq 'tun_down') { Stop-Process -InputObject $tun -Force }
        $finished = $guard.WaitForExit(50000)
        $row.stopLatencyMs = $timer.ElapsedMilliseconds
        $row.final = Read-Json $statusPath
        $row.stopEvidence = Read-Json (Join-Path $sessionFolder 'claude-stop.json')
        if (Test-Path -LiteralPath $packageCleanup) { $row.packageCleanupLog = Get-Content -LiteralPath $packageCleanup -Raw -ErrorAction SilentlyContinue }
        $row.lastExitCheck = Read-Json (Join-Path $sessionFolder 'exit-check.json')
        $row.inspection = & .\guardian.exe inspect $sessionFolder | ConvertFrom-Json
        if ($manifest.msixCandidate -and $manifest.layout -ne 'app-files') {
            Set-Check $row 'expected_stop_trigger' ($row.stopEvidence.reason -eq $cases[$case])
        }
        Set-Check $row 'application_and_components_terminated' (@($appPids.Values | Where-Object { -not $_.HasExited }).Count -eq 0)
        if ($manifest.msixCandidate -and $manifest.layout -ne 'app-files') {
            $registeredUsers = (Get-AppxPackage -AllUsers -Name Claude).PackageUserInformation
            Set-Check $row 'temporary_package_registration_removed' (@($registeredUsers | Where-Object {
                $_.UserSecurityId.Sid -eq $row.processSID[0] -and [string]$_.InstallState -like 'Installed*'
            }).Count -eq 0 -and (Get-AppxPackage -Name Claude).PackageFullName -eq $pkg.PackageFullName)
        }
        Set-Check $row 'correct_stop_reason' ($finished -and $row.final.state -eq 'stopped' -and $row.final.reason -eq $cases[$case])
        Set-Check $row 'session_rules_and_identity_cleaned' ($row.inspection.windowsError -eq 0 -and $row.inspection.rulesPresent -eq 0 -and
            $row.final.dns -eq 'restored' -and -not (Test-Path (Join-Path $sessionFolder 'identity.txt')))
        if ($case -eq 'transport_down') { Remove-Item -LiteralPath (Join-Path $root 'transport-down') }
        Write-Report
    }
    $success = $true
} catch {
    $report.failure = ($_ | Out-String).Trim()
} finally {
    if ($guard -and -not $guard.HasExited) {
        'stop' | Set-Content (Join-Path $sessionFolder 'stop')
        [void]$guard.WaitForExit(15000)
    }
    if ($sessionFolder) {
        $report.lastGuardianStatus = Read-Json (Join-Path $sessionFolder 'status.json')
        try {
            $packageCleanup = Join-Path $sessionFolder 'claude-package-cleanup.log'
            if (Test-Path -LiteralPath $packageCleanup) { $report.packageCleanupLog = Get-Content -LiteralPath $packageCleanup -Raw }
            Write-Report
            if ($report.lastGuardianStatus.state -eq 'cleanup_required') {
                $report.retainedPackageRegistrations = @((Get-AppxPackage -AllUsers -Name Claude).PackageUserInformation | Select-Object UserSecurityId,InstallState)
                $report.retainedProfiles = @(Get-ChildItem C:\Users -Directory | Where-Object Name -Match '^PH_[0-9a-f]{16}(\.|$)' | ForEach-Object {
                    [pscustomobject]@{name = $_.Name; aliasPresent = Test-Path -LiteralPath (Join-Path $_.FullName 'AppData\Local\Microsoft\WindowsApps\claude-desktop.exe');
                        registrationLog = Get-Content -LiteralPath (Join-Path $_.FullName 'claude-registration.log') -Raw -ErrorAction SilentlyContinue}
                })
            }
        } catch { $report.packageDiagnosticsError = $_.Exception.Message }
    }
    Write-Report
    foreach ($helper in $helpers) {
        if (-not $helper.HasExited) { Stop-Process -InputObject $helper -Force -ErrorAction SilentlyContinue }
    }
    if ($pkg) {
        try { Remove-AppxPackage -Package $pkg.PackageFullName -ErrorAction Stop } catch { $report.uninstallError = $_.Exception.Message }
    }
    if ($provisioned) {
        try { Remove-AppxProvisionedPackage -Online -PackageName $provisioned.PackageName -ErrorAction Stop | Out-Null } catch { $report.provisioningCleanupError = $_.Exception.Message }
    }
    if ($manifest.layout -eq 'app-files' -and (Test-Path -LiteralPath $appFiles)) {
        try { Remove-Item -LiteralPath $appFiles -Recurse -Force } catch { $report.appFilesCleanupError = $_.Exception.Message }
    }
    try {
        $report.cleanup.guardianStopped = -not $guard -or $guard.HasExited
        $report.cleanup.temporaryAccountsAbsent = @(Get-LocalUser | Where-Object Name -Match '^PH_[0-9a-f]{16}$').Count -eq 0
        $report.cleanup.temporaryProfilesAbsent = @(Get-ChildItem C:\Users -Directory | Where-Object Name -Match '^PH_[0-9a-f]{16}(\.|$)').Count -eq 0
        $report.cleanup.claudeProcessesAbsent = @(Get-Process -Name Claude -ErrorAction SilentlyContinue).Count -eq 0
        $report.cleanup.claudePackageAbsent = -not (Get-AppxPackage -Name Claude)
        $report.cleanup.testAppFilesAbsent = -not (Test-Path -LiteralPath $appFiles)
        if ($manifest.layout -eq 'provisioned') {
            $report.cleanup.provisionedPackageAbsent = -not (Get-AppxProvisionedPackage -Online | Where-Object DisplayName -eq 'Claude')
        }
        if (Test-Path .\session-inventory.exe) {
            $inventory = & .\session-inventory.exe inspect | ConvertFrom-Json
            $report.cleanup.sessionRulesAbsent = $LASTEXITCODE -eq 0 -and $inventory.complete -eq $true -and $inventory.windowsError -eq 0 -and $inventory.rulesPresent -eq 0
        }
    } catch { $report.cleanupError = $_.Exception.Message }
    $expectedCleanup = if ($manifest.layout -eq 'provisioned') { 8 } else { 7 }
    $report.passed = $success -and $report.cleanup.Count -eq $expectedCleanup -and @($report.cleanup.Values | Where-Object { $_ -ne $true }).Count -eq 0
    Write-Report
    [int](-not $report.passed) | Set-Content (Join-Path $results 'finished.txt')
}
