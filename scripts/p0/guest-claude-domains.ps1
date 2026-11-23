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
$report = [ordered]@{schemaVersion = 1; rows = @(); checks = [ordered]@{}; cleanup = [ordered]@{}}
$helpers = @()
$guardian = $null
$tun = $null
$folder = $null
$rule = $null
$tempProfile = $null
$observerLog = Join-Path $results 'domain-observer.log'

function Read-Json($Path) {
    if (Test-Path -LiteralPath $Path) {
        try { Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json } catch { }
    }
}
function Read-Lines($Path) {
    if (Test-Path -LiteralPath $Path) { Get-Content -LiteralPath $Path | ForEach-Object { try { $_ | ConvertFrom-Json } catch { } } }
}
function Write-Report {
    $path = Join-Path $results 'claude-domain-audit.json'
    $json = $report | ConvertTo-Json -Depth 9
    for ($attempt = 0; ; $attempt++) {
        try { [IO.File]::WriteAllText($path, $json, [Text.Encoding]::UTF8); return }
        catch [IO.IOException] { if ($attempt -ge 24) { throw }; Start-Sleep -Milliseconds 200 }
    }
}
function Wait-For($Seconds, [scriptblock]$Condition) {
    $stop = [DateTime]::UtcNow.AddSeconds($Seconds)
    do { if (& $Condition) { return $true }; Start-Sleep -Milliseconds 250 } while ([DateTime]::UtcNow -lt $stop)
    return $false
}
function Start-Helper($File, $Arguments, $Log) {
    Start-Process -FilePath (Join-Path $root $File) -ArgumentList $Arguments -WorkingDirectory $root -WindowStyle Hidden -PassThru `
        -RedirectStandardOutput (Join-Path $results ($Log + '.log')) -RedirectStandardError (Join-Path $results ($Log + '.stderr.log'))
}
function Query-ObservedDNS([string]$Name) {
    Resolve-DnsName -Name $Name -Type A -DnsOnly -NoHostsFile -QuickTimeout -ErrorAction SilentlyContinue | Out-Null
    return @(Read-Lines $observerLog | Where-Object { $_.event -eq 'dns' -and $_.name -eq $Name }).Count -gt 0
}

try {
    $manifest = Read-Json C:\P0Input\manifest.json
    if ($manifest.publicBridgeRound -notmatch '^[a-f0-9]{8}$' -or (Test-Path -LiteralPath $root)) { throw 'Fresh guest and bridge required' }
    New-Item -ItemType Directory -Path $root | Out-Null
    Copy-Item -LiteralPath C:\P0Input\manifest.json -Destination (Join-Path $root 'manifest.json')
    foreach ($entry in $manifest.files) {
        if ($entry.path -notmatch '^[a-z0-9][a-z0-9.-]+$') { throw 'Invalid fixture name' }
        $dst = Join-Path $root $entry.path
        Copy-Item -LiteralPath (Join-Path C:\P0Input $entry.path) -Destination $dst
        if ((Get-FileHash -LiteralPath $dst).Hash -ne $entry.sha256) { throw 'Fixture hash mismatch' }
    }
    $report.guardianSha256 = ($manifest.files | Where-Object path -eq 'guardian.exe').sha256
    $report.catalogSha256 = ($manifest.files | Where-Object path -eq 'claude-code-domains.json').sha256
    $report.expectedProxyIPv4 = $manifest.expectedProxyIPv4
    $env:PROXY_HARBOR_P0_GUEST = 'offline-lab'
    Set-Location -LiteralPath $root
    $catalog = Read-Json (Join-Path $root 'claude-code-domains.json')
    $domains = @(foreach ($group in $catalog.groups) { $group.domains })
    if ($domains.Count -ne 24 -or @($domains | Sort-Object -Unique).Count -ne $domains.Count -or
        @($domains | Where-Object {$_ -notmatch '^[a-z0-9.-]+\.[a-z]{2,}$'}).Count) { throw 'Expected the 24 catalog hosts' }
    $report.domains = $domains
    $targets = $domains
    $report.rootMethod = 'HEAD'
    if (@($manifest.selectedDomains | Where-Object {$_}).Count) {
        $targets = @($manifest.selectedDomains)
        if (@($targets | Where-Object {$_ -notin $domains}).Count -or @($targets | Sort-Object -Unique).Count -ne $targets.Count) { throw 'Retry targets must belong to the catalog' }
        $report.rootMethod = 'GET'
        $report.retryOf = $manifest.retryOf
    }
    $report.targets = $targets
    $report.stage = 'controls'
    Write-Report

    $helpers += Start-Helper 'node.exe' @('claude-domain-observer.mjs') 'domain-observer'
    if (-not (Wait-For 8 { @(Read-Lines $observerLog | Where-Object event -Match '-ready$').Count -eq 3 })) { throw 'Controlled observer startup failed' }
    $tag = [Guid]::NewGuid().ToString('N').Substring(0,10)
    $owner = "ProxyHarbor.P0.ClaudeDomains.$tag"
    Add-DnsClientNrptRule -Namespace (@('.p0-catalog.invalid') + $domains) -NameServers '127.0.0.1' -DisplayName $owner | Out-Null
    $rule = Get-DnsClientNrptRule | Where-Object DisplayName -eq $owner
    if (-not $rule) { throw 'Could not independently locate test DNS rule' }
    $report.checks.dnsPositiveBefore = Query-ObservedDNS "$tag-before.p0-catalog.invalid"
    $control = [Net.Sockets.TcpClient]::new()
    try { $control.Connect('127.0.0.1', 18085) } finally { $control.Dispose() }
    $report.checks.directPositive = Wait-For 5 { @(Read-Lines $observerLog | Where-Object event -eq 'direct-accepted').Count -eq 1 }
    if (-not $report.checks.dnsPositiveBefore -or -not $report.checks.directPositive) { throw 'Positive controls failed' }

    $report.stage = 'transport'
    Write-Report
    $bridgeRoot = Join-Path $results ('proxy-bridge-' + $manifest.publicBridgeRound)
    if (-not (Wait-For 120 { Test-Path (Join-Path $bridgeRoot 'control.json') })) { throw 'Host bridge readiness timeout' }
    $helpers += Start-Helper 'node.exe' @('codex-file-bridge.mjs','guest',$bridgeRoot,'900000','10809') 'guest-bridge'
    $relay = Start-Helper 'node.exe' @('claude-guest-relay.mjs','domain-audit') 'domain-proxy'
    $helpers += $relay
    if (-not (Wait-For 20 { @(Read-Lines (Join-Path $results 'guest-bridge.log') | Where-Object event -eq 'listening').Count -eq 1 })) { throw 'Guest bridge did not listen' }
    $config = @{log = @{level = 'warn'}; inbounds = @(@{type = 'tun'; tag = 'tun'; interface_name = 'singbox_tun'; address = @('172.19.0.1/30');
        auto_route = $true; strict_route = $true; dns_mode = 'disabled'; stack = 'gvisor'});
        outbounds = @(@{type = 'http'; tag = 'proxy'; server = '127.0.0.1'; server_port = 10808});
        route = @{final = 'proxy'; auto_detect_interface = $true}}
    $config | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $root 'tun.json') -Encoding Ascii
    $tun = Start-Helper 'sing-box.exe' @('run','-c','tun.json') 'domain-tun'
    $helpers += $tun
    if (-not (Wait-For 20 { $p = & .\guardian.exe check | ConvertFrom-Json; $p.tunReady })) { throw 'Guest TUN route unavailable' }
    $report.stage = 'protected_probe'
    Write-Report
    $session = [Guid]::NewGuid().ToString()
    $folder = Join-Path $root ("sessions\" + $session)
    New-Item -ItemType Directory -Path $folder | Out-Null
    $account = 'PH_' + $session.Replace('-','').Substring(0,16)
    $statusPath = Join-Path $folder 'status.json'
    $exitPath = Join-Path $folder 'exit-check.json'
    $guardian = Start-Helper 'proxy-harbor.exe' @($folder,$manifest.expectedProxyIPv4,$relay.Id,'C:\P0Lab\domain-probe.exe') 'domain-guardian'
    [void](Wait-For 55 { $s = Read-Json $statusPath; $s.state -eq 'monitoring' -or $guardian.HasExited })
    $report.initial = Read-Json $statusPath
    $report.initialExitCheck = Read-Json $exitPath
    $report.checks.sessionProtected = $report.initial.state -eq 'monitoring' -and $report.initial.filterCount -eq 20 -and
        $report.initial.dns -eq 'system_blocked' -and $report.initial.tunIndex -gt 0 -and $report.initialExitCheck.matchesExpected
    if (-not $report.checks.sessionProtected) { throw 'Managed probe did not reach monitoring' }
    $probe = Get-Process -Id $report.initial.pid -ErrorAction Stop
    $temp = Get-LocalUser -Name $account
    $record = Get-CimInstance Win32_Process -Filter ('ProcessId=' + $probe.Id) -OperationTimeoutSec 5
    $ownerId = Invoke-CimMethod -InputObject $record -MethodName GetOwnerSid -OperationTimeoutSec 5
    $report.checks.probeIdentity = $ownerId.Sid -eq $temp.SID.Value
    $profileRecord = Get-CimInstance Win32_UserProfile -Filter ("SID='" + $temp.SID.Value + "'") -OperationTimeoutSec 5
    $tempProfile = $profileRecord.LocalPath
    if ($tempProfile -notmatch '^C:\\Users\\PH_[0-9a-f]{16}(\.[a-z0-9.-]+)?$' -or -not $report.checks.probeIdentity) { throw 'Managed user identity mismatch' }
    $report.checks.dnsCanaryBlocked = -not (Query-ObservedDNS "$tag-during.p0-catalog.invalid") -and -not $guardian.HasExited
    $pending = @{}
    $tracePending = @{}
    $deadline = [DateTime]::UtcNow.AddSeconds(360)
    do {
        $count = $pending.Count + $tracePending.Count
        foreach ($file in Get-ChildItem -LiteralPath $tempProfile -Filter 'domain-*.json' -File -ErrorAction SilentlyContinue) {
            if (-not $pending.ContainsKey($file.Name)) {
                $row = Read-Json $file.FullName
                if ($row -and $row.domain -in $targets) { $pending[$file.Name] = $row }
            }
        }
        foreach ($file in Get-ChildItem -LiteralPath $tempProfile -Filter 'trace-*.json' -File -ErrorAction SilentlyContinue) {
            if (-not $tracePending.ContainsKey($file.Name)) {
                $row = Read-Json $file.FullName
                if ($row -and $row.domain -in $domains) { $tracePending[$file.Name] = $row }
            }
        }
        if ($pending.Count + $tracePending.Count -ne $count) {
            $report.rows = @($pending.GetEnumerator() | Sort-Object Name | ForEach-Object Value)
            $report.targetExitSamples = @($tracePending.GetEnumerator() | Sort-Object Name | ForEach-Object Value)
            Write-Report
        }
        if ($guardian.HasExited -or (Test-Path -LiteralPath (Join-Path $tempProfile 'domains-ready'))) { break }
        Start-Sleep -Milliseconds 250
    } while ([DateTime]::UtcNow -lt $deadline)
    $report.finalExitCheck = Read-Json $exitPath
    $connects = @(Read-Lines (Join-Path $results 'domain-proxy.log'))
    foreach ($row in @($report.rows) + @($report.targetExitSamples | Where-Object {$_})) {
        $matched = @($connects | Where-Object { $_.event -eq 'connect' -and $_.port -eq $row.localPort -and $_.authority -eq ($row.domain + ':443') }).Count -ge 1
        $row | Add-Member -NotePropertyName relayConnectObserved -NotePropertyValue $matched
    }
    $dnsEvents = @(Read-Lines $observerLog | Where-Object event -eq 'dns')
    $report.catalogLocalDNS = @($dnsEvents | Where-Object { $_.name -in $domains })
    $report.checks.catalogLocalDNSAbsent = $report.catalogLocalDNS.Count -eq 0 -and @((@($report.rows) + @($report.targetExitSamples | Where-Object {$_})) | Where-Object localDNS).Count -eq 0
    $report.checks.allSelectedAttempted = $pending.Count -eq $targets.Count
    $report.checks.proxyOnlyObserved = $pending.Count -gt 0 -and @($report.rows | Where-Object { $_.tcpPeer -ne '127.0.0.1:10808' -or -not $_.relayConnectObserved }).Count -eq 0
    $report.stage = 'direct_control'
    Write-Report
    if (-not $report.checks.allSelectedAttempted -or $guardian.HasExited) { throw 'Protected catalog probe was interrupted' }
    'test' | Set-Content -LiteralPath (Join-Path $root 'direct-negative')
    [void]$guardian.WaitForExit(40000)
    $report.final = Read-Json $statusPath
    $report.checks.directBlocked = $guardian.HasExited -and $report.final.state -eq 'stopped' -and
        $report.final.reason -eq 'bypass_blocked' -and $report.final.blockedRemotePort -eq 18085 -and
        @(Read-Lines $observerLog | Where-Object event -eq 'direct-accepted').Count -eq 1
    $report.checks.managedProbeTerminated = $probe.HasExited
    if ($tun -and -not $tun.HasExited) { Stop-Process -InputObject $tun -Force }
    $report.checks.dnsPositiveAfter = Query-ObservedDNS "$tag-after.p0-catalog.invalid"
} catch {
    $report.failure = ($_ | Out-String).Trim()
} finally {
    if ($guardian -and -not $guardian.HasExited -and $folder) {
        'stop' | Set-Content -LiteralPath (Join-Path $folder 'stop')
        [void]$guardian.WaitForExit(30000)
    }
    if ($folder) { $report.lastGuardianStatus = Read-Json (Join-Path $folder 'status.json') }
    foreach ($process in $helpers) {
        if (-not $process.HasExited) { Stop-Process -InputObject $process -Force -ErrorAction SilentlyContinue }
    }
    try {
        if ($rule) { Remove-DnsClientNrptRule -Name $rule.Name -Force }
        $report.cleanup.testNRPTRemoved = -not $rule -or -not (Get-DnsClientNrptRule | Where-Object DisplayName -eq $owner)
        $report.cleanup.guardianExited = -not $guardian -or $guardian.HasExited
        $report.cleanup.accountAbsent = -not $folder -or -not (Get-LocalUser -Name $account -ErrorAction SilentlyContinue)
        $report.cleanup.profileAbsent = -not $tempProfile -or -not (Test-Path -LiteralPath $tempProfile)
        $inventory = & .\session-inventory.exe inspect | ConvertFrom-Json
        $report.cleanup.rulesAbsent = $LASTEXITCODE -eq 0 -and $inventory.complete -and $inventory.windowsError -eq 0 -and $inventory.rulesPresent -eq 0
    } catch { $report.cleanupError = $_.Exception.Message }
    $outcomes = @($report.checks.Values) + @($report.cleanup.Values)
    $report.protectionChecksPassed = -not $report.failure -and $report.checks.Count -eq 11 -and $report.cleanup.Count -eq 5 -and
        @($outcomes | Where-Object { $_ -ne $true }).Count -eq 0
    Write-Report
    [int](-not $report.protectionChecksPassed) | Set-Content -LiteralPath (Join-Path $results 'finished.txt')
}
