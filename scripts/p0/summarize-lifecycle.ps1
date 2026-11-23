param([Parameter(Mandatory)][ValidatePattern('^[0-9]{8}-[0-9]{6}-[a-f0-9]{6}$')][string]$BundleIdentifier)
$ErrorActionPreference='Stop'
$repository=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$bundle=Join-Path $repository ('.local\p0\sandbox\'+$BundleIdentifier)
$results=Join-Path $bundle 'results'
$summary=Get-Content -LiteralPath (Join-Path $results 'sandbox-summary.json') -Raw|ConvertFrom-Json
if($summary.state -ne 'complete'){throw 'Guest validation is still running'}
$rows=@();$reportHashes=@();$failures=@()
foreach($name in @('sid-lifecycle-report.json','wfp-isolated-kernel-report.json','dns-wfp-boundary-report.json','sid-policy-boundary-report.json')){
    $path=Join-Path $results $name
    if(-not (Test-Path -LiteralPath $path)){$failures+=$name;continue}
    $report=Get-Content -LiteralPath $path -Raw|ConvertFrom-Json
    $items=if($report.cases){@($report.cases)}else{@($report)}
    $checks=0;$failed=0
    foreach($item in $items){if($item.checks){$checks+=@($item.checks.psobject.Properties).Count;$failed+=@($item.checks.psobject.Properties|Where-Object Value -ne $true).Count}}
    $cleanupOK=if($report.cleanup){$report.cleanup -eq 'verified'}else{@($items|Where-Object cleanup -ne 'verified').Count -eq 0}
    if($report.nrptCleanup -and $report.nrptCleanup -ne 'verified'){$cleanupOK=$false}
    if($failed -or -not $cleanupOK){$failures+=$name}
    $rows+=@{report=$name;checks=$checks;failedChecks=$failed;cleanupVerified=$cleanupOK;scope=$report.scope}
    $reportHashes+=@{path=$name;sha256=(Get-FileHash -LiteralPath $path).Hash}
}
if($summary.error -or $summary.lifecycleChecks -ne 'passed' -or $summary.lifecycleRegressionChecks -ne 'passed'){$failures+='guest-summary'}
$sourcePaths=@('native\p0\isolation_policy.c','native\p0\dns_isolation_lab.c','native\p0\run-sandbox.ps1','app\proxy-harbor\cmd\p0-probe\main.go','app\proxy-harbor\cmd\p0-probe\lifecycle.go','app\proxy-harbor\internal\engine\sid_lifecycle_system_test.go','scripts\p0\prepare-sandbox.ps1','scripts\p0\sandbox-lab.ps1','scripts\p0\summarize-lifecycle.ps1')
$sources=@($sourcePaths|ForEach-Object {@{path=$_;sha256=(Get-FileHash -LiteralPath (Join-Path $repository $_)).Hash}})
$record=[ordered]@{schemaVersion=1;generatedAtUtc=[DateTimeOffset]::UtcNow.ToString('o');bundle=$BundleIdentifier;overall='not_accepted';desktopProtectionEnabled=$false;boundedLifecycleChecks=if($failures.Count){'failed'}else{'passed'};failedReports=$failures;reports=$rows;reportHashes=$reportHashes;sourceHashes=$sources;guestSummary=$summary;scope='Guest NIC down/up; fixed public IPv4 TCP control; loopback tunnels; SID controller and child faults; supervised fixture recovery';remaining=@('Real handover between distinct routed networks and sleep/resume not verified','No final SID reboot or earliest-boot evidence added','Supervised fixture DACL/profile recovery is not a deployed production recovery service','No actual desktop application acceptance; no Claude testing; no P1 work')}
$record|ConvertTo-Json -Depth 12|Set-Content -LiteralPath (Join-Path $repository '.local\p0\lifecycle-validation.json') -Encoding UTF8
$record|ConvertTo-Json -Depth 12
if($failures.Count){throw 'Lifecycle acceptance has failed reports'}
