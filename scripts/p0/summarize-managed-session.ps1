param([Parameter(Mandatory)][ValidatePattern('^[0-9]{8}-[0-9]{6}-[a-f0-9]{6}$')][string]$BundleIdentifier)
$ErrorActionPreference='Stop'
$repository=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$bundle=Join-Path $repository ('.local\p0\sandbox\'+$BundleIdentifier)
$results=Join-Path $bundle 'results'
$summary=Get-Content -LiteralPath (Join-Path $results 'sandbox-summary.json') -Raw|ConvertFrom-Json
if($summary.state -ne 'complete'){throw 'Guest batch is not complete'}
$rows=@();$hashes=@();$failures=@()
foreach($name in @('managed-session-report.json','managed-chrome-report.json')){
 $path=Join-Path $results $name
 $report=Get-Content -LiteralPath $path -Raw|ConvertFrom-Json
 $items=if($report.cases){@($report.cases)}else{@($report)}
 $count=0;$failed=0
 foreach($item in $items){$count+=@($item.checks.psobject.Properties).Count;$failed+=@($item.checks.psobject.Properties|Where-Object Value -ne $true).Count;if($item.cleanup -ne 'verified'){$failed++}}
 if($failed -or -not $count){$failures+=$name}
 $rows+=@{report=$name;checks=$count;failedChecks=$failed;scope=$report.scope}
 $hashes+=@{path=$name;sha256=(Get-FileHash -LiteralPath $path).Hash}
}
if($summary.managedSessionChecks -ne 'passed' -or $summary.managedChromeChecks -ne 'passed' -or $summary.cleanup -ne 'verified' -or $summary.error){$failures+='guest-summary'}
$testedSource=Join-Path $bundle 'input\native\session\guardian.c'
$currentSource=Join-Path $repository 'native\session\guardian.c'
$nativeMatches=(Get-FileHash -LiteralPath $testedSource).Hash -eq (Get-FileHash -LiteralPath $currentSource).Hash
if(-not $nativeMatches){$failures+='guardian-source-changed'}
$sourceNames=@('native\session\guardian.c','native\session\inventory.c','app\proxy-harbor\internal\session\runtime.go','app\proxy-harbor\internal\session\platform_windows.go','app\proxy-harbor\internal\desktop\service.go','app\proxy-harbor\internal\desktop\sessions_native.go','app\proxy-harbor\internal\desktop\sessions_server.go','app\proxy-harbor\internal\engine\session_guardian_system_test.go','app\proxy-harbor\internal\engine\managed_chrome_system_test.go','app\proxy-harbor\cmd\session-fixture\main.go','app\proxy-harbor\frontend\src\Workspace.vue','scripts\build-guardian.ps1','scripts\p0\prepare-sandbox.ps1','native\p0\run-sandbox.ps1')
$sources=@($sourceNames|ForEach-Object {@{path=$_;sha256=(Get-FileHash -LiteralPath (Join-Path $repository $_)).Hash}})
$record=[ordered]@{schemaVersion=1;generatedAtUtc=[DateTimeOffset]::UtcNow.ToString('o');clientDate='2026-11-15';bundle=$BundleIdentifier;overall='not_accepted';desktopProtectionEnabled=$false;boundedSessionChecks=if($failures.Count){'failed'}else{'passed'};reports=$rows;failedReports=$failures;reportHashes=$hashes;sourceHashes=$sources;nativeSourceMatchesExecutedBundle=$nativeMatches;testedGuardianSHA256=(Get-FileHash -LiteralPath (Join-Path $bundle 'input\.local\p0\bin\proxy-harbor-guardian.exe')).Hash;guestSummary=$summary;boundaries=@('Unknown executable descendants are detected after creation; no inherited network identity proof for arbitrary children','Chrome headless fixed anonymous HTTPS workflows only; no complete Codex application acceptance','Proxy-only WFP path; guest transparent TUN exit probe timed out in earlier preserved runs; not declared passed','DNS/shared resolver and complete WebRTC behavior remain unverified','No host system policy experiments, automatic reboot, node credentials or Claude tests','Desktop admission is disabled under the replacement AGENTS instructions')}
$record|ConvertTo-Json -Depth 12|Set-Content -LiteralPath (Join-Path $repository '.local\p0\managed-session-validation.json') -Encoding UTF8
$record.reports|ForEach-Object {[pscustomobject]$_}|Format-Table report,checks,failedChecks
if($failures.Count){throw 'Managed session validation contains failures'}
