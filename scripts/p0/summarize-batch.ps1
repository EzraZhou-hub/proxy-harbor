param([Parameter(Mandatory)][ValidatePattern('^[0-9]{8}-[0-9]{6}-[a-f0-9]{6}$')][string]$BundleIdentifier)
$ErrorActionPreference='Stop'
$repository=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$bundle=Join-Path $repository ('.local\p0\sandbox\'+$BundleIdentifier)
$results=Join-Path $bundle 'results'
$summary=Get-Content -LiteralPath (Join-Path $results 'sandbox-summary.json') -Raw|ConvertFrom-Json
if($summary.state -ne 'complete'){throw 'Wait for the current batch to finish'}
$rows=@();$evidence=@()
foreach($name in @('relay-policy-report.json','transparent-policy-report.json','dns-coverage-report.json','dns-system-boundary-report.json','relay-port-report.json','udp-dualstack-report.json','public-network-report.json','isolated-kernel-report.json','wfp-isolated-kernel-report.json','dns-wfp-boundary-report.json','sid-policy-boundary-report.json','isolated-public\report.json')){
    $path=Join-Path $results $name
    if(-not (Test-Path -LiteralPath $path)){$rows+=@{report=$name;state='not_run'};continue}
    $report=Get-Content -LiteralPath $path -Raw|ConvertFrom-Json
    $items=if($report.cases){@($report.cases)}else{@($report)}
    $checks=0;$failed=0
    foreach($item in $items){if($item.checks){$checks+=@($item.checks.psobject.Properties).Count;$failed+=@($item.checks.psobject.Properties|Where-Object Value -ne $true).Count}}
    $rows+=@{report=$name;cases=$items.Count;checks=$checks;failedChecks=$failed;scope=$report.scope}
    $evidence+=@{path=$name;sha256=(Get-FileHash -LiteralPath $path).Hash}
}
$protocol=Get-Content -LiteralPath (Join-Path $results 'upstream-tests.log') -Raw
$required=@('protocolChecks','policyChecks','relayPolicyChecks','transparentChecks','dnsCoverageChecks','systemDNSBoundaryChecks','relayPortChecks','udpDualStackChecks','publicNetworkChecks','isolatedKernelChecks','wfpIsolationChecks','wfpDNSBoundaryChecks','sidBoundaryChecks','isolatedPublicChecks')
$failedPhases=@($required|Where-Object {$summary.$_ -ne 'passed'})
$sourceNames=@('native\p0\strict-dns.c','native\p0\strict-ipc.c','native\p0\dns_isolation_lab.c','native\p0\isolation_policy.c','native\p0\isolation_policy.h','native\p0\net_event_lab.c','native\p0\relay_port_guard.c','native\p0\run-sandbox.ps1','app\proxy-harbor\internal\engine\relay_proof.go','app\proxy-harbor\internal\engine\relay_proof_test.go','app\proxy-harbor\internal\engine\relay.go','app\proxy-harbor\internal\engine\upstream.go','app\proxy-harbor\internal\engine\dns_system_boundary_test.go','app\proxy-harbor\internal\engine\isolated_kernel_system_test.go','app\proxy-harbor\internal\engine\public_network_system_test.go','app\proxy-harbor\internal\engine\relay_port_system_test.go','app\proxy-harbor\internal\engine\udp_dualstack_system_test.go','app\proxy-harbor\internal\engine\sid_policy_system_test.go','app\proxy-harbor\internal\engine\batch_recovery_system_test.go','app\proxy-harbor\cmd\p0-probe\main.go','app\proxy-harbor\cmd\p0-probe\child.go','app\proxy-harbor\cmd\p0-probe\container_windows.go','app\proxy-harbor\cmd\p0-probe\mapped_windows.go','app\proxy-harbor\cmd\p0-probe\public.go','app\proxy-harbor\cmd\p0-probe\public_wire.go','app\proxy-harbor\cmd\p0-relay\main.go','scripts\p0\build-lab.ps1','scripts\p0\build-transparent.ps1','scripts\p0\prepare-sandbox.ps1','scripts\p0\sandbox-lab.ps1','scripts\p0\guest-batch-reboot.ps1','scripts\p0\guest-isolated-public.ps1','scripts\p0\invoke-batch-recovery.ps1','scripts\p0\start-batch-bridge.ps1','scripts\p0\stop-batch-bridge.ps1')
$sources=@($sourceNames|ForEach-Object {@{path=$_;sha256=(Get-FileHash -LiteralPath (Join-Path $repository $_)).Hash}})
$result=[ordered]@{
    schemaVersion=1;generatedAtUtc=[DateTimeOffset]::UtcNow.ToString('o');overall='not_accepted';desktopProtectionEnabled=$false
    bundle=$BundleIdentifier;scope='Windows 11 x64 fixed fixtures; existing IPv4 proxy, user-confirmed v2rayN global mode; IPv6 blocked, public IPv6 deferred'
    boundedBatchChecks=if($failedPhases.Count -eq 0 -and -not $summary.error){'passed'}else{'incomplete_or_failed'}
    failedPhases=$failedPhases;protocolTopLevelPasses=[regex]::Matches($protocol,'(?m)^--- PASS: [^/\s]+ \(').Count
    reports=$rows;reportHashes=$evidence;sourceHashes=$sources;guestSummary=$summary
    upstreamReference='global-mode-upstream-check-20261114.json'
    rebootEvidence=@{bundle='20261114-062459-aae4f3';scope='12 persistent parent/helper/port fixture rules only; no claim for later SID policy or earliest boot';checks=39}
    boundaries=@('No real Claude tests; no new account or node credentials','Actual application compatibility remains a later phase','Public IPv6 intentionally unverified; controlled IPv6 and mapped sockets are separate evidence','Earliest boot, complete network-change/sleep coverage and long-running production service lifecycle not verified','No host policy changes or driver load; only one explicitly authorized guest reboot')
}
$destination=Join-Path $repository '.local\p0\batch-validation.json'
$correctionPath=Join-Path $results 'metadata-correction.json'
if(Test-Path -LiteralPath $correctionPath){$result.metadataCorrection=Get-Content -LiteralPath $correctionPath -Raw|ConvertFrom-Json}
$result|ConvertTo-Json -Depth 15|Set-Content -LiteralPath $destination -Encoding UTF8
$result|ConvertTo-Json -Depth 15|Set-Content -LiteralPath (Join-Path $results 'batch-final-summary.json') -Encoding UTF8
[pscustomobject]@{report=$destination;boundedBatchChecks=$result.boundedBatchChecks;overall=$result.overall;protocolTests=$result.protocolTopLevelPasses;failedPhases=$failedPhases}|ConvertTo-Json -Depth 4
