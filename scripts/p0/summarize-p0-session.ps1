param([Parameter(Mandatory)][ValidatePattern('^[0-9]{8}-[0-9]{6}-[a-f0-9]{6}$')][string]$BundleIdentifier)
$ErrorActionPreference='Stop'
$repository=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$bundle=Join-Path $repository ('.local\p0\sandbox\'+$BundleIdentifier)
$results=Join-Path $bundle 'results'
$summary=Get-Content -LiteralPath (Join-Path $results 'sandbox-summary.json') -Raw|ConvertFrom-Json
$manifest=Get-Content -LiteralPath (Join-Path $bundle 'input\manifest.json') -Raw|ConvertFrom-Json
if($summary.state -ne 'complete' -or $summary.error -or $summary.cleanup -ne 'verified'){throw 'Guest batch or independent cleanup did not pass'}
foreach($field in @('protocolChecks','managedUserSessionChecks','userCapsuleChecks','capsuleChecks','managedRuntimeChecks','managedUserExitChecks','managedUserChromeChecks','capsuleBrowserChecks')){if($summary.$field -ne 'passed'){throw "Required suite not passed: $field"}}
$rows=@();$reportHashes=@()
$installer=@($manifest.files|Where-Object path -eq 'installer\chrome-enterprise64.msi')
$reports=@('managed-user-session-report.json','user-capsule-inheritance-report.json','capsule-inheritance-report.json','managed-runtime-report.json','managed-user-exit-report.json','managed-user-chrome-report.json','user-capsule-browser-report.json','session-cleanup-audit.json')
if($installer.Count -or $summary.managedWebRTCChecks){
 if($summary.managedWebRTCChecks -and $summary.managedWebRTCChecks -ne 'passed'){throw 'Chrome DNS and complete ICE suite did not pass'}
 $reports+='managed-webrtc-report.json'
}
if(@($manifest.files|Where-Object path -eq 'native\session\tcp_path.c').Count){
 if($summary.managedClientExitChecks -ne 'passed'){throw 'Desktop client fixed-exit suite did not pass'}
 $reports+='managed-client-exit-report.json'
}
foreach($name in $reports){
 $path=Join-Path $results $name
 $report=Get-Content -LiteralPath $path -Raw|ConvertFrom-Json
 $items=if($report.cases){@($report.cases)}else{@($report)}
 $count=0
 foreach($item in $items){
  $checks=@($item.checks.psobject.Properties)
  if(-not $checks.Count -or @($checks|Where-Object Value -ne $true).Count -or $item.cleanup -ne 'verified'){throw "Failed checks or cleanup in $name"}
  $count+=$checks.Count
 }
 if($name -in @('managed-user-exit-report.json','managed-client-exit-report.json','managed-webrtc-report.json') -and $report.guestCertificateRemoved -ne $true){throw 'Temporary guest certificate cleanup not verified'}
 $rows+=@{report=$name;checks=$count;failedChecks=0;scope=$report.scope}
 $reportHashes+=@{path=$name;sha256=(Get-FileHash -LiteralPath $path).Hash}
}
if($installer.Count){
 if($installer.Count -ne 1 -or $summary.installedChromeChecks -ne 'passed' -or -not $summary.installedChromeVersion -or $summary.chromeMsiSHA256 -ne $installer[0].sha256){throw 'Missing installed-Chrome result or package identity'}
 $runtime=Get-Content -LiteralPath (Join-Path $results 'managed-runtime-report.json') -Raw|ConvertFrom-Json
 $browser=Get-Content -LiteralPath (Join-Path $results 'managed-user-chrome-report.json') -Raw|ConvertFrom-Json
 $health=Get-Content -LiteralPath (Join-Path $results 'managed-user-exit-report.json') -Raw|ConvertFrom-Json
 $installedExe='C:\Program Files\Google\Chrome\Application\chrome.exe'
 if($runtime.testedExecutable -ne $installedExe -or $browser.normal_executable -ne $installedExe -or $browser.proxy_failure_executable -ne $installedExe){throw 'Real installed browser was not exercised'}
 foreach($key in @('original_chrome_survives','original_browser_has_different_sid','real_network_service_identified','real_renderer_identified','observed_chrome_descendants_share_session_sid','competing_recovery_preserves_live_session','unrelated_listener_rejected_by_desktop_discovery')){if($runtime.checks.$key -ne $true){throw "Missing installed Chrome proof: $key"}}
 foreach($key in @('wrong_initial_exit_rejects_without_launch','embedded_nul_rejects_without_launch','wrong_proxy_process_rejects_without_launch','reserved_address_rejects_without_launch','no_identity_recovery_is_idempotent')){if($health.checks.$key -ne $true){throw "Missing preflight proof: $key"}}
 $rtc=Get-Content -LiteralPath (Join-Path $results 'managed-webrtc-report.json') -Raw|ConvertFrom-Json
 if($summary.installedWebRTCChecks -ne 'passed' -or !$rtc.checks.managed_ice_contained -or !$rtc.checks.ordinary_chrome_sent_stun -or !$rtc.checks.no_stun_packet_from_managed_browser){throw 'Missing bounded ICE/STUN evidence'}
}
$snapshot=Get-Content -LiteralPath (Join-Path $bundle 'input\source-snapshot.json') -Raw|ConvertFrom-Json
$postValidationChanges=@()
foreach($source in $snapshot.files){
 $current=(Get-FileHash -LiteralPath (Join-Path $repository $source.path)).Hash
 if($current -ne $source.sha256){
  if($source.path -notin @('app\proxy-harbor\internal\desktop\sessions_native.go','app\proxy-harbor\internal\desktop\sessions_gate_test.go')){throw "Source changed since executed package: $($source.path)"}
  $postValidationChanges+=@{path=$source.path;executedSHA256=$source.sha256;currentSHA256=$current;reason='Desktop admission explicitly locked under replacement AGENTS; validation test tightened'}
 }
}
if((Get-Content -LiteralPath (Join-Path $repository 'app\proxy-harbor\internal\desktop\sessions_native.go') -Raw) -notmatch 'func nativeSessionsAllowed\(\) bool \{ return false \}'){throw 'Desktop admission must remain disabled'}
if((Get-Content -LiteralPath (Join-Path $repository 'app\proxy-harbor\internal\desktop\sessions_server.go') -Raw) -notmatch 'func nativeSessionsAllowed\(\) bool \{ return false \}'){throw 'Server admission must remain disabled'}
$approvalPath=Join-Path $repository 'app\proxy-harbor\internal\session\approved_guardian.json'
$approval=Get-Content -LiteralPath $approvalPath -Raw|ConvertFrom-Json
$tested=Join-Path $bundle 'input\.local\p0\bin\proxy-harbor-guardian.exe'
$testedSHA=(Get-FileHash -LiteralPath $tested).Hash
if($testedSHA -ne $approval.guardianSha256){throw 'Pinned helper differs from the executed native binary'}
$protocolLog=Get-Content -LiteralPath (Join-Path $results 'capsule-protocol-tests.log')
$protocolCount=@($protocolLog|Where-Object {$_ -match '^--- PASS:'}).Count
if(-not $protocolCount -or @($protocolLog|Where-Object {$_ -match '^--- FAIL:'}).Count){throw 'Protocol report is incomplete'}
if($approval.accepted -ne $false){throw 'Candidate fingerprint must not declare P0 accepted'}
$record=[ordered]@{schemaVersion=1;generatedAtUtc=[DateTimeOffset]::UtcNow.ToString('o');overall='not_accepted';desktopProtectionEnabled=$false;boundedCandidateChecks='passed';scope='Guest-only Windows x64 Chrome candidate: inherited user identity, independent blocking and termination; not desktop or complete P0 acceptance';bundle=$BundleIdentifier;protocolTopLevelTests=$protocolCount;reports=$rows;reportHashes=$reportHashes;testedGuardianSHA256=$testedSHA;sourceSnapshot=$snapshot;nativeAndRuntimeSourcesMatchExecutedBundle=$true;postValidationChanges=$postValidationChanges;guestSummary=$summary;boundaries=@('Replacement AGENTS explicitly keeps both desktop entry points disabled; not P1','Existing browser windows are outside the newly launched session','Temporary browser profile and its data are removed after stopping','Complete DNS/shared resolver and WebRTC behavior remain unverified; protected-process IPv6 and UDP are blocked','Other applications, external components and browser versions need separate compatibility validation','No host policy experiment, automatic reboot, Claude operation or node-credential access','Earliest startup and cross-reboot protection are outside the current first session scope')}
foreach($extra in @(@{key='buildValidation';path='.local\p0\session-build-validation.json'},@{key='hostCleanup';path='.local\p0\session-host-cleanup.json'})){
 $extraPath=Join-Path $repository $extra.path
 if(Test-Path -LiteralPath $extraPath){$record[$extra.key]=Get-Content -LiteralPath $extraPath -Raw|ConvertFrom-Json}
}
$record|ConvertTo-Json -Depth 18|Set-Content -LiteralPath (Join-Path $repository '.local\p0\p0-session-validation.json') -Encoding UTF8
$rows|ForEach-Object{[pscustomobject]$_}|Format-Table report,checks,failedChecks
Write-Output "Bounded guest candidate passed; P0 remains not_accepted and desktop disabled. Protocol top-level tests: $protocolCount"
