param([switch]$Elevated)
$ErrorActionPreference = 'Stop'
$outputDirectory = 'C:\P0Results'
$inputDirectory = 'C:\P0Input'
$workingDirectory = 'C:\P0Lab'
$writeSummary = $true
# Logon may run again after the explicitly authorized guest reboot.
if(Test-Path 'C:\P0Lab\.local\p0\reboot-pending.txt'){exit 0}
if(Test-Path 'C:\P0Lab\.local\p0\batch-reboot-pending.json'){exit 0}
function Invoke-GuestTool {
    param([string]$Executable, [string[]]$Arguments, [string]$LogName)
    # Windows PowerShell 5.1 can split unquoted dotted native arguments and
    # turn redirected stderr into terminating errors under ErrorAction Stop.
    # Start-Process preserves these fixed arguments and records both streams.
    $process = Start-Process -FilePath $Executable -ArgumentList $Arguments -WorkingDirectory $workingDirectory -WindowStyle Hidden -Wait -PassThru `
        -RedirectStandardOutput (Join-Path $outputDirectory ($LogName + '.log')) `
        -RedirectStandardError (Join-Path $outputDirectory ($LogName + '.stderr.log'))
    return $process.ExitCode
}
# These fixed paths exist only inside the disposable Windows guest. No host
# Windows configuration, user profile, or installed application is mapped in.
$summary = [ordered]@{
    schemaVersion = 1
    generatedAt = [DateTime]::UtcNow.ToString('o')
    overall = 'not_accepted'
    protocolChecks = 'not_run'
    policyChecks = 'not_run'
    relayPolicyChecks = 'not_run'
    relayCleanup = 'not_run'
    transparentChecks = 'not_run'
    transparentCleanup = 'not_run'
    dnsCoverageChecks = 'not_run'
    dnsCoverageCleanup = 'not_run'
    systemDNSBoundaryChecks = 'not_run'
    systemDNSBoundaryCleanup = 'not_run'
    relayPortChecks = 'not_run'
    relayPortCleanup = 'not_run'
    udpDualStackChecks = 'not_run'
    udpDualStackCleanup = 'not_run'
    isolatedKernelChecks = 'not_run'
    isolatedKernelCleanup = 'not_run'
    wfpIsolationChecks = 'not_run'
    wfpIsolationCleanup = 'not_run'
    wfpDNSBoundaryChecks = 'not_run'
    wfpDNSBoundaryCleanup = 'not_run'
    sidBoundaryChecks = 'not_run'
    sidBoundaryCleanup = 'not_run'
    isolatedPublicChecks = 'not_run'
    isolatedPublicCleanup = 'not_run'
    publicNetworkChecks = 'not_run'
    publicNetworkCleanup = 'not_run'
    cleanup = 'not_run'
    rebootChecks = 'not_run'
    rebootCleanup = 'not_run'
}
try {
    if (-not (Test-Path -LiteralPath $inputDirectory) -or -not (Test-Path -LiteralPath $outputDirectory)) {
        throw 'Required disposable guest mappings are absent. Do not run this script on the development host.'
    }
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        if ($Elevated) { throw 'Guest administrator authorization was not granted.' }
        Start-Process -FilePath 'powershell.exe' -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File C:\P0Input\run-sandbox.ps1 -Elevated' -Verb RunAs -WindowStyle Hidden
        $writeSummary = $false
        exit 0
    }
    $manifest = Get-Content -LiteralPath (Join-Path $inputDirectory 'manifest.json') -Raw | ConvertFrom-Json
    foreach ($entry in $manifest.files) {
        $file = [IO.Path]::GetFullPath((Join-Path $inputDirectory $entry.path))
        if (-not $file.StartsWith($inputDirectory + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'Invalid bundle manifest path.' }
        if ((Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash -ne $entry.sha256) { throw "Bundle checksum mismatch: $($entry.path)" }
    }
    New-Item -ItemType Directory -Force -Path $workingDirectory | Out-Null
    foreach ($entry in Get-ChildItem -LiteralPath $inputDirectory -Force) {
        Copy-Item -LiteralPath $entry.FullName -Destination $workingDirectory -Recurse -Force
    }
    Push-Location $workingDirectory
    try {
        $env:PROXY_HARBOR_P0_GUEST = 'offline-lab'
        if($manifest.capsuleChecks){
            $protocol=Invoke-GuestTool -Executable (Join-Path $workingDirectory '.local\p0\bin\p0-upstream-tests.exe') -Arguments @('-test.v','-test.timeout=90s') -LogName 'capsule-protocol-tests'
            $summary.protocolChecks=if($protocol -eq 0){'passed'}else{'failed'}
            if($protocol -ne 0){throw 'Protocol regression checks failed'}
            $managedUser=Invoke-GuestTool -Executable (Join-Path $workingDirectory '.local\p0\bin\p0-policy-tests.exe') -Arguments @('-test.v','-test.run=^TestManagedUserSessionGuardian$','-test.timeout=240s') -LogName 'managed-user-session-tests'
            if(Test-Path '.local\p0\managed-user-session-report.json'){Copy-Item -LiteralPath '.local\p0\managed-user-session-report.json' -Destination $outputDirectory -Force}
            $summary.managedUserSessionChecks=if($managedUser -eq 0){'passed'}else{'failed'}
            if($managedUser -ne 0){throw 'Managed user session combination failed'}
            $userCode=Invoke-GuestTool -Executable (Join-Path $workingDirectory '.local\p0\bin\p0-policy-tests.exe') -Arguments @('-test.v','-test.run=^TestP0UserCapsuleInheritance$','-test.timeout=150s') -LogName 'user-capsule-inheritance-tests'
            if(Test-Path '.local\p0\user-capsule-inheritance-report.json'){Copy-Item -LiteralPath '.local\p0\user-capsule-inheritance-report.json' -Destination $outputDirectory -Force}
            $summary.userCapsuleChecks=if($userCode -eq 0){'passed'}else{'failed'}
            if($userCode -ne 0){throw 'User inherited identity experiment failed'}
            $code=Invoke-GuestTool -Executable (Join-Path $workingDirectory '.local\p0\bin\p0-policy-tests.exe') -Arguments @('-test.v','-test.run=^TestP0CapsuleInheritance$','-test.timeout=150s') -LogName 'capsule-inheritance-tests'
            if(Test-Path '.local\p0\capsule-inheritance-report.json'){Copy-Item -LiteralPath '.local\p0\capsule-inheritance-report.json' -Destination $outputDirectory -Force}
            $summary.capsuleChecks=if($code -eq 0){'passed'}else{'failed'}
            $summary.cleanup=if($code -eq 0){'verified'}else{'not_verified'}
            if($code -ne 0){throw 'Inherited capsule identity tests failed'}
            if($manifest.chromeSessionChecks){
                $msi='C:\P0Lab\installer\chrome-enterprise64.msi'
                $browserExe='C:\Program Files\Google\Chrome\Application\chrome.exe'
                if(Test-Path -LiteralPath $msi){
                    if(Test-Path -LiteralPath $browserExe){throw 'Refusing to replace pre-existing Chrome'}
                    $setup=Start-Process msiexec.exe -ArgumentList @('/i',$msi,'/qn','/norestart','REBOOT=ReallySuppress','NOGOOGLEUPDATEPING=1','/log','C:\P0Results\chrome-install.log') -Wait -PassThru -WindowStyle Hidden
                    if($setup.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $browserExe)){throw "Guest-only Chrome install failed: $($setup.ExitCode)"}
                    $env:PH_GUEST_INSTALLED_CHROME='1'
                    $summary.installedChromeVersion=(Get-Item -LiteralPath $browserExe).VersionInfo.ProductVersion
                    $summary.chromeMsiSHA256=(Get-FileHash -LiteralPath $msi).Hash
                }
                $runtime=Invoke-GuestTool -Executable (Join-Path $workingDirectory '.local\p0\bin\proxy-harbor.exe') -Arguments @('-test.v','-test.run=^TestManagedRuntimeChromeWindow$','-test.timeout=150s') -LogName 'managed-runtime-tests'
                if(Test-Path '.local\p0\managed-runtime-report.json'){Copy-Item -LiteralPath '.local\p0\managed-runtime-report.json' -Destination $outputDirectory -Force}
                $summary.managedRuntimeChecks=if($runtime -eq 0){'passed'}else{'failed'}
                if($runtime -ne 0){throw 'Desktop runtime and visible Chrome window checks failed'}
                $exitProbe=Invoke-GuestTool -Executable (Join-Path $workingDirectory '.local\p0\bin\proxy-harbor.exe') -Arguments @('-test.v','-test.run=^TestManagedUserExitChange$','-test.timeout=150s') -LogName 'managed-user-exit-tests'
                if(Test-Path '.local\p0\managed-user-exit-report.json'){Copy-Item -LiteralPath '.local\p0\managed-user-exit-report.json' -Destination $outputDirectory -Force}
                $summary.managedUserExitChecks=if($exitProbe -eq 0){'passed'}else{'failed'}
                if($exitProbe -ne 0){throw 'Production health-probe TLS/exit-change checks failed'}
                $clientExit=Invoke-GuestTool -Executable (Join-Path $workingDirectory '.local\p0\bin\proxy-harbor.exe') -Arguments @('-test.v','-test.run=^TestManagedClientExitChange$','-test.timeout=150s') -LogName 'managed-client-exit-tests'
                if(Test-Path '.local\p0\managed-client-exit-report.json'){Copy-Item -LiteralPath '.local\p0\managed-client-exit-report.json' -Destination $outputDirectory -Force}
                $summary.managedClientExitChecks=if($clientExit -eq 0){'passed'}else{'failed'}
                if($clientExit -ne 0){throw 'Client fixed-exit and direct-connection checks failed'}
                $managedChrome=Invoke-GuestTool -Executable (Join-Path $workingDirectory '.local\p0\bin\proxy-harbor.exe') -Arguments @('-test.v','-test.run=^TestManagedUserChromeSession$','-test.timeout=240s') -LogName 'managed-user-chrome-tests'
                if(Test-Path '.local\p0\managed-user-chrome-report.json'){Copy-Item -LiteralPath '.local\p0\managed-user-chrome-report.json' -Destination $outputDirectory -Force}
                $summary.managedUserChromeChecks=if($managedChrome -eq 0){'passed'}else{'failed'}
                if($managedChrome -ne 0){throw 'Production user guardian Chrome combination failed'}
                $dnsLifecycle=Invoke-GuestTool -Executable (Join-Path $workingDirectory '.local\p0\bin\proxy-harbor.exe') -Arguments @('-test.v','-test.run=^TestManagedSystemDNSLifecycle$','-test.timeout=240s') -LogName 'managed-system-dns-tests'
                if(Test-Path '.local\p0\managed-system-dns-report.json'){Copy-Item -LiteralPath '.local\p0\managed-system-dns-report.json' -Destination $outputDirectory -Force}
                $summary.managedSystemDNSChecks=if($dnsLifecycle -eq 0){'passed'}else{'failed'}
                if($dnsLifecycle -ne 0){throw 'System DNS session restriction and recovery checks failed'}
                if($env:PH_GUEST_INSTALLED_CHROME -ne '1'){
                    $rtc=Invoke-GuestTool -Executable (Join-Path $workingDirectory '.local\p0\bin\proxy-harbor.exe') -Arguments @('-test.v','-test.run=^TestChromeWebRTCPrivacy$','-test.timeout=150s') -LogName 'managed-webrtc-tests'
                    if(Test-Path '.local\p0\managed-webrtc-report.json'){Copy-Item -LiteralPath '.local\p0\managed-webrtc-report.json' -Destination $outputDirectory -Force}
                    $summary.managedWebRTCChecks=if($rtc -eq 0){'passed'}else{'failed'}
                    if($rtc -ne 0){throw 'Chrome DNS and complete ICE privacy checks failed'}
                }
                $browser=Invoke-GuestTool -Executable (Join-Path $workingDirectory '.local\p0\bin\p0-policy-tests.exe') -Arguments @('-test.v','-test.run=^TestP0UserCapsuleBrowser$','-test.timeout=180s') -LogName 'user-capsule-browser-tests'
                if(Test-Path '.local\p0\user-capsule-browser-report.json'){Copy-Item -LiteralPath '.local\p0\user-capsule-browser-report.json' -Destination $outputDirectory -Force}
                $summary.capsuleBrowserChecks=if($browser -eq 0){'passed'}else{'failed'}
                if($browser -ne 0){$summary.cleanup='not_verified';throw 'Dedicated-user browser combination failed'}
                if($env:PH_GUEST_INSTALLED_CHROME -eq '1'){
                    $rtc=Invoke-GuestTool -Executable (Join-Path $workingDirectory '.local\p0\bin\proxy-harbor.exe') -Arguments @('-test.v','-test.run=^TestInstalledChromeWebRTC$','-test.timeout=150s') -LogName 'managed-webrtc-tests'
                    if(Test-Path '.local\p0\managed-webrtc-report.json'){Copy-Item -LiteralPath '.local\p0\managed-webrtc-report.json' -Destination $outputDirectory -Force}
                    $summary.installedWebRTCChecks=if($rtc -eq 0){'passed'}else{'failed'}
                    if($rtc -ne 0){throw 'Installed Chrome ICE and STUN tests failed'}
                    $uninstall=Start-Process msiexec.exe -ArgumentList @('/x',$msi,'/qn','/norestart','REBOOT=ReallySuppress','/log','C:\P0Results\chrome-uninstall.log') -Wait -PassThru -WindowStyle Hidden
                    if($uninstall.ExitCode -ne 0 -or (Test-Path -LiteralPath $browserExe)){throw "Guest-only Chrome uninstall failed: $($uninstall.ExitCode)"}
                    $summary.installedChromeChecks='passed'
                }
            }
            & 'C:\P0Lab\scripts\p0\guest-session-audit.ps1'
            $summary.cleanup='verified'
            return
        }
        if($manifest.sessionChecks){
            $code=Invoke-GuestTool -Executable (Join-Path $workingDirectory '.local\p0\bin\p0-policy-tests.exe') -Arguments @('-test.v','-test.run=^TestManagedSessionGuardian$','-test.timeout=300s') -LogName 'managed-session-tests'
            Copy-Item -LiteralPath '.local\p0\managed-session-report.json' -Destination $outputDirectory -Force
            $summary.managedSessionChecks=if($code -eq 0){'passed'}else{'failed'}
            $summary.cleanup=if($code -eq 0){'verified'}else{'not_verified'}
            if($code -ne 0){throw 'Managed session guardian tests failed'}
            if($manifest.chromeSessionChecks){
                $chrome=Invoke-GuestTool -Executable (Join-Path $workingDirectory '.local\p0\bin\proxy-harbor.exe') -Arguments @('-test.v','-test.run=^TestManagedChromeSession$','-test.timeout=240s') -LogName 'managed-chrome-tests'
                if(Test-Path '.local\p0\managed-chrome-report.json'){Copy-Item -LiteralPath '.local\p0\managed-chrome-report.json' -Destination $outputDirectory -Force}
                $summary.managedChromeChecks=if($chrome -eq 0){'passed'}else{'failed'}
                if($chrome -ne 0){$summary.cleanup='not_verified';throw 'Managed real Chrome test failed'}
            }
            return
        }
        if($manifest.lifecycleOnly){
            $code=Invoke-GuestTool -Executable (Join-Path $workingDirectory '.local\p0\bin\p0-policy-tests.exe') -Arguments @('-test.v','-test.run=^TestP0SIDLifecycle$','-test.timeout=300s') -LogName 'sid-lifecycle-tests'
            Copy-Item -LiteralPath '.local\p0\sid-lifecycle-report.json' -Destination $outputDirectory -Force
            if(Test-Path '.local\p0\lifecycle-acl-baseline.json'){Copy-Item -LiteralPath '.local\p0\lifecycle-acl-baseline.json' -Destination $outputDirectory -Force}
            $report=Get-Content '.local\p0\sid-lifecycle-report.json' -Raw|ConvertFrom-Json
            $summary.lifecycleChecks=if($code -eq 0){'passed'}else{'failed'}
            $summary.cleanup=$report.cleanup
            if($code -ne 0 -or $report.cleanup -ne 'verified'){throw 'SID lifecycle checks or cleanup failed.'}
            if($manifest.transparentChecks){
                $regression=Invoke-GuestTool -Executable (Join-Path $workingDirectory '.local\p0\bin\p0-policy-tests.exe') -Arguments @('-test.v','-test.run=^TestP0(WFPIsolatedKernel|WFPDNSBoundary|SIDPolicyUnlistedComponent)$','-test.timeout=240s') -LogName 'sid-lifecycle-regression'
                foreach($name in @('wfp-isolated-kernel-report.json','dns-wfp-boundary-report.json','sid-policy-boundary-report.json')){if(Test-Path (Join-Path '.local\p0' $name)){Copy-Item -LiteralPath (Join-Path '.local\p0' $name) -Destination $outputDirectory -Force}}
                $summary.lifecycleRegressionChecks=if($regression -eq 0){'passed'}else{'failed'}
                if($regression -ne 0){throw 'Existing SID/DNS/transparent regression failed.'}
            }
            return
        }
        if($manifest.publicNetwork){
            $routes=@(Get-NetRoute -AddressFamily IPv6 -ErrorAction Stop)
            @{osVersion=[Environment]::OSVersion.VersionString;networkEnabled=$true;ipv6RouteQuerySucceeded=$true;ipv6DefaultRouteCount=@($routes|Where-Object DestinationPrefix -eq '::/0').Count}|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $outputDirectory 'guest-network-context.json') -Encoding UTF8
        }
        if (-not $manifest.transparentOnly) {
        $protocolExit = Invoke-GuestTool -Executable (Join-Path $workingDirectory '.local\p0\bin\p0-upstream-tests.exe') -Arguments @('-test.v', '-test.timeout=90s') -LogName 'upstream-tests'
        $summary.protocolChecks = if ($protocolExit -eq 0) { 'passed' } else { 'failed' }
        if ($protocolExit -ne 0) { throw 'Guest upstream transport checks failed.' }
        $policyExit = Invoke-GuestTool -Executable (Join-Path $workingDirectory 'node.exe') -Arguments @('scripts\p0\policy-lab.mjs', '--apply') -LogName 'policy-console'
        $policyReport = Get-Content -LiteralPath '.\.local\p0\policy-report.json' -Raw | ConvertFrom-Json
        $summary.policyChecks = if ($policyExit -eq 0 -and -not $policyReport.error) { 'passed' } else { 'failed' }
        $summary.cleanup = $policyReport.cleanup
        Copy-Item -LiteralPath '.\.local\p0\policy-report.json' -Destination $outputDirectory -Force
        if (Test-Path -LiteralPath '.\.local\p0\recovery.json') { Copy-Item -LiteralPath '.\.local\p0\recovery.json' -Destination $outputDirectory -Force }
        if ($policyExit -ne 0 -or $policyReport.cleanup -ne 'verified') { throw 'Guest policy tests or cleanup did not pass. See the report.' }
        $env:PROXY_HARBOR_P0_GUEST = 'offline-lab'
        $relayExit = Invoke-GuestTool -Executable (Join-Path $workingDirectory '.local\p0\bin\p0-policy-tests.exe') -Arguments @('-test.v', '-test.run=^TestP0PersistentRelayGuard$', '-test.timeout=180s') -LogName 'relay-policy-tests'
        $summary.relayPolicyChecks = if ($relayExit -eq 0) { 'passed' } else { 'failed' }
        if (Test-Path -LiteralPath '.\.local\p0\relay-policy-report.json') {
            $relayReport = Get-Content -LiteralPath '.\.local\p0\relay-policy-report.json' -Raw | ConvertFrom-Json
            $summary.relayCleanup = if (@($relayReport.cases | Where-Object { $_.cleanup -ne 'verified' }).Count -eq 0) { 'verified' } else { 'failed' }
            Copy-Item -LiteralPath '.\.local\p0\relay-policy-report.json' -Destination $outputDirectory -Force
        }
        if (Test-Path -LiteralPath '.\.local\p0\relay-recovery.json') { Copy-Item -LiteralPath '.\.local\p0\relay-recovery.json' -Destination $outputDirectory -Force }
        if ($relayExit -ne 0 -or $summary.relayCleanup -ne 'verified') { throw 'Guest relay policy tests or cleanup did not pass. See the report.' }
        $portExit = Invoke-GuestTool -Executable (Join-Path $workingDirectory '.local\p0\bin\p0-policy-tests.exe') -Arguments @('-test.v', '-test.run=^TestP0RelayPortOwnership$', '-test.timeout=90s') -LogName 'relay-port-tests'
        $summary.relayPortChecks = if ($portExit -eq 0) { 'passed' } else {'failed'}
        if (Test-Path -LiteralPath '.\.local\p0\relay-port-report.json') {
            $portReport = Get-Content -LiteralPath '.\.local\p0\relay-port-report.json' -Raw | ConvertFrom-Json
            $summary.relayPortCleanup = $portReport.cleanup
            Copy-Item -LiteralPath '.\.local\p0\relay-port-report.json' -Destination $outputDirectory -Force
        }
        if ($portExit -ne 0 -or $summary.relayPortCleanup -ne 'verified') { throw 'Guest relay port reservation tests or cleanup failed.' }
        $udpExit = Invoke-GuestTool -Executable (Join-Path $workingDirectory '.local\p0\bin\p0-policy-tests.exe') -Arguments @('-test.v', '-test.run=^TestP0UDPAndDualStack$', '-test.timeout=120s') -LogName 'udp-dualstack-tests'
        $summary.udpDualStackChecks = if($udpExit -eq 0){'passed'}else{'failed'}
        if(Test-Path -LiteralPath '.\.local\p0\udp-dualstack-report.json') {
            $udpReport = Get-Content -LiteralPath '.\.local\p0\udp-dualstack-report.json' -Raw|ConvertFrom-Json
            $summary.udpDualStackCleanup = $udpReport.cleanup
            Copy-Item -LiteralPath '.\.local\p0\udp-dualstack-report.json' -Destination $outputDirectory -Force
        }
        if($udpExit -ne 0 -or $summary.udpDualStackCleanup -ne 'verified'){throw 'Guest UDP and mapped dual-stack observations or cleanup failed.'}
        if($manifest.publicNetwork){
            $networkExit=Invoke-GuestTool -Executable (Join-Path $workingDirectory '.local\p0\bin\p0-policy-tests.exe') -Arguments @('-test.v','-test.run=^TestP0PublicNetworkGuard$','-test.timeout=120s') -LogName 'public-network-tests'
            $networkReport=Get-Content -LiteralPath '.\.local\p0\public-network-report.json' -Raw|ConvertFrom-Json
            $summary.publicNetworkChecks=if($networkExit -ne 0){'failed'}elseif($networkReport.allBaselinesAvailable){'passed'}else{'not_verified_missing_baselines'}
            $summary.publicNetworkCleanup=$networkReport.cleanup
            Copy-Item -LiteralPath '.\.local\p0\public-network-report.json' -Destination $outputDirectory -Force
            if($networkExit -ne 0 -or $summary.publicNetworkCleanup -notin @('verified','not_needed')){throw 'Public network observations or cleanup failed.'}
        }
        }
        if ($manifest.transparentChecks) {
            $transparentExit = Invoke-GuestTool -Executable (Join-Path $workingDirectory '.local\p0\bin\p0-policy-tests.exe') -Arguments @('-test.v', '-test.run=^TestP0TransparentInterception$', '-test.timeout=180s') -LogName 'transparent-policy-tests'
            $summary.transparentChecks = if ($transparentExit -eq 0) { 'passed' } else { 'failed' }
            if (Test-Path -LiteralPath '.\.local\p0\transparent-policy-report.json') {
                $transparentReport = Get-Content -LiteralPath '.\.local\p0\transparent-policy-report.json' -Raw | ConvertFrom-Json
                $summary.transparentCleanup = if ($transparentReport.cases.Count -eq 6 -and @($transparentReport.cases | Where-Object { $_.cleanup -ne 'verified' }).Count -eq 0) { 'verified' } else { 'failed' }
                Copy-Item -LiteralPath '.\.local\p0\transparent-policy-report.json' -Destination $outputDirectory -Force
            }
            if ($transparentExit -ne 0 -or $summary.transparentCleanup -ne 'verified') { throw 'Guest transparent interception or cleanup checks failed. See the report.' }
            $dnsExit = Invoke-GuestTool -Executable (Join-Path $workingDirectory '.local\p0\bin\p0-policy-tests.exe') -Arguments @('-test.v', '-test.run=^TestP0DNSCoverage$', '-test.timeout=120s') -LogName 'dns-coverage-tests'
            $summary.dnsCoverageChecks = if ($dnsExit -eq 0) { 'passed' } else { 'failed' }
            if (Test-Path -LiteralPath '.\.local\p0\dns-coverage-report.json') {
                $dnsReport = Get-Content -LiteralPath '.\.local\p0\dns-coverage-report.json' -Raw | ConvertFrom-Json
                $summary.dnsCoverageCleanup = $dnsReport.cleanup
                Copy-Item -LiteralPath '.\.local\p0\dns-coverage-report.json' -Destination $outputDirectory -Force
            }
            if ($dnsExit -ne 0 -or $summary.dnsCoverageCleanup -ne 'verified') { throw 'Guest DNS audit or policy cleanup failed. See the report.' }
            $boundaryExit = Invoke-GuestTool -Executable (Join-Path $workingDirectory '.local\p0\bin\p0-policy-tests.exe') -Arguments @('-test.v', '-test.run=^TestP0SystemDNSBoundary$', '-test.timeout=180s') -LogName 'dns-system-boundary-tests'
            $summary.systemDNSBoundaryChecks = if ($boundaryExit -eq 0) { 'passed' } else { 'failed' }
            if (Test-Path -LiteralPath '.\.local\p0\dns-system-boundary-report.json') {
                $boundaryReport = Get-Content -LiteralPath '.\.local\p0\dns-system-boundary-report.json' -Raw | ConvertFrom-Json
                $summary.systemDNSBoundaryCleanup = if ($boundaryReport.cleanup -eq 'verified' -and $boundaryReport.nrptCleanup -eq 'verified') {'verified'} else {'failed'}
                Copy-Item -LiteralPath '.\.local\p0\dns-system-boundary-report.json' -Destination $outputDirectory -Force
            }
            if ($boundaryExit -ne 0 -or $summary.systemDNSBoundaryCleanup -ne 'verified') { throw 'Default DNS boundary experiment did not pass. See its independent report.' }
            $isolatedExit = Invoke-GuestTool -Executable (Join-Path $workingDirectory '.local\p0\bin\p0-policy-tests.exe') -Arguments @('-test.v', '-test.run=^TestP0IsolatedTransparentKernel$', '-test.timeout=180s') -LogName 'isolated-kernel-tests'
            $summary.isolatedKernelChecks = if($isolatedExit -eq 0){'passed'}else{'failed'}
            if(Test-Path -LiteralPath '.\.local\p0\isolated-kernel-report.json') {
                $isolatedReport = Get-Content -LiteralPath '.\.local\p0\isolated-kernel-report.json' -Raw|ConvertFrom-Json
                $summary.isolatedKernelCleanup = if($isolatedReport.cases.Count -eq 6 -and @($isolatedReport.cases|Where-Object {$_.cleanup -ne 'verified'}).Count -eq 0){'verified'}else{'failed'}
                Copy-Item -LiteralPath '.\.local\p0\isolated-kernel-report.json' -Destination $outputDirectory -Force
            }
            if($isolatedExit -ne 0 -or $summary.isolatedKernelCleanup -ne 'verified'){throw 'Combined AppContainer/transparent kernel experiment did not pass.'}
            $wfpExit=Invoke-GuestTool -Executable (Join-Path $workingDirectory '.local\p0\bin\p0-policy-tests.exe') -Arguments @('-test.v','-test.run=^TestP0WFPIsolatedKernel$','-test.timeout=180s') -LogName 'wfp-isolated-kernel-tests'
            $summary.wfpIsolationChecks=if($wfpExit -eq 0){'passed'}else{'failed'}
            $wfpReport=Get-Content -LiteralPath '.\.local\p0\wfp-isolated-kernel-report.json' -Raw|ConvertFrom-Json
            $summary.wfpIsolationCleanup=if($wfpReport.cases.Count -eq 6 -and @($wfpReport.cases|Where-Object {$_.cleanup -ne 'verified'}).Count -eq 0){'verified'}else{'failed'}
            Copy-Item -LiteralPath '.\.local\p0\wfp-isolated-kernel-report.json' -Destination $outputDirectory -Force
            if($wfpExit -ne 0 -or $summary.wfpIsolationCleanup -ne 'verified'){throw 'Scoped WFP AppContainer policy experiment did not pass.'}
            $wfpDNSExit=Invoke-GuestTool -Executable (Join-Path $workingDirectory '.local\p0\bin\p0-policy-tests.exe') -Arguments @('-test.v','-test.run=^TestP0WFPDNSBoundary$','-test.timeout=180s') -LogName 'dns-wfp-boundary-tests'
            $wfpDNSReport=Get-Content -LiteralPath '.\.local\p0\dns-wfp-boundary-report.json' -Raw|ConvertFrom-Json
            $summary.wfpDNSBoundaryChecks=if($wfpDNSExit -eq 0){'passed'}else{'failed'}
            $summary.wfpDNSBoundaryCleanup=if($wfpDNSReport.cleanup -eq 'verified' -and $wfpDNSReport.nrptCleanup -eq 'verified'){'verified'}else{'failed'}
            Copy-Item -LiteralPath '.\.local\p0\dns-wfp-boundary-report.json' -Destination $outputDirectory -Force
            if($wfpDNSExit -ne 0 -or $summary.wfpDNSBoundaryCleanup -ne 'verified'){throw 'Scoped SID policy DNS boundary observations did not pass.'}
            $sidExit=Invoke-GuestTool -Executable (Join-Path $workingDirectory '.local\p0\bin\p0-policy-tests.exe') -Arguments @('-test.v','-test.run=^TestP0SIDPolicyUnlistedComponent$','-test.timeout=90s') -LogName 'sid-policy-boundary-tests'
            $sidReport=Get-Content -LiteralPath '.\.local\p0\sid-policy-boundary-report.json' -Raw|ConvertFrom-Json
            $summary.sidBoundaryChecks=if($sidExit -eq 0){'passed'}else{'failed'};$summary.sidBoundaryCleanup=$sidReport.cleanup
            Copy-Item -LiteralPath '.\.local\p0\sid-policy-boundary-report.json' -Destination $outputDirectory -Force
            if($sidExit -ne 0 -or $summary.sidBoundaryCleanup -ne 'verified'){throw 'Unlisted component SID restriction tests did not pass.'}
        }
        if($manifest.publicChecks) {
            & 'C:\P0Lab\scripts\p0\guest-isolated-public.ps1' -BridgeRound $manifest.publicBridgeRound -ExpectedProxyIPv4 $manifest.expectedProxyIPv4
            $publicReport=Get-Content -LiteralPath 'C:\P0Results\isolated-public\report.json' -Raw|ConvertFrom-Json
            $summary.isolatedPublicChecks=$publicReport.boundedPublicChecks;$summary.isolatedPublicCleanup=$publicReport.cleanup
            if($summary.isolatedPublicChecks -ne 'passed' -or $summary.isolatedPublicCleanup -ne 'verified'){throw 'Isolated public HTTPS validation or cleanup failed.'}
        }
        if($manifest.rebootChecks) {
            $summary.state='awaiting_guest_restart'
            $summary.rebootChecks='pending';$summary.rebootCleanup='pending'
            $summary|ConvertTo-Json -Depth 8|Set-Content -LiteralPath (Join-Path $outputDirectory 'sandbox-summary.json') -Encoding UTF8
            $writeSummary=$false
            try { & 'C:\P0Lab\scripts\p0\guest-reboot.ps1' } catch {$writeSummary=$true;throw}
        }
    } finally { Pop-Location }
} catch {
    $summary.error = $_.Exception.Message
    if($manifest -and $manifest.capsuleChecks){$summary.cleanup='not_verified'}
} finally {
    if ($writeSummary -and (Test-Path -LiteralPath $outputDirectory)) {
        $summary.state = 'complete'
        $summary | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $outputDirectory 'sandbox-summary.json') -Encoding UTF8
    }
}
