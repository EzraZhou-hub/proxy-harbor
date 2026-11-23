param([string]$NodeExecutable = 'D:\develop\Node\node.exe', [switch]$IncludeTransparent, [switch]$TransparentOnly, [switch]$RebootChecks, [switch]$PublicChecks, [switch]$PublicNetwork, [string]$ExpectedProxyIPv4='', [switch]$IPv4Only, [switch]$LifecycleOnly, [switch]$SessionChecks, [switch]$ChromeSessionChecks, [switch]$CapsuleChecks, [switch]$InstalledChromeChecks)
$ErrorActionPreference = 'Stop'
if($InstalledChromeChecks -and (-not $ChromeSessionChecks -or -not $CapsuleChecks)){throw 'Installed Chrome validation requires the Chrome session capsule suite.'}
if($RebootChecks -and (-not $IncludeTransparent -or $TransparentOnly)){throw 'Reboot checks require the complete transparent package.'}
if ($TransparentOnly -and -not $IncludeTransparent) { throw 'TransparentOnly requires IncludeTransparent.' }
if($PublicChecks -and (-not $IncludeTransparent -or $RebootChecks)){throw 'Public checks require the transparent package and no automatic reboot.'}
if($LifecycleOnly -and ($RebootChecks -or $PublicChecks -or $TransparentOnly)){throw 'Lifecycle-only checks cannot include reboot, public endpoint or transparent-only checks.'}
if($SessionChecks -and ($RebootChecks -or $LifecycleOnly -or $TransparentOnly)){throw 'Session checks are an independent guest batch without reboot.'}
if($ChromeSessionChecks -and (-not $SessionChecks -or -not $PublicChecks -or -not $PublicNetwork)){throw 'Chrome session validation requires the explicit session and networked public test package'}
if($CapsuleChecks -and ($RebootChecks -or $TransparentOnly -or $LifecycleOnly)){throw 'Capsule batch cannot include automatic reboot or other exclusive batches'}
if($PublicNetwork -and ((-not $PublicChecks -and -not $LifecycleOnly) -or $TransparentOnly)){throw 'Network requires an explicit public or lifecycle test package.'}
if($IPv4Only -and -not $PublicNetwork){throw 'IPv4-only public validation requires the explicit networked test package.'}
if($ExpectedProxyIPv4){$expectedAddress=$null;if(-not $PublicChecks -or -not [Net.IPAddress]::TryParse($ExpectedProxyIPv4,[ref]$expectedAddress) -or $expectedAddress.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork -or $expectedAddress.Equals([Net.IPAddress]::Any) -or [Net.IPAddress]::IsLoopback($expectedAddress)){throw 'Expected proxy exit must be an explicitly supplied IPv4 with public checks.'}}
$repositoryDirectory = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
function Get-CodeSnapshot {
 $paths=@('app\proxy-harbor\go.mod','app\proxy-harbor\go.sum','scripts\build-guardian.ps1','scripts\p0\prepare-sandbox.ps1','scripts\p0\guest-session-audit.ps1')
 foreach($directory in @('app\proxy-harbor\internal','app\proxy-harbor\cmd','native\session','native\p0')){
  foreach($file in Get-ChildItem -LiteralPath (Join-Path $repositoryDirectory $directory) -Recurse -File){if($file.Extension -in @('.go','.c','.h','.ps1','.json')){$paths+=$file.FullName.Substring($repositoryDirectory.Length+1)}}
 }
 @($paths|Sort-Object -Unique|ForEach-Object{@{path=$_;sha256=(Get-FileHash -LiteralPath (Join-Path $repositoryDirectory $_)).Hash}})
}
$sourceSnapshot=@(Get-CodeSnapshot)
if($SessionChecks){
 $approval=Get-Content -LiteralPath (Join-Path $repositoryDirectory 'app\proxy-harbor\internal\session\approved_guardian.json') -Raw|ConvertFrom-Json
 if($approval.quarantined){throw 'The pinned session guardian is quarantined. Session packaging stopped.'}
 foreach($source in $approval.sourceHashes){if((Get-FileHash -LiteralPath (Join-Path $repositoryDirectory $source.path)).Hash -ne $source.sha256){throw 'Native source changed after the pinned build; rebuild and update the candidate record.'}}
 if((Get-FileHash -LiteralPath (Join-Path $repositoryDirectory 'app\proxy-harbor\bin\proxy-harbor-guardian.exe')).Hash -ne $approval.guardianSha256){throw 'Native binary does not match the pinned candidate.'}
}
$bundleIdentifier = [DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss') + '-' + [guid]::NewGuid().ToString('N').Substring(0,6)
$bundleDirectory = Join-Path $repositoryDirectory ".local\p0\sandbox\$bundleIdentifier\input"
$resultDirectory = Join-Path $repositoryDirectory ".local\p0\sandbox\$bundleIdentifier\results"
$binaryDirectory = Join-Path $repositoryDirectory '.local\p0\bin'
New-Item -ItemType Directory -Force -Path $bundleDirectory, $resultDirectory | Out-Null
$env:GOTMPDIR = Join-Path $repositoryDirectory '.cache\review-go-tmp'
$env:GOCACHE = Join-Path $repositoryDirectory '.cache\review-go-build'
Push-Location (Join-Path $repositoryDirectory 'app\proxy-harbor')
try {
    go test -c -tags p0integration -o (Join-Path $binaryDirectory 'p0-upstream-tests.exe') ./internal/engine
    if ($LASTEXITCODE -ne 0) { throw 'Standalone protocol test build failed.' }
    go test -c -tags p0system -o (Join-Path $binaryDirectory 'p0-policy-tests.exe') ./internal/engine
    if ($LASTEXITCODE -ne 0) { throw 'Guest-only relay policy test build failed.' }
    if($SessionChecks){go build -o (Join-Path $binaryDirectory 'session-fixture.exe') ./cmd/session-fixture;if($LASTEXITCODE -ne 0){throw 'Session fixture build failed'}}
} finally { Pop-Location }
$files = [ordered]@{
    'node.exe' = $NodeExecutable
    'NODE-LICENSE.txt' = (Join-Path $repositoryDirectory 'native\p0\NODE-LICENSE.txt')
    'run-sandbox.ps1' = (Join-Path $repositoryDirectory 'native\p0\run-sandbox.ps1')
    'native\p0\dns_isolation_lab.c' = (Join-Path $repositoryDirectory 'native\p0\dns_isolation_lab.c')
    'native\p0\relay_port_guard.c' = (Join-Path $repositoryDirectory 'native\p0\relay_port_guard.c')
    'native\p0\net_event_lab.c' = (Join-Path $repositoryDirectory 'native\p0\net_event_lab.c')
    'native\p0\isolation_policy.c' = (Join-Path $repositoryDirectory 'native\p0\isolation_policy.c')
    'native\p0\isolation_policy.h' = (Join-Path $repositoryDirectory 'native\p0\isolation_policy.h')
    'scripts\p0\build-lab.ps1' = (Join-Path $PSScriptRoot 'build-lab.ps1')
    'scripts\p0\policy-lab.mjs' = (Join-Path $PSScriptRoot 'policy-lab.mjs')
    'scripts\p0\guest-isolated-public.ps1' = (Join-Path $PSScriptRoot 'guest-isolated-public.ps1')
    'scripts\p0\codex-file-bridge.mjs' = (Join-Path $PSScriptRoot 'codex-file-bridge.mjs')
    '.local\p0\bin\p0-wfp.exe' = (Join-Path $binaryDirectory 'p0-wfp.exe')
    '.local\p0\bin\p0-relay-guard.exe' = (Join-Path $binaryDirectory 'p0-relay-guard.exe')
    '.local\p0\bin\proxy-harbor-p0-relay.exe' = (Join-Path $binaryDirectory 'proxy-harbor-p0-relay.exe')
    '.local\p0\bin\p0-policy-tests.exe' = (Join-Path $binaryDirectory 'p0-policy-tests.exe')
    '.local\p0\bin\p0-dns-isolation.exe' = (Join-Path $binaryDirectory 'p0-dns-isolation.exe')
    '.local\p0\bin\p0-port-guard.exe' = (Join-Path $binaryDirectory 'p0-port-guard.exe')
    '.local\p0\bin\p0-net-events.exe' = (Join-Path $binaryDirectory 'p0-net-events.exe')
    '.local\p0\bin\p0-isolation-inspect.exe' = (Join-Path $binaryDirectory 'p0-isolation-inspect.exe')
    '.local\p0\bin\proxy-harbor-p0-probe.exe' = (Join-Path $binaryDirectory 'proxy-harbor-p0-probe.exe')
    '.local\p0\bin\p0-upstream-tests.exe' = (Join-Path $binaryDirectory 'p0-upstream-tests.exe')
    '.local\p0\control\proxy-harbor-p0-probe.exe' = (Join-Path $repositoryDirectory '.local\p0\control\proxy-harbor-p0-probe.exe')
}
$files['.local\p0\bin\p0-helper-guard.exe'] = Join-Path $binaryDirectory 'p0-helper-guard.exe'
$files['.local\p0\bin\helpers\proxy-harbor-p0-helper.exe'] = Join-Path $binaryDirectory 'helpers\proxy-harbor-p0-helper.exe'
foreach($name in @('guest-recovery.ps1','guest-reboot.ps1','guest-batch-reboot.ps1','guest-session-audit.ps1')){$files['scripts\p0\'+$name]=Join-Path $PSScriptRoot $name}
$manifest = @()
if($CapsuleChecks){foreach($name in @('p0-capsule.exe','p0-user-capsule.exe','capsule-probe.exe')){$files['.local\p0\bin\'+$name]=Join-Path $binaryDirectory $name};foreach($source in @('capsule_lab.c','user_capsule_lab.c','user_policy.c','user_policy.h')){$files['native\p0\'+$source]=Join-Path $repositoryDirectory ('native\p0\'+$source)}}
if($SessionChecks){
    $files['.local\p0\bin\proxy-harbor-guardian.exe']=Join-Path $repositoryDirectory 'app\proxy-harbor\bin\proxy-harbor-guardian.exe'
    $files['.local\p0\bin\proxy-harbor-session-inventory.exe']=Join-Path $repositoryDirectory 'app\proxy-harbor\bin\proxy-harbor-session-inventory.exe'
    $files['.local\p0\bin\session-fixture.exe']=Join-Path $binaryDirectory 'session-fixture.exe'
    $files['.local\p0\control\session-fixture.exe']=Join-Path $binaryDirectory 'session-fixture.exe'
    $files['native\session\guardian.c']=Join-Path $repositoryDirectory 'native\session\guardian.c'
    foreach($name in @('account.c','account.h','tcp_path.c','tcp_path.h','system_dns.c','system_dns.h')){$files['native\session\'+$name]=Join-Path $repositoryDirectory ('native\session\'+$name)}
}
if($ChromeSessionChecks){
    if($InstalledChromeChecks){
        $msi=Join-Path $repositoryDirectory '.cache\p0\chrome-guest-enterprise64.msi'
        $signature=Get-AuthenticodeSignature -LiteralPath $msi
        if($signature.Status -ne 'Valid' -or $signature.SignerCertificate.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::SimpleName,$false) -ne 'Google LLC'){throw 'A valid Google LLC signed Chrome Enterprise MSI is required.'}
        $files['installer\chrome-enterprise64.msi']=$msi
    }
    $chrome='C:\Program Files\Google\Chrome\Application'
    foreach($file in Get-ChildItem -LiteralPath $chrome -Recurse -File){$relative=$file.FullName.Substring($chrome.Length+1);$files['chrome\'+$relative]=$file.FullName}
    $files['.local\p0\bin\sing-box.exe']='D:\Bufengruanj\v2rayN-windows-64\bin\sing_box\sing-box.exe'
    $files['.local\p0\bin\wintun.dll']='D:\Bufengruanj\v2rayN-windows-64\bin\xray\wintun.dll'
    $files['.local\p0\bin\proxy-harbor.exe']=Join-Path $binaryDirectory 'p0-policy-tests.exe'
}
if ($IncludeTransparent) {
    $buildRecord = Get-Content -LiteralPath (Join-Path $repositoryDirectory '.local\p0\transparent-build.json') -Raw | ConvertFrom-Json
    if ($buildRecord.strictDnsSHA256 -ne (Get-FileHash -LiteralPath (Join-Path $repositoryDirectory 'native\p0\strict-dns.c') -Algorithm SHA256).Hash -or
        $buildRecord.strictIpcSHA256 -ne (Get-FileHash -LiteralPath (Join-Path $repositoryDirectory 'native\p0\strict-ipc.c') -Algorithm SHA256).Hash -or
        $buildRecord.buildScriptSHA256 -ne (Get-FileHash -LiteralPath (Join-Path $PSScriptRoot 'build-transparent.ps1') -Algorithm SHA256).Hash) { throw 'Rebuild the transparent candidate: source or build script changed.' }
    foreach ($artifact in $buildRecord.files) {
        if ((Get-FileHash -LiteralPath (Join-Path $binaryDirectory ('transparent\' + $artifact.name)) -Algorithm SHA256).Hash -ne $artifact.sha256) { throw 'Transparent candidate binary changed after its build.' }
    }
    foreach ($name in @('proxychains_win32_x64.exe','proxychains_hook_x64.dll','proxychains_helper_win32_x64.exe','proxychains_helper_win32_x86.exe','PROXYCHAINS-COPYING.txt','MINHOOK-LICENSE.txt','UTHASH-LICENSE.txt')) {
        $files['.local\p0\bin\transparent\' + $name] = Join-Path $binaryDirectory ('transparent\' + $name)
    }
    foreach ($name in @('proxychains','minhook','uthash')) { $files['sources\' + $name + '.zip'] = Join-Path $repositoryDirectory ('.cache\p0\proxychains-sources\' + $name + '.zip') }
    foreach ($name in @('build-transparent.ps1','verify-transparent-source.mjs')) { $files['scripts\p0\' + $name] = Join-Path $PSScriptRoot $name }
    $files['.cache\p0\proxychains-source-manifest.json'] = Join-Path $repositoryDirectory '.cache\p0\proxychains-source-manifest.json'
    $files['docs\p0-transparent-lock.json'] = Join-Path $repositoryDirectory 'docs\p0-transparent-lock.json'
    $files['native\p0\strict-dns.c'] = Join-Path $repositoryDirectory 'native\p0\strict-dns.c'
    $files['native\p0\strict-ipc.c'] = Join-Path $repositoryDirectory 'native\p0\strict-ipc.c'
}
foreach ($relative in $files.Keys) {
    $target = Join-Path $bundleDirectory $relative
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $target) | Out-Null
    Copy-Item -LiteralPath $files[$relative] -Destination $target -Force
    $manifest += @{ path = $relative; sha256 = (Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash }
}
$snapshotPath=Join-Path $bundleDirectory 'source-snapshot.json'
@{schemaVersion=1;files=$sourceSnapshot}|ConvertTo-Json -Depth 5|Set-Content -LiteralPath $snapshotPath -Encoding UTF8
$manifest+=@{path='source-snapshot.json';sha256=(Get-FileHash -LiteralPath $snapshotPath).Hash}
$after=@(Get-CodeSnapshot)
if(($sourceSnapshot|ConvertTo-Json -Compress) -ne ($after|ConvertTo-Json -Compress)){throw 'Source changed during packaging; discard this unused package and retry.'}
@{ schemaVersion = 1; capsuleChecks=[bool]$CapsuleChecks; chromeSessionChecks=[bool]$ChromeSessionChecks; sessionChecks=[bool]$SessionChecks; lifecycleOnly=[bool]$LifecycleOnly; rebootChecks = [bool]$RebootChecks; transparentChecks = [bool]$IncludeTransparent; transparentOnly = [bool]$TransparentOnly; publicChecks=[bool]$PublicChecks;publicNetwork=[bool]$PublicNetwork;publicIPv4Only=[bool]$IPv4Only;expectedProxyIPv4=$ExpectedProxyIPv4;publicBridgeRound=[guid]::NewGuid().ToString('N').Substring(0,8); files = $manifest } | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $bundleDirectory 'manifest.json') -Encoding UTF8
$escapedBundle = [Security.SecurityElement]::Escape($bundleDirectory)
$escapedResults = [Security.SecurityElement]::Escape($resultDirectory)
$networking=if($PublicNetwork){'Enable'}else{'Disable'}
$configuration = @"
<Configuration>
  <Networking>$networking</Networking>
  <vGPU>Disable</vGPU>
  <AudioInput>Disable</AudioInput>
  <VideoInput>Disable</VideoInput>
  <PrinterRedirection>Disable</PrinterRedirection>
  <ClipboardRedirection>Disable</ClipboardRedirection>
  <MemoryInMB>4096</MemoryInMB>
  <MappedFolders>
    <MappedFolder><HostFolder>$escapedBundle</HostFolder><SandboxFolder>C:\P0Input</SandboxFolder><ReadOnly>true</ReadOnly></MappedFolder>
    <MappedFolder><HostFolder>$escapedResults</HostFolder><SandboxFolder>C:\P0Results</SandboxFolder><ReadOnly>false</ReadOnly></MappedFolder>
  </MappedFolders>
  <LogonCommand><Command>powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\P0Input\run-sandbox.ps1</Command></LogonCommand>
</Configuration>
"@
$configurationPath = Join-Path $repositoryDirectory '.local\p0\proxy-harbor-p0.wsb'
Set-Content -LiteralPath $configurationPath -Value $configuration -Encoding UTF8
Write-Output ("Prepared P0 test environment (guest networking {0}): {1}" -f $networking,$configurationPath)
Write-Output "Guest reports: $resultDirectory"
Write-Output 'Preparation only. No Windows feature was enabled and no policy was installed.'
