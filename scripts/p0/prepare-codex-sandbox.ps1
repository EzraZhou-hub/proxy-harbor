param([switch]$RealProxyBridge,[switch]$ManualLogin)
if($ManualLogin){$RealProxyBridge=$true}
$ErrorActionPreference = 'Stop'
$repositoryDirectory = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
# Only shipped program files. No user profile, login material or configuration.
$applicationDirectory = Join-Path $repositoryDirectory '.local\p0\sandbox\20261113-111504-81a4a8\input\codex-app'
foreach ($name in @('ChatGPT.exe','resources\app.asar','resources\codex.exe')) {
    if (-not (Test-Path -LiteralPath (Join-Path $applicationDirectory $name) -PathType Leaf)) { throw 'Expected Codex program version is absent.' }
}
$applicationFiles = @(Get-ChildItem -LiteralPath $applicationDirectory -Recurse -Force)
if (@($applicationFiles | Where-Object { $_.Attributes -band [IO.FileAttributes]::ReparsePoint }).Count) { throw 'Refusing to follow program reparse points.' }
$identifier = [DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss') + '-' + [guid]::NewGuid().ToString('N').Substring(0,6)
$bundleRoot = Join-Path $repositoryDirectory ('.local\p0\sandbox\' + $identifier)
$inputDirectory = Join-Path $bundleRoot 'input'
$resultDirectory = Join-Path $bundleRoot 'results'
New-Item -ItemType Directory -Path $inputDirectory,$resultDirectory | Out-Null
$copyLog = Join-Path $bundleRoot 'program-copy.log'
$archiveSource=Join-Path $repositoryDirectory '.local\p0\sandbox\20261113-135935-c591ae\input\codex-program.tar'
$archiveManifest=Get-Content -LiteralPath (Join-Path (Split-Path -Parent $archiveSource) 'manifest.json') -Raw|ConvertFrom-Json
$archiveDigest=($archiveManifest.files|Where-Object {$_.path -eq 'codex-program.tar'}).sha256
if((Get-FileHash -LiteralPath $archiveSource).Hash -ne $archiveDigest){throw 'Previously verified program archive changed.'}
Copy-Item -LiteralPath $archiveSource -Destination (Join-Path $inputDirectory 'codex-program.tar')
$files = [ordered]@{
    'run-sandbox.ps1' = (Join-Path $PSScriptRoot 'run-codex-sandbox.ps1')
    'scripts\p0\guest-codex.ps1' = (Join-Path $PSScriptRoot 'guest-codex.ps1')
    'scripts\p0\codex-proxy-observer.mjs' = (Join-Path $PSScriptRoot 'codex-proxy-observer.mjs')
    'scripts\p0\codex-file-bridge.mjs' = (Join-Path $PSScriptRoot 'codex-file-bridge.mjs')
    'scripts\p0\guest-codex-login.ps1' = (Join-Path $PSScriptRoot 'guest-codex-login.ps1')
    'scripts\p0\codex-callback-fixture.mjs' = (Join-Path $PSScriptRoot 'codex-callback-fixture.mjs')
    'node.exe' = 'D:\develop\Node\node.exe'
    'NODE-LICENSE.txt' = (Join-Path $repositoryDirectory 'native\p0\NODE-LICENSE.txt')
    '.local\p0\bin\proxy-harbor-p0-relay.exe' = (Join-Path $repositoryDirectory '.local\p0\bin\proxy-harbor-p0-relay.exe')
    '.local\p0\bin\p0-upstream-check.exe' = (Join-Path $repositoryDirectory '.local\p0\bin\p0-upstream-check.exe')
}
$build = Get-Content -LiteralPath (Join-Path $repositoryDirectory '.local\p0\transparent-build.json') -Raw | ConvertFrom-Json
if ($build.strictDnsSHA256 -ne (Get-FileHash -LiteralPath (Join-Path $repositoryDirectory 'native\p0\strict-dns.c')).Hash -or
    $build.buildScriptSHA256 -ne (Get-FileHash -LiteralPath (Join-Path $PSScriptRoot 'build-transparent.ps1')).Hash) { throw 'Transparent candidate build is stale.' }
foreach ($artifact in $build.files) {
    $source = Join-Path $repositoryDirectory ('.local\p0\bin\transparent\' + $artifact.name)
    if ((Get-FileHash -LiteralPath $source).Hash -ne $artifact.sha256) { throw 'Transparent candidate digest mismatch.' }
    $files['.local\p0\bin\transparent\' + $artifact.name] = $source
}
foreach ($name in @('PROXYCHAINS-COPYING.txt','MINHOOK-LICENSE.txt','UTHASH-LICENSE.txt')) {
    $files['.local\p0\bin\transparent\' + $name] = Join-Path $repositoryDirectory ('.local\p0\bin\transparent\' + $name)
}
foreach ($relative in $files.Keys) {
    $target = Join-Path $inputDirectory $relative
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $target) | Out-Null
    Copy-Item -LiteralPath $files[$relative] -Destination $target
}
$manifest = @(Get-ChildItem -LiteralPath $inputDirectory -File -Recurse | ForEach-Object {
    @{path=$_.FullName.Substring($inputDirectory.Length+1);sha256=(Get-FileHash -LiteralPath $_.FullName).Hash;bytes=$_.Length}
})
@{schemaVersion=1;manualLogin=[bool]$ManualLogin;realProxyBridge=[bool]$RealProxyBridge;scope='Codex program archive; fresh guest data; NIC disabled';sourcePackage='OpenAI.Codex_26.1106.6628.0_x64__2p2nqsd0c76g0';files=$manifest} |
    ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $inputDirectory 'manifest.json') -Encoding UTF8
$escapedInput = [Security.SecurityElement]::Escape($inputDirectory)
$escapedResults = [Security.SecurityElement]::Escape($resultDirectory)
@"
<Configuration>
  <Networking>Disable</Networking><vGPU>Disable</vGPU>
  <AudioInput>Disable</AudioInput><VideoInput>Disable</VideoInput>
  <PrinterRedirection>Disable</PrinterRedirection><ClipboardRedirection>Disable</ClipboardRedirection>
  <MemoryInMB>6144</MemoryInMB>
  <MappedFolders>
    <MappedFolder><HostFolder>$escapedInput</HostFolder><SandboxFolder>C:\P0Input</SandboxFolder><ReadOnly>true</ReadOnly></MappedFolder>
    <MappedFolder><HostFolder>$escapedResults</HostFolder><SandboxFolder>C:\P0Results</SandboxFolder><ReadOnly>false</ReadOnly></MappedFolder>
  </MappedFolders>
  <LogonCommand><Command>powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\P0Input\run-sandbox.ps1</Command></LogonCommand>
</Configuration>
"@ | Set-Content -LiteralPath (Join-Path $repositoryDirectory '.local\p0\proxy-harbor-p0.wsb') -Encoding UTF8
@{bundle=$bundleRoot;results=$resultDirectory;programFiles=@($applicationFiles|Where-Object {-not $_.PSIsContainer}).Count;totalFiles=$manifest.Count} | ConvertTo-Json
