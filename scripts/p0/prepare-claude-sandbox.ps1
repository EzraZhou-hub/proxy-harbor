param(
    [Parameter(Mandatory)][string]$Package,
    [Parameter(Mandatory)][string]$ExpectedProxyIPv4,
    [ValidateSet('installed','provisioned','app-files')][string]$Layout = 'installed',
    [ValidateSet('lifecycle','guardian-crash','complete','tun')][string]$Scenarios = 'lifecycle',
    [switch]$MSIXCandidate,
    [string]$DesktopGuardian,
    [ValidatePattern('^\d{8}-\d{6}-[a-f0-9]{6}$')][string]$GuardianBundle,
    [string]$VcVars = 'D:\develop\vs2022\Community\VC\Auxiliary\Build\vcvars64.bat'
)
$ErrorActionPreference = 'Stop'
if ($DesktopGuardian -and ($MSIXCandidate -or $GuardianBundle -or $Layout -ne 'installed')) {
    throw 'A desktop guardian must be verified independently against an installed MSIX'
}
if ($DesktopGuardian) { $MSIXCandidate = $true }
if ($Scenarios -ne 'lifecycle' -and (-not $MSIXCandidate -or $Layout -ne 'installed')) {
    throw 'Guardian crash scenarios require the installed MSIX candidate'
}
if ($GuardianBundle -and -not $MSIXCandidate) { throw 'A frozen bundle requires the MSIX candidate' }
$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$packagePath = (Resolve-Path -LiteralPath $Package).Path
$staging = (Join-Path $repo '.cache\p0') + '\'
if (-not $packagePath.StartsWith($staging, [StringComparison]::OrdinalIgnoreCase) -or
    [IO.Path]::GetExtension($packagePath) -ne '.msix' -or (Get-Item -LiteralPath $packagePath).Length -lt 1MB) {
    throw 'A complete official MSIX staged in the project test directory is required'
}
$address = [Net.IPAddress]::Parse($ExpectedProxyIPv4)
if ($address.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork -or $address.ToString() -ne $ExpectedProxyIPv4) {
    throw 'Expected a canonical IPv4 address'
}
$pin = Get-Content (Join-Path $repo 'app\proxy-harbor\internal\session\approved_guardian.json') -Raw | ConvertFrom-Json
$guardian = Join-Path $repo 'app\proxy-harbor\bin\proxy-harbor-guardian.exe'
if ($pin.quarantined) { throw 'Guardian candidate is quarantined' }
if (-not $MSIXCandidate) {
    if ((Get-FileHash -LiteralPath $guardian).Hash -ne $pin.guardianSha256) { throw 'Pinned guardian mismatch' }
    foreach ($source in $pin.sourceHashes) {
        if ((Get-FileHash -LiteralPath (Join-Path $repo $source.path)).Hash -ne $source.sha256) { throw 'Pinned source mismatch' }
    }
}
$id = [DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss') + '-' + [guid]::NewGuid().ToString('N').Substring(0, 6)
$bundle = Join-Path $repo ".local\p0\sandbox\$id"
$inputPath = Join-Path $bundle 'input'
$results = Join-Path $bundle 'results'
New-Item -ItemType Directory -Path $inputPath,$results | Out-Null
if ($DesktopGuardian) {
    $guardian = (Resolve-Path -LiteralPath $DesktopGuardian).Path
    $desktopBins = (Join-Path $repo 'app\proxy-harbor\bin') + '\'
    if (-not $guardian.StartsWith($desktopBins, [StringComparison]::OrdinalIgnoreCase) -or
        [IO.Path]::GetFileName($guardian) -ne 'proxy-harbor-guardian.exe') {
        throw 'Choose a desktop guardian from the project output directory'
    }
} elseif ($GuardianBundle) {
    $previous = Join-Path $repo ".local\p0\sandbox\$GuardianBundle"
    $prior = Get-Content (Join-Path $previous 'results\claude-validation.json') -Raw -Encoding UTF8 | ConvertFrom-Json
    $guardian = Join-Path $previous 'input\guardian.exe'
    if (-not $prior.msixCandidate -or (Get-FileHash -LiteralPath $guardian).Hash -ne $prior.guardianSha256) {
        throw 'MSIX candidate digest mismatch'
    }
    Copy-Item -LiteralPath (Join-Path $previous 'guardian-sources.json') -Destination (Join-Path $bundle 'guardian-sources.json')
} elseif ($MSIXCandidate) {
    $build = Join-Path $bundle 'candidate-build'
    New-Item -ItemType Directory -Path $build | Out-Null
    $units = 'guardian.c','account.c','tcp_path.c','system_dns.c','claude_msix.c'
    $source = Join-Path $repo 'native\session'
    $unitArgs = ($units | ForEach-Object { '"' + (Join-Path $source $_) + '"' }) -join ' '
    $compile = Join-Path $build 'compile.cmd'
    @"
@echo off
set "TEMP=$build"
set "TMP=$build"
call "$VcVars" >nul
if errorlevel 1 exit /b 1
cl.exe /nologo /W4 /WX /MT /O2 /DUNICODE /D_UNICODE /DPH_CLAUDE_MSIX /DPH_CLAUDE_MSIX_GUEST $unitArgs /Fe:guardian.exe /link Fwpuclnt.lib Advapi32.lib Rpcrt4.lib Iphlpapi.lib Ws2_32.lib Winhttp.lib Netapi32.lib Userenv.lib Bcrypt.lib Wtsapi32.lib Ole32.lib Shell32.lib
"@ | Set-Content -LiteralPath $compile -Encoding ASCII
    Push-Location $build
    try {
        & $env:ComSpec /d /c $compile | Out-Host
        if ($LASTEXITCODE -ne 0) { throw 'Guest MSIX guardian build failed' }
    } finally { Pop-Location }
    $guardian = Join-Path $build 'guardian.exe'
    @(Get-ChildItem -LiteralPath $source -File | Where-Object Extension -In '.c','.h' | ForEach-Object {
        @{path = 'native/session/' + $_.Name; sha256 = (Get-FileHash -LiteralPath $_.FullName).Hash}
    }) | ConvertTo-Json -Depth 3 | Set-Content (Join-Path $bundle 'guardian-sources.json') -Encoding UTF8
}
$parentSource = Join-Path $PSScriptRoot 'claude-guest-parent.go'
$parent = Join-Path $inputPath 'proxy-harbor.exe'
$previousCache = $env:GOCACHE
$previousTemp = $env:GOTMPDIR
Push-Location (Join-Path $repo 'app\proxy-harbor')
try {
    $env:GOCACHE = Join-Path $repo '.cache\review-go-build'
    $env:GOTMPDIR = Join-Path $repo '.cache\review-go-tmp'
    New-Item -ItemType Directory -Force -Path $env:GOCACHE,$env:GOTMPDIR | Out-Null
    & go build -trimpath -o $parent $parentSource
    if ($LASTEXITCODE -ne 0) { throw 'Guest launcher build failed' }
} finally {
    $env:GOCACHE = $previousCache
    $env:GOTMPDIR = $previousTemp
    Pop-Location
}
$files = [ordered]@{
    'Claude.msix' = $packagePath
    'guardian.exe' = $guardian
    'session-inventory.exe' = Join-Path $repo 'app\proxy-harbor\bin\proxy-harbor-session-inventory.exe'
    'node.exe' = (Get-Command node.exe).Source
    'sing-box.exe' = 'D:\Bufengruanj\v2rayN-windows-64\bin\sing_box\sing-box.exe'
    'wintun.dll' = 'D:\Bufengruanj\v2rayN-windows-64\bin\xray\wintun.dll'
    'run-sandbox.ps1' = Join-Path $PSScriptRoot 'guest-claude.ps1'
    'codex-file-bridge.mjs' = Join-Path $PSScriptRoot 'codex-file-bridge.mjs'
    'claude-guest-relay.mjs' = Join-Path $PSScriptRoot 'claude-guest-relay.mjs'
}
$entries = @(@{path = 'proxy-harbor.exe'; sha256 = (Get-FileHash -LiteralPath $parent).Hash}) + @(foreach ($file in $files.GetEnumerator()) {
    $destination = Join-Path $inputPath $file.Key
    Copy-Item -LiteralPath $file.Value -Destination $destination
    @{path = $file.Key; sha256 = (Get-FileHash -LiteralPath $destination).Hash}
})
@{schemaVersion = 1; publicNetwork = $true; publicChecks = $true; rebootChecks = $false;
    publicBridgeRound = [guid]::NewGuid().ToString('N').Substring(0, 8); expectedProxyIPv4 = $ExpectedProxyIPv4; layout = $Layout;
    msixCandidate = [bool]$MSIXCandidate; scenarios = $Scenarios; guardianBundle = $GuardianBundle;
    desktopGuardian = [bool]$DesktopGuardian;
    files = $entries} | ConvertTo-Json -Depth 4 | Set-Content (Join-Path $inputPath 'manifest.json') -Encoding UTF8
@{path = 'scripts/p0/claude-guest-parent.go'; sha256 = (Get-FileHash -LiteralPath $parentSource).Hash} |
    ConvertTo-Json | Set-Content (Join-Path $bundle 'parent-source.json') -Encoding UTF8
$escapedInput = [Security.SecurityElement]::Escape($inputPath)
$escapedResults = [Security.SecurityElement]::Escape($results)
@"
<Configuration>
  <Networking>Enable</Networking><vGPU>Disable</vGPU><AudioInput>Disable</AudioInput><VideoInput>Disable</VideoInput>
  <PrinterRedirection>Disable</PrinterRedirection><ClipboardRedirection>Disable</ClipboardRedirection><MemoryInMB>6144</MemoryInMB>
  <MappedFolders>
    <MappedFolder><HostFolder>$escapedInput</HostFolder><SandboxFolder>C:\P0Input</SandboxFolder><ReadOnly>true</ReadOnly></MappedFolder>
    <MappedFolder><HostFolder>$escapedResults</HostFolder><SandboxFolder>C:\P0Results</SandboxFolder><ReadOnly>false</ReadOnly></MappedFolder>
  </MappedFolders>
  <LogonCommand><Command>powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\P0Input\run-sandbox.ps1</Command></LogonCommand>
</Configuration>
"@ | Set-Content (Join-Path $repo '.local\p0\proxy-harbor-p0.wsb') -Encoding UTF8
Write-Output $bundle
