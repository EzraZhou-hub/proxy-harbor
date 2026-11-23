param([string]$ExpectedProxyIPv4 = '131.103.130.202', [string]$RetryFrom, [switch]$TLSFailuresOnly,
    [ValidatePattern('^\d{8}-\d{6}-[a-f0-9]{6}$')][string]$GuardianBundle = '20261118-022819-37eaac')
$ErrorActionPreference = 'Stop'
$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$baseline = Join-Path $repo ".local\p0\sandbox\$GuardianBundle"
$baselineReport = Get-Content (Join-Path $baseline 'results\claude-validation.json') -Raw | ConvertFrom-Json
$guardian = Join-Path $baseline 'input\guardian.exe'
if (-not $baselineReport.passed -or (Get-FileHash -LiteralPath $guardian).Hash -ne $baselineReport.guardianSha256) { throw 'Verified Claude guest guardian required' }
$address = [Net.IPAddress]::Parse($ExpectedProxyIPv4)
if ($address.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork -or $address.ToString() -ne $ExpectedProxyIPv4) { throw 'Canonical IPv4 required' }
$catalogPath = Join-Path $repo 'app\proxy-harbor\frontend\src\data\claude-code-domains.json'
$selectedDomains = @()
if ($TLSFailuresOnly -and -not $RetryFrom) { throw 'A prior TLS report is required' }
if ($RetryFrom) {
    if ($RetryFrom -notmatch '^\d{8}-\d{6}-[a-f0-9]{6}$') { throw 'Expected a local audit bundle ID' }
    $prior = Get-Content (Join-Path $repo ".local\p0\sandbox\$RetryFrom\results\claude-domain-audit.json") -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($prior.catalogSha256 -ne (Get-FileHash -LiteralPath $catalogPath).Hash -or $prior.expectedProxyIPv4 -ne $ExpectedProxyIPv4) { throw 'Retry needs the identical catalog and fixed exit' }
    $selectedDomains = @($prior.rows | Where-Object { -not $_.tlsVerified -or (-not $TLSFailuresOnly -and -not $_.httpStatus) } | ForEach-Object domain)
    if (-not $selectedDomains.Count) { throw 'No incomplete HTTPS responses to retry' }
}
$id = [DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss') + '-' + [guid]::NewGuid().ToString('N').Substring(0, 6)
$bundle = Join-Path $repo ".local\p0\sandbox\$id"
$inputDir = Join-Path $bundle 'input'
$results = Join-Path $bundle 'results'
New-Item -ItemType Directory -Path $inputDir,$results | Out-Null

$files = [ordered]@{
    'guardian.exe' = $guardian
    'claude-code-domains.json' = $catalogPath
    'run-sandbox.ps1' = Join-Path $PSScriptRoot 'guest-claude-domains.ps1'
    'claude-domain-observer.mjs' = Join-Path $PSScriptRoot 'claude-domain-observer.mjs'
    'claude-guest-relay.mjs' = Join-Path $PSScriptRoot 'claude-guest-relay.mjs'
}
foreach ($name in @('node.exe','sing-box.exe','wintun.dll','session-inventory.exe','codex-file-bridge.mjs')) {
    $files[$name] = Join-Path $baseline "input\$name"
}
foreach ($file in $files.GetEnumerator()) { Copy-Item -LiteralPath $file.Value -Destination (Join-Path $inputDir $file.Key) }
$oldCache = $env:GOCACHE
$oldTemp = $env:GOTMPDIR
Push-Location (Join-Path $repo 'app\proxy-harbor')
try {
    $env:GOCACHE = Join-Path $repo '.cache\review-go-build'
    $env:GOTMPDIR = Join-Path $repo '.cache\review-go-tmp'
    foreach ($build in @(@{Ex='proxy-harbor.exe'; Src='claude-guest-parent.go'}, @{Ex='domain-probe.exe'; Src='claude-domain-probe.go'})) {
        & go build -trimpath -o (Join-Path $inputDir $build.Ex) (Join-Path $PSScriptRoot $build.Src)
        if ($LASTEXITCODE -ne 0) { throw "Guest fixture build failed: $($build.Src)" }
    }
} finally {
    $env:GOCACHE = $oldCache
    $env:GOTMPDIR = $oldTemp
    Pop-Location
}
$entries = @(Get-ChildItem -LiteralPath $inputDir -File | ForEach-Object { @{path = $_.Name; sha256 = (Get-FileHash -LiteralPath $_.FullName).Hash} })
@{schemaVersion = 1; publicNetwork = $true; publicChecks = $true; rebootChecks = $false;
    expectedProxyIPv4 = $ExpectedProxyIPv4; publicBridgeRound = [guid]::NewGuid().ToString('N').Substring(0, 8);
    selectedDomains = $selectedDomains; retryOf = $RetryFrom;
    files = $entries} | ConvertTo-Json -Depth 4 | Set-Content (Join-Path $inputDir 'manifest.json') -Encoding UTF8
$inXml = [Security.SecurityElement]::Escape($inputDir)
$outXml = [Security.SecurityElement]::Escape($results)
@"
<Configuration>
  <Networking>Enable</Networking><vGPU>Disable</vGPU><AudioInput>Disable</AudioInput><VideoInput>Disable</VideoInput>
  <PrinterRedirection>Disable</PrinterRedirection><ClipboardRedirection>Disable</ClipboardRedirection><MemoryInMB>6144</MemoryInMB>
  <MappedFolders>
    <MappedFolder><HostFolder>$inXml</HostFolder><SandboxFolder>C:\P0Input</SandboxFolder><ReadOnly>true</ReadOnly></MappedFolder>
    <MappedFolder><HostFolder>$outXml</HostFolder><SandboxFolder>C:\P0Results</SandboxFolder><ReadOnly>false</ReadOnly></MappedFolder>
  </MappedFolders>
  <LogonCommand><Command>powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\P0Input\run-sandbox.ps1</Command></LogonCommand>
</Configuration>
"@ | Set-Content (Join-Path $repo '.local\p0\proxy-harbor-p0.wsb') -Encoding UTF8
Write-Output $bundle
