param(
    [string]$MakeNsis = 'makensis.exe',
    [switch]$E2E
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$project = Join-Path $root 'app\proxy-harbor'
$pin = Get-Content (Join-Path $project 'internal\session\approved_guardian.json') -Raw | ConvertFrom-Json
if (-not $pin.claudeDesktop -or $pin.quarantined -or $pin.guardianSha256 -cnotmatch '^[a-f0-9]{64}$') {
    throw 'A validated Claude Desktop guardian is required for release packaging.'
}
foreach ($source in $pin.sourceHashes) {
    $path = Join-Path $root $source.path
    if ((Get-FileHash -LiteralPath $path).Hash -ne $source.sha256) {
        throw "Guardian source has changed since verification: $($source.path)"
    }
}
$make = (Get-Command $MakeNsis -CommandType Application -ErrorAction Stop).Source
$info = Get-Content (Join-Path $project 'build\windows\info.json') -Raw | ConvertFrom-Json
$version = $info.fixed.product_version
if ($version -cnotmatch '^\d+\.\d+\.\d+$') { throw 'Invalid release version.' }
$bin = "bin\release-$version"
& (Join-Path $PSScriptRoot 'build.ps1') -BinDir $bin -Check -E2E:$E2E

$output = Join-Path $project $bin
$guardian = Join-Path $output 'proxy-harbor-guardian.exe'
if ((Get-FileHash -LiteralPath $guardian).Hash -ne $pin.guardianSha256) {
    throw 'The release guardian does not match the desktop fingerprint.'
}
$setup = Join-Path $output "Proxy-Harbor-$version-win-x64-setup.exe"
$installerDir = Join-Path $project 'build\windows\nsis'
wails3 generate webview2bootstrapper -dir $installerDir
if ($LASTEXITCODE -ne 0) { throw 'WebView2 bootstrapper generation failed.' }
Push-Location $installerDir
try {
    $arguments = @('/V2', '/INPUTCHARSET', 'UTF8', '/DINFO_COMPANYNAME=Proxy Harbor', "/DINFO_PRODUCTVERSION=$version",
        "/DARG_WAILS_AMD64_BINARY=$output\proxy-harbor.exe", "/DARG_PROXY_HARBOR_BIN=$output",
        "/DARG_PROXY_HARBOR_SETUP=$setup", 'project.nsi')
    & $make @arguments
    if ($LASTEXITCODE -ne 0) { throw 'Windows installer packaging failed.' }
} finally { Pop-Location }
$hash = (Get-FileHash -LiteralPath $setup).Hash.ToLowerInvariant()
"$hash  $([IO.Path]::GetFileName($setup))" | Set-Content -LiteralPath "$setup.sha256" -Encoding ASCII
Write-Output $setup
