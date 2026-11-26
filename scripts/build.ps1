param([switch]$Check, [switch]$E2E, [string]$BinDir='bin')
$ErrorActionPreference = 'Stop'
$projectDirectory = Join-Path $PSScriptRoot '..\app\proxy-harbor'
$repositoryDirectory = Split-Path -Parent $PSScriptRoot
$env:npm_config_cache = Join-Path $repositoryDirectory '.cache\npm'
$env:GOTMPDIR=Join-Path $repositoryDirectory '.cache\review-go-tmp'
$env:GOCACHE=Join-Path $repositoryDirectory '.cache\review-go-build'
New-Item -ItemType Directory -Force -Path $env:GOTMPDIR,$env:GOCACHE|Out-Null
function Assert-Exit([string]$Step) {
    if ($LASTEXITCODE -ne 0) { throw "$Step failed (exit $LASTEXITCODE)." }
}
foreach ($tool in @('go', 'wails3', 'npm.cmd')) {
    if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) { throw "Required command not found: $tool" }
}
Push-Location $projectDirectory
try {
    & (Join-Path $PSScriptRoot 'build-guardian.ps1') -UsePinnedGuardian -BinDir $BinDir
    if (-not (Test-Path -LiteralPath 'frontend\node_modules')) {
        npm.cmd ci --prefix frontend --no-audit --no-fund
        Assert-Exit 'Frontend dependency installation'
    }
    wails3 build "BIN_DIR=$BinDir"
    Assert-Exit 'Desktop build'
    if ($Check) {
        go test ./...
        Assert-Exit 'Go tests'
        npm.cmd run check --prefix frontend
        Assert-Exit 'Frontend type check'
    }
    if ($E2E) {
        go build -tags server -o bin/proxy-harbor-server.exe .
        Assert-Exit 'Test host build'
        Push-Location frontend
        try { npm.cmd run test:e2e; Assert-Exit 'UI integration tests' }
        finally { Pop-Location }
    }
    Write-Output "Built: $(Join-Path (Join-Path $projectDirectory $BinDir) 'proxy-harbor.exe')"
} finally { Pop-Location }
