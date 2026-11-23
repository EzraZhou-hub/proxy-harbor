param([string]$VcVars = 'D:\develop\vs2022\Community\VC\Auxiliary\Build\vcvars64.bat')
$ErrorActionPreference = 'Stop'
$repositoryDirectory = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$outputDirectory = Join-Path $repositoryDirectory '.local\p0\bin'
$controlDirectory = Join-Path $repositoryDirectory '.local\p0\control'
if (-not (Test-Path -LiteralPath $VcVars)) { throw "MSVC environment not found: $VcVars" }
New-Item -ItemType Directory -Force -Path $outputDirectory, $controlDirectory | Out-Null
$env:GOTMPDIR = Join-Path $repositoryDirectory '.cache\review-go-tmp'
$env:GOCACHE = Join-Path $repositoryDirectory '.cache\review-go-build'
New-Item -ItemType Directory -Force -Path $env:GOTMPDIR, $env:GOCACHE | Out-Null
Push-Location (Join-Path $repositoryDirectory 'app\proxy-harbor')
try {
    go build -o (Join-Path $outputDirectory 'proxy-harbor-p0-probe.exe') ./cmd/p0-probe
    if ($LASTEXITCODE -ne 0) { throw 'P0 probe build failed.' }
    go build -o (Join-Path $outputDirectory 'proxy-harbor-p0-relay.exe') ./cmd/p0-relay
    if ($LASTEXITCODE -ne 0) { throw 'P0 relay build failed.' }
    go build -o (Join-Path $outputDirectory 'capsule-probe.exe') ./cmd/capsule-probe
    if($LASTEXITCODE -ne 0){throw 'Capsule probe build failed'}
} finally { Pop-Location }
Copy-Item -LiteralPath (Join-Path $outputDirectory 'proxy-harbor-p0-probe.exe') -Destination (Join-Path $controlDirectory 'proxy-harbor-p0-probe.exe') -Force
$helperDirectory = Join-Path $outputDirectory 'helpers'
New-Item -ItemType Directory -Force -Path $helperDirectory | Out-Null
Copy-Item -LiteralPath (Join-Path $outputDirectory 'proxy-harbor-p0-probe.exe') -Destination (Join-Path $helperDirectory 'proxy-harbor-p0-helper.exe') -Force
$source = Join-Path $repositoryDirectory 'native\p0\wfp_lab.c'
$compileScript = Join-Path $outputDirectory 'compile.cmd'
$compileText = @"
@echo off
call "$VcVars" >nul
if errorlevel 1 exit /b 1
cl.exe /nologo /W4 /WX /MT /O2 /DUNICODE /D_UNICODE /D_WIN32_WINNT=0x0A00 "$source" /Fe:p0-wfp.exe /link Fwpuclnt.lib Advapi32.lib Rpcrt4.lib
if errorlevel 1 exit /b 1
cl.exe /nologo /W4 /WX /MT /O2 /DUNICODE /D_UNICODE /DP0_RELAY_GUARD /D_WIN32_WINNT=0x0A00 "$source" /Fe:p0-relay-guard.exe /link Fwpuclnt.lib Advapi32.lib Rpcrt4.lib
if errorlevel 1 exit /b 1
cl.exe /nologo /W4 /WX /MT /O2 /DUNICODE /D_UNICODE /DP0_RELAY_GUARD /DP0_HELPER_GUARD /D_WIN32_WINNT=0x0A00 "$source" /Fe:p0-helper-guard.exe /link Fwpuclnt.lib Advapi32.lib Rpcrt4.lib
if errorlevel 1 exit /b 1
cl.exe /nologo /W4 /WX /MT /O2 /DUNICODE /D_UNICODE /D_WIN32_WINNT=0x0A00 "$(Join-Path $repositoryDirectory 'native\p0\dns_isolation_lab.c')" "$(Join-Path $repositoryDirectory 'native\p0\isolation_policy.c')" /Fe:p0-dns-isolation.exe /link Userenv.lib Advapi32.lib Fwpuclnt.lib Rpcrt4.lib
if errorlevel 1 exit /b 1
cl.exe /nologo /W4 /WX /MT /O2 /DUNICODE /D_UNICODE /D_WIN32_WINNT=0x0A00 "$(Join-Path $repositoryDirectory 'native\p0\relay_port_guard.c')" /Fe:p0-port-guard.exe /link Fwpuclnt.lib Advapi32.lib Rpcrt4.lib
if errorlevel 1 exit /b 1
cl.exe /nologo /W4 /WX /MT /O2 /DUNICODE /D_UNICODE /D_WIN32_WINNT=0x0A00 "$(Join-Path $repositoryDirectory 'native\p0\net_event_lab.c')" /Fe:p0-net-events.exe /link Fwpuclnt.lib Advapi32.lib Rpcrt4.lib
if errorlevel 1 exit /b 1
cl.exe /nologo /W4 /WX /MT /O2 /DUNICODE /D_UNICODE /DP0_ISOLATION_INSPECT /D_WIN32_WINNT=0x0A00 "$(Join-Path $repositoryDirectory 'native\p0\isolation_policy.c')" /Fe:p0-isolation-inspect.exe /link Fwpuclnt.lib Advapi32.lib Rpcrt4.lib
if errorlevel 1 exit /b 1
cl.exe /nologo /W4 /WX /MT /O2 /DUNICODE /D_UNICODE /D_WIN32_WINNT=0x0A00 "$(Join-Path $repositoryDirectory 'native\p0\capsule_lab.c')" "$(Join-Path $repositoryDirectory 'native\p0\isolation_policy.c')" /Fe:p0-capsule.exe /link Userenv.lib Advapi32.lib Fwpuclnt.lib Rpcrt4.lib Ole32.lib
if errorlevel 1 exit /b 1
cl.exe /nologo /W4 /WX /MT /O2 /DUNICODE /D_UNICODE /D_WIN32_WINNT=0x0A00 "$(Join-Path $repositoryDirectory 'native\p0\user_capsule_lab.c')" "$(Join-Path $repositoryDirectory 'native\p0\user_policy.c')" /Fe:p0-user-capsule.exe /link Userenv.lib Netapi32.lib Bcrypt.lib Advapi32.lib Fwpuclnt.lib Rpcrt4.lib
"@
Set-Content -LiteralPath $compileScript -Value $compileText -Encoding ascii
Push-Location $outputDirectory
try {
    & $env:ComSpec /d /c $compileScript
    if ($LASTEXITCODE -ne 0) { throw 'P0 WFP laboratory build failed.' }
} finally { Pop-Location }
Write-Output "Built P0 tools: $outputDirectory"
Write-Output 'Build only. No filters, drivers or services were installed.'
