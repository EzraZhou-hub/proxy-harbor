$ErrorActionPreference='Stop'
$repositoryDirectory=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$output=Join-Path $repositoryDirectory '.local\p0\bin'
$vcvars='D:\develop\vs2022\Community\VC\Auxiliary\Build\vcvars64.bat'
$source=Join-Path $repositoryDirectory 'native\p0\wfp_lab.c'
$compile=Join-Path $output 'compile-edge.cmd'
@"
@echo off
call "$vcvars" >nul
if errorlevel 1 exit /b 1
cl.exe /nologo /W4 /WX /MT /O2 /DUNICODE /D_UNICODE /DP0_RELAY_GUARD /DP0_EDGE_GUARD /D_WIN32_WINNT=0x0A00 "$source" /Fe:p0-edge-guard.exe /link Fwpuclnt.lib Advapi32.lib Rpcrt4.lib
"@|Set-Content -LiteralPath $compile -Encoding ASCII
Push-Location $output
try {& $env:ComSpec /d /c $compile;if($LASTEXITCODE -ne 0){throw 'Edge guard compilation failed.'}} finally {Pop-Location}
@{sourceSHA256=(Get-FileHash -LiteralPath $source).Hash;binarySHA256=(Get-FileHash -LiteralPath (Join-Path $output 'p0-edge-guard.exe')).Hash;builtAtUtc=[DateTimeOffset]::UtcNow.ToString('o');hostExecution='not_run'}|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $repositoryDirectory '.local\p0\edge-build.json') -Encoding UTF8
