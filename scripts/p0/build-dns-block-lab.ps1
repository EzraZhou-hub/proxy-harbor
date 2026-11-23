param(
    [string]$VcVars = 'D:\develop\vs2022\Community\VC\Auxiliary\Build\vcvars64.bat'
)
$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$output = Join-Path $root '.local\p0\bin'
New-Item -ItemType Directory -Force -Path $output | Out-Null
$source = Join-Path $root 'native\p0\dns_block_lab.c'
$script = Join-Path $output 'compile-dns-block-lab.cmd'
@"
@echo off
call "$VcVars" >nul
if errorlevel 1 exit /b 1
cl.exe /nologo /W4 /WX /MT /DUNICODE /D_UNICODE "$source" "$(Join-Path $root 'native\session\system_dns.c')" /Fe:dns-block-lab.exe /link Fwpuclnt.lib Rpcrt4.lib Advapi32.lib
exit /b %errorlevel%
"@ | Set-Content -LiteralPath $script -Encoding ASCII
Push-Location $output
try {
    & $env:ComSpec /d /c $script
    if ($LASTEXITCODE -ne 0) { throw 'Temporary DNS guard build failed' }
} finally { Pop-Location }
Write-Output 'Guest-only DNS experiment built. No network settings or rules changed.'
