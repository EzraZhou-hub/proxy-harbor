param(
 [string]$VcVars='D:\develop\vs2022\Community\VC\Auxiliary\Build\vcvars64.bat',
 [string]$BinDir='bin',
 [switch]$UsePinnedGuardian,
 [switch]$BuildClaudeDesktop
)
$ErrorActionPreference='Stop'
$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$output=Join-Path (Join-Path $root 'app\proxy-harbor') $BinDir
New-Item -ItemType Directory -Force -Path $output|Out-Null
$compile=Join-Path $output 'compile-guardian.cmd'
$reuse=$false
if($UsePinnedGuardian -and $BuildClaudeDesktop){throw 'Choose either the pinned artifact or a new Claude Desktop build.'}
$approvalPath=Join-Path $root 'app\proxy-harbor\internal\session\approved_guardian.json'
if(!$BuildClaudeDesktop -and (Test-Path -LiteralPath $approvalPath)){
 $approval=Get-Content -LiteralPath $approvalPath -Raw|ConvertFrom-Json
 if($approval.quarantined){throw "Pinned guardian $($approval.guardianSha256) is quarantined. Native build and cache restoration stopped."}
 $validPin=$approval.guardianSha256 -match '^[a-f0-9]{64}$'
 $sourcesMatch=$validPin -and @($approval.sourceHashes).Count -ge 3
 if(-not $UsePinnedGuardian){
  foreach($source in $approval.sourceHashes){
   $resolved=[IO.Path]::GetFullPath((Join-Path $root $source.path))
   if(-not $resolved.StartsWith($root+'\',[StringComparison]::OrdinalIgnoreCase) -or -not(Test-Path -LiteralPath $resolved) -or (Get-FileHash -LiteralPath $resolved).Hash -ne $source.sha256){$sourcesMatch=$false}
  }
 }
 if($validPin -and ($UsePinnedGuardian -or $sourcesMatch)){
  $target=Join-Path $output 'proxy-harbor-guardian.exe'
  $candidates=@($target, (Join-Path $root '.local\p0\accepted\proxy-harbor-guardian.exe'))
  if($approval.evidenceBundle -match '^\d{8}-\d{6}-[a-f0-9]{6}$'){
   $candidates+=Join-Path $root ".local\p0\sandbox\$($approval.evidenceBundle)\input\release-guardian.exe"
   $candidates+=Join-Path $root ".local\p0\sandbox\$($approval.evidenceBundle)\input\guardian.exe"
   $candidates+=Join-Path $root ".local\p0\sandbox\$($approval.evidenceBundle)\results\updates\proxy-harbor-guardian.exe"
   $candidates+=Join-Path $root ".local\p0\sandbox\$($approval.evidenceBundle)\input\.local\p0\bin\proxy-harbor-guardian.exe"
  }
  foreach($candidate in $candidates){
   if((Test-Path -LiteralPath $candidate -PathType Leaf) -and (Get-FileHash -LiteralPath $candidate).Hash -eq $approval.guardianSha256){
    if($candidate -ne $target){Copy-Item -LiteralPath $candidate -Destination $target -Force}
    $reuse=$true
    break
   }
  }
 }
}
if($UsePinnedGuardian -and -not $reuse){throw 'No guardian executable matches the pinned desktop fingerprint.'}
$claudeDefines=if($BuildClaudeDesktop){'/DPH_CLAUDE_MSIX /DPH_CLAUDE_MSIX_DESKTOP /DPH_CLAUDE_TAKEOVER'}else{''}
$claudeUnit=if($BuildClaudeDesktop){
 (('claude_msix.c','claude_takeover.c' | ForEach-Object {'"'+(Join-Path $root "native\session\$_")+'"'}) -join ' ')
}else{''}
$guardBuild=if($reuse){'rem Reuse the native artifact matching the pinned SHA-256.'}else{@"
cl.exe /nologo /W4 /WX /MT /O2 /DUNICODE /D_UNICODE $claudeDefines "$(Join-Path $root 'native\session\guardian.c')" "$(Join-Path $root 'native\session\account.c')" "$(Join-Path $root 'native\session\tcp_path.c')" "$(Join-Path $root 'native\session\system_dns.c')" $claudeUnit /Fe:proxy-harbor-guardian.exe /link /Brepro Fwpuclnt.lib Advapi32.lib Rpcrt4.lib Iphlpapi.lib Ws2_32.lib Winhttp.lib Netapi32.lib Userenv.lib Bcrypt.lib Wtsapi32.lib Ole32.lib Shell32.lib User32.lib
"@}
@"
@echo off
call "$VcVars" >nul
if errorlevel 1 exit /b 1
$guardBuild
if errorlevel 1 exit /b 1
cl.exe /nologo /W4 /WX /MT /O2 /DUNICODE /D_UNICODE "$(Join-Path $root 'native\session\inventory.c')" /Fe:proxy-harbor-session-inventory.exe /link Fwpuclnt.lib Rpcrt4.lib
"@|Set-Content -LiteralPath $compile -Encoding ASCII
Push-Location $output
try {& $env:ComSpec /d /c $compile;if($LASTEXITCODE -ne 0){throw 'Session guardian build failed'}}finally{Pop-Location}
Write-Output 'Guardian built. No process launched or system policy modified.'
if($reuse){Write-Output 'Pinned native artifact retained; runtime validation status is recorded separately.'}
