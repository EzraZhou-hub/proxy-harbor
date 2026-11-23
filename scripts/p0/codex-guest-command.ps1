param([ValidateSet('Inspect','Rerun')][string]$Action='Inspect',[ValidatePattern('^[a-z0-9-]{1,24}$')][string]$RunIdentifier='revised')
$ErrorActionPreference='Stop'
$repositoryDirectory=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$active=Get-Content -LiteralPath (Join-Path $repositoryDirectory '.local\p0\sandbox-active.json') -Raw | ConvertFrom-Json
$identifier=[guid]::Empty
if($active.owner -ne 'proxy-harbor-p0' -or $active.stoppedAtUtc -or -not [guid]::TryParse($active.id,[ref]$identifier)){throw 'A running project-owned guest is required.'}
$resultDirectory=[IO.Path]::GetFullPath($active.resultDirectory)
$allowedRoot=[IO.Path]::GetFullPath((Join-Path $repositoryDirectory '.local\p0\sandbox'))+'\'
if(-not $resultDirectory.StartsWith($allowedRoot,[StringComparison]::OrdinalIgnoreCase)){throw 'Unexpected results mapping.'}
[xml]$configuration=Get-Content -LiteralPath $active.configuration -Raw
$mappings=@($configuration.Configuration.MappedFolders.MappedFolder)
if($configuration.Configuration.Networking -ne 'Disable' -or $mappings.Count -ne 2 -or
   [IO.Path]::GetFullPath([string]$mappings[1].HostFolder) -ne $resultDirectory){throw 'Guest configuration does not match the active record.'}
$source=@'
$ErrorActionPreference='Stop'
Set-Location -LiteralPath 'C:\P0Lab'
$targets=@(Get-CimInstance Win32_Process | Where-Object {$_.ExecutablePath -and $_.ExecutablePath.StartsWith('C:\P0Lab\codex-app\',[StringComparison]::OrdinalIgnoreCase)} | Select-Object ProcessId,ParentProcessId,ExecutablePath)
@{identity=[Security.Principal.WindowsIdentity]::GetCurrent().Name;processes=$targets} | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath 'C:\P0Results\guest-inspect.json' -Encoding UTF8
'@
if($Action -eq 'Rerun') {
    $updates=Join-Path $resultDirectory ('updates\'+$RunIdentifier)
    New-Item -ItemType Directory -Force -Path $updates | Out-Null
    $target=Join-Path $updates 'guest-codex.ps1'
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'guest-codex.ps1') -Destination $target -Force
    $digest=(Get-FileHash -LiteralPath $target).Hash
    $source=@"
`$ErrorActionPreference='Stop'
if((Get-FileHash -LiteralPath 'C:\P0Results\updates\$RunIdentifier\guest-codex.ps1').Hash -ne '$digest'){throw 'Revision digest mismatch.'}
Copy-Item -LiteralPath 'C:\P0Results\updates\$RunIdentifier\guest-codex.ps1' -Destination 'C:\P0Lab\scripts\p0\guest-codex.ps1' -Force
Set-Location -LiteralPath 'C:\P0Lab'
`$env:PROXY_HARBOR_P0_GUEST='offline-lab'
& 'C:\P0Lab\scripts\p0\guest-codex.ps1' -RunIdentifier '$RunIdentifier'
"@
    @{action='Rerun';guestId=$active.id;scriptSHA256=$digest;initialBundlePreserved=$true;requestedAt=[DateTimeOffset]::UtcNow.ToString('o')} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $updates 'revision.json') -Encoding UTF8
}
$source="try {`n"+$source+"`n} catch { `$_ | Out-String | Set-Content -LiteralPath 'C:\P0Results\guest-command-error.txt' -Encoding UTF8; exit 1 }"
$encoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($source))
$saved=@{}
foreach($name in @('HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','NO_PROXY')){$saved[$name]=[Environment]::GetEnvironmentVariable($name,'Process')}
try {
    foreach($name in @('HTTP_PROXY','HTTPS_PROXY','ALL_PROXY')){[Environment]::SetEnvironmentVariable($name,'http://127.0.0.1:9','Process')}
    $env:NO_PROXY='localhost,127.0.0.1,::1'
    $response=(& wsb.exe exec --id $active.id --run-as ExistingLogin --working-directory 'C:\P0Lab' --command ('powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand '+$encoded) --raw | Out-String)
    if($LASTEXITCODE -ne 0){throw 'Guest command failed.'}
    $response
    if(($response | ConvertFrom-Json).ExitCode -ne 0){throw 'Guest process failed; see guest-command-error.txt.'}
} finally {foreach($name in $saved.Keys){[Environment]::SetEnvironmentVariable($name,$saved[$name],'Process')}}
