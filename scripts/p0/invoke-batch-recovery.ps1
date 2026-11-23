param([ValidateSet('Prepare','Restart')][string]$Action='Prepare',[switch]$AuthorizeOneGuestRestart)
$ErrorActionPreference='Stop'
if($Action -eq 'Restart' -and -not $AuthorizeOneGuestRestart){throw 'A new explicit one-guest restart authorization is required'}
$repository=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$active=Get-Content -LiteralPath (Join-Path $repository '.local\p0\sandbox-active.json') -Raw|ConvertFrom-Json
if($active.owner -ne 'proxy-harbor-p0' -or $active.stoppedAtUtc){throw 'Running project-owned guest required'}
$bundle=[IO.Directory]::GetParent($active.resultDirectory).FullName
$allowed=[IO.Path]::GetFullPath((Join-Path $repository '.local\p0\sandbox'))+'\'
if(-not ($bundle+'\').StartsWith($allowed,[StringComparison]::OrdinalIgnoreCase)){throw 'Scoped project bundle required'}
$manifest=Get-Content -LiteralPath (Join-Path $bundle 'input\manifest.json') -Raw|ConvertFrom-Json
$entry=@($manifest.files|Where-Object path -eq 'scripts\p0\guest-batch-reboot.ps1')
if($entry.Count -ne 1 -or (Get-FileHash -LiteralPath (Join-Path $bundle 'input\scripts\p0\guest-batch-reboot.ps1')).Hash -ne $entry[0].sha256){throw 'Prepared recovery script checksum required'}
$summary=Get-Content -LiteralPath (Join-Path $active.resultDirectory 'sandbox-summary.json') -Raw|ConvertFrom-Json
if($summary.state -ne 'complete' -or $summary.error){throw 'Finish the current protocol/network checks first'}
$command='$env:PROXY_HARBOR_P0_GUEST=''offline-lab'';Set-Location ''C:\P0Lab'';& ''C:\P0Lab\scripts\p0\guest-batch-reboot.ps1'' -Action '+$Action
if($Action -eq 'Restart'){$command+=' -AuthorizeOneGuestRestart'}
$encoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
$saved=@{};foreach($name in @('HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','NO_PROXY')){$saved[$name]=[Environment]::GetEnvironmentVariable($name,'Process')}
try {
    foreach($name in @('HTTP_PROXY','HTTPS_PROXY','ALL_PROXY')){[Environment]::SetEnvironmentVariable($name,'http://127.0.0.1:9','Process')}
    $env:NO_PROXY='localhost,127.0.0.1,::1'
    $inventory=& wsb.exe list --raw|ConvertFrom-Json
    if(-not @($inventory.WindowsSandboxEnvironments|Where-Object Id -eq $active.id).Count){throw 'Owned guest is no longer listed'}
    & wsb.exe exec --id $active.id --run-as System --working-directory 'C:\P0Lab' --command ('powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand '+$encoded) --raw
    if($LASTEXITCODE -ne 0 -and $Action -ne 'Restart'){throw 'Guest recovery preparation command failed'}
} finally {foreach($name in $saved.Keys){[Environment]::SetEnvironmentVariable($name,$saved[$name],'Process')}}
