# An explicit recovery action for the existing manual-login guest; no renewal loop.
$ErrorActionPreference='Stop'
$repositoryDirectory=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$active=Get-Content -LiteralPath (Join-Path $repositoryDirectory '.local\p0\sandbox-active.json') -Raw|ConvertFrom-Json
$parsedId=[guid]::Empty
if($active.owner -ne 'proxy-harbor-p0' -or $active.stoppedAtUtc -or -not [guid]::TryParse($active.id,[ref]$parsedId)){throw 'A running project-owned guest is required.'}
$results=[IO.Path]::GetFullPath($active.resultDirectory)
$allowed=[IO.Path]::GetFullPath((Join-Path $repositoryDirectory '.local\p0\sandbox'))+'\'
if(-not $results.StartsWith($allowed,[StringComparison]::OrdinalIgnoreCase)){throw 'Unexpected result root.'}
[xml]$configuration=Get-Content -LiteralPath $active.configuration -Raw
$mappings=@($configuration.Configuration.MappedFolders.MappedFolder)
if($configuration.Configuration.Networking -ne 'Disable' -or $mappings.Count -ne 2 -or [IO.Path]::GetFullPath([string]$mappings[1].HostFolder) -ne $results){throw 'Configuration mismatch.'}
$manifest=Get-Content -LiteralPath (Join-Path ([string]$mappings[0].HostFolder) 'manifest.json') -Raw|ConvertFrom-Json
if(-not $manifest.manualLogin){throw 'Manual-login bundle required.'}
$state=Get-Content -LiteralPath (Join-Path $results 'manual\state.json') -Raw|ConvertFrom-Json
if($state.proxyAddress -notmatch '^127\.0\.0\.1:([0-9]+)$'){throw 'Missing original loopback port.'}
$port=[int]$Matches[1]
if($port -lt 1024 -or $port -gt 65535){throw 'Unexpected port.'}
$bundle=Split-Path -Parent $results
$previousPath=Join-Path $bundle 'bridge-recovery.json'
if(Test-Path -LiteralPath $previousPath){
    $previous=Get-Content -LiteralPath $previousPath -Raw|ConvertFrom-Json
    $previousRoot=[IO.Path]::GetFullPath($previous.root)
    if(-not $previousRoot.StartsWith($results+'\proxy-bridge',[StringComparison]::OrdinalIgnoreCase)){throw 'Unexpected previous bridge root.'}
    if(-not (Test-Path -LiteralPath (Join-Path $previousRoot 'host-stopped.json'))){throw 'Previous bridge has not stopped; refusing overlapping recovery.'}
}
$round=[guid]::NewGuid().ToString('N').Substring(0,8)
$updates=Join-Path $results ('updates\bridge-'+$round)
New-Item -ItemType Directory -Path $updates|Out-Null
$source=Join-Path $PSScriptRoot 'codex-file-bridge.mjs'
Copy-Item -LiteralPath $source -Destination (Join-Path $updates 'codex-file-bridge.mjs')
$digest=(Get-FileHash -LiteralPath $source).Hash
$root=Join-Path $results ('proxy-bridge-'+$round)
$bridge=Start-Process -FilePath 'D:\develop\Node\node.exe' -ArgumentList @('scripts\p0\codex-file-bridge.mjs','host',$root,'900000') -WorkingDirectory $repositoryDirectory -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $bundle ('host-bridge-'+$round+'.jsonl')) -RedirectStandardError (Join-Path $bundle ('host-bridge-'+$round+'.stderr.log'))
$record=[ordered]@{round=$round;hostPid=$bridge.Id;guestId=$active.id;port=$port;scriptSHA256=$digest;root=$root;leaseMs=900000;automaticRenewal=$false;reason='User reported login page became unavailable; previous lease_expired';requestedAtUtc=[DateTimeOffset]::UtcNow.ToString('o')}
$record|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $bundle ('bridge-recovery-'+$round+'.json')) -Encoding UTF8
$record|ConvertTo-Json|Set-Content -LiteralPath $previousPath -Encoding UTF8
$code=@"
`$ErrorActionPreference='Stop'
try {
if((Get-FileHash -LiteralPath 'C:\P0Results\updates\bridge-$round\codex-file-bridge.mjs').Hash -ne '$digest'){throw 'Bridge revision digest mismatch.'}
Copy-Item -LiteralPath 'C:\P0Results\updates\bridge-$round\codex-file-bridge.mjs' -Destination 'C:\P0Lab\scripts\p0\codex-file-bridge.mjs' -Force
Set-Location -LiteralPath 'C:\P0Lab'
`$env:PROXY_HARBOR_P0_GUEST='offline-lab'
`$process=Start-Process -FilePath 'C:\P0Lab\node.exe' -ArgumentList @('scripts\p0\codex-file-bridge.mjs','guest','C:\P0Results\proxy-bridge-$round','900000','$port') -WorkingDirectory 'C:\P0Lab' -WindowStyle Hidden -PassThru -RedirectStandardOutput 'C:\P0Results\manual\bridge-$round.jsonl' -RedirectStandardError 'C:\P0Results\manual\bridge-$round.stderr.log'
`$ready=`$false
for(`$attempt=0;`$attempt -lt 150;`$attempt++){
    if(Test-Path -LiteralPath 'C:\P0Results\manual\bridge-$round.jsonl'){
        `$first=Get-Content -LiteralPath 'C:\P0Results\manual\bridge-$round.jsonl' -TotalCount 1
        if(`$first -and (`$first|ConvertFrom-Json).address -eq '127.0.0.1:$port'){`$ready=`$true;break}
    }
    Start-Sleep -Milliseconds 100
}
if(-not `$ready){throw 'Recovered channel did not become ready.'}
`$check=Start-Process -FilePath 'C:\P0Lab\.local\p0\bin\p0-upstream-check.exe' -ArgumentList @('-protocol','http','-upstream','127.0.0.1:$port') -WindowStyle Hidden -Wait -PassThru -RedirectStandardOutput 'C:\P0Results\manual\recovery-$round-https.json' -RedirectStandardError 'C:\P0Results\manual\recovery-$round-https.stderr.log'
if(`$check.ExitCode -ne 0){throw 'Recovered channel HTTPS check failed.'}
@{guestPid=`$process.Id;round='$round';port=$port;leaseMs=900000;state='recovery_https_verified'}|ConvertTo-Json|Set-Content -LiteralPath 'C:\P0Results\manual\bridge-recovery-$round.json' -Encoding UTF8
} catch { `$_.Exception.Message|Set-Content -LiteralPath 'C:\P0Results\manual\recovery-$round-error.txt';exit 1 }
"@
$encoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($code))
$saved=@{}
foreach($name in @('HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','NO_PROXY')){$saved[$name]=[Environment]::GetEnvironmentVariable($name,'Process')}
try {
    foreach($name in @('HTTP_PROXY','HTTPS_PROXY','ALL_PROXY')){[Environment]::SetEnvironmentVariable($name,'http://127.0.0.1:9','Process')}
    $env:NO_PROXY='localhost,127.0.0.1,::1'
    $response=(& wsb.exe exec --id $active.id --run-as ExistingLogin --working-directory 'C:\P0Lab' --command ('powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand '+$encoded) --raw|Out-String)
    if($LASTEXITCODE -ne 0 -or ($response|ConvertFrom-Json).ExitCode -ne 0){throw 'Guest recovery failed; see fixed-target check metadata.'}
    $check=Get-Content -LiteralPath (Join-Path $results ('manual\recovery-'+$round+'-https.json')) -Raw|ConvertFrom-Json
    if(-not $check.passed -or -not $check.targetTLSVerified){throw 'Recovery certificate verification failed.'}
    $summaryPath=Join-Path $repositoryDirectory '.local\p0\codex-login-session.json'
    $summary=Get-Content -LiteralPath $summaryPath -Raw|ConvertFrom-Json
    $summary.sessionState='awaiting_user_login_after_explicit_15_minute_recovery'
    $summary.hostBridgeLeaseMs=900000;$summary.recoveryRound=$record;$summary.recoveryHTTPSCheck=$check
    $summary.userReport='Login page opened then unavailable; previous round confirmed lease_expired'
    $summary.checkedAtUtc=[DateTimeOffset]::UtcNow.ToString('o')
    $summary|ConvertTo-Json -Depth 12|Set-Content -LiteralPath $summaryPath -Encoding UTF8
    $record|ConvertTo-Json
} finally {foreach($name in $saved.Keys){[Environment]::SetEnvironmentVariable($name,$saved[$name],'Process')}}
