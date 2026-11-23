$ErrorActionPreference='Stop'
$repository=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$recordPath=Join-Path $repository '.local\p0\batch-public-bridge.json'
if(Test-Path -LiteralPath $recordPath){$prior=Get-Content -LiteralPath $recordPath -Raw|ConvertFrom-Json;if(-not $prior.stopped -and (Get-Process -Id $prior.processId -ErrorAction SilentlyContinue)){throw 'Stop the recorded bridge before creating another round'}}
$active=Get-Content -LiteralPath (Join-Path $repository '.local\p0\sandbox-active.json') -Raw|ConvertFrom-Json
if($active.owner -ne 'proxy-harbor-p0' -or $active.stoppedAtUtc){throw 'Running project guest required'}
$bundle=[IO.Directory]::GetParent($active.resultDirectory).FullName
$allowed=[IO.Path]::GetFullPath((Join-Path $repository '.local\p0\sandbox'))+'\'
if(-not ($bundle+'\').StartsWith($allowed,[StringComparison]::OrdinalIgnoreCase)){throw 'Project bundle path required'}
$manifest=Get-Content -LiteralPath (Join-Path $bundle 'input\manifest.json') -Raw|ConvertFrom-Json
if(-not $manifest.publicChecks -or $manifest.publicBridgeRound -notmatch '^[a-f0-9]{8}$'){throw 'Prepared public check bundle required'}
$root=Join-Path $active.resultDirectory ('proxy-bridge-'+$manifest.publicBridgeRound)
if(Test-Path -LiteralPath $root){throw 'Fresh bridge root required; no automatic renewal'}
$bridge=Start-Process -FilePath 'D:\develop\Node\node.exe' -ArgumentList @('scripts/p0/codex-file-bridge.mjs','host',$root,'900000') -WorkingDirectory $repository -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $active.resultDirectory 'host-public-bridge.jsonl') -RedirectStandardError (Join-Path $active.resultDirectory 'host-public-bridge.stderr.log')
[ordered]@{schemaVersion=1;owner='proxy-harbor-p0';processId=$bridge.Id;guestId=$active.id;bundle=$bundle;root=$root;upstream='127.0.0.1:10808';leaseMs=900000;automaticRenewal=$false;startedAtUtc=[DateTimeOffset]::UtcNow.ToString('o');stopped=$false}|ConvertTo-Json|Set-Content -LiteralPath $recordPath -Encoding UTF8
[pscustomobject]@{bridgeProcessId=$bridge.Id;guestId=$active.id;leaseMs=900000;automaticRenewal=$false;hostListenerOpened=$false}|ConvertTo-Json
