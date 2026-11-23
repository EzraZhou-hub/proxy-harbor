param([Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{8}$')][string]$BridgeRound,[string]$ExpectedProxyIPv4='',[ValidateSet('appcontainer','appcontainer-wfp')][string]$IsolationMode='appcontainer-wfp')
$ErrorActionPreference='Stop'
if((Get-Location).Path -ne 'C:\P0Lab' -or $env:PROXY_HARBOR_P0_GUEST -ne 'offline-lab' -or $PSCommandPath -ne 'C:\P0Lab\scripts\p0\guest-isolated-public.ps1'){throw 'Fixed offline P0 guest required.'}
$output='C:\P0Results\isolated-public'
New-Item -ItemType Directory -Path $output|Out-Null
$bin='C:\P0Lab\.local\p0\bin'
$manifest=Get-Content -LiteralPath 'C:\P0Lab\manifest.json' -Raw|ConvertFrom-Json
$report=[ordered]@{schemaVersion=1;overall='not_accepted';scope='Fixed anonymous HTTPS through AppContainer + transparent hook + listener proof; 12 fixture rules and 6 SID rules in WFP mode';guestNetworking=if($manifest.publicNetwork){'enabled'}else{'disabled'};checks=[ordered]@{};cleanup='pending';applicationProtectionVerified=$false}
$bridge=$null;$relay=$null
$guards=@('p0-relay-guard.exe','p0-helper-guard.exe','p0-port-guard.exe')
$previous=@{};foreach($name in @('P0_RELAY_PROOF_KEY','P0_EXPECTED_RELAY_PID','P0_PEER_TABLE_DIAGNOSTIC')){$previous[$name]=[Environment]::GetEnvironmentVariable($name,'Process')}
function Save-Report{$report|ConvertTo-Json -Depth 12|Set-Content -LiteralPath (Join-Path $output 'report.json') -Encoding UTF8}
function Check([string]$Name,[bool]$Pass){$report.checks[$Name]=$Pass;Save-Report;if(-not $Pass){throw ('Public observation failed: '+$Name)}}
function Policy([string]$Name,[string]$Action,[string]$Port){$arguments=@($Action);if($Port){$arguments+=,$Port};$raw=& (Join-Path $bin $Name) @arguments;$code=$LASTEXITCODE;$r=$raw|ConvertFrom-Json;if($code -ne 0 -or $r.windowsError -ne 0){throw ('Guest policy action failed: '+$Name+'/'+$Action)};return $r}
function Ready([string]$Path){for($i=0;$i -lt 200;$i++){if(Test-Path -LiteralPath $Path){$line=Get-Content -LiteralPath $Path -TotalCount 1;if($line){return ($line|ConvertFrom-Json)}};Start-Sleep -Milliseconds 100};throw 'Public helper readiness timed out'}
try {
    foreach($name in $guards){Check ('clean_'+$name) ((Policy $name 'inspect' '').rulesPresent -eq 0)}
    $root='C:\P0Results\proxy-bridge-'+$BridgeRound
    $bridgeLog=Join-Path $output 'bridge.jsonl'
    $bridge=Start-Process -FilePath 'C:\P0Lab\node.exe' -ArgumentList @('scripts\p0\codex-file-bridge.mjs','guest',$root,'900000') -WorkingDirectory 'C:\P0Lab' -WindowStyle Hidden -PassThru -RedirectStandardOutput $bridgeLog -RedirectStandardError (Join-Path $output 'bridge.stderr.log')
    $upstream=(Ready $bridgeLog).address
    $key=New-Object byte[] 32;$rng=[Security.Cryptography.RandomNumberGenerator]::Create();try{$rng.GetBytes($key)}finally{$rng.Dispose()}
    $env:P0_RELAY_PROOF_KEY=([BitConverter]::ToString($key)).Replace('-','').ToLowerInvariant();[Array]::Clear($key,0,$key.Length)
    $relayLog=Join-Path $output 'relay.jsonl'
    $relay=Start-Process -FilePath (Join-Path $bin 'proxy-harbor-p0-relay.exe') -ArgumentList @('-protocol','http','-upstream',$upstream,'-lease','5m') -WorkingDirectory 'C:\P0Lab' -WindowStyle Hidden -PassThru -RedirectStandardOutput $relayLog -RedirectStandardError (Join-Path $output 'relay.stderr.log')
    $address=(Ready $relayLog).address;$port=($address -split ':')[-1]
    $env:P0_EXPECTED_RELAY_PID=[string]$relay.Id;$env:P0_PEER_TABLE_DIAGNOSTIC='1'
    $report.proxyPath='AC regular HTTPS -> transparent SOCKS5 + ephemeral HMAC proof -> Relay/Gate -> file bridge -> host HTTP 127.0.0.1:10808'
    $report.relayAddress=$address
    @{scope='guest-only';port=$port;guards=$guards;bridgeRound=$BridgeRound;relayProofKeyPersisted=$false}|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $output 'recovery.json') -Encoding UTF8
    foreach($name in $guards){$action=if($name -eq 'p0-port-guard.exe'){'reserve-fixture-only'}else{'install-fixture-only'};Check ('installed_'+$name) ((Policy $name $action $port).rulesPresent -eq 4)}
    @"
strict_chain
proxy_dns
remote_dns_subnet_cidr_v4 198.18.0.0/15
use_fake_ip_when_hostname_not_matched 1
resolve_locally_if_match_hosts 0
map_resolved_ip_to_host 0
search_for_host_by_resolved_ip 0
first_tunnel_uses_ipv4 1
first_tunnel_uses_ipv6 0
default_target PROXY
tcp_connect_time_out 8000
tcp_read_time_out 8000
log_level 200
[ProxyList]
socks5 127.0.0.1 $port
"@|Set-Content -LiteralPath (Join-Path $bin 'isolation-transparent.conf') -Encoding ASCII
    $label=[guid]::NewGuid().ToString('N').Substring(0,16)
    $process=Start-Process -FilePath (Join-Path $bin 'p0-dns-isolation.exe') -ArgumentList @($IsolationMode,$label,$port,'transparent-public') -WorkingDirectory 'C:\P0Lab' -WindowStyle Hidden -PassThru -Wait -RedirectStandardOutput (Join-Path $output 'probe.jsonl') -RedirectStandardError (Join-Path $output 'probe.stderr.log')
    $records=@(Get-Content -LiteralPath (Join-Path $output 'probe.jsonl')|ForEach-Object {try{$_|ConvertFrom-Json}catch{}})
    $native=@($records|Where-Object isolationResult|Select-Object -Last 1)
    $public=@($records|Where-Object publicCheck|Select-Object -Last 1)
    $report.isolation=if($native.Count){$native[0]}else{$null};$report.publicResult=if($public.Count){$public[0]}else{$null}
    Check 'native_execution_completed' ($process.ExitCode -eq 0 -and $native.Count -eq 1 -and $native[0].error -eq 0 -and $native[0].childExitCode -eq 0 -and -not $native[0].timedOut)
    Check 'public_https_certificate_and_container' ($public.Count -eq 1 -and $public[0].success -and $public[0].tlsVerified -and $public[0].zeroCapabilityAppContainer)
    if($ExpectedProxyIPv4){Check 'observed_exit_matches_verified_proxy_ipv4' ($public[0].observedExitIPv4 -eq $ExpectedProxyIPv4);$report.expectedProxyIPv4=$ExpectedProxyIPv4}
    Check 'native_identity_and_cleanup' ($native[0].isAppContainer -eq 1 -and $native[0].capabilityCount -eq 0 -and $native[0].aclRestored -and $native[0].relayAclRestored -and $native[0].loopbackRestored -and $native[0].profileDeleted)
    if($IsolationMode -eq 'appcontainer-wfp'){Check 'package_scope_without_debug_exemption' ($native[0].packageRulesInstalled -eq 6 -and $native[0].packagePolicyRestored -and -not $native[0].loopbackEnabled)}
    Stop-Process -Id $relay.Id -Force;$relay=$null
    foreach($name in $guards){Check ('relay_exit_rules_persist_'+$name) ((Policy $name 'inspect' '').rulesPresent -eq 4)}
    $report.boundedPublicChecks='passed'
} catch {$report.error=$_.Exception.Message;$report.boundedPublicChecks='failed'}
finally {
    $clean=$true
    foreach($name in $guards){try{if((Policy $name 'remove-fixture-only' '').rulesPresent -ne 0){$clean=$false}}catch{$clean=$false;$report.cleanupError=$_.Exception.Message}}
    foreach($p in @($relay,$bridge)){if($p){$p.Refresh();if(-not $p.HasExited){Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue}}}
    $report.cleanup=if($clean){'verified'}else{'failed'}
    if(Test-Path -LiteralPath (Join-Path $bin 'isolation-transparent.conf')){Remove-Item -LiteralPath (Join-Path $bin 'isolation-transparent.conf')}
    foreach($name in $previous.Keys){[Environment]::SetEnvironmentVariable($name,$previous[$name],'Process')}
    Save-Report
}
