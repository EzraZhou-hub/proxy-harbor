param([ValidatePattern('^[a-z0-9-]{0,24}$')][string]$RunIdentifier='', [ValidatePattern('^([a-f0-9]{8})?$')][string]$BridgeRound='', [switch]$NetworkTrace)
$ErrorActionPreference='Stop'
if((Get-Location).Path -ne 'C:\P0Lab' -or $env:PROXY_HARBOR_P0_GUEST -ne 'offline-lab' -or $PSCommandPath -ne 'C:\P0Lab\scripts\p0\guest-edge.ps1'){throw 'Fixed disposable Edge guest required.'}
$output=if($RunIdentifier){'C:\P0Results\edge-'+$RunIdentifier}else{'C:\P0Results\edge'}
$privateRun=if($RunIdentifier){$RunIdentifier}else{'initial'}
New-Item -ItemType Directory -Path $output|Out-Null
$edge='C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe'
$guard='C:\P0Lab\.local\p0\bin\p0-edge-guard.exe'
$report=[ordered]@{schemaVersion=1;overall='not_accepted';applicationProtectionVerified=$false;checks=[ordered]@{};cases=@();cleanup='pending';scope='Guest Edge explicit SOCKS proxy and independent fixed-identity TCP blocking; guest NIC disabled'}
$bridge=$null;$relay=$null;$canary=$null
function Save-Report {$report|ConvertTo-Json -Depth 14|Set-Content -LiteralPath (Join-Path $output 'report.json') -Encoding UTF8}
function Check([string]$Name,[bool]$Value){$report.checks[$Name]=$Value;Save-Report;if(-not $Value){throw ('Observation failed: '+$Name)}}
function Ready([string]$Path){for($attempt=0;$attempt -lt 200;$attempt++){if(Test-Path -LiteralPath $Path){$line=Get-Content -LiteralPath $Path -TotalCount 1;if($line){return ($line|ConvertFrom-Json)}};Start-Sleep -Milliseconds 100};throw 'Helper readiness timed out.'}
function Policy([string]$Action,[string]$Port){$args=@($Action);if($Port){$args+=,$Port};$line=& $guard @args;$value=$line|ConvertFrom-Json;if($LASTEXITCODE -ne 0 -or $value.windowsError -ne 0){throw ('Guest policy action failed: '+$Action)};return $value}
function Stop-Edge {
    for($attempt=0;$attempt -lt 20;$attempt++){
        $processes=@(Get-CimInstance Win32_Process -Filter "Name='msedge.exe'" -Property ProcessId,ExecutablePath|Where-Object {$_.ExecutablePath -eq $edge})
        if(-not $processes.Count){return}
        foreach($process in $processes){Stop-Process -Id $process.ProcessId -Force -ErrorAction SilentlyContinue}
        Start-Sleep -Milliseconds 300
    }
    throw 'Guest test browser processes remain.'
}
function Browser([string]$Name,[string]$Url,[string]$Proxy,[string]$Expected,[switch]$Screenshot){
    $data=Join-Path ('C:\P0Lab\edge-test-data\'+$privateRun) $Name
    New-Item -ItemType Directory -Path $data|Out-Null
    $dom=Join-Path $output ($Name+'.html')
    $arguments=@('--headless=new','--no-first-run','--disable-gpu','--disable-background-networking','--timeout=30000','--dump-dom',('--user-data-dir='+$data))
    if($NetworkTrace){$arguments+=('--log-net-log='+ (Join-Path $output ($Name+'-netlog.json')))}
    if($Proxy){$arguments+=('--proxy-server='+$Proxy)}else{$arguments+='--no-proxy-server'}
    if($Screenshot){$arguments+=('--screenshot='+ (Join-Path $output ($Name+'.png')));$arguments+='--window-size=1280,900'}
    $arguments+=$Url
    $case=[ordered]@{name=$Name;url=$Url;proxy=$Proxy;timedOut=$false;captureBudgetMs=30000;expectedContentObserved=$false;edgeProcesses=@()}
    $report.cases+=,$case
    try {
        $process=Start-Process -FilePath $edge -ArgumentList $arguments -WorkingDirectory 'C:\P0Lab' -WindowStyle Hidden -PassThru -RedirectStandardOutput $dom -RedirectStandardError (Join-Path $output ($Name+'.stderr.log'))
        Start-Sleep -Seconds 1
        $case.edgeProcesses=@(Get-CimInstance Win32_Process -Filter "Name='msedge.exe'" -Property ProcessId,ParentProcessId,ExecutablePath|Where-Object {$_.ExecutablePath -eq $edge}|Select-Object ProcessId,ParentProcessId,ExecutablePath)
        if(-not $process.WaitForExit(40000)){$case.timedOut=$true}
        if(Test-Path -LiteralPath $dom){$text=[string](Get-Content -LiteralPath $dom -Raw);$case.expectedContentObserved=[bool]($text -match $Expected);$case.networkErrorMarkers=@([regex]::Matches($text,'ERR_[A-Z_]+')|ForEach-Object {$_.Value}|Sort-Object -Unique)}
    } finally {Stop-Edge;Save-Report}
    return $case
}
function Canary-Test([string]$Name,[string]$Base,[bool]$Expected){
    $nonce=[guid]::NewGuid().ToString('N').Substring(0,16)
    $case=Browser $Name ($Base+'/edge-'+$nonce) '' 'EDGE-CANARY'
    $observed=@(Get-Content -LiteralPath (Join-Path $output 'canary.jsonl')|ForEach-Object {$_|ConvertFrom-Json}|Where-Object {$_.event -eq 'request' -and $_.nonce -eq $nonce})
    $case.wireObservations=$observed
    Check ($Name+'_browser_result') ($case.expectedContentObserved -eq $Expected)
    Check ($Name+'_endpoint_result') (($observed.Count -gt 0) -eq $Expected)
    if($Expected){Check ($Name+'_client_is_real_edge') (@($observed|Where-Object {$_.ownerQuerySucceeded -and $_.owner.path -eq $edge}).Count -gt 0)}
}
try {
    $report.edgeVersion=(Get-Item -LiteralPath $edge).VersionInfo.FileVersion
    $report.edgeSHA256=(Get-FileHash -LiteralPath $edge).Hash
    Check 'clean_initial_policy' ((Policy 'inspect' '').rulesPresent -eq 0)
    $canaryLog=Join-Path $output 'canary.jsonl'
    $canary=Start-Process -FilePath 'C:\P0Lab\node.exe' -ArgumentList 'scripts\p0\edge-canary.mjs' -WorkingDirectory 'C:\P0Lab' -WindowStyle Hidden -PassThru -RedirectStandardOutput $canaryLog -RedirectStandardError (Join-Path $output 'canary.stderr.log')
    $endpoints=Ready $canaryLog
    Canary-Test 'baseline-ipv4' $endpoints.ipv4 $true
    Canary-Test 'baseline-ipv6' $endpoints.ipv6 $true
    $bridgeLog=Join-Path $output 'bridge.jsonl'
    $bridgeRoot=if($BridgeRound){'C:\P0Results\proxy-bridge-'+$BridgeRound}else{'C:\P0Results\proxy-bridge'}
    $bridge=Start-Process -FilePath 'C:\P0Lab\node.exe' -ArgumentList @('scripts\p0\codex-file-bridge.mjs','guest',$bridgeRoot,'900000') -WorkingDirectory 'C:\P0Lab' -WindowStyle Hidden -PassThru -RedirectStandardOutput $bridgeLog -RedirectStandardError (Join-Path $output 'bridge.stderr.log')
    $address=(Ready $bridgeLog).address
    $relayLog=Join-Path $output 'relay.jsonl'
    $relay=Start-Process -FilePath 'C:\P0Lab\.local\p0\bin\proxy-harbor-p0-relay.exe' -ArgumentList @('-protocol','http','-upstream',$address,'-lease','5m') -WorkingDirectory 'C:\P0Lab' -WindowStyle Hidden -PassThru -RedirectStandardOutput $relayLog -RedirectStandardError (Join-Path $output 'relay.stderr.log')
    $relayAddress=(Ready $relayLog).address;$port=($relayAddress -split ':')[-1]
    $report.relayAddress=$relayAddress;$report.relayPid=$relay.Id
    $browserProxy='socks5://'+$relayAddress
    $report.proxyPath='Edge SOCKS5 -> project relay/gate -> guest file bridge -> host HTTP proxy'
    $baselineProxy=Browser 'baseline-proxy-public' 'https://api.ipify.org?format=json' $browserProxy '\{"ip":"[0-9.]+"\}'
    Check 'project_proxy_works_before_rules' $baselineProxy.expectedContentObserved
    $report.installedPolicy=Policy 'install-fixture-only' $port
    Check 'four_persistent_rules_installed' ($report.installedPolicy.rulesPresent -eq 4)
    foreach($site in @(
        @{name='public-ip';url='https://api.ipify.org?format=json';expected='\{"ip":"[0-9.]+"\}'},
        @{name='example';url='https://example.com/';expected='<title>Example Domain</title>'},
        @{name='google';url='https://www.google.com/';expected='<title>Google</title>'},
        @{name='wikipedia';url='https://www.wikipedia.org/';expected='<title>Wikipedia</title>'}
    )){
        $case=Browser $site.name $site.url $browserProxy $site.expected -Screenshot
        $report.checks[$site.name+'_through_project_relay']=$case.expectedContentObserved
        Save-Report
    }
    Canary-Test 'guarded-ipv4-direct' $endpoints.ipv4 $false
    Canary-Test 'guarded-ipv6-direct' $endpoints.ipv6 $false
    # A different executable still reaches the same controlled endpoint.
    $controlUrl=$endpoints.ipv4+'/control-'+[guid]::NewGuid().ToString('N').Substring(0,16)
    $control=Start-Process -FilePath 'C:\P0Lab\node.exe' -ArgumentList @('-e',('require(''http'').get('''+$controlUrl+''',r=>{r.resume();r.on(''end'',()=>process.exit(r.statusCode===200?0:1))}).on(''error'',()=>process.exit(1))')) -WorkingDirectory 'C:\P0Lab' -WindowStyle Hidden -Wait -PassThru
    Check 'other_application_unaffected' ($control.ExitCode -eq 0)
    Stop-Process -Id $relay.Id -Force -ErrorAction Stop;$relay=$null
    $down=Browser 'relay-down-public' 'https://api.ipify.org?format=json' $browserProxy '\{"ip":"[0-9.]+"\}'
    Check 'public_request_fails_after_relay_exit' (-not $down.expectedContentObserved)
    Check 'independent_rules_remain_after_relay_exit' ((Policy 'inspect' '').rulesPresent -eq 4)
    Canary-Test 'relay-down-ipv4-direct' $endpoints.ipv4 $false
    Canary-Test 'relay-down-ipv6-direct' $endpoints.ipv6 $false
    Check 'explicit_rule_removal' ((Policy 'remove-fixture-only' '').rulesPresent -eq 0)
    Canary-Test 'restored-ipv4-direct' $endpoints.ipv4 $true
    Canary-Test 'restored-ipv6-direct' $endpoints.ipv6 $true
    $report.boundedEdgeTCPChecks=if(@($report.checks.Values|Where-Object {-not $_}).Count){'completed_with_failed_checks'}else{'passed'}
} catch {$report.error=$_.Exception.Message}
finally {
    try {Stop-Edge;$removed=Policy 'remove-fixture-only' '';if($removed.rulesPresent -ne 0){throw 'Rules remain'};$report.cleanup='verified'} catch {$report.cleanup='failed';$report.cleanupError=$_.Exception.Message}
    foreach($process in @($relay,$bridge,$canary)){if($process){$process.Refresh();if(-not $process.HasExited){Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue}}}
    Save-Report
}
