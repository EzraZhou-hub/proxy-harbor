param([ValidatePattern('^[a-f0-9]{8}$')][string]$BridgeRound)
$ErrorActionPreference='Stop'
if((Get-Location).Path -ne 'C:\P0Lab' -or $env:PROXY_HARBOR_P0_GUEST -ne 'offline-lab'){throw 'Guest only.'}
$output='C:\P0Results\edge-diagnostic';New-Item -ItemType Directory -Path $output|Out-Null
function Ready([string]$Path){for($attempt=0;$attempt -lt 150;$attempt++){if(Test-Path -LiteralPath $Path){$line=Get-Content -LiteralPath $Path -TotalCount 1;if($line){return ($line|ConvertFrom-Json)}};Start-Sleep -Milliseconds 100};throw 'Helper readiness timeout.'}
$bridge=$null;$relay=$null
try {
    $bridge=Start-Process -FilePath 'C:\P0Lab\node.exe' -ArgumentList @('scripts\p0\codex-file-bridge.mjs','guest',('C:\P0Results\proxy-bridge-'+$BridgeRound),'900000') -WorkingDirectory 'C:\P0Lab' -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $output 'bridge.jsonl') -RedirectStandardError (Join-Path $output 'bridge.stderr.log')
    $http=(Ready (Join-Path $output 'bridge.jsonl')).address
    $relay=Start-Process -FilePath 'C:\P0Lab\.local\p0\bin\proxy-harbor-p0-relay.exe' -ArgumentList @('-protocol','http','-upstream',$http,'-lease','3m') -WorkingDirectory 'C:\P0Lab' -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $output 'relay.jsonl') -RedirectStandardError (Join-Path $output 'relay.stderr.log')
    $socks=(Ready (Join-Path $output 'relay.jsonl')).address
    foreach($protocol in @('http','socks5')){
        $address=if($protocol -eq 'http'){$http}else{$socks}
        $check=Start-Process -FilePath 'C:\P0Lab\.local\p0\bin\p0-upstream-check.exe' -ArgumentList @('-protocol',$protocol,'-upstream',$address) -WorkingDirectory 'C:\P0Lab' -WindowStyle Hidden -Wait -PassThru -RedirectStandardOutput (Join-Path $output ($protocol+'-transport.json')) -RedirectStandardError (Join-Path $output ($protocol+'-transport.stderr.log'))
        $proxy=if($protocol -eq 'http'){'http://'+$http}else{'socks5://'+$socks}
        $data='C:\P0Lab\edge-diagnostic-'+$protocol;New-Item -ItemType Directory -Path $data|Out-Null
        $browser=Start-Process -FilePath 'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe' -ArgumentList @('--headless=new','--no-first-run','--disable-gpu','--timeout=30000','--dump-dom',('--user-data-dir='+$data),('--proxy-server='+$proxy),'https://api.ipify.org?format=json') -WorkingDirectory 'C:\P0Lab' -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $output ($protocol+'-browser.html')) -RedirectStandardError (Join-Path $output ($protocol+'-browser.stderr.log'))
        $done=$browser.WaitForExit(40000)
        @{protocol=$protocol;browserTimedOut=(-not $done);transportExitCode=$check.ExitCode}|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $output ($protocol+'-result.json')) -Encoding UTF8
        Get-CimInstance Win32_Process -Filter "Name='msedge.exe'" -Property ProcessId,ExecutablePath|Where-Object {$_.ExecutablePath -eq 'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe'}|ForEach-Object {Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue}
        Start-Sleep -Seconds 1
    }
} catch {$_.Exception.Message|Set-Content -LiteralPath (Join-Path $output 'error.txt')}
finally {foreach($process in @($relay,$bridge)){if($process){$process.Refresh();if(-not $process.HasExited){Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue}}}}
