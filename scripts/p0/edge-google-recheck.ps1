param([ValidatePattern('^[a-f0-9]{8}$')][string]$BridgeRound)
$ErrorActionPreference='Stop'
if((Get-Location).Path -ne 'C:\P0Lab' -or $env:PROXY_HARBOR_P0_GUEST -ne 'offline-lab'){throw 'Guest only.'}
$output='C:\P0Results\edge-google-recheck';New-Item -ItemType Directory -Path $output|Out-Null
$guard='C:\P0Lab\.local\p0\bin\p0-edge-guard.exe';$bridge=$null;$relay=$null
$report=[ordered]@{overall='not_accepted';applicationProtectionVerified=$false;attempts=@();cleanup='pending';scope='Single public-page recheck; same project SOCKS5 path; fixed guest Edge policy'}
function Ready([string]$Path){for($i=0;$i -lt 150;$i++){if(Test-Path -LiteralPath $Path){$line=Get-Content -LiteralPath $Path -TotalCount 1;if($line){return ($line|ConvertFrom-Json)}};Start-Sleep -Milliseconds 100};throw 'Readiness timed out.'}
try {
    $bridge=Start-Process -FilePath 'C:\P0Lab\node.exe' -ArgumentList @('scripts\p0\codex-file-bridge.mjs','guest',('C:\P0Results\proxy-bridge-'+$BridgeRound),'900000') -WorkingDirectory 'C:\P0Lab' -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $output 'bridge.jsonl') -RedirectStandardError (Join-Path $output 'bridge.stderr.log')
    $http=(Ready (Join-Path $output 'bridge.jsonl')).address
    $relay=Start-Process -FilePath 'C:\P0Lab\.local\p0\bin\proxy-harbor-p0-relay.exe' -ArgumentList @('-protocol','http','-upstream',$http,'-lease','5m') -WorkingDirectory 'C:\P0Lab' -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $output 'relay.jsonl') -RedirectStandardError (Join-Path $output 'relay.stderr.log')
    $address=(Ready (Join-Path $output 'relay.jsonl')).address;$port=($address -split ':')[-1]
    $installed=(& $guard install-fixture-only $port)|ConvertFrom-Json
    if($LASTEXITCODE -ne 0 -or $installed.rulesPresent -ne 4){throw 'Expected four Edge restrictions.'}
    for($attempt=1;$attempt -le 2;$attempt++){
        $data='C:\P0Lab\google-recheck-'+$attempt;New-Item -ItemType Directory -Path $data|Out-Null
        $dom=Join-Path $output ('google-'+$attempt+'.html')
        $process=Start-Process -FilePath 'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe' -ArgumentList @('--headless=new','--no-first-run','--disable-gpu','--disable-background-networking','--timeout=45000','--dump-dom',('--user-data-dir='+$data),('--proxy-server=socks5://'+$address),('--screenshot='+ (Join-Path $output ('google-'+$attempt+'.png'))),'--window-size=1280,900','https://www.google.com/') -WorkingDirectory 'C:\P0Lab' -WindowStyle Hidden -PassThru -RedirectStandardOutput $dom -RedirectStandardError (Join-Path $output ('google-'+$attempt+'.stderr.log'))
        $finished=$process.WaitForExit(55000)
        $content=[string](Get-Content -LiteralPath $dom -Raw)
        $observed=$content -match '<title>Google</title>'
        $report.attempts+=@{attempt=$attempt;captureBudgetMs=45000;timedOut=(-not $finished);expectedContentObserved=$observed}
        Get-CimInstance Win32_Process -Filter "Name='msedge.exe'" -Property ProcessId,ExecutablePath|Where-Object {$_.ExecutablePath -eq 'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe'}|ForEach-Object {Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue}
        if($observed){$report.googleObserved=$true;break}
    }
} catch {$report.error=$_.Exception.Message}
finally {
    $removed=(& $guard remove-fixture-only)|ConvertFrom-Json
    $report.cleanup=if($LASTEXITCODE -eq 0 -and $removed.rulesPresent -eq 0){'verified'}else{'failed'}
    foreach($process in @($bridge,$relay)){if($process){$process.Refresh();if(-not $process.HasExited){Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue}}}
    $report|ConvertTo-Json -Depth 8|Set-Content -LiteralPath (Join-Path $output 'report.json') -Encoding UTF8
}
