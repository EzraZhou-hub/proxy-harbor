$ErrorActionPreference='Stop'
if((Get-Location).Path -ne 'C:\P0Lab' -or $env:PROXY_HARBOR_P0_GUEST -ne 'offline-lab' -or $PSCommandPath -ne 'C:\P0Lab\scripts\p0\guest-codex-login.ps1'){throw 'Fixed disposable guest only.'}
$output='C:\P0Results\manual'
New-Item -ItemType Directory -Path $output | Out-Null
$state=[ordered]@{schemaVersion=1;state='preflight';flow='explicit_proxy_browser';applicationProtectionVerified=$false;credentialsCollected=$false;applicationLogsCollected=$false;automaticScreenshots=$false}
function Save-State {$state|ConvertTo-Json -Depth 8|Set-Content -LiteralPath (Join-Path $output 'state.json') -Encoding UTF8}
function Ready-Record([string]$Path){
    for($attempt=0;$attempt -lt 150;$attempt++){
        if(Test-Path -LiteralPath $Path){$line=Get-Content -LiteralPath $Path -TotalCount 1;if($line){return ($line|ConvertFrom-Json)}}
        Start-Sleep -Milliseconds 100
    }
    throw 'Helper did not become ready.'
}
Save-State
$bridge=$null;$fixture=$null
try {
    $private='C:\P0Lab\codex-login-data'
    foreach($name in @('appdata','localappdata','codex-home','user-data','temp','edge-preflight')){New-Item -ItemType Directory -Path (Join-Path $private $name) -Force|Out-Null}
    $env:APPDATA=Join-Path $private 'appdata';$env:LOCALAPPDATA=Join-Path $private 'localappdata'
    $env:CODEX_HOME=Join-Path $private 'codex-home';$env:CODEX_ELECTRON_USER_DATA_PATH=Join-Path $private 'user-data'
    $env:TEMP=Join-Path $private 'temp';$env:TMP=$env:TEMP
    $bridgeLog=Join-Path $output 'bridge.jsonl'
    $bridge=Start-Process -FilePath 'C:\P0Lab\node.exe' -ArgumentList @('scripts\p0\codex-file-bridge.mjs','guest','C:\P0Results\proxy-bridge','900000') -WorkingDirectory 'C:\P0Lab' -WindowStyle Hidden -PassThru -RedirectStandardOutput $bridgeLog -RedirectStandardError (Join-Path $output 'bridge.stderr.log')
    $address=(Ready-Record $bridgeLog).address
    if($address -notmatch '^127\.0\.0\.1:[0-9]+$'){throw 'Invalid loopback bridge.'}
    $clock=[Diagnostics.Stopwatch]::StartNew()
    $env:HTTP_PROXY='http://'+$address;$env:HTTPS_PROXY=$env:HTTP_PROXY;$env:ALL_PROXY=$env:HTTP_PROXY;$env:NO_PROXY='localhost,127.0.0.1,::1'
    # Guest-only user settings and guest-only Edge policy. No host registry.
    $internet='HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
    New-ItemProperty -Path $internet -Name ProxyEnable -Value 1 -PropertyType DWord -Force|Out-Null
    New-ItemProperty -Path $internet -Name ProxyServer -Value $address -PropertyType String -Force|Out-Null
    New-ItemProperty -Path $internet -Name ProxyOverride -Value 'localhost;127.0.0.1;[::1]' -PropertyType String -Force|Out-Null
    $edgePolicy='HKCU:\Software\Policies\Microsoft\Edge'
    New-Item -Path $edgePolicy -Force|Out-Null
    $policy=@{ProxyMode='fixed_servers';ProxyServer=$env:HTTP_PROXY;ProxyBypassList='localhost;127.0.0.1;[::1]'}|ConvertTo-Json -Compress
    New-ItemProperty -Path $edgePolicy -Name ProxySettings -Value $policy -PropertyType String -Force|Out-Null
    $edge='C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe'
    if(-not (Test-Path -LiteralPath $edge)){throw 'Guest Edge is unavailable.'}
    $fixtureLog=Join-Path $output 'callback-fixture.jsonl'
    $fixture=Start-Process -FilePath 'C:\P0Lab\node.exe' -ArgumentList 'scripts\p0\codex-callback-fixture.mjs' -WorkingDirectory 'C:\P0Lab' -WindowStyle Hidden -PassThru -RedirectStandardOutput $fixtureLog -RedirectStandardError (Join-Path $output 'callback-fixture.stderr.log')
    $callbackPort=(Ready-Record $fixtureLog).port
    foreach($check in @('public','loopback')){
        $target=if($check -eq 'public'){'https://api.ipify.org?format=json'}else{'http://127.0.0.1:'+ $callbackPort +'/p0-callback-test'}
        $dom=Join-Path $output ($check+'-preflight.html')
        $arguments=@('--headless=new','--no-first-run','--disable-gpu','--dump-dom',('--user-data-dir='+ (Join-Path $private 'edge-preflight')),$target)
        $process=Start-Process -FilePath $edge -ArgumentList $arguments -WindowStyle Hidden -PassThru -RedirectStandardOutput $dom -RedirectStandardError (Join-Path $output ($check+'-preflight.stderr.log'))
        if(-not $process.WaitForExit(45000)){Stop-Process -Id $process.Id -Force;throw ('Guest browser preflight timed out: '+$check)}
        $content=Get-Content -LiteralPath $dom -Raw
        if($check -eq 'public'){
            if($content -notmatch '\{"ip":"([0-9.]+)"\}'){throw 'Guest browser public HTTPS response was not obtained.'}
            $state.browserObservedExitIPv4=$Matches[1];$state.browserPublicHTTPS=$true
        } else {
            if($content -notlike '*P0 loopback callback OK*'){throw 'Guest browser loopback bypass failed.'}
            $state.browserLoopbackBypass=$true
        }
    }
    Stop-Process -Id $fixture.Id -Force -ErrorAction SilentlyContinue;$fixture=$null
    Add-Type -TypeDefinition @'
using System;
using System.Diagnostics;
public static class P0LoginLaunch {
    public static Process Start(string proxy) {
        var info=new ProcessStartInfo(@"C:\P0Lab\codex-app\ChatGPT.exe","--proxy-server="+proxy);
        info.WorkingDirectory=@"C:\P0Lab\codex-app";info.UseShellExecute=false;
        info.RedirectStandardOutput=true;info.RedirectStandardError=true;
        var process=new Process();process.StartInfo=info;
        process.OutputDataReceived+=delegate(object sender,DataReceivedEventArgs args){};
        process.ErrorDataReceived+=delegate(object sender,DataReceivedEventArgs args){};
        process.Start();process.BeginOutputReadLine();process.BeginErrorReadLine();return process;
    }
}
'@
    $application=[P0LoginLaunch]::Start($env:HTTP_PROXY)
    Start-Sleep -Seconds 12
    $state.applicationPid=$application.Id;$state.bridgePid=$bridge.Id;$state.proxyAddress=$address
    $state.state='awaiting_user_login';$state.remainingNetworkSeconds=[Math]::Max(0,900-[int]$clock.Elapsed.TotalSeconds)
    $state.nextAction='Use Continue to sign in inside this Sandbox; no credentials in chat.'
    Save-State
    while($clock.Elapsed.TotalSeconds -lt 900){
        if(Test-Path -LiteralPath 'C:\P0Results\manual-finish.json'){$state.state='user_reported_finished';Save-State;break}
        Start-Sleep -Seconds 1
    }
    if($state.state -eq 'awaiting_user_login'){$state.state='network_permission_expired';$state.remainingNetworkSeconds=0;Save-State}
} catch {$state.state='preflight_failed';$state.error=$_.Exception.Message;Save-State}
finally {
    if($fixture){Stop-Process -Id $fixture.Id -Force -ErrorAction SilentlyContinue}
    if($bridge){Stop-Process -Id $bridge.Id -Force -ErrorAction SilentlyContinue}
}
