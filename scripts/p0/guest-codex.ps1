param([ValidatePattern('^[a-z0-9-]{1,24}$')][string]$RunIdentifier='initial',[switch]$RealProxyBridge)
$ErrorActionPreference = 'Stop'
if ((Get-Location).Path -ne 'C:\P0Lab' -or $env:PROXY_HARBOR_P0_GUEST -ne 'offline-lab' -or
    $PSCommandPath -ne 'C:\P0Lab\scripts\p0\guest-codex.ps1') { throw 'Fixed disposable guest only.' }
$application = 'C:\P0Lab\codex-app\ChatGPT.exe'
$candidate = 'C:\P0Lab\.local\p0\bin\transparent\proxychains_win32_x64.exe'
$relayExecutable = 'C:\P0Lab\.local\p0\bin\proxy-harbor-p0-relay.exe'
$results = Join-Path 'C:\P0Results' $RunIdentifier
New-Item -ItemType Directory -Path $results | Out-Null
$report = [ordered]@{
    schemaVersion=1;generatedAt=[DateTimeOffset]::UtcNow.ToString('o');overall='not_accepted'
    scope='Real copied Codex desktop; no login; offline startup and proxy-request observation'
    sourcePackage='OpenAI.Codex_26.1106.6628.0_x64__2p2nqsd0c76g0'
    applicationProtectionVerified=$false;systemRulesInstalled=$false;cases=@();cleanup='pending'
}
Add-Type -AssemblyName System.Drawing,System.Windows.Forms,UIAutomationClient,UIAutomationTypes
Add-Type -TypeDefinition @'
using System;
using System.Text;
using System.Collections.Generic;
using System.Runtime.InteropServices;
public static class P0CodexWindows {
    public delegate bool EnumProc(IntPtr window, IntPtr param);
    [DllImport("user32.dll")] static extern bool EnumWindows(EnumProc callback, IntPtr param);
    [DllImport("user32.dll")] static extern bool IsWindowVisible(IntPtr window);
    [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr window, out uint pid);
    [DllImport("user32.dll", CharSet=CharSet.Unicode)] static extern int GetWindowText(IntPtr window, StringBuilder text, int capacity);
    [DllImport("user32.dll", CharSet=CharSet.Unicode)] static extern int GetClassName(IntPtr window, StringBuilder text, int capacity);
    [StructLayout(LayoutKind.Sequential)] struct RECT { public int left,top,right,bottom; }
    [DllImport("user32.dll")] static extern bool GetWindowRect(IntPtr window,out RECT rect);
    [DllImport("user32.dll")] public static extern bool PrintWindow(IntPtr window,IntPtr dc,uint flags);
    public static int[] Size(long handle) { RECT r; if(!GetWindowRect(new IntPtr(handle),out r)) throw new System.ComponentModel.Win32Exception(); return new int[]{r.right-r.left,r.bottom-r.top}; }
    public class Window { public long handle; public uint pid; public string title; public string className; }
    public static Window[] Get(uint[] pids) {
        var found=new List<Window>();
        EnumWindows(delegate(IntPtr h, IntPtr unused) {
            uint pid; GetWindowThreadProcessId(h,out pid);
            if(IsWindowVisible(h) && Array.IndexOf(pids,pid)>=0) {
                var title=new StringBuilder(1024);var name=new StringBuilder(256);
                GetWindowText(h,title,title.Capacity);GetClassName(h,name,name.Capacity);
                found.Add(new Window { handle=h.ToInt64(),pid=pid,title=title.ToString(),className=name.ToString() });
            }
            return true;
        },IntPtr.Zero);
        return found.ToArray();
    }
}
'@
function Get-CopiedProcesses {
    @(Get-CimInstance Win32_Process | Where-Object {
        $_.ExecutablePath -and $_.ExecutablePath.StartsWith('C:\P0Lab\codex-app\',[StringComparison]::OrdinalIgnoreCase)
    })
}
function Stop-CopiedProcesses {
    # Only this isolated guest's copied program tree. Never installed processes.
    for ($attempt=0;$attempt -lt 20;$attempt++) {
        $remaining = @(Get-CopiedProcesses)
        if (-not $remaining.Count) { return }
        foreach ($process in $remaining) {
            try { Stop-Process -Id $process.ProcessId -Force -ErrorAction Stop }
            catch { $_.Exception.Message | Add-Content -LiteralPath (Join-Path $results 'process-cleanup-errors.log') }
        }
        Start-Sleep -Milliseconds 500
    }
    if (@(Get-CopiedProcesses).Count) { throw 'Copied Codex processes remain.' }
}
function Read-Endpoint([string]$Path,[string]$Property) {
    for ($attempt=0;$attempt -lt 80;$attempt++) {
        if (Test-Path -LiteralPath $Path) {
            $line = Get-Content -LiteralPath $Path -TotalCount 1 -ErrorAction SilentlyContinue
            if ($line -and $line.StartsWith('{')) {
                $value = $line | ConvertFrom-Json
                if ($value.$Property) { return [string]$value.$Property }
            }
        }
        Start-Sleep -Milliseconds 100
    }
    throw "No observer/relay ready record: $Path"
}
$savedEnvironment=@{}
$environmentNames=@('HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','NO_PROXY','CODEX_ELECTRON_USER_DATA_PATH','CODEX_HOME','APPDATA','LOCALAPPDATA','TEMP','TMP','P0_EXPECTED_RELAY_PID','ELECTRON_RUN_AS_NODE')
foreach($name in $environmentNames){$savedEnvironment[$name]=[Environment]::GetEnvironmentVariable($name,'Process')}
try {
    Stop-CopiedProcesses
    $fileBridge=$null;$bridgeAddress=$null
    if($RealProxyBridge){
        $bridgeLog=Join-Path $results 'file-bridge.jsonl'
        $fileBridge=Start-Process -FilePath 'C:\P0Lab\node.exe' -ArgumentList @('scripts\p0\codex-file-bridge.mjs','guest','C:\P0Results\proxy-bridge') -WorkingDirectory 'C:\P0Lab' -WindowStyle Hidden -PassThru -RedirectStandardOutput $bridgeLog -RedirectStandardError (Join-Path $results 'file-bridge.stderr.log')
        $bridgeAddress=Read-Endpoint $bridgeLog 'address'
        $report.scope='Real copied Codex desktop; fresh data; disabled guest NIC; file bridge to host loopback proxy'
        $check=Start-Process -FilePath 'C:\P0Lab\.local\p0\bin\p0-upstream-check.exe' -ArgumentList @('-protocol','http','-upstream',$bridgeAddress) -WindowStyle Hidden -Wait -PassThru -RedirectStandardOutput (Join-Path $results 'bridge-https-check.json') -RedirectStandardError (Join-Path $results 'bridge-https-check.stderr.log')
        if($check.ExitCode -ne 0){throw 'Real proxy bridge HTTPS verification failed.'}
        $report.bridgeHTTPSCheck=Get-Content -LiteralPath (Join-Path $results 'bridge-https-check.json') -Raw|ConvertFrom-Json
    }
    foreach ($mode in @('baseline','explicit-proxy','transparent-candidate')) {
        $record=[ordered]@{mode=$mode;startedAt=[DateTimeOffset]::UtcNow.ToString('o');status='pending';samples=@();proxyRequests=@();cleanup='pending'}
        $report.cases+=,$record
        $observer=$null;$relay=$null;$launcher=$null
        $caseDirectory=Join-Path ('C:\P0Lab\codex-test-data\'+$RunIdentifier) $mode
        New-Item -ItemType Directory -Path $caseDirectory | Out-Null
        foreach($folder in @('user-data','codex-home','appdata','localappdata','temp')) { New-Item -ItemType Directory -Path (Join-Path $caseDirectory $folder) | Out-Null }
        try {
            foreach($name in @('HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','NO_PROXY','P0_EXPECTED_RELAY_PID','ELECTRON_RUN_AS_NODE')){[Environment]::SetEnvironmentVariable($name,$null,'Process')}
            $env:CODEX_ELECTRON_USER_DATA_PATH=Join-Path $caseDirectory 'user-data'
            $env:CODEX_HOME=Join-Path $caseDirectory 'codex-home'
            $env:APPDATA=Join-Path $caseDirectory 'appdata'
            $env:LOCALAPPDATA=Join-Path $caseDirectory 'localappdata'
            $env:TEMP=Join-Path $caseDirectory 'temp';$env:TMP=$env:TEMP
            $observerLog=Join-Path $results ($mode+'-observer.jsonl')
            $observer=Start-Process -FilePath 'C:\P0Lab\node.exe' -ArgumentList 'scripts\p0\codex-proxy-observer.mjs' -WorkingDirectory 'C:\P0Lab' -WindowStyle Hidden -PassThru -RedirectStandardOutput $observerLog -RedirectStandardError (Join-Path $results ($mode+'-observer.stderr.log'))
            $observerAddress=Read-Endpoint $observerLog 'address'
            if($RealProxyBridge){$observerAddress=$bridgeAddress;$record.upstream='file_bridge_to_host_loopback_proxy'}
            $executable=$application;$arguments=@()
            if($mode -eq 'explicit-proxy') {
                $env:HTTP_PROXY='http://'+$observerAddress;$env:HTTPS_PROXY=$env:HTTP_PROXY;$env:ALL_PROXY=$env:HTTP_PROXY
                $arguments=@('--proxy-server='+$env:HTTP_PROXY)
            } elseif($mode -eq 'transparent-candidate') {
                $relayLog=Join-Path $results ($mode+'-relay.jsonl')
                $relay=Start-Process -FilePath $relayExecutable -ArgumentList @('-protocol','http','-upstream',$observerAddress,'-lease','2m') -WorkingDirectory 'C:\P0Lab' -WindowStyle Hidden -PassThru -RedirectStandardOutput $relayLog -RedirectStandardError (Join-Path $results ($mode+'-relay.stderr.log'))
                $relayAddress=Read-Endpoint $relayLog 'address'
                $relayPort=($relayAddress -split ':')[-1]
                $configuration=Join-Path $caseDirectory 'proxychains.conf'
                "strict_chain`nproxy_dns`nremote_dns_subnet_cidr_v4 198.18.0.0/15`nuse_fake_ip_when_hostname_not_matched 1`nresolve_locally_if_match_hosts 0`nmap_resolved_ip_to_host 0`nsearch_for_host_by_resolved_ip 0`nfirst_tunnel_uses_ipv4 1`nfirst_tunnel_uses_ipv6 0`ndefault_target PROXY`ntcp_connect_time_out 1000`ntcp_read_time_out 1000`nlog_level 200`n[ProxyList]`nsocks5 127.0.0.1 $relayPort`n" | Set-Content -LiteralPath $configuration -Encoding ASCII
                $env:P0_EXPECTED_RELAY_PID=[string]$relay.Id
                $executable=$candidate;$arguments=@('-q','-f',$configuration,$application)
            }
            $launchParameters=@{FilePath=$executable;WorkingDirectory='C:\P0Lab\codex-app';PassThru=$true;RedirectStandardOutput=(Join-Path $results ($mode+'-application.log'));RedirectStandardError=(Join-Path $results ($mode+'-application.stderr.log'))}
            if($arguments.Count){$launchParameters.ArgumentList=$arguments}
            $launcher=Start-Process @launchParameters
            $record.launcherPid=$launcher.Id
            for($sample=0;$sample -lt 6;$sample++) {
                Start-Sleep -Seconds 5
                $processes=@(Get-CopiedProcesses)
                $details=@($processes | ForEach-Object {
                    $modules=@();$moduleError=$null;$moduleCount=0;$role='main';$utility=$null
                    if($_.CommandLine -match '--type=([a-zA-Z0-9-]+)'){$role=$Matches[1]}
                    if($_.CommandLine -match '--utility-sub-type=([a-zA-Z0-9_.-]+)'){$utility=$Matches[1]}
                    if($_.ExecutablePath.EndsWith('\resources\codex.exe',[StringComparison]::OrdinalIgnoreCase)){$role='codex-backend'}
                    try {$loaded=@((Get-Process -Id $_.ProcessId -ErrorAction Stop).Modules);$moduleCount=$loaded.Count;$modules=@($loaded | Where-Object {$_.ModuleName -eq 'proxychains_hook_x64.dll'} | Select-Object -ExpandProperty FileName)} catch {$moduleError=$_.Exception.Message}
                    @{pid=$_.ProcessId;parentPid=$_.ParentProcessId;path=$_.ExecutablePath;role=$role;utility=$utility;moduleCount=$moduleCount;hookModules=$modules;moduleReadError=$moduleError}
                })
                $windows=@([P0CodexWindows]::Get([uint32[]]@($processes.ProcessId)))
                $record.samples+=@{seconds=5*($sample+1);processes=$details;windows=$windows}
                if($sample -eq 5 -or (-not $processes.Count -and $launcher.HasExited)) {
                    try {
                        if(-not $windows.Count){throw 'No visible target window.'}
                        $size=[P0CodexWindows]::Size($windows[0].handle)
                        if($size[0] -lt 1 -or $size[1] -lt 1 -or $size[0] -gt 4096 -or $size[1] -gt 4096){throw 'Unexpected target window size.'}
                        $bitmap=New-Object Drawing.Bitmap $size[0],$size[1]
                        $graphics=[Drawing.Graphics]::FromImage($bitmap)
                        try {
                            $dc=$graphics.GetHdc()
                            try {$printed=[P0CodexWindows]::PrintWindow([IntPtr]$windows[0].handle,$dc,2)} finally {$graphics.ReleaseHdc($dc)}
                            if(-not $printed){throw 'Target window capture failed.'}
                            $bitmap.Save((Join-Path $results ($mode+'.png')),[Drawing.Imaging.ImageFormat]::Png)
                            $record.windowCaptureApiSucceeded=$true
                        } finally {$graphics.Dispose();$bitmap.Dispose()}
                    } catch {$record.windowCaptureError=$_.Exception.Message}
                    $ui=@()
                    foreach($window in $windows) {
                        try {
                            $root=[Windows.Automation.AutomationElement]::FromHandle([IntPtr]$window.handle)
                            $elements=$root.FindAll([Windows.Automation.TreeScope]::Descendants,[Windows.Automation.Condition]::TrueCondition)
                            $ui+=@($elements | Select-Object -First 100 | ForEach-Object {@{name=$_.Current.Name;type=$_.Current.ControlType.ProgrammaticName}})
                        } catch {$record.uiReadError=$_.Exception.Message}
                    }
                    $record.ui=$ui
                    break
                }
            }
            $launcher.Refresh();$record.launcherExited=$launcher.HasExited
            if($launcher.HasExited){$record.launcherExitCode=$launcher.ExitCode}
            $record.dataDirectoryCreated=Test-Path -LiteralPath (Join-Path $caseDirectory 'user-data\Local State')
            $record.nativeProfileDataCreated=Test-Path -LiteralPath (Join-Path $env:APPDATA 'Codex\web\Codex\Local State')
            $record.userDataFiles=@(Get-ChildItem -LiteralPath (Join-Path $caseDirectory 'user-data') -Recurse -File | Select-Object -ExpandProperty Name -First 30)
            $record.status='observed'
        } catch {$record.status='error';$record.error=$_.Exception.Message}
        finally {
            Stop-CopiedProcesses
            foreach($process in @($launcher,$relay,$observer)) {if($process){$process.Refresh();if(-not $process.HasExited){Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue}}}
            if(Test-Path -LiteralPath $observerLog) {
                $record.proxyRequests=@(Get-Content -LiteralPath $observerLog | ForEach-Object {try{$item=$_|ConvertFrom-Json;if($item.event -eq 'request'){$item}}catch{}})
            }
            $record.cleanup=if(@(Get-CopiedProcesses).Count -eq 0){'verified'}else{'failed'}
            $report | ConvertTo-Json -Depth 15 | Set-Content -LiteralPath (Join-Path $results 'codex-report.json') -Encoding UTF8
        }
    }
    $report.cleanup='verified'
} catch {$report.error=$_.Exception.Message}
finally {
    if($fileBridge){$fileBridge.Refresh();if(-not $fileBridge.HasExited){Stop-Process -Id $fileBridge.Id -Force -ErrorAction SilentlyContinue}}
    foreach($name in $savedEnvironment.Keys){[Environment]::SetEnvironmentVariable($name,$savedEnvironment[$name],'Process')}
    $report | ConvertTo-Json -Depth 15 | Set-Content -LiteralPath (Join-Path $results 'codex-report.json') -Encoding UTF8
}
