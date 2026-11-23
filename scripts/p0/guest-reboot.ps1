param([switch]$AfterRestart)
$ErrorActionPreference='Stop'
if(((-not $AfterRestart) -and $env:PROXY_HARBOR_P0_GUEST -ne 'offline-lab') -or (Get-Location).Path -ne 'C:\P0Lab' -or -not (Test-Path 'C:\P0Lab\manifest.json')){throw 'Guest reboot harness only.'}
$lab='C:\P0Lab\.local\p0'
$summaryPath='C:\P0Results\sandbox-summary.json'
function Run-Test($name,$log){
    $p=Start-Process -FilePath "$lab\bin\p0-policy-tests.exe" -ArgumentList @('-test.v',('-test.run=^'+$name+'$'),'-test.timeout=150s') -WorkingDirectory 'C:\P0Lab' -WindowStyle Hidden -Wait -PassThru -RedirectStandardOutput "$lab\$log.log" -RedirectStandardError "$lab\$log.stderr.log"
    if($p.ExitCode -ne 0){throw "Guest recovery test failed: $name"}
}
if(-not $AfterRestart){
    Run-Test 'TestP0RecoveryPreparation' 'reboot-preparation'
    (Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o')|Set-Content "$lab\reboot-before.txt"
    # This task exists only inside the disposable guest and deletes itself.
    $action=New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-NoProfile -ExecutionPolicy Bypass -File C:\P0Lab\scripts\p0\guest-reboot.ps1 -AfterRestart' -WorkingDirectory 'C:\P0Lab'
    $trigger=New-ScheduledTaskTrigger -AtStartup
    Register-ScheduledTask -TaskName 'ProxyHarborP0Recovery' -Action $action -Trigger $trigger -User 'SYSTEM' -RunLevel Highest -Force|Out-Null
    'authorized-one-guest-restart'|Set-Content "$lab\reboot-pending.txt"
    Restart-Computer -Force
    return
}
# Startup tasks do not inherit the previous process environment.
if(-not (Test-Path "$lab\reboot-pending.txt")){throw 'No authorized pending guest restart.'}
$env:PROXY_HARBOR_P0_GUEST='offline-lab'
$summary=$null
try {
    for($i=0;$i -lt 20 -and -not (Test-Path $summaryPath);$i++){Start-Sleep -Seconds 2}
    $summary=Get-Content $summaryPath -Raw|ConvertFrom-Json
    (Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o')|Set-Content "$lab\reboot-after.txt"
    Run-Test 'TestP0RecoveryAfterBoot' 'reboot-after'
    $summary.rebootChecks='passed';$summary.rebootCleanup='verified'
} catch {
    if($null -eq $summary){$summary=[pscustomobject]@{overall='not_accepted';rebootChecks='failed';rebootCleanup='unverified';state='complete'}}
    $summary.rebootChecks='failed';$summary|Add-Member -NotePropertyName error -NotePropertyValue $_.Exception.Message -Force
} finally {
    if($summary){$summary.state='complete';$summary|ConvertTo-Json -Depth 8|Set-Content $summaryPath -Encoding UTF8}
    foreach($name in @('reboot-preparation.log','reboot-preparation.stderr.log','reboot-after.log','reboot-after.stderr.log','reboot-policy-report.json','reboot-before.txt','reboot-after.txt','policy-session.json')){if(Test-Path "$lab\$name"){Copy-Item -LiteralPath "$lab\$name" -Destination 'C:\P0Results' -Force}}
    Unregister-ScheduledTask -TaskName 'ProxyHarborP0Recovery' -Confirm:$false -ErrorAction SilentlyContinue
}
