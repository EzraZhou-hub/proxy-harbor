param([ValidateSet('Prepare','Restart','Verify')][string]$Action='Prepare',[switch]$AuthorizeOneGuestRestart)
$ErrorActionPreference='Stop'
if((Get-Location).Path -ne 'C:\P0Lab' -or $PSCommandPath -ne 'C:\P0Lab\scripts\p0\guest-batch-reboot.ps1' -or -not (Test-Path 'C:\P0Lab\manifest.json')){throw 'Fixed disposable guest required'}
$lab='C:\P0Lab\.local\p0';$output='C:\P0Results';$pending=Join-Path $lab 'batch-reboot-pending.json';$task='ProxyHarborP0BatchRecovery'
function Run-Test([string]$Name,[string]$Log){$p=Start-Process -FilePath (Join-Path $lab 'bin\p0-policy-tests.exe') -ArgumentList @('-test.v',('-test.run=^'+$Name+'$'),'-test.timeout=150s') -WorkingDirectory 'C:\P0Lab' -WindowStyle Hidden -Wait -PassThru -RedirectStandardOutput (Join-Path $output ($Log+'.log')) -RedirectStandardError (Join-Path $output ($Log+'.stderr.log'));if($p.ExitCode -ne 0){throw ('Batch recovery test failed: '+$Name)}}
function Boot-Time{(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o')}
if($Action -eq 'Prepare'){
    if($env:PROXY_HARBOR_P0_GUEST -ne 'offline-lab' -or (Test-Path $pending) -or (Get-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue)){throw 'Clean explicit guest stage required'}
    Run-Test 'TestP0BatchRecoveryPreparation' 'batch-reboot-preparation'
    $before=Boot-Time;$before|Set-Content -LiteralPath (Join-Path $lab 'reboot-before.txt')
    $record=[ordered]@{schemaVersion=1;owner='proxy-harbor-p0-batch';beforeBoot=$before;state='prepared_waiting_for_explicit_restart_authorization';restartIssued=$false;rules=12;hostRestart=$false;task=$task}
    $record|ConvertTo-Json|Set-Content -LiteralPath $pending -Encoding UTF8
    $scheduled=New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File C:\P0Lab\scripts\p0\guest-batch-reboot.ps1 -Action Verify' -WorkingDirectory 'C:\P0Lab'
    Register-ScheduledTask -TaskName $task -Action $scheduled -Trigger (New-ScheduledTaskTrigger -AtStartup) -User 'SYSTEM' -RunLevel Highest|Out-Null
    $record|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $output 'batch-reboot-preparation.json') -Encoding UTF8
    Write-Output 'Prepared 12 guest fixture rules. No restart was performed; explicit authorization is required.'
    return
}
$record=Get-Content -LiteralPath $pending -Raw|ConvertFrom-Json
if($record.owner -ne 'proxy-harbor-p0-batch' -or $record.rules -ne 12 -or $record.hostRestart){throw 'Invalid pending guest-only recovery record'}
if($Action -eq 'Restart'){
    if(-not $AuthorizeOneGuestRestart -or $env:PROXY_HARBOR_P0_GUEST -ne 'offline-lab' -or $record.restartIssued -or (Boot-Time) -ne $record.beforeBoot){throw 'A fresh explicit one-guest restart authorization is required'}
    $record.restartIssued=$true;$record.state='authorized_single_guest_restart_issued'
    $record|ConvertTo-Json|Set-Content -LiteralPath $pending -Encoding UTF8
    Restart-Computer -Force
    return
}
$env:PROXY_HARBOR_P0_GUEST='offline-lab'
$result=[ordered]@{schemaVersion=1;overall='not_accepted';state='complete';checks='not_run';cleanup='not_verified';earliestBootCoverage='not_verified'}
try {
    $after=Boot-Time;if($after -eq $record.beforeBoot){throw 'Guest boot identity did not change'}
    $after|Set-Content -LiteralPath (Join-Path $lab 'reboot-after.txt')
    $result.beforeBoot=$record.beforeBoot;$result.afterBoot=$after;$result.bfeState=(Get-Service BFE).Status.ToString()
    Run-Test 'TestP0BatchRecoveryAfterBoot' 'batch-reboot-after'
    $report=Get-Content -LiteralPath (Join-Path $lab 'batch-reboot-policy-report.json') -Raw|ConvertFrom-Json
    $result.checks='passed';$result.cleanup=$report.cleanup
} catch {$result.checks='failed';$result.error=$_.Exception.Message}
finally {
    foreach($name in @('batch-reboot-policy-report.json','reboot-policy-report.json','reboot-before.txt','reboot-after.txt','port-reboot-session.json','policy-session.json')){if(Test-Path (Join-Path $lab $name)){Copy-Item -LiteralPath (Join-Path $lab $name) -Destination $output -Force}}
    $result|ConvertTo-Json -Depth 8|Set-Content -LiteralPath (Join-Path $output 'batch-reboot-summary.json') -Encoding UTF8
    $registered=Get-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue
    if($registered -and @($registered.Actions|Where-Object {$_.Arguments -like '*C:\P0Lab\scripts\p0\guest-batch-reboot.ps1 -Action Verify'}).Count -eq 1){Unregister-ScheduledTask -TaskName $task -Confirm:$false}
}
