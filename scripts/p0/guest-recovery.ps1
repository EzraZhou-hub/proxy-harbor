param([ValidateSet('Arm','Status','Release')][string]$Action='Status', [int]$Port=0)
$ErrorActionPreference='Stop'
if ($env:PROXY_HARBOR_P0_GUEST -ne 'offline-lab' -or (Get-Location).Path -ne 'C:\P0Lab' -or -not (Test-Path 'C:\P0Input\manifest.json')) { throw 'Recovery is restricted to the disposable P0 guest.' }
$journalPath='C:\P0Lab\.local\p0\policy-session.json'
$guards=@('p0-relay-guard.exe','p0-helper-guard.exe')
$digests=@{}
foreach($name in $guards){$digests[$name]=(Get-FileHash -LiteralPath (Join-Path '.local\p0\bin' $name)).Hash}
function Save-Journal($record) {
    $temp=$journalPath+'.'+[guid]::NewGuid().ToString('N')+'.tmp'
    $record|ConvertTo-Json -Depth 8|Set-Content -LiteralPath $temp -Encoding UTF8
    Move-Item -LiteralPath $temp -Destination $journalPath -Force
}
function Invoke-Guard($name,$operation,$entrancePort) {
    $arguments=@($operation)
    if($operation -eq 'install-fixture-only'){$arguments+= [string]$entrancePort}
    $data= & (Join-Path 'C:\P0Lab\.local\p0\bin' $name) @arguments | ConvertFrom-Json
    if($LASTEXITCODE -ne 0 -or $data.windowsError -ne 0){throw "Guard operation failed: $name/$operation"}
    return $data
}
if(Test-Path -LiteralPath $journalPath){
    $journal=Get-Content -LiteralPath $journalPath -Raw|ConvertFrom-Json
    if($journal.owner -ne 'proxy-harbor-p0' -or $journal.version -ne 1){throw 'Unrecognized recovery record.'}
    foreach($name in $guards){if($journal.digests.$name -ne $digests[$name]){throw 'Recovery tool changed; refusing mutation.'}}
} elseif($Action -eq 'Arm') {
    if($Port -lt 1024 -or $Port -gt 65535){throw 'Invalid relay port.'}
    $journal=[pscustomobject]@{version=1;owner='proxy-harbor-p0';state='prepared';port=$Port;digests=$digests;createdAtUtc=[DateTimeOffset]::UtcNow.ToString('o')}
    # Durable intent precedes the first persistent rule mutation.
    Save-Journal $journal
} else {throw 'Recovery record missing; refusing automatic rule changes.'}
if($Action -eq 'Arm') {
    if($Port -ne $journal.port){throw 'Session port changed; recover the previous session first.'}
    foreach($name in $guards){Invoke-Guard $name 'install-fixture-only' $Port | Out-Null}
    $journal.state='blocked'; Save-Journal $journal
}
if($Action -eq 'Release') {
    # Only the two lab names are inspected; no installed application is probed.
    foreach($name in @('proxy-harbor-p0-probe','proxy-harbor-p0-helper')) {
        foreach($process in @(Get-Process -Name $name -ErrorAction SilentlyContinue)) {
            if(-not $process.Path -or $process.Path.StartsWith('C:\P0Lab\',[StringComparison]::OrdinalIgnoreCase)){throw 'Fixture is still running; keep its blocking rules.'}
        }
    }
    foreach($name in $guards){Invoke-Guard $name 'remove-fixture-only' 0|Out-Null}
    $journal.state='released'; Save-Journal $journal
}
$inventory=@(foreach($name in $guards){Invoke-Guard $name 'inspect' 0})
$count=($inventory|Measure-Object -Property rulesPresent -Sum).Sum
$state=if($count -eq 8){'blocked_pending_recovery'}elseif($count -eq 0){'released'}else{'blocked_partial_recovery_required'}
@{state=$state;rulesPresent=$count;automaticRelease=$false;recordState=$journal.state}|ConvertTo-Json -Compress

