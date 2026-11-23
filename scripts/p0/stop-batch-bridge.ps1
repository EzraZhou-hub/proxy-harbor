$ErrorActionPreference='Stop'
$repository=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$recordPath=Join-Path $repository '.local\p0\batch-public-bridge.json'
$record=Get-Content -LiteralPath $recordPath -Raw|ConvertFrom-Json
$allowed=[IO.Path]::GetFullPath((Join-Path $repository '.local\p0\sandbox'))+'\'
if($record.owner -ne 'proxy-harbor-p0' -or -not ([IO.Path]::GetFullPath($record.bundle)+'\').StartsWith($allowed,[StringComparison]::OrdinalIgnoreCase)){throw 'Refusing an unowned bridge record'}
$process=Get-CimInstance Win32_Process -Filter ('ProcessId='+[int]$record.processId)
if($process){
    if($process.ExecutablePath -ne 'D:\develop\Node\node.exe' -or -not $process.CommandLine.Contains('codex-file-bridge.mjs') -or -not $process.CommandLine.Contains($record.root)){throw 'Bridge process identity changed; refusing to stop it'}
    Stop-Process -Id $record.processId -Force
}
if(Get-Process -Id $record.processId -ErrorAction SilentlyContinue){throw 'Bridge process remains'}
$record.stopped=$true
$record|Add-Member -NotePropertyName stoppedAtUtc -NotePropertyValue ([DateTimeOffset]::UtcNow.ToString('o')) -Force
$record|ConvertTo-Json|Set-Content -LiteralPath $recordPath -Encoding UTF8
$record|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $record.bundle 'results\host-bridge-cleanup.json') -Encoding UTF8
Write-Output 'Owned batch bridge stopped. Host proxy process and configuration were not changed.'
