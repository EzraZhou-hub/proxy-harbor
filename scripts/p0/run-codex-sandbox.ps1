$ErrorActionPreference = 'Stop'
$report = [ordered]@{schemaVersion=1;overall='not_accepted';state='preparing';hostPolicyChanged=$false;applicationProtectionVerified=$false}
try {
    if (-not (Test-Path -LiteralPath 'C:\P0Input\codex-program.tar') -or -not (Test-Path -LiteralPath 'C:\P0Results')) { throw 'Disposable guest mappings are required.' }
    if (Test-Path -LiteralPath 'C:\P0Lab') { throw 'A fresh guest is required.' }
    $manifest = Get-Content -LiteralPath 'C:\P0Input\manifest.json' -Raw | ConvertFrom-Json
    foreach ($entry in $manifest.files) {
        $file = [IO.Path]::GetFullPath((Join-Path 'C:\P0Input' $entry.path))
        if (-not $file.StartsWith('C:\P0Input\',[StringComparison]::OrdinalIgnoreCase)) { throw 'Invalid manifest path.' }
        if ((Get-FileHash -LiteralPath $file).Hash -ne $entry.sha256) { throw "Checksum mismatch: $($entry.path)" }
    }
    New-Item -ItemType Directory -Path 'C:\P0Lab' | Out-Null
    & robocopy.exe 'C:\P0Input' 'C:\P0Lab' /E /COPY:DAT /DCOPY:DAT /XJ /R:0 /W:0 /NFL /NDL /NP /NJH /NJS /LOG:C:\P0Results\guest-copy.log | Out-Null
    if ($LASTEXITCODE -ge 8) { throw "Guest program copy failed: $LASTEXITCODE" }
    New-Item -ItemType Directory -Path 'C:\P0Lab\codex-app' | Out-Null
    & tar.exe -xf 'C:\P0Lab\codex-program.tar' -C 'C:\P0Lab\codex-app'
    if($LASTEXITCODE -ne 0){throw 'Guest program extraction failed.'}
    $env:PROXY_HARBOR_P0_GUEST = 'offline-lab'
    Set-Location -LiteralPath 'C:\P0Lab'
    if($manifest.manualLogin){
        & 'C:\P0Lab\scripts\p0\guest-codex-login.ps1'
        $report.manualState=Get-Content -LiteralPath 'C:\P0Results\manual\state.json' -Raw|ConvertFrom-Json
        return
    }
    & 'C:\P0Lab\scripts\p0\guest-codex.ps1' -RealProxyBridge:([bool]$manifest.realProxyBridge)
    $observations=Get-Content -LiteralPath 'C:\P0Results\initial\codex-report.json' -Raw | ConvertFrom-Json
    $report.startupChecks=if(-not $observations.error -and @($observations.cases).Count -eq 3 -and @($observations.cases | Where-Object {$_.status -ne 'observed'}).Count -eq 0){'completed'}else{'failed'}
} catch { $report.error=$_.Exception.Message }
finally {
    $report.state='complete'
    $report | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath 'C:\P0Results\sandbox-summary.json' -Encoding UTF8
}
