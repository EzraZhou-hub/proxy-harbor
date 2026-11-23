param([switch]$Elevated)
$ErrorActionPreference='Stop'
$summary=[ordered]@{schemaVersion=1;overall='not_accepted';state='preparing';applicationProtectionVerified=$false}
$writeSummary=$true
try {
    if(-not (Test-Path -LiteralPath 'C:\P0Input\manifest.json') -or -not (Test-Path -LiteralPath 'C:\P0Results')){throw 'Disposable guest mappings required.'}
    $principal=[Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
    if(-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){
        if($Elevated){throw 'Guest elevation was not granted.'}
        Start-Process -FilePath 'powershell.exe' -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File C:\P0Input\run-sandbox.ps1 -Elevated' -Verb RunAs -WindowStyle Hidden
        $writeSummary=$false;return
    }
    if(Test-Path -LiteralPath 'C:\P0Lab'){throw 'Fresh guest required.'}
    $manifest=Get-Content -LiteralPath 'C:\P0Input\manifest.json' -Raw|ConvertFrom-Json
    foreach($entry in $manifest.files){
        $file=[IO.Path]::GetFullPath((Join-Path 'C:\P0Input' $entry.path))
        if(-not $file.StartsWith('C:\P0Input\',[StringComparison]::OrdinalIgnoreCase) -or (Get-FileHash -LiteralPath $file).Hash -ne $entry.sha256){throw 'Input manifest verification failed.'}
    }
    New-Item -ItemType Directory -Path 'C:\P0Lab'|Out-Null
    & robocopy.exe 'C:\P0Input' 'C:\P0Lab' /E /COPY:DAT /DCOPY:DAT /XJ /R:0 /W:0 /NFL /NDL /NP /NJH /NJS /LOG:C:\P0Results\guest-copy.log|Out-Null
    if($LASTEXITCODE -ge 8){throw 'Guest copy failed.'}
    Set-Location -LiteralPath 'C:\P0Lab';$env:PROXY_HARBOR_P0_GUEST='offline-lab'
    & 'C:\P0Lab\scripts\p0\guest-edge.ps1' -NetworkTrace
    $result=Get-Content -LiteralPath 'C:\P0Results\edge\report.json' -Raw|ConvertFrom-Json
    $summary.edgeChecks=$result.boundedEdgeTCPChecks;$summary.cleanup=$result.cleanup
    if($result.error){$summary.error=$result.error}
} catch {$summary.error=$_.Exception.Message}
finally {if($writeSummary){$summary.state='complete';$summary|ConvertTo-Json -Depth 8|Set-Content -LiteralPath 'C:\P0Results\sandbox-summary.json' -Encoding UTF8}}
