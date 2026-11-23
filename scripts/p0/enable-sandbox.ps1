param([switch]$Enable)
$ErrorActionPreference = 'Stop'
$repositoryDirectory = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$outputDirectory = Join-Path $repositoryDirectory '.local\p0'
$scratchDirectory = Join-Path $repositoryDirectory '.cache\p0\dism'
New-Item -ItemType Directory -Force -Path $outputDirectory, $scratchDirectory | Out-Null
$reportPath = Join-Path $outputDirectory 'sandbox-setup.json'
$report = [ordered]@{ schemaVersion = 1; generatedAt = [DateTime]::UtcNow.ToString('o'); state = 'running'; rebootInvoked = $false; changes = @() }
function Save-SetupReport { $report | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $reportPath -Encoding UTF8 }
try {
    Save-SetupReport
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Windows administrator authorization is required.' }
    $before = @(Get-WindowsOptionalFeature -Online | Select-Object FeatureName,State)
    $before | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $outputDirectory 'windows-features-before.json') -Encoding UTF8
    $feature = $before | Where-Object FeatureName -eq 'Containers-DisposableClientVM'
    if (-not $feature) { throw 'Windows Sandbox is not available in this Windows installation.' }
    $report.before = [string]$feature.State
    $report.restartNeeded = [string]$feature.State -eq 'EnablePending'
    if ($Enable -and [string]$feature.State -notin @('Enabled','EnablePending')) {
        $result = Enable-WindowsOptionalFeature -Online -FeatureName 'Containers-DisposableClientVM' -All -NoRestart -ScratchDirectory $scratchDirectory -LogPath (Join-Path $outputDirectory 'sandbox-feature-dism.log')
        $report.restartNeeded = [bool]$result.RestartNeeded
    }
    $after = @(Get-WindowsOptionalFeature -Online | Select-Object FeatureName,State)
    $prior = @{}
    foreach ($entry in $before) { $prior[$entry.FeatureName] = [string]$entry.State }
    $report.changes = @($after | Where-Object { $prior[$_.FeatureName] -ne [string]$_.State } | ForEach-Object { @{ feature = $_.FeatureName; before = $prior[$_.FeatureName]; after = [string]$_.State } })
    $final = $after | Where-Object FeatureName -eq 'Containers-DisposableClientVM'
    $report.after = [string]$final.State
    if ([string]$final.State -eq 'EnablePending') { $report.restartNeeded = $true }
    $report.state = if ($report.restartNeeded) { 'restart_required' } elseif ([string]$final.State -eq 'Enabled') { 'enabled' } else { 'not_enabled' }
} catch {
    $report.state = 'failed'
    $report.error = $_.Exception.Message
    $report.restartNeeded = $null
    $report.servicingStateUncertain = $true
} finally { Save-SetupReport }
if ($report.state -eq 'failed') { exit 1 }
