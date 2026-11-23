param([ValidateSet('Inspect', 'Start', 'Stop', 'Connect')][string]$Action = 'Inspect', [switch]$PublicNetwork)
$ErrorActionPreference = 'Stop'
$repositoryDirectory = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$labDirectory = Join-Path $repositoryDirectory '.local\p0'
$activePath = Join-Path $labDirectory 'sandbox-active.json'
$configurationPath = Join-Path $labDirectory 'proxy-harbor-p0.wsb'
$sandboxCommand = (Get-Command wsb.exe -ErrorAction Stop).Source

function Invoke-SandboxCommand {
    param([string[]]$Arguments)
    $previousPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $response = (& $sandboxCommand @Arguments 2>&1 | Out-String)
        $code = $LASTEXITCODE
    } finally { $ErrorActionPreference = $previousPreference }
    if ($code -ne 0) { throw "Windows Sandbox command failed ($code): $response" }
    if ($response.Trim()) { return ($response | ConvertFrom-Json) }
}

# Sandbox uses local HTTP/2 management traffic. An inherited Windows proxy
# without loopback exclusions prevents initialization. Override only this
# script's process and its children; restore its environment before returning.
# External HTTP traffic is deliberately unavailable to these management clients.
# The WSB file independently controls guest networking. Network enablement is
# accepted only for an explicitly selected, bounded P0 public-check package.
$previousEnvironment = @{}
foreach ($name in @('HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'NO_PROXY')) {
    $previousEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
}
try {
    foreach ($name in @('HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY')) {
        [Environment]::SetEnvironmentVariable($name, 'http://127.0.0.1:9', 'Process')
    }
    [Environment]::SetEnvironmentVariable('NO_PROXY', 'localhost,127.0.0.1,::1', 'Process')
    $inventory = Invoke-SandboxCommand -Arguments @('list', '--raw')
    if ($Action -eq 'Inspect') { $inventory | ConvertTo-Json -Depth 8; return }
    if($Action -eq 'Connect'){
        $active=Get-Content -LiteralPath $activePath -Raw|ConvertFrom-Json
        $ownedId=[guid]::Empty
        if($active.owner -ne 'proxy-harbor-p0' -or $active.stoppedAtUtc -or -not [guid]::TryParse($active.id,[ref]$ownedId) -or -not @($inventory.WindowsSandboxEnvironments|Where-Object {$_.Id -eq $active.id}).Count){throw 'A running project-owned Sandbox is required.'}
        # Interactive viewer for the user's manual login, not a background helper.
        Start-Process -FilePath $sandboxCommand -ArgumentList @('connect','--id',$active.id) -WindowStyle Normal|Out-Null
        Write-Output 'Opened the project Sandbox viewer for manual login.'
        return
    }
    if ($Action -eq 'Stop') {
        $active = Get-Content -LiteralPath $activePath -Raw | ConvertFrom-Json
        $parsedId = [guid]::Empty
        if ($active.owner -ne 'proxy-harbor-p0' -or -not [guid]::TryParse($active.id, [ref]$parsedId)) {
            throw 'No project-owned Sandbox record. Refusing to stop another environment.'
        }
        if (@($inventory.WindowsSandboxEnvironments | Where-Object { $_.Id -eq $active.id }).Count) {
            Invoke-SandboxCommand -Arguments @('stop', '--id', $active.id, '--raw') | Out-Null
        }
        $after = Invoke-SandboxCommand -Arguments @('list', '--raw')
        if (@($after.WindowsSandboxEnvironments | Where-Object { $_.Id -eq $active.id }).Count) {
            throw 'The project Sandbox is still present after stop.'
        }
        $active | Add-Member -NotePropertyName stoppedAtUtc -NotePropertyValue ([DateTimeOffset]::UtcNow.ToString('o')) -Force
        $active | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $activePath -Encoding UTF8
        Write-Output 'Project Sandbox stopped and no longer listed. Host reports retained.'
        return
    }
    if (@($inventory.WindowsSandboxEnvironments).Count) {
        throw 'A Sandbox already exists. Refusing to adopt or interrupt another environment.'
    }
    $configuration = Get-Content -LiteralPath $configurationPath -Raw
    [xml]$settings = $configuration
    $mappings = @($settings.Configuration.MappedFolders.MappedFolder)
    $validNetwork=($settings.Configuration.Networking -eq 'Disable' -and -not $PublicNetwork) -or ($settings.Configuration.Networking -eq 'Enable' -and $PublicNetwork)
    if (-not $validNetwork -or $mappings.Count -ne 2 -or
        $mappings[0].ReadOnly -ne 'true' -or $mappings[1].ReadOnly -ne 'false') {
        throw 'Expected the explicitly selected network mode and exactly two scoped mappings.'
    }
    $allowedRoot = [IO.Path]::GetFullPath((Join-Path $labDirectory 'sandbox')) + [IO.Path]::DirectorySeparatorChar
    foreach ($mapping in $mappings) {
        $mappedPath = [IO.Path]::GetFullPath([string]$mapping.HostFolder)
        if (-not $mappedPath.StartsWith($allowedRoot, [StringComparison]::OrdinalIgnoreCase) -or
            -not (Test-Path -LiteralPath $mappedPath -PathType Container)) {
            throw 'Sandbox mapping falls outside the project lab directory or does not exist.'
        }
    }
    if($PublicNetwork){$manifest=Get-Content -LiteralPath (Join-Path ([string]$mappings[0].HostFolder) 'manifest.json') -Raw|ConvertFrom-Json;if(-not $manifest.publicNetwork -or (-not $manifest.publicChecks -and -not $manifest.lifecycleOnly -and -not $manifest.networkLeakChecks) -or $manifest.rebootChecks){throw 'Networked guest requires a bounded public, lifecycle or network-leak validation package without automatic restart.'}}
    if (@(Get-ChildItem -LiteralPath ([string]$mappings[1].HostFolder) -Force).Count) {
        throw 'Prepare a fresh bundle before running again; existing results are preserved.'
    }
    $started = Invoke-SandboxCommand -Arguments @('start', '--config', $configuration, '--raw')
    $record = [ordered]@{schemaVersion=1;owner='proxy-harbor-p0';id=$started.Id;startedAtUtc=[DateTimeOffset]::UtcNow.ToString('o');configuration=$configurationPath;resultDirectory=[string]$mappings[1].HostFolder;hostPolicyChanged=$false}
    $record | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $activePath -Encoding UTF8
    $connection = Start-Process -FilePath $sandboxCommand -ArgumentList @('connect', '--id', $started.Id) -WindowStyle Hidden -PassThru `
        -RedirectStandardOutput (Join-Path $labDirectory 'sandbox-connect.log') `
        -RedirectStandardError (Join-Path $labDirectory 'sandbox-connect.stderr.log')
    $record.connectProcessId = $connection.Id
    $record | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $activePath -Encoding UTF8
    $record | ConvertTo-Json -Depth 8
} finally {
    foreach ($name in $previousEnvironment.Keys) {
        if ($null -eq $previousEnvironment[$name]) {
            Remove-Item -LiteralPath ('Env:\' + $name) -ErrorAction SilentlyContinue
        } else {
            [Environment]::SetEnvironmentVariable($name, $previousEnvironment[$name], 'Process')
        }
    }
}
