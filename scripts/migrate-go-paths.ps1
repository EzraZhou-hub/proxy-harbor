$ErrorActionPreference = 'Stop'

$goExecutable = 'D:\develop\Go\bin\go.exe'
$workspaceRoot = 'D:\develop\go-workspace'
$cacheRoot = 'D:\develop\go-cache'
$configurationRoot = 'D:\develop\go-config'
$expectedRoots = @($workspaceRoot, $cacheRoot, $configurationRoot)
foreach ($targetRoot in $expectedRoots) {
    $resolvedTarget = [IO.Path]::GetFullPath($targetRoot).TrimEnd('\')
    if ($resolvedTarget -ne $targetRoot -or -not $resolvedTarget.StartsWith('D:\develop\', [StringComparison]::OrdinalIgnoreCase)) {
        throw "Unexpected migration destination: $targetRoot"
    }
    if ((Test-Path -LiteralPath $targetRoot) -and ((Get-Item -LiteralPath $targetRoot -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "Destination must not be a link: $targetRoot"
    }
}
if (-not (Test-Path -LiteralPath $goExecutable)) { throw 'The installed Go executable was not found.' }
$originalSettings = (& $goExecutable env -json GOPATH GOBIN GOMODCACHE GOCACHE GOENV GOROOT | ConvertFrom-Json)
if ($LASTEXITCODE -ne 0) { throw 'Cannot read Go configuration.' }

$newSettings = [ordered]@{
    GOPATH = $workspaceRoot
    GOBIN = "$workspaceRoot\bin"
    GOMODCACHE = "$workspaceRoot\pkg\mod"
    GOCACHE = "$cacheRoot\build"
    GOTMPDIR = "$cacheRoot\tmp"
    GOENV = "$configurationRoot\env"
}
$originalUser = [ordered]@{}
foreach ($settingName in @($newSettings.Keys) + @('Path')) {
    $originalUser[$settingName] = [Environment]::GetEnvironmentVariable($settingName, 'User')
}
$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss-fff'
$backupRoot = "$configurationRoot\backups\$timestamp"
New-Item -ItemType Directory -Path $backupRoot -Force | Out-Null
# Backup files can contain private proxy/configuration values: restrict access before writing.
$userSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
& icacls.exe $configurationRoot '/inheritance:r' '/grant:r' "*$($userSid):(OI)(CI)F" '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Cannot protect the Go configuration directory.' }
& icacls.exe $backupRoot '/inheritance:r' '/grant:r' "*$($userSid):(OI)(CI)F" '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Cannot protect the backup directory.' }
[ordered]@{ CreatedAt = (Get-Date).ToString('o'); UserEnvironment = $originalUser; GoSettings = $originalSettings } |
    ConvertTo-Json -Depth 5 | Set-Content -LiteralPath "$backupRoot\before.json" -Encoding utf8

$oldConfiguration = ''
if ($originalSettings.GOENV -and $originalSettings.GOENV -ne 'off' -and (Test-Path -LiteralPath $originalSettings.GOENV)) {
    Copy-Item -LiteralPath $originalSettings.GOENV -Destination "$backupRoot\original-go-env" -ErrorAction Stop
    $oldConfiguration = [IO.File]::ReadAllText($originalSettings.GOENV)
}
# Preserve unrelated settings; directory settings are now explicit user environment variables.
$directoryKeys = '^(GOPATH|GOBIN|GOMODCACHE|GOCACHE|GOTMPDIR|GOENV)='
$newConfiguration = (($oldConfiguration -split '\r?\n' | Where-Object { $_ -notmatch $directoryKeys -and $_ -ne '' }) -join "`n")
if ($newConfiguration) { $newConfiguration += "`n" }
if (Test-Path -LiteralPath $newSettings.GOENV) {
    Copy-Item -LiteralPath $newSettings.GOENV -Destination "$backupRoot\previous-d-drive-go-env"
    if ([IO.File]::ReadAllText($newSettings.GOENV) -ne $newConfiguration) {
        throw 'The destination GOENV already contains different settings. No environment variables were changed.'
    }
}

function Copy-TreeWithoutReplacingDifferentFiles([string]$Source, [string]$Destination) {
    if (-not $Source -or -not (Test-Path -LiteralPath $Source)) { return }
    $sourceFull = [IO.Path]::GetFullPath($Source).TrimEnd('\')
    $destinationFull = [IO.Path]::GetFullPath($Destination).TrimEnd('\')
    if ($sourceFull -eq $destinationFull) { return }
    if ((Get-Item -LiteralPath $Source -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw "Source is a link; refusing automatic copy: $Source"
    }
    $entries = @(Get-ChildItem -LiteralPath $Source -Recurse -Force -ErrorAction Stop)
    foreach ($entry in $entries) {
        if ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Linked entry needs manual review: $($entry.FullName)" }
        $relativePath = $entry.FullName.Substring($sourceFull.Length).TrimStart('\')
        $destinationPath = Join-Path $Destination $relativePath
        if ((Test-Path -LiteralPath $destinationPath) -and -not $entry.PSIsContainer) {
            $existingItem = Get-Item -LiteralPath $destinationPath -Force
            if ($existingItem.PSIsContainer -or $existingItem.Length -ne $entry.Length -or
                (Get-FileHash -LiteralPath $entry.FullName).Hash -ne (Get-FileHash -LiteralPath $destinationPath).Hash) {
                throw "Different destination file exists; refusing to replace: $destinationPath"
            }
        }
    }
    New-Item -ItemType Directory -Path $Destination -Force | Out-Null
    foreach ($entry in $entries) {
        $relativePath = $entry.FullName.Substring($sourceFull.Length).TrimStart('\')
        $destinationPath = Join-Path $Destination $relativePath
        if ($entry.PSIsContainer) {
            New-Item -ItemType Directory -Path $destinationPath -Force | Out-Null
        } elseif (-not (Test-Path -LiteralPath $destinationPath)) {
            New-Item -ItemType Directory -Path (Split-Path -Parent $destinationPath) -Force | Out-Null
            Copy-Item -LiteralPath $entry.FullName -Destination $destinationPath
            if ((Get-FileHash -LiteralPath $entry.FullName).Hash -ne (Get-FileHash -LiteralPath $destinationPath).Hash) {
                throw "Copy verification failed: $destinationPath"
            }
        }
    }
}

foreach ($directory in @($workspaceRoot, $newSettings.GOBIN, $newSettings.GOMODCACHE, $newSettings.GOCACHE, $newSettings.GOTMPDIR)) {
    New-Item -ItemType Directory -Path $directory -Force | Out-Null
}
$oldWorkspaces = @($originalSettings.GOPATH -split ';' | Where-Object { $_ })
if ($oldWorkspaces.Count -gt 1) { throw 'Multiple GOPATH entries need individual mapping; no environment variables were changed.' }
foreach ($oldWorkspace in $oldWorkspaces) { Copy-TreeWithoutReplacingDifferentFiles $oldWorkspace $workspaceRoot }
Copy-TreeWithoutReplacingDifferentFiles $originalSettings.GOBIN $newSettings.GOBIN
Copy-TreeWithoutReplacingDifferentFiles $originalSettings.GOMODCACHE $newSettings.GOMODCACHE
# Build cache is disposable and will be regenerated on D:, avoiding migration of Codex sandbox caches.
[IO.File]::WriteAllText($newSettings.GOENV, $newConfiguration, [Text.UTF8Encoding]::new($false))

$oldToolPaths = @($originalSettings.GOBIN) + @($oldWorkspaces | ForEach-Object { Join-Path $_ 'bin' })
$oldToolPaths = @($oldToolPaths | Where-Object { $_ } | ForEach-Object { $_.TrimEnd('\') })
$newUserParts = @($originalUser.Path -split ';' | Where-Object {
    $entryExpanded = [Environment]::ExpandEnvironmentVariables($_).TrimEnd('\')
    -not ($oldToolPaths -contains $entryExpanded) -and $entryExpanded -ne $newSettings.GOBIN
})
$newUserPath = ($newUserParts + @($newSettings.GOBIN)) -join ';'

try {
    foreach ($settingName in $newSettings.Keys) {
        [Environment]::SetEnvironmentVariable($settingName, $newSettings[$settingName], 'User')
        [Environment]::SetEnvironmentVariable($settingName, $newSettings[$settingName], 'Process')
    }
    [Environment]::SetEnvironmentVariable('Path', $newUserPath, 'User')
    foreach ($settingName in $newSettings.Keys) {
        if ([Environment]::GetEnvironmentVariable($settingName, 'User') -ne $newSettings[$settingName]) { throw "User setting did not persist: $settingName" }
    }
    $verification = (& $goExecutable env -json GOROOT GOPATH GOBIN GOMODCACHE GOCACHE GOTMPDIR GOENV | ConvertFrom-Json)
    if ($LASTEXITCODE -ne 0) { throw 'Cannot verify updated Go configuration.' }
    foreach ($settingName in $newSettings.Keys) {
        if ($verification.$settingName -ne $newSettings[$settingName]) { throw "Go setting verification failed: $settingName" }
    }
    $verification | ConvertTo-Json
    [pscustomobject]@{ Backup = $backupRoot; OldFilesRetained = $true; UserPathUpdated = $true } | ConvertTo-Json
} catch {
    foreach ($settingName in $originalUser.Keys) {
        [Environment]::SetEnvironmentVariable($settingName, $originalUser[$settingName], 'User')
    }
    throw "Migration did not complete; user environment restored. Backup: $backupRoot. Error: $($_.Exception.Message)"
}
