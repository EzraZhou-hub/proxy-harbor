$ErrorActionPreference = 'Stop'
Push-Location (Join-Path $PSScriptRoot '..\app\proxy-harbor')
try { wails3 dev; if ($LASTEXITCODE -ne 0) { throw 'Desktop development session failed.' } }
finally { Pop-Location }
