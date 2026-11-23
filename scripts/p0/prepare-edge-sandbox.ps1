$ErrorActionPreference='Stop'
$repositoryDirectory=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$build=Get-Content -LiteralPath (Join-Path $repositoryDirectory '.local\p0\edge-build.json') -Raw|ConvertFrom-Json
$guard=Join-Path $repositoryDirectory '.local\p0\bin\p0-edge-guard.exe'
if((Get-FileHash -LiteralPath $guard).Hash -ne $build.binarySHA256 -or (Get-FileHash -LiteralPath (Join-Path $repositoryDirectory 'native\p0\wfp_lab.c')).Hash -ne $build.sourceSHA256){throw 'Edge guard build is stale.'}
$identifier=[DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss')+'-'+[guid]::NewGuid().ToString('N').Substring(0,6)
$bundle=Join-Path $repositoryDirectory ('.local\p0\sandbox\'+$identifier)
$inputDirectory=Join-Path $bundle 'input';$results=Join-Path $bundle 'results'
New-Item -ItemType Directory -Path $inputDirectory,$results|Out-Null
$files=[ordered]@{
    'run-sandbox.ps1'=(Join-Path $PSScriptRoot 'run-edge-sandbox.ps1')
    'scripts\p0\guest-edge.ps1'=(Join-Path $PSScriptRoot 'guest-edge.ps1')
    'scripts\p0\edge-canary.mjs'=(Join-Path $PSScriptRoot 'edge-canary.mjs')
    'scripts\p0\codex-file-bridge.mjs'=(Join-Path $PSScriptRoot 'codex-file-bridge.mjs')
    'native\p0\wfp_lab.c'=(Join-Path $repositoryDirectory 'native\p0\wfp_lab.c')
    'scripts\p0\build-edge-lab.ps1'=(Join-Path $PSScriptRoot 'build-edge-lab.ps1')
    '.local\p0\bin\p0-edge-guard.exe'=$guard
    '.local\p0\bin\proxy-harbor-p0-relay.exe'=(Join-Path $repositoryDirectory '.local\p0\bin\proxy-harbor-p0-relay.exe')
    'node.exe'='D:\develop\Node\node.exe'
    'NODE-LICENSE.txt'=(Join-Path $repositoryDirectory 'native\p0\NODE-LICENSE.txt')
}
$manifest=@()
foreach($relative in $files.Keys){$target=Join-Path $inputDirectory $relative;New-Item -ItemType Directory -Force -Path (Split-Path -Parent $target)|Out-Null;Copy-Item -LiteralPath $files[$relative] -Destination $target;$manifest+=@{path=$relative;sha256=(Get-FileHash -LiteralPath $target).Hash}}
@{schemaVersion=1;scope='Fresh guest Edge, real proxy via project relay, independent per-application WFP restrictions';files=$manifest}|ConvertTo-Json -Depth 6|Set-Content -LiteralPath (Join-Path $inputDirectory 'manifest.json') -Encoding UTF8
$escapedInput=[Security.SecurityElement]::Escape($inputDirectory);$escapedResults=[Security.SecurityElement]::Escape($results)
@"
<Configuration>
<Networking>Disable</Networking><vGPU>Disable</vGPU><AudioInput>Disable</AudioInput><VideoInput>Disable</VideoInput><PrinterRedirection>Disable</PrinterRedirection><ClipboardRedirection>Disable</ClipboardRedirection><MemoryInMB>6144</MemoryInMB>
<MappedFolders>
<MappedFolder><HostFolder>$escapedInput</HostFolder><SandboxFolder>C:\P0Input</SandboxFolder><ReadOnly>true</ReadOnly></MappedFolder>
<MappedFolder><HostFolder>$escapedResults</HostFolder><SandboxFolder>C:\P0Results</SandboxFolder><ReadOnly>false</ReadOnly></MappedFolder>
</MappedFolders>
<LogonCommand><Command>powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\P0Input\run-sandbox.ps1</Command></LogonCommand>
</Configuration>
"@|Set-Content -LiteralPath (Join-Path $repositoryDirectory '.local\p0\proxy-harbor-p0.wsb') -Encoding UTF8
@{bundle=$bundle;results=$results;files=$manifest.Count}|ConvertTo-Json
