param([string]$ExpectedProxyIPv4='131.103.130.202',[string]$Scenarios='',[string]$BinDir='bin')
$ErrorActionPreference='Stop'
$repository=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$ip=$null
if(-not [Net.IPAddress]::TryParse($ExpectedProxyIPv4,[ref]$ip) -or $ip.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork){throw 'Fixed IPv4 required'}
$approval=Get-Content (Join-Path $repository 'app\proxy-harbor\internal\session\approved_guardian.json') -Raw|ConvertFrom-Json
foreach($source in $approval.sourceHashes){if((Get-FileHash (Join-Path $repository $source.path)).Hash -ne $source.sha256){throw 'Pinned source mismatch'}}
$binary=Join-Path (Join-Path $repository 'app\proxy-harbor') $BinDir
if((Get-FileHash (Join-Path $binary 'proxy-harbor-guardian.exe')).Hash -ne $approval.guardianSha256){throw 'Pinned guardian mismatch'}
$id=[DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss')+'-'+[guid]::NewGuid().ToString('N').Substring(0,6)
$bundle=Join-Path $repository ('.local\p0\sandbox\'+$id)
$input=Join-Path $bundle 'input';$results=Join-Path $bundle 'results'
New-Item -ItemType Directory -Path $input,$results|Out-Null
$files=[ordered]@{
 'node.exe'='D:\develop\Node\node.exe'
 'scripts\p0\codex-file-bridge.mjs'=(Join-Path $PSScriptRoot 'codex-file-bridge.mjs')
 '.local\p0\bin\proxy-harbor.exe'=(Join-Path $repository '.local\p0\bin\p0-tun-dns-tests.exe')
 '.local\p0\bin\proxy-harbor-guardian.exe'=(Join-Path $binary 'proxy-harbor-guardian.exe')
 '.local\p0\bin\proxy-harbor-session-inventory.exe'=(Join-Path $binary 'proxy-harbor-session-inventory.exe')
 '.local\p0\bin\capsule-probe.exe'=(Join-Path $repository '.local\p0\bin\capsule-probe.exe')
 '.local\p0\bin\sing-box.exe'='D:\Bufengruanj\v2rayN-windows-64\bin\sing_box\sing-box.exe'
 '.local\p0\bin\wintun.dll'='D:\Bufengruanj\v2rayN-windows-64\bin\xray\wintun.dll'
 'run-sandbox.ps1'=(Join-Path $PSScriptRoot 'guest-tun-dns-validation.ps1')
}
$chrome='C:\Program Files\Google\Chrome\Application'
foreach($file in Get-ChildItem $chrome -Recurse -File){$files['chrome\'+$file.FullName.Substring($chrome.Length+1)]=$file.FullName}
$entries=@()
foreach($relative in $files.Keys){$dest=Join-Path $input $relative;New-Item -ItemType Directory -Force -Path (Split-Path $dest)|Out-Null;Copy-Item -LiteralPath $files[$relative] -Destination $dest;$entries+=@{path=$relative;sha256=(Get-FileHash $dest).Hash}}
$testAddress=(Get-Content (Join-Path $repository '.cache\p0\ipify-test-ip.txt') -Raw).Trim()
$targetIP=$null;if(-not [Net.IPAddress]::TryParse($testAddress,[ref]$targetIP) -or $targetIP.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork){throw 'Previously resolved public test address required'}
$manifest=@{schemaVersion=1;publicNetwork=$true;publicChecks=$true;chromeSessionChecks=$true;rebootChecks=$false;expectedProxyIPv4=$ExpectedProxyIPv4;publicTestAddress=$testAddress;scenarios=$Scenarios;publicBridgeRound=[guid]::NewGuid().ToString('N').Substring(0,8);files=$entries}
$manifest|ConvertTo-Json -Depth 5|Set-Content (Join-Path $input 'manifest.json') -Encoding UTF8
$sources=@('native/session','app/proxy-harbor/internal/engine','app/proxy-harbor/internal/session','scripts/p0/prepare-tun-dns-validation.ps1','scripts/p0/guest-tun-dns-validation.ps1','scripts/p0/codex-file-bridge.mjs')
$hashes=@(foreach($path in $sources){foreach($file in Get-ChildItem (Join-Path $repository $path) -Recurse -File){if($file.Extension -in @('.go','.c','.h','.json','.ps1','.mjs')){@{path=$file.FullName.Substring($repository.Length+1);sha256=(Get-FileHash $file.FullName).Hash}}}})
$hashes|ConvertTo-Json -Depth 4|Set-Content (Join-Path $bundle 'source-hashes.json') -Encoding UTF8
$escapedInput=[Security.SecurityElement]::Escape($input);$escapedResults=[Security.SecurityElement]::Escape($results)
@"
<Configuration><Networking>Enable</Networking><vGPU>Disable</vGPU><AudioInput>Disable</AudioInput><VideoInput>Disable</VideoInput><PrinterRedirection>Disable</PrinterRedirection><ClipboardRedirection>Disable</ClipboardRedirection><MemoryInMB>4096</MemoryInMB><MappedFolders><MappedFolder><HostFolder>$escapedInput</HostFolder><SandboxFolder>C:\P0Input</SandboxFolder><ReadOnly>true</ReadOnly></MappedFolder><MappedFolder><HostFolder>$escapedResults</HostFolder><SandboxFolder>C:\P0Results</SandboxFolder><ReadOnly>false</ReadOnly></MappedFolder></MappedFolders><LogonCommand><Command>powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\P0Input\run-sandbox.ps1</Command></LogonCommand></Configuration>
"@|Set-Content (Join-Path $repository '.local\p0\proxy-harbor-p0.wsb') -Encoding UTF8
$bundle|Set-Content (Join-Path $repository '.cache\p0\tun-dns-package.txt')
Write-Output $bundle
