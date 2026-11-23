param([switch]$Elevated)
$ErrorActionPreference='Stop'
try {
 if(-not(Test-Path C:\P0Input\manifest.json) -or -not(Test-Path C:\P0Results)){throw 'Disposable guest mappings required'}
 $admin=([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
 if(-not $admin){if($Elevated){throw 'Guest elevation failed'};Start-Process powershell.exe -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File C:\P0Input\run-sandbox.ps1 -Elevated' -Verb RunAs -WindowStyle Hidden;return}
 $manifest=Get-Content C:\P0Input\manifest.json -Raw|ConvertFrom-Json
 foreach($entry in $manifest.files){$path=[IO.Path]::GetFullPath((Join-Path C:\P0Input $entry.path));if(-not $path.StartsWith('C:\P0Input\',[StringComparison]::OrdinalIgnoreCase) -or (Get-FileHash $path).Hash -ne $entry.sha256){throw 'Invalid package file'}}
 New-Item -ItemType Directory -Path C:\P0Lab -Force|Out-Null
 Get-ChildItem C:\P0Input -Force|ForEach-Object {Copy-Item -LiteralPath $_.FullName -Destination C:\P0Lab -Recurse -Force}
 $env:PROXY_HARBOR_P0_GUEST='offline-lab'
 $env:PH_TUN_SCENARIOS=$manifest.scenarios
 Set-Location C:\P0Lab
 'ready'|Set-Content C:\P0Results\guest-ready.txt
 $control='C:\P0Results\proxy-bridge-'+$manifest.publicBridgeRound+'\control.json'
 $until=[DateTime]::UtcNow.AddSeconds(120)
 while(-not(Test-Path $control)){if([DateTime]::UtcNow -gt $until){throw 'Host transport readiness timeout'};Start-Sleep -Milliseconds 200}
 $p=Start-Process C:\P0Lab\.local\p0\bin\proxy-harbor.exe -ArgumentList @('-test.v','-test.run=^TestManagedTUNSystemDNS$','-test.timeout=600s') -WorkingDirectory C:\P0Lab -WindowStyle Hidden -PassThru -Wait -RedirectStandardOutput C:\P0Results\tun-dns.log -RedirectStandardError C:\P0Results\tun-dns.stderr.log
 Copy-Item C:\P0Lab\.local\p0\tun-dns-report.json C:\P0Results
 if(Test-Path C:\P0Lab\.local\p0\tun-dns-console.log){Copy-Item C:\P0Lab\.local\p0\tun-dns-console.log C:\P0Results}
 $checks=[ordered]@{}
 $checks.accounts_zero=@(Get-LocalUser|Where-Object {$_.Name -match '^PH_[0-9a-f]{16}$|^PHp0_[0-9a-f]{14}$'}).Count -eq 0
 $checks.profiles_zero=@(Get-ChildItem C:\Users -Directory|Where-Object {$_.Name -match '^PH_[0-9a-f]{16}(\.|$)|^PHp0_[0-9a-f]{14}(\.|$)'}).Count -eq 0
 $checks.test_nrpt_zero=@(Get-DnsClientNrptRule|Where-Object {$_.DisplayName -like 'ProxyHarbor.P0.*'}).Count -eq 0
 $checks.guest_singbox_zero=@(Get-Process sing-box -ErrorAction SilentlyContinue).Count -eq 0
 $checks.guest_proxy_port_zero=@(Get-NetTCPConnection -LocalPort 10808 -State Listen -ErrorAction SilentlyContinue).Count -eq 0
 if(Test-Path C:\P0Lab\.local\p0\sessions){foreach($folder in Get-ChildItem C:\P0Lab\.local\p0\sessions -Directory){$row=& C:\P0Lab\.local\p0\bin\proxy-harbor-guardian.exe inspect $folder.FullName|ConvertFrom-Json;$checks['session_'+$folder.Name]=$LASTEXITCODE -eq 0 -and $row.windowsError -eq 0 -and $row.rulesPresent -eq 0}}
 $global=& C:\P0Lab\.local\p0\bin\proxy-harbor-session-inventory.exe inspect|ConvertFrom-Json
 $checks.global_rules_zero=$LASTEXITCODE -eq 0 -and $global.complete -eq $true -and $global.windowsError -eq 0 -and $global.rulesPresent -eq 0
 $clean=@($checks.Values|Where-Object {$_ -ne $true}).Count -eq 0
 @{checks=$checks;cleanup=if($clean){'verified'}else{'failed'}}|ConvertTo-Json -Depth 4|Set-Content C:\P0Results\tun-dns-cleanup.json
 $p.ExitCode|Set-Content C:\P0Results\finished.txt
 if(-not $clean){throw 'Independent cleanup failed'}
} catch {$_|Out-String|Set-Content C:\P0Results\error.txt}
