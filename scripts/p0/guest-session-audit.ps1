$ErrorActionPreference='Stop'
if((Get-Location).Path -ne 'C:\P0Lab' -or $env:PROXY_HARBOR_P0_GUEST -ne 'offline-lab' -or -not(Test-Path 'C:\P0Input\manifest.json')){throw 'Disposable guest only'}
$checks=[ordered]@{}
$accounts=@(Get-LocalUser | Where-Object {$_.Name -match '^PH_[0-9a-f]{16}$|^PHp0_[0-9a-f]{14}$'})
$profiles=@(Get-ChildItem -LiteralPath 'C:\Users' -Directory | Where-Object {$_.Name -match '^PH_[0-9a-f]{16}(\.|$)|^PHp0_[0-9a-f]{14}(\.|$)'})
$checks.temporary_accounts_zero=$accounts.Count -eq 0
$checks.temporary_profiles_zero=$profiles.Count -eq 0
$inventories=@()
$guardian='C:\P0Lab\.local\p0\bin\proxy-harbor-guardian.exe'
foreach($directory in Get-ChildItem -LiteralPath 'C:\P0Lab\.local\p0\sessions' -Directory){
 if($directory.Name -notmatch '^[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}$'){throw 'Unexpected session directory'}
 $json=& $guardian inspect $directory.FullName
 $exitCode=$LASTEXITCODE
 $row=$json|ConvertFrom-Json
 $checks['rules_zero_'+$directory.Name]=$exitCode -eq 0 -and $row.windowsError -eq 0 -and $row.rulesPresent -eq 0
 $inventories+=@{session=$directory.Name;rules=$row.rulesPresent;error=$row.windowsError;toolExitCode=$exitCode}
}
foreach($name in @('p0-isolation-inspect.exe','p0-port-guard.exe','p0-user-capsule.exe')){
 $json=& ('C:\P0Lab\.local\p0\bin\'+$name) inspect
 $exitCode=$LASTEXITCODE
 $row=$json|ConvertFrom-Json
 $checks['fixture_rules_zero_'+$name]=$exitCode -eq 0 -and $row.rulesPresent -eq 0
}
$checks.recovery_records_removed=-not(Test-Path 'C:\P0Lab\.local\p0\isolated-sid-recovery.json') -and -not(Test-Path 'C:\P0Lab\.local\p0\user-capsule-recovery.json')
$globalJson=& 'C:\P0Lab\.local\p0\bin\proxy-harbor-session-inventory.exe' inspect
$globalExit=$LASTEXITCODE
$globalInventory=$globalJson|ConvertFrom-Json
$checks.managed_namespace_globally_empty=$globalExit -eq 0 -and $globalInventory.windowsError -eq 0 -and $globalInventory.complete -eq $true -and $globalInventory.rulesPresent -eq 0
$passed=@($checks.Values|Where-Object {$_ -ne $true}).Count -eq 0
@{schemaVersion=1;scope='Independent read-only guest account/profile and precise WFP key audit';checks=$checks;cleanup=if($passed){'verified'}else{'failed'};accounts=@($accounts|ForEach-Object Name);profiles=@($profiles|ForEach-Object Name);inventories=$inventories}|ConvertTo-Json -Depth 6|Set-Content -LiteralPath 'C:\P0Results\session-cleanup-audit.json' -Encoding UTF8
if(-not $passed){throw 'Independent session cleanup audit failed'}
