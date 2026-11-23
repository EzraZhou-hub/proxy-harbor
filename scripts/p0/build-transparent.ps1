param([string]$MSBuild = 'D:\develop\vs2022\Community\MSBuild\Current\Bin\MSBuild.exe')
$ErrorActionPreference = 'Stop'
$repositoryDirectory = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$commit = 'ff54115885b0fc268cee6f22f386bbc2df5ad589'
$sourceDirectory = Join-Path $repositoryDirectory ".cache\p0\Proxychains\$commit\source"
$buildDirectory = Join-Path $repositoryDirectory ('.local\p0\transparent-build\' + [guid]::NewGuid().ToString('N').Substring(0,8))
$binaryDirectory = Join-Path $repositoryDirectory '.local\p0\bin\transparent'
if (-not (Test-Path -LiteralPath $MSBuild)) { throw 'MSBuild was not found.' }
Push-Location $repositoryDirectory
try {
    & node (Join-Path $PSScriptRoot 'verify-transparent-source.mjs')
    if ($LASTEXITCODE -ne 0) { throw 'Locked transparent candidate source verification failed.' }
} finally { Pop-Location }
New-Item -ItemType Directory -Force -Path $buildDirectory, $binaryDirectory | Out-Null
foreach ($entry in Get-ChildItem -LiteralPath $sourceDirectory -Force) {
    Copy-Item -LiteralPath $entry.FullName -Destination $buildDirectory -Recurse -Force
}
$hookMain = Join-Path $buildDirectory 'src\dll\hookdll_main.c'
$hookText = Get-Content -LiteralPath $hookMain -Raw
$hookText = [regex]::Replace($hookText, '\b_CLIENT_ID\b', '_PXCH_CLIENT_ID')
$hookText = [regex]::Replace($hookText, '\bCLIENT_ID\b', 'PXCH_CLIENT_ID')
$hookText = [regex]::Replace($hookText, '\bPCLIENT_ID\b', 'PPXCH_CLIENT_ID')
$hookText = $hookText.Replace('ret_resume:', "ret_resume:`nif (dwLastError != 0) { TerminateProcess(pPi->hProcess, dwLastError); return dwLastError; }")
$hookText = $hookText.Replace('Win32HookWs2_32();', 'Win32HookWs2_32(); P0InstallStrictDnsHooks();')
$hookText = $hookText.Replace('#include "hookdll_win32.h"', '#include "hookdll_win32.h"' + "`n" + '#include "p0_strict_dns.h"')
Set-Content -LiteralPath $hookMain -Value $hookText -Encoding UTF8
$ipcMain = Join-Path $buildDirectory 'src\exe\main.c'
$ipcText = Get-Content -LiteralPath $ipcMain -Raw
$ipcStart = $ipcText.IndexOf('if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(')
$ipcEnd = $ipcText.IndexOf('SecAttr.nLength', $ipcStart)
if($ipcStart -lt 0 -or $ipcEnd -lt 0){throw 'Expected upstream IPC security initialization was not found.'}
$ipcText = $ipcText.Substring(0,$ipcStart) + "if (!P0BuildPipeSecurityDescriptor(&pSecDesc)) return GetLastError();`n`t" + $ipcText.Substring($ipcEnd)
$ipcText = $ipcText.Replace('#include <Sddl.h>',"#include <Sddl.h>`nBOOL P0BuildPipeSecurityDescriptor(PSECURITY_DESCRIPTOR *);")
Set-Content -LiteralPath $ipcMain -Value $ipcText -Encoding UTF8
Copy-Item -LiteralPath (Join-Path $repositoryDirectory 'native\p0\strict-ipc.c') -Destination (Join-Path $buildDirectory 'src\exe\p0_strict_ipc.c')
$argsFile = Join-Path $buildDirectory 'src\exe\args_and_config.c'
$argsText = Get-Content -LiteralPath $argsFile -Raw
$originalPipe = 'L"\\\\.\\pipe\\proxychains_'
if(-not $argsText.Contains($originalPipe)){throw 'Expected upstream IPC pipe prefix was not found.'}
$argsText = $argsText.Replace($originalPipe,'L"\\\\.\\pipe\\LOCAL\\proxychains_')
Set-Content -LiteralPath $argsFile -Value $argsText -Encoding UTF8
$strictHeader = @'
#pragma once
#include <windows.h>
void P0InstallStrictDnsHooks(void);
int __stdcall P0ValidateRelaySocket(UINT_PTR);
int __stdcall P0GetAddrInfoExW(const wchar_t *,const wchar_t *,DWORD,void *,const void *,void **,void *,void *,void *,void **);
int __stdcall P0GetAddrInfoExA(const char *,const char *,DWORD,void *,const void *,void **,void *,void *,void *,void **);
void __stdcall P0FreeAddrInfoExW(void *);
void __stdcall P0FreeAddrInfoExA(void *);
'@
Set-Content -LiteralPath (Join-Path $buildDirectory 'src\dll\p0_strict_dns.h') -Value $strictHeader -Encoding UTF8
Copy-Item -LiteralPath (Join-Path $repositoryDirectory 'native\p0\strict-dns.c') -Destination (Join-Path $buildDirectory 'src\dll\p0_strict_dns.c')
$connectionFile = Join-Path $buildDirectory 'src\dll\hook_connect_win32.c'
$connectionText = Get-Content -LiteralPath $connectionFile -Raw
$connectionText = $connectionText.Replace('#include "hookdll_win32.h"', '#include "hookdll_win32.h"' + "`n" + '#include "p0_strict_dns.h"')
$connectionText = $connectionText.Replace('return orig_fpWs2_32_GetAddrInfoExW(', 'return P0GetAddrInfoExW(').Replace('return orig_fpWs2_32_GetAddrInfoExA(', 'return P0GetAddrInfoExA(')
$connectionText = $connectionText.Replace('orig_fpWs2_32_FreeAddrInfoExW(pAddrInfoEx);', 'P0FreeAddrInfoExW(pAddrInfoEx);').Replace('orig_fpWs2_32_FreeAddrInfoExA_(pAddrInfoEx);', 'P0FreeAddrInfoExA(pAddrInfoEx);')
$connectionText = [regex]::Replace($connectionText,'(PXCH_DLL_API int Ws2_32_Socks5Handshake\([^\r\n]+\)\s*\{)','$1' + "`nif (!P0ValidateRelaySocket((UINT_PTR)s)) { WSASetLastError(WSAEACCES); return SOCKET_ERROR; }`n")
$connectionText = [regex]::Replace($connectionText,'(PROXY_FUNC2\(Ws2_32, gethostbyaddr\)\s*\{)','$1' + "`nWSASetLastError(WSAHOST_NOT_FOUND); return NULL;`n")
foreach ($name in @('getnameinfo','GetNameInfoW')) {
    $connectionText = [regex]::Replace($connectionText,('(PROXY_FUNC2\(Ws2_32, ' + $name + '\)\s*\{)'),'$1' + "`nif (pNodeBuffer && !(Flags & NI_NUMERICHOST)) return EAI_NONAME;`n")
}
Set-Content -LiteralPath $connectionFile -Value $connectionText -Encoding UTF8
$installerFile = Join-Path $buildDirectory 'src\dll\hook_installer.c'
$installerText = (Get-Content -LiteralPath $installerFile -Raw).Replace('GetProcAddress(hWs2_32, "FreeAddrInfoExA")','GetProcAddress(hWs2_32, "FreeAddrInfoEx")')
Set-Content -LiteralPath $installerFile -Value $installerText -Encoding UTF8
$createFile = Join-Path $buildDirectory 'src\dll\hook_createprocess_win32.c'
$createText = Get-Content -LiteralPath $createFile -Raw
$createText = $createText.Replace('dwReturn = InjectTargetProcess(&ProcessInformation, dwCreationFlags);', 'dwReturn = InjectTargetProcess(&ProcessInformation, dwCreationFlags);' + "`n" + 'if (dwReturn != 0) { TerminateProcess(ProcessInformation.hProcess, dwReturn); CloseHandle(ProcessInformation.hThread); CloseHandle(ProcessInformation.hProcess); if (lpProcessInformation) ZeroMemory(lpProcessInformation, sizeof(*lpProcessInformation)); SetLastError(dwReturn); g_bCurrentlyInWinapiCall=FALSE; return FALSE; }')
Set-Content -LiteralPath $createFile -Value $createText -Encoding UTF8
$genericHeader = Join-Path $buildDirectory 'include\includes_generic.h'
$genericText = (Get-Content -LiteralPath $genericHeader -Raw).Replace('#define _WIN32_WINNT 0x0502','#define _WIN32_WINNT 0x0A00')
Set-Content -LiteralPath $genericHeader -Value $genericText -Encoding UTF8
$projectFiles = @(
    'proxychains.exe\proxychains.exe.vcxproj',
    'proxychains_hook.dll\proxychains_hook.dll.vcxproj',
    'proxychains_helper\proxychains_helper.vcxproj',
    'minhook\build\VC15\libMinHook.vcxproj'
)
foreach ($relative in $projectFiles) {
    $path = Join-Path $buildDirectory $relative
    [xml]$project = Get-Content -LiteralPath $path -Raw
    # Upgrade only the isolated build copy. Keep the audited source immutable.
    foreach ($element in $project.SelectNodes('//*[local-name()="PlatformToolset"]')) { $element.InnerText = 'v143' }
    foreach ($element in $project.SelectNodes('//*[local-name()="WindowsTargetPlatformVersion"]')) { $element.InnerText = '10.0.26100.0' }
    foreach ($element in $project.SelectNodes('//*[local-name()="RuntimeLibrary"]')) { $element.InnerText = 'MultiThreaded' }
    foreach ($element in $project.SelectNodes('//*[local-name()="DebugInformationFormat"]')) { $element.InnerText = 'None' }
    foreach ($element in $project.SelectNodes('//*[local-name()="GenerateDebugInformation"]')) { $element.InnerText = 'false' }
    foreach ($element in $project.SelectNodes('//*[local-name()="WholeProgramOptimization"]')) { $element.InnerText = 'false' }
    foreach ($element in $project.SelectNodes('//*[local-name()="IgnoreSpecificDefaultLibraries"]')) { $element.InnerText = '' }
    foreach ($element in @($project.SelectNodes('//*[local-name()="Import" and contains(@Project,"UserRootDir")]'))) { $element.ParentNode.RemoveChild($element) | Out-Null }
    # Explicitly use the static CRT for all configurations and dependencies.
    $definitions = $project.CreateElement('ItemDefinitionGroup', $project.DocumentElement.NamespaceURI)
    $compile = $project.CreateElement('ClCompile', $project.DocumentElement.NamespaceURI)
    $runtime = $project.CreateElement('RuntimeLibrary', $project.DocumentElement.NamespaceURI)
    $runtime.InnerText = 'MultiThreaded'
    $compile.AppendChild($runtime) | Out-Null
    $debugFormat = $project.CreateElement('DebugInformationFormat', $project.DocumentElement.NamespaceURI)
    $debugFormat.InnerText = 'None'
    $compile.AppendChild($debugFormat) | Out-Null
    $options = $project.CreateElement('AdditionalOptions', $project.DocumentElement.NamespaceURI)
    $options.InnerText = '/utf-8 %(AdditionalOptions)'
    $compile.AppendChild($options) | Out-Null
    $definitions.AppendChild($compile) | Out-Null
    $project.DocumentElement.AppendChild($definitions) | Out-Null
    if ($relative -eq 'proxychains_hook.dll\proxychains_hook.dll.vcxproj') {
        $items = $project.CreateElement('ItemGroup',$project.DocumentElement.NamespaceURI)
        $added = $project.CreateElement('ClCompile',$project.DocumentElement.NamespaceURI)
        $added.SetAttribute('Include','..\src\dll\p0_strict_dns.c')
        $items.AppendChild($added) | Out-Null
        $project.DocumentElement.AppendChild($items) | Out-Null
    }
    if ($relative -eq 'proxychains.exe\proxychains.exe.vcxproj') {
        $items = $project.CreateElement('ItemGroup',$project.DocumentElement.NamespaceURI)
        $added = $project.CreateElement('ClCompile',$project.DocumentElement.NamespaceURI)
        $added.SetAttribute('Include','..\src\exe\p0_strict_ipc.c')
        $items.AppendChild($added) | Out-Null
        $project.DocumentElement.AppendChild($items) | Out-Null
    }
    $project.Save($path)
}
function Build-CandidateProject {
    param([string]$RelativePath, [string]$Architecture)
    $log = Join-Path $buildDirectory ((Split-Path -Leaf $RelativePath) + '-' + $Architecture + '.log')
    & $MSBuild (Join-Path $buildDirectory $RelativePath) /nologo /m:1 /v:minimal /p:Configuration=Release "/p:Platform=$Architecture" /p:PlatformToolset=v143 /p:WindowsTargetPlatformVersion=10.0.26100.0 "/p:SolutionDir=$buildDirectory\" *> $log
    if ($LASTEXITCODE -ne 0) { Get-Content -LiteralPath $log -Tail 25; throw "Transparent candidate build failed: $RelativePath/$Architecture. Log: $log" }
}
# Upstream's audited pre-build step runs these helpers only with --dump-functions
# to generate C arrays from their own function bodies. It does not inject a
# process, read application configuration or perform network operations.
Build-CandidateProject 'proxychains_helper\proxychains_helper.vcxproj' 'Win32'
Build-CandidateProject 'proxychains_helper\proxychains_helper.vcxproj' 'x64'
Build-CandidateProject 'proxychains.exe\proxychains.exe.vcxproj' 'x64'
$outputs = @('proxychains_win32_x64.exe','proxychains_hook_x64.dll','proxychains_helper_win32_x64.exe','proxychains_helper_win32_x86.exe')
foreach ($name in $outputs) {
    $file = Join-Path $buildDirectory ('win32_output\' + $name)
    if (-not (Test-Path -LiteralPath $file)) { throw "Missing candidate output: $name" }
    Copy-Item -LiteralPath $file -Destination (Join-Path $binaryDirectory $name) -Force
}
Copy-Item -LiteralPath (Join-Path $sourceDirectory 'COPYING') -Destination (Join-Path $binaryDirectory 'PROXYCHAINS-COPYING.txt') -Force
Copy-Item -LiteralPath (Join-Path $sourceDirectory 'minhook\LICENSE.txt') -Destination (Join-Path $binaryDirectory 'MINHOOK-LICENSE.txt') -Force
Copy-Item -LiteralPath (Join-Path $sourceDirectory 'uthash\LICENSE') -Destination (Join-Path $binaryDirectory 'UTHASH-LICENSE.txt') -Force
@{sourceCommit=$commit;buildDirectory=$buildDirectory;builtAtUtc=[DateTimeOffset]::UtcNow.ToString('o');runtimeExecutedOnHost=$false;strictIpcSHA256=(Get-FileHash -LiteralPath (Join-Path $repositoryDirectory 'native\p0\strict-ipc.c') -Algorithm SHA256).Hash;strictDnsSHA256=(Get-FileHash -LiteralPath (Join-Path $repositoryDirectory 'native\p0\strict-dns.c') -Algorithm SHA256).Hash;buildScriptSHA256=(Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash;files=@($outputs | ForEach-Object { @{name=$_;sha256=(Get-FileHash -LiteralPath (Join-Path $binaryDirectory $_) -Algorithm SHA256).Hash} })} | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $repositoryDirectory '.local\p0\transparent-build.json') -Encoding UTF8
Write-Output "Built free/open-source candidate: $binaryDirectory"
Write-Output 'Build only; candidate launcher and hook DLL are not run on the host.'
