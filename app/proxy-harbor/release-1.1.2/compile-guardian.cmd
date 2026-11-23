@echo off
call "D:\develop\vs2022\Community\VC\Auxiliary\Build\vcvars64.bat" >nul
if errorlevel 1 exit /b 1
cl.exe /nologo /W4 /WX /MT /O2 /DUNICODE /D_UNICODE /DPH_CLAUDE_MSIX /DPH_CLAUDE_MSIX_DESKTOP /DPH_CLAUDE_TAKEOVER "D:\zhou\Desktop\zhuyao\claude-test\native\session\guardian.c" "D:\zhou\Desktop\zhuyao\claude-test\native\session\account.c" "D:\zhou\Desktop\zhuyao\claude-test\native\session\tcp_path.c" "D:\zhou\Desktop\zhuyao\claude-test\native\session\system_dns.c" "D:\zhou\Desktop\zhuyao\claude-test\native\session\claude_msix.c" "D:\zhou\Desktop\zhuyao\claude-test\native\session\claude_takeover.c" /Fe:proxy-harbor-guardian.exe /link /Brepro Fwpuclnt.lib Advapi32.lib Rpcrt4.lib Iphlpapi.lib Ws2_32.lib Winhttp.lib Netapi32.lib Userenv.lib Bcrypt.lib Wtsapi32.lib Ole32.lib Shell32.lib User32.lib
if errorlevel 1 exit /b 1
cl.exe /nologo /W4 /WX /MT /O2 /DUNICODE /D_UNICODE "D:\zhou\Desktop\zhuyao\claude-test\native\session\inventory.c" /Fe:proxy-harbor-session-inventory.exe /link Fwpuclnt.lib Rpcrt4.lib
