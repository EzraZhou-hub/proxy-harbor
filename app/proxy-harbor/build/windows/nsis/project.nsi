Unicode true

!ifndef ARG_PROXY_HARBOR_BIN
    !error "Build the full Windows distribution with scripts/release.ps1."
!endif
!ifmacrondef PROXY_HARBOR_REQUIRE_IDLE
!macro PROXY_HARBOR_REQUIRE_IDLE
    ClearErrors
    nsExec::ExecToStack /TIMEOUT=10000 '"$INSTDIR\proxy-harbor-session-inventory.exe" require-empty'
    Pop $0
    Pop $1
    ${If} $0 != "0"
        MessageBox MB_ICONSTOP "请先在 Proxy Harbor 中停止或恢复受管会话，然后重试。" /SD IDOK
        SetErrorLevel 3
        Abort
    ${EndIf}
!macroend
!endif

####
## Please note: Template replacements don't work in this file. They are provided with default defines like
## mentioned underneath.
## If the keyword is not defined, "wails_tools.nsh" will populate them.
## If they are defined here, "wails_tools.nsh" will not touch them. This allows you to use this project.nsi manually
## from outside of Wails for debugging and development of the installer.
## 
## For development first make a wails nsis build to populate the "wails_tools.nsh":
## > wails build --target windows/amd64 --nsis
## Then you can call makensis on this file with specifying the path to your binary:
## For a AMD64 only installer:
## > makensis -DARG_WAILS_AMD64_BINARY=..\..\bin\app.exe
## For a ARM64 only installer:
## > makensis -DARG_WAILS_ARM64_BINARY=..\..\bin\app.exe
## For a installer with both architectures:
## > makensis -DARG_WAILS_AMD64_BINARY=..\..\bin\app-amd64.exe -DARG_WAILS_ARM64_BINARY=..\..\bin\app-arm64.exe
####
## The following information is taken from the wails_tools.nsh file, but they can be overwritten here.
####
## !define INFO_PROJECTNAME    "my-project" # Default "proxy-harbor"
## !define INFO_COMPANYNAME    "My Company" # Default "My Company"
## !define INFO_PRODUCTNAME    "My Product Name" # Default "Proxy Harbor"
## !define INFO_PRODUCTVERSION "1.0.0"     # Default "0.1.0"
## !define INFO_COPYRIGHT      "(c) Now, My Company" # Default "© 2026, My Company"
###
## !define PRODUCT_EXECUTABLE  "Application.exe"      # Default "${INFO_PROJECTNAME}.exe"
## !define UNINST_KEY_NAME     "UninstKeyInRegistry"  # Default "${INFO_COMPANYNAME}${INFO_PRODUCTNAME}"
####
## !define REQUEST_EXECUTION_LEVEL "admin"            # Default "admin"  see also https://nsis.sourceforge.io/Docs/Chapter4.html
## !define WAILS_INSTALL_SCOPE     "user"             # Default "machine" - set to "user" for per-user install ($LOCALAPPDATA) without UAC prompt
####
## Include the wails tools
####
!include "wails_tools.nsh"

# The version information for this two must consist of 4 parts
VIProductVersion "${INFO_PRODUCTVERSION}.0"
VIFileVersion    "${INFO_PRODUCTVERSION}.0"

VIAddVersionKey "CompanyName"     "${INFO_COMPANYNAME}"
VIAddVersionKey "FileDescription" "${INFO_PRODUCTNAME} Installer"
VIAddVersionKey "ProductVersion"  "${INFO_PRODUCTVERSION}"
VIAddVersionKey "FileVersion"     "${INFO_PRODUCTVERSION}"
VIAddVersionKey "LegalCopyright"  "${INFO_COPYRIGHT}"
VIAddVersionKey "ProductName"     "${INFO_PRODUCTNAME}"

# Enable HiDPI support. https://nsis.sourceforge.io/Reference/ManifestDPIAware
ManifestDPIAware true

!include "MUI.nsh"

!define MUI_ICON "..\icon.ico"
!define MUI_UNICON "..\icon.ico"
# !define MUI_WELCOMEFINISHPAGE_BITMAP "resources\leftimage.bmp" #Include this to add a bitmap on the left side of the Welcome Page. Must be a size of 164x314
!define MUI_FINISHPAGE_NOAUTOCLOSE # Wait on the INSTFILES page so the user can take a look into the details of the installation steps
!define MUI_ABORTWARNING # This will warn the user if they exit from the installer.

!insertmacro MUI_PAGE_WELCOME # Welcome to the installer page.
# !insertmacro MUI_PAGE_LICENSE "resources\eula.txt" # Adds a EULA page to the installer
!insertmacro MUI_PAGE_INSTFILES # Installing page.
!insertmacro MUI_PAGE_FINISH # Finished installation page.

!insertmacro MUI_UNPAGE_INSTFILES # Uninstalling page

!insertmacro MUI_LANGUAGE "SimpChinese"

## The following two statements can be used to sign the installer and the uninstaller. The path to the binaries are provided in %1
#!uninstfinalize 'signtool --file "%1"'
#!finalize 'signtool --file "%1"'

Name "${INFO_PRODUCTNAME}"
OutFile "${ARG_PROXY_HARBOR_SETUP}"
InstallDir "$PROGRAMFILES64\${INFO_PRODUCTNAME}"
ShowInstDetails show # This will always show the installation details.

Function .onInit
   !insertmacro wails.checkArchitecture
   StrCpy $INSTDIR "$PROGRAMFILES64\${INFO_PRODUCTNAME}"
FunctionEnd

Section
    !insertmacro wails.setShellContext
    IfFileExists "$INSTDIR\proxy-harbor-session-inventory.exe" 0 +2
    Call CheckIdle
    Call CheckRunning

    !insertmacro wails.webview2runtime

    SetOutPath $INSTDIR
    
    !insertmacro wails.files
    File "${ARG_PROXY_HARBOR_BIN}\proxy-harbor-guardian.exe"
    File "${ARG_PROXY_HARBOR_BIN}\proxy-harbor-session-inventory.exe"

    CreateShortcut "$SMPROGRAMS\${INFO_PRODUCTNAME}.lnk" "$INSTDIR\${PRODUCT_EXECUTABLE}"
    CreateShortCut "$DESKTOP\${INFO_PRODUCTNAME}.lnk" "$INSTDIR\${PRODUCT_EXECUTABLE}"

    !insertmacro wails.associateFiles
    !insertmacro wails.associateCustomProtocols
    
    !insertmacro wails.writeUninstaller
SectionEnd

Function CheckIdle
    !insertmacro PROXY_HARBOR_REQUIRE_IDLE
FunctionEnd

# The program keeps running in the notification area after its window is
# closed, and a running image cannot be replaced. Probe the executable for
# write access and close the resident process after confirmation.
Function CheckRunning
    IfFileExists "$INSTDIR\${PRODUCT_EXECUTABLE}" 0 done
    ClearErrors
    FileOpen $9 "$INSTDIR\${PRODUCT_EXECUTABLE}" a
    ${If} ${Errors}
        MessageBox MB_OKCANCEL|MB_ICONEXCLAMATION "Proxy Harbor 仍在后台托盘运行，安装程序需要先关闭它才能继续。$\r$\n$\r$\n是否立即关闭？" IDOK close IDCANCEL abort
        abort:
            SetErrorLevel 5
            Abort
        close:
            nsExec::ExecToStack '"$SYSDIR\taskkill.exe" /F /IM "${PRODUCT_EXECUTABLE}"'
            Pop $0
            Pop $1
            Sleep 1500
    ${Else}
        FileClose $9
    ${EndIf}
    done:
FunctionEnd

Section "uninstall" 
    !insertmacro wails.setShellContext

    !insertmacro PROXY_HARBOR_REQUIRE_IDLE
    Call un.CheckRunning
    ClearErrors
    Delete "$INSTDIR\${PRODUCT_EXECUTABLE}"
    ${If} ${Errors}
        MessageBox MB_ICONSTOP "请先从托盘菜单退出 Proxy Harbor，然后重试。" /SD IDOK
        SetErrorLevel 4
        Abort
    ${EndIf}
    Delete "$INSTDIR\proxy-harbor-guardian.exe"
    Delete "$INSTDIR\proxy-harbor-session-inventory.exe"

    DeleteRegValue HKCU "Software\Microsoft\Windows\CurrentVersion\Run" "proxy-harbor"

    Delete "$SMPROGRAMS\${INFO_PRODUCTNAME}.lnk"
    Delete "$DESKTOP\${INFO_PRODUCTNAME}.lnk"

    !insertmacro wails.unassociateFiles
    !insertmacro wails.unassociateCustomProtocols

    !insertmacro wails.deleteUninstaller
    RMDir "$INSTDIR"
SectionEnd

Function un.CheckRunning
    IfFileExists "$INSTDIR\${PRODUCT_EXECUTABLE}" 0 done
    ClearErrors
    FileOpen $9 "$INSTDIR\${PRODUCT_EXECUTABLE}" a
    ${If} ${Errors}
        MessageBox MB_OKCANCEL|MB_ICONEXCLAMATION "Proxy Harbor 仍在后台托盘运行，卸载程序需要先关闭它才能继续。$\r$\n$\r$\n是否立即关闭？" IDOK close IDCANCEL abort
        abort:
            SetErrorLevel 5
            Abort
        close:
            nsExec::ExecToStack '"$SYSDIR\taskkill.exe" /F /IM "${PRODUCT_EXECUTABLE}"'
            Pop $0
            Pop $1
            Sleep 1500
    ${Else}
        FileClose $9
    ${EndIf}
    done:
FunctionEnd
