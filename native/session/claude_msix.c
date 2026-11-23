#define _WIN32_WINNT 0x0A00
#define WIN32_LEAN_AND_MEAN
#include "claude_msix.h"
#include <sddl.h>
#include <stdio.h>
#include <wchar.h>

static const wchar_t family[] = L"Claude_pzs8sxrjxfjjc";
static const wchar_t image_suffix[] = L"\\app\\Claude.exe";

BOOL ClaudeMSIXPackage(const wchar_t *image, wchar_t *package) {
    size_t length = wcslen(image), tail = ARRAYSIZE(image_suffix) - 1;
    if (length <= tail || image[1] != L':' || image[2] != L'\\')
        return FALSE;
    const wchar_t *end = image + length - tail;
    if (_wcsicmp(end, image_suffix))
        return FALSE;
    const wchar_t *name = end;
    while (name > image + 2 && name[-1] != L'\\')
        --name;
    if (name == end || end - name > PACKAGE_FULL_NAME_MAX_LENGTH)
        return FALSE;
    for (const wchar_t *part = name; part < end; ++part) {
        wchar_t c = *part;
        if (!((c >= L'a' && c <= L'z') || (c >= L'A' && c <= L'Z') ||
              (c >= L'0' && c <= L'9') || c == L'.' || c == L'_' || c == L'-'))
            return FALSE;
    }
    wcsncpy_s(package, PACKAGE_FULL_NAME_MAX_LENGTH + 1, name, (size_t)(end - name));
    const wchar_t x64_suffix[] = L"_x64__pzs8sxrjxfjjc";
    size_t package_length = wcslen(package), suffix_length = ARRAYSIZE(x64_suffix) - 1;
    if (package_length <= suffix_length || _wcsicmp(package + package_length - suffix_length, x64_suffix))
        return FALSE;
    wchar_t parsed[PACKAGE_FAMILY_NAME_MAX_LENGTH + 1];
    UINT32 parsed_length = ARRAYSIZE(parsed);
    return PackageFamilyNameFromFullName(package, &parsed_length, parsed) == ERROR_SUCCESS &&
           !_wcsicmp(parsed, family);
}

static BOOL append_executable(wchar_t *path, size_t capacity) {
    return wcscat_s(path, capacity, image_suffix) == 0;
}

BOOL ClaudeMSIXInstalledImage(const wchar_t *image, const wchar_t *package) {
    wchar_t path[1024];
    UINT32 length = ARRAYSIZE(path) - ARRAYSIZE(image_suffix);
    if (GetStagedPackagePathByFullName(package, &length, path) == ERROR_SUCCESS &&
        append_executable(path, ARRAYSIZE(path)) && !_wcsicmp(path, image))
        return TRUE;
    length = ARRAYSIZE(path) - ARRAYSIZE(image_suffix);
    return GetPackagePathByFullName(package, &length, path) == ERROR_SUCCESS &&
           append_executable(path, ARRAYSIZE(path)) && !_wcsicmp(path, image);
}

BOOL ClaudeMSIXFindImage(wchar_t *image, size_t capacity) {
    wchar_t names[4096], *packages[32], path[1024], parsed[PACKAGE_FULL_NAME_MAX_LENGTH + 1];
    UINT32 count = ARRAYSIZE(packages), length = ARRAYSIZE(names);
    if (GetPackagesByPackageFamily(family, &count, packages, &length, names) != ERROR_SUCCESS)
        return FALSE;
    BOOL found = FALSE;
    for (UINT32 i = 0; i < count; ++i) {
        length = ARRAYSIZE(path) - ARRAYSIZE(image_suffix);
        if (GetStagedPackagePathByFullName(packages[i], &length, path) != ERROR_SUCCESS ||
            !append_executable(path, ARRAYSIZE(path)) || !ClaudeMSIXPackage(path, parsed) ||
            _wcsicmp(parsed, packages[i]))
            continue;
        if (found || wcscpy_s(image, capacity, path))
            return FALSE;
        found = TRUE;
    }
    return found;
}

static BOOL image_file_id(const wchar_t *path, FILE_ID_INFO *id) {
    HANDLE image = CreateFileW(path, FILE_READ_ATTRIBUTES,
                               FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
                               OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (image == INVALID_HANDLE_VALUE)
        return FALSE;
    BOOL ok = GetFileInformationByHandleEx(image, FileIdInfo, id, sizeof(*id));
    CloseHandle(image);
    return ok;
}

static BOOL same_installed_image(const wchar_t *actual, const wchar_t *expected) {
    // AppX can expose the package through links to another installation volume.
    FILE_ID_INFO a, b;
    return !_wcsicmp(actual, expected) ||
           (image_file_id(actual, &a) && image_file_id(expected, &b) &&
            a.VolumeSerialNumber == b.VolumeSerialNumber &&
            !memcmp(&a.FileId, &b.FileId, sizeof(a.FileId)));
}

BOOL ClaudeMSIXMatches(HANDLE process, const wchar_t *image, const wchar_t *package, PSID sid) {
    wchar_t actual_image[1024], actual_package[PACKAGE_FULL_NAME_MAX_LENGTH + 1];
    DWORD path_length = ARRAYSIZE(actual_image);
    UINT32 package_length = ARRAYSIZE(actual_package);
    if (!QueryFullProcessImageNameW(process, 0, actual_image, &path_length) ||
        !same_installed_image(actual_image, image) ||
        GetPackageFullName(process, &package_length, actual_package) != ERROR_SUCCESS ||
        _wcsicmp(actual_package, package))
        return FALSE;
    HANDLE token = NULL;
    BYTE data[256];
    DWORD size;
    if (!OpenProcessToken(process, TOKEN_QUERY, &token))
        return FALSE;
    BOOL match = GetTokenInformation(token, TokenUser, data, sizeof(data), &size) &&
                 EqualSid(((TOKEN_USER *)data)->User.Sid, sid);
    CloseHandle(token);
    return match;
}

static DWORD appx(const wchar_t *script, DWORD timeout, const wchar_t *diagnostic_path, SESSION_ACCOUNT *account) {
    wchar_t system[MAX_PATH], executable[MAX_PATH], command[4096];
    UINT length = GetSystemDirectoryW(system, ARRAYSIZE(system));
    if (!length || length >= ARRAYSIZE(system))
        return ERROR_PATH_NOT_FOUND;
    if (swprintf_s(executable, ARRAYSIZE(executable), L"%ls\\WindowsPowerShell\\v1.0\\powershell.exe", system) < 0 ||
        swprintf_s(command, ARRAYSIZE(command),
                   L"\"%ls\" -NoProfile -NonInteractive -Command \"$ErrorActionPreference='Stop';"
                   L"try {Import-Module -Name '%ls\\WindowsPowerShell\\v1.0\\Modules\\Appx\\Appx.psd1';%ls}"
                   L"catch {[Console]::Error.WriteLine($_.Exception.Message);exit 1}\"",
                   executable, system, script) < 0)
        return ERROR_INVALID_PARAMETER;
    STARTUPINFOW startup = {0};
    PROCESS_INFORMATION process = {0};
    startup.cb = sizeof(startup);
    HANDLE diagnostic = NULL, input = NULL;
    DWORD code = ERROR_SUCCESS;
    if (diagnostic_path) {
        SECURITY_ATTRIBUTES security = {sizeof(security), NULL, TRUE};
        diagnostic = CreateFileW(diagnostic_path, GENERIC_WRITE, FILE_SHARE_READ, &security, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        input = CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, &security, OPEN_EXISTING, 0, NULL);
        if (diagnostic == INVALID_HANDLE_VALUE || input == INVALID_HANDLE_VALUE) {
            code = ERROR_WRITE_FAULT;
            goto close_streams;
        }
        startup.dwFlags = STARTF_USESTDHANDLES;
        startup.hStdInput = input;
        startup.hStdOutput = diagnostic;
        startup.hStdError = diagnostic;
    }
    BOOL launched = account ? CreateProcessWithLogonW(account->name, L".", account->password, LOGON_WITH_PROFILE,
                                                      executable, command, CREATE_NO_WINDOW, NULL, system, &startup, &process)
                            : CreateProcessW(executable, command, NULL, NULL, diagnostic_path != NULL,
                                             CREATE_NO_WINDOW, NULL, system, &startup, &process);
    if (!launched)
        code = GetLastError();
    if (account)
        SecureZeroMemory(account->password, sizeof(account->password));
close_streams:
    if (diagnostic && diagnostic != INVALID_HANDLE_VALUE)
        CloseHandle(diagnostic);
    if (input && input != INVALID_HANDLE_VALUE)
        CloseHandle(input);
    if (code)
        return code;
    DWORD wait = WaitForSingleObject(process.hProcess, timeout);
    if (wait == WAIT_OBJECT_0) {
        if (!GetExitCodeProcess(process.hProcess, &code))
            code = GetLastError();
    } else {
        code = wait == WAIT_TIMEOUT ? ERROR_TIMEOUT : GetLastError();
        TerminateProcess(process.hProcess, 1);
        WaitForSingleObject(process.hProcess, 3000);
    }
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    return code;
}

static int registration_script(wchar_t *script, size_t capacity, const wchar_t *sid, const wchar_t *action) {
    return swprintf_s(script, capacity,
                      L"$sid='%ls'; $family='%ls';"
                      L"$registered={Appx\\Get-AppxPackage -AllUsers -Name Claude | Where-Object {"
                      L"$_.PackageFamilyName -eq $family -and ($_.PackageUserInformation | Where-Object {"
                      L"$_.UserSecurityId.Sid -eq $sid -and [string]$_.InstallState -like 'Installed*'})}};%ls",
                      sid, family, action);
}

DWORD ClaudeMSIXRegistrationPresent(PSID sid, BOOL *present) {
    wchar_t *text = NULL, script[1024];
    *present = FALSE;
    if (!ConvertSidToStringSidW(sid, &text))
        return GetLastError();
    int size = registration_script(script, ARRAYSIZE(script), text, L"if (& $registered) {exit 5308676}");
    LocalFree(text);
    DWORD result = size > 0 ? appx(script, 20000, NULL, NULL) : ERROR_INVALID_PARAMETER;
    if (result == 5308676) {
        *present = TRUE;
        return ERROR_SUCCESS;
    }
    return result;
}

DWORD ClaudeMSIXUnregister(SESSION_ACCOUNT *account, const wchar_t *diagnostic_path) {
    wchar_t *text = NULL, script[1024], verify[512];
    if (!ConvertSidToStringSidW(account->sid, &text))
        return GetLastError();
    DWORD removal_result = ERROR_SUCCESS;
    if (account->password[0]) {
        // Cross-user removal can remain pending until the account logs on.
        // Use the already-verified session identity to remove its own package.
        int count = swprintf_s(script, ARRAYSIZE(script),
                               L"$sid='%ls';if ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne $sid) {exit 1};"
                               L"Appx\\Get-AppxPackage -Name Claude | Where-Object PackageFamilyName -eq '%ls' | "
                               L"ForEach-Object {Appx\\Remove-AppxPackage -Package $_.PackageFullName}", text, family);
        removal_result = count > 0 ? appx(script, 20000, NULL, account) : ERROR_INVALID_PARAMETER;
    }

    // Windows can finish the queued removal after the helper times out.
    // Allow cleanup to continue only after an independent SID-scoped query
    // confirms there is no installed or pending-removal registration.
    int count = swprintf_s(verify, ARRAYSIZE(verify),
                           L"[Console]::WriteLine('removal_helper_exit=%lu');"
                           L"$clock=[Diagnostics.Stopwatch]::StartNew();"
                           L"do {if (-not (& $registered)) {"
                           L"[Console]::WriteLine('registration=absent');exit 0};"
                           L"Start-Sleep -Milliseconds 250} while ($clock.ElapsedMilliseconds -lt 25000);"
                           L"throw 'Claude registration remains installed or pending removal for session SID'",
                           removal_result);
    int size = count > 0 ? registration_script(script, ARRAYSIZE(script), text, verify) : -1;
    LocalFree(text);
    return size > 0 ? appx(script, 30000, diagnostic_path, NULL) : ERROR_INVALID_PARAMETER;
}

DWORD ClaudeMSIXLaunch(const wchar_t *image, unsigned proxy_port) {
    wchar_t package[PACKAGE_FULL_NAME_MAX_LENGTH + 1], script[512];
    BOOL in_job = FALSE;
    if (!ClaudeMSIXPackage(image, package) || !ClaudeMSIXInstalledImage(image, package) ||
        !IsProcessInJob(GetCurrentProcess(), NULL, &in_job) || !in_job ||
        swprintf_s(script, ARRAYSIZE(script),
                   L"Appx\\Add-AppxPackage -RegisterByFamilyName -MainPackage %ls;"
                   L"if (-not (Appx\\Get-AppxPackage -Name Claude | Where-Object PackageFullName -eq '%ls')) {exit 11}",
                   family, package) < 0)
        return 0x81010000;
    // Secondary logon loads the profile after the guardian prepared the
    // environment. Resolve these paths in the now-loaded private profile.
    wchar_t profile[MAX_PATH], local[MAX_PATH], roaming[MAX_PATH], temp[MAX_PATH], alias[MAX_PATH], command[4096];
    DWORD length = GetCurrentDirectoryW(ARRAYSIZE(profile), profile);
    if (!length || length >= ARRAYSIZE(profile) ||
        swprintf_s(local, ARRAYSIZE(local), L"%ls\\AppData\\Local", profile) < 0 ||
        swprintf_s(roaming, ARRAYSIZE(roaming), L"%ls\\AppData\\Roaming", profile) < 0 ||
        swprintf_s(temp, ARRAYSIZE(temp), L"%ls\\Temp", local) < 0 ||
        swprintf_s(alias, ARRAYSIZE(alias), L"%ls\\Microsoft\\WindowsApps\\claude-desktop.exe", local) < 0 ||
        !SetEnvironmentVariableW(L"USERPROFILE", profile) || !SetEnvironmentVariableW(L"LOCALAPPDATA", local) ||
        !SetEnvironmentVariableW(L"APPDATA", roaming) || !SetEnvironmentVariableW(L"TEMP", temp) ||
        !SetEnvironmentVariableW(L"TMP", temp))
        return 0x81030000;
    if (!CreateDirectoryW(temp, NULL) && GetLastError() != ERROR_ALREADY_EXISTS)
        return 0x81030000 | (GetLastError() & 0xffff);
    DWORD error = appx(script, 20000, L"claude-registration.log", NULL);
    if (error)
        return 0x81020000 | (error & 0xffff);
    for (unsigned i = 0; i < 20 && GetFileAttributesW(alias) == INVALID_FILE_ATTRIBUTES; ++i)
        Sleep(100);
    if (GetFileAttributesW(alias) == INVALID_FILE_ATTRIBUTES)
        return 0x81070000 | (GetLastError() & 0xffff);
    if (swprintf_s(command, ARRAYSIZE(command),
                   L"\"%ls\" --proxy-server=http://127.0.0.1:%u --proxy-bypass-list=\"<-loopback>\"",
                   alias, proxy_port) < 0)
        return 0x81030000;
    HANDLE token = NULL;
    BYTE data[256];
    DWORD size;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
        return 0x81040000;
    BOOL valid = GetTokenInformation(token, TokenUser, data, sizeof(data), &size);
    CloseHandle(token);
    if (!valid)
        return 0x81040000;
    STARTUPINFOW startup = {0};
    PROCESS_INFORMATION app = {0};
    startup.cb = sizeof(startup);
    // App execution aliases are reparse points. Invoke the fully quoted path
    // through the command line, as the Windows Process API launch probe did.
    if (!CreateProcessW(NULL, command, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &startup, &app))
        return 0x81050000 | (GetLastError() & 0xffff);
    // The guardian owns the Job handle and performs the final verification
    // while the application is still suspended. Only identifiers cross back.
    DWORD result = 0x81060000;
    if (app.dwProcessId < 0x80000000 && ClaudeMSIXMatches(app.hProcess, image, package, ((TOKEN_USER *)data)->User.Sid)) {
        FILETIME created, exited, kernel, user;
        HANDLE handoff = CreateFileW(L"claude-suspended.txt", GENERIC_WRITE, 0, NULL,
                                     CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
        result = 0x81080000;
        if (handoff != INVALID_HANDLE_VALUE) {
            if (GetProcessTimes(app.hProcess, &created, &exited, &kernel, &user)) {
                char record[96];
                ULONGLONG born = ((ULONGLONG)created.dwHighDateTime << 32) | created.dwLowDateTime;
                int length_bytes = sprintf_s(record, sizeof(record), "%lu %lu %llu\n", app.dwProcessId, app.dwThreadId, born);
                DWORD written;
                if (length_bytes > 0 && WriteFile(handoff, record, (DWORD)length_bytes, &written, NULL) &&
                    written == (DWORD)length_bytes)
                    result = app.dwProcessId;
            }
            CloseHandle(handoff);
        }
    }
    if (result != app.dwProcessId) {
        TerminateProcess(app.hProcess, 1);
        WaitForSingleObject(app.hProcess, 3000);
    }
    CloseHandle(app.hThread);
    CloseHandle(app.hProcess);
    return result;
}
