// Guest-only inherited-identity candidate. No arbitrary image or account data.
#define _WIN32_WINNT 0x0A00
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <userenv.h>
#include <sddl.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <wchar.h>
#include "isolation_policy.h"

static BOOL guest(void) {
    wchar_t cwd[MAX_PATH], marker[32], image[MAX_PATH];
    return GetCurrentDirectoryW(MAX_PATH, cwd) &&
           !_wcsicmp(cwd, L"C:\\P0Lab") &&
           GetEnvironmentVariableW(L"PROXY_HARBOR_P0_GUEST", marker, 32) &&
           !wcscmp(marker, L"offline-lab") &&
           GetModuleFileNameW(NULL, image, MAX_PATH) &&
           !_wcsicmp(image, L"C:\\P0Lab\\.local\\p0\\bin\\p0-capsule.exe");
}
static BOOL member_alive(PSID sid) {
    HANDLE list = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (list == INVALID_HANDLE_VALUE)
        return TRUE;
    PROCESSENTRY32W entry = {0};
    entry.dwSize = sizeof(entry);
    BOOL alive = FALSE;
    for (BOOL more = Process32FirstW(list, &entry); more && !alive;
         more = Process32NextW(list, &entry)) {
        HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE,
                                     entry.th32ProcessID);
        if (!process)
            continue;
        HANDLE token = NULL;
        if (OpenProcessToken(process, TOKEN_QUERY, &token)) {
            BYTE data[256];
            DWORD size = 0;
            if (GetTokenInformation(token, TokenAppContainerSid, data,
                                    sizeof(data), &size)) {
                TOKEN_APPCONTAINER_INFORMATION *info =
                    (TOKEN_APPCONTAINER_INFORMATION *)data;
                if (info->TokenAppContainer &&
                    EqualSid(info->TokenAppContainer, sid))
                    alive = TRUE;
            }
            CloseHandle(token);
        }
        CloseHandle(process);
    }
    CloseHandle(list);
    return alive;
}

int wmain(int argc, wchar_t **argv) {
    if (!guest() || argc != 5)
        return 2;
    BOOL recover = !wcscmp(argv[1], L"recover"),
         browser = !wcscmp(argv[1], L"chrome");
    if (!recover && !browser && wcscmp(argv[1], L"probe"))
        return 2;
    if (wcslen(argv[2]) != 16)
        return 2;
    for (unsigned i = 0; i < 16; ++i)
        if (!((argv[2][i] >= L'0' && argv[2][i] <= L'9') ||
              (argv[2][i] >= L'a' && argv[2][i] <= L'f')))
            return 2;
    wchar_t *end = NULL;
    unsigned long port = wcstoul(argv[3], &end, 10);
    if (!end || *end || port < 1024 || port > 65535)
        return 2;
    if (wcscmp(argv[4], L"P0"))
        return 2;
    wchar_t profile[128];
    swprintf_s(profile, 128, L"ProxyHarbor.P0.Capsule.%ls", argv[2]);
    PSID sid = NULL;
    DWORD error = 0;
    BOOL created = FALSE, deleted = FALSE, restored = TRUE, launched = FALSE,
         empty = TRUE;
    HANDLE job = NULL, token = NULL, handles[3] = {0};
    LPWSTR user_folder = NULL;
    DWORD exit_code = MAXDWORD;
    P0_ISOLATION_POLICY policy = {0};
    PROCESS_INFORMATION process = {0};
    STARTUPINFOEXW startup = {0};
    LPPROC_THREAD_ATTRIBUTE_LIST attributes = NULL;
    char *sid_text = NULL;
    if (recover) {
        HRESULT hr = DeriveAppContainerSidFromAppContainerName(profile, &sid);
        if (FAILED(hr))
            return 3;
        if (member_alive(sid)) {
            FreeSid(sid);
            return 4;
        }
        error = P0RecoverIsolationPolicyForSid(sid, (UINT16)port);
        if (!error) {
            hr = DeleteAppContainerProfile(profile);
            if (FAILED(hr) && hr != HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND))
                error = (DWORD)hr;
        }
        FreeSid(sid);
        printf("{\"recovered\":%s,\"error\":%lu}\n", error ? "false" : "true",
               error);
        return error ? 1 : 0;
    }
    HRESULT hr = CreateAppContainerProfile(
        profile, profile, L"Temporary P0 browser network capsule", NULL, 0,
        &sid);
    if (FAILED(hr)) {
        error = (DWORD)hr;
        goto cleanup;
    }
    created = TRUE;
    if (!ConvertSidToStringSidA(sid, &sid_text)) {
        error = GetLastError();
        goto cleanup;
    }
    LPWSTR wide_sid = NULL;
    if (!ConvertSidToStringSidW(sid, &wide_sid)) {
        error = GetLastError();
        goto cleanup;
    }
    hr = GetAppContainerFolderPath(wide_sid, &user_folder);
    LocalFree(wide_sid);
    if (FAILED(hr)) {
        error = (DWORD)hr;
        goto cleanup;
    }
    error = P0InstallIsolationPolicy(sid, (UINT16)port, &policy);
    if (error)
        goto cleanup;
    SIZE_T bytes = 0;
    InitializeProcThreadAttributeList(NULL, 1, 0, &bytes);
    attributes = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, bytes);
    if (!attributes) {
        error = ERROR_OUTOFMEMORY;
        goto cleanup;
    }
    if (!InitializeProcThreadAttributeList(attributes, 1, 0, &bytes)) {
        error = GetLastError();
        HeapFree(GetProcessHeap(), 0, attributes);
        attributes = NULL;
        goto cleanup;
    }
    SECURITY_CAPABILITIES caps = {0};
    caps.AppContainerSid = sid;
    if (!UpdateProcThreadAttribute(attributes, 0,
                                   PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
                                   &caps, sizeof(caps), NULL, NULL)) {
        error = GetLastError();
        goto cleanup;
    }
    for (unsigned i = 0; i < 3; ++i) {
        HANDLE source = GetStdHandle(
            i == 0 ? STD_INPUT_HANDLE
                   : (i == 1 ? STD_OUTPUT_HANDLE : STD_ERROR_HANDLE));
        if (!DuplicateHandle(GetCurrentProcess(), source, GetCurrentProcess(),
                             &handles[i], 0, TRUE, DUPLICATE_SAME_ACCESS)) {
            error = GetLastError();
            goto cleanup;
        }
    }
    startup.StartupInfo.cb = sizeof(startup);
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = handles[0];
    startup.StartupInfo.hStdOutput = handles[1];
    startup.StartupInfo.hStdError = handles[2];
    startup.lpAttributeList = attributes;
    job = CreateJobObjectW(NULL, NULL);
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits = {0};
    limits.BasicLimitInformation.LimitFlags =
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if (!job || !SetInformationJobObject(job, JobObjectExtendedLimitInformation,
                                         &limits, sizeof(limits))) {
        error = GetLastError();
        goto cleanup;
    }
    wchar_t image[512], command[4096];
    swprintf_s(image, 512, L"C:\\Program Files\\ProxyHarborP0Capsule\\%ls",
               browser ? L"chrome\\chrome.exe" : L"capsule-probe.exe");
    if (browser)
        swprintf_s(
            command, 4096,
            L"\"%ls\" --headless=new --disable-gpu --no-first-run "
            L"--disable-crashpad-for-testing --user-data-dir=\"%ls\\browser\" "
            L"--proxy-server=socks5://127.0.0.1:%lu --disable-quic "
            L"--force-webrtc-ip-handling-policy=disable_non_proxied_udp "
            L"--dump-dom https://api.ipify.org/",
            image, user_folder, port);
    else
        swprintf_s(command, 4096, L"\"%ls\" -proxy 127.0.0.1:%lu", image, port);
    if (!CreateProcessW(image, command, NULL, NULL, TRUE,
                        EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED |
                            CREATE_NO_WINDOW,
                        NULL, user_folder, &startup.StartupInfo, &process)) {
        error = GetLastError();
        goto cleanup;
    }
    launched = TRUE;
    if (!AssignProcessToJobObject(job, process.hProcess) ||
        !OpenProcessToken(process.hProcess, TOKEN_QUERY, &token)) {
        error = GetLastError();
        goto cleanup;
    }
    BYTE token_info[256];
    DWORD size = 0;
    if (!GetTokenInformation(token, TokenAppContainerSid, token_info,
                             sizeof(token_info), &size) ||
        !EqualSid(
            ((TOKEN_APPCONTAINER_INFORMATION *)token_info)->TokenAppContainer,
            sid)) {
        error = ERROR_INVALID_TOKEN;
        goto cleanup;
    }
    printf("{\"capsuleReady\":true,\"sid\":\"%s\",\"pid\":%lu,\"profile\":"
           "\"temporary\",\"rules\":6,\"debugLoopback\":false}\n",
           sid_text, process.dwProcessId);
    fflush(stdout);
    if (ResumeThread(process.hThread) == MAXDWORD) {
        error = GetLastError();
        goto cleanup;
    }
    if (WaitForSingleObject(process.hProcess, browser ? 60000 : 120000) !=
        WAIT_OBJECT_0) {
        error = WAIT_TIMEOUT;
        goto cleanup;
    }
    if (!GetExitCodeProcess(process.hProcess, &exit_code))
        error = GetLastError();
cleanup:
    if (job) {
        TerminateJobObject(job, 1);
        for (unsigned i = 0; i < 50; ++i) {
            JOBOBJECT_BASIC_ACCOUNTING_INFORMATION info = {0};
            if (!QueryInformationJobObject(job,
                                           JobObjectBasicAccountingInformation,
                                           &info, sizeof(info), NULL)) {
                empty = FALSE;
                break;
            }
            if (!info.ActiveProcesses)
                break;
            if (i == 49)
                empty = FALSE;
            Sleep(100);
        }
        CloseHandle(job);
    }
    if (process.hProcess) {
        if (WaitForSingleObject(process.hProcess, 0) != WAIT_OBJECT_0)
            TerminateProcess(process.hProcess, 1);
        CloseHandle(process.hProcess);
        CloseHandle(process.hThread);
    }
    if (token)
        CloseHandle(token);
    if (empty)
        restored = P0RemoveIsolationPolicy(&policy);
    else
        restored = FALSE;
    if (created && restored)
        deleted = SUCCEEDED(DeleteAppContainerProfile(profile));
    if (user_folder)
        CoTaskMemFree(user_folder);
    for (unsigned i = 0; i < 3; ++i)
        if (handles[i])
            CloseHandle(handles[i]);
    if (attributes) {
        DeleteProcThreadAttributeList(attributes);
        HeapFree(GetProcessHeap(), 0, attributes);
    }
    printf(
        "{\"capsuleResult\":true,\"error\":%lu,\"exitCode\":%lu,\"launched\":%"
        "s,\"jobEmpty\":%s,\"policyRestored\":%s,\"profileDeleted\":%s}\n",
        error, exit_code, launched ? "true" : "false", empty ? "true" : "false",
        restored ? "true" : "false", deleted ? "true" : "false");
    if (sid_text)
        LocalFree(sid_text);
    if (sid)
        FreeSid(sid);
    return error || !restored || !deleted ? 1 : 0;
}
