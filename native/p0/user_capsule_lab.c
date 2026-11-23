// Fixed guest-only experiment. Creates a new ordinary account, never adopts
// an existing account and never reads user passwords, profiles or proxy nodes.
#define _WIN32_WINNT 0x0A00
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <lm.h>
#include <userenv.h>
#include <bcrypt.h>
#include <sddl.h>
#include <stdio.h>
#include <wchar.h>
#include "user_policy.h"

static BOOL guest(void) {
    wchar_t cwd[MAX_PATH], image[MAX_PATH], marker[32];
    return GetCurrentDirectoryW(MAX_PATH, cwd) &&
           !_wcsicmp(cwd, L"C:\\P0Lab") &&
           GetModuleFileNameW(NULL, image, MAX_PATH) &&
           !_wcsicmp(image,
                     L"C:\\P0Lab\\.local\\p0\\bin\\p0-user-capsule.exe") &&
           GetEnvironmentVariableW(L"PROXY_HARBOR_P0_GUEST", marker, 32) &&
           !wcscmp(marker, L"offline-lab");
}
int wmain(int argc, wchar_t **argv) {
    if (!guest())
        return 2;
    if (argc == 2 && !wcscmp(argv[1], L"inspect")) {
        unsigned count;
        DWORD e = UserPolicyInspect(&count);
        printf("{\"rulesPresent\":%u,\"windowsError\":%lu}\n", count, e);
        return e ? 1 : 0;
    }
    if (argc != 5 ||
        (wcscmp(argv[1], L"chrome") && wcscmp(argv[1], L"probe")) ||
        wcscmp(argv[4], L"P0") || wcslen(argv[2]) != 16)
        return 2;
    for (unsigned i = 0; i < 16; ++i)
        if (!((argv[2][i] >= L'0' && argv[2][i] <= L'9') ||
              (argv[2][i] >= L'a' && argv[2][i] <= L'f')))
            return 2;
    wchar_t *end = NULL;
    unsigned long port = wcstoul(argv[3], &end, 10);
    if (!end || *end || port < 1024 || port > 65535)
        return 2;
    BOOL browser = !wcscmp(argv[1], L"chrome"), created = FALSE,
         profile_deleted = TRUE, removed = TRUE, empty = TRUE, deleted = FALSE;
    DWORD error = 0, exit_code = MAXDWORD, phase = 0;
    USER_POLICY policy = {0};
    HANDLE login = NULL, token = NULL, job = NULL, handles[3] = {0};
    PROCESS_INFORMATION process = {0};
    STARTUPINFOW startup = {0};
    void *base_environment = NULL;
    wchar_t *environment = NULL;
    wchar_t username[32], password[80], profile_path[MAX_PATH] = {0};
    BYTE random[32], sid_data[SECURITY_MAX_SID_SIZE];
    DWORD sid_size = sizeof(sid_data), domain_size = 128;
    wchar_t domain[128];
    SID_NAME_USE use;
    char *sid_text = NULL;
    swprintf_s(username, 32, L"PHp0_%ls", argv[2] + 2);
    if (BCryptGenRandom(NULL, random, sizeof(random),
                        BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0)
        return 3;
    wcscpy_s(password, 80, L"P0!a");
    for (unsigned i = 0; i < sizeof(random); ++i)
        swprintf_s(password + 4 + i * 2, 80 - 4 - i * 2, L"%02x", random[i]);
    SecureZeroMemory(random, sizeof(random));
    USER_INFO_1 info = {0};
    info.usri1_name = username;
    info.usri1_password = password;
    info.usri1_priv = USER_PRIV_USER;
    info.usri1_flags =
        UF_NORMAL_ACCOUNT | UF_DONT_EXPIRE_PASSWD | UF_PASSWD_CANT_CHANGE;
    info.usri1_comment = L"Proxy Harbor disposable P0 guest account";
    error = NetUserAdd(NULL, 1, (BYTE *)&info, NULL);
    if (error)
        goto cleanup;
    created = TRUE;
    phase = 1;
    if (!LookupAccountNameW(NULL, username, sid_data, &sid_size, domain,
                            &domain_size, &use) ||
        !ConvertSidToStringSidA(sid_data, &sid_text)) {
        error = GetLastError();
        goto cleanup;
    }
    error = UserPolicyInstall(sid_data, (UINT16)port, &policy);
    if (error)
        goto cleanup;
    phase = 2;
    if (!LogonUserW(username, L".", password, LOGON32_LOGON_INTERACTIVE,
                    LOGON32_PROVIDER_DEFAULT, &login)) {
        error = GetLastError();
        goto cleanup;
    }
    // CreateProfile only creates this newly owned profile, without loading or
    // inspecting any existing profile. Chrome uses its ordinary Win32 sandbox.
    wchar_t *wide_sid = NULL;
    if (!ConvertSidToStringSidW(sid_data, &wide_sid)) {
        error = GetLastError();
        goto cleanup;
    }
    HRESULT hr = CreateProfile(wide_sid, username, profile_path, MAX_PATH);
    LocalFree(wide_sid);
    if (FAILED(hr)) {
        error = (DWORD)hr;
        goto cleanup;
    }
    phase = 3;
    if (!CreateEnvironmentBlock(&base_environment, login, FALSE)) {
        error = GetLastError();
        goto cleanup;
    }
    SIZE_T env_size = 0;
    for (wchar_t *p = (wchar_t *)base_environment; *p; p += wcslen(p) + 1)
        env_size += wcslen(p) + 1;
    static const wchar_t marker[] = L"PROXY_HARBOR_P0_GUEST=offline-lab";
    environment =
        HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
                  (env_size + _countof(marker) + 1) * sizeof(wchar_t));
    if (!environment) {
        error = ERROR_OUTOFMEMORY;
        goto cleanup;
    }
    memcpy(environment, base_environment, env_size * sizeof(wchar_t));
    memcpy(environment + env_size, marker, sizeof(marker));
    for (unsigned i = 0; i < 3; ++i) {
        HANDLE source = GetStdHandle(i == 0   ? STD_INPUT_HANDLE
                                     : i == 1 ? STD_OUTPUT_HANDLE
                                              : STD_ERROR_HANDLE);
        if (!DuplicateHandle(GetCurrentProcess(), source, GetCurrentProcess(),
                             &handles[i], 0, TRUE, DUPLICATE_SAME_ACCESS)) {
            error = GetLastError();
            goto cleanup;
        }
    }
    startup.cb = sizeof(startup);
    startup.dwFlags = STARTF_USESTDHANDLES;
    startup.hStdInput = handles[0];
    startup.hStdOutput = handles[1];
    startup.hStdError = handles[2];
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
        swprintf_s(command, 4096,
                   L"\"%ls\" --headless=new --disable-gpu --no-first-run "
                   L"--user-data-dir=\"%ls\\browser\" "
                   L"--proxy-server=socks5://127.0.0.1:%lu --disable-quic "
                   L"--force-webrtc-ip-handling-policy=disable_non_proxied_udp "
                   L"--dump-dom https://api.ipify.org/",
                   image, profile_path, port);
    else
        swprintf_s(command, 4096, L"\"%ls\" -user-capsule -proxy 127.0.0.1:%lu",
                   image, port);
    if (!CreateProcessWithLogonW(
            username, L".", password, LOGON_WITH_PROFILE, image, command,
            CREATE_SUSPENDED | CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT,
            environment, profile_path, &startup, &process)) {
        error = GetLastError();
        goto cleanup;
    }
    phase = 4;
    SecureZeroMemory(password, sizeof(password));
    if (!AssignProcessToJobObject(job, process.hProcess) ||
        !OpenProcessToken(process.hProcess, TOKEN_QUERY, &token)) {
        error = GetLastError();
        goto cleanup;
    }
    BYTE user[256];
    DWORD size = 0;
    if (!GetTokenInformation(token, TokenUser, user, sizeof(user), &size) ||
        !EqualSid(((TOKEN_USER *)user)->User.Sid, sid_data)) {
        error = ERROR_INVALID_TOKEN;
        goto cleanup;
    }
    printf("{\"capsuleReady\":true,\"sid\":\"%s\",\"pid\":%lu,\"rules\":8,"
           "\"debugLoopback\":false,\"identity\":\"dedicated-user\"}\n",
           sid_text, process.dwProcessId);
    fflush(stdout);
    if (ResumeThread(process.hThread) == MAXDWORD) {
        error = GetLastError();
        goto cleanup;
    }
    phase = 5;
    if (WaitForSingleObject(process.hProcess, browser ? 60000 : 120000) !=
        WAIT_OBJECT_0) {
        error = WAIT_TIMEOUT;
        goto cleanup;
    }
    if (!GetExitCodeProcess(process.hProcess, &exit_code))
        error = GetLastError();
cleanup:
    SecureZeroMemory(password, sizeof(password));
    if (job) {
        TerminateJobObject(job, 1);
        for (unsigned i = 0; i < 100; ++i) {
            JOBOBJECT_BASIC_ACCOUNTING_INFORMATION account = {0};
            if (!QueryInformationJobObject(job,
                                           JobObjectBasicAccountingInformation,
                                           &account, sizeof(account), NULL)) {
                empty = FALSE;
                break;
            }
            if (!account.ActiveProcesses)
                break;
            if (i == 99)
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
    if (login)
        CloseHandle(login);
    if (base_environment)
        DestroyEnvironmentBlock(base_environment);
    if (environment)
        HeapFree(GetProcessHeap(), 0, environment);
    if (empty)
        removed = UserPolicyRemove(&policy);
    else
        removed = FALSE;
    if (created && empty && removed) {
        // Only a profile created for this new SID can be removed. Windows owns
        // path validation and removes its registry/profile entries together.
        if (profile_path[0]) {
            wchar_t *wide = NULL;
            profile_deleted = ConvertSidToStringSidW(sid_data, &wide) &&
                              DeleteProfileW(wide, NULL, NULL);
            if (wide)
                LocalFree(wide);
        }
        if (profile_deleted)
            deleted = NetUserDel(NULL, username) == NERR_Success;
    }
    for (unsigned i = 0; i < 3; ++i)
        if (handles[i])
            CloseHandle(handles[i]);
    printf("{\"capsuleResult\":true,\"error\":%lu,\"phase\":%lu,\"exitCode\":%"
           "lu,\"jobEmpty\":%s,\"policyRestored\":%s,\"profileDeleted\":%s,"
           "\"accountDeleted\":%s}\n",
           error, phase, exit_code, empty ? "true" : "false",
           removed ? "true" : "false", profile_deleted ? "true" : "false",
           deleted ? "true" : "false");
    if (sid_text)
        LocalFree(sid_text);
    return error || !empty || !removed || !profile_deleted || !deleted ? 1 : 0;
}
