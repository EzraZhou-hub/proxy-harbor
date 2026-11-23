// Dedicated non-administrator identity. Child processes inherit TokenUser and
// are constrained by the same WFP principal before their first instruction.
#define _WIN32_WINNT 0x0A00
#define WIN32_LEAN_AND_MEAN
#include "account.h"
#include <lm.h>
#include <userenv.h>
#include <bcrypt.h>
#include <sddl.h>
#include <wtsapi32.h>
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>

void SessionAccountName(const GUID *id, wchar_t name[32]) {
    swprintf_s(name, 32, L"PH_%08lx%04x%04x", id->Data1, id->Data2,
               id->Data3);
}
static void paths(const GUID *id, const wchar_t *directory,
                  SESSION_ACCOUNT *a) {
    ZeroMemory(a, sizeof(*a));
    SessionAccountName(id, a->name);
    wchar_t uuid[40];
    StringFromGUID2(id, uuid, 40);
    swprintf_s(a->comment, 128, L"Proxy Harbor owned session %ls", uuid);
    swprintf_s(a->record, 1200, L"%ls\\identity.txt", directory);
}
static DWORD lookup(SESSION_ACCOUNT *a) {
    USER_INFO_4 *info = NULL;
    DWORD error = NetUserGetInfo(NULL, a->name, 4, (BYTE **)&info);
    if (error)
        return error;
    if (!info->usri4_comment || wcscmp(info->usri4_comment, a->comment) ||
        info->usri4_priv != USER_PRIV_USER || !IsValidSid(info->usri4_user_sid))
        error = ERROR_INVALID_OWNER;
    if (!error) {
        a->sid_size = GetLengthSid(info->usri4_user_sid);
        if (a->sid_size > sizeof(a->sid))
            error = ERROR_INVALID_SID;
        else
            CopySid(sizeof(a->sid), a->sid, info->usri4_user_sid);
    }
    NetApiBufferFree(info);
    return error;
}
DWORD SessionAccountConfirmAbsent(const GUID *id, const wchar_t *directory) {
    SESSION_ACCOUNT candidate;
    paths(id, directory, &candidate);
    DWORD error = lookup(&candidate);
    return error == NERR_UserNotFound ? 0 : error ? error : ERROR_BUSY;
}
static BOOL canonical(SESSION_ACCOUNT *a, char out[1024], DWORD *size) {
    char *sid = NULL, name[64], comment[256];
    if (!ConvertSidToStringSidA(a->sid, &sid))
        return FALSE;
    WideCharToMultiByte(CP_UTF8, 0, a->name, -1, name, sizeof(name), NULL,
                        NULL);
    WideCharToMultiByte(CP_UTF8, 0, a->comment, -1, comment, sizeof(comment),
                        NULL, NULL);
    int n = sprintf_s(out, 1024, "PH-ACCOUNT-1\n%s\n%s\n%s\nEND\n", name,
                      comment, sid);
    LocalFree(sid);
    *size = n > 0 ? (DWORD)n : 0;
    return n > 0;
}
static DWORD account_error(SESSION_ACCOUNT *a, const char *phase, DWORD pid,
                           DWORD error) {
    wchar_t path[1200];
    wcscpy_s(path, 1200, a->record);
    wchar_t *slash = wcsrchr(path, L'\\');
    if (slash)
        wcscpy_s(slash + 1, 1200 - (size_t)(slash + 1 - path),
                 L"identity-error.json");
    FILE *file = NULL;
    if (!_wfopen_s(&file, path, L"wb") && file) {
        fprintf(file, "{\"phase\":\"%s\",\"pid\":%lu,\"error\":%lu}\n", phase,
                pid, error);
        fclose(file);
    }
    return error;
}
static DWORD generate_password(SESSION_ACCOUNT *a) {
    BYTE random[32];
    if (BCryptGenRandom(NULL, random, sizeof(random),
                        BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0)
        return ERROR_GEN_FAILURE;
    wcscpy_s(a->password, 80, L"P0!a");
    for (unsigned i = 0; i < sizeof(random); ++i)
        swprintf_s(a->password + 4 + i * 2, 80 - 4 - i * 2, L"%02x", random[i]);
    SecureZeroMemory(random, sizeof(random));
    return ERROR_SUCCESS;
}

DWORD SessionAccountCreate(const GUID *id, const wchar_t *directory,
                           SESSION_ACCOUNT *a) {
    paths(id, directory, a);
    // A record is reserved before making an account. Its handle prevents any
    // replacement until cleanup or process death. An existing record refuses.
    a->record_lock = CreateFileW(
        a->record, GENERIC_READ | GENERIC_WRITE | DELETE, FILE_SHARE_READ, NULL,
        CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    if (a->record_lock == INVALID_HANDLE_VALUE) {
        a->record_lock = NULL;
        return GetLastError();
    }
    DWORD error = generate_password(a);
    if (error)
        return error;
    USER_INFO_1 info = {0};
    info.usri1_name = a->name;
    info.usri1_password = a->password;
    info.usri1_priv = USER_PRIV_USER;
    info.usri1_flags =
        UF_NORMAL_ACCOUNT | UF_DONT_EXPIRE_PASSWD | UF_PASSWD_CANT_CHANGE;
    info.usri1_comment = a->comment;
    error = NetUserAdd(NULL, 1, (BYTE *)&info, NULL);
    if (error)
        return error;
    a->created = TRUE;
    // NetUserAdd does not reliably add the account to BUILTIN\Users. Group
    // names are localized; resolve the well-known SID rather than hardcode it.
    USER_INFO_4 *created_info = NULL;
    error = NetUserGetInfo(NULL, a->name, 4, (BYTE **)&created_info);
    if (error)
        return error;
    LOCALGROUP_MEMBERS_INFO_0 member = {0};
    member.lgrmi0_sid = created_info->usri4_user_sid;
    BYTE group_sid[SECURITY_MAX_SID_SIZE];
    DWORD group_size = sizeof(group_sid), name_size = 128, domain_size = 128;
    wchar_t group_name[128], domain[128];
    SID_NAME_USE use;
    if (!CreateWellKnownSid(WinBuiltinUsersSid, NULL, group_sid, &group_size) ||
        !LookupAccountSidW(NULL, group_sid, group_name, &name_size, domain,
                           &domain_size, &use))
        error = GetLastError();
    else {
        error =
            NetLocalGroupAddMembers(NULL, group_name, 0, (BYTE *)&member, 1);
        if (error == ERROR_MEMBER_IN_ALIAS)
            error = 0;
    }
    NetApiBufferFree(created_info);
    if (error)
        return error;
    error = lookup(a);
    if (error)
        return error;
    char data[1024];
    DWORD length = 0, written = 0;
    if (!canonical(a, data, &length) ||
        !WriteFile(a->record_lock, data, length, &written, NULL) ||
        written != length || !FlushFileBuffers(a->record_lock))
        return ERROR_WRITE_FAULT;
    wchar_t *sid = NULL;
    if (!ConvertSidToStringSidW(a->sid, &sid))
        return GetLastError();
    HRESULT hr = CreateProfile(sid, a->name, a->profile, MAX_PATH);
    LocalFree(sid);
    return FAILED(hr) ? (DWORD)hr : 0;
}
static DWORD load_account(const GUID *id, const wchar_t *directory,
                           SESSION_ACCOUNT *a, BOOL observe) {
    paths(id, directory, a);
    a->record_lock =
        CreateFileW(a->record, observe ? GENERIC_READ : GENERIC_READ | DELETE,
                    observe ? FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE :
                              FILE_SHARE_READ, NULL,
                    OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (a->record_lock == INVALID_HANDLE_VALUE) {
        a->record_lock = NULL;
        return GetLastError();
    }
    char expected[1024], actual[1024] = {0}, name[64], comment[256],
                         sid_text[192], end[8];
    DWORD size = 0, read = 0;
    if (GetFileSize(a->record_lock, NULL) >= sizeof(actual) ||
        !ReadFile(a->record_lock, actual, sizeof(actual) - 1, &read, NULL) ||
        sscanf_s(actual, "PH-ACCOUNT-1\n%63[^\n]\n%255[^\n]\n%191[^\n]\n%7s",
                 name, (unsigned)sizeof(name), comment,
                 (unsigned)sizeof(comment), sid_text,
                 (unsigned)sizeof(sid_text), end, (unsigned)sizeof(end)) != 4 ||
        strcmp(end, "END"))
        return ERROR_INVALID_DATA;
    PSID sid = NULL;
    if (!ConvertStringSidToSidA(sid_text, &sid))
        return ERROR_INVALID_SID;
    a->sid_size = GetLengthSid(sid);
    BOOL valid =
        a->sid_size <= sizeof(a->sid) && CopySid(sizeof(a->sid), a->sid, sid);
    LocalFree(sid);
    if (!valid || !canonical(a, expected, &size) || size != read ||
        memcmp(actual, expected, size))
        return ERROR_INVALID_OWNER;
    SESSION_ACCOUNT current = *a;
    DWORD error = lookup(&current);
    if (error == NERR_UserNotFound)
        return 0; // Retired account; policy cleanup may still be pending.
    if (error || !EqualSid(current.sid, a->sid))
        return error ? error : ERROR_INVALID_OWNER;
    a->created = TRUE;
    return 0;
}
DWORD SessionAccountLoad(const GUID *id, const wchar_t *directory,
                         SESSION_ACCOUNT *a) {
    return load_account(id, directory, a, FALSE);
}
DWORD SessionAccountObserve(const GUID *id, const wchar_t *directory,
                            SESSION_ACCOUNT *a) {
    return load_account(id, directory, a, TRUE);
}
DWORD SessionAccountProcessIdentity(const SESSION_ACCOUNT *a, HANDLE process) {
    HANDLE token = NULL;
    DWORD error;
    if (OpenProcessToken(process, TOKEN_QUERY, &token)) {
        BYTE data[256];
        DWORD size = 0;
        if (GetTokenInformation(token, TokenUser, data, sizeof(data), &size))
            error = EqualSid(((TOKEN_USER *)data)->User.Sid, (PSID)a->sid)
                        ? ERROR_SUCCESS : ERROR_INVALID_OWNER;
        else
            error = GetLastError();
        CloseHandle(token);
        return error;
    }
    error = GetLastError();
    if (error != ERROR_ACCESS_DENIED)
        return error;

    // Sandboxed renderers can restrict token queries. Ask Windows for the
    // account SID while the caller holds and checks the same process handle.
    DWORD pid = GetProcessId(process);
    if (!pid)
        return GetLastError();
    DWORD level = 1, count = 0;
    WTS_PROCESS_INFO_EXW *list = NULL;
    if (!WTSEnumerateProcessesExW(WTS_CURRENT_SERVER_HANDLE, &level,
                                  WTS_ANY_SESSION, (wchar_t **)&list, &count))
        return GetLastError();
    error = ERROR_NOT_FOUND;
    for (DWORD i = 0; i < count; ++i) {
        if (list[i].ProcessId == pid && list[i].pUserSid) {
            error = EqualSid(list[i].pUserSid, (PSID)a->sid)
                        ? ERROR_SUCCESS : ERROR_INVALID_OWNER;
            break;
        }
    }
    WTSFreeMemoryExW(WTSTypeProcessInfoLevel1, list, count);
    return error;
}
BOOL SessionAccountAlive(SESSION_ACCOUNT *a) {
    if (!IsValidSid(a->sid))
        return TRUE;
    DWORD level = 1, count = 0;
    WTS_PROCESS_INFO_EXW *list = NULL;
    if (!WTSEnumerateProcessesExW(WTS_CURRENT_SERVER_HANDLE, &level,
                                  WTS_ANY_SESSION, (wchar_t **)&list, &count))
        return TRUE;
    BOOL alive = FALSE;
    for (DWORD i = 0; i < count; ++i)
        if (list[i].pUserSid && EqualSid(list[i].pUserSid, a->sid)) {
            HANDLE p = OpenProcess(SYNCHRONIZE, FALSE, list[i].ProcessId);
            if (p) {
                alive = WaitForSingleObject(p, 0) != WAIT_OBJECT_0;
                CloseHandle(p);
            } else
                alive = GetLastError() != ERROR_INVALID_PARAMETER;
            if (alive)
                break;
        }
    WTSFreeMemoryExW(WTSTypeProcessInfoLevel1, list, count);
    return alive;
}
#ifdef PH_CLAUDE_MSIX
DWORD SessionAccountRecoverPassword(SESSION_ACCOUNT *a) {
    if (!a->created || !a->record_lock || !IsValidSid(a->sid))
        return ERROR_INVALID_OWNER;
    if (SessionAccountAlive(a))
        return ERROR_BUSY;
    SESSION_ACCOUNT current = *a;
    DWORD error = lookup(&current);
    if (error || !EqualSid(a->sid, current.sid))
        return error ? error : ERROR_INVALID_OWNER;
    error = generate_password(a);
    if (error)
        return error;
    USER_INFO_1003 password = {a->password};
    error = NetUserSetInfo(NULL, a->name, 1003, (BYTE *)&password, NULL);
    if (error)
        SecureZeroMemory(a->password, sizeof(a->password));
    return error;
}
#endif
static int compare_environment(const void *left, const void *right) {
    const wchar_t *a = *(const wchar_t *const *)left;
    const wchar_t *b = *(const wchar_t *const *)right;
    const wchar_t *a_end = wcschr(a + (a[0] == L'='), L'=');
    const wchar_t *b_end = wcschr(b + (b[0] == L'='), L'=');
    return CompareStringOrdinal(a, a_end ? (int)(a_end - a) : -1,
                                b, b_end ? (int)(b_end - b) : -1, TRUE) - CSTR_EQUAL;
}

static DWORD proxy_environment(wchar_t *base, unsigned port, const wchar_t *marker,
                               wchar_t **result) {
    const wchar_t *keys[] = { L"ALL_PROXY=", L"HTTP_PROXY=", L"HTTPS_PROXY=", L"NO_PROXY=" };
    wchar_t proxy[3][80];
    SIZE_T capacity = 5;
    for (const wchar_t *p = base; *p; p += wcslen(p) + 1)
        ++capacity;
    const wchar_t **rows = calloc(capacity, sizeof(*rows));
    if (!rows)
        return ERROR_OUTOFMEMORY;
    SIZE_T count = 0;
    for (const wchar_t *p = base; *p; p += wcslen(p) + 1) {
        BOOL replace = FALSE;
        for (unsigned i = 0; i < _countof(keys); ++i)
            if (!_wcsnicmp(p, keys[i], wcslen(keys[i])))
                replace = TRUE;
        if (!replace && _wcsnicmp(p, L"PROXY_HARBOR_P0_GUEST=", wcslen(L"PROXY_HARBOR_P0_GUEST=")))
            rows[count++] = p;
    }
    for (unsigned i = 0; i < _countof(proxy); ++i) {
        swprintf_s(proxy[i], _countof(proxy[i]), L"%lshttp://127.0.0.1:%u", keys[i], port);
        rows[count++] = proxy[i];
    }
    // Removing NO_PROXY from the clean target environment eliminates inherited exceptions.
    if (marker[0])
        rows[count++] = marker;
    qsort(rows, count, sizeof(*rows), compare_environment);
    SIZE_T chars = 1;
    for (SIZE_T i = 0; i < count; ++i)
        chars += wcslen(rows[i]) + 1;
    *result = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, chars * sizeof(wchar_t));
    if (*result) {
        wchar_t *dest = *result;
        for (SIZE_T i = 0; i < count; ++i) {
            SIZE_T n = wcslen(rows[i]) + 1;
            memcpy(dest, rows[i], n * sizeof(*dest));
            dest += n;
        }
    }
    free(rows);
    return *result ? ERROR_SUCCESS : ERROR_OUTOFMEMORY;
}

DWORD SessionAccountLaunch(SESSION_ACCOUNT *a, const wchar_t *image,
                           wchar_t *command, unsigned proxy_port, STARTUPINFOW *startup,
                           PROCESS_INFORMATION *process, BOOL keep_password) {
    if (!a->created || !a->password[0] || !a->profile[0])
        return ERROR_INVALID_OWNER;
    HANDLE token = NULL;
    void *base = NULL;
    wchar_t *environment = NULL;
    if (!LogonUserW(a->name, L".", a->password, LOGON32_LOGON_INTERACTIVE,
                    LOGON32_PROVIDER_DEFAULT, &token))
        return GetLastError();
    DWORD error = 0;
    if (!CreateEnvironmentBlock(&base, token, FALSE)) {
        error = GetLastError();
        goto cleanup;
    }
    wchar_t marker[64] = {0};
    // A P0-only environment marker is forwarded solely inside the fixed guest.
    wchar_t cwd[MAX_PATH], value[32];
    if (GetCurrentDirectoryW(MAX_PATH, cwd) && !_wcsicmp(cwd, L"C:\\P0Lab") &&
        GetEnvironmentVariableW(L"PROXY_HARBOR_P0_GUEST", value, 32) &&
        !wcscmp(value, L"offline-lab"))
        wcscpy_s(marker, 64, L"PROXY_HARBOR_P0_GUEST=offline-lab");
    error = proxy_environment(base, proxy_port, marker, &environment);
    if (error)
        goto cleanup;
    if (!CreateProcessWithLogonW(a->name, L".", a->password, LOGON_WITH_PROFILE,
                                 image, command,
                                 CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT,
                                 environment, a->profile, startup, process))
        error = GetLastError();
cleanup:
    if (!keep_password || error)
        SecureZeroMemory(a->password, sizeof(a->password));
    if (environment)
        HeapFree(GetProcessHeap(), 0, environment);
    if (base)
        DestroyEnvironmentBlock(base);
    CloseHandle(token);
    return error;
}
DWORD SessionAccountTerminate(SESSION_ACCOUNT *a) {
    if (!IsValidSid(a->sid))
        return ERROR_INVALID_SID;
    unsigned stable = 0;
    DWORD pending = ERROR_BUSY;
    for (unsigned round = 0; round < 50; ++round) {
        DWORD level = 1, count = 0;
        WTS_PROCESS_INFO_EXW *list = NULL;
        if (!WTSEnumerateProcessesExW(WTS_CURRENT_SERVER_HANDLE, &level,
                                      WTS_ANY_SESSION, (wchar_t **)&list,
                                      &count))
            return account_error(a, "enumerate_processes", 0, GetLastError());
        DWORD error = 0;
        BOOL found = FALSE;
        for (DWORD i = 0; i < count && !error; ++i)
            if (list[i].pUserSid && EqualSid(list[i].pUserSid, a->sid)) {
                HANDLE p = OpenProcess(PROCESS_TERMINATE |
                                           PROCESS_QUERY_LIMITED_INFORMATION |
                                           SYNCHRONIZE,
                                       FALSE, list[i].ProcessId);
                if (!p) {
                    DWORD e = GetLastError();
                    if (e != ERROR_INVALID_PARAMETER) {
                        pending = e;
                        found = TRUE;
                    }
                    // WTS may briefly retain an exiting process after the Job
                    // is empty. Retry a fresh snapshot; never infer exit from
                    // denial.
                    continue;
                }
                if (WaitForSingleObject(p, 0) == WAIT_TIMEOUT) {
                    HANDLE token = NULL;
                    BYTE data[256];
                    DWORD size = 0;
                    BOOL owned =
                        OpenProcessToken(p, TOKEN_QUERY, &token) &&
                        GetTokenInformation(token, TokenUser, data,
                                            sizeof(data), &size) &&
                        EqualSid(((TOKEN_USER *)data)->User.Sid, a->sid);
                    if (token)
                        CloseHandle(token);
                    if (!owned && WaitForSingleObject(p, 0) != WAIT_OBJECT_0)
                        pending = ERROR_INVALID_OWNER;
                    else if (owned && !TerminateProcess(p, 1) &&
                             WaitForSingleObject(p, 0) != WAIT_OBJECT_0)
                        pending = GetLastError();
                    found = TRUE;
                }
                CloseHandle(p);
            }
        WTSFreeMemoryExW(WTSTypeProcessInfoLevel1, list, count);
        if (error)
            return account_error(a, "terminate_member", 0, error);
        stable = found ? 0 : stable + 1;
        if (stable >= 3 && !SessionAccountAlive(a))
            return 0;
        Sleep(100);
    }
    return account_error(a, "processes_not_confirmed_gone", 0, pending);
}
DWORD SessionAccountRetire(SESSION_ACCOUNT *a) {
    if (!a->record_lock)
        return a->created ? ERROR_INVALID_OWNER : 0;
    if (a->created) {
        if (SessionAccountAlive(a))
            return ERROR_BUSY;
        if (a->profile_key) {
            if (!UnloadUserProfile(a->profile_token, a->profile_key))
                return GetLastError();
            a->profile_key = NULL;
            CloseHandle(a->profile_token);
            a->profile_token = NULL;
        }
        // Revalidate account identity immediately before deletion.
        SESSION_ACCOUNT check = *a;
        DWORD error = lookup(&check);
        if (error || !EqualSid(check.sid, a->sid))
            return error ? error : ERROR_INVALID_OWNER;
        wchar_t *sid = NULL;
        if (!ConvertSidToStringSidW(a->sid, &sid))
            return GetLastError();
        USER_INFO_1008 flags = {0};
        flags.usri1008_flags = UF_SCRIPT | UF_NORMAL_ACCOUNT |
                               UF_ACCOUNTDISABLE | UF_DONT_EXPIRE_PASSWD;
        error = NetUserSetInfo(NULL, a->name, 1008, (BYTE *)&flags, NULL);
        if (error) {
            LocalFree(sid);
            return error;
        }
        BOOL removed = FALSE;
        for (unsigned i = 0; i < 50; ++i) {
            removed = DeleteProfileW(sid, NULL, NULL);
            error = removed ? 0 : GetLastError();
            if (!error || error == ERROR_FILE_NOT_FOUND)
                break;
            if (error != ERROR_BUSY && error != ERROR_SHARING_VIOLATION)
                break;
            Sleep(100);
        }
        LocalFree(sid);
        if (error && error != ERROR_FILE_NOT_FOUND)
            return error;
        error = NetUserDel(NULL, a->name);
        if (error)
            return error;
        a->created = FALSE;
    }
    return 0;
}
DWORD SessionAccountForget(SESSION_ACCOUNT *a) {
    if (!a->record_lock)
        return 0;
    if (a->created)
        return ERROR_BUSY;
    FILE_DISPOSITION_INFO disposition = {TRUE};
    return SetFileInformationByHandle(a->record_lock, FileDispositionInfo,
                                      &disposition, sizeof(disposition))
               ? 0
               : GetLastError();
}
DWORD SessionAccountDelete(SESSION_ACCOUNT *a) {
    DWORD e = SessionAccountRetire(a);
    return e ? e : SessionAccountForget(a);
}
void SessionAccountRelease(SESSION_ACCOUNT *a) {
    SecureZeroMemory(a->password, sizeof(a->password));
    if (a->record_lock)
        CloseHandle(a->record_lock);
    a->record_lock = NULL;
    if (a->profile_token)
        CloseHandle(a->profile_token);
}

// Load the new user's hive only while installing policies. Holding an extra
// profile reference throughout the session prevents crash recovery from
// deleting it after the guardian loses the matching UnloadUserProfile handle.
static DWORD profile_privilege(const wchar_t *name, BOOL enable) {
    HANDLE token = NULL;
    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token))
        return GetLastError();
    TOKEN_PRIVILEGES privileges = {0};
    privileges.PrivilegeCount = 1;
    DWORD error = 0;
    if (!LookupPrivilegeValueW(NULL, name, &privileges.Privileges[0].Luid))
        error = GetLastError();
    if (!error) {
        privileges.Privileges[0].Attributes = enable ? SE_PRIVILEGE_ENABLED : 0;
        SetLastError(0);
        BOOL adjusted =
            AdjustTokenPrivileges(token, FALSE, &privileges, 0, NULL, NULL);
        error = GetLastError();
        if (!adjusted && !error)
            error = ERROR_PRIVILEGE_NOT_HELD;
    }
    CloseHandle(token);
    return error;
}
static DWORD browser_policy(HKEY root, unsigned port, BOOL install) {
    HKEY key = NULL;
    DWORD disposition = 0;
    DWORD error =
        install ? RegCreateKeyExW(root, L"Software\\Policies\\Google\\Chrome",
                                  0, NULL, 0, KEY_READ | KEY_WRITE | WRITE_DAC,
                                  NULL, &key, &disposition)
                : RegOpenKeyExW(root, L"Software\\Policies\\Google\\Chrome", 0,
                                KEY_READ, &key);
    if (error)
        return error;
    wchar_t proxy[80];
    swprintf_s(proxy, _countof(proxy), L"http://127.0.0.1:%u", port);
    // URL DNS is delegated to the fixed HTTP proxy. Disable speculative
    // resolution and the independent browser DoH path.
    const wchar_t *names[] = {L"ProxyMode", L"ProxyServer", L"ProxyBypassList",
                              L"DnsOverHttpsMode", L"WebRtcIPHandling"};
    const wchar_t *values[] = {L"fixed_servers", proxy, L"<-loopback>", L"off",
                               L"disable_non_proxied_udp"};
    for (unsigned i = 0; !error && i < _countof(names); ++i) {
        DWORD bytes = (DWORD)((wcslen(values[i]) + 1) * sizeof(wchar_t));
        if (install)
            error = RegSetValueExW(key, names[i], 0, REG_SZ,
                                   (const BYTE *)values[i], bytes);
        else {
            wchar_t actual[256] = {0};
            DWORD type = 0, size = sizeof(actual);
            error = RegQueryValueExW(key, names[i], NULL, &type, (BYTE *)actual,
                                     &size);
            if (!error && (type != REG_SZ || size != bytes ||
                           memcmp(actual, values[i], bytes)))
                error = ERROR_INVALID_DATA;
        }
    }
    const wchar_t *numeric[] = {L"NetworkPredictionOptions", L"QuicAllowed",
                                L"EnableMediaRouter"};
    const DWORD expected[] = {2, 0, 0};
    for (unsigned i = 0; !error && i < _countof(numeric); ++i) {
        DWORD actual = 0, size = sizeof(actual), type = 0;
        if (install)
            error = RegSetValueExW(key, numeric[i], 0, REG_DWORD,
                                   (const BYTE *)&expected[i], sizeof(DWORD));
        else {
            error = RegQueryValueExW(key, numeric[i], NULL, &type,
                                     (BYTE *)&actual, &size);
            if (!error && (type != REG_DWORD || size != sizeof(DWORD) ||
                           actual != expected[i]))
                error = ERROR_INVALID_DATA;
        }
    }
    if (!error && install) {
        PSECURITY_DESCRIPTOR sd = NULL;
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
                L"D:P(A;CI;KA;;;SY)(A;CI;KA;;;BA)(A;CI;KR;;;BU)",
                SDDL_REVISION_1, &sd, NULL))
            error = GetLastError();
        else {
            error = RegSetKeySecurity(key,
                                      DACL_SECURITY_INFORMATION |
                                          PROTECTED_DACL_SECURITY_INFORMATION,
                                      sd);
            LocalFree(sd);
        }
        if (!error)
            error = RegFlushKey(key);
    }
    RegCloseKey(key);
    return error;
}
DWORD SessionAccountBrowserPolicy(SESSION_ACCOUNT *a, unsigned port) {
    if (!a->created || !a->password[0] || a->profile_key)
        return ERROR_INVALID_STATE;
    if (!LogonUserW(a->name, L".", a->password, LOGON32_LOGON_INTERACTIVE,
                    LOGON32_PROVIDER_DEFAULT, &a->profile_token))
        return GetLastError();
    DWORD error = profile_privilege(SE_BACKUP_NAME, TRUE);
    if (!error)
        error = profile_privilege(SE_RESTORE_NAME, TRUE);
    PROFILEINFOW profile = {0};
    profile.dwSize = sizeof(profile);
    profile.dwFlags = PI_NOUI;
    profile.lpUserName = a->name;
    if (!error && !LoadUserProfileW(a->profile_token, &profile))
        error = GetLastError();
    if (profile.hProfile)
        a->profile_key = profile.hProfile;
    if (!error)
        error = browser_policy((HKEY)a->profile_key, port, TRUE);
    if (!error)
        error = browser_policy((HKEY)a->profile_key, port, FALSE);
    if (a->profile_key) {
        if (UnloadUserProfile(a->profile_token, a->profile_key))
            a->profile_key = NULL;
        else if (!error)
            error = GetLastError();
    }
    if (!a->profile_key && a->profile_token) {
        CloseHandle(a->profile_token);
        a->profile_token = NULL;
    }
    return error;
}
BOOL SessionAccountBrowserPolicyValid(SESSION_ACCOUNT *a, unsigned port) {
    // CreateProcessWithLogonW(LOGON_WITH_PROFILE) owns the live profile.
    // Read it briefly without adding a LoadUserProfile reference.
    wchar_t *sid = NULL;
    if (!a->created || !ConvertSidToStringSidW(a->sid, &sid))
        return FALSE;
    HKEY root = NULL;
    LSTATUS error = RegOpenKeyExW(HKEY_USERS, sid, 0, KEY_READ, &root);
    LocalFree(sid);
    BOOL valid = !error && !browser_policy(root, port, FALSE);
    if (root)
        RegCloseKey(root);
    return valid;
}
