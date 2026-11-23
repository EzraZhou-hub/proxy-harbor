// Disposable-guest experiment for a session user's shared DNS RPC path.
#define _WIN32_WINNT 0x0A00
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#pragma warning(push)
#pragma warning(disable: 4201)
#include <windns.h>
#pragma warning(pop)
#include <objbase.h>
#include <fwpmu.h>
#include <sddl.h>
#include <stdio.h>
#include <wchar.h>
#include "../session/account.h"

static int client(const wchar_t *name, const wchar_t *output) {
    PDNS_RECORD records = NULL;
    DNS_STATUS result = DnsQuery_W(name, DNS_TYPE_A, DNS_QUERY_BYPASS_CACHE,
                                   NULL, &records, NULL);
    FILE *file = NULL;
    if (_wfopen_s(&file, output, L"wb") || !file)
        return 2;
    fprintf(file, "{\"dnsStatus\":%ld,\"records\":%s}\n", result,
            records ? "true" : "false");
    fclose(file);
    if (records)
        DnsRecordListFree(records, DnsFreeRecordList);
    return 0;
}

int wmain(int argc, wchar_t **argv) {
    wchar_t cwd[MAX_PATH], marker[32];
    if (!GetCurrentDirectoryW(MAX_PATH, cwd) ||
        !GetEnvironmentVariableW(L"PROXY_HARBOR_P0_GUEST", marker, 32) ||
        wcscmp(marker, L"offline-lab"))
        return 2;
    if (argc == 4 && !wcscmp(argv[1], L"client") &&
        !_wcsnicmp(cwd, L"C:\\Users\\PH_", 12) &&
        wcslen(argv[2]) == 37 &&
        !wcscmp(argv[2] + 16, L".p0-dns-audit.invalid"))
        return client(argv[2], argv[3]);
    if (argc != 3 || !GetCurrentDirectoryW(MAX_PATH, cwd) ||
        _wcsicmp(cwd, L"C:\\P0Lab") ||
        !GetEnvironmentVariableW(L"PROXY_HARBOR_P0_GUEST", marker, 32) ||
        wcscmp(marker, L"offline-lab"))
        return 2;
    if (!wcscmp(argv[1], L"cleanup")) {
        const wchar_t *prefix = L"C:\\P0Lab\\rpc-";
        if (_wcsnicmp(argv[2], prefix, wcslen(prefix)))
            return 2;
        GUID owned;
        if (CLSIDFromString(argv[2] + wcslen(prefix), &owned) != S_OK)
            return 2;
        SESSION_ACCOUNT stale = {0};
        DWORD result = SessionAccountLoad(&owned, argv[2], &stale);
        if (!result && stale.created)
            result = SessionAccountTerminate(&stale);
        if (!result)
            result = SessionAccountDelete(&stale);
        SessionAccountRelease(&stale);
        printf("{\"cleanupError\":%lu}\n", result);
        return result ? 1 : 0;
    }
    BOOL filtered = !wcscmp(argv[1], L"filtered");
    if (!filtered && wcscmp(argv[1], L"control"))
        return 2;
    GUID id;
    if (UuidCreate(&id) != RPC_S_OK)
        return 2;
    wchar_t uuid[40], folder[MAX_PATH];
    StringFromGUID2(&id, uuid, 40);
    swprintf_s(folder, MAX_PATH, L"C:\\P0Lab\\rpc-%ls", uuid);
    if (!CreateDirectoryW(folder, NULL))
        return 2;
    SESSION_ACCOUNT account = {0};
    DWORD error = SessionAccountCreate(&id, folder, &account);
    HANDLE engine = NULL;
    PSECURITY_DESCRIPTOR descriptor = NULL;
    if (!error && filtered) {
        FWPM_SESSION0 session = {0};
        session.flags = FWPM_SESSION_FLAG_DYNAMIC;
        error = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, &session, &engine);
        wchar_t *sid = NULL, sddl[256];
        if (!error && !ConvertSidToStringSidW(account.sid, &sid))
            error = GetLastError();
        if (!error) {
            swprintf_s(sddl, 256, L"D:(A;;CC;;;%ls)", sid);
            if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    sddl, SDDL_REVISION_1, &descriptor, NULL))
                error = GetLastError();
        }
        if (sid)
            LocalFree(sid);
        FWP_BYTE_BLOB sd = {0};
        if (!error) {
            sd.data = descriptor;
            sd.size = GetSecurityDescriptorLength(descriptor);
            FWPM_FILTER_CONDITION0 condition = {0};
            condition.fieldKey = FWPM_CONDITION_REMOTE_USER_TOKEN;
            condition.matchType = FWP_MATCH_EQUAL;
            condition.conditionValue.type = FWP_SECURITY_DESCRIPTOR_TYPE;
            condition.conditionValue.sd = &sd;
            FWPM_FILTER0 filter = {0};
            filter.filterKey = id;
            filter.layerKey = FWPM_LAYER_RPC_UM;
            filter.subLayerKey = FWPM_SUBLAYER_UNIVERSAL;
            filter.displayData.name = L"ProxyHarbor guest DNS RPC experiment";
            filter.action.type = FWP_ACTION_BLOCK;
            filter.numFilterConditions = 1;
            filter.filterCondition = &condition;
            error = FwpmFilterAdd0(engine, &filter, NULL, NULL);
        }
    }
    wchar_t output[MAX_PATH], image[MAX_PATH], command[2048];
    swprintf_s(output, MAX_PATH, L"%ls\\dns-rpc.json", account.profile);
    if (!error && !GetModuleFileNameW(NULL, image, MAX_PATH))
        error = GetLastError();
    if (!error) {
        swprintf_s(command, 2048, L"\"%ls\" client \"%ls\" \"%ls\"",
                   image, argv[2], output);
        STARTUPINFOW startup = {0};
        startup.cb = sizeof(startup);
        PROCESS_INFORMATION process = {0};
        wchar_t environment[] =
            L"PROXY_HARBOR_P0_GUEST=offline-lab\0SystemRoot=C:\\Windows\0";
        if (!CreateProcessWithLogonW(account.name, L".", account.password,
                                     LOGON_WITH_PROFILE, image, command,
                                     CREATE_UNICODE_ENVIRONMENT,
                                     environment, account.profile, &startup, &process))
            error = GetLastError();
        else {
            DWORD wait = WaitForSingleObject(process.hProcess, 15000);
            DWORD code = 0;
            if (wait != WAIT_OBJECT_0) {
                TerminateProcess(process.hProcess, 1);
                WaitForSingleObject(process.hProcess, 3000);
                error = ERROR_TIMEOUT;
            } else if (!GetExitCodeProcess(process.hProcess, &code) || code)
                error = code ? code : GetLastError();
            CloseHandle(process.hThread);
            CloseHandle(process.hProcess);
        }
    }
    if (!error) {
        FILE *file = NULL;
        if (!_wfopen_s(&file, output, L"rb") && file) {
            char text[256] = {0};
            fread(text, 1, sizeof(text) - 1, file);
            fclose(file);
            printf("%s", text);
        } else
            error = ERROR_FILE_NOT_FOUND;
    }
    DWORD cleanup = SessionAccountTerminate(&account);
    if (!cleanup)
        cleanup = SessionAccountDelete(&account);
    SessionAccountRelease(&account);
    if (engine)
        FwpmEngineClose0(engine);
    if (descriptor)
        LocalFree(descriptor);
    printf("{\"error\":%lu,\"cleanupError\":%lu,\"filtered\":%s}\n",
           error, cleanup, filtered ? "true" : "false");
    return error || cleanup ? 1 : 0;
}
