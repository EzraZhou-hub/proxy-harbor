// Guest-only experiment. A dynamic WFP session owns temporary DNS restrictions.
// This executable is not used by the desktop protection entry points.
#define _WIN32_WINNT 0x0A00
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <fwpmu.h>
#include <stdio.h>
#include <wchar.h>
#include "../session/system_dns.h"

static DWORD inspect(unsigned *count) {
    *count = 0;
    HANDLE engine = NULL, enumeration = NULL;
    DWORD error = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, NULL, &engine);
    if (!error)
        error = FwpmFilterCreateEnumHandle0(engine, NULL, &enumeration);
    while (!error) {
        FWPM_FILTER0 **rows = NULL;
        UINT32 size = 0;
        error = FwpmFilterEnum0(engine, enumeration, 256, &rows, &size);
        if (!error) {
            for (UINT32 i = 0; i < size; ++i)
                if (rows[i]->displayData.name &&
                    (!wcscmp(rows[i]->displayData.name,
                             L"Proxy Harbor temporary guest DNS experiment") ||
                     !wcscmp(rows[i]->displayData.name,
                             L"Proxy Harbor session system DNS guard v1")))
                    ++*count;
        }
        if (rows)
            FwpmFreeMemory0((void **)&rows);
        if (error || size < 256)
            break;
    }
    if (enumeration)
        FwpmFilterDestroyEnumHandle0(engine, enumeration);
    if (engine)
        FwpmEngineClose0(engine);
    return error;
}

int wmain(int argc, wchar_t **argv) {
    wchar_t cwd[MAX_PATH], marker[32], image[MAX_PATH];
    if (!GetCurrentDirectoryW(MAX_PATH, cwd) || _wcsicmp(cwd, L"C:\\P0Lab") ||
        !GetEnvironmentVariableW(L"PROXY_HARBOR_P0_GUEST", marker, 32) ||
        wcscmp(marker, L"offline-lab") ||
        !GetModuleFileNameW(NULL, image, MAX_PATH) ||
        _wcsicmp(image, L"C:\\P0Lab\\.local\\p0\\bin\\dns-block-lab.exe"))
        return 2;
    if (argc == 2 && !wcscmp(argv[1], L"inspect")) {
        unsigned count = 0;
        DWORD error = inspect(&count);
        printf("{\"rules\":%u,\"error\":%lu}\n", count, error);
        return error ? 1 : 0;
    }
    BOOL system = argc == 2 && !wcscmp(argv[1], L"system");
    BOOL service = argc == 2 && !wcscmp(argv[1], L"service");
    if (argc != 1 && !system && !service)
        return 2;
    FWPM_SESSION0 session = {0};
    session.flags = FWPM_SESSION_FLAG_DYNAMIC;
    HANDLE engine = NULL;
    DWORD error = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, &session, &engine);
    GUID owner = {0};
    if (!error && UuidCreate(&owner) != RPC_S_OK)
        error = ERROR_GEN_FAILURE;
    if (!error)
        error = FwpmTransactionBegin0(engine, 0);
    if (!error) {
        FWPM_SUBLAYER0 layer = {0};
        layer.subLayerKey = owner;
        layer.displayData.name = L"Proxy Harbor temporary guest DNS experiment";
        layer.weight = 0xffff;
        error = FwpmSubLayerAdd0(engine, &layer, NULL);
    }
    for (unsigned i = 0; !error && !system && !service && i < 4; ++i) {
        FWPM_FILTER_CONDITION0 condition = {0};
        condition.fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
        condition.matchType = FWP_MATCH_EQUAL;
        condition.conditionValue.type = FWP_UINT16;
        condition.conditionValue.uint16 = i < 2 ? 53 : 853;
        FWPM_FILTER0 filter = {0};
        filter.filterKey = owner;
        filter.filterKey.Data1 ^= i + 1;
        filter.subLayerKey = owner;
        filter.layerKey = i % 2 ? FWPM_LAYER_ALE_AUTH_CONNECT_V6 :
                                 FWPM_LAYER_ALE_AUTH_CONNECT_V4;
        filter.displayData.name = L"Proxy Harbor temporary guest DNS experiment";
        filter.providerData.data = (BYTE *)&owner;
        filter.providerData.size = sizeof(owner);
        filter.action.type = FWP_ACTION_BLOCK;
        filter.weight.type = FWP_UINT8;
        filter.weight.uint8 = 15;
        filter.numFilterConditions = 1;
        filter.filterCondition = &condition;
        error = FwpmFilterAdd0(engine, &filter, NULL, NULL);
    }
    if (!error)
        error = FwpmTransactionCommit0(engine);
    if (error && engine)
        FwpmTransactionAbort0(engine);
    SYSTEM_DNS_GUARD guard = {0};
    if (!error && (system || service))
        error = SystemDNSOpen(&guard, engine, &owner, FALSE);
    if (!error && (system || service))
        error = SystemDNSInstall(&guard);
    if (!error && (system || service))
        error = SystemDNSVerify(&guard);
    // Verify the service conditions independently from the classic-port rules.
    // Only remove the first four keys installed by this exact lab invocation.
    for (unsigned i = 0; !error && service && i < 4; ++i) {
        GUID key = owner;
        key.Data1 ^= 0x444e5300u + i;
        error = FwpmFilterDeleteByKey0(engine, &key);
    }
    printf("{\"ready\":%s,\"error\":%lu}\n", error ? "false" : "true", error);
    fflush(stdout);
    if (!error)
        (void)getchar();
    if ((system || service) && guard.count) {
        DWORD cleanup = SystemDNSRemove(&guard);
        if (!error)
            error = cleanup;
    }
    SystemDNSClose(&guard);
    if (engine)
        FwpmEngineClose0(engine);
    return error ? 1 : 0;
}
