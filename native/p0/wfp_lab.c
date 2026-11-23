// Isolated P0 policy laboratory. Each build has one fixed application identity.
// The Edge variant permits mutations only at its exact disposable guest path.
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <fwpmu.h>
#include <stdio.h>
#include <wchar.h>

#if defined(P0_EDGE_GUARD)
#define RULE_COUNT 4
static const GUID LAYER_KEY = {0x78c0ad15,0x2bd0,0x47bd,{0xb5,0xec,0x01,0x32,0xd7,0x3b,0x3e,0x8c}};
static const GUID FILTER_KEYS[RULE_COUNT] = {
{0xc7abcf61,0xe42f,0x4276,{0x89,0x4c,0x6b,0xa6,0xab,0x08,0x03,0xe1}},
{0xc7abcf62,0xe42f,0x4276,{0x89,0x4c,0x6b,0xa6,0xab,0x08,0x03,0xe1}},
{0xc7abcf63,0xe42f,0x4276,{0x89,0x4c,0x6b,0xa6,0xab,0x08,0x03,0xe1}},
{0xc7abcf64,0xe42f,0x4276,{0x89,0x4c,0x6b,0xa6,0xab,0x08,0x03,0xe1}}
};
static const wchar_t OWNER[] = L"Proxy Harbor P0 disposable Edge fixture only";
#elif defined(P0_HELPER_GUARD)
#define RULE_COUNT 4
static const GUID LAYER_KEY = {0x78c0ad14,0x2bd0,0x47bd,{0xb5,0xec,0x01,0x32,0xd7,0x3b,0x3e,0x8c}};
static const GUID FILTER_KEYS[RULE_COUNT] = {
{0xc7abcf51,0xe42f,0x4276,{0x89,0x4c,0x6b,0xa6,0xab,0x08,0x03,0xe1}},
{0xc7abcf52,0xe42f,0x4276,{0x89,0x4c,0x6b,0xa6,0xab,0x08,0x03,0xe1}},
{0xc7abcf53,0xe42f,0x4276,{0x89,0x4c,0x6b,0xa6,0xab,0x08,0x03,0xe1}},
{0xc7abcf54,0xe42f,0x4276,{0x89,0x4c,0x6b,0xa6,0xab,0x08,0x03,0xe1}}
};
static const wchar_t OWNER[] = L"Proxy Harbor P0 helper fixture only";
#elif defined(P0_RELAY_GUARD)
#define RULE_COUNT 4
static const GUID LAYER_KEY = {0x78c0ad13,0x2bd0,0x47bd,{0xb5,0xec,0x01,0x32,0xd7,0x3b,0x3e,0x8c}};
static const GUID FILTER_KEYS[RULE_COUNT] = {
    {0xc7abcf41,0xe42f,0x4276,{0x89,0x4c,0x6b,0xa6,0xab,0x08,0x03,0xe1}},
    {0xc7abcf42,0xe42f,0x4276,{0x89,0x4c,0x6b,0xa6,0xab,0x08,0x03,0xe1}},
    {0xc7abcf43,0xe42f,0x4276,{0x89,0x4c,0x6b,0xa6,0xab,0x08,0x03,0xe1}},
    {0xc7abcf44,0xe42f,0x4276,{0x89,0x4c,0x6b,0xa6,0xab,0x08,0x03,0xe1}}
};
static const wchar_t OWNER[] = L"Proxy Harbor P0 relay fixture only";
#else
#define RULE_COUNT 2
static const GUID LAYER_KEY = {0x78c0ad12,0x2bd0,0x47bd,{0xb5,0xec,0x01,0x32,0xd7,0x3b,0x3e,0x8c}};
static const GUID FILTER_KEYS[RULE_COUNT] = {
    {0xc7abcf31,0xe42f,0x4276,{0x89,0x4c,0x6b,0xa6,0xab,0x08,0x03,0xe1}},
    {0xc7abcf32,0xe42f,0x4276,{0x89,0x4c,0x6b,0xa6,0xab,0x08,0x03,0xe1}}
};
static const wchar_t OWNER[] = L"Proxy Harbor P0 fixture only";
#endif
static UINT16 relay_port;
#if defined(P0_EDGE_GUARD)
static BOOL edge_guest_only(void) {
    wchar_t cwd[MAX_PATH],marker[32],image[MAX_PATH];
    return GetCurrentDirectoryW(MAX_PATH,cwd) && _wcsicmp(cwd,L"C:\\P0Lab")==0 &&
        GetEnvironmentVariableW(L"PROXY_HARBOR_P0_GUEST",marker,32) && wcscmp(marker,L"offline-lab")==0 &&
        GetModuleFileNameW(NULL,image,MAX_PATH) && _wcsicmp(image,L"C:\\P0Lab\\.local\\p0\\bin\\p0-edge-guard.exe")==0;
}
#elif defined(P0_HELPER_GUARD)
static const wchar_t FIXTURE[] = L"helpers\\proxy-harbor-p0-helper.exe";
#else
static const wchar_t FIXTURE[] = L"proxy-harbor-p0-probe.exe";
#endif

static BOOL elevated(void) {
    HANDLE token = NULL;
    TOKEN_ELEVATION elevation = {0};
    DWORD size = 0;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return FALSE;
    BOOL ok = GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &size);
    CloseHandle(token);
    return ok && elevation.TokenIsElevated;
}

static BOOL fixture_path(wchar_t *path, DWORD capacity) {
#ifdef P0_EDGE_GUARD
    return wcscpy_s(path,capacity,L"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe")==0;
#else
    DWORD size = GetModuleFileNameW(NULL, path, capacity);
    if (!size || size >= capacity) return FALSE;
    wchar_t *separator = wcsrchr(path, L'\\');
    if (!separator) return FALSE;
    separator[1] = L'\0';
    return wcscat_s(path, capacity, FIXTURE) == 0;
#endif
}

static const GUID *network_layer(int index) {
#ifdef P0_RELAY_GUARD
    return index == 3 ? &FWPM_LAYER_ALE_AUTH_CONNECT_V6 : &FWPM_LAYER_ALE_AUTH_CONNECT_V4;
#else
    return index ? &FWPM_LAYER_ALE_AUTH_CONNECT_V6 : &FWPM_LAYER_ALE_AUTH_CONNECT_V4;
#endif
}

static UINT32 extra_condition(FWPM_FILTER_CONDITION0 *condition, int index) {
#ifdef P0_RELAY_GUARD
    condition->matchType = FWP_MATCH_NOT_EQUAL;
    switch (index) {
    case 0:
        condition->fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
        condition->conditionValue.type = FWP_UINT32;
        condition->conditionValue.uint32 = 0x7f000001;
        return 1;
    case 1:
        condition->fieldKey = FWPM_CONDITION_IP_PROTOCOL;
        condition->conditionValue.type = FWP_UINT8;
        condition->conditionValue.uint8 = IPPROTO_TCP;
        return 1;
    case 2:
        condition->fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
        condition->conditionValue.type = FWP_UINT16;
        condition->conditionValue.uint16 = relay_port;
        return 1;
    }
#else
    (void)condition;
    (void)index;
#endif
    return 0;
}

static BOOL owned_conditions(const FWPM_FILTER0 *filter, int index) {
    FWPM_FILTER_CONDITION0 expected = {0};
    UINT32 count = extra_condition(&expected, index);
    if (filter->numFilterConditions != count + 1 || !filter->filterCondition) return FALSE;
    if (!count) return TRUE;
    const FWPM_FILTER_CONDITION0 *actual = NULL;
    for (UINT32 i = 0; i < filter->numFilterConditions; ++i) {
        if (IsEqualGUID(&filter->filterCondition[i].fieldKey, &expected.fieldKey)) actual = &filter->filterCondition[i];
    }
    if (!actual) return FALSE;
    if (!IsEqualGUID(&actual->fieldKey, &expected.fieldKey) || actual->matchType != expected.matchType ||
        actual->conditionValue.type != expected.conditionValue.type) return FALSE;
    switch (expected.conditionValue.type) {
    case FWP_UINT32: return actual->conditionValue.uint32 == expected.conditionValue.uint32;
    case FWP_UINT8: return actual->conditionValue.uint8 == expected.conditionValue.uint8;
    case FWP_UINT16:
        return actual->conditionValue.uint16 >= 1024 && (!relay_port || actual->conditionValue.uint16 == relay_port);
    default: return FALSE;
    }
}

static const FWPM_FILTER_CONDITION0 *application_condition(const FWPM_FILTER0 *filter) {
    if (!filter->filterCondition) return NULL;
    for (UINT32 i = 0; i < filter->numFilterConditions; ++i) {
        if (IsEqualGUID(&filter->filterCondition[i].fieldKey, &FWPM_CONDITION_ALE_APP_ID)) return &filter->filterCondition[i];
    }
    return NULL;
}

static BOOL exact_application(const FWPM_FILTER_CONDITION0 *condition, const wchar_t *path) {
    if (!condition || condition->matchType != FWP_MATCH_EQUAL ||
        condition->conditionValue.type != FWP_BYTE_BLOB_TYPE || !condition->conditionValue.byteBlob) return FALSE;
    FWP_BYTE_BLOB *expected = NULL;
    if (FwpmGetAppIdFromFileName0(path, &expected) != ERROR_SUCCESS) return FALSE;
    FWP_BYTE_BLOB *actual = condition->conditionValue.byteBlob;
    BOOL match = actual->data && actual->size == expected->size &&
        memcmp(actual->data, expected->data, actual->size) == 0;
    FwpmFreeMemory0((void **)&expected);
    return match;
}

// The project keys, owner marker, exact fixture path, layer, action and single
// application identity condition must all match before any existing rule changes.
static BOOL owned_filter(const FWPM_FILTER0 *filter, const wchar_t *path, int index) {
    size_t bytes = (wcslen(path) + 1) * sizeof(wchar_t);
    const FWPM_FILTER_CONDITION0 *app = application_condition(filter);
    return filter->displayData.name && wcscmp(filter->displayData.name, OWNER) == 0 &&
        IsEqualGUID(&filter->subLayerKey, &LAYER_KEY) &&
        IsEqualGUID(&filter->layerKey, network_layer(index)) &&
        filter->action.type == FWP_ACTION_BLOCK &&
        filter->providerData.size == bytes && filter->providerData.data &&
        memcmp(filter->providerData.data, path, bytes) == 0 &&
        owned_conditions(filter, index) &&
        (filter->flags & FWPM_FILTER_FLAG_PERSISTENT) && !(filter->flags & FWPM_FILTER_FLAG_DISABLED) &&
        exact_application(app, path);
}

static DWORD inventory(HANDLE engine, const wchar_t *path, unsigned *count, FWP_BYTE_BLOB *expected) {
    *count = 0;
    for (int i = 0; i < RULE_COUNT; ++i) {
        FWPM_FILTER0 *filter = NULL;
        DWORD result = FwpmFilterGetByKey0(engine, &FILTER_KEYS[i], &filter);
        if (result == FWP_E_FILTER_NOT_FOUND) continue;
        if (result != ERROR_SUCCESS) return result;
        BOOL owned = owned_filter(filter, path, i);
        if (owned && expected) {
            FWP_BYTE_BLOB *actual = application_condition(filter)->conditionValue.byteBlob;
            owned = actual->size == expected->size && memcmp(actual->data, expected->data, actual->size) == 0 &&
                (filter->flags & FWPM_FILTER_FLAG_PERSISTENT) && !(filter->flags & FWPM_FILTER_FLAG_DISABLED);
        }
        FwpmFreeMemory0((void **)&filter);
        if (!owned) return ERROR_INVALID_OWNER;
        ++*count;
    }
    return ERROR_SUCCESS;
}

static DWORD ensure_sublayer(HANDLE engine) {
    FWPM_SUBLAYER0 *existing = NULL;
    DWORD result = FwpmSubLayerGetByKey0(engine, &LAYER_KEY, &existing);
    if (result == ERROR_SUCCESS) {
        BOOL owned = existing->displayData.name && wcscmp(existing->displayData.name, OWNER) == 0;
        FwpmFreeMemory0((void **)&existing);
        return owned ? ERROR_SUCCESS : ERROR_INVALID_OWNER;
    }
    if (result != FWP_E_SUBLAYER_NOT_FOUND) return result;
    FWPM_SUBLAYER0 layer = {0};
    layer.subLayerKey = LAYER_KEY;
    layer.displayData.name = (wchar_t *)OWNER;
    layer.flags = FWPM_SUBLAYER_FLAG_PERSISTENT;
    layer.weight = 0x7000;
    return FwpmSubLayerAdd0(engine, &layer, NULL);
}

static DWORD install_rules(HANDLE engine, const wchar_t *path, BOOL *changed) {
    DWORD attributes = GetFileAttributesW(path);
    if (attributes == INVALID_FILE_ATTRIBUTES || (attributes & FILE_ATTRIBUTE_DIRECTORY)) return ERROR_FILE_NOT_FOUND;
    FWP_BYTE_BLOB *app = NULL;
    DWORD result = FwpmGetAppIdFromFileName0(path, &app);
    if (result != ERROR_SUCCESS) return result;
    result = FwpmTransactionBegin0(engine, 0);
    if (result != ERROR_SUCCESS) { FwpmFreeMemory0((void **)&app); return result; }
    unsigned count = 0;
    result = inventory(engine, path, &count, app);
    if (result == ERROR_SUCCESS && count != 0 && count != RULE_COUNT) result = ERROR_INVALID_STATE;
    if (result == ERROR_SUCCESS && count == 0) result = ensure_sublayer(engine);
    for (int i = 0; result == ERROR_SUCCESS && count == 0 && i < RULE_COUNT; ++i) {
        FWPM_FILTER_CONDITION0 conditions[2] = {0};
        conditions[0].fieldKey = FWPM_CONDITION_ALE_APP_ID;
        conditions[0].matchType = FWP_MATCH_EQUAL;
        conditions[0].conditionValue.type = FWP_BYTE_BLOB_TYPE;
        conditions[0].conditionValue.byteBlob = app;
        FWPM_FILTER0 filter = {0};
        filter.filterKey = FILTER_KEYS[i];
        filter.displayData.name = (wchar_t *)OWNER;
        filter.flags = FWPM_FILTER_FLAG_PERSISTENT;
        filter.providerData.size = (UINT32)((wcslen(path) + 1) * sizeof(wchar_t));
        filter.providerData.data = (UINT8 *)path;
        filter.layerKey = *network_layer(i);
        filter.subLayerKey = LAYER_KEY;
        filter.weight.type = FWP_UINT8;
        filter.weight.uint8 = 15;
        filter.numFilterConditions = 1 + extra_condition(&conditions[1], i);
        filter.filterCondition = conditions;
        filter.action.type = FWP_ACTION_BLOCK;
        result = FwpmFilterAdd0(engine, &filter, NULL, NULL);
    }
    if (result == ERROR_SUCCESS) {
        result = FwpmTransactionCommit0(engine);
        if (result == ERROR_SUCCESS) *changed = count == 0;
    }
    if (result != ERROR_SUCCESS) FwpmTransactionAbort0(engine);
    FwpmFreeMemory0((void **)&app);
    return result;
}

static DWORD remove_rules(HANDLE engine, const wchar_t *path, BOOL *changed) {
    DWORD result = FwpmTransactionBegin0(engine, 0);
    if (result != ERROR_SUCCESS) return result;
    unsigned count = 0;
    result = inventory(engine, path, &count, NULL);
    for (int i = 0; result == ERROR_SUCCESS && i < RULE_COUNT; ++i) {
        DWORD deleted = FwpmFilterDeleteByKey0(engine, &FILTER_KEYS[i]);
        if (deleted != ERROR_SUCCESS && deleted != FWP_E_FILTER_NOT_FOUND) result = deleted;
    }
    if (result == ERROR_SUCCESS) {
        FWPM_SUBLAYER0 *layer = NULL;
        result = FwpmSubLayerGetByKey0(engine, &LAYER_KEY, &layer);
        if (result == ERROR_SUCCESS) {
            BOOL owned = layer->displayData.name && wcscmp(layer->displayData.name, OWNER) == 0;
            FwpmFreeMemory0((void **)&layer);
            result = owned ? FwpmSubLayerDeleteByKey0(engine, &LAYER_KEY) : ERROR_INVALID_OWNER;
        } else if (result == FWP_E_SUBLAYER_NOT_FOUND) result = ERROR_SUCCESS;
    }
    if (result == ERROR_SUCCESS) {
        result = FwpmTransactionCommit0(engine);
        if (result == ERROR_SUCCESS) *changed = count != 0;
    }
    if (result != ERROR_SUCCESS) FwpmTransactionAbort0(engine);
    return result;
}

int wmain(int argc, wchar_t **argv) {
    BOOL inspect = argc == 2 && wcscmp(argv[1], L"inspect") == 0;
#ifdef P0_RELAY_GUARD
    BOOL install = argc == 3 && wcscmp(argv[1], L"install-fixture-only") == 0;
    if (install) {
        wchar_t *end = NULL;
        unsigned long port = wcstoul(argv[2], &end, 10);
        if (!end || *end || port < 1024 || port > 65535) return 2;
        relay_port = (UINT16)port;
    }
#else
    BOOL install = argc == 2 && wcscmp(argv[1], L"install-fixture-only") == 0;
#endif
    BOOL remove = argc == 2 && wcscmp(argv[1], L"remove-fixture-only") == 0;
#ifdef P0_EDGE_GUARD
    if((install || remove) && !edge_guest_only()) { fputs("Edge policy mutations are fixed-path guest-only\n",stderr); return 2; }
#endif
    if (!inspect && !install && !remove) {
#ifdef P0_RELAY_GUARD
        fputs("Usage: p0-relay-guard.exe inspect|install-fixture-only <relay-port>|remove-fixture-only\n", stderr);
#else
        fputs("Usage: p0-wfp.exe inspect|install-fixture-only|remove-fixture-only\n", stderr);
#endif
        return 2;
    }
    wchar_t path[32768];
    if (!fixture_path(path, 32768)) return 2;
    HANDLE engine = NULL;
    DWORD result = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, NULL, &engine);
    BOOL changed = FALSE;
    unsigned count = 0;
    if (result == ERROR_SUCCESS) {
        if (install) result = install_rules(engine, path, &changed);
        else if (remove) result = remove_rules(engine, path, &changed);
        if (result == ERROR_SUCCESS) result = inventory(engine, path, &count, NULL);
        FwpmEngineClose0(engine);
    }
    printf("{\"schemaVersion\":1,\"elevated\":%s,\"windowsError\":%lu,\"rulesPresent\":%u,\"systemChanged\":%s,\"scope\":\"fixed temporary fixture identity only\"}\n",
        elevated() ? "true" : "false", result, count, changed ? "true" : "false");
    return result == ERROR_SUCCESS ? 0 : 1;
}
