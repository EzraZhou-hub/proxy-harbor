#define _WIN32_WINNT 0x0A00
#define WIN32_LEAN_AND_MEAN
#include "system_dns.h"
#include <sddl.h>
#include <stdio.h>
#include <wchar.h>

static const wchar_t name[] = L"Proxy Harbor session system DNS guard v1";

static void make_filter(SYSTEM_DNS_GUARD *g, unsigned index, FWPM_FILTER0 *f,
                        FWPM_FILTER_CONDITION0 c[2]) {
    ZeroMemory(f, sizeof(*f));
    ZeroMemory(c, 2 * sizeof(*c));
    f->filterKey = g->session;
    f->filterKey.Data1 ^= 0x444e5300u + index;
    f->subLayerKey = g->session;
    f->layerKey = index % 2 ? FWPM_LAYER_ALE_AUTH_CONNECT_V6 :
                              FWPM_LAYER_ALE_AUTH_CONNECT_V4;
    f->displayData.name = (wchar_t *)name;
    f->flags = g->persistent ? FWPM_FILTER_FLAG_PERSISTENT : 0;
    f->providerData.data = (BYTE *)&g->session;
    f->providerData.size = sizeof(g->session);
    f->action.type = FWP_ACTION_BLOCK;
    f->weight.type = FWP_UINT8;
    f->weight.uint8 = 15;
    f->numFilterConditions = index < 4 ? 1 : 2;
    f->filterCondition = c;
    c[0].matchType = FWP_MATCH_EQUAL;
    if (index < 4) {
        c[0].fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
        c[0].conditionValue.type = FWP_UINT16;
        c[0].conditionValue.uint16 = index < 2 ? 53 : 853;
    } else {
        c[0].fieldKey = FWPM_CONDITION_ALE_APP_ID;
        c[0].conditionValue.type = FWP_BYTE_BLOB_TYPE;
        c[0].conditionValue.byteBlob = g->service_app;
        c[1].fieldKey = FWPM_CONDITION_ALE_USER_ID;
        c[1].matchType = FWP_MATCH_EQUAL;
        c[1].conditionValue.type = FWP_SECURITY_DESCRIPTOR_TYPE;
        c[1].conditionValue.sd = &g->security;
    }
}

static BOOL same_condition(const FWPM_FILTER_CONDITION0 *a,
                            const FWPM_FILTER_CONDITION0 *b) {
    if (!IsEqualGUID(&a->fieldKey, &b->fieldKey) ||
        a->matchType != b->matchType ||
        a->conditionValue.type != b->conditionValue.type)
        return FALSE;
    if (a->conditionValue.type == FWP_UINT16)
        return a->conditionValue.uint16 == b->conditionValue.uint16;
    const FWP_BYTE_BLOB *x = a->conditionValue.byteBlob;
    const FWP_BYTE_BLOB *y = b->conditionValue.byteBlob;
    return x && y && x->data && y->data && x->size == y->size &&
           !memcmp(x->data, y->data, x->size);
}

static BOOL owned(SYSTEM_DNS_GUARD *g, unsigned index, FWPM_FILTER0 *actual) {
    FWPM_FILTER0 expected;
    FWPM_FILTER_CONDITION0 conditions[2];
    make_filter(g, index, &expected, conditions);
    if (!IsEqualGUID(&actual->filterKey, &expected.filterKey) ||
        !IsEqualGUID(&actual->subLayerKey, &g->session) ||
        !IsEqualGUID(&actual->layerKey, &expected.layerKey) ||
        (actual->flags & ~FWPM_FILTER_FLAG_INDEXED) != expected.flags ||
        actual->action.type != FWP_ACTION_BLOCK ||
        !actual->displayData.name || wcscmp(actual->displayData.name, name) ||
        actual->weight.type != FWP_UINT8 || actual->weight.uint8 != 15 ||
        actual->providerData.size != sizeof(g->session) ||
        !actual->providerData.data ||
        memcmp(actual->providerData.data, &g->session, sizeof(g->session)) ||
        actual->numFilterConditions != expected.numFilterConditions)
        return FALSE;
    for (unsigned i = 0; i < expected.numFilterConditions; ++i) {
        BOOL found = FALSE;
        for (unsigned j = 0; j < actual->numFilterConditions; ++j)
            if (same_condition(&conditions[i], &actual->filterCondition[j]))
                found = TRUE;
        if (!found)
            return FALSE;
    }
    return TRUE;
}

DWORD SystemDNSOpen(SYSTEM_DNS_GUARD *g, HANDLE engine, const GUID *session,
                    BOOL persistent) {
    ZeroMemory(g, sizeof(*g));
    g->engine = engine;
    g->session = *session;
    g->persistent = persistent;
    BYTE sid[SECURITY_MAX_SID_SIZE];
    wchar_t domain[128];
    DWORD sid_size = sizeof(sid), domain_size = 128;
    SID_NAME_USE use;
    if (!LookupAccountNameW(NULL, L"NT SERVICE\\Dnscache", sid, &sid_size,
                            domain, &domain_size, &use))
        return GetLastError();
    wchar_t *text = NULL, sddl[256];
    if (!ConvertSidToStringSidW(sid, &text))
        return GetLastError();
    swprintf_s(sddl, 256, L"D:(A;;CC;;;%ls)", text);
    LocalFree(text);
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl, SDDL_REVISION_1, &g->descriptor, NULL))
        return GetLastError();
    g->security.data = g->descriptor;
    g->security.size = GetSecurityDescriptorLength(g->descriptor);
    wchar_t image[MAX_PATH];
    if (!GetSystemDirectoryW(image, MAX_PATH))
        return GetLastError();
    wcscat_s(image, MAX_PATH, L"\\svchost.exe");
    DWORD error = FwpmGetAppIdFromFileName0(image, &g->service_app);
    for (unsigned i = 0; !error && i < SYSTEM_DNS_RULES; ++i) {
        FWPM_FILTER0 expected, *actual = NULL;
        FWPM_FILTER_CONDITION0 c[2];
        make_filter(g, i, &expected, c);
        error = FwpmFilterGetByKey0(engine, &expected.filterKey, &actual);
        if (error == FWP_E_FILTER_NOT_FOUND) {
            error = 0;
            continue;
        }
        if (!error) {
            if (!owned(g, i, actual))
                error = ERROR_INVALID_OWNER;
            else
                ++g->count;
        }
        if (actual)
            FwpmFreeMemory0((void **)&actual);
    }
    return error;
}

DWORD SystemDNSInstall(SYSTEM_DNS_GUARD *g) {
    if (g->count)
        return ERROR_ALREADY_EXISTS;
    DWORD error = FwpmTransactionBegin0(g->engine, 0);
    if (error)
        return error;
    for (unsigned i = 0; !error && i < SYSTEM_DNS_RULES; ++i) {
        FWPM_FILTER0 f;
        FWPM_FILTER_CONDITION0 c[2];
        make_filter(g, i, &f, c);
        error = FwpmFilterAdd0(g->engine, &f, NULL, NULL);
    }
    if (!error)
        error = FwpmTransactionCommit0(g->engine);
    if (error)
        FwpmTransactionAbort0(g->engine);
    else
        g->count = SYSTEM_DNS_RULES;
    return error;
}

DWORD SystemDNSVerify(SYSTEM_DNS_GUARD *g) {
    for (unsigned i = 0; i < SYSTEM_DNS_RULES; ++i) {
        FWPM_FILTER0 expected, *actual = NULL;
        FWPM_FILTER_CONDITION0 c[2];
        make_filter(g, i, &expected, c);
        DWORD error = FwpmFilterGetByKey0(g->engine, &expected.filterKey, &actual);
        if (!error && !owned(g, i, actual))
            error = ERROR_INVALID_OWNER;
        if (actual)
            FwpmFreeMemory0((void **)&actual);
        if (error)
            return error;
    }
    return 0;
}

DWORD SystemDNSRemove(SYSTEM_DNS_GUARD *g) {
    DWORD error = FwpmTransactionBegin0(g->engine, 0);
    if (error)
        return error;
    for (unsigned i = 0; !error && i < SYSTEM_DNS_RULES; ++i) {
        FWPM_FILTER0 expected, *actual = NULL;
        FWPM_FILTER_CONDITION0 c[2];
        make_filter(g, i, &expected, c);
        error = FwpmFilterGetByKey0(g->engine, &expected.filterKey, &actual);
        if (error == FWP_E_FILTER_NOT_FOUND) {
            error = 0;
            continue;
        }
        if (!error && !owned(g, i, actual))
            error = ERROR_INVALID_OWNER;
        if (actual)
            FwpmFreeMemory0((void **)&actual);
        if (!error)
            error = FwpmFilterDeleteByKey0(g->engine, &expected.filterKey);
    }
    if (!error)
        error = FwpmTransactionCommit0(g->engine);
    if (error)
        FwpmTransactionAbort0(g->engine);
    else
        g->count = 0;
    return error;
}

void SystemDNSClose(SYSTEM_DNS_GUARD *g) {
    if (g->service_app)
        FwpmFreeMemory0((void **)&g->service_app);
    if (g->descriptor)
        LocalFree(g->descriptor);
    ZeroMemory(g, sizeof(*g));
}
