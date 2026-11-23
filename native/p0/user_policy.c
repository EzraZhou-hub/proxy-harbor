// Disposable guest experiment: a dedicated ordinary user is the inherited
// network principal. No image discovery delay and no AppContainer requirement.
#define WIN32_LEAN_AND_MEAN
#include "user_policy.h"
#include <sddl.h>
#include <stdio.h>
#include <wchar.h>

static const GUID layer = {0x83c94c80,
                           0xe657,
                           0x446c,
                           {0x89, 0x0d, 0xd7, 0x15, 0x14, 0x30, 0x37, 0x5a}};
static const wchar_t owner[] = L"Proxy Harbor P0 dedicated user only v1";
static const wchar_t journal_path[] =
    L"C:\\P0Lab\\.local\\p0\\user-capsule-recovery.json";
static GUID key(unsigned index) {
    GUID result = layer;
    result.Data1 += index + 1;
    return result;
}
static void make_filter(USER_POLICY *p, unsigned i, FWPM_FILTER0 *f,
                        FWPM_FILTER_CONDITION0 c[4]) {
    ZeroMemory(f, sizeof(*f));
    ZeroMemory(c, 4 * sizeof(*c));
    f->filterKey = key(i);
    f->subLayerKey = layer;
    f->layerKey = i == 3   ? FWPM_LAYER_ALE_AUTH_CONNECT_V6
                  : i == 5 ? FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4
                  : i == 6 ? FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4
                  : i == 7 ? FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6
                           : FWPM_LAYER_ALE_AUTH_CONNECT_V4;
    f->displayData.name = (wchar_t *)owner;
    f->flags = FWPM_FILTER_FLAG_PERSISTENT;
    f->action.type = i == 4 || i == 5 ? FWP_ACTION_PERMIT : FWP_ACTION_BLOCK;
    if (i == 4 || i == 5)
        f->flags |= FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT;
    f->weight.type = FWP_UINT8;
    f->weight.uint8 = 15;
    f->providerData.data = (BYTE *)p->journal;
    f->providerData.size = p->journal_size;
    f->filterCondition = c;
    c[0].fieldKey =
        i == 5 ? FWPM_CONDITION_ALE_APP_ID : FWPM_CONDITION_ALE_USER_ID;
    c[0].matchType = FWP_MATCH_EQUAL;
    c[0].conditionValue.type =
        i == 5 ? FWP_BYTE_BLOB_TYPE : FWP_SECURITY_DESCRIPTOR_TYPE;
    if (i == 5)
        c[0].conditionValue.byteBlob = p->relay;
    else
        c[0].conditionValue.sd = &p->security;
    f->numFilterConditions = i == 3 || i >= 6 ? 1 : i < 3 ? 2 : 4;
    if (f->numFilterConditions == 1)
        return;
    if (i < 3) {
        c[1].matchType = FWP_MATCH_NOT_EQUAL;
        if (i == 0) {
            c[1].fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
            c[1].conditionValue.type = FWP_UINT32;
            c[1].conditionValue.uint32 = 0x7f000001;
        }
        if (i == 1) {
            c[1].fieldKey = FWPM_CONDITION_IP_PROTOCOL;
            c[1].conditionValue.type = FWP_UINT8;
            c[1].conditionValue.uint8 = 6;
        }
        if (i == 2) {
            c[1].fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
            c[1].conditionValue.type = FWP_UINT16;
            c[1].conditionValue.uint16 = p->port;
        }
        return;
    }
    c[1].fieldKey = i == 5 ? FWPM_CONDITION_IP_LOCAL_ADDRESS
                           : FWPM_CONDITION_IP_REMOTE_ADDRESS;
    c[1].matchType = FWP_MATCH_EQUAL;
    c[1].conditionValue.type = FWP_UINT32;
    c[1].conditionValue.uint32 = 0x7f000001;
    c[2].fieldKey = FWPM_CONDITION_IP_PROTOCOL;
    c[2].matchType = FWP_MATCH_EQUAL;
    c[2].conditionValue.type = FWP_UINT8;
    c[2].conditionValue.uint8 = 6;
    c[3].fieldKey =
        i == 5 ? FWPM_CONDITION_IP_LOCAL_PORT : FWPM_CONDITION_IP_REMOTE_PORT;
    c[3].matchType = FWP_MATCH_EQUAL;
    c[3].conditionValue.type = FWP_UINT16;
    c[3].conditionValue.uint16 = p->port;
}
static BOOL equal_value(const FWP_CONDITION_VALUE0 *a,
                        const FWP_CONDITION_VALUE0 *b) {
    if (a->type != b->type)
        return FALSE;
    if (a->type == FWP_UINT8)
        return a->uint8 == b->uint8;
    if (a->type == FWP_UINT16)
        return a->uint16 == b->uint16;
    if (a->type == FWP_UINT32)
        return a->uint32 == b->uint32;
    if (a->type == FWP_SECURITY_DESCRIPTOR_TYPE ||
        a->type == FWP_BYTE_BLOB_TYPE) {
        FWP_BYTE_BLOB *x = a->byteBlob, *y = b->byteBlob;
        return x && x->data && x->size == y->size &&
               !memcmp(x->data, y->data, x->size);
    }
    return FALSE;
}
static BOOL owned(USER_POLICY *p, unsigned i, FWPM_FILTER0 *f) {
    FWPM_FILTER0 wanted;
    FWPM_FILTER_CONDITION0 c[4];
    make_filter(p, i, &wanted, c);
    if (!IsEqualGUID(&f->filterKey, &wanted.filterKey) ||
        !IsEqualGUID(&f->subLayerKey, &layer) ||
        !IsEqualGUID(&f->layerKey, &wanted.layerKey) ||
        (f->flags & ~FWPM_FILTER_FLAG_INDEXED) != wanted.flags ||
        f->action.type != wanted.action.type || !f->displayData.name ||
        wcscmp(f->displayData.name, owner) ||
        f->providerData.size != p->journal_size || !f->providerData.data ||
        memcmp(f->providerData.data, p->journal, p->journal_size) ||
        f->numFilterConditions != wanted.numFilterConditions ||
        !f->filterCondition)
        return FALSE;
    for (unsigned n = 0; n < wanted.numFilterConditions; ++n) {
        BOOL found = FALSE;
        for (unsigned j = 0; j < f->numFilterConditions; ++j)
            if (IsEqualGUID(&f->filterCondition[j].fieldKey, &c[n].fieldKey) &&
                f->filterCondition[j].matchType == c[n].matchType &&
                equal_value(&f->filterCondition[j].conditionValue,
                            &c[n].conditionValue))
                found = TRUE;
        if (!found)
            return FALSE;
    }
    return TRUE;
}
DWORD UserPolicyInspect(unsigned *count) {
    HANDLE engine = NULL;
    *count = 0;
    DWORD error = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, NULL, &engine);
    for (unsigned i = 0; !error && i < 8; ++i) {
        GUID id = key(i);
        FWPM_FILTER0 *f = NULL;
        DWORD e = FwpmFilterGetByKey0(engine, &id, &f);
        if (e == FWP_E_FILTER_NOT_FOUND)
            continue;
        if (e) {
            error = e;
            break;
        }
        if (!f->displayData.name || wcscmp(f->displayData.name, owner))
            error = ERROR_INVALID_OWNER;
        ++*count;
        FwpmFreeMemory0((void **)&f);
    }
    if (engine)
        FwpmEngineClose0(engine);
    return error;
}
DWORD UserPolicyInstall(PSID sid, UINT16 port, USER_POLICY *p) {
    ZeroMemory(p, sizeof(*p));
    p->port = port;
    wchar_t *text = NULL, sddl[256];
    char *narrow = NULL;
    if (!ConvertSidToStringSidW(sid, &text) ||
        !ConvertSidToStringSidA(sid, &narrow)) {
        if (text)
            LocalFree(text);
        return GetLastError();
    }
    swprintf_s(sddl, 256, L"D:(A;;CC;;;%ls)", text);
    LocalFree(text);
    int length = sprintf_s(p->journal, sizeof(p->journal),
                           "{\"owner\":\"proxy-harbor-p0-user\",\"sid\":\"%s\","
                           "\"port\":%u,\"rules\":8}\n",
                           narrow, port);
    LocalFree(narrow);
    if (length <= 0)
        return ERROR_INVALID_DATA;
    p->journal_size = (DWORD)length;
    DWORD security_size = 0;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl, SDDL_REVISION_1, &p->descriptor, &security_size))
        return GetLastError();
    p->security.size = security_size;
    p->security.data = (BYTE *)p->descriptor;
    DWORD error =
        FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, NULL, &p->engine);
    if (!error)
        error = FwpmGetAppIdFromFileName0(
            L"C:\\P0Lab\\.local\\p0\\bin\\proxy-harbor-p0-relay.exe",
            &p->relay);
    if (error)
        return error;
    HANDLE file = CreateFileW(journal_path, GENERIC_WRITE, 0, NULL, CREATE_NEW,
                              FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE)
        return GetLastError();
    p->recorded = TRUE;
    DWORD written = 0;
    BOOL saved = WriteFile(file, p->journal, p->journal_size, &written, NULL) &&
                 written == p->journal_size && FlushFileBuffers(file);
    CloseHandle(file);
    if (!saved)
        return ERROR_WRITE_FAULT;
    error = FwpmTransactionBegin0(p->engine, 0);
    if (error)
        return error;
    FWPM_SUBLAYER0 sub = {0};
    sub.subLayerKey = layer;
    sub.displayData.name = (wchar_t *)owner;
    sub.flags = FWPM_SUBLAYER_FLAG_PERSISTENT;
    sub.weight = 0xffef;
    error = FwpmSubLayerAdd0(p->engine, &sub, NULL);
    for (unsigned i = 0; !error && i < 8; ++i) {
        FWPM_FILTER0 f;
        FWPM_FILTER_CONDITION0 c[4];
        make_filter(p, i, &f, c);
        error = FwpmFilterAdd0(p->engine, &f, NULL, NULL);
    }
    if (!error) {
        error = FwpmTransactionCommit0(p->engine);
        if (!error)
            p->installed = TRUE;
    }
    if (error)
        FwpmTransactionAbort0(p->engine);
    return error;
}
BOOL UserPolicyRemove(USER_POLICY *p) {
    BOOL ok = TRUE;
    HANDLE file = INVALID_HANDLE_VALUE;
    if (p->recorded) {
        file = CreateFileW(journal_path, GENERIC_READ | DELETE, FILE_SHARE_READ,
                           NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        char data[512];
        DWORD read = 0;
        ok = file != INVALID_HANDLE_VALUE &&
             GetFileSize(file, NULL) == p->journal_size &&
             ReadFile(file, data, sizeof(data), &read, NULL) &&
             read == p->journal_size && !memcmp(data, p->journal, read);
    }
    if (ok && p->installed) {
        DWORD error = FwpmTransactionBegin0(p->engine, 0);
        for (unsigned i = 0; !error && i < 8; ++i) {
            GUID id = key(i);
            FWPM_FILTER0 *f = NULL;
            error = FwpmFilterGetByKey0(p->engine, &id, &f);
            if (!error && !owned(p, i, f))
                error = ERROR_INVALID_OWNER;
            if (f)
                FwpmFreeMemory0((void **)&f);
        }
        for (unsigned i = 0; !error && i < 8; ++i) {
            GUID id = key(i);
            error = FwpmFilterDeleteByKey0(p->engine, &id);
        }
        if (!error)
            error = FwpmSubLayerDeleteByKey0(p->engine, &layer);
        if (!error)
            error = FwpmTransactionCommit0(p->engine);
        if (error)
            FwpmTransactionAbort0(p->engine);
        ok = error == ERROR_SUCCESS;
    }
    if (ok && p->recorded) {
        FILE_DISPOSITION_INFO disposition = {TRUE};
        ok = SetFileInformationByHandle(file, FileDispositionInfo, &disposition,
                                        sizeof(disposition));
    }
    if (file != INVALID_HANDLE_VALUE)
        CloseHandle(file);
    if (p->relay)
        FwpmFreeMemory0((void **)&p->relay);
    if (p->engine)
        FwpmEngineClose0(p->engine);
    if (p->descriptor)
        LocalFree(p->descriptor);
    ZeroMemory(p, sizeof(*p));
    return ok;
}
