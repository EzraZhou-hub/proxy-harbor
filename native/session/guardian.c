// Proxy Harbor session guardian. System APIs only; no third-party SDK.
#define _WIN32_WINNT 0x0A00
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <fwpmu.h>
#include <iphlpapi.h>
#include <netioapi.h>
#include <sddl.h>
#include <stdio.h>
#include <stdlib.h>
#include <tlhelp32.h>
#include <wchar.h>
#include <winhttp.h>
#include <lm.h>
#include "account.h"
#include "tcp_path.h"
#include "system_dns.h"
#ifdef PH_CLAUDE_MSIX
#include <objbase.h>
#include "claude_msix.h"
#endif
#ifdef PH_CLAUDE_TAKEOVER
#include "claude_takeover.h"
static CLAUDE_TAKEOVER takeover;
#endif

#define MAX_IMAGES 64
#define BASE_RULES 6
static const wchar_t owner[] = L"Proxy Harbor managed session v1";
static wchar_t directory[1024], images[MAX_IMAGES][1024], mode[32];
static GUID session_id;
static unsigned image_count, proxy_port;
static DWORD expected_proxy_pid;
static ULONGLONG expected_proxy_created;
static DWORD parent_pid, child_pid, error_code;
static ULONGLONG parent_created;
static HANDLE engine, parent, job, lock_file, proxy_process, tun_process;
static FWP_BYTE_BLOB *app_ids[MAX_IMAGES];
static UINT64 filter_ids[MAX_IMAGES * 8];
static unsigned installed;
static NET_LUID tun_luid;
static NET_IFINDEX tun_index;
static BOOL lab, events_saved, emergency;
static BOOL user_identity, desktop_client, current_user, require_tun, system_dns_enabled;
static SYSTEM_DNS_GUARD dns_guard;
static HANDLE dns_watch;
static SESSION_ACCOUNT account;
static PSECURITY_DESCRIPTOR account_descriptor;
static FWP_BYTE_BLOB account_security;
static FWP_BYTE_BLOB proxy_security;
static PSECURITY_DESCRIPTOR proxy_descriptor;
static FWP_BYTE_BLOB *proxy_app;
static HANDLE proxy_record;
static UINT32 previous_events;
static FILETIME began;
static char observed_exit[64], expected_exit[16];
static volatile LONG64 last_exit_check;
static char blocked_at[32], block_direction[12];
static UINT64 blocked_filter;
static unsigned blocked_protocol, blocked_remote_port;
static HANDLE stop_checks, exit_thread, exit_alarm;
enum exit_fault { EXIT_HEALTHY, EXIT_MISMATCH, EXIT_UNVERIFIED };
static volatile LONG exit_fault;
static SESSION_TCP_PEER unexpected_peer;
static DWORD network_error;
static BOOL diagnostics_pending;
#ifdef PH_CLAUDE_MSIX
static BOOL claude_msix;
static wchar_t claude_package[PACKAGE_FULL_NAME_MAX_LENGTH + 1];
#endif
static ULONGLONG creation(HANDLE process);
static BOOL ipv4_public(const char *text);
static BOOL verify_filters(void);

static void path_for(wchar_t *out, size_t size, const wchar_t *leaf) {
    swprintf_s(out, size, L"%ls\\%ls", directory, leaf);
}
static BOOL stop_requested(void) {
    wchar_t stop[1200];
    path_for(stop, ARRAYSIZE(stop), L"stop");
    return GetFileAttributesW(stop) != INVALID_FILE_ATTRIBUTES;
}
static BOOL write_file(const wchar_t *leaf, const char *data) {
    wchar_t path[1200];
    path_for(path, 1200, leaf);
    HANDLE f = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE)
        return FALSE;
    DWORD length = (DWORD)strlen(data), written = 0;
    BOOL ok = WriteFile(f, data, length, &written, NULL) && written == length &&
              FlushFileBuffers(f);
    CloseHandle(f);
    return ok;
}
static void status(const char *state, const char *reason) {
    char json[1024];
    SYSTEMTIME now;
    GetSystemTime(&now);
    sprintf_s(json, sizeof(json),
              "{\"state\":\"%s\",\"reason\":\"%s\",\"error\":%lu,\"pid\":%lu,"
              "\"guardianPid\":%lu,\"guardianCreated\":%llu,"
              "\"supervisorThreadId\":%lu,"
              "\"filterCount\":%u,\"proxyExit\":\"%s\",\"tunIndex\":%lu,"
              "\"blockedAt\":\"%s\",\"blockedFilterId\":\"%llu\","
              "\"blockDirection\":\"%s\","
              "\"blockedProtocol\":%u,\"blockedRemotePort\":%u,"
              "\"unexpectedPeerPid\":%lu,\"unexpectedPeerFamily\":%u,"
              "\"unexpectedPeerPort\":%u,\"jobQueryRetries\":%lu,"
              "\"updatedAt\":\"%04u-%02u-%02uT%02u:%"
              "02u:%02uZ\",\"dns\":\"%s\",\"udp\":\"%s\","
              "\"ipv6\":\"%s\"}\n",
              state, reason, error_code, child_pid, GetCurrentProcessId(),
              creation(GetCurrentProcess()), GetCurrentThreadId(), installed + dns_guard.count,
              observed_exit, tun_index, blocked_at, blocked_filter,
              block_direction, blocked_protocol, blocked_remote_port,
              unexpected_peer.pid, unexpected_peer.family, unexpected_peer.remote_port,
              SessionJobQueryRetries(), now.wYear,
              now.wMonth, now.wDay, now.wHour, now.wMinute, now.wSecond,
              system_dns_enabled ? (dns_guard.count ? "system_blocked" : "restored") : "not_verified",
              !strcmp(state, "monitoring") ? "blocked" : "not_verified",
              !strcmp(state, "monitoring") ? "blocked" : "not_verified");
    if (write_file(L"status.tmp", json)) {
        wchar_t from[1200], to[1200];
        path_for(from, 1200, L"status.tmp");
        path_for(to, 1200, L"status.json");
        MoveFileExW(from, to,
                    MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH);
    }
}
static ULONGLONG creation(HANDLE process) {
    FILETIME c, e, k, u;
    ULARGE_INTEGER value;
    if (!GetProcessTimes(process, &c, &e, &k, &u))
        return 0;
    value.LowPart = c.dwLowDateTime;
    value.HighPart = c.dwHighDateTime;
    return value.QuadPart;
}
static BOOL same_image(HANDLE process, const wchar_t *expected) {
    wchar_t text[1024];
    DWORD length = 1024;
    return QueryFullProcessImageNameW(process, 0, text, &length) &&
           !_wcsicmp(text, expected);
}
static BOOL read_request(const wchar_t *folder, BOOL require_image) {
    DWORD length = GetFullPathNameW(folder, 1024, directory, NULL);
    if (!length || length >= 1024 || wcschr(directory, L'"') ||
        directory[1] != L':' || directory[2] != L'\\')
        return FALSE;
    wchar_t ancestor[1024];
    wcscpy_s(ancestor, 1024, directory);
    for (;;) {
        DWORD flags = GetFileAttributesW(ancestor);
        if (flags == INVALID_FILE_ATTRIBUTES ||
            (flags & FILE_ATTRIBUTE_REPARSE_POINT))
            return FALSE;
        wchar_t *slash = wcsrchr(ancestor, L'\\');
        if (!slash || slash <= ancestor + 2)
            break;
        *slash = 0;
    }
    DWORD attr = GetFileAttributesW(directory);
    if (attr == INVALID_FILE_ATTRIBUTES || !(attr & FILE_ATTRIBUTE_DIRECTORY) ||
        (attr & FILE_ATTRIBUTE_REPARSE_POINT))
        return FALSE;
    wchar_t path[1200];
    path_for(path, 1200, L"request.txt");
    FILE *file = NULL;
    if (_wfopen_s(&file, path, L"rt, ccs=UTF-8") || !file)
        return FALSE;
    wchar_t lines[8][1024] = {{0}};
    BOOL ok = TRUE;
    for (int i = 0; i < 8; ++i) {
        if (!fgetws(lines[i], 1024, file)) {
            ok = FALSE;
            break;
        }
        lines[i][wcscspn(lines[i], L"\r\n")] = 0;
    }
    if (ok) {
        wchar_t *end = NULL;
        system_dns_enabled = !wcscmp(lines[0], L"PH4") || !wcscmp(lines[0], L"PH5");
        require_tun = !wcscmp(lines[0], L"PH3") || !wcscmp(lines[0], L"PH4");
        BOOL pinned = system_dns_enabled || require_tun || !wcscmp(lines[0], L"PH2");
        const wchar_t *leaf = wcsrchr(directory, L'\\');
        ok = leaf && !_wcsicmp(leaf + 1, lines[1]) &&
             (pinned || !wcscmp(lines[0], L"PH1")) &&
             UuidFromStringW((RPC_WSTR)lines[1], &session_id) == RPC_S_OK;
        parent_pid = wcstoul(lines[2], &end, 10);
        ok = ok && end && !*end && parent_pid;
        parent_created = _wcstoui64(lines[3], &end, 10);
        ok = ok && end && !*end && parent_created;
        proxy_port = (unsigned)wcstoul(lines[4], &end, 10);
        ok = ok && end && !*end && proxy_port >= 1024 && proxy_port <= 65535;
        if (wcslen(lines[5]) >= _countof(mode))
            ok = FALSE;
        else
            wcscpy_s(mode, 32, lines[5]);
        image_count = (unsigned)wcstoul(lines[6], &end, 10);
        ok = ok && end && !*end && image_count > 0 && image_count <= MAX_IMAGES;
        if (pinned) {
            char binding[96], canonical[96];
#ifdef PH_CLAUDE_TAKEOVER
            current_user = !wcscmp(mode, L"claude-restart");
#endif
            desktop_client = current_user || !wcscmp(mode, L"client-user");
            ok = ok && (desktop_client || !wcscmp(mode, L"chrome-user")) && image_count == 1 &&
                 WideCharToMultiByte(CP_UTF8, 0, lines[7], -1, binding,
                                     sizeof(binding), NULL, NULL) &&
                 sscanf_s(binding, "%15s %lu %llu", expected_exit,
                          (unsigned)sizeof(expected_exit), &expected_proxy_pid,
                          &expected_proxy_created) == 3 &&
                 expected_proxy_pid && expected_proxy_created &&
                 ipv4_public(expected_exit);
            if (ok) {
                sprintf_s(canonical, sizeof(canonical), "%s %lu %llu",
                          expected_exit, expected_proxy_pid,
                          expected_proxy_created);
                ok = !strcmp(binding, canonical);
            }
        } else {
            ok = ok && !wcscmp(lines[7], L"END");
        }
    }
    for (unsigned i = 0; ok && i < image_count; ++i) {
        if (!fgetws(images[i], 1024, file)) {
            ok = FALSE;
            break;
        }
        images[i][wcscspn(images[i], L"\r\n")] = 0;
        if (wcschr(images[i], L'"') ||
            (require_image &&
#ifdef PH_CLAUDE_MSIX_DESKTOP
             !desktop_client &&
#endif
             GetFileAttributesW(images[i]) == INVALID_FILE_ATTRIBUTES))
            ok = FALSE;
    }
    wchar_t extra[4];
    if (ok && fgetws(extra, 4, file))
        ok = FALSE;
    fclose(file);
#ifdef PH_CLAUDE_MSIX
    claude_msix = desktop_client && ClaudeMSIXPackage(images[0], claude_package);
    if (claude_msix && require_image)
        ok = ok && ClaudeMSIXInstalledImage(images[0], claude_package);
#ifdef PH_CLAUDE_MSIX_DESKTOP
    if (desktop_client)
        ok = ok && claude_msix && !wcscmp(lines[0], L"PH4") && proxy_port == 10808;
#endif
#endif
    user_identity = desktop_client || !wcscmp(mode, L"chrome-user") ||
                    !wcscmp(mode, L"edge-user") ||
                    !wcscmp(mode, L"fixture-user");
    lab = !wcscmp(mode, L"fixture") || !wcscmp(mode, L"fixture-user");
    if (wcscmp(mode, L"chrome") && wcscmp(mode, L"codex") && !lab &&
        !user_identity)
        ok = FALSE;
    if (require_image && !expected_exit[0] && !lab && user_identity)
        ok = FALSE; // Old identity records remain inspectable and recoverable.
    if (!wcscmp(lines[0], L"PH5")) {
        wchar_t cwd[MAX_PATH], marker[32];
        ok = ok && GetCurrentDirectoryW(MAX_PATH, cwd) &&
             !_wcsicmp(cwd, L"C:\\P0Lab") &&
             GetEnvironmentVariableW(L"PROXY_HARBOR_P0_GUEST", marker, 32) &&
             !wcscmp(marker, L"offline-lab");
    }
    if (lab || (require_image && !user_identity)) {
        wchar_t cwd[1024], marker[32];
        ok = ok && GetCurrentDirectoryW(1024, cwd) &&
             !_wcsicmp(cwd, L"C:\\P0Lab") &&
             GetEnvironmentVariableW(L"PROXY_HARBOR_P0_GUEST", marker, 32) &&
             !wcscmp(marker, L"offline-lab");
        for (unsigned i = 0; lab && i < image_count && i < MAX_IMAGES; ++i)
            if (_wcsnicmp(images[i], L"C:\\P0Lab\\", 9))
                ok = FALSE;
    }
    return ok;
}
static GUID key_for(unsigned image, unsigned rule) {
    GUID key = session_id;
    key.Data1 ^= 0x50480000u + image * 16u + rule;
    return key;
}
static BOOL equal_condition(const FWPM_FILTER_CONDITION0 *a,
                            const FWPM_FILTER_CONDITION0 *b) {
    if (!IsEqualGUID(&a->fieldKey, &b->fieldKey) ||
        a->matchType != b->matchType ||
        a->conditionValue.type != b->conditionValue.type)
        return FALSE;
    if (a->conditionValue.type == FWP_UINT32)
        return a->conditionValue.uint32 == b->conditionValue.uint32;
    if (a->conditionValue.type == FWP_UINT16)
        return a->conditionValue.uint16 == b->conditionValue.uint16;
    if (a->conditionValue.type == FWP_UINT8)
        return a->conditionValue.uint8 == b->conditionValue.uint8;
    if (a->conditionValue.type == FWP_BYTE_BLOB_TYPE ||
        a->conditionValue.type == FWP_SECURITY_DESCRIPTOR_TYPE) {
        FWP_BYTE_BLOB *x = a->conditionValue.byteBlob,
                      *y = b->conditionValue.byteBlob;
        return x && x->data && x->size == y->size &&
               !memcmp(x->data, y->data, x->size);
    }
    return FALSE;
}
static void make_filter(unsigned image, unsigned rule, FWPM_FILTER0 *filter,
                        FWPM_FILTER_CONDITION0 conditions[3]) {
    ZeroMemory(filter, sizeof(*filter));
    ZeroMemory(conditions, 3 * sizeof(*conditions));
    filter->filterKey = key_for(image, rule);
    filter->subLayerKey = session_id;
    filter->layerKey = (rule == 3 || rule == 5 || rule == 7)
                           ? FWPM_LAYER_ALE_AUTH_CONNECT_V6
                           : FWPM_LAYER_ALE_AUTH_CONNECT_V4;
    if (rule == 4)
        filter->layerKey = FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4;
    if (rule == 5)
        filter->layerKey = FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6;
    filter->displayData.name = (wchar_t *)owner;
    filter->flags = FWPM_FILTER_FLAG_PERSISTENT;
    filter->action.type = FWP_ACTION_BLOCK;
    filter->weight.type = FWP_UINT8;
    filter->weight.uint8 = 15;
    filter->providerData.data = (BYTE *)&session_id;
    filter->providerData.size = sizeof(session_id);
    filter->numFilterConditions = (rule < 3 || rule == 4) ? 2 : 1;
    filter->filterCondition = conditions;
    conditions[0].fieldKey = FWPM_CONDITION_ALE_APP_ID;
    conditions[0].matchType = FWP_MATCH_EQUAL;
    conditions[0].conditionValue.type = FWP_BYTE_BLOB_TYPE;
    conditions[0].conditionValue.byteBlob = app_ids[image];
    if (user_identity && !current_user) {
        conditions[0].fieldKey = FWPM_CONDITION_ALE_USER_ID;
        conditions[0].conditionValue.type = FWP_SECURITY_DESCRIPTOR_TYPE;
        conditions[0].conditionValue.sd = &account_security;
        if (rule == 4)
            filter->numFilterConditions = 1;
    }
    conditions[1].matchType = FWP_MATCH_NOT_EQUAL;
    if (rule == 0 || rule == 4) {
        conditions[1].fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
        conditions[1].conditionValue.type = FWP_UINT32;
        conditions[1].conditionValue.uint32 = 0x7f000001;
    }
    if (rule == 1) {
        conditions[1].fieldKey = FWPM_CONDITION_IP_PROTOCOL;
        conditions[1].conditionValue.type = FWP_UINT8;
        conditions[1].conditionValue.uint8 = 6;
    }
    if (rule == 2) {
        conditions[1].fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
        conditions[1].conditionValue.type = FWP_UINT16;
        conditions[1].conditionValue.uint16 = (UINT16)proxy_port;
    }
    if (current_user) {
        // Match both the installed image and the Windows user's SID. Inbound
        // connections from outside loopback are blocked; the client's local
        // bridge (Code mode, MCP helpers) may still accept 127.0.0.1 clients.
        FWPM_FILTER_CONDITION0 *scope = &conditions[filter->numFilterConditions++];
        scope->fieldKey = FWPM_CONDITION_ALE_USER_ID;
        scope->matchType = FWP_MATCH_EQUAL;
        scope->conditionValue.type = FWP_SECURITY_DESCRIPTOR_TYPE;
        scope->conditionValue.sd = &account_security;
    }
}
static BOOL owned(const FWPM_FILTER0 *actual, unsigned image, unsigned rule) {
    FWPM_FILTER0 expected;
    FWPM_FILTER_CONDITION0 conditions[3];
    make_filter(image, rule, &expected, conditions);
    if (!IsEqualGUID(&actual->filterKey, &expected.filterKey) ||
        !IsEqualGUID(&actual->layerKey, &expected.layerKey) ||
        !IsEqualGUID(&actual->subLayerKey, &session_id) ||
        (actual->flags & ~FWPM_FILTER_FLAG_INDEXED) != expected.flags ||
        actual->action.type != FWP_ACTION_BLOCK ||
        actual->weight.type != FWP_UINT8 || actual->weight.uint8 != 15 ||
        !actual->displayData.name || wcscmp(actual->displayData.name, owner) ||
        actual->providerData.size != sizeof(session_id) ||
        !actual->providerData.data ||
        memcmp(actual->providerData.data, &session_id, sizeof(session_id)) ||
        actual->numFilterConditions != expected.numFilterConditions ||
        !actual->filterCondition)
        return FALSE;
    for (unsigned i = 0; i < expected.numFilterConditions; ++i) {
        BOOL found = FALSE;
        for (unsigned j = 0; j < actual->numFilterConditions; ++j)
            if (equal_condition(&conditions[i], &actual->filterCondition[j]))
                found = TRUE;
        if (!found)
            return FALSE;
    }
    return TRUE;
}
static void proxy_filter(unsigned index, FWPM_FILTER0 *f,
                         FWPM_FILTER_CONDITION0 c[3]) {
    ZeroMemory(f, sizeof(*f));
    ZeroMemory(c, 3 * sizeof(*c));
    f->filterKey = key_for(MAX_IMAGES, index);
    f->subLayerKey = session_id;
    const GUID *layers[4] = {&FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V4,
                             &FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V6,
                             &FWPM_LAYER_ALE_AUTH_LISTEN_V4,
                             &FWPM_LAYER_ALE_AUTH_LISTEN_V6};
    f->layerKey = *layers[index / 2];
    f->displayData.name = (wchar_t *)owner;
    f->flags = FWPM_FILTER_FLAG_PERSISTENT;
    f->action.type = FWP_ACTION_BLOCK;
    f->weight.type = FWP_UINT8;
    f->weight.uint8 = 15;
    f->providerData.data = (BYTE *)&session_id;
    f->providerData.size = sizeof(session_id);
    f->numFilterConditions = index < 4 ? 3 : 2;
    f->filterCondition = c;
    c[0].fieldKey = FWPM_CONDITION_IP_LOCAL_PORT;
    c[0].matchType = FWP_MATCH_EQUAL;
    c[0].conditionValue.type = FWP_UINT16;
    c[0].conditionValue.uint16 = (UINT16)proxy_port;
    c[1].fieldKey = FWPM_CONDITION_IP_PROTOCOL;
    c[1].matchType = FWP_MATCH_EQUAL;
    c[1].conditionValue.type = FWP_UINT8;
    c[1].conditionValue.uint8 = 6;
    unsigned principal = index < 4 ? 2 : 1;
    c[principal].matchType = FWP_MATCH_NOT_EQUAL;
    c[principal].fieldKey =
        index % 2 ? FWPM_CONDITION_ALE_USER_ID : FWPM_CONDITION_ALE_APP_ID;
    c[principal].conditionValue.type =
        index % 2 ? FWP_SECURITY_DESCRIPTOR_TYPE : FWP_BYTE_BLOB_TYPE;
    if (index % 2)
        c[principal].conditionValue.sd = &proxy_security;
    else
        c[principal].conditionValue.byteBlob = proxy_app;
}
static BOOL proxy_filter_owned(unsigned index, FWPM_FILTER0 *actual) {
    FWPM_FILTER0 expected;
    FWPM_FILTER_CONDITION0 c[3];
    proxy_filter(index, &expected, c);
    if (!IsEqualGUID(&actual->filterKey, &expected.filterKey) ||
        !IsEqualGUID(&actual->layerKey, &expected.layerKey) ||
        !IsEqualGUID(&actual->subLayerKey, &session_id) ||
        (actual->flags & ~FWPM_FILTER_FLAG_INDEXED) != expected.flags ||
        actual->action.type != FWP_ACTION_BLOCK ||
        actual->weight.type != FWP_UINT8 || actual->weight.uint8 != 15 ||
        !actual->displayData.name || wcscmp(actual->displayData.name, owner) ||
        actual->providerData.size != sizeof(session_id) ||
        !actual->providerData.data ||
        memcmp(actual->providerData.data, &session_id, sizeof(session_id)) ||
        actual->numFilterConditions != expected.numFilterConditions ||
        !actual->filterCondition)
        return FALSE;
    for (unsigned i = 0; i < expected.numFilterConditions; ++i) {
        BOOL found = FALSE;
        for (unsigned n = 0; n < expected.numFilterConditions; ++n)
            if (equal_condition(&c[i], &actual->filterCondition[n]))
                found = TRUE;
        if (!found)
            return FALSE;
    }
    return TRUE;
}
static DWORD install(BOOL block_all) {
    DWORD e = FwpmTransactionBegin0(engine, 0);
    if (e)
        return e;
    if (!block_all) {
        FWPM_SUBLAYER0 layer = {0};
        layer.subLayerKey = session_id;
        layer.displayData.name = (wchar_t *)owner;
        layer.flags = FWPM_SUBLAYER_FLAG_PERSISTENT;
        layer.weight = 0xfff0;
        e = FwpmSubLayerAdd0(engine, &layer, NULL);
    }
    unsigned start = block_all ? 6 : 0, end = block_all ? 8 : 6;
    for (unsigned i = 0; !e && i < image_count; ++i)
        for (unsigned r = start; !e && r < end; ++r) {
            FWPM_FILTER0 f;
            FWPM_FILTER_CONDITION0 c[3];
            make_filter(i, r, &f, c);
            e = FwpmFilterAdd0(engine, &f, NULL, &filter_ids[i * 8 + r]);
        }
    for (unsigned i = 0; !e && user_identity && !block_all && i < 8; ++i) {
        FWPM_FILTER0 f;
        FWPM_FILTER_CONDITION0 c[3];
        proxy_filter(i, &f, c);
        e = FwpmFilterAdd0(engine, &f, NULL, NULL);
    }
    if (!e)
        e = FwpmTransactionCommit0(engine);
    if (e)
        FwpmTransactionAbort0(engine);
    else {
        installed += image_count * (end - start);
        if (user_identity && !block_all)
            installed += 8;
        emergency = block_all;
    }
    return e;
}
static DWORD remove_owned(void) {
    DWORD e = FwpmTransactionBegin0(engine, 0);
    if (e)
        return e;
    unsigned count = 0;
    for (unsigned i = 0; !e && i < image_count; ++i)
        for (unsigned r = 0; !e && r < 8; ++r) {
            GUID key = key_for(i, r);
            FWPM_FILTER0 *f = NULL;
            e = FwpmFilterGetByKey0(engine, &key, &f);
            if (e == FWP_E_FILTER_NOT_FOUND) {
                e = 0;
                continue;
            }
            if (!e) {
                if (!owned(f, i, r))
                    e = ERROR_INVALID_OWNER;
                FwpmFreeMemory0((void **)&f);
                if (!e) {
                    e = FwpmFilterDeleteByKey0(engine, &key);
                    ++count;
                }
            }
        }
    for (unsigned i = 0; !e && user_identity && i < 8; ++i) {
        GUID key = key_for(MAX_IMAGES, i);
        FWPM_FILTER0 *f = NULL;
        e = FwpmFilterGetByKey0(engine, &key, &f);
        if (e == FWP_E_FILTER_NOT_FOUND) {
            e = 0;
            continue;
        }
        if (!e) {
            if (!proxy_filter_owned(i, f))
                e = ERROR_INVALID_OWNER;
            FwpmFreeMemory0((void **)&f);
        }
        if (!e)
            e = FwpmFilterDeleteByKey0(engine, &key);
    }
    if (!e) {
        FWPM_SUBLAYER0 *s = NULL;
        e = FwpmSubLayerGetByKey0(engine, &session_id, &s);
        if (e == FWP_E_SUBLAYER_NOT_FOUND)
            e = 0;
        else if (!e) {
            BOOL own = s->displayData.name &&
                       !wcscmp(s->displayData.name, owner) &&
                       s->weight == 0xfff0;
            FwpmFreeMemory0((void **)&s);
            e = own ? FwpmSubLayerDeleteByKey0(engine, &session_id)
                    : ERROR_INVALID_OWNER;
        }
    }
    if (!e)
        e = FwpmTransactionCommit0(engine);
    if (e)
        FwpmTransactionAbort0(engine);
    else
        installed = 0;
    (void)count;
    return e;
}
static BOOL any_existing(void) {
#ifdef PH_CLAUDE_TAKEOVER
    if (current_user) {
        BOOL active;
        return ClaudeTakeoverFind(&takeover, FALSE, &active) || active;
    }
#endif
    if (user_identity)
        return IsValidSid(account.sid) && SessionAccountAlive(&account);
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE)
        return TRUE;
    PROCESSENTRY32W entry = {0};
    entry.dwSize = sizeof(entry);
    BOOL found = FALSE;
    for (BOOL more = Process32FirstW(snapshot, &entry); more && !found;
         more = Process32NextW(snapshot, &entry)) {
        for (unsigned i = 0; i < image_count; ++i) {
            const wchar_t *name = wcsrchr(images[i], L'\\');
            if (!name || _wcsicmp(name + 1, entry.szExeFile))
                continue;
            HANDLE p = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE,
                                   entry.th32ProcessID);
            if (!p) {
                found = TRUE;
                break;
            }
            found = same_image(p, images[i]);
            CloseHandle(p);
            if (found)
                break;
        }
    }
    CloseHandle(snapshot);
    return found;
}
static DWORD listener_pid(void) {
    DWORD size = 0;
    GetExtendedTcpTable(NULL, &size, FALSE, AF_INET,
                        TCP_TABLE_OWNER_PID_LISTENER, 0);
    PMIB_TCPTABLE_OWNER_PID table = HeapAlloc(GetProcessHeap(), 0, size);
    if (!table)
        return 0;
    DWORD pid = 0;
    if (!GetExtendedTcpTable(table, &size, FALSE, AF_INET,
                             TCP_TABLE_OWNER_PID_LISTENER, 0))
        for (DWORD i = 0; i < table->dwNumEntries; ++i)
            if (ntohs((USHORT)table->table[i].dwLocalPort) == proxy_port &&
                table->table[i].dwLocalAddr == htonl(0x7f000001)) {
                pid = table->table[i].dwOwningPid;
                break;
            }
    HeapFree(GetProcessHeap(), 0, table);
    return pid;
}
static HANDLE named_process(const wchar_t *name) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE)
        return NULL;
    PROCESSENTRY32W entry = {0};
    entry.dwSize = sizeof(entry);
    HANDLE result = NULL;
    for (BOOL more = Process32FirstW(snapshot, &entry); more;
         more = Process32NextW(snapshot, &entry))
        if (!_wcsicmp(entry.szExeFile, name)) {
            if (result) {
                CloseHandle(result);
                result = NULL;
                break;
            }
            result =
                OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION,
                            FALSE, entry.th32ProcessID);
        }
    CloseHandle(snapshot);
    return result;
}
// Resolve the current loopback listener to the core inside its live v2rayN
// parent's installation. Only process metadata is read; never open node files.
static BOOL v2rayn_owner(DWORD *pid, ULONGLONG *born) {
    *pid = listener_pid();
    HANDLE core = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE,
                              FALSE, *pid);
    if (!core)
        return FALSE;
    *born = creation(core);
    DWORD parent_id = 0;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32W entry = {0};
    entry.dwSize = sizeof(entry);
    if (snapshot != INVALID_HANDLE_VALUE) {
        for (BOOL more = Process32FirstW(snapshot, &entry); more;
             more = Process32NextW(snapshot, &entry))
            if (entry.th32ProcessID == *pid) {
                parent_id = entry.th32ParentProcessID;
                break;
            }
        CloseHandle(snapshot);
    }
    HANDLE manager = OpenProcess(
        PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, parent_id);
    BOOL ok = FALSE;
    if (manager) {
        wchar_t path[2048], expected[2112];
        DWORD length = _countof(path);
        ULONGLONG manager_born = creation(manager);
        if (manager_born && manager_born <= *born &&
            QueryFullProcessImageNameW(manager, 0, path, &length)) {
            wchar_t *base = wcsrchr(path, L'\\');
            if (base && !_wcsicmp(base + 1, L"v2rayN.exe")) {
                *base = 0;
                swprintf_s(expected, _countof(expected),
                           L"%ls\\bin\\xray\\xray.exe", path);
                ok = same_image(core, expected);
                if (!ok) {
                    swprintf_s(expected, _countof(expected),
                               L"%ls\\bin\\sing_box\\sing-box.exe", path);
                    ok = same_image(core, expected);
                }
            }
        }
        ok = ok && WaitForSingleObject(manager, 0) == WAIT_TIMEOUT;
        CloseHandle(manager);
    }
    ok = ok && listener_pid() == *pid &&
         WaitForSingleObject(core, 0) == WAIT_TIMEOUT;
    CloseHandle(core);
    return ok;
}
static BOOL tun_ok(BOOL initial) {
    if (lab || (user_identity && !require_tun))
        return TRUE;
    SOCKADDR_INET destination = {0};
    destination.Ipv4.sin_family = AF_INET;
    destination.Ipv4.sin_addr.s_addr = htonl(0x01010101);
    MIB_IPFORWARD_ROW2 route;
    SOCKADDR_INET source;
    if (GetBestRoute2(NULL, 0, NULL, &destination, 0, &route, &source))
        return FALSE;
    MIB_IF_ROW2 row = {0};
    row.InterfaceLuid = route.InterfaceLuid;
    if (GetIfEntry2(&row) || row.OperStatus != IfOperStatusUp)
        return FALSE;
    if (initial) {
        if (!wcsstr(row.Description, L"sing-tun") &&
            !wcsstr(row.Alias, L"singbox_tun"))
            return FALSE;
        tun_luid = route.InterfaceLuid;
        tun_index = route.InterfaceIndex;
    }
    return route.InterfaceLuid.Value == tun_luid.Value;
}
static BOOL ipv4_public(const char *text) {
    IN_ADDR addr;
    char canonical[16];
    if (InetPtonA(AF_INET, text, &addr) != 1 ||
        !InetNtopA(AF_INET, &addr, canonical, sizeof(canonical)) ||
        strcmp(canonical, text))
        return FALSE;
    UINT32 v = ntohl(addr.s_addr);
    return (v >> 24) != 0 && (v >> 24) != 10 && (v >> 24) != 127 &&
           (v >> 24) < 224 && (v & 0xfff00000) != 0xac100000 &&
           (v & 0xffff0000) != 0xc0a80000 && (v & 0xffff0000) != 0xa9fe0000 &&
           (v & 0xffc00000) != 0x64400000 && (v >> 8) != 0xc00000 &&
           (v >> 8) != 0xc00002 && (v >> 8) != 0xc05863 &&
           (v >> 17) != (0xc6120000 >> 17) && (v >> 8) != 0xc63364 &&
           (v >> 8) != 0xcb0071;
}
// A TLS read may finish in the middle of a syntactically valid address.
// Require the complete bounded response and canonical ASCII before comparing.
static BOOL read_exit_body(HINTERNET request, char out[64]) {
    DWORD used = 0;
    ULONGLONG deadline = GetTickCount64() + 5000;
    while (used <= 15 && GetTickCount64() < deadline) {
        DWORD n = 0;
        if (!WinHttpReadData(request, out + used, 16 - used, &n))
            return FALSE;
        if (!n) {
            out[used] = 0;
            if (strlen(out) == used && ipv4_public(out))
                return TRUE;
            break;
        }
        used += n;
    }
    SetLastError(ERROR_INVALID_DATA);
    return FALSE;
}
static BOOL query_exit(char out[64]) {
    wchar_t proxy[64];
    swprintf_s(proxy, 64, L"127.0.0.1:%u", proxy_port);
    HINTERNET s =
        WinHttpOpen(L"ProxyHarbor/0.2", WINHTTP_ACCESS_TYPE_NAMED_PROXY, proxy,
                    WINHTTP_NO_PROXY_BYPASS, 0);
    if (!s) {
        network_error = GetLastError();
        return FALSE;
    }
    WinHttpSetTimeouts(s, 5000, 5000, 5000, 5000);
    HINTERNET c = WinHttpConnect(s, L"api.ipify.org", 443, 0),
              r = c ? WinHttpOpenRequest(
                          c, L"GET", L"/", NULL, WINHTTP_NO_REFERER,
                          WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE)
                    : NULL;
    BOOL ok = FALSE;
    if (r) {
        DWORD disabled = WINHTTP_DISABLE_REDIRECTS;
        DWORD code = 0, size = sizeof(code);
        if (WinHttpSetOption(r, WINHTTP_OPTION_DISABLE_FEATURE, &disabled,
                             sizeof(disabled)) &&
            WinHttpSendRequest(r, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                               WINHTTP_NO_REQUEST_DATA, 0, 0, 0) &&
            WinHttpReceiveResponse(r, NULL) &&
            WinHttpQueryHeaders(
                r, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                WINHTTP_HEADER_NAME_BY_INDEX, &code, &size,
                WINHTTP_NO_HEADER_INDEX) &&
            code == 200)
            ok = read_exit_body(r, out);
        network_error = ok ? 0 : GetLastError();
        if (!ok && !network_error)
            network_error = ERROR_INVALID_DATA;
        WinHttpCloseHandle(r);
    } else
        network_error = GetLastError();
    if (c)
        WinHttpCloseHandle(c);
    WinHttpCloseHandle(s);
    return ok;
}
static BOOL exit_ok(BOOL initial) {
    if (lab) {
        if (initial)
            strcpy_s(observed_exit, 64, "fixture");
        return TRUE;
    }
    // Managed images can only reach the explicit HTTP entrance. A separate
    // transparent-TUN probe is diagnostic and cannot certify these images.
    char proxy[64] = {0};
    BOOL proxy_ok = query_exit(proxy);
    DWORD proxy_error = network_error;
    const char *baseline = expected_exit[0] ? expected_exit : observed_exit;
    BOOL mismatch = proxy_ok && baseline[0] && strcmp(proxy, baseline) != 0;
    if (!proxy_ok || mismatch) {
        // Wake enforcement before any diagnostic file write or flush.
        InterlockedExchange(&exit_fault, mismatch ? EXIT_MISMATCH : EXIT_UNVERIFIED);
        if (exit_alarm)
            SetEvent(exit_alarm);
    } else {
        InterlockedExchange64(&last_exit_check, (LONG64)GetTickCount64());
    }
    if (directory[0]) {
        char result[512];
        SYSTEMTIME now;
        GetSystemTime(&now);
        sprintf_s(
            result, sizeof(result),
            "{\"proxySucceeded\":%s,\"proxyError\":%lu,\"path\":"
            "\"explicit_proxy_only\",\"expected\":\"%s\",\"observed\":\"%s\","
            "\"matchesExpected\":%s,\"checkedAt\":\"%04u-%02u-%02uT%02u:%02u:%"
            "02uZ\"}\n",
            proxy_ok ? "true" : "false", proxy_error, expected_exit,
            proxy_ok ? proxy : "",
            proxy_ok && expected_exit[0] && !strcmp(proxy, expected_exit)
                ? "true"
                : "false",
            now.wYear, now.wMonth, now.wDay, now.wHour, now.wMinute,
            now.wSecond);
        if (write_file(L"exit-check.tmp", result)) {
            wchar_t from[1200], to[1200];
            path_for(from, _countof(from), L"exit-check.tmp");
            path_for(to, _countof(to), L"exit-check.json");
            MoveFileExW(from, to,
                        MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH);
        }
    }
    if (!proxy_ok)
        return FALSE;
    if (mismatch) {
        network_error = ERROR_INVALID_DATA;
        return FALSE;
    }
    if (initial)
        strcpy_s(observed_exit, 64, proxy);
    return TRUE;
}
static const char *exit_stop_reason(void) {
    LONG fault = InterlockedCompareExchange(&exit_fault, 0, 0);
    if (fault == EXIT_MISMATCH)
        return "exit_mismatch";
    if (fault == EXIT_UNVERIFIED)
        return "exit_unverified";
    ULONGLONG last = (ULONGLONG)InterlockedCompareExchange64(&last_exit_check, 0, 0);
    if (!lab && (!last || GetTickCount64() - last >= 30000))
        return "exit_unverified";
    return NULL;
}
static DWORD events_begin(void) {
    FWP_VALUE0 *v = NULL;
    DWORD e = FwpmEngineGetOption0(engine, FWPM_ENGINE_COLLECT_NET_EVENTS, &v);
    if (e)
        return e;
    if (v->type != FWP_UINT32 || v->uint32 > 1) {
        FwpmFreeMemory0((void **)&v);
        return ERROR_INVALID_DATA;
    }
    previous_events = v->uint32;
    FwpmFreeMemory0((void **)&v);
    char text[16];
    sprintf_s(text, 16, "%u\n", previous_events);
    if (!write_file(L"events.previous", text))
        return ERROR_WRITE_FAULT;
    events_saved = TRUE;
    if (!previous_events) {
        FWP_VALUE0 on = {0};
        on.type = FWP_UINT32;
        on.uint32 = 1;
        e = FwpmEngineSetOption0(engine, FWPM_ENGINE_COLLECT_NET_EVENTS, &on);
    }
    GetSystemTimeAsFileTime(&began);
    return e;
}
static BOOL events_restore(void) {
    if (!events_saved)
        return TRUE;
    FWP_VALUE0 v = {0};
    v.type = FWP_UINT32;
    v.uint32 = previous_events;
    if (FwpmEngineSetOption0(engine, FWPM_ENGINE_COLLECT_NET_EVENTS, &v))
        return FALSE;
    FWP_VALUE0 *actual = NULL;
    BOOL ok = FwpmEngineGetOption0(engine, FWPM_ENGINE_COLLECT_NET_EVENTS,
                                   &actual) == 0;
    if (ok)
        ok = actual && actual->type == FWP_UINT32 &&
             actual->uint32 == previous_events;
    if (actual)
        FwpmFreeMemory0((void **)&actual);
    return ok;
}
static DWORD WINAPI check_exits(LPVOID unused) {
    (void)unused;
    while (WaitForSingleObject(stop_checks, 10000) == WAIT_TIMEOUT)
        if (!exit_ok(FALSE))
            break;
    return 0;
}
static DWORD load_events_previous(void) {
    wchar_t path[1200];
    path_for(path, 1200, L"events.previous");
    HANDLE file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                              OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE)
        return GetLastError() == ERROR_FILE_NOT_FOUND ? 0 : GetLastError();
    char data[4];
    DWORD size = GetFileSize(file, NULL), read = 0;
    BOOL ok = size == 2 && ReadFile(file, data, 2, &read, NULL) && read == 2 &&
              (data[0] == '0' || data[0] == '1') && data[1] == '\n';
    CloseHandle(file);
    if (!ok)
        return ERROR_INVALID_DATA;
    previous_events = (UINT32)(data[0] - '0');
    events_saved = TRUE;
    return 0;
}
static int blocked_event(void) {
    FWP_VALUE0 *enabled = NULL;
    DWORD setting =
        FwpmEngineGetOption0(engine, FWPM_ENGINE_COLLECT_NET_EVENTS, &enabled);
    BOOL collecting = !setting && enabled && enabled->type == FWP_UINT32 &&
                      enabled->uint32 == 1;
    if (enabled)
        FwpmFreeMemory0((void **)&enabled);
    if (!collecting)
        return -1;
    FWPM_NET_EVENT_ENUM_TEMPLATE0 query = {0};
    query.startTime = began;
    GetSystemTimeAsFileTime(&query.endTime);
    HANDLE enumeration = NULL;
    if (FwpmNetEventCreateEnumHandle0(engine, &query, &enumeration))
        return -1;
    int matched = 0;
    for (unsigned page = 0; page < 64 && !matched; ++page) {
        FWPM_NET_EVENT0 **events = NULL;
        UINT32 count = 0;
        DWORD e = FwpmNetEventEnum0(engine, enumeration, 256, &events, &count);
        if (e) {
            matched = -1;
            if (events)
                FwpmFreeMemory0((void **)&events);
            break;
        }
        for (UINT32 i = 0; i < count && !matched; ++i) {
            FWPM_NET_EVENT0 *event = events[i];
            if (event->type != FWPM_NET_EVENT_TYPE_CLASSIFY_DROP ||
                !event->classifyDrop)
                continue;
            for (unsigned image = 0; image < image_count && !matched; ++image)
                for (unsigned rule = 0; rule < BASE_RULES; ++rule)
                    if (event->classifyDrop->filterId ==
                        filter_ids[image * 8 + rule]) {
                        SYSTEMTIME utc;
                        if (FileTimeToSystemTime(&event->header.timeStamp,
                                                 &utc))
                            sprintf_s(blocked_at, sizeof(blocked_at),
                                      "%04u-%02u-%02uT%02u:%02u:%02uZ",
                                      utc.wYear, utc.wMonth, utc.wDay,
                                      utc.wHour, utc.wMinute, utc.wSecond);
                        blocked_filter = event->classifyDrop->filterId;
                        strcpy_s(block_direction, sizeof(block_direction),
                                 rule >= 4 ? "inbound" : "outbound");
                        if (event->header.flags &
                            FWPM_NET_EVENT_FLAG_IP_PROTOCOL_SET)
                            blocked_protocol = event->header.ipProtocol;
                        if (event->header.flags &
                            FWPM_NET_EVENT_FLAG_REMOTE_PORT_SET)
                            blocked_remote_port = event->header.remotePort;
                        matched = 1;
                        break;
                    }
        }
        if (events)
            FwpmFreeMemory0((void **)&events);
        if (count < 256)
            break;
        if (page == 63)
            matched = -1;
    }
    FwpmNetEventDestroyEnumHandle0(engine, enumeration);
    return matched;
}
static DWORD active_processes(void) {
#ifdef PH_CLAUDE_TAKEOVER
    if (current_user)
        return takeover.root && WaitForSingleObject(takeover.root, 0) == WAIT_TIMEOUT;
#endif
    JOBOBJECT_BASIC_ACCOUNTING_INFORMATION info;
    if (!QueryInformationJobObject(job, JobObjectBasicAccountingInformation,
                                   &info, sizeof(info), NULL))
        return MAXDWORD;
    return info.ActiveProcesses;
}
static DWORD component_failure(const char *phase, DWORD pid, DWORD error) {
    char report[128];
    sprintf_s(report, sizeof(report), "{\"phase\":\"%s\",\"pid\":%lu,\"error\":%lu}\n",
              phase, pid, error);
    write_file(L"component-check.json", report);
    return error;
}
static DWORD check_components(void) {
#ifdef PH_CLAUDE_TAKEOVER
    if (current_user)
        return ClaudeTakeoverHealth(&takeover);
#endif
    ULONG_PTR storage[258];
    JOBOBJECT_BASIC_PROCESS_ID_LIST *list = (void *)storage;
    if (!QueryInformationJobObject(job, JobObjectBasicProcessIdList, list,
                                   sizeof(storage), NULL))
        return component_failure("job_members", 0, GetLastError());
    if (list->NumberOfAssignedProcesses != list->NumberOfProcessIdsInList ||
        list->NumberOfProcessIdsInList > 256)
        return component_failure("job_members", 0, ERROR_MORE_DATA);
    for (DWORD i = 0; i < list->NumberOfProcessIdsInList; ++i) {
        DWORD pid = (DWORD)list->ProcessIdList[i];
        HANDLE p;
        DWORD error = SessionOpenJobProcess(job, pid, &p);
        if (error)
            return component_failure("job_process_handle", pid, error);
        if (!p)
            continue;
        BOOL match = FALSE;
        if (user_identity) {
            error = SessionAccountProcessIdentity(&account, p);
            DWORD wait = WaitForSingleObject(p, 0);
            DWORD wait_error = wait == WAIT_FAILED ? GetLastError() : 0;
            CloseHandle(p);
            if (wait_error)
                return component_failure("process_state", pid, wait_error);
            if (error && wait != WAIT_OBJECT_0)
                return component_failure("process_identity", pid, error);
            continue;
        }
        for (unsigned j = 0; j < image_count; ++j)
            if (same_image(p, images[j])) {
                match = TRUE;
                break;
            }
        if (!match) {
            wchar_t system[1024];
            if (GetSystemDirectoryW(system, 1000)) {
                wcscat_s(system, 1024, L"\\conhost.exe");
                match = same_image(p, system);
            }
        }
        if (!match) {
            wchar_t full[1024];
            DWORD length = 1024;
            if (QueryFullProcessImageNameW(p, 0, full, &length)) {
                char text[4096];
                int n = WideCharToMultiByte(CP_UTF8, 0, full, -1, text,
                                            sizeof(text), NULL, NULL);
                if (n > 0)
                    write_file(L"unlisted-component.txt", text);
            }
        }
        DWORD wait = WaitForSingleObject(p, 0);
        CloseHandle(p);
        if (!match && wait != WAIT_OBJECT_0)
            return component_failure("process_image", pid, ERROR_INVALID_OWNER);
    }
    return ERROR_SUCCESS;
}
#ifdef PH_CLAUDE_MSIX
static DWORD unregister_claude(void) {
    wchar_t diagnostic[1200];
    path_for(diagnostic, ARRAYSIZE(diagnostic), L"claude-package-cleanup.log");
    DWORD error = ClaudeMSIXUnregister(&account, diagnostic);
    if (error) {
        FILE *file = NULL;
        fprintf(stderr, "Claude temporary package cleanup failed (%lu)\n", error);
        if (!_wfopen_s(&file, diagnostic, L"rb") && file) {
            char bytes[4096];
            size_t count = fread(bytes, 1, sizeof(bytes), file);
            fwrite(bytes, 1, count, stderr);
            fclose(file);
        }
        fflush(stderr);
    }
    return error;
}

static DWORD resume_claude(DWORD pid) {
    wchar_t path[1200];
    swprintf_s(path, ARRAYSIZE(path), L"%ls\\claude-suspended.txt", account.profile);
    HANDLE file = CreateFileW(path, GENERIC_READ, 0, NULL, OPEN_EXISTING,
                              FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    if (file == INVALID_HANDLE_VALUE)
        return GetLastError();
    BY_HANDLE_FILE_INFORMATION info;
    char record[96] = {0}, canonical[96];
    DWORD bytes = 0;
    DWORD recorded_pid = 0, thread_id = 0;
    ULONGLONG born = 0;
    BOOL valid = GetFileType(file) == FILE_TYPE_DISK && GetFileInformationByHandle(file, &info) &&
                 !(info.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY)) &&
                 info.nNumberOfLinks == 1 && !info.nFileSizeHigh && info.nFileSizeLow < sizeof(record) &&
                 ReadFile(file, record, sizeof(record) - 1, &bytes, NULL) && bytes == info.nFileSizeLow &&
                 sscanf_s(record, "%lu %lu %llu", &recorded_pid, &thread_id, &born) == 3 &&
                 recorded_pid == pid && thread_id && born &&
                 sprintf_s(canonical, sizeof(canonical), "%lu %lu %llu\n", pid, thread_id, born) == (int)bytes &&
                 !memcmp(record, canonical, bytes);
    CloseHandle(file);
    if (!valid)
        return ERROR_INVALID_DATA;
    HANDLE app = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE |
                                 PROCESS_SET_QUOTA | SYNCHRONIZE, FALSE, pid);
    if (!app)
        return GetLastError();
    HANDLE thread = OpenThread(THREAD_SUSPEND_RESUME | THREAD_QUERY_LIMITED_INFORMATION, FALSE, thread_id);
    BOOL belongs = FALSE;
    DWORD error = 0;
    if (!thread)
        error = 0x82010000 | (GetLastError() & 0xffff);
    else if (GetProcessIdOfThread(thread) != pid || creation(app) != born ||
             !ClaudeMSIXMatches(app, images[0], claude_package, account.sid) ||
             WaitForSingleObject(app, 0) != WAIT_TIMEOUT)
        error = 0x82020000;
    else if (!IsProcessInJob(app, job, &belongs))
        error = 0x82030000 | (GetLastError() & 0xffff);
    else if (!belongs) {
        // AppX activation can run in a Windows Job outside the launcher's
        // hierarchy. Windows only permits nesting into an empty new Job.
        HANDLE app_job = CreateJobObjectW(NULL, NULL);
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits = {0};
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        if (!app_job || !SetInformationJobObject(app_job, JobObjectExtendedLimitInformation, &limits, sizeof(limits)) ||
            !AssignProcessToJobObject(app_job, app) || !IsProcessInJob(app, app_job, &belongs) || !belongs)
            error = 0x82040000 | (GetLastError() & 0xffff);
        if (!error) {
            CloseHandle(job);
            job = app_job;
        } else if (app_job)
            CloseHandle(app_job);
    }
    if (!error) {
        if (exit_stop_reason() || !tun_ok(FALSE) ||
            WaitForSingleObject(parent, 0) != WAIT_TIMEOUT || listener_pid() != expected_proxy_pid ||
            !verify_filters() || blocked_event() != 0 || (system_dns_enabled && SystemDNSVerify(&dns_guard)))
            error = ERROR_INVALID_STATE;
        else
            error = ResumeThread(thread) == 1 ? 0 : ERROR_INVALID_STATE;
    }
    if (thread)
        CloseHandle(thread);
    CloseHandle(app);
    return error;
}

static DWORD await_claude(HANDLE launcher) {
    ULONGLONG deadline = GetTickCount64() + 27000;
    DWORD wait;
    do {
        if (exit_stop_reason() || !tun_ok(FALSE) ||
            WaitForSingleObject(parent, 0) != WAIT_TIMEOUT ||
            WaitForSingleObject(proxy_process, 0) != WAIT_TIMEOUT || listener_pid() != expected_proxy_pid ||
            (system_dns_enabled && (!dns_watch || WaitForSingleObject(dns_watch, 0) != WAIT_TIMEOUT || SystemDNSVerify(&dns_guard))) ||
            !verify_filters() || blocked_event() != 0)
            return ERROR_INVALID_STATE;
        if (stop_requested())
            return ERROR_CANCELLED;
        wait = WaitForSingleObject(launcher, 200);
    } while (wait == WAIT_TIMEOUT && GetTickCount64() < deadline);
    if (wait != WAIT_OBJECT_0)
        return wait == WAIT_TIMEOUT ? ERROR_TIMEOUT : GetLastError();
    DWORD pid;
    if (!GetExitCodeProcess(launcher, &pid))
        return GetLastError();
    if (!pid || pid >= 0x80000000) {
        char report[96];
        sprintf_s(report, sizeof(report), "{\"helperStatus\":\"0x%08lx\"}\n", pid);
        write_file(L"claude-launch.json", report);
        return ERROR_PROCESS_ABORTED;
    }
    DWORD error = resume_claude(pid);
    if (error) {
        char report[96];
        sprintf_s(report, sizeof(report), "{\"resumeError\":%lu}\n", error);
        write_file(L"claude-launch.json", report);
        return error;
    }
    char report[96];
    sprintf_s(report, sizeof(report), "{\"pid\":%lu,\"packageVerified\":true,\"jobVerified\":true}\n", pid);
    if (!write_file(L"claude-launch.json", report))
        return ERROR_WRITE_FAULT;
    child_pid = pid;
    return 0;
}
#endif
static DWORD launch(void) {
    wchar_t command[4096], profile[1200];
    BOOL capture_guest = FALSE;
    if (user_identity)
        swprintf_s(profile, 1200, L"%ls\\browser", account.profile);
    else
        path_for(profile, 1200, L"profile");
    CreateDirectoryW(profile, NULL);
    if (lab && user_identity) {
        // Fixture commands live in the new account's profile, outside the
        // privileged guardian records. Production grants no target access.
        swprintf_s(
            command, 4096,
            L"\"%ls\" -session-fixture \"%ls\" -proxy-port %u -owned-profile",
            images[0], account.profile, proxy_port);
        char location[2048];
        if (!WideCharToMultiByte(CP_UTF8, 0, account.profile, -1, location,
                                 sizeof(location), NULL, NULL) ||
            !write_file(L"fixture-directory.txt", location))
            return ERROR_WRITE_FAULT;
    } else if (lab)
        swprintf_s(command, 4096,
                   L"\"%ls\" -session-fixture \"%ls\" -proxy-port %u",
                   images[0], directory, proxy_port);
    else if (desktop_client)
        swprintf_s(command, 4096,
                   L"\"%ls\" --user-data-dir=\"%ls\" --proxy-server=http://127.0.0.1:%u "
                   L"--proxy-bypass-list=\"<-loopback>\"",
                   images[0], profile, proxy_port);
    else
        swprintf_s(command, 4096,
                   L"\"%ls\" --user-data-dir=\"%ls\" --no-first-run "
                   L"--proxy-server=http://127.0.0.1:%u "
                   L"--proxy-bypass-list=\"<-loopback>\" --disable-quic "
                   L"--disable-features=MediaRouter "
                   L"--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
                   images[0], profile, proxy_port);
    if (!lab && !desktop_client && (!wcscmp(mode, L"chrome") || user_identity)) {
        if (user_identity)
            wcscat_s(command, _countof(command),
                     L" --host-resolver-rules=\"MAP * ~NOTFOUND, EXCLUDE "
                     L"127.0.0.1\"");
        wchar_t headless[16], guest_cwd[MAX_PATH], guest_marker[32];
        if (user_identity &&
            GetEnvironmentVariableW(L"PH_GUEST_CHROME_MODE", headless, 16) &&
            GetCurrentDirectoryW(MAX_PATH, guest_cwd) &&
            !_wcsicmp(guest_cwd, L"C:\\P0Lab") &&
            GetEnvironmentVariableW(L"PROXY_HARBOR_P0_GUEST", guest_marker,
                                    32) &&
            !wcscmp(guest_marker, L"offline-lab")) {
            if (wcscmp(headless, L"dom") && wcscmp(headless, L"hold"))
                return ERROR_INVALID_PARAMETER;
            size_t used = wcslen(command);
            swprintf_s(
                command + used, 4096 - used,
                L" --headless=new --disable-gpu %ls https://api.ipify.org/",
                !wcscmp(headless, L"dom") ? L"--dump-dom" : L"");
            capture_guest = TRUE;
        }
        wchar_t debug[16], cwd[1024], marker[32];
        if (GetEnvironmentVariableW(L"PH_GUEST_CHROME_DEBUG_PORT", debug, 16) &&
            GetCurrentDirectoryW(1024, cwd) && !_wcsicmp(cwd, L"C:\\P0Lab") &&
            GetEnvironmentVariableW(L"PROXY_HARBOR_P0_GUEST", marker, 32) &&
            !wcscmp(marker, L"offline-lab")) {
            wchar_t *end = NULL;
            unsigned long port = wcstoul(debug, &end, 10);
            if (!end || *end || port < 1024 || port > 65535)
                return ERROR_INVALID_PARAMETER;
            size_t used = wcslen(command);
            swprintf_s(command + used, 4096 - used,
                       L" --headless=new --remote-debugging-port=%lu "
                       L"--disable-gpu about:blank",
                       port);
        }
    }
    wchar_t proxy[80];
    swprintf_s(proxy, 80, L"http://127.0.0.1:%u", proxy_port);
    SetEnvironmentVariableW(L"HTTP_PROXY", proxy);
    SetEnvironmentVariableW(L"HTTPS_PROXY", proxy);
    SetEnvironmentVariableW(L"ALL_PROXY", proxy);
    SetEnvironmentVariableW(L"NO_PROXY", L"");
    if (!wcscmp(mode, L"codex")) {
        wchar_t local[1200], roaming[1200], codex[1200];
        path_for(local, 1200, L"local");
        path_for(roaming, 1200, L"roaming");
        path_for(codex, 1200, L"codex");
        CreateDirectoryW(local, NULL);
        CreateDirectoryW(roaming, NULL);
        CreateDirectoryW(codex, NULL);
        SetEnvironmentVariableW(L"APPDATA", roaming);
        SetEnvironmentVariableW(L"LOCALAPPDATA", local);
        SetEnvironmentVariableW(L"CODEX_HOME", codex);
        SetEnvironmentVariableW(L"CODEX_ELECTRON_USER_DATA_PATH", profile);
    }
    if (user_identity) {
        const wchar_t *launch_image = images[0];
        BOOL keep_password = FALSE;
#ifdef PH_CLAUDE_MSIX
        wchar_t helper[MAX_PATH];
        if (claude_msix) {
            DWORD length = GetModuleFileNameW(NULL, helper, ARRAYSIZE(helper));
            wchar_t id[40];
            if (!length || length >= ARRAYSIZE(helper) ||
                !StringFromGUID2(&session_id, id, ARRAYSIZE(id)) ||
                swprintf_s(command, ARRAYSIZE(command), L"\"%ls\" claude-msix-launch \"%ls\" %u %ls",
                           helper, images[0], proxy_port, id) < 0)
                return ERROR_INVALID_PARAMETER;
            launch_image = helper;
            keep_password = TRUE; // Used once for AppX removal in the same identity.
        }
#endif
        PROCESS_INFORMATION process = {0};
        STARTUPINFOW startup = {0};
        startup.cb = sizeof(startup);
        HANDLE handles[3] = {0};
        if (capture_guest) {
            for (unsigned i = 0; i < 3; ++i) {
                HANDLE source = GetStdHandle(i == 0   ? STD_INPUT_HANDLE
                                             : i == 1 ? STD_OUTPUT_HANDLE
                                                      : STD_ERROR_HANDLE);
                if (!DuplicateHandle(GetCurrentProcess(), source,
                                     GetCurrentProcess(), &handles[i], 0, TRUE,
                                     DUPLICATE_SAME_ACCESS)) {
                    DWORD e = GetLastError();
                    for (unsigned n = 0; n < 3; ++n)
                        if (handles[n])
                            CloseHandle(handles[n]);
                    return e;
                }
            }
            startup.dwFlags = STARTF_USESTDHANDLES;
            startup.hStdInput = handles[0];
            startup.hStdOutput = handles[1];
            startup.hStdError = handles[2];
        }
        DWORD error = SessionAccountLaunch(&account, launch_image, command,
                                           proxy_port, &startup, &process, keep_password);
        for (unsigned i = 0; i < 3; ++i)
            if (handles[i])
                CloseHandle(handles[i]);
        if (error)
            return error;
#ifdef PH_CLAUDE_MSIX
        if (!claude_msix)
#endif
            child_pid = process.dwProcessId;
        if (!AssignProcessToJobObject(job, process.hProcess))
            error = GetLastError();
        HANDLE token = NULL;
        BYTE data[256];
        DWORD size = 0;
        if (!error &&
            (!OpenProcessToken(process.hProcess, TOKEN_QUERY, &token) ||
             !GetTokenInformation(token, TokenUser, data, sizeof(data),
                                  &size) ||
             !EqualSid(((TOKEN_USER *)data)->User.Sid, account.sid)))
            error = ERROR_INVALID_TOKEN;
        if (token)
            CloseHandle(token);
        if (!error && (!verify_filters() || blocked_event() != 0 ||
                       WaitForSingleObject(parent, 0) != WAIT_TIMEOUT ||
                       WaitForSingleObject(proxy_process, 0) != WAIT_TIMEOUT ||
                       listener_pid() != GetProcessId(proxy_process)))
            error = ERROR_INVALID_STATE;
        if (!error && !lab && !desktop_client &&
            !SessionAccountBrowserPolicyValid(&account, proxy_port))
            error = ERROR_INVALID_STATE;
        if (!error && exit_stop_reason())
            error = ERROR_NETWORK_UNREACHABLE;
        if (!error && ResumeThread(process.hThread) == MAXDWORD)
            error = GetLastError();
#ifdef PH_CLAUDE_MSIX
        if (!error && claude_msix)
            error = await_claude(process.hProcess);
#endif
        if (error) {
            TerminateProcess(process.hProcess, 1);
            WaitForSingleObject(process.hProcess, 3000);
        }
        CloseHandle(process.hThread);
        CloseHandle(process.hProcess);
        return error;
    }
    HANDLE token = NULL, primary = NULL;
    PROCESS_INFORMATION process = {0};
    STARTUPINFOW startup = {0};
    startup.cb = sizeof(startup);
    startup.lpDesktop = L"winsta0\\default";
    if (!OpenProcessToken(parent, TOKEN_QUERY | TOKEN_DUPLICATE, &token))
        return GetLastError();
    if (!DuplicateTokenEx(token, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation,
                          TokenPrimary, &primary)) {
        DWORD e = GetLastError();
        CloseHandle(token);
        return e;
    }
    CloseHandle(token);
    LPWCH environment = GetEnvironmentStringsW();
    if (!environment) {
        CloseHandle(primary);
        return GetLastError();
    }
    wchar_t working[1024];
    wcscpy_s(working, 1024, images[0]);
    wchar_t *slash = wcsrchr(working, L'\\');
    if (slash)
        *slash = 0;
    BOOL created = CreateProcessWithTokenW(
        primary, 0, images[0], command,
        CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT |
            (lab ? CREATE_NO_WINDOW : 0),
        environment, lab ? L"C:\\P0Lab" : working, &startup, &process);
    DWORD create_error = created ? 0 : GetLastError();
    FreeEnvironmentStringsW(environment);
    CloseHandle(primary);
    if (!created)
        return create_error;
    child_pid = process.dwProcessId;
    DWORD e = 0;
    if (!AssignProcessToJobObject(job, process.hProcess))
        e = GetLastError();
    if (!e && exit_stop_reason())
        e = ERROR_NETWORK_UNREACHABLE;
    if (!e && ResumeThread(process.hThread) == MAXDWORD)
        e = GetLastError();
    if (e) {
        TerminateProcess(process.hProcess, 1);
        WaitForSingleObject(process.hProcess, 3000);
    }
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    return e;
}
static BOOL parent_valid(void) {
    parent = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE,
                         parent_pid);
    if (!parent || creation(parent) != parent_created)
        return FALSE;
    if (lab)
        return TRUE;
    wchar_t own[1024], expected[1024];
    DWORD length = GetModuleFileNameW(NULL, own, 1024);
    if (!length)
        return FALSE;
    wchar_t *base = wcsrchr(own, L'\\');
    if (!base)
        return FALSE;
    *base = 0;
    swprintf_s(expected, 1024, L"%ls\\proxy-harbor.exe", own);
    return same_image(parent, expected);
}
static BOOL verify_binding(BOOL require_filter_ids) {
    for (unsigned i = 0; i < image_count; ++i)
        for (unsigned r = 0; r < BASE_RULES; ++r) {
            GUID key = key_for(i, r);
            FWPM_FILTER0 *f = NULL;
            if (FwpmFilterGetByKey0(engine, &key, &f))
                return FALSE;
            BOOL ok = owned(f, i, r) && (!require_filter_ids || f->filterId == filter_ids[i * 8 + r]);
            FwpmFreeMemory0((void **)&f);
            if (!ok)
                return FALSE;
        }
    for (unsigned i = 0; user_identity && i < 8; ++i) {
        GUID key = key_for(MAX_IMAGES, i);
        FWPM_FILTER0 *f = NULL;
        if (FwpmFilterGetByKey0(engine, &key, &f))
            return FALSE;
        BOOL ok = proxy_filter_owned(i, f);
        FwpmFreeMemory0((void **)&f);
        if (!ok)
            return FALSE;
    }
    return TRUE;
}
static BOOL verify_filters(void) {
    return verify_binding(TRUE);
}
#ifdef PH_CLAUDE_MSIX
static DWORD recover_claude_registration(void) {
    BOOL registered;
    DWORD error = ClaudeMSIXRegistrationPresent(account.sid, &registered);
    if (error || !registered)
        return error;

    // Re-logon is only for package removal. Require the owned SID rules
    // and block every outbound connection before issuing a fresh secret.
    if (!verify_binding(FALSE))
        return ERROR_INVALID_OWNER;
    unsigned emergency_rules = 0;
    for (unsigned r = 6; r < 8; ++r) {
        GUID key = key_for(0, r);
        FWPM_FILTER0 *filter = NULL;
        error = FwpmFilterGetByKey0(engine, &key, &filter);
        if (error == FWP_E_FILTER_NOT_FOUND)
            continue;
        if (error)
            return error;
        BOOL own = owned(filter, 0, r);
        FwpmFreeMemory0((void **)&filter);
        if (!own)
            return ERROR_INVALID_OWNER;
        ++emergency_rules;
    }
    if (emergency_rules == 0) {
        error = install(TRUE);
        if (error)
            return error;
    } else if (emergency_rules != 2) {
        return ERROR_INVALID_STATE;
    }
    if (!write_file(L"claude-recovery.json", "{\"outboundBlockedBeforeReLogon\":true}\n"))
        return ERROR_WRITE_FAULT;
    error = SessionAccountRecoverPassword(&account);
    if (!error)
        error = unregister_claude();
    if (!error)
        error = SessionAccountTerminate(&account);
    return error;
}
#endif
static BOOL acquire_lock(BOOL recover) {
    wchar_t path[1200];
    path_for(path, 1200, L"owner.lock");
    lock_file = CreateFileW(path, GENERIC_READ | GENERIC_WRITE, 0, NULL,
                            recover ? OPEN_ALWAYS : CREATE_NEW,
                            FILE_ATTRIBUTE_NORMAL, NULL);
    return lock_file != INVALID_HANDLE_VALUE;
}
static DWORD account_policy(BOOL recover) {
    DWORD error;
    PSID identity = account.sid;
#ifdef PH_CLAUDE_TAKEOVER
    if (current_user) {
        wchar_t record[1200];
        path_for(record, ARRAYSIZE(record), L"takeover.bin");
        error = recover ? ClaudeTakeoverRead(&takeover, record)
                        : ClaudeTakeoverBind(&takeover, record, images[0], claude_package, parent);
        if (!error) {
            identity = takeover.identity.sid;
            app_ids[0] = &takeover.app_id;
        }
    } else
#endif
        error = recover ? SessionAccountLoad(&session_id, directory, &account)
                        : SessionAccountCreate(&session_id, directory, &account);
    if (error)
        return error;
    wchar_t *sid = NULL, sddl[256];
    DWORD length = 0;
    if (!ConvertSidToStringSidW(identity, &sid))
        return GetLastError();
    swprintf_s(sddl, 256, L"D:(A;;CC;;;%ls)", sid);
    LocalFree(sid);
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl, SDDL_REVISION_1, &account_descriptor, &length))
        return GetLastError();
    account_security.data = account_descriptor;
    account_security.size = length;
    return 0;
}
static DWORD proxy_identity(BOOL recover) {
    wchar_t path[1200], image[1024] = {0}, sid_text[192] = {0};
    path_for(path, 1200, L"proxy-identity.txt");
    proxy_record = CreateFileW(
        path, GENERIC_READ | GENERIC_WRITE | DELETE, FILE_SHARE_READ, NULL,
        recover ? OPEN_EXISTING : CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    if (proxy_record == INVALID_HANDLE_VALUE) {
        proxy_record = NULL;
        return GetLastError();
    }
    PSID sid = NULL;
    BYTE user[256];
    HANDLE token = NULL;
    DWORD size = 0;
    if (recover) {
        char bytes[4096] = {0};
        wchar_t data[2048];
        DWORD read = 0;
        if (GetFileSize(proxy_record, NULL) >= sizeof(bytes) ||
            !ReadFile(proxy_record, bytes, sizeof(bytes) - 1, &read, NULL) ||
            !MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, bytes, -1, data,
                                 2048))
            return ERROR_INVALID_DATA;
        unsigned port = 0;
        wchar_t extra[8] = {0};
        if (swscanf_s(data, L"PH-PROXY-1\n%191[^\n]\n%u\n%1023[^\n]\n%7s",
                      sid_text, (unsigned)_countof(sid_text), &port, image,
                      (unsigned)_countof(image), extra,
                      (unsigned)_countof(extra)) != 4 ||
            port != proxy_port || wcscmp(extra, L"END") ||
            !ConvertStringSidToSidW(sid_text, &sid))
            return ERROR_INVALID_DATA;
        // Canonical record validation, including complete byte length.
        wchar_t canonical[1600];
        char encoded[4096];
        swprintf_s(canonical, 1600, L"PH-PROXY-1\n%ls\n%u\n%ls\nEND\n",
                   sid_text, proxy_port, image);
        int n = WideCharToMultiByte(CP_UTF8, 0, canonical, -1, encoded,
                                    sizeof(encoded), NULL, NULL);
        if (n <= 0 || (DWORD)(n - 1) != read || memcmp(encoded, bytes, read)) {
            LocalFree(sid);
            return ERROR_INVALID_DATA;
        }
    } else {
        DWORD length = 1024;
        if (!OpenProcessToken(proxy_process, TOKEN_QUERY, &token) ||
            !GetTokenInformation(token, TokenUser, user, sizeof(user), &size) ||
            !QueryFullProcessImageNameW(proxy_process, 0, image, &length)) {
            DWORD e = GetLastError();
            if (token)
                CloseHandle(token);
            return e;
        }
        sid = ((TOKEN_USER *)user)->User.Sid;
        wchar_t *text = NULL;
        if (!ConvertSidToStringSidW(sid, &text)) {
            CloseHandle(token);
            return GetLastError();
        }
        wcscpy_s(sid_text, 192, text);
        LocalFree(text);
        CloseHandle(token);
        wchar_t canonical[1600];
        char encoded[4096];
        swprintf_s(canonical, 1600, L"PH-PROXY-1\n%ls\n%u\n%ls\nEND\n",
                   sid_text, proxy_port, image);
        int n = WideCharToMultiByte(CP_UTF8, 0, canonical, -1, encoded,
                                    sizeof(encoded), NULL, NULL);
        DWORD written = 0;
        if (n <= 0 ||
            !WriteFile(proxy_record, encoded, (DWORD)n - 1, &written, NULL) ||
            written != (DWORD)n - 1 || !FlushFileBuffers(proxy_record))
            return ERROR_WRITE_FAULT;
    }
    wchar_t sddl[256];
    DWORD length = 0;
    swprintf_s(sddl, 256, L"D:(A;;CC;;;%ls)", sid_text);
    DWORD error = ConvertStringSecurityDescriptorToSecurityDescriptorW(
                      sddl, SDDL_REVISION_1, &proxy_descriptor, &length)
                      ? 0
                      : GetLastError();
    if (!error) {
        proxy_security.data = proxy_descriptor;
        proxy_security.size = length;
        error = FwpmGetAppIdFromFileName0(image, &proxy_app);
    }
    if (recover && sid)
        LocalFree(sid);
    return error;
}
static int watch_dns(const wchar_t *pid_text, const wchar_t *created_text) {
    wchar_t *end = NULL;
    DWORD pid = wcstoul(pid_text, &end, 10);
    if (!pid || !end || *end || !system_dns_enabled || !user_identity)
        return 2;
    ULONGLONG born = _wcstoui64(created_text, &end, 10);
    if (!born || !end || *end)
        return 2;
    HANDLE supervisor = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION,
                                    FALSE, pid);
    wchar_t own[MAX_PATH];
    if (!supervisor || creation(supervisor) != born ||
        !GetModuleFileNameW(NULL, own, MAX_PATH) ||
        !same_image(supervisor, own)) {
        if (supervisor)
            CloseHandle(supervisor);
        return 3;
    }
    SESSION_ACCOUNT observed = {0};
    DWORD error;
    if (current_user)
        error = account_policy(TRUE);
    else {
        error = SessionAccountObserve(&session_id, directory, &observed);
        if (!error && !observed.created)
            error = ERROR_INVALID_OWNER;
    }
    HANDLE dns_engine = NULL;
    if (!error)
        error = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, NULL, &dns_engine);
    if (!error)
        error = SystemDNSOpen(&dns_guard, dns_engine, &session_id, TRUE);
    if (!error)
        error = SystemDNSVerify(&dns_guard);
    char binding[96];
    sprintf_s(binding, sizeof(binding), "%lu %llu\n",
              GetCurrentProcessId(), creation(GetCurrentProcess()));
    if (!error && !write_file(L"dns-watch.ready", binding))
        error = ERROR_WRITE_FAULT;
    ULONGLONG disconnected = 0;
    while (!error) {
        DWORD parent_state = WaitForSingleObject(supervisor, 200);
        wchar_t stop[1200];
        path_for(stop, _countof(stop), L"dns-watch.stop");
        BOOL stopping = GetFileAttributesW(stop) != INVALID_FILE_ATTRIBUTES;
        if (parent_state == WAIT_FAILED) {
            error = GetLastError();
            break;
        }
        if (parent_state == WAIT_OBJECT_0) {
            // For temporary accounts, terminate the cached SID. For takeover,
            // allow the worker time to observe its broken guardian pipe.
            error = current_user ? ERROR_SUCCESS : SessionAccountTerminate(&observed);
            if (error)
                break;
            if (current_user && !disconnected)
                disconnected = GetTickCount64();
            stopping = TRUE;
        }
        if (stopping) {
            if (current_user ? !any_existing() : !SessionAccountAlive(&observed)) {
                error = SystemDNSRemove(&dns_guard);
                break;
            }
            if (disconnected) {
                if (GetTickCount64() - disconnected >= 5000) {
                    error = ERROR_BUSY;
                    break;
                }
                Sleep(100);
            }
        }
        error = SystemDNSVerify(&dns_guard);
    }
    write_file(L"dns-watch.state", error ? "cleanup_required\n" : "restored\n");
    SystemDNSClose(&dns_guard);
    if (dns_engine)
        FwpmEngineClose0(dns_engine);
    SessionAccountRelease(&observed);
#ifdef PH_CLAUDE_TAKEOVER
    if (current_user)
        ClaudeTakeoverRelease(&takeover);
#endif
    if (account_descriptor)
        LocalFree(account_descriptor);
    CloseHandle(supervisor);
    return error ? 1 : 0;
}

static DWORD start_dns_watch(void) {
    wchar_t image[MAX_PATH], command[1600];
    if (!GetModuleFileNameW(NULL, image, MAX_PATH))
        return GetLastError();
    swprintf_s(command, _countof(command), L"\"%ls\" dns-watch \"%ls\" %lu %llu",
               image, directory, GetCurrentProcessId(), creation(GetCurrentProcess()));
    STARTUPINFOW startup = {0};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION process = {0};
    if (!CreateProcessW(image, command, NULL, NULL, FALSE, CREATE_NO_WINDOW,
                        NULL, NULL, &startup, &process))
        return GetLastError();
    CloseHandle(process.hThread);
    dns_watch = process.hProcess;
    char expected[96];
    sprintf_s(expected, sizeof(expected), "%lu %llu\n", process.dwProcessId,
              creation(dns_watch));
    for (unsigned i = 0; i < 100; ++i) {
        if (WaitForSingleObject(dns_watch, 0) != WAIT_TIMEOUT)
            return ERROR_PROCESS_ABORTED;
        wchar_t path[1200];
        path_for(path, _countof(path), L"dns-watch.ready");
        FILE *file = NULL;
        if (!_wfopen_s(&file, path, L"rb") && file) {
            char actual[96] = {0};
            size_t n = fread(actual, 1, sizeof(actual) - 1, file);
            fclose(file);
            if (n == strlen(expected) && !memcmp(actual, expected, n))
                return 0;
        }
        Sleep(50);
    }
    return ERROR_TIMEOUT;
}

static DWORD stop_dns_watch(void) {
    if (dns_watch) {
        if (!write_file(L"dns-watch.stop", "stop\n"))
            return ERROR_WRITE_FAULT;
        DWORD waited = WaitForSingleObject(dns_watch, 10000);
        if (waited == WAIT_TIMEOUT)
            return ERROR_TIMEOUT;
        if (waited != WAIT_OBJECT_0)
            return GetLastError();
        DWORD code = 0;
        if (!GetExitCodeProcess(dns_watch, &code))
            return GetLastError();
        // A failed watcher may leave owned rules. The caller has already
        // confirmed the session account has no processes before this fallback.
    }
    return SystemDNSRemove(&dns_guard);
}

int wmain(int argc, wchar_t **argv) {
#ifdef PH_CLAUDE_MSIX_GUEST
    wchar_t own[MAX_PATH], guest_marker[32];
    DWORD own_length = GetModuleFileNameW(NULL, own, ARRAYSIZE(own));
    DWORD marker_length = GetEnvironmentVariableW(L"PROXY_HARBOR_P0_GUEST", guest_marker, ARRAYSIZE(guest_marker));
    if (!own_length || own_length >= ARRAYSIZE(own) || _wcsicmp(own, L"C:\\P0Lab\\guardian.exe") ||
        !marker_length || marker_length >= ARRAYSIZE(guest_marker) || wcscmp(guest_marker, L"offline-lab"))
        return 2;
#endif
#ifdef PH_CLAUDE_TAKEOVER
    if (argc == 3 && !wcscmp(argv[1], L"claude-takeover-worker")) {
        if (!read_request(argv[2], TRUE) || !current_user)
            return ERROR_INVALID_PARAMETER;
        takeover.image = images[0];
        takeover.package = claude_package;
        DWORD error = ClaudeTakeoverWorker(&takeover, directory, parent_pid);
        ClaudeTakeoverRelease(&takeover);
        return (int)error;
    }
#endif
#ifdef PH_CLAUDE_MSIX
    if (argc == 2 && !wcscmp(argv[1], L"claude-image")) {
        wchar_t image[1024];
        char utf8[4096];
        if (!ClaudeMSIXFindImage(image, ARRAYSIZE(image)) ||
            !WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, image, -1, utf8, sizeof(utf8), NULL, NULL))
            return 1;
        puts(utf8);
        return 0;
    }
    if (argc == 5 && !wcscmp(argv[1], L"claude-msix-launch")) {
        GUID id;
        wchar_t username[256], expected[32];
        DWORD size = ARRAYSIZE(username);
        if (wcscmp(argv[3], L"10808") || FAILED(CLSIDFromString(argv[4], &id)) ||
            !GetUserNameW(username, &size))
            return 2;
        SessionAccountName(&id, expected);
        if (_wcsicmp(username, expected))
            return 2;
        ExitProcess(ClaudeMSIXLaunch(argv[2], 10808));
    }
#endif
    if (argc == 5 && !wcscmp(argv[1], L"dns-watch")) {
        if (!read_request(argv[2], FALSE))
            return 3;
        return watch_dns(argv[3], argv[4]);
    }
    if (argc == 2 && !wcscmp(argv[1], L"proxy-owner")) {
        proxy_port = 10808;
        DWORD pid = 0;
        ULONGLONG born = 0;
        if (!v2rayn_owner(&pid, &born))
            return 1;
        printf("{\"pid\":%lu,\"created\":%llu}\n", pid, born);
        return 0;
    }
    if (argc == 2 && !wcscmp(argv[1], L"check")) {
        proxy_port = 10808;
        DWORD pid = 0;
        ULONGLONG born = 0;
        BOOL recognized = v2rayn_owner(&pid, &born);
        BOOL observed = recognized && query_exit(observed_exit);
        BOOL tun_ready = tun_ok(TRUE);
        printf("{\"systemChanged\":false,\"recognizedListener\":%s,"
               "\"proxyListenerPid\":%lu,\"exitVerified\":false,"
               "\"proxyExit\":\"%s\",\"tunReady\":%s,\"tunIndex\":%lu}\n",
               recognized ? "true" : "false", pid,
               observed ? observed_exit : "", tun_ready ? "true" : "false", tun_index);
        return observed ? 0 : 1;
    }
    if (argc != 3 ||
        (wcscmp(argv[1], L"start") && wcscmp(argv[1], L"recover") &&
         wcscmp(argv[1], L"inspect") && wcscmp(argv[1], L"fault-policy") &&
         wcscmp(argv[1], L"fault-monitor")))
        return 2;
    if (!read_request(argv[2], !wcscmp(argv[1], L"start")))
        return 3;
    if (!wcscmp(argv[1], L"fault-policy") ||
        !wcscmp(argv[1], L"fault-monitor")) {
        wchar_t cwd[MAX_PATH], marker[32], image[MAX_PATH];
        if (!GetCurrentDirectoryW(MAX_PATH, cwd) ||
            _wcsicmp(cwd, L"C:\\P0Lab") ||
            !GetEnvironmentVariableW(L"PROXY_HARBOR_P0_GUEST", marker, 32) ||
            wcscmp(marker, L"offline-lab") ||
            !GetModuleFileNameW(NULL, image, MAX_PATH) ||
            _wcsicmp(image,
                     L"C:\\P0Lab\\.local\\p0\\bin\\proxy-harbor-guardian.exe"))
            return 2;
        HANDLE e = NULL;
        DWORD error = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, NULL, &e);
        if (!error && !wcscmp(argv[1], L"fault-monitor")) {
            FWP_VALUE0 off = {0};
            off.type = FWP_UINT32;
            error =
                FwpmEngineSetOption0(e, FWPM_ENGINE_COLLECT_NET_EVENTS, &off);
        } else if (!error) {
            GUID key = key_for(0, 5);
            FWPM_FILTER0 *f = NULL;
            error = FwpmFilterGetByKey0(e, &key, &f);
            if (!error &&
                (!IsEqualGUID(&f->subLayerKey, &session_id) ||
                 !f->displayData.name || wcscmp(f->displayData.name, owner) ||
                 f->providerData.size != sizeof(session_id) ||
                 !f->providerData.data ||
                 memcmp(f->providerData.data, &session_id, sizeof(session_id))))
                error = ERROR_INVALID_OWNER;
            if (f)
                FwpmFreeMemory0((void **)&f);
            if (!error)
                error = FwpmFilterDeleteByKey0(e, &key);
        }
        if (e)
            FwpmEngineClose0(e);
        return error ? 1 : 0;
    }
    if (!wcscmp(argv[1], L"inspect")) {
        HANDLE read_engine = NULL;
        DWORD e =
            FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, NULL, &read_engine);
        unsigned count = 0;
        if (!e)
            for (unsigned i = 0; i < image_count; ++i)
                for (unsigned r = 0; r < 8; ++r) {
                    GUID key = key_for(i, r);
                    FWPM_FILTER0 *f = NULL;
                    DWORD found = FwpmFilterGetByKey0(read_engine, &key, &f);
                    if (!found) {
                        ++count;
                        FwpmFreeMemory0((void **)&f);
                    } else if (found != FWP_E_FILTER_NOT_FOUND)
                        e = found;
                }
        for (unsigned i = 0; !e && user_identity && i < 8; ++i) {
            GUID key = key_for(MAX_IMAGES, i);
            FWPM_FILTER0 *f = NULL;
            DWORD found = FwpmFilterGetByKey0(read_engine, &key, &f);
            if (!found) {
                ++count;
                FwpmFreeMemory0((void **)&f);
            } else if (found != FWP_E_FILTER_NOT_FOUND)
                e = found;
        }
        if (!e && system_dns_enabled) {
            SYSTEM_DNS_GUARD dns = {0};
            e = SystemDNSOpen(&dns, read_engine, &session_id, TRUE);
            count += dns.count;
            SystemDNSClose(&dns);
        }
        if (read_engine)
            FwpmEngineClose0(read_engine);
        printf("{\"windowsError\":%lu,\"rulesPresent\":%u,\"systemChanged\":"
               "false}\n",
               e, count);
        return e ? 1 : 0;
    }
    BOOL recover = !wcscmp(argv[1], L"recover");
    const char *reason = "preflight_failed";
    BOOL running = FALSE, clean = FALSE;
    if (!acquire_lock(recover))
        return 4;
    HANDLE mutex =
        CreateMutexW(NULL, FALSE, L"Global\\ProxyHarborManagedSessionV1");
    DWORD waited = mutex ? WaitForSingleObject(mutex, 0) : WAIT_FAILED;
    if (waited != WAIT_OBJECT_0 && waited != WAIT_ABANDONED) {
        if (!recover) {
            error_code = ERROR_BUSY;
            status("failed", "another_session_active");
            wchar_t path[1200];
            path_for(path, 1200, L"owner.lock");
            CloseHandle(lock_file);
            DeleteFileW(path);
        } else
            CloseHandle(lock_file);
        if (mutex)
            CloseHandle(mutex);
        return 4;
    }
    status("preparing", "checking_proxy");
    error_code = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, NULL, &engine);
    if (error_code)
        goto finish;
    if (system_dns_enabled) {
        error_code = SystemDNSOpen(&dns_guard, engine, &session_id, TRUE);
        if (error_code)
            goto finish;
    }
    for (unsigned i = 0; !user_identity && i < image_count; ++i) {
        error_code = FwpmGetAppIdFromFileName0(images[i], &app_ids[i]);
        if (error_code)
            goto finish;
    }
    if (recover) {
        for (unsigned i = 0; i < image_count; ++i)
            for (unsigned r = 0; r < 8; ++r) {
                GUID key = key_for(i, r);
                FWPM_FILTER0 *f = NULL;
                DWORD found = FwpmFilterGetByKey0(engine, &key, &f);
                if (!found) {
                    ++installed;
                    FwpmFreeMemory0((void **)&f);
                } else if (found != FWP_E_FILTER_NOT_FOUND) {
                    error_code = found;
                    goto finish;
                }
            }
        for (unsigned i = 0; user_identity && i < 8; ++i) {
            GUID key = key_for(MAX_IMAGES, i);
            FWPM_FILTER0 *f = NULL;
            DWORD found = FwpmFilterGetByKey0(engine, &key, &f);
            if (!found) {
                ++installed;
                FwpmFreeMemory0((void **)&f);
            } else if (found != FWP_E_FILTER_NOT_FOUND) {
                error_code = found;
                goto finish;
            }
        }
    }
    if (user_identity && recover) {
        // An interrupted start can have no identities yet. Only accept missing
        // records once their policy namespace and unjournaled user are absent.
        FWPM_SUBLAYER0 *layer = NULL;
        DWORD found = FwpmSubLayerGetByKey0(engine, &session_id, &layer);
        if (layer)
            FwpmFreeMemory0((void **)&layer);
        if (found && found != FWP_E_SUBLAYER_NOT_FOUND) {
            error_code = found;
            goto finish;
        }
        BOOL empty = !installed && found == FWP_E_SUBLAYER_NOT_FOUND;
        error_code = proxy_identity(TRUE);
        if (empty && error_code == ERROR_FILE_NOT_FOUND)
            error_code = 0;
        if (!error_code) {
            error_code = account_policy(TRUE);
            if (empty && error_code == ERROR_FILE_NOT_FOUND && !current_user)
                error_code =
                    SessionAccountConfirmAbsent(&session_id, directory);
            if (empty && error_code == ERROR_FILE_NOT_FOUND && current_user)
                error_code = 0;
        }
        if (error_code)
            goto finish;
    }
    if ((!current_user || recover) && (!current_user || (app_ids[0] || installed)) && any_existing()) {
        error_code = ERROR_BUSY;
        reason = "application_already_running";
        goto finish;
    }
    if (recover) {
        reason = "recovered";
        error_code = load_events_previous();
#ifdef PH_CLAUDE_MSIX
        if (!error_code && claude_msix && account.created) {
            error_code = recover_claude_registration();
            if (error_code)
                reason = "package_cleanup_pending";
        }
#endif
        if (!error_code && user_identity && !current_user)
            error_code = SessionAccountRetire(&account);
        if (!error_code && system_dns_enabled)
            error_code = SystemDNSRemove(&dns_guard);
        if (!error_code)
            error_code = remove_owned();
        if (!error_code && user_identity && !current_user)
            error_code = SessionAccountForget(&account);
        clean = error_code == 0;
        goto finish;
    }
    if (!parent_valid()) {
        error_code = ERROR_INVALID_OWNER;
        reason = "parent_identity_changed";
        goto finish;
    }
    if (!tun_ok(TRUE)) {
        error_code = ERROR_NETWORK_UNREACHABLE;
        reason = "tun_not_ready";
        goto finish;
    }
    DWORD proxy_pid = listener_pid();
    proxy_process = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION,
                                FALSE, proxy_pid);
    if (!proxy_process) {
        error_code = GetLastError();
        reason = "proxy_unavailable";
        goto finish;
    }
    if (expected_proxy_pid &&
        (proxy_pid != expected_proxy_pid ||
         creation(proxy_process) != expected_proxy_created)) {
        error_code = ERROR_INVALID_OWNER;
        reason = "proxy_owner_changed";
        goto finish;
    }
    if (user_identity) {
        error_code = proxy_identity(FALSE);
        if (error_code)
            goto finish;
    }
    if (!lab && !user_identity) {
        tun_process = named_process(L"sing-box.exe");
        if (!tun_process) {
            error_code = ERROR_INVALID_OWNER;
            reason = "tun_process_unconfirmed";
            goto finish;
        }
    }
    if (!exit_ok(TRUE)) {
        error_code = network_error ? network_error : ERROR_NETWORK_UNREACHABLE;
        reason = exit_fault == EXIT_MISMATCH ? "exit_mismatch_before_launch" : "exit_not_verified";
        goto finish;
    }
    if (user_identity) {
        error_code = account_policy(FALSE);
        if (!error_code && !lab && !desktop_client)
            error_code = SessionAccountBrowserPolicy(&account, proxy_port);
        if (error_code)
            goto finish;
    }
    error_code = install(FALSE);
    if (error_code)
        goto finish;
    if (system_dns_enabled) {
        error_code = SystemDNSInstall(&dns_guard);
        if (!error_code)
            error_code = start_dns_watch();
        if (error_code) {
            reason = "dns_guard_failed";
            goto finish;
        }
    }
    error_code = current_user ? ERROR_SUCCESS : events_begin();
    if (error_code)
        goto finish;
    if (!current_user) {
        job = CreateJobObjectW(NULL, NULL);
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits = {0};
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        if (!job || !SetInformationJobObject(job, JobObjectExtendedLimitInformation,
                                             &limits, sizeof(limits))) {
            error_code = GetLastError();
            goto finish;
        }
    }
    stop_checks = CreateEventW(NULL, TRUE, FALSE, NULL);
    exit_alarm = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!stop_checks || !exit_alarm) {
        error_code = ERROR_NO_SYSTEM_RESOURCES;
        goto finish;
    }
    exit_thread = CreateThread(NULL, 0, check_exits, NULL, 0, NULL);
    if (!exit_thread) {
        error_code = GetLastError();
        goto finish;
    }
#ifdef PH_CLAUDE_TAKEOVER
    if (current_user) {
        reason = "takeover_launch_failed";
        error_code = ClaudeTakeoverPrepare(&takeover, directory);
        if (!error_code && (!verify_filters() || stop_requested() || exit_stop_reason() || !tun_ok(FALSE) ||
                            WaitForSingleObject(proxy_process, 0) != WAIT_TIMEOUT ||
                            WaitForSingleObject(parent, 0) != WAIT_TIMEOUT || listener_pid() != proxy_pid)) {
            error_code = ERROR_INVALID_STATE;
        }
        if (!error_code) {
            BOOL active;
            reason = "takeover_restart_failed";
            status("preparing", "taking_over");
            error_code = ClaudeTakeoverFind(&takeover, TRUE, &active);
            if (!error_code && (any_existing() || stop_requested() || exit_stop_reason() || !verify_filters()))
                error_code = ERROR_BUSY;
        }
        if (!error_code) {
            reason = "takeover_launch_failed";
            error_code = events_begin();
        }
        if (!error_code)
            error_code = ClaudeTakeoverResume(&takeover);
        if (!error_code)
            child_pid = takeover.root_pid;
    } else
#endif
        error_code = launch();
    if (error_code) {
        const char *fault = exit_stop_reason();
        if (fault)
            reason = fault;
        goto finish;
    }
    running = TRUE;
    reason = "application_exited";
    ULONGLONG next_verify = 0;
    status("monitoring", "proxy_only");
    while (active_processes()) {
        const char *fault = exit_stop_reason();
        if (fault) {
            reason = fault;
            break;
        }
        if (stop_requested()) {
            reason = "user_stopped";
            break;
        }
        if (WaitForSingleObject(parent, 0) != WAIT_TIMEOUT) {
            reason = "desktop_exited";
            break;
        }
        if (system_dns_enabled &&
            (!dns_watch || WaitForSingleObject(dns_watch, 0) != WAIT_TIMEOUT ||
             SystemDNSVerify(&dns_guard))) {
            reason = "dns_guard_failed";
            break;
        }
        if (WaitForSingleObject(proxy_process, 0) != WAIT_TIMEOUT ||
            listener_pid() != proxy_pid) {
            reason = "proxy_unavailable";
            break;
        }
        if (tun_process &&
            WaitForSingleObject(tun_process, 0) != WAIT_TIMEOUT) {
            reason = "tun_process_exited";
            break;
        }
        if (!tun_ok(FALSE)) {
            reason = "tun_route_changed";
            break;
        }
        DWORD component_error = check_components();
        if (component_error) {
            reason = component_error == ERROR_INVALID_OWNER
                         ? "unlisted_component" : "component_check_failed";
            break;
        }
        int event = blocked_event();
        if (event) {
            reason = event > 0 ? "bypass_blocked" : "monitor_unavailable";
            break;
        }
        if (user_identity && !current_user) {
            DWORD audit = SessionCheckTCPPath(job, proxy_port, &unexpected_peer);
            if (audit) {
                reason = unexpected_peer.pid ? "unexpected_tcp_peer" : "tcp_audit_unavailable";
                break;
            }
        }
        ULONGLONG now = GetTickCount64();
        if (now >= next_verify) {
            if (user_identity && !lab && !desktop_client &&
                !SessionAccountBrowserPolicyValid(&account, proxy_port)) {
                reason = "browser_policy_changed";
                break;
            }
            if (!verify_filters()) {
                reason = "policy_changed";
                break;
            }
            next_verify = now + 1000;
            status("monitoring", "proxy_only");
        }
        if (WaitForSingleObject(exit_alarm, 200) == WAIT_FAILED) {
            reason = "monitor_unavailable";
            break;
        }
    }
finish:
#ifdef PH_CLAUDE_TAKEOVER
    if (current_user && !running && !recover && error_code) {
        char report[224];
        sprintf_s(report, sizeof(report), "{\"reason\":\"%s\",\"error\":%lu,\"workerError\":%lu,\"stage\":\"%s\"}\n",
                  reason, error_code, takeover.launcher ? ClaudeTakeoverHealth(&takeover) : 0,
                  takeover.prepare_stage ? takeover.prepare_stage : "");
        write_file(L"takeover-start-error.json", report);
    }
    if (current_user && running && !strcmp(reason, "application_exited") &&
        ClaudeTakeoverHealth(&takeover) == ERROR_INVALID_OWNER)
        reason = "unlisted_component";
    if (current_user && takeover.launcher) {
        if (running && installed && !emergency) {
            DWORD e = install(TRUE);
            if (e && !error_code)
                error_code = e;
            status("blocking", reason);
        }
        ClaudeTakeoverRelease(&takeover);
    }
#endif
    if (job && active_processes()) {
        if (engine && installed && !emergency) {
            DWORD e = install(TRUE);
            if (e && !error_code)
                error_code = e;
        }
        BOOL killed = TerminateJobObject(job, 1);
        status("blocking", reason);
        for (int i = 0; killed && i < 50 && active_processes(); ++i)
            Sleep(100);
        if (!killed || active_processes()) {
            error_code = ERROR_BUSY;
            status("cleanup_required", "termination_not_confirmed");
            goto release;
        }
    }
    if (user_identity && !recover && account.created && job) {
        if (installed && !emergency && SessionAccountAlive(&account)) {
            DWORD e = install(TRUE);
            if (e) {
                error_code = e;
                status("cleanup_required", "blocking_not_confirmed");
                goto release;
            }
            status("blocking", reason);
        }
        DWORD e = SessionAccountTerminate(&account);
        if (e) {
            error_code = e;
            status("cleanup_required", "sid_termination_pending");
            goto release;
        }
#ifdef PH_CLAUDE_MSIX
        if (claude_msix) {
            char report[128];
            sprintf_s(report, sizeof(report), "{\"reason\":\"%s\",\"error\":%lu}\n", reason, error_code);
            write_file(L"claude-stop.json", report);
            fputs(report, stdout);
            fflush(stdout);
            e = unregister_claude();
            if (e) {
                error_code = e;
                status("cleanup_required", "package_cleanup_pending");
                goto release;
            }
            // Removing the package logs the temporary account on again.
            // Recheck its full process set before retiring the profile.
            e = SessionAccountTerminate(&account);
            if (e) {
                error_code = e;
                status("cleanup_required", "sid_termination_pending");
                goto release;
            }
        }
#endif
        e = SessionAccountRetire(&account);
        if (e) {
            error_code = e;
            status("cleanup_required", "identity_cleanup_pending");
            goto release;
        }
    }
    if (system_dns_enabled && !recover && dns_guard.count) {
#ifdef PH_CLAUDE_TAKEOVER
        if (current_user && app_ids[0]) {
            takeover.root_pid = 0;
            if (any_existing()) {
                error_code = ERROR_BUSY;
                status("cleanup_required", "takeover_application_still_running");
                goto release;
            }
        }
#endif
        if (user_identity && account.created && SessionAccountAlive(&account)) {
            error_code = ERROR_BUSY;
            status("cleanup_required", "dns_restore_pending");
            goto release;
        }
        DWORD e = stop_dns_watch();
        if (e) {
            error_code = e;
            status("cleanup_required", "dns_restore_pending");
            goto release;
        }
    }
    if (engine && installed && !recover) {
        DWORD e = remove_owned();
        if (e)
            error_code = e;
        else
            clean = TRUE;
    }
    if (user_identity && !recover && !installed && account.record_lock) {
        DWORD e = SessionAccountDelete(&account);
        if (e) {
            error_code = e;
            clean = FALSE;
        }
    }
    if (events_saved && (!recover || !error_code)) {
        if (!events_restore()) {
            error_code = ERROR_WRITE_FAULT;
            clean = FALSE;
            diagnostics_pending = TRUE;
        } else if (!installed) {
            wchar_t path[1200];
            path_for(path, 1200, L"events.previous");
            if (!DeleteFileW(path) && GetLastError() != ERROR_FILE_NOT_FOUND) {
                error_code = GetLastError();
                diagnostics_pending = TRUE;
            }
        }
    }
    if (proxy_record && !installed && (!recover || !error_code) &&
        (!account.created || clean)) {
        FILE_DISPOSITION_INFO disposition = {TRUE};
        if (!SetFileInformationByHandle(proxy_record, FileDispositionInfo,
                                        &disposition, sizeof(disposition))) {
            error_code = GetLastError();
            diagnostics_pending = TRUE;
        }
    }
#ifdef PH_CLAUDE_TAKEOVER
    if (current_user && !installed && !dns_guard.count && (!recover || !error_code)) {
        ClaudeTakeoverRelease(&takeover);
        wchar_t record[1200];
        path_for(record, ARRAYSIZE(record), L"takeover.bin");
        if (!DeleteFileW(record) && GetLastError() != ERROR_FILE_NOT_FOUND) {
            error_code = GetLastError();
            diagnostics_pending = TRUE;
        }
    }
#endif
    if (installed || dns_guard.count || diagnostics_pending || (!clean && running) ||
        (recover && error_code) || account.created)
        status("cleanup_required", reason);
    else
        status(error_code ? "failed" : "stopped", reason);
release:
#ifdef PH_CLAUDE_TAKEOVER
    if (current_user)
        ClaudeTakeoverRelease(&takeover);
#endif
    if (stop_checks)
        SetEvent(stop_checks);
    if (exit_thread) {
        WaitForSingleObject(exit_thread, INFINITE);
        CloseHandle(exit_thread);
    }
    if (exit_alarm)
        CloseHandle(exit_alarm);
    if (stop_checks)
        CloseHandle(stop_checks);
    if (job)
        CloseHandle(job);
    if (proxy_process)
        CloseHandle(proxy_process);
    if (tun_process)
        CloseHandle(tun_process);
    if (parent)
        CloseHandle(parent);
    if (dns_watch)
        CloseHandle(dns_watch);
    SystemDNSClose(&dns_guard);
    for (unsigned i = 0; i < image_count; ++i)
        if (app_ids[i] && !current_user)
            FwpmFreeMemory0((void **)&app_ids[i]);
    if (engine)
        FwpmEngineClose0(engine);
    if (proxy_record)
        CloseHandle(proxy_record);
    if (proxy_app)
        FwpmFreeMemory0((void **)&proxy_app);
    if (proxy_descriptor)
        LocalFree(proxy_descriptor);
    SessionAccountRelease(&account);
    if (account_descriptor)
        LocalFree(account_descriptor);
    if (lock_file && lock_file != INVALID_HANDLE_VALUE) {
        CloseHandle(lock_file);
        if (!installed) {
            wchar_t p[1200];
            path_for(p, 1200, L"owner.lock");
            DeleteFileW(p);
        }
    }
    if (mutex) {
        ReleaseMutex(mutex);
        CloseHandle(mutex);
    }
    return error_code ? 1 : 0;
}
