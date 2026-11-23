#define _WIN32_WINNT 0x0A00
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include "tcp_path.h"

static DWORD job_query_retries;

static HANDLE retry_restricted_job_query(DWORD pid, DWORD access, DWORD *error) {
    // The guardian is already elevated. Enable its existing debug privilege
    // on this thread only, solely for the read-only process handle request.
    if (!ImpersonateSelf(SecurityImpersonation)) {
        *error = GetLastError();
        return NULL;
    }
    HANDLE process = NULL, token = NULL;
    TOKEN_PRIVILEGES privileges = {0};
    privileges.PrivilegeCount = 1;
    privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (LookupPrivilegeValueW(NULL, SE_DEBUG_NAME, &privileges.Privileges[0].Luid) &&
        OpenThreadToken(GetCurrentThread(), TOKEN_ADJUST_PRIVILEGES, TRUE, &token) &&
        AdjustTokenPrivileges(token, FALSE, &privileges, 0, NULL, NULL) &&
        GetLastError() == ERROR_SUCCESS) {
        process = OpenProcess(access, FALSE, pid);
        *error = process ? ERROR_SUCCESS : GetLastError();
    } else {
        *error = GetLastError();
    }
    if (token)
        CloseHandle(token);
    if (!RevertToSelf())
        ExitProcess(GetLastError()); // The Job closes and persistent rules remain recoverable.
    return process;
}

DWORD SessionOpenJobProcess(HANDLE job, DWORD pid, HANDLE *process) {
    const DWORD access = SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION;
    *process = NULL;
    HANDLE candidate = OpenProcess(access, FALSE, pid);
    DWORD error = candidate ? ERROR_SUCCESS : GetLastError();
    BOOL retried = error == ERROR_ACCESS_DENIED;
    if (retried)
        candidate = retry_restricted_job_query(pid, access, &error);
    if (!candidate)
        return error == ERROR_INVALID_PARAMETER ? ERROR_SUCCESS : error;

    BOOL belongs = FALSE;
    if (!IsProcessInJob(candidate, job, &belongs))
        error = GetLastError();
    if (!belongs) {
        if (WaitForSingleObject(candidate, 0) == WAIT_OBJECT_0)
            error = ERROR_SUCCESS;
        CloseHandle(candidate);
        return error;
    }
    if (retried)
        ++job_query_retries;
    *process = candidate;
    return ERROR_SUCCESS;
}

DWORD SessionJobQueryRetries(void) {
    return job_query_retries;
}

typedef struct {
    DWORD pid;
    HANDLE process;
} MEMBER;

static DWORD check_peer(MEMBER *members, DWORD count, DWORD pid, DWORD state,
                        unsigned family, unsigned port, SESSION_TCP_PEER *peer) {
    if (!pid || state == MIB_TCP_STATE_LISTEN || state == MIB_TCP_STATE_CLOSED ||
        state == MIB_TCP_STATE_TIME_WAIT || state == MIB_TCP_STATE_DELETE_TCB)
        return ERROR_SUCCESS;
    for (DWORD i = 0; i < count; ++i) {
        if (members[i].pid != pid)
            continue;
        DWORD wait = WaitForSingleObject(members[i].process, 0);
        if (wait == WAIT_OBJECT_0)
            return ERROR_SUCCESS;
        if (wait != WAIT_TIMEOUT)
            return ERROR_INVALID_HANDLE;
        peer->pid = pid;
        peer->family = family;
        peer->remote_port = port;
        return ERROR_ACCESS_DISABLED_BY_POLICY;
    }
    return ERROR_SUCCESS;
}

static DWORD check_family(MEMBER *members, DWORD count, unsigned family,
                          unsigned proxy_port, SESSION_TCP_PEER *peer) {
    DWORD size = 0;
    void *table = NULL;
    DWORD error = GetExtendedTcpTable(NULL, &size, FALSE, family,
                                      TCP_TABLE_OWNER_PID_CONNECTIONS, 0);
    for (unsigned attempt = 0; error == ERROR_INSUFFICIENT_BUFFER && attempt < 4; ++attempt) {
        if (table)
            HeapFree(GetProcessHeap(), 0, table);
        table = HeapAlloc(GetProcessHeap(), 0, size);
        if (!table)
            return ERROR_OUTOFMEMORY;
        error = GetExtendedTcpTable(table, &size, FALSE, family,
                                    TCP_TABLE_OWNER_PID_CONNECTIONS, 0);
    }
    if (error == ERROR_SUCCESS && table) {
        if (family == AF_INET) {
            MIB_TCPTABLE_OWNER_PID *v4 = table;
            for (DWORD i = 0; !error && i < v4->dwNumEntries; ++i) {
                MIB_TCPROW_OWNER_PID *row = &v4->table[i];
                unsigned port = ntohs((u_short)row->dwRemotePort);
                if (row->dwRemoteAddr != htonl(INADDR_LOOPBACK) || port != proxy_port)
                    error = check_peer(members, count, row->dwOwningPid, row->dwState,
                                       family, port, peer);
            }
        } else {
            MIB_TCP6TABLE_OWNER_PID *v6 = table;
            for (DWORD i = 0; !error && i < v6->dwNumEntries; ++i) {
                MIB_TCP6ROW_OWNER_PID *row = &v6->table[i];
                error = check_peer(members, count, row->dwOwningPid, row->dwState,
                                   family, ntohs((u_short)row->dwRemotePort), peer);
            }
        }
    } else if (!error) {
        error = ERROR_INVALID_DATA;
    }
    if (table)
        HeapFree(GetProcessHeap(), 0, table);
    return error;
}

DWORD SessionCheckTCPPath(HANDLE job, unsigned proxy_port, SESSION_TCP_PEER *peer) {
    ULONG_PTR storage[258];
    JOBOBJECT_BASIC_PROCESS_ID_LIST *list = (void *)storage;
    MEMBER members[256];
    DWORD count = 0;
    ZeroMemory(peer, sizeof(*peer));
    if (!QueryInformationJobObject(job, JobObjectBasicProcessIdList, list,
                                   sizeof(storage), NULL))
        return GetLastError();
    if (list->NumberOfAssignedProcesses != list->NumberOfProcessIdsInList ||
        list->NumberOfProcessIdsInList > ARRAYSIZE(members))
        return ERROR_MORE_DATA;
    DWORD error = ERROR_SUCCESS;
    for (DWORD i = 0; i < list->NumberOfProcessIdsInList; ++i) {
        DWORD pid = (DWORD)list->ProcessIdList[i];
        HANDLE process;
        error = SessionOpenJobProcess(job, pid, &process);
        if (error)
            break;
        if (!process)
            continue;
        members[count].pid = pid;
        members[count++].process = process;
    }
    if (!error && count)
        error = check_family(members, count, AF_INET, proxy_port, peer);
    if (!error && count)
        error = check_family(members, count, AF_INET6, proxy_port, peer);
    for (DWORD i = 0; i < count; ++i)
        CloseHandle(members[i].process);
    return error;
}
