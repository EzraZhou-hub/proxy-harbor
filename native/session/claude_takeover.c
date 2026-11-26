#define _WIN32_WINNT 0x0A00
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include "claude_takeover.h"
#include "claude_msix.h"
#include <sddl.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <userenv.h>
#include <wchar.h>

static DWORD process_user(HANDLE process, BYTE sid[SECURITY_MAX_SID_SIZE]) {
    HANDLE token;
    BYTE buffer[256];
    DWORD size;
    if (!OpenProcessToken(process, TOKEN_QUERY, &token))
        return GetLastError();
    BOOL valid = GetTokenInformation(token, TokenUser, buffer, sizeof(buffer), &size) &&
                 CopySid(SECURITY_MAX_SID_SIZE, sid, ((TOKEN_USER *)buffer)->User.Sid);
    DWORD error = valid ? ERROR_SUCCESS : GetLastError();
    CloseHandle(token);
    return error;
}

static DWORD set_identity(CLAUDE_TAKEOVER *state) {
    CLAUDE_TAKEOVER_IDENTITY *record = &state->identity;
    size_t length = wcsnlen(record->image, ARRAYSIZE(record->image));
    if (record->version != 1 || !IsValidSid(record->sid) || !length ||
        length == ARRAYSIZE(record->image) || _wcsnicmp(record->image, L"\\Device\\", 8))
        return ERROR_INVALID_DATA;
    state->app_id.data = (BYTE *)record->image;
    state->app_id.size = (UINT32)((length + 1) * sizeof(wchar_t));
    return ERROR_SUCCESS;
}

DWORD ClaudeTakeoverBind(CLAUDE_TAKEOVER *state, const wchar_t *record, const wchar_t *image,
                         const wchar_t *package, HANDLE parent) {
    DWORD error = process_user(parent, state->identity.sid);
    if (error)
        return error;
    if (!ProcessIdToSessionId(GetProcessId(parent), &state->session))
        return GetLastError();
    state->parent = parent;
    state->image = image;
    state->package = package;
    HANDLE file = CreateFileW(image, FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE,
                              NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE)
        return GetLastError();
    wchar_t physical[1024];
    DWORD length = GetFinalPathNameByHandleW(file, physical, ARRAYSIZE(physical), VOLUME_NAME_DOS);
    CloseHandle(file);
    if (!length || length >= ARRAYSIZE(physical) || wcsncmp(physical, L"\\\\?\\", 4))
        return ERROR_INVALID_NAME;
    FWP_BYTE_BLOB *id = NULL;
    error = FwpmGetAppIdFromFileName0(physical + 4, &id);
    if (error)
        return error;
    if (!id || !id->data || id->size < sizeof(wchar_t) || id->size > sizeof(state->identity.image) ||
        id->size % sizeof(wchar_t) || ((wchar_t *)id->data)[id->size / sizeof(wchar_t) - 1])
        error = ERROR_INVALID_DATA;
    if (!error)
        memcpy(state->identity.image, id->data, id->size);
    FwpmFreeMemory0((void **)&id);
    state->identity.version = 1;
    if (!error)
        error = set_identity(state);
    if (error)
        return error;
    state->journal = CreateFileW(record, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_NEW,
                                  FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    if (state->journal == INVALID_HANDLE_VALUE)
        return GetLastError();
    DWORD written;
    if (!WriteFile(state->journal, &state->identity, sizeof(state->identity), &written, NULL) ||
        written != sizeof(state->identity) || !FlushFileBuffers(state->journal))
        return ERROR_WRITE_FAULT;
    return ERROR_SUCCESS;
}

DWORD ClaudeTakeoverRead(CLAUDE_TAKEOVER *state, const wchar_t *record) {
    HANDLE file = CreateFileW(record, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                              OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    if (file == INVALID_HANDLE_VALUE)
        return GetLastError();
    BY_HANDLE_FILE_INFORMATION info;
    DWORD read;
    BOOL valid = GetFileInformationByHandle(file, &info) &&
                 !(info.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY)) &&
                 info.nNumberOfLinks == 1 && !info.nFileSizeHigh && info.nFileSizeLow == sizeof(state->identity) &&
                 ReadFile(file, &state->identity, sizeof(state->identity), &read, NULL) &&
                 read == sizeof(state->identity);
    if (!valid) {
        CloseHandle(file);
        return ERROR_INVALID_DATA;
    }
    state->journal = file;
    return set_identity(state);
}

static BOOL covered_image(CLAUDE_TAKEOVER *state, HANDLE process) {
    wchar_t path[1024];
    DWORD length = ARRAYSIZE(path);
    return QueryFullProcessImageNameW(process, PROCESS_NAME_NATIVE, path, &length) &&
           !_wcsicmp(path, state->identity.image);
}

static BOOL CALLBACK close_window(HWND window, LPARAM target) {
    DWORD pid;
    GetWindowThreadProcessId(window, &pid);
    if (pid == (DWORD_PTR)target)
        PostMessageW(window, WM_CLOSE, 0, 0);
    return TRUE;
}

DWORD ClaudeTakeoverFind(CLAUDE_TAKEOVER *state, BOOL restart, BOOL *active) {
    *active = FALSE;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE)
        return GetLastError();
    HANDLE targets[128];
    DWORD count = 0;
    PROCESSENTRY32W entry = {0};
    entry.dwSize = sizeof(entry);
    BOOL more = Process32FirstW(snapshot, &entry);
    DWORD error = more ? ERROR_SUCCESS : GetLastError();
    for (; more && !error; more = Process32NextW(snapshot, &entry)) {
        DWORD pid = entry.th32ProcessID;
        if (pid == state->root_pid || _wcsicmp(entry.szExeFile, L"Claude.exe"))
            continue;
        HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE |
                                         (restart ? PROCESS_TERMINATE : 0), FALSE, pid);
        if (!process) {
            if (GetLastError() != ERROR_INVALID_PARAMETER)
                error = GetLastError();
            continue;
        }
        BYTE sid[SECURITY_MAX_SID_SIZE];
        if (WaitForSingleObject(process, 0) == WAIT_TIMEOUT) {
            error = process_user(process, sid);
            if (!error && EqualSid(sid, state->identity.sid)) {
                BOOL covered = covered_image(state, process);
                wchar_t name[PACKAGE_FULL_NAME_MAX_LENGTH + 1], family[PACKAGE_FAMILY_NAME_MAX_LENGTH + 1];
                UINT32 length = ARRAYSIZE(name), family_length = ARRAYSIZE(family);
                BOOL claude = GetPackageFullName(process, &length, name) == ERROR_SUCCESS &&
                              PackageFamilyNameFromFullName(name, &family_length, family) == ERROR_SUCCESS &&
                              !_wcsicmp(family, L"Claude_pzs8sxrjxfjjc");
                if (covered || claude) {
                    *active = TRUE;
                    DWORD session;
                    if (restart && (!covered || !claude || !ProcessIdToSessionId(pid, &session) ||
                                    session != state->session || count == ARRAYSIZE(targets)))
                        error = ERROR_BUSY;
                    else if (restart) {
                        targets[count++] = process;
                        process = NULL;
                    }
                }
            }
        }
        if (process)
            CloseHandle(process);
    }
    if (!error && GetLastError() != ERROR_NO_MORE_FILES)
        error = GetLastError();
    CloseHandle(snapshot);
    if (!error && count) {
        for (DWORD i = 0; i < count; ++i)
            EnumWindows(close_window, GetProcessId(targets[i]));
        WaitForSingleObject(targets[0], 2000);
        for (DWORD i = 0; i < count; ++i)
            if (WaitForSingleObject(targets[i], 0) != WAIT_OBJECT_0 &&
                !TerminateProcess(targets[i], 1) && WaitForSingleObject(targets[i], 0) != WAIT_OBJECT_0)
                error = GetLastError();
        for (DWORD i = 0; i < count; ++i)
            if (WaitForSingleObject(targets[i], 2000) != WAIT_OBJECT_0)
                error = ERROR_BUSY;
    }
    for (DWORD i = 0; i < count; ++i)
        CloseHandle(targets[i]);
    return error;
}

static ULONGLONG process_birth(HANDLE process) {
    FILETIME born, exited, kernel, user;
    if (!GetProcessTimes(process, &born, &exited, &kernel, &user))
        return 0;
    return ((ULONGLONG)born.dwHighDateTime << 32) | born.dwLowDateTime;
}

BOOL ClaudeTakeoverCovered(CLAUDE_TAKEOVER *state, HANDLE process) {
    return covered_image(state, process) &&
           ClaudeMSIXMatches(process, state->image, state->package, state->identity.sid);
}

typedef struct {
    DWORD pid, thread;
    ULONGLONG created;
} TAKEOVER_PROCESS;

enum pipe_operation { PIPE_CONNECT, PIPE_READ, PIPE_WRITE };

static DWORD pipe_operation(CLAUDE_TAKEOVER *state, enum pipe_operation operation, void *buffer, DWORD size) {
    OVERLAPPED io = {0};
    io.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!io.hEvent)
        return GetLastError();
    DWORD transferred = 0;
    BOOL done;
    if (operation == PIPE_CONNECT)
        done = ConnectNamedPipe(state->pipe, &io);
    else if (operation == PIPE_READ)
        done = ReadFile(state->pipe, buffer, size, &transferred, &io);
    else
        done = WriteFile(state->pipe, buffer, size, &transferred, &io);
    DWORD error = done ? ERROR_SUCCESS : GetLastError();
    if (operation == PIPE_CONNECT && error == ERROR_PIPE_CONNECTED)
        error = ERROR_SUCCESS;
    if (error == ERROR_IO_PENDING) {
        HANDLE waits[] = {io.hEvent, state->launcher};
        DWORD wait = WaitForMultipleObjects(ARRAYSIZE(waits), waits, FALSE, 12000);
        if (wait == WAIT_OBJECT_0) {
            error = GetOverlappedResult(state->pipe, &io, &transferred, FALSE) ? ERROR_SUCCESS : GetLastError();
        } else {
            CancelIoEx(state->pipe, &io);
            GetOverlappedResult(state->pipe, &io, &transferred, TRUE);
            error = wait == WAIT_TIMEOUT ? ERROR_TIMEOUT : ERROR_PROCESS_ABORTED;
        }
    }
    CloseHandle(io.hEvent);
    if (!error && operation != PIPE_CONNECT && transferred != size)
        error = ERROR_INVALID_DATA;
    return error;
}

static BOOL pipe_name(const wchar_t *folder, wchar_t name[128]) {
    const wchar_t *leaf = wcsrchr(folder, L'\\');
    return leaf && swprintf_s(name, 128, L"\\\\.\\pipe\\ProxyHarborClaude-%ls", leaf + 1) > 0;
}

static DWORD bind_worker(CLAUDE_TAKEOVER *state, const wchar_t *folder) {
    wchar_t path[1200], actual[1024], executable[1024];
    if (swprintf_s(path, ARRAYSIZE(path), L"%ls\\takeover-worker.txt", folder) < 0)
        return ERROR_INVALID_NAME;
    HANDLE file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
                              FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    if (file == INVALID_HANDLE_VALUE)
        return GetLastError();
    BY_HANDLE_FILE_INFORMATION info;
    char text[96] = {0}, canonical[96];
    DWORD count, pid = 0;
    ULONGLONG born = 0;
    BOOL valid = GetFileInformationByHandle(file, &info) &&
                 !(info.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY)) &&
                 info.nNumberOfLinks == 1 && !info.nFileSizeHigh && info.nFileSizeLow < sizeof(text) &&
                 ReadFile(file, text, sizeof(text) - 1, &count, NULL) && count == info.nFileSizeLow &&
                 sscanf_s(text, "%lu %llu", &pid, &born) == 2 && pid && born &&
                 sprintf_s(canonical, sizeof(canonical), "%lu %llu\n", pid, born) == (int)count &&
                 !memcmp(text, canonical, count);
    CloseHandle(file);
    if (!valid)
        return ERROR_INVALID_DATA;
    HANDLE worker = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE | PROCESS_TERMINATE, FALSE, pid);
    if (!worker)
        return GetLastError();
    BYTE sid[SECURITY_MAX_SID_SIZE];
    DWORD length = ARRAYSIZE(actual);
    DWORD own_length = GetModuleFileNameW(NULL, executable, ARRAYSIZE(executable));
    valid = process_birth(worker) == born && WaitForSingleObject(worker, 0) == WAIT_TIMEOUT &&
            !process_user(worker, sid) && EqualSid(sid, state->identity.sid) &&
            own_length && own_length < ARRAYSIZE(executable) &&
            QueryFullProcessImageNameW(worker, 0, actual, &length) && !_wcsicmp(actual, executable);
    if (valid) {
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        PROCESSENTRY32W entry = {0};
        entry.dwSize = sizeof(entry);
        valid = FALSE;
        if (snapshot != INVALID_HANDLE_VALUE) {
            for (BOOL more = Process32FirstW(snapshot, &entry); more; more = Process32NextW(snapshot, &entry)) {
                if (entry.th32ProcessID == pid) {
                    valid = entry.th32ParentProcessID == GetProcessId(state->parent);
                    break;
                }
            }
            CloseHandle(snapshot);
        }
    }
    if (!valid) {
        CloseHandle(worker);
        return ERROR_INVALID_OWNER;
    }
    state->launcher = worker;
    return ERROR_SUCCESS;
}

DWORD ClaudeTakeoverPrepare(CLAUDE_TAKEOVER *state, const wchar_t *folder, unsigned proxy_port) {
    state->prepare_stage = "create_pipe";
    wchar_t name[128], sddl[300], *sid = NULL;
    if (!pipe_name(folder, name))
        return ERROR_INVALID_NAME;
    if (!ConvertSidToStringSidW(state->identity.sid, &sid))
        return GetLastError();
    int formatted = swprintf_s(sddl, ARRAYSIZE(sddl),
                               L"D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;%ls)S:(ML;;NW;;;ME)", sid);
    LocalFree(sid);
    PSECURITY_DESCRIPTOR descriptor = NULL;
    if (formatted < 0 || !ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, SDDL_REVISION_1, &descriptor, NULL))
        return ERROR_INVALID_SECURITY_DESCR;
    SECURITY_ATTRIBUTES access = {sizeof(access), descriptor, FALSE};
    state->pipe = CreateNamedPipeW(name, PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
                                    PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_REJECT_REMOTE_CLIENTS,
                                    1, 4096, 4096, 0, &access);
    DWORD error = state->pipe == INVALID_HANDLE_VALUE ? GetLastError() : ERROR_SUCCESS;
    LocalFree(descriptor);
    if (!error) {
        state->prepare_stage = "bind_worker";
        error = bind_worker(state, folder);
    }
    if (!error) {
        state->prepare_stage = "connect_worker";
        error = pipe_operation(state, PIPE_CONNECT, NULL, 0);
    }
    ULONG client;
    if (!error && (!GetNamedPipeClientProcessId(state->pipe, &client) || client != GetProcessId(state->launcher)))
        error = ERROR_INVALID_OWNER;
    if (!error) {
        state->prepare_stage = "bind_proxy_port";
        DWORD port = proxy_port;
        error = pipe_operation(state, PIPE_WRITE, &port, sizeof(port));
    }
    TAKEOVER_PROCESS message = {0};
    if (!error) {
        state->prepare_stage = "read_worker";
        error = pipe_operation(state, PIPE_READ, &message, sizeof(message));
    }
    if (error)
        return error;
    if (!message.pid || !message.thread || !message.created)
        return ERROR_INVALID_DATA;
    state->prepare_stage = "verify_root";
    HANDLE app = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE,
                             FALSE, message.pid);
    HANDLE thread = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, message.thread);
    if (!app || !thread || GetProcessIdOfThread(thread) != message.pid ||
        process_birth(app) != message.created || !ClaudeTakeoverCovered(state, app)) {
        error = ERROR_INVALID_OWNER;
    } else {
        state->root_pid = message.pid;
        state->root = app;
        app = NULL;
    }
    if (thread)
        CloseHandle(thread);
    if (app)
        CloseHandle(app);
    return error;
}

DWORD ClaudeTakeoverResume(CLAUDE_TAKEOVER *state) {
    BYTE go = 1, confirmed = 0;
    DWORD error = pipe_operation(state, PIPE_WRITE, &go, sizeof(go));
    if (!error)
        error = pipe_operation(state, PIPE_READ, &confirmed, sizeof(confirmed));
    return error ? error : confirmed == go ? ERROR_SUCCESS : ERROR_PROCESS_ABORTED;
}

DWORD ClaudeTakeoverHealth(CLAUDE_TAKEOVER *state) {
    if (WaitForSingleObject(state->launcher, 0) == WAIT_TIMEOUT)
        return ERROR_SUCCESS;
    DWORD error;
    return GetExitCodeProcess(state->launcher, &error) && error ? error : ERROR_PROCESS_ABORTED;
}

// Record every descendant image in a bounded log so a later compatibility
// report can list what Claude started. Blocked identities also replace the
// single-object record the desktop already knows how to collect.
static void report_component(const wchar_t *folder, DWORD pid, const wchar_t *path, const char *reason,
                             BOOL last_block) {
    const wchar_t *leaf = wcsrchr(path, L'\\');
    leaf = leaf ? leaf + 1 : path;
    char image[128] = {0}, report[256];
    for (size_t i = 0; i + 1 < ARRAYSIZE(image) && leaf[i]; ++i) {
        wchar_t c = leaf[i];
        image[i] = (c >= L'a' && c <= L'z') || (c >= L'A' && c <= L'Z') ||
                   (c >= L'0' && c <= L'9') || c == L'.' || c == L'-' || c == L'_' ? (char)c : '_';
    }
    int length = sprintf_s(report, sizeof(report), "{\"pid\":%lu,\"image\":\"%s\",\"reason\":\"%s\"}\n",
                           pid, image, reason);
    if (length < 0)
        return;
    wchar_t log_path[1200];
    if (swprintf_s(log_path, ARRAYSIZE(log_path), L"%ls\\takeover-components.log", folder) >= 0) {
        HANDLE log = CreateFileW(log_path, FILE_APPEND_DATA, FILE_SHARE_READ, NULL, OPEN_ALWAYS,
                                 FILE_FLAG_OPEN_REPARSE_POINT, NULL);
        if (log != INVALID_HANDLE_VALUE) {
            LARGE_INTEGER size;
            DWORD written;
            if (GetFileSizeEx(log, &size) && size.QuadPart < 65536)
                WriteFile(log, report, (DWORD)length, &written, NULL);
            CloseHandle(log);
        }
    }
    if (!last_block)
        return;
    wchar_t report_path[1200];
    if (swprintf_s(report_path, ARRAYSIZE(report_path), L"%ls\\takeover-component.json", folder) < 0)
        return;
    HANDLE file = CreateFileW(report_path, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS,
                              FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    if (file != INVALID_HANDLE_VALUE) {
        DWORD written;
        WriteFile(file, report, (DWORD)length, &written, NULL);
        CloseHandle(file);
    }
}

static void report_containment(const wchar_t *folder, BOOL job, DWORD error) {
    wchar_t path[1200];
    if (swprintf_s(path, ARRAYSIZE(path), L"%ls\\takeover-containment.json", folder) < 0)
        return;
    char text[96];
    int length = sprintf_s(text, sizeof(text), "{\"job\":%s,\"error\":%lu}\n",
                           job ? "true" : "false", error);
    if (length < 0)
        return;
    HANDLE file = CreateFileW(path, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS,
                              FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    if (file == INVALID_HANDLE_VALUE)
        return;
    DWORD written;
    WriteFile(file, text, (DWORD)length, &written, NULL);
    CloseHandle(file);
}

// Fallback when a job cannot be created or assigned: stop the root and the
// descendants still linked to it through their recorded parent process id.
static void terminate_tree(HANDLE root) {
    DWORD known[256] = {0};
    unsigned count = 1;
    known[0] = GetProcessId(root);
    TerminateProcess(root, 1);
    WaitForSingleObject(root, 2000);
    for (int pass = 0; pass < 4 && count < ARRAYSIZE(known); ++pass) {
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot == INVALID_HANDLE_VALUE)
            return;
        PROCESSENTRY32W entry = {0};
        entry.dwSize = sizeof(entry);
        unsigned before = count;
        for (BOOL more = Process32FirstW(snapshot, &entry); more; more = Process32NextW(snapshot, &entry)) {
            BOOL related = FALSE, listed = FALSE;
            for (unsigned i = 0; i < count; ++i) {
                if (known[i] == entry.th32ParentProcessID)
                    related = TRUE;
                if (known[i] == entry.th32ProcessID)
                    listed = TRUE;
            }
            if (!related || listed)
                continue;
            if (count == ARRAYSIZE(known))
                break;
            known[count++] = entry.th32ProcessID;
            HANDLE child = OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE, FALSE, entry.th32ProcessID);
            if (child) {
                TerminateProcess(child, 1);
                WaitForSingleObject(child, 1000);
                CloseHandle(child);
            }
        }
        CloseHandle(snapshot);
        if (count == before)
            break;
    }
}

#define SEEN_SLOTS 256

// Record newly observed descendants for compatibility reports. This replaces
// the per-creation debug events; short-lived helpers can be missed by the
// two-second sampling window.
static void scan_components(HANDLE job, CLAUDE_TAKEOVER *state, const wchar_t *folder,
                            DWORD *seen, unsigned *next) {
    ULONG_PTR storage[516];
    JOBOBJECT_BASIC_PROCESS_ID_LIST *list = (void *)storage;
    if (!QueryInformationJobObject(job, JobObjectBasicProcessIdList, list,
                                   sizeof(storage), NULL) ||
        list->NumberOfAssignedProcesses != list->NumberOfProcessIdsInList)
        return;
    for (DWORD i = 0; i < list->NumberOfProcessIdsInList; ++i) {
        DWORD pid = (DWORD)list->ProcessIdList[i];
        BOOL known = FALSE;
        for (unsigned j = 0; j < SEEN_SLOTS && !known; ++j)
            known = seen[j] == pid;
        if (known)
            continue;
        seen[*next] = pid;
        *next = (*next + 1) % SEEN_SLOTS;
        HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (!process)
            continue;
        wchar_t path[1024] = {0};
        DWORD length = ARRAYSIZE(path);
        if (QueryFullProcessImageNameW(process, PROCESS_NAME_NATIVE, path, &length) &&
            _wcsicmp(path, state->identity.image))
            report_component(folder, pid, path, "child_admitted", FALSE);
        CloseHandle(process);
    }
}

static DWORD supervise_processes(CLAUDE_TAKEOVER *state, HANDLE pipe, HANDLE root,
                                 HANDLE job, const wchar_t *folder) {
    DWORD seen[SEEN_SLOTS] = {0};
    unsigned next = 0;
    ULONGLONG next_scan = 0;
    DWORD result = ERROR_BROKEN_PIPE;
    for (;;) {
        if (!PeekNamedPipe(pipe, NULL, 0, NULL, NULL, NULL))
            break;
        DWORD wait = WaitForSingleObject(root, 200);
        if (wait == WAIT_OBJECT_0) {
            result = ERROR_SUCCESS;
            break;
        }
        if (wait == WAIT_FAILED) {
            result = GetLastError();
            break;
        }
        ULONGLONG now = GetTickCount64();
        if (job && now >= next_scan) {
            scan_components(job, state, folder, seen, &next);
            next_scan = now + 2000;
        }
    }
    return result;
}

DWORD ClaudeTakeoverWorker(CLAUDE_TAKEOVER *state, const wchar_t *folder, DWORD desktop_parent, unsigned proxy_port) {
    wchar_t name[128], journal[1200];
    if (!pipe_name(folder, name) ||
        swprintf_s(journal, ARRAYSIZE(journal), L"%ls\\takeover.bin", folder) < 0)
        return ERROR_INVALID_NAME;
    BYTE sid[SECURITY_MAX_SID_SIZE];
    HANDLE token = NULL;
    TOKEN_ELEVATION elevation;
    DWORD size;
    if (process_user(GetCurrentProcess(), sid) ||
        !OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
        return ERROR_INVALID_OWNER;
    BOOL ordinary = GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &size) &&
                    !elevation.TokenIsElevated;
    CloseHandle(token);
    if (!ordinary)
        return ERROR_INVALID_OWNER;
    HANDLE desktop = OpenProcess(SYNCHRONIZE, FALSE, desktop_parent);
    if (!desktop)
        return GetLastError();
    HANDLE pipe = INVALID_HANDLE_VALUE;
    DWORD connection_error = ERROR_TIMEOUT;
    ULONGLONG deadline = GetTickCount64() + 120000;
    while (GetTickCount64() < deadline && WaitForSingleObject(desktop, 0) == WAIT_TIMEOUT) {
        pipe = CreateFileW(name, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
        if (pipe != INVALID_HANDLE_VALUE)
            break;
        connection_error = GetLastError();
        if (connection_error != ERROR_FILE_NOT_FOUND && connection_error != ERROR_PIPE_BUSY)
            break;
        Sleep(100);
    }
    CloseHandle(desktop);
    if (pipe == INVALID_HANDLE_VALUE)
        return connection_error;
    DWORD error = ClaudeTakeoverRead(state, journal);
    PROCESS_INFORMATION app = {0};
    HANDLE job = NULL;
    if (error || !EqualSid(sid, state->identity.sid)) {
        if (!error)
            error = ERROR_INVALID_OWNER;
        goto done;
    }
    DWORD bound_port = 0, transferred;
    // Both sides read the request independently. Verify the port the guardian
    // bound before constructing the suspended client's launch command.
    if (!ReadFile(pipe, &bound_port, sizeof(bound_port), &transferred, NULL) ||
        transferred != sizeof(bound_port) || bound_port != proxy_port) {
        error = ERROR_INVALID_DATA;
        goto done;
    }
    error = ERROR_INVALID_OWNER;
    wchar_t local[1024], command[1400];
    DWORD length = GetEnvironmentVariableW(L"LOCALAPPDATA", local, ARRAYSIZE(local));
    if (!length || length >= ARRAYSIZE(local) ||
        swprintf_s(command, ARRAYSIZE(command),
                    L"\"%ls\\Microsoft\\WindowsApps\\claude-desktop.exe\" --proxy-server=http://127.0.0.1:%u --proxy-bypass-list=\"<-loopback>\"",
                    local, proxy_port) < 0) {
        error = ERROR_INVALID_NAME;
        goto done;
    }
    STARTUPINFOW startup = {0};
    startup.cb = sizeof(startup);
    // Start without a debugger so Code mode commands run natively. The job
    // provides tree containment and kill-on-close; the client image itself is
    // still bound to the explicit proxy by the guardian's WFP rules.
    if (!CreateProcessW(NULL, command, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, local, &startup, &app)) {
        error = GetLastError();
        goto done;
    }
    if (!ClaudeTakeoverCovered(state, app.hProcess))
        goto done;
    job = CreateJobObjectW(NULL, NULL);
    if (job) {
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits = {0};
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation, &limits, sizeof(limits)) ||
            !AssignProcessToJobObject(job, app.hProcess)) {
            DWORD reason = GetLastError();
            CloseHandle(job);
            job = NULL;
            report_containment(folder, FALSE, reason);
        } else {
            report_containment(folder, TRUE, 0);
        }
    } else {
        report_containment(folder, FALSE, GetLastError());
    }
    TAKEOVER_PROCESS message = {app.dwProcessId, app.dwThreadId, process_birth(app.hProcess)};
    BYTE go = 0;
    error = ERROR_PROCESS_ABORTED;
    if (message.created && WriteFile(pipe, &message, sizeof(message), &transferred, NULL) &&
        transferred == sizeof(message) && ReadFile(pipe, &go, sizeof(go), &transferred, NULL) &&
        transferred == sizeof(go) && go == 1 && ResumeThread(app.hThread) == 1 &&
        WriteFile(pipe, &go, sizeof(go), &transferred, NULL) && transferred == sizeof(go))
        error = supervise_processes(state, pipe, app.hProcess, job, folder);
done:
    if (app.hProcess) {
        if (error) {
            if (job)
                TerminateJobObject(job, 1);
            else
                terminate_tree(app.hProcess);
        }
        CloseHandle(app.hProcess);
        CloseHandle(app.hThread);
    }
    if (job)
        CloseHandle(job);
    CloseHandle(pipe);
    return error;
}

void ClaudeTakeoverRelease(CLAUDE_TAKEOVER *state) {
    if (state->pipe && state->pipe != INVALID_HANDLE_VALUE)
        CloseHandle(state->pipe);
    state->pipe = NULL;
    if (state->launcher) {
        if (WaitForSingleObject(state->launcher, 3000) != WAIT_OBJECT_0) {
            TerminateProcess(state->launcher, 1);
            WaitForSingleObject(state->launcher, 3000);
        }
        CloseHandle(state->launcher);
        state->launcher = NULL;
    }
    if (state->root) {
        WaitForSingleObject(state->root, 3000);
        CloseHandle(state->root);
        state->root = NULL;
    }
    if (state->journal && state->journal != INVALID_HANDLE_VALUE)
        CloseHandle(state->journal);
    state->journal = NULL;
}

