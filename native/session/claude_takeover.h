#pragma once

#include <windows.h>
#include <fwpmu.h>

typedef struct {
    DWORD version;
    BYTE sid[SECURITY_MAX_SID_SIZE];
    wchar_t image[1024];
} CLAUDE_TAKEOVER_IDENTITY;

typedef struct {
    CLAUDE_TAKEOVER_IDENTITY identity;
    FWP_BYTE_BLOB app_id;
    HANDLE journal, parent, launcher, pipe, root;
    const wchar_t *image, *package;
    DWORD root_pid, session;
    const char *prepare_stage;
} CLAUDE_TAKEOVER;

DWORD ClaudeTakeoverBind(CLAUDE_TAKEOVER *state, const wchar_t *record, const wchar_t *image,
                         const wchar_t *package, HANDLE parent);
DWORD ClaudeTakeoverRead(CLAUDE_TAKEOVER *state, const wchar_t *record);
DWORD ClaudeTakeoverFind(CLAUDE_TAKEOVER *state, BOOL restart, BOOL *active);
DWORD ClaudeTakeoverPrepare(CLAUDE_TAKEOVER *state, const wchar_t *folder);
DWORD ClaudeTakeoverResume(CLAUDE_TAKEOVER *state);
DWORD ClaudeTakeoverHealth(CLAUDE_TAKEOVER *state);
BOOL ClaudeTakeoverCovered(CLAUDE_TAKEOVER *state, HANDLE process);
DWORD ClaudeTakeoverWorker(CLAUDE_TAKEOVER *state, const wchar_t *folder, DWORD parent);
void ClaudeTakeoverRelease(CLAUDE_TAKEOVER *state);
