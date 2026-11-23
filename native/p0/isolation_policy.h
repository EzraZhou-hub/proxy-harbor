#pragma once
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <fwpmu.h>
typedef struct P0_ISOLATION_POLICY {
    HANDLE engine;
    PSID sid;
    UINT16 port;
    BYTE owner[SECURITY_MAX_SID_SIZE+8];
    UINT32 owner_size;
    FWP_BYTE_BLOB *relay_app;
    unsigned installed;
    BOOL journal_created;
    DWORD journal_size;
    char journal[512];
} P0_ISOLATION_POLICY;
DWORD P0InstallIsolationPolicy(PSID sid,UINT16 port,P0_ISOLATION_POLICY *policy);
BOOL P0RemoveIsolationPolicy(P0_ISOLATION_POLICY *policy);
DWORD P0RecoverIsolationPolicyForSid(PSID sid, UINT16 port);
