#pragma once
#include <windows.h>
#include <fwpmu.h>
typedef struct USER_POLICY {
    HANDLE engine;
    PSECURITY_DESCRIPTOR descriptor;
    FWP_BYTE_BLOB security;
    FWP_BYTE_BLOB *relay;
    char journal[512];
    DWORD journal_size;
    UINT16 port;
    BOOL recorded, installed;
} USER_POLICY;
DWORD UserPolicyInstall(PSID sid, UINT16 port, USER_POLICY *policy);
BOOL UserPolicyRemove(USER_POLICY *policy);
DWORD UserPolicyInspect(unsigned *count);
