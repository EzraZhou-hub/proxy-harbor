#pragma once
#include <windows.h>
#include <fwpmu.h>

#define SYSTEM_DNS_RULES 6
typedef struct {
    HANDLE engine;
    GUID session;
    FWP_BYTE_BLOB *service_app;
    PSECURITY_DESCRIPTOR descriptor;
    FWP_BYTE_BLOB security;
    unsigned count;
    BOOL persistent;
} SYSTEM_DNS_GUARD;

DWORD SystemDNSOpen(SYSTEM_DNS_GUARD *guard, HANDLE engine, const GUID *session,
                    BOOL persistent);
DWORD SystemDNSInstall(SYSTEM_DNS_GUARD *guard);
DWORD SystemDNSVerify(SYSTEM_DNS_GUARD *guard);
DWORD SystemDNSRemove(SYSTEM_DNS_GUARD *guard);
void SystemDNSClose(SYSTEM_DNS_GUARD *guard);
