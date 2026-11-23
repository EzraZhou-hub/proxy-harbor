#pragma once
#include <windows.h>
typedef struct SESSION_ACCOUNT {
    wchar_t name[32], password[80], profile[MAX_PATH], record[1200],
        comment[128];
    BYTE sid[SECURITY_MAX_SID_SIZE];
    DWORD sid_size;
    HANDLE record_lock;
    HANDLE profile_token, profile_key;
    BOOL created;
} SESSION_ACCOUNT;
DWORD SessionAccountCreate(const GUID *id, const wchar_t *directory,
                           SESSION_ACCOUNT *account);
DWORD SessionAccountLoad(const GUID *id, const wchar_t *directory,
                         SESSION_ACCOUNT *account);
DWORD SessionAccountObserve(const GUID *id, const wchar_t *directory,
                            SESSION_ACCOUNT *account);
DWORD SessionAccountConfirmAbsent(const GUID *id, const wchar_t *directory);
DWORD SessionAccountLaunch(SESSION_ACCOUNT *account, const wchar_t *image,
                           wchar_t *command, unsigned proxy_port, STARTUPINFOW *startup,
                           PROCESS_INFORMATION *process, BOOL keep_password);
DWORD SessionAccountBrowserPolicy(SESSION_ACCOUNT *account, unsigned port);
BOOL SessionAccountBrowserPolicyValid(SESSION_ACCOUNT *account, unsigned port);
DWORD SessionAccountProcessIdentity(const SESSION_ACCOUNT *account, HANDLE process);
BOOL SessionAccountAlive(SESSION_ACCOUNT *account);
#ifdef PH_CLAUDE_MSIX
void SessionAccountName(const GUID *id, wchar_t name[32]);
DWORD SessionAccountRecoverPassword(SESSION_ACCOUNT *account);
#endif
DWORD SessionAccountTerminate(SESSION_ACCOUNT *account);
DWORD SessionAccountRetire(SESSION_ACCOUNT *account);
DWORD SessionAccountForget(SESSION_ACCOUNT *account);
DWORD SessionAccountDelete(SESSION_ACCOUNT *account);
void SessionAccountRelease(SESSION_ACCOUNT *account);
