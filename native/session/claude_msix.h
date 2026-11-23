#pragma once

#include <windows.h>
#include <appmodel.h>
#include "account.h"

BOOL ClaudeMSIXPackage(const wchar_t *image, wchar_t *package);
BOOL ClaudeMSIXFindImage(wchar_t *image, size_t capacity);
BOOL ClaudeMSIXInstalledImage(const wchar_t *image, const wchar_t *package);
BOOL ClaudeMSIXMatches(HANDLE process, const wchar_t *image, const wchar_t *package, PSID sid);
DWORD ClaudeMSIXLaunch(const wchar_t *image, unsigned proxy_port);
DWORD ClaudeMSIXRegistrationPresent(PSID sid, BOOL *present);
DWORD ClaudeMSIXUnregister(SESSION_ACCOUNT *account, const wchar_t *diagnostic_path);
