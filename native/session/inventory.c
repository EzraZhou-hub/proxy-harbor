// Read-only inventory of this project's managed-session policy namespace.
#define _WIN32_WINNT 0x0A00
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <fwpmu.h>
#include <stdio.h>
#include <wchar.h>

int wmain(int argc, wchar_t **argv) {
    if (argc != 2 || (wcscmp(argv[1], L"inspect") && wcscmp(argv[1], L"require-empty"))) return 2;
    BOOL require_empty = !wcscmp(argv[1], L"require-empty");
    HANDLE engine = NULL, enumeration = NULL;
    DWORD error = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, NULL, &engine);
    unsigned count = 0;
    if (!error) error = FwpmFilterCreateEnumHandle0(engine, NULL, &enumeration);
    BOOL complete = FALSE;
    for (unsigned page = 0; !error && page < 1024; ++page) {
        FWPM_FILTER0 **filters = NULL;
        UINT32 returned = 0;
        error = FwpmFilterEnum0(engine, enumeration, 256, &filters, &returned);
        if (!error) {
            for (UINT32 i = 0; i < returned; ++i) {
                FWPM_FILTER0 *filter = filters[i];
                if (filter->displayData.name &&
                    (!wcscmp(filter->displayData.name, L"Proxy Harbor managed session v1") ||
                     !wcscmp(filter->displayData.name, L"Proxy Harbor session system DNS guard v1"))) ++count;
            }
        }
        if (filters) FwpmFreeMemory0((void **)&filters);
        if (returned < 256) { complete = !error; break; }
    }
    if (!error && !complete) error = ERROR_MORE_DATA;
    if (enumeration) FwpmFilterDestroyEnumHandle0(engine, enumeration);
    if (engine) FwpmEngineClose0(engine);
    printf("{\"windowsError\":%lu,\"rulesPresent\":%u,\"systemChanged\":false,\"complete\":%s}\n",
           error, count, complete ? "true" : "false");
    return error ? 1 : require_empty && count != 0 ? 3 : 0;
}
