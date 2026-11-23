#pragma once
#include <windows.h>

typedef struct {
    DWORD pid;
    unsigned family;
    unsigned remote_port;
} SESSION_TCP_PEER;

// Called with a PID from a Job snapshot. On success, a NULL handle means
// the process has exited or the PID now belongs to a different Job.
DWORD SessionOpenJobProcess(HANDLE job, DWORD pid, HANDLE *process);
DWORD SessionJobQueryRetries(void);

// ERROR_ACCESS_DISABLED_BY_POLICY records a live TCP peer outside the
// permitted entrance. Other errors mean the snapshot could not be verified.
DWORD SessionCheckTCPPath(HANDLE job, unsigned proxy_port, SESSION_TCP_PEER *peer);
