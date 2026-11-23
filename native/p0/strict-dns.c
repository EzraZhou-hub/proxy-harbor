// SPDX-License-Identifier: GPL-2.0-or-later
// P0-only additions to the pinned proxychains candidate. No system resolver
// fallback: unsupported async DNS fails, and ordinary queries use its FakeIP
// mapping. The original target name is later sent through the selected proxy.
#define _WIN32_WINNT 0x0A00
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>
#include <windows.h>
#include <windns.h>
#include <iphlpapi.h>
#include <MinHook.h>
#include <wchar.h>
#include <string.h>
#include <bcrypt.h>
#pragma comment(lib,"Iphlpapi.lib")
#pragma comment(lib,"Bcrypt.lib")

extern int WSAAPI ProxyWs2_32_GetAddrInfoW(const wchar_t *, const wchar_t *, const void *, void **);
extern void WSAAPI ProxyWs2_32_FreeAddrInfoW(void *);
extern void (WSAAPI *orig_fpWs2_32_FreeAddrInfoExW)(void *);
extern void (WSAAPI *orig_fpWs2_32_FreeAddrInfoExA_)(void *);

typedef struct allocation { void *value; struct allocation *next; } allocation;
static SRWLOCK allocation_lock = SRWLOCK_INIT;
static allocation *allocations;
static void (WINAPI *original_record_free)(void *, DNS_FREE_TYPE);
static void (WINAPI *original_dns_free)(void *, DNS_FREE_TYPE);
static HANDLE relay_process;
static DWORD relay_pid;
static BYTE relay_proof_key[32];
static BOOL relay_proof_enabled;
static LONG peer_diagnostic_written;

static BOOL proof_io(SOCKET socket_handle,BYTE *data,int length,BOOL sending) {
    ULONGLONG deadline=GetTickCount64()+1000;
    while(length>0 && GetTickCount64()<deadline) {
        fd_set sockets;FD_ZERO(&sockets);FD_SET(socket_handle,&sockets);
        TIMEVAL wait={0,100000};
        int ready=select(0,sending?NULL:&sockets,sending?&sockets:NULL,NULL,&wait);
        if(ready==SOCKET_ERROR)return FALSE;
        if(!ready)continue;
        int count=sending?send(socket_handle,(const char *)data,length,0):recv(socket_handle,(char *)data,length,0);
        if(count==SOCKET_ERROR && WSAGetLastError()==WSAEWOULDBLOCK)continue;
        if(count<=0)return FALSE;
        data+=count;length-=count;
    }
    return length==0;
}
static BOOL relay_challenge(SOCKET socket_handle) {
    BYTE challenge[40]={'P','H','P','0','A','U','T','H'},reply[32],expected[32];
    BCRYPT_ALG_HANDLE algorithm=NULL;BCRYPT_HASH_HANDLE hash=NULL;BOOL verified=FALSE;
    if(BCryptGenRandom(NULL,challenge+8,32,BCRYPT_USE_SYSTEM_PREFERRED_RNG)<0)return FALSE;
    if(!proof_io(socket_handle,challenge,sizeof(challenge),TRUE) || !proof_io(socket_handle,reply,sizeof(reply),FALSE))return FALSE;
    if(BCryptOpenAlgorithmProvider(&algorithm,BCRYPT_SHA256_ALGORITHM,NULL,BCRYPT_ALG_HANDLE_HMAC_FLAG)<0)goto cleanup_proof;
    if(BCryptCreateHash(algorithm,&hash,NULL,0,relay_proof_key,32,0)<0 || BCryptHashData(hash,challenge,sizeof(challenge),0)<0 || BCryptFinishHash(hash,expected,sizeof(expected),0)<0)goto cleanup_proof;
    BYTE difference=0;for(int i=0;i<32;++i)difference|=expected[i]^reply[i];
    verified=difference==0 && WaitForSingleObject(relay_process,0)==WAIT_TIMEOUT;
cleanup_proof:
    if(hash)BCryptDestroyHash(hash);
    if(algorithm)BCryptCloseAlgorithmProvider(algorithm,0);
    SecureZeroMemory(expected,sizeof(expected));
    return verified;
}

static void initialization_failed(const char *stage,LONG status) {
    char message[256]; DWORD written;
    int length=wsprintfA(message,"P0 strict hook initialization failed: %s (%ld)\n",stage,status);
    WriteFile(GetStdHandle(STD_ERROR_HANDLE),message,(DWORD)length,&written,NULL);
    ExitProcess(ERROR_DLL_INIT_FAILED);
}

int WSAAPI P0ValidateRelaySocket(UINT_PTR value) {
    SOCKADDR_IN local={0},peer={0}; int size=sizeof(local);
    SOCKET socket_handle=(SOCKET)value;
    if(!relay_process || WaitForSingleObject(relay_process,0)!=WAIT_TIMEOUT ||
       getsockname(socket_handle,(SOCKADDR *)&local,&size)!=0) return FALSE;
    size=sizeof(peer);
    if(getpeername(socket_handle,(SOCKADDR *)&peer,&size)!=0 || peer.sin_family!=AF_INET ||
       ntohl(peer.sin_addr.s_addr)!=0x7f000001) return FALSE;
    if(relay_proof_enabled) {
        if(GetEnvironmentVariableW(L"P0_PEER_TABLE_DIAGNOSTIC",NULL,0) && InterlockedCompareExchange(&peer_diagnostic_written,1,0)==0) {
            DWORD bytes=0,status=GetExtendedTcpTable(NULL,&bytes,FALSE,AF_INET,TCP_TABLE_OWNER_PID_CONNECTIONS,0);BOOL visible=FALSE;
            if(status==ERROR_INSUFFICIENT_BUFFER && bytes<8*1024*1024) {
                PMIB_TCPTABLE_OWNER_PID table=HeapAlloc(GetProcessHeap(),0,bytes);
                if(table){status=GetExtendedTcpTable(table,&bytes,FALSE,AF_INET,TCP_TABLE_OWNER_PID_CONNECTIONS,0);if(!status)for(DWORD i=0;i<table->dwNumEntries;++i){MIB_TCPROW_OWNER_PID *row=&table->table[i];if(row->dwState==MIB_TCP_STATE_ESTAB && row->dwLocalAddr==peer.sin_addr.s_addr && (USHORT)row->dwLocalPort==peer.sin_port && row->dwRemoteAddr==local.sin_addr.s_addr && (USHORT)row->dwRemotePort==local.sin_port && row->dwOwningPid==relay_pid){visible=TRUE;break;}}HeapFree(GetProcessHeap(),0,table);}
            }
            char message[128];DWORD written;int n=wsprintfA(message,"P0 relay peer table diagnostic: status=%lu expectedPeerVisible=%u\n",status,visible);WriteFile(GetStdHandle(STD_ERROR_HANDLE),message,(DWORD)n,&written,NULL);
        }
        return relay_challenge(socket_handle);
    }
    for(int attempt=0;attempt<10;++attempt) {
        DWORD bytes=0;
        if(GetExtendedTcpTable(NULL,&bytes,FALSE,AF_INET,TCP_TABLE_OWNER_PID_CONNECTIONS,0)!=ERROR_INSUFFICIENT_BUFFER) return FALSE;
        PMIB_TCPTABLE_OWNER_PID table=HeapAlloc(GetProcessHeap(),0,bytes);
        if(!table) return FALSE;
        DWORD status=GetExtendedTcpTable(table,&bytes,FALSE,AF_INET,TCP_TABLE_OWNER_PID_CONNECTIONS,0);
        BOOL found=FALSE;
        if(status==NO_ERROR) for(DWORD i=0;i<table->dwNumEntries;++i) {
            MIB_TCPROW_OWNER_PID *row=&table->table[i];
            if(row->dwState==MIB_TCP_STATE_ESTAB && row->dwLocalAddr==peer.sin_addr.s_addr &&
               (USHORT)row->dwLocalPort==peer.sin_port && row->dwRemoteAddr==local.sin_addr.s_addr &&
               (USHORT)row->dwRemotePort==local.sin_port && row->dwOwningPid==relay_pid) { found=TRUE; break; }
        }
        HeapFree(GetProcessHeap(),0,table);
        if(found) return WaitForSingleObject(relay_process,0)==WAIT_TIMEOUT;
        Sleep(2);
    }
    return FALSE;
}

static void *tracked_allocate(SIZE_T bytes) {
    void *value = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, bytes);
    allocation *entry = HeapAlloc(GetProcessHeap(), 0, sizeof(*entry));
    if (!value || !entry) { if (value) HeapFree(GetProcessHeap(), 0, value); if (entry) HeapFree(GetProcessHeap(), 0, entry); return NULL; }
    entry->value = value;
    AcquireSRWLockExclusive(&allocation_lock);
    entry->next = allocations; allocations = entry;
    ReleaseSRWLockExclusive(&allocation_lock);
    return value;
}

static BOOL tracked_free(void *value) {
    BOOL found = FALSE;
    AcquireSRWLockExclusive(&allocation_lock);
    allocation **entry = &allocations;
    while (*entry) {
        if ((*entry)->value == value) {
            allocation *removed = *entry; *entry = removed->next;
            HeapFree(GetProcessHeap(), 0, removed); HeapFree(GetProcessHeap(), 0, value); found = TRUE; break;
        }
        entry = &(*entry)->next;
    }
    ReleaseSRWLockExclusive(&allocation_lock);
    return found;
}

static BOOL ascii_name(const wchar_t *name) {
    if (!name || !*name) return FALSE;
    size_t size = 0;
    for (; size < 254 && name[size]; ++size) { if (name[size] > 127) return FALSE; }
    return size < 254;
}

static int extended_lookup(const wchar_t *name, const wchar_t *service, DWORD space, const void *provider, const void *hints,
                          void **result, void *overlapped, void *completion, void **handle, BOOL wide) {
    if (result) *result = NULL;
    if (handle) *handle = NULL;
    if (!result || !ascii_name(name) || provider || (space != NS_ALL && space != NS_DNS)) return WSAEINVAL;
    // Do not dispatch an unsupported request to the original DNS service.
    if (overlapped || completion) return WSAEOPNOTSUPP;
    const ADDRINFOEXW *input = hints;
    ADDRINFOW basic = {0};
    if (input) { basic.ai_flags=input->ai_flags; basic.ai_family=input->ai_family; basic.ai_socktype=input->ai_socktype; basic.ai_protocol=input->ai_protocol; }
    ADDRINFOW *addresses = NULL;
    int status = ProxyWs2_32_GetAddrInfoW(name, service, &basic, (void **)&addresses);
    if (status) return status;
    SIZE_T count = 0;
    for (ADDRINFOW *p=addresses; p; p=p->ai_next) { if (++count > 64 || p->ai_addrlen > sizeof(SOCKADDR_STORAGE)) { ProxyWs2_32_FreeAddrInfoW(addresses); return WSAEFAULT; } }
    if (!count) { ProxyWs2_32_FreeAddrInfoW(addresses); return WSAHOST_NOT_FOUND; }
    ADDRINFOEXW *output = tracked_allocate(count * (sizeof(*output) + sizeof(SOCKADDR_STORAGE)));
    if (!output) { ProxyWs2_32_FreeAddrInfoW(addresses); return WSA_NOT_ENOUGH_MEMORY; }
    BYTE *storage = (BYTE *)(output + count);
    SIZE_T index = 0;
    for (ADDRINFOW *p=addresses; p; p=p->ai_next,++index) {
        output[index].ai_flags=p->ai_flags; output[index].ai_family=p->ai_family;
        output[index].ai_socktype=p->ai_socktype; output[index].ai_protocol=p->ai_protocol;
        output[index].ai_addrlen=p->ai_addrlen; output[index].ai_addr=(SOCKADDR *)(storage + index*sizeof(SOCKADDR_STORAGE));
        memcpy(output[index].ai_addr,p->ai_addr,p->ai_addrlen);
        if (index+1<count) output[index].ai_next=&output[index+1];
        // Canonical names and EX provider/blob fields are absent, not fabricated.
    }
    (void)wide; // ADDRINFOEXA/W share this prefix; canonical names are NULL.
    ProxyWs2_32_FreeAddrInfoW(addresses); *result=output; return 0;
}

int WSAAPI P0GetAddrInfoExW(const wchar_t *name,const wchar_t *service,DWORD space,void *provider,const void *hints,void **result,void *timeout,void *overlapped,void *completion,void **handle) {
    (void)timeout; return extended_lookup(name,service,space,provider,hints,result,overlapped,completion,handle,TRUE);
}

int WSAAPI P0GetAddrInfoExA(const char *name,const char *service,DWORD space,void *provider,const void *hints,void **result,void *timeout,void *overlapped,void *completion,void **handle) {
    wchar_t wide_name[254],wide_service[64];
    if (!name || !MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,name,-1,wide_name,254) ||
        (service && !MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,service,-1,wide_service,64))) { if(result)*result=NULL; return WSAEINVAL; }
    (void)timeout; return extended_lookup(wide_name,service?wide_service:NULL,space,provider,hints,result,overlapped,completion,handle,FALSE);
}

void WSAAPI P0FreeAddrInfoExW(void *value) { if (!tracked_free(value)) orig_fpWs2_32_FreeAddrInfoExW(value); }
void WSAAPI P0FreeAddrInfoExA(void *value) { if (!tracked_free(value)) orig_fpWs2_32_FreeAddrInfoExA_(value); }

static DNS_STATUS query_records(const wchar_t *name,WORD type,void **result,BOOL wide) {
    if (result) *result=NULL;
    if (!result || !ascii_name(name)) return ERROR_INVALID_PARAMETER;
    if (type!=DNS_TYPE_A) return ERROR_NOT_SUPPORTED; /* Strict P0 permits IPv4 TCP only. */
    ADDRINFOW hints={0},*addresses=NULL;
    hints.ai_family=type==DNS_TYPE_A?AF_INET:AF_INET6; hints.ai_socktype=SOCK_STREAM; hints.ai_protocol=IPPROTO_TCP;
    int status=ProxyWs2_32_GetAddrInfoW(name,L"0",&hints,(void **)&addresses);
    if (status || !addresses) return DNS_INFO_NO_RECORDS;
    SIZE_T count=0;
    for(ADDRINFOW *p=addresses;p;p=p->ai_next) {
        if(++count>64 || !p->ai_addr ||
           p->ai_family!=(type==DNS_TYPE_A?AF_INET:AF_INET6) ||
           p->ai_addrlen<(type==DNS_TYPE_A?sizeof(SOCKADDR_IN):sizeof(SOCKADDR_IN6))) {
            ProxyWs2_32_FreeAddrInfoW(addresses); return ERROR_INVALID_DATA;
        }
    }
    SIZE_T name_bytes=(wcslen(name)+1)*(wide?sizeof(wchar_t):1);
    DNS_RECORDW *records=tracked_allocate(count*sizeof(*records)+name_bytes);
    if(!records) { ProxyWs2_32_FreeAddrInfoW(addresses); return ERROR_NOT_ENOUGH_MEMORY; }
    void *stored_name=records+count;
    if(wide) memcpy(stored_name,name,name_bytes);
    else WideCharToMultiByte(CP_UTF8,0,name,-1,stored_name,(int)name_bytes,NULL,NULL);
    SIZE_T index=0;
    for(ADDRINFOW *p=addresses;p;p=p->ai_next,++index) {
        DNS_RECORDW *record=&records[index]; record->pName=stored_name; record->wType=type; record->dwTtl=0;
        record->Flags.S.Section=DnsSectionAnswer; record->Flags.S.CharSet=wide?DnsCharSetUnicode:DnsCharSetUtf8;
        if(type==DNS_TYPE_A) { record->wDataLength=sizeof(DNS_A_DATA); record->Data.A.IpAddress=((SOCKADDR_IN *)p->ai_addr)->sin_addr.s_addr; }
        else { record->wDataLength=sizeof(DNS_AAAA_DATA); memcpy(&record->Data.AAAA.Ip6Address,&((SOCKADDR_IN6 *)p->ai_addr)->sin6_addr,16); }
        if(index+1<count) record->pNext=&records[index+1];
    }
    ProxyWs2_32_FreeAddrInfoW(addresses); *result=records; return ERROR_SUCCESS;
}

/* FakeIP supplies a confined address token, not a local resolver-cache lookup
   or a complete wire DNS answer. Never claim unsupported semantics succeeded. */
static BOOL supported_options(ULONG64 options) {
    const ULONG64 supported=DNS_QUERY_BYPASS_CACHE|DNS_QUERY_NO_LOCAL_NAME|DNS_QUERY_NO_HOSTS_FILE|
        DNS_QUERY_NO_NETBT|DNS_QUERY_NO_MULTICAST|DNS_QUERY_TREAT_AS_FQDN;
    return (options & ~supported)==0;
}
static DNS_STATUS WINAPI query_w(PCWSTR name,WORD type,DWORD options,PVOID extra,PDNS_RECORDW *records,PVOID *reserved) {
    if(records) *records=NULL;
    if(extra || reserved) return ERROR_INVALID_PARAMETER;
    if(!supported_options(options)) return ERROR_NOT_SUPPORTED;
    return query_records(name,type,(void **)records,TRUE);
}
static DNS_STATUS WINAPI query_a(PCSTR name,WORD type,DWORD options,PVOID extra,PDNS_RECORDA *records,PVOID *reserved) {
    if(records) *records=NULL;
    if(extra || reserved) return ERROR_INVALID_PARAMETER;
    if(!supported_options(options)) return ERROR_NOT_SUPPORTED;
    wchar_t wide[254]; if(!name || !MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,name,-1,wide,254)) { if(records)*records=NULL; return ERROR_INVALID_PARAMETER; }
    return query_records(wide,type,(void **)records,FALSE);
}
typedef struct dns_job {
    struct dns_job *next;
    PDNS_QUERY_RESULT result;
    PDNS_QUERY_CANCEL cancel;
    PDNS_RECORDW records;
    DNS_QUERY_COMPLETION_ROUTINE *callback;
    void *context;
    LONG state; /* 0 pending, 1 completing, 2 cancelled */
} dns_job;
static SRWLOCK jobs_lock=SRWLOCK_INIT;
static dns_job *jobs;

static void CALLBACK complete_dns(PTP_CALLBACK_INSTANCE instance,void *context,PTP_WORK work) {
    dns_job *job=context;
    (void)instance;
    if(InterlockedCompareExchange(&job->state,1,0)==2) {
        if(job->records) tracked_free(job->records);
        job->result->pQueryRecords=NULL;
        job->result->QueryStatus=ERROR_OPERATION_ABORTED;
    } else { job->result->pQueryRecords=job->records; job->result->QueryStatus=ERROR_SUCCESS; }
    job->callback(job->context,job->result);
    AcquireSRWLockExclusive(&jobs_lock);
    dns_job **entry=&jobs;
    while(*entry && *entry!=job) entry=&(*entry)->next;
    if(*entry) *entry=job->next;
    ReleaseSRWLockExclusive(&jobs_lock);
    HeapFree(GetProcessHeap(),0,job);
    CloseThreadpoolWork(work);
}

static DNS_STATUS WINAPI cancel_query(PDNS_QUERY_CANCEL cancel) {
    if(!cancel) return ERROR_INVALID_PARAMETER;
    DNS_STATUS status=ERROR_INVALID_HANDLE;
    AcquireSRWLockShared(&jobs_lock);
    for(dns_job *job=jobs;job;job=job->next) if(job->cancel==cancel) {
        InterlockedCompareExchange(&job->state,2,0);
        status=ERROR_SUCCESS;
        break;
    }
    ReleaseSRWLockShared(&jobs_lock);
    return status;
}

static DNS_STATUS WINAPI query_ex(PDNS_QUERY_REQUEST request,PDNS_QUERY_RESULT result,PDNS_QUERY_CANCEL cancel) {
    if(!request||!result||result->Version!=DNS_QUERY_RESULTS_VERSION1) return ERROR_INVALID_PARAMETER;
    result->pQueryRecords=NULL;
    result->QueryStatus=ERROR_INVALID_PARAMETER;
    if(request->Version!=DNS_QUERY_REQUEST_VERSION1) return result->QueryStatus;
    if(cancel) ZeroMemory(cancel,sizeof(*cancel));
    result->QueryOptions=request->QueryOptions;
    if(request->pDnsServerList || request->InterfaceIndex || !supported_options(request->QueryOptions))
        return result->QueryStatus=ERROR_NOT_SUPPORTED;
    result->QueryStatus=query_records(request->QueryName,request->QueryType,(void **)&result->pQueryRecords,TRUE);
    if(request->pQueryCompletionCallback && result->QueryStatus==ERROR_SUCCESS) {
        dns_job *job=HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,sizeof(*job));
        if(!job) { tracked_free(result->pQueryRecords); result->pQueryRecords=NULL; return result->QueryStatus=ERROR_NOT_ENOUGH_MEMORY; }
        job->result=result; job->cancel=cancel; job->callback=request->pQueryCompletionCallback; job->context=request->pQueryContext;
        PTP_WORK work=CreateThreadpoolWork(complete_dns,job,NULL);
        if(!work) { HeapFree(GetProcessHeap(),0,job); tracked_free(result->pQueryRecords); result->pQueryRecords=NULL; return result->QueryStatus=ERROR_NOT_ENOUGH_MEMORY; }
        AcquireSRWLockExclusive(&jobs_lock); job->next=jobs; jobs=job; ReleaseSRWLockExclusive(&jobs_lock);
        job->records=result->pQueryRecords; result->pQueryRecords=NULL; result->QueryStatus=DNS_REQUEST_PENDING;
        /* Resolution is already confined to FakeIP; only completion is queued.
           The caller owns result/cancel until its callback has completed. */
        SubmitThreadpoolWork(work);
        return DNS_REQUEST_PENDING;
    }
    return result->QueryStatus;
}
static void WINAPI record_free(void *value,DNS_FREE_TYPE type) { if(!tracked_free(value)) original_record_free(value,type); }
static void WINAPI dns_free(void *value,DNS_FREE_TYPE type) { if(!tracked_free(value)) original_dns_free(value,type); }
/* Newer raw DNS bypasses DnsQueryEx. Until it has a confined implementation,
   reject it at entry instead of dispatching to the shared DNS service. */
static DNS_STATUS WINAPI raw_query(void *request,void *cancel) { (void)request; (void)cancel; return ERROR_NOT_SUPPORTED; }

void P0InstallStrictDnsHooks(void) {
    wchar_t proof_text[65];DWORD proof_length=GetEnvironmentVariableW(L"P0_RELAY_PROOF_KEY",proof_text,65);
    if(proof_length) {
        if(proof_length!=64)initialization_failed("relay proof configuration",ERROR_INVALID_PARAMETER);
        for(int i=0;i<64;++i) {
            wchar_t c=proof_text[i];int n=(c>=L'0'&&c<=L'9')?c-L'0':((c>=L'a'&&c<=L'f')?c-L'a'+10:-1);
            if(n<0)initialization_failed("relay proof configuration",ERROR_INVALID_PARAMETER);
            if(!(i&1))relay_proof_key[i/2]=(BYTE)(n<<4);else relay_proof_key[i/2]|=(BYTE)n;
        }
        relay_proof_enabled=TRUE;SecureZeroMemory(proof_text,sizeof(proof_text));
    }
    wchar_t process_text[32],*end=NULL,image[1024]; DWORD image_size=1024;
    if(!GetEnvironmentVariableW(L"P0_EXPECTED_RELAY_PID",process_text,32)) initialization_failed("relay identity missing",0);
    unsigned long pid=wcstoul(process_text,&end,10);
    if(!pid || !end || *end) initialization_failed("relay identity invalid",0);
    relay_pid=(DWORD)pid;
    relay_process=OpenProcess(SYNCHRONIZE|PROCESS_QUERY_LIMITED_INFORMATION,FALSE,relay_pid);
    if(!relay_process || !QueryFullProcessImageNameW(relay_process,0,image,&image_size) ||
       _wcsicmp(image,L"C:\\P0Lab\\.local\\p0\\bin\\proxy-harbor-p0-relay.exe")!=0 ||
       WaitForSingleObject(relay_process,0)!=WAIT_TIMEOUT) initialization_failed("relay identity mismatch",(LONG)GetLastError());
    HMODULE dns=LoadLibraryW(L"dnsapi.dll");
    struct {const char *name;void *hook;void **original;} hooks[]={
        {"DnsQuery_W",query_w,NULL},{"DnsQuery_A",query_a,NULL},{"DnsQuery_UTF8",query_a,NULL},
        {"DnsQueryEx",query_ex,NULL},{"DnsCancelQuery",cancel_query,NULL},{"DnsRecordListFree",record_free,(void **)&original_record_free},{"DnsFree",dns_free,(void **)&original_dns_free}
    };
    void *installed[sizeof(hooks)/sizeof(hooks[0])]={0};
    for(size_t i=0;i<sizeof(hooks)/sizeof(hooks[0]);++i) {
        void *target=(void *)GetProcAddress(dns,hooks[i].name);
        if(!target) initialization_failed(hooks[i].name,(LONG)GetLastError());
        BOOL duplicate=FALSE; for(size_t j=0;j<i;++j) if(installed[j]==target) duplicate=TRUE;
        installed[i]=target;
        if(!duplicate) { MH_STATUS status=MH_CreateHook(target,hooks[i].hook,hooks[i].original); if(status!=MH_OK) initialization_failed(hooks[i].name,status); }
    }
    HMODULE winsock=GetModuleHandleW(L"ws2_32.dll");
    void *raw=(void *)GetProcAddress(dns,"DnsQueryRaw");
    if(raw) { MH_STATUS status=MH_CreateHook(raw,raw_query,NULL); if(status!=MH_OK) initialization_failed("DnsQueryRaw",status); }
    const char *required[]={"connect","WSAConnect","getaddrinfo","GetAddrInfoW","GetAddrInfoExW","GetAddrInfoExA","gethostbyname"};
    for(size_t i=0;i<sizeof(required)/sizeof(required[0]);++i) {
        void *target=(void *)GetProcAddress(winsock,required[i]);
        if(!target) initialization_failed(required[i],(LONG)GetLastError());
        MH_STATUS status=MH_QueueEnableHook(target); if(status!=MH_OK) initialization_failed(required[i],status);
    }
    // The upstream original-function variable now points to MinHook's
    // trampoline. Query the actual extension entry before checking its hook.
    WSADATA data; if(WSAStartup(MAKEWORD(2,2),&data)!=0) initialization_failed("WSAStartup",WSAGetLastError());
    SOCKET socket_handle=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
    GUID extension=WSAID_CONNECTEX; LPFN_CONNECTEX connect_ex=NULL; DWORD bytes;
    if(socket_handle==INVALID_SOCKET || WSAIoctl(socket_handle,SIO_GET_EXTENSION_FUNCTION_POINTER,&extension,sizeof(extension),&connect_ex,sizeof(connect_ex),&bytes,NULL,NULL)!=0) initialization_failed("ConnectEx lookup",WSAGetLastError());
    MH_STATUS status=MH_QueueEnableHook((void *)connect_ex);
    closesocket(socket_handle); WSACleanup();
    if(status!=MH_OK) initialization_failed("ConnectEx",status);
    status=MH_EnableHook(MH_ALL_HOOKS); if(status!=MH_OK) initialization_failed("enable",status);
}
