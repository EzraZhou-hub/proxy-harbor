// Temporary guest-only AppContainer/LPAC DNS boundary experiment.
// No arbitrary process, domain, capabilities or ACL target is accepted.
#define _WIN32_WINNT 0x0A00
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <userenv.h>
#include <aclapi.h>
#include <sddl.h>
#include <stdio.h>
#include <wchar.h>
#include "isolation_policy.h"

static const wchar_t probe[] = L"C:\\P0Lab\\.local\\p0\\bin\\proxy-harbor-p0-probe.exe";
static const wchar_t candidate[]=L"C:\\P0Lab\\.local\\p0\\bin\\transparent\\proxychains_win32_x64.exe";
static const wchar_t control_probe[]=L"C:\\P0Lab\\.local\\p0\\control\\proxy-harbor-p0-probe.exe";
static const wchar_t *paths[] = {L"C:\\P0Lab", L"C:\\P0Lab\\.local", L"C:\\P0Lab\\.local\\p0", L"C:\\P0Lab\\.local\\p0\\bin", probe,
    L"C:\\P0Lab\\.local\\p0\\bin\\helpers",L"C:\\P0Lab\\.local\\p0\\bin\\helpers\\proxy-harbor-p0-helper.exe",
    L"C:\\P0Lab\\.local\\p0\\bin\\transparent",candidate,L"C:\\P0Lab\\.local\\p0\\bin\\transparent\\proxychains_hook_x64.dll",
    L"C:\\P0Lab\\.local\\p0\\bin\\transparent\\proxychains_helper_win32_x64.exe",L"C:\\P0Lab\\.local\\p0\\bin\\transparent\\proxychains_helper_win32_x86.exe",
    L"C:\\P0Lab\\.local\\p0\\bin\\isolation-transparent.conf",L"C:\\P0Lab\\.local\\p0\\control",control_probe};
typedef struct saved_acl { PSECURITY_DESCRIPTOR descriptor; PACL acl; BOOL changed; } saved_acl;

static BOOL guest_only(void) {
    wchar_t cwd[MAX_PATH], marker[32], image[MAX_PATH];
    return GetCurrentDirectoryW(MAX_PATH,cwd) && _wcsicmp(cwd,L"C:\\P0Lab")==0 &&
        GetEnvironmentVariableW(L"PROXY_HARBOR_P0_GUEST",marker,32) && wcscmp(marker,L"offline-lab")==0 &&
        GetModuleFileNameW(NULL,image,MAX_PATH) && _wcsicmp(image,L"C:\\P0Lab\\.local\\p0\\bin\\p0-dns-isolation.exe")==0;
}

static DWORD grant_read(PSID sid,const wchar_t *path,saved_acl *saved) {
    DWORD status=GetNamedSecurityInfoW((LPWSTR)path,SE_FILE_OBJECT,DACL_SECURITY_INFORMATION,NULL,NULL,&saved->acl,NULL,&saved->descriptor);
    if(status!=ERROR_SUCCESS) return status;
    // Refuse an unexpected null DACL instead of changing its meaning.
    if(!saved->acl) return ERROR_INVALID_SECURITY_DESCR;
    EXPLICIT_ACCESSW access={0};
    access.grfAccessPermissions=GENERIC_READ|GENERIC_EXECUTE;
    access.grfAccessMode=GRANT_ACCESS;
    access.grfInheritance=NO_INHERITANCE;
    access.Trustee.TrusteeForm=TRUSTEE_IS_SID;
    access.Trustee.TrusteeType=TRUSTEE_IS_UNKNOWN;
    access.Trustee.ptstrName=(LPWSTR)sid;
    PACL changed=NULL;
    status=SetEntriesInAclW(1,&access,saved->acl,&changed);
    if(status==ERROR_SUCCESS) {
        status=SetNamedSecurityInfoW((LPWSTR)path,SE_FILE_OBJECT,DACL_SECURITY_INFORMATION,NULL,NULL,changed,NULL);
        if(status==ERROR_SUCCESS) saved->changed=TRUE;
    }
    if(changed) LocalFree(changed);
    return status;
}

static BOOL restore_acl(const wchar_t *path,saved_acl *saved) {
    BOOL verified=TRUE;
    if(saved->changed) {
        verified=SetNamedSecurityInfoW((LPWSTR)path,SE_FILE_OBJECT,DACL_SECURITY_INFORMATION,NULL,NULL,saved->acl,NULL)==ERROR_SUCCESS;
        PACL actual=NULL; PSECURITY_DESCRIPTOR descriptor=NULL;
        if(verified) verified=GetNamedSecurityInfoW((LPWSTR)path,SE_FILE_OBJECT,DACL_SECURITY_INFORMATION,NULL,NULL,&actual,NULL,&descriptor)==ERROR_SUCCESS;
        if(verified) verified=actual && actual->AclSize==saved->acl->AclSize && memcmp(actual,saved->acl,actual->AclSize)==0;
        if(descriptor) LocalFree(descriptor);
    }
    if(saved->descriptor) LocalFree(saved->descriptor);
    return verified;
}

// The strict hook only needs to hold and query the exact relay process. Grant
// those read/synchronize rights to this one temporary identity, never write,
// injection, termination or access to another process. Restore the original
// process DACL after the job (and all descendants) has ended.
static DWORD relay_query_access(PSID sid,HANDLE *process,saved_acl *saved) {
    wchar_t text[32],image[MAX_PATH],*end=NULL;DWORD length=MAX_PATH;
    if(!GetEnvironmentVariableW(L"P0_EXPECTED_RELAY_PID",text,32))return ERROR_INVALID_PARAMETER;
    unsigned long pid=wcstoul(text,&end,10);if(!pid || !end || *end)return ERROR_INVALID_PARAMETER;
    *process=OpenProcess(READ_CONTROL|WRITE_DAC|PROCESS_QUERY_LIMITED_INFORMATION|SYNCHRONIZE,FALSE,(DWORD)pid);
    if(!*process)return GetLastError();
    if(!QueryFullProcessImageNameW(*process,0,image,&length))return GetLastError();
    if(_wcsicmp(image,L"C:\\P0Lab\\.local\\p0\\bin\\proxy-harbor-p0-relay.exe") || WaitForSingleObject(*process,0)!=WAIT_TIMEOUT)return ERROR_INVALID_OWNER;
    DWORD error=GetSecurityInfo(*process,SE_KERNEL_OBJECT,DACL_SECURITY_INFORMATION,NULL,NULL,&saved->acl,NULL,&saved->descriptor);
    if(error)return error;
    if(!saved->acl)return ERROR_INVALID_SECURITY_DESCR;
    EXPLICIT_ACCESSW access={0};access.grfAccessPermissions=SYNCHRONIZE|PROCESS_QUERY_LIMITED_INFORMATION;
    access.grfAccessMode=GRANT_ACCESS;access.grfInheritance=NO_INHERITANCE;access.Trustee.TrusteeForm=TRUSTEE_IS_SID;access.Trustee.ptstrName=(LPWSTR)sid;
    PACL changed=NULL;error=SetEntriesInAclW(1,&access,saved->acl,&changed);
    if(!error){error=SetSecurityInfo(*process,SE_KERNEL_OBJECT,DACL_SECURITY_INFORMATION,NULL,NULL,changed,NULL);if(!error)saved->changed=TRUE;}
    if(changed)LocalFree(changed);
    return error;
}
static BOOL restore_relay_acl(HANDLE process,saved_acl *saved) {
    BOOL ok=TRUE;
    if(saved->changed) {
        ok=SetSecurityInfo(process,SE_KERNEL_OBJECT,DACL_SECURITY_INFORMATION,NULL,NULL,saved->acl,NULL)==ERROR_SUCCESS;
        PACL actual=NULL;PSECURITY_DESCRIPTOR descriptor=NULL;
        if(ok)ok=GetSecurityInfo(process,SE_KERNEL_OBJECT,DACL_SECURITY_INFORMATION,NULL,NULL,&actual,NULL,&descriptor)==ERROR_SUCCESS;
        if(ok)ok=actual && actual->AclSize==saved->acl->AclSize && !memcmp(actual,saved->acl,actual->AclSize);
        if(descriptor)LocalFree(descriptor);
    }
    if(saved->descriptor)LocalFree(saved->descriptor);
    if(process)CloseHandle(process);
    return ok;
}

// GetTokenInformation's LPAC-specific class is not supported by all systems.
// Verify the documented access-control distinction instead, with a positive
// package-SID control. A failed AccessCheck is never interpreted as denial.
static DWORD access_probe(HANDLE token,const wchar_t *sddl,BOOL *allowed) {
    PSECURITY_DESCRIPTOR descriptor=NULL;
    HANDLE impersonation=NULL;
    DWORD error=0,granted=0,length=sizeof(PRIVILEGE_SET);
    PRIVILEGE_SET privileges={0};
    GENERIC_MAPPING mapping={1,2,4,7};
    if(!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl,SDDL_REVISION_1,&descriptor,NULL)) return GetLastError();
    if(!DuplicateToken(token,SecurityImpersonation,&impersonation)) error=GetLastError();
    else if(!AccessCheck(descriptor,impersonation,1,&mapping,&privileges,&length,&granted,allowed)) error=GetLastError();
    if(impersonation) CloseHandle(impersonation);
    LocalFree(descriptor);
    return error;
}

typedef DWORD (WINAPI *get_loopback_fn)(DWORD *,PSID_AND_ATTRIBUTES *);
typedef DWORD (WINAPI *set_loopback_fn)(DWORD,PSID_AND_ATTRIBUTES);
static void free_config(DWORD count,PSID_AND_ATTRIBUTES entries) {
    if(!entries) return;
    for(DWORD i=0;i<count;++i) HeapFree(GetProcessHeap(),0,entries[i].Sid);
    if(entries) HeapFree(GetProcessHeap(),0,entries);
}
// Add/remove only our new identity; preserve all other entries from the latest
// configuration. This API is used solely in the disposable diagnostic guest.
static DWORD loopback_identity(PSID sid,BOOL add,BOOL *mutated) {
    HMODULE module=LoadLibraryExW(L"FirewallAPI.dll",NULL,LOAD_LIBRARY_SEARCH_SYSTEM32);
    if(!module) return GetLastError();
    get_loopback_fn get_config=(get_loopback_fn)(void *)GetProcAddress(module,"NetworkIsolationGetAppContainerConfig");
    set_loopback_fn set_config=(set_loopback_fn)(void *)GetProcAddress(module,"NetworkIsolationSetAppContainerConfig");
    DWORD count=0,error=0,kept=0; PSID_AND_ATTRIBUTES before=NULL,after=NULL,changed=NULL;
    if(!get_config || !set_config) { error=ERROR_PROC_NOT_FOUND; goto cleanup; }
    error=get_config(&count,&before); if(error) goto cleanup;
    if(count>4096) { error=ERROR_INVALID_DATA; goto cleanup; }
    changed=HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,(count+1)*sizeof(*changed));
    if(!changed) { error=ERROR_NOT_ENOUGH_MEMORY; goto cleanup; }
    for(DWORD i=0;i<count;++i) {
        if(EqualSid(before[i].Sid,sid)) { if(add) { error=ERROR_ALREADY_EXISTS; goto cleanup; } }
        else changed[kept++]=before[i];
    }
    if(add) { changed[kept].Sid=sid; changed[kept++].Attributes=0; }
    error=set_config(kept,changed); if(error) goto cleanup;
    if(mutated) *mutated=TRUE;
    DWORD actual_count=0;
    error=get_config(&actual_count,&after); if(error) goto cleanup;
    if(actual_count!=kept) error=ERROR_INVALID_DATA;
    for(DWORD i=0;!error && i<kept;++i) {
        BOOL found=FALSE;
        for(DWORD j=0;j<actual_count;++j) if(EqualSid(changed[i].Sid,after[j].Sid) && changed[i].Attributes==after[j].Attributes) found=TRUE;
        if(!found) error=ERROR_INVALID_DATA;
    }
    free_config(actual_count,after);
cleanup:
    if(changed) HeapFree(GetProcessHeap(),0,changed);
    free_config(count,before);
    FreeLibrary(module);
    return error;
}

int wmain(int argc,wchar_t **argv) {
    if(!guest_only() || (argc!=3 && argc!=4 && argc!=5) || (wcscmp(argv[1],L"appcontainer")!=0 && wcscmp(argv[1],L"lpac")!=0 && wcscmp(argv[1],L"appcontainer-wfp")!=0) || wcslen(argv[2])!=16) {
        fputs("Guest-only fixed DNS isolation experiment\n",stderr); return 2;
    }
    for(int i=0;i<16;++i) if(!((argv[2][i]>=L'0'&&argv[2][i]<=L'9')||(argv[2][i]>=L'a'&&argv[2][i]<=L'f'))) return 2;
    const BOOL lpac=wcscmp(argv[1],L"lpac")==0;
    const BOOL package_policy=wcscmp(argv[1],L"appcontainer-wfp")==0;
    unsigned long relay_port=0;
    if(argc>=4) { wchar_t *end=NULL; relay_port=wcstoul(argv[3],&end,10); if(!end || *end || relay_port<1024 || relay_port>65535) return 2; }
    const wchar_t *scenario=L"ex-custom-server";
    if(argc==5) {
        const wchar_t *allowed[]={L"w",L"a",L"utf8",L"ex-sync",L"ex-async",L"ex-system",L"w-cache-only",L"ex-cache-only",L"ex-custom-server",L"transparent-public",L"transparent-winsock-root",L"transparent-winsock-child",L"transparent-winsock",L"transparent-dns-sync",L"transparent-dns-async",L"unlisted-tcp4",L"unlisted-tcp6",L"unlisted-udp4",L"unlisted-udp6"};
        BOOL valid=FALSE;
        for(size_t i=0;i<sizeof(allowed)/sizeof(allowed[0]);++i) if(wcscmp(argv[4],allowed[i])==0) valid=TRUE;
        if(wcscmp(argv[4],L"lifecycle")==0 && package_policy) valid=TRUE;
        if(!valid) return 2;
        scenario=argv[4];
    }
    const BOOL lifecycle=wcscmp(scenario,L"lifecycle")==0;
    const BOOL transparent=wcsncmp(scenario,L"transparent-",12)==0;
    const BOOL public_check=wcscmp(scenario,L"transparent-public")==0;
    const BOOL unlisted=wcsncmp(scenario,L"unlisted-",9)==0;
    const size_t total_paths=sizeof(paths)/sizeof(paths[0]);
    const size_t path_count=transparent?total_paths-2:(unlisted?total_paths:5);
    wchar_t profile[64],command[512];
    swprintf_s(profile,64,L"ProxyHarbor.P0.DNS.%lu.%ls",GetCurrentProcessId(),argv[1]);
    swprintf_s(command,512,L"\"%ls\" -dns-audit %ls -dns-audit-name %ls.p0-dns-audit.invalid",probe,scenario,argv[2]);
    if(transparent) {
        const wchar_t *api=wcsncmp(scenario,L"transparent-winsock",19)==0?L"winsock":(wcscmp(scenario,L"transparent-dns-sync")==0?L"dnsqueryex-sync":L"dnsqueryex-async");
        int depth=wcscmp(scenario,L"transparent-winsock-root")==0?0:(wcscmp(scenario,L"transparent-winsock-child")==0?1:2);
        swprintf_s(command,512,L"\"%ls\" -q -f C:\\P0Lab\\.local\\p0\\bin\\isolation-transparent.conf \"%ls\" -transparent-target no-local-dns.proxy-harbor.invalid:443 -resolve-api %ls -spawn-depth %d -use-helper=true",candidate,probe,api,depth);
        if(public_check)swprintf_s(command,512,L"\"%ls\" -q -f C:\\P0Lab\\.local\\p0\\bin\\isolation-transparent.conf \"%ls\" -public-check",candidate,probe);
    }
    if(unlisted){wchar_t text[8],*end=NULL;if(!package_policy||!GetEnvironmentVariableW(L"P0_UNLISTED_TEST_PORT",text,8))return 2;unsigned long port=wcstoul(text,&end,10);if(!end||*end||port<1024||port>65535||port==relay_port)return 2;const wchar_t *network=scenario+9;const wchar_t *host=network[3]==L'6'?L"[::1]":L"127.0.0.1";swprintf_s(command,512,L"\"%ls\" -network %ls -address %ls:%lu",control_probe,network,host,port);}
    if(lifecycle)swprintf_s(command,512,L"\"%ls\" -lifecycle",probe);
    PSID sid=NULL;
    BOOL created=FALSE,launched=FALSE,acl_verified=TRUE,profile_deleted=FALSE,timed_out=FALSE;
    DWORD error=0,exit_code=0,is_container=0,is_lpac=0,capability_count=MAXDWORD,bytes=0;
    BOOL package_access=FALSE,all_packages_access=FALSE;
    BOOL loopback_changed=FALSE,loopback_restored=TRUE,proxy_attempted=FALSE;
    DWORD dns_exit_code=0,proxy_exit_code=0;
    saved_acl saved[sizeof(paths)/sizeof(paths[0])]={0};
    saved_acl relay_acl={0};HANDLE relay_access=NULL;BOOL relay_acl_restored=TRUE;
    P0_ISOLATION_POLICY isolated_policy={0};BOOL package_policy_restored=TRUE;unsigned package_rules=0;
    STARTUPINFOEXW startup={0}; PROCESS_INFORMATION process={0};
    LPPROC_THREAD_ATTRIBUTE_LIST attributes=NULL;
    HANDLE inherited[3]={NULL,NULL,NULL},token=NULL,job=NULL;
    char *sid_text=NULL;
    HRESULT hr=CreateAppContainerProfile(profile,profile,L"Disposable Proxy Harbor P0 DNS experiment",NULL,0,&sid);
    if(FAILED(hr)) { error=(DWORD)hr; goto cleanup; }
    created=TRUE;
    if(!ConvertSidToStringSidA(sid,&sid_text)) { error=GetLastError(); goto cleanup; }
    for(size_t i=0;i<path_count;++i) {
        if(unlisted && i>=5 && i<total_paths-2)continue;
        error=grant_read(sid,paths[i],&saved[i]); if(error) goto cleanup;
    }
    if(relay_port && !package_policy) { error=loopback_identity(sid,TRUE,&loopback_changed); if(error) goto cleanup; }
    if(package_policy) {error=P0InstallIsolationPolicy(sid,(UINT16)relay_port,&isolated_policy);if(error)goto cleanup;package_rules=isolated_policy.installed;}
    if(transparent) {error=relay_query_access(sid,&relay_access,&relay_acl);if(error)goto cleanup;}
    SIZE_T size=0;
    InitializeProcThreadAttributeList(NULL,lpac?2:1,0,&size);
    attributes=HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,size);
    if(!attributes) { error=ERROR_NOT_ENOUGH_MEMORY; goto cleanup; }
    if(!InitializeProcThreadAttributeList(attributes,lpac?2:1,0,&size)) { error=GetLastError(); HeapFree(GetProcessHeap(),0,attributes); attributes=NULL; goto cleanup; }
    SECURITY_CAPABILITIES capabilities={0}; capabilities.AppContainerSid=sid;
    if(!UpdateProcThreadAttribute(attributes,0,PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,&capabilities,sizeof(capabilities),NULL,NULL)) { error=GetLastError(); goto cleanup; }
    DWORD opt_out=PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT;
    if(lpac && !UpdateProcThreadAttribute(attributes,0,PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY,&opt_out,sizeof(opt_out),NULL,NULL)) { error=GetLastError(); goto cleanup; }
    if(!SetEnvironmentVariableW(L"P0_REQUIRE_APP_CONTAINER",L"1")) {error=GetLastError();goto cleanup;}
    for(int i=0;i<3;++i) {
        DWORD standard=i==0?STD_INPUT_HANDLE:(i==1?STD_OUTPUT_HANDLE:STD_ERROR_HANDLE);
        HANDLE source=GetStdHandle(standard);
        if(source==NULL || source==INVALID_HANDLE_VALUE || !DuplicateHandle(GetCurrentProcess(),source,GetCurrentProcess(),&inherited[i],0,TRUE,DUPLICATE_SAME_ACCESS)) { error=GetLastError(); goto cleanup; }
    }
    startup.StartupInfo.cb=sizeof(startup);
    startup.StartupInfo.dwFlags=STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput=inherited[0]; startup.StartupInfo.hStdOutput=inherited[1]; startup.StartupInfo.hStdError=inherited[2];
    startup.lpAttributeList=attributes;
    job=CreateJobObjectW(NULL,NULL);
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits={0}; limits.BasicLimitInformation.LimitFlags=JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if(!job || !SetInformationJobObject(job,JobObjectExtendedLimitInformation,&limits,sizeof(limits))) { error=GetLastError(); goto cleanup; }
    for(int pass=0;pass<((relay_port && !public_check && !lifecycle)?2:1);++pass) {
    if(pass==1) {
        puts("{\"isolationPhase\":\"explicit_proxy\"}");fflush(stdout);
        proxy_attempted=TRUE;
        swprintf_s(command,512,L"\"%ls\" -proxy-protocol socks5 -proxy 127.0.0.1:%lu -target %ls.p0-dns-audit.invalid:443",probe,relay_port,argv[2]);
    }
    const wchar_t *image=(transparent && pass==0)?candidate:((unlisted && pass==0)?control_probe:probe);
    if(!CreateProcessW(image,command,NULL,NULL,TRUE,EXTENDED_STARTUPINFO_PRESENT|CREATE_SUSPENDED|CREATE_NO_WINDOW,NULL,L"C:\\P0Lab",&startup.StartupInfo,&process)) { error=GetLastError(); goto cleanup; }
    launched=TRUE;
    if(!AssignProcessToJobObject(job,process.hProcess)) { error=GetLastError(); goto cleanup; }
    if(!OpenProcessToken(process.hProcess,TOKEN_QUERY|TOKEN_DUPLICATE,&token) ||
       !GetTokenInformation(token,TokenIsAppContainer,&is_container,sizeof(is_container),&bytes)) { error=GetLastError(); goto cleanup; }
    GetTokenInformation(token,TokenCapabilities,NULL,0,&bytes);
    TOKEN_GROUPS *groups=HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,bytes);
    if(!groups) { error=ERROR_NOT_ENOUGH_MEMORY; goto cleanup; }
    if(GetTokenInformation(token,TokenCapabilities,groups,bytes,&bytes)) capability_count=groups->GroupCount;
    else error=GetLastError();
    HeapFree(GetProcessHeap(),0,groups);
    if(error) goto cleanup;
    wchar_t *wide_sid=NULL,package_sddl[256];
    if(!ConvertSidToStringSidW(sid,&wide_sid)) { error=GetLastError(); goto cleanup; }
    swprintf_s(package_sddl,256,L"O:SYG:SYD:(A;;0x1;;;WD)(A;;0x1;;;%ls)",wide_sid);
    LocalFree(wide_sid);
    error=access_probe(token,package_sddl,&package_access);
    if(!error) error=access_probe(token,L"O:SYG:SYD:(A;;0x1;;;WD)(A;;0x1;;;AC)",&all_packages_access);
    is_lpac=package_access && !all_packages_access;
    if(error || !is_container || !package_access || (is_lpac!=0)!=lpac || capability_count!=0) { if(!error) error=ERROR_INVALID_TOKEN; goto cleanup; }
    if(ResumeThread(process.hThread)==MAXDWORD) { error=GetLastError(); goto cleanup; }
    if(WaitForSingleObject(process.hProcess,lifecycle?180000:(public_check?25000:4000))!=WAIT_OBJECT_0) { timed_out=TRUE; error=WAIT_TIMEOUT; goto cleanup; }
    if(!GetExitCodeProcess(process.hProcess,&exit_code)) error=GetLastError();
    if(pass==0) dns_exit_code=exit_code; else proxy_exit_code=exit_code;
    CloseHandle(process.hProcess); CloseHandle(process.hThread); ZeroMemory(&process,sizeof(process));
    CloseHandle(token); token=NULL;
    if(error) goto cleanup;
    }
cleanup:
    if(process.hProcess) {
        if(WaitForSingleObject(process.hProcess,0)!=WAIT_OBJECT_0) { TerminateProcess(process.hProcess,1); WaitForSingleObject(process.hProcess,1000); }
        CloseHandle(process.hProcess); CloseHandle(process.hThread);
    }
    if(token) CloseHandle(token);
    if(job) CloseHandle(job);
    package_policy_restored=P0RemoveIsolationPolicy(&isolated_policy);
    relay_acl_restored=restore_relay_acl(relay_access,&relay_acl);
    for(int i=0;i<3;++i) if(inherited[i]) CloseHandle(inherited[i]);
    if(attributes) { DeleteProcThreadAttributeList(attributes); HeapFree(GetProcessHeap(),0,attributes); }
    if(loopback_changed) loopback_restored=loopback_identity(sid,FALSE,NULL)==ERROR_SUCCESS;
    for(size_t i=path_count;i>0;--i) if(!restore_acl(paths[i-1],&saved[i-1])) acl_verified=FALSE;
    if(created && package_policy_restored) profile_deleted=SUCCEEDED(DeleteAppContainerProfile(profile));
    printf("{\"isolationResult\":true,\"mode\":\"%s\",\"launched\":%s,\"error\":%lu,\"childExitCode\":%lu,\"proxyAttempted\":%s,\"proxyChildExitCode\":%lu,\"loopbackEnabled\":%s,\"loopbackRestored\":%s,\"timedOut\":%s,\"isAppContainer\":%lu,\"isLPAC\":%lu,\"lpacVerification\":\"access_check_pair\",\"packageSidAccess\":%s,\"allApplicationPackagesAccess\":%s,\"capabilityCount\":%lu,\"sid\":\"%s\",\"aclRestored\":%s,\"relayAclRestored\":%s,\"packageRulesInstalled\":%u,\"packagePolicyRestored\":%s,\"profileDeleted\":%s}\n",
        lpac?"lpac":(package_policy?"appcontainer-wfp":"appcontainer"),launched?"true":"false",error,dns_exit_code,proxy_attempted?"true":"false",proxy_exit_code,loopback_changed?"true":"false",loopback_restored?"true":"false",timed_out?"true":"false",is_container,is_lpac,package_access?"true":"false",all_packages_access?"true":"false",capability_count,sid_text?sid_text:"",acl_verified?"true":"false",relay_acl_restored?"true":"false",package_rules,package_policy_restored?"true":"false",profile_deleted?"true":"false");
    if(sid_text) LocalFree(sid_text);
    if(sid) FreeSid(sid);
    return error || !launched || !acl_verified || !profile_deleted || !loopback_restored || !relay_acl_restored || !package_policy_restored ? 1 : 0;
}
