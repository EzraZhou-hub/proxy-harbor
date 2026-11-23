// Guest-owned AppContainer SID policy. Four deny rules, one exact outbound
// loopback permit, one exact relay-side loopback accept permit. No debug
// loopback exemption and no Internet capability is granted.
#include "isolation_policy.h"
#include <stdio.h>
#include <wchar.h>
#include <sddl.h>
#include <tlhelp32.h>

static const GUID sublayer={0x78c0ad17,0x2bd0,0x47bd,{0xb5,0xec,0x01,0x32,0xd7,0x3b,0x3e,0x8c}};
static const GUID keys[6]={
{0xc7abcf81,0xe42f,0x4276,{0x89,0x4c,0x6b,0xa6,0xab,0x08,0x03,0xe1}},
{0xc7abcf82,0xe42f,0x4276,{0x89,0x4c,0x6b,0xa6,0xab,0x08,0x03,0xe1}},
{0xc7abcf83,0xe42f,0x4276,{0x89,0x4c,0x6b,0xa6,0xab,0x08,0x03,0xe1}},
{0xc7abcf84,0xe42f,0x4276,{0x89,0x4c,0x6b,0xa6,0xab,0x08,0x03,0xe1}},
{0xc7abcf85,0xe42f,0x4276,{0x89,0x4c,0x6b,0xa6,0xab,0x08,0x03,0xe1}},
{0xc7abcf86,0xe42f,0x4276,{0x89,0x4c,0x6b,0xa6,0xab,0x08,0x03,0xe1}}};
static wchar_t owner_name[]=L"Proxy Harbor P0 disposable isolated SID only";

static void make_filter(P0_ISOLATION_POLICY *p,int i,FWPM_FILTER0 *f,FWPM_FILTER_CONDITION0 c[4]){
    ZeroMemory(f,sizeof(*f));ZeroMemory(c,4*sizeof(*c));
    f->filterKey=keys[i];f->subLayerKey=sublayer;f->layerKey=i==3?FWPM_LAYER_ALE_AUTH_CONNECT_V6:(i==5?FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4:FWPM_LAYER_ALE_AUTH_CONNECT_V4);
    f->displayData.name=owner_name;f->flags=FWPM_FILTER_FLAG_PERSISTENT;f->action.type=i<4?FWP_ACTION_BLOCK:FWP_ACTION_PERMIT;
    if(i>=4)f->flags|=FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT;
    f->weight.type=FWP_UINT8;f->weight.uint8=15;f->providerData.data=p->owner;f->providerData.size=p->owner_size;f->filterCondition=c;
    c[0].fieldKey=i==5?FWPM_CONDITION_ALE_APP_ID:FWPM_CONDITION_ALE_PACKAGE_ID;c[0].matchType=FWP_MATCH_EQUAL;
    if(i==5){c[0].conditionValue.type=FWP_BYTE_BLOB_TYPE;c[0].conditionValue.byteBlob=p->relay_app;}else{c[0].conditionValue.type=FWP_SID;c[0].conditionValue.sid=(SID *)p->sid;}
    f->numFilterConditions=i==3?1:(i<3?2:4);
    if(i==3)return;
    if(i<3){c[1].matchType=FWP_MATCH_NOT_EQUAL;if(i==0){c[1].fieldKey=FWPM_CONDITION_IP_REMOTE_ADDRESS;c[1].conditionValue.type=FWP_UINT32;c[1].conditionValue.uint32=0x7f000001;}if(i==1){c[1].fieldKey=FWPM_CONDITION_IP_PROTOCOL;c[1].conditionValue.type=FWP_UINT8;c[1].conditionValue.uint8=6;}if(i==2){c[1].fieldKey=FWPM_CONDITION_IP_REMOTE_PORT;c[1].conditionValue.type=FWP_UINT16;c[1].conditionValue.uint16=p->port;}return;}
    c[1].fieldKey=i==5?FWPM_CONDITION_IP_LOCAL_ADDRESS:FWPM_CONDITION_IP_REMOTE_ADDRESS;c[1].matchType=FWP_MATCH_EQUAL;c[1].conditionValue.type=FWP_UINT32;c[1].conditionValue.uint32=0x7f000001;
    c[2].fieldKey=FWPM_CONDITION_IP_PROTOCOL;c[2].matchType=FWP_MATCH_EQUAL;c[2].conditionValue.type=FWP_UINT8;c[2].conditionValue.uint8=6;
    c[3].fieldKey=i==5?FWPM_CONDITION_IP_LOCAL_PORT:FWPM_CONDITION_IP_REMOTE_PORT;c[3].matchType=FWP_MATCH_EQUAL;c[3].conditionValue.type=FWP_UINT16;c[3].conditionValue.uint16=p->port;
}
static BOOL equal_condition(const FWPM_FILTER_CONDITION0 *a,const FWPM_FILTER_CONDITION0 *b){
    if(!IsEqualGUID(&a->fieldKey,&b->fieldKey)||a->matchType!=b->matchType||a->conditionValue.type!=b->conditionValue.type)return FALSE;
    switch(a->conditionValue.type){case FWP_UINT32:return a->conditionValue.uint32==b->conditionValue.uint32;case FWP_UINT16:return a->conditionValue.uint16==b->conditionValue.uint16;case FWP_UINT8:return a->conditionValue.uint8==b->conditionValue.uint8;case FWP_SID:return a->conditionValue.sid&&IsValidSid(a->conditionValue.sid)&&EqualSid(a->conditionValue.sid,b->conditionValue.sid);case FWP_BYTE_BLOB_TYPE:{FWP_BYTE_BLOB *x=a->conditionValue.byteBlob,*y=b->conditionValue.byteBlob;return x&&x->data&&x->size==y->size&&!memcmp(x->data,y->data,x->size);}default:return FALSE;}
}
static BOOL owned_filter(P0_ISOLATION_POLICY *p,int i,const FWPM_FILTER0 *actual){
    FWPM_FILTER0 expected;FWPM_FILTER_CONDITION0 c[4];make_filter(p,i,&expected,c);
    // BFE adds INDEXED on this Windows build. It is a performance flag, not
    // an action/ownership change. No other unexpected flag is accepted.
    if(!IsEqualGUID(&actual->filterKey,&expected.filterKey)||!IsEqualGUID(&actual->subLayerKey,&sublayer)||!IsEqualGUID(&actual->layerKey,&expected.layerKey)||(actual->flags&~FWPM_FILTER_FLAG_INDEXED)!=expected.flags||actual->action.type!=expected.action.type||!actual->displayData.name||wcscmp(actual->displayData.name,owner_name)||actual->providerData.size!=p->owner_size||!actual->providerData.data||memcmp(actual->providerData.data,p->owner,p->owner_size)||actual->numFilterConditions!=expected.numFilterConditions||!actual->filterCondition)return FALSE;
    for(UINT32 j=0;j<expected.numFilterConditions;++j){BOOL found=FALSE;for(UINT32 k=0;k<actual->numFilterConditions;++k)if(equal_condition(&actual->filterCondition[k],&c[j]))found=TRUE;if(!found)return FALSE;}
    return TRUE;
}
DWORD P0InstallIsolationPolicy(PSID sid,UINT16 port,P0_ISOLATION_POLICY *p){
    ZeroMemory(p,sizeof(*p));if(!IsValidSid(sid)||GetLengthSid(sid)>SECURITY_MAX_SID_SIZE||port<1024)return ERROR_INVALID_PARAMETER;
    p->sid=sid;p->port=port;p->owner_size=8+GetLengthSid(sid);memcpy(p->owner,"P0SIDv1",7);memcpy(p->owner+8,sid,GetLengthSid(sid));p->owner[7]=0; // Port is separately validated in each rule.
    DWORD error=FwpmEngineOpen0(NULL,RPC_C_AUTHN_WINNT,NULL,NULL,&p->engine);if(error)return error;
    error=FwpmGetAppIdFromFileName0(L"C:\\P0Lab\\.local\\p0\\bin\\proxy-harbor-p0-relay.exe",&p->relay_app);if(error)return error;
    LPSTR sid_text=NULL;if(!ConvertSidToStringSidA(sid,&sid_text))return GetLastError();int length=sprintf_s(p->journal,sizeof(p->journal),"{\"owner\":\"proxy-harbor-p0-isolated-sid\",\"sid\":\"%s\",\"port\":%u,\"ruleCount\":6}\n",sid_text,port);LocalFree(sid_text);if(length<=0)return ERROR_INVALID_DATA;p->journal_size=(DWORD)length;
    HANDLE file=CreateFileW(L"C:\\P0Lab\\.local\\p0\\isolated-sid-recovery.json",GENERIC_WRITE,0,NULL,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,NULL);if(file==INVALID_HANDLE_VALUE)return GetLastError();p->journal_created=TRUE;DWORD written=0;BOOL recorded=WriteFile(file,p->journal,p->journal_size,&written,NULL)&&written==p->journal_size&&FlushFileBuffers(file);CloseHandle(file);if(!recorded)return ERROR_WRITE_FAULT;
    error=FwpmTransactionBegin0(p->engine,0);if(error)return error;
    for(int i=0;i<6;++i){FWPM_FILTER0 *old=NULL;error=FwpmFilterGetByKey0(p->engine,&keys[i],&old);if(!error){FwpmFreeMemory0((void **)&old);error=ERROR_ALREADY_EXISTS;break;}if(error==FWP_E_FILTER_NOT_FOUND)error=ERROR_SUCCESS;if(error)break;}
    if(!error){FWPM_SUBLAYER0 *old=NULL;error=FwpmSubLayerGetByKey0(p->engine,&sublayer,&old);if(!error){BOOL match=old->displayData.name&&!wcscmp(old->displayData.name,owner_name);FwpmFreeMemory0((void **)&old);if(!match)error=ERROR_INVALID_OWNER;}else if(error==FWP_E_SUBLAYER_NOT_FOUND){FWPM_SUBLAYER0 s={0};s.subLayerKey=sublayer;s.displayData.name=owner_name;s.flags=FWPM_SUBLAYER_FLAG_PERSISTENT;s.weight=0xfff0;error=FwpmSubLayerAdd0(p->engine,&s,NULL);}}
    for(int i=0;!error&&i<6;++i){FWPM_FILTER0 f;FWPM_FILTER_CONDITION0 c[4];make_filter(p,i,&f,c);error=FwpmFilterAdd0(p->engine,&f,NULL,NULL);}
    if(!error){error=FwpmTransactionCommit0(p->engine);if(!error)p->installed=6;}
    if(error)FwpmTransactionAbort0(p->engine);
    return error;
}
static HANDLE verified_journal(P0_ISOLATION_POLICY *p){
    // Deny writes and replacement until the policy transaction has finished.
    HANDLE file=CreateFileW(L"C:\\P0Lab\\.local\\p0\\isolated-sid-recovery.json",GENERIC_READ|DELETE,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
    char actual[512];DWORD count=0;BOOL match=file!=INVALID_HANDLE_VALUE;
    if(match)match=GetFileSize(file,NULL)==p->journal_size&&ReadFile(file,actual,sizeof(actual),&count,NULL)&&count==p->journal_size&&!memcmp(actual,p->journal,count);
    if(!match){if(file!=INVALID_HANDLE_VALUE)CloseHandle(file);return INVALID_HANDLE_VALUE;}
    return file;
}
BOOL P0RemoveIsolationPolicy(P0_ISOLATION_POLICY *p){
    // Refuse before changing policy. Keep the live context for an explicit retry.
    HANDLE journal=INVALID_HANDLE_VALUE;
    if(p->journal_created){journal=verified_journal(p);if(journal==INVALID_HANDLE_VALUE)return FALSE;}
    BOOL verified=TRUE;
    if(p->installed){DWORD error=FwpmTransactionBegin0(p->engine,0);for(int i=0;!error&&i<6;++i){FWPM_FILTER0 *f=NULL;error=FwpmFilterGetByKey0(p->engine,&keys[i],&f);if(!error){if(!owned_filter(p,i,f))error=ERROR_INVALID_OWNER;FwpmFreeMemory0((void **)&f);}}
        for(int i=0;!error&&i<6;++i)error=FwpmFilterDeleteByKey0(p->engine,&keys[i]);
        if(!error){FWPM_SUBLAYER0 *s=NULL;error=FwpmSubLayerGetByKey0(p->engine,&sublayer,&s);if(!error){BOOL own=s->displayData.name&&!wcscmp(s->displayData.name,owner_name);FwpmFreeMemory0((void **)&s);error=own?FwpmSubLayerDeleteByKey0(p->engine,&sublayer):ERROR_INVALID_OWNER;}}
        if(!error)error=FwpmTransactionCommit0(p->engine);if(error)FwpmTransactionAbort0(p->engine);verified=error==ERROR_SUCCESS;
        for(int i=0;verified&&i<6;++i){FWPM_FILTER0 *f=NULL;DWORD e=FwpmFilterGetByKey0(p->engine,&keys[i],&f);if(f)FwpmFreeMemory0((void **)&f);verified=e==FWP_E_FILTER_NOT_FOUND;}
    }
    if(verified&&p->journal_created){FILE_DISPOSITION_INFO disposition={TRUE};verified=SetFileInformationByHandle(journal,FileDispositionInfo,&disposition,sizeof(disposition));}
    if(journal!=INVALID_HANDLE_VALUE)CloseHandle(journal);
    if(p->relay_app)FwpmFreeMemory0((void **)&p->relay_app);if(p->engine)FwpmEngineClose0(p->engine);ZeroMemory(p,sizeof(*p));return verified;
}

DWORD P0RecoverIsolationPolicyForSid(PSID sid,UINT16 port){
    P0_ISOLATION_POLICY p={0};if(!IsValidSid(sid)||GetLengthSid(sid)>SECURITY_MAX_SID_SIZE||port<1024)return ERROR_INVALID_PARAMETER;
    p.sid=sid;p.port=port;p.owner_size=8+GetLengthSid(sid);memcpy(p.owner,"P0SIDv1",7);memcpy(p.owner+8,sid,GetLengthSid(sid));
    char *text=NULL;if(!ConvertSidToStringSidA(sid,&text))return GetLastError();
    int length=sprintf_s(p.journal,sizeof(p.journal),"{\"owner\":\"proxy-harbor-p0-isolated-sid\",\"sid\":\"%s\",\"port\":%u,\"ruleCount\":6}\n",text,port);LocalFree(text);if(length<=0)return ERROR_INVALID_DATA;
    p.journal_size=(DWORD)length;p.journal_created=TRUE;p.installed=6;
    DWORD error=FwpmEngineOpen0(NULL,RPC_C_AUTHN_WINNT,NULL,NULL,&p.engine);
    if(!error)error=FwpmGetAppIdFromFileName0(L"C:\\P0Lab\\.local\\p0\\bin\\proxy-harbor-p0-relay.exe",&p.relay_app);
    if(!error&&!P0RemoveIsolationPolicy(&p))error=ERROR_INVALID_OWNER;
    if(p.relay_app)FwpmFreeMemory0((void **)&p.relay_app);if(p.engine)FwpmEngineClose0(p.engine);return error;
}
#ifdef P0_ISOLATION_INSPECT
static BOOL fixture_running(void){
    HANDLE snapshot=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);if(snapshot==INVALID_HANDLE_VALUE)return TRUE;
    PROCESSENTRY32W entry={0};entry.dwSize=sizeof(entry);BOOL running=FALSE;
    for(BOOL more=Process32FirstW(snapshot,&entry);more;more=Process32NextW(snapshot,&entry)){
        if(_wcsicmp(entry.szExeFile,L"proxy-harbor-p0-probe.exe")&&_wcsicmp(entry.szExeFile,L"proxy-harbor-p0-helper.exe")&&_wcsicmp(entry.szExeFile,L"proxychains_win32_x64.exe"))continue;
        HANDLE process=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,FALSE,entry.th32ProcessID);wchar_t image[MAX_PATH];DWORD size=MAX_PATH;
        if(!process){running=TRUE;break;}
        if(!QueryFullProcessImageNameW(process,0,image,&size)||!_wcsnicmp(image,L"C:\\P0Lab\\",9))running=TRUE;
        CloseHandle(process);if(running)break;
    }
    CloseHandle(snapshot);return running;
}
static DWORD recover_fixture(void){
    wchar_t cwd[MAX_PATH],image[MAX_PATH],marker[32];
    if(!GetCurrentDirectoryW(MAX_PATH,cwd)||_wcsicmp(cwd,L"C:\\P0Lab")||!GetModuleFileNameW(NULL,image,MAX_PATH)||_wcsicmp(image,L"C:\\P0Lab\\.local\\p0\\bin\\p0-isolation-inspect.exe")||!GetEnvironmentVariableW(L"PROXY_HARBOR_P0_GUEST",marker,32)||wcscmp(marker,L"offline-lab"))return ERROR_ACCESS_DENIED;
    HANDLE file=CreateFileW(L"C:\\P0Lab\\.local\\p0\\isolated-sid-recovery.json",GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
    if(file==INVALID_HANDLE_VALUE)return GetLastError();
    char data[512]={0},sid_text[192]={0};DWORD size=GetFileSize(file,NULL),read=0;unsigned port=0;
    BOOL ok=size>0&&size<sizeof(data)&&ReadFile(file,data,size,&read,NULL)&&read==size;CloseHandle(file);
    if(!ok||sscanf_s(data,"{\"owner\":\"proxy-harbor-p0-isolated-sid\",\"sid\":\"%191[^\"]\",\"port\":%u,\"ruleCount\":6}",sid_text,(unsigned)sizeof(sid_text),&port)!=2||port<1024||port>65535||strncmp(sid_text,"S-1-15-2-",9))return ERROR_INVALID_DATA;
    P0_ISOLATION_POLICY p={0};
    if(!ConvertStringSidToSidA(sid_text,&p.sid)||!IsValidSid(p.sid)||GetLengthSid(p.sid)>SECURITY_MAX_SID_SIZE)return ERROR_INVALID_SID;
    p.port=(UINT16)port;p.owner_size=8+GetLengthSid(p.sid);memcpy(p.owner,"P0SIDv1",7);memcpy(p.owner+8,p.sid,GetLengthSid(p.sid));
    int length=sprintf_s(p.journal,sizeof(p.journal),"{\"owner\":\"proxy-harbor-p0-isolated-sid\",\"sid\":\"%s\",\"port\":%u,\"ruleCount\":6}\n",sid_text,port);
    if(length<=0||(DWORD)length!=size||memcmp(data,p.journal,size)){LocalFree(p.sid);return ERROR_INVALID_DATA;}
    p.journal_size=size;p.journal_created=TRUE;p.installed=6;
    PSID allocated=p.sid;DWORD error=FwpmEngineOpen0(NULL,RPC_C_AUTHN_WINNT,NULL,NULL,&p.engine);
    if(!error)error=FwpmGetAppIdFromFileName0(L"C:\\P0Lab\\.local\\p0\\bin\\proxy-harbor-p0-relay.exe",&p.relay_app);
    for(int i=0;!error&&i<6;++i){FWPM_FILTER0 *f=NULL;error=FwpmFilterGetByKey0(p.engine,&keys[i],&f);if(!error&&!owned_filter(&p,i,f))error=ERROR_INVALID_OWNER;if(f)FwpmFreeMemory0((void **)&f);}
    if(!error&&fixture_running())error=ERROR_BUSY;
    if(!error&&!P0RemoveIsolationPolicy(&p))error=ERROR_INVALID_OWNER;
    if(p.relay_app)FwpmFreeMemory0((void **)&p.relay_app);if(p.engine)FwpmEngineClose0(p.engine);LocalFree(allocated);return error;
}
int wmain(int argc,wchar_t **argv){if(argc==2&&!wcscmp(argv[1],L"recover-fixture-only")){DWORD e=recover_fixture();printf("{\"windowsError\":%lu,\"recovered\":%s}\n",e,e?"false":"true");return e?1:0;}if(argc!=2||wcscmp(argv[1],L"inspect"))return 2;HANDLE engine=NULL;DWORD error=FwpmEngineOpen0(NULL,RPC_C_AUTHN_WINNT,NULL,NULL,&engine);unsigned count=0;if(!error){for(int i=0;i<6;++i){FWPM_FILTER0 *f=NULL;DWORD e=FwpmFilterGetByKey0(engine,&keys[i],&f);if(e==FWP_E_FILTER_NOT_FOUND)continue;if(e){error=e;break;}if(!f->displayData.name||wcscmp(f->displayData.name,owner_name))error=ERROR_INVALID_OWNER;++count;FwpmFreeMemory0((void **)&f);if(error)break;}FwpmEngineClose0(engine);}printf("{\"windowsError\":%lu,\"rulesPresent\":%u,\"systemChanged\":false,\"scope\":\"read-only isolated SID fixture inventory\"}\n",error,count);return error?1:0;}
#endif
