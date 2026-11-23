// Guest-only observation of the fixed probe's UDP request to 1.1.1.1:53.
// Save/restore diagnostic collection; print only matching project drop events.
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <fwpmu.h>
#include <stdio.h>
#include <wchar.h>

static const wchar_t probe[]=L"C:\\P0Lab\\.local\\p0\\bin\\proxy-harbor-p0-probe.exe";
static const GUID keys[4]={
{0xc7abcf41,0xe42f,0x4276,{0x89,0x4c,0x6b,0xa6,0xab,0x08,0x03,0xe1}},
{0xc7abcf42,0xe42f,0x4276,{0x89,0x4c,0x6b,0xa6,0xab,0x08,0x03,0xe1}},
{0xc7abcf43,0xe42f,0x4276,{0x89,0x4c,0x6b,0xa6,0xab,0x08,0x03,0xe1}},
{0xc7abcf44,0xe42f,0x4276,{0x89,0x4c,0x6b,0xa6,0xab,0x08,0x03,0xe1}}};
static BOOL guest_only(void){wchar_t cwd[MAX_PATH],marker[32],image[MAX_PATH];return GetCurrentDirectoryW(MAX_PATH,cwd)&&!_wcsicmp(cwd,L"C:\\P0Lab")&&GetEnvironmentVariableW(L"PROXY_HARBOR_P0_GUEST",marker,32)&&!wcscmp(marker,L"offline-lab")&&GetModuleFileNameW(NULL,image,MAX_PATH)&&!_wcsicmp(image,L"C:\\P0Lab\\.local\\p0\\bin\\p0-net-events.exe");}

int wmain(int argc,wchar_t **argv){
    if(!guest_only()||argc!=2||wcscmp(argv[1],L"observe-fixed-public-udp")){fputs("Guest-only fixed public UDP event observer\n",stderr);return 2;}
    HANDLE engine=NULL;FWP_BYTE_BLOB *app=NULL;FWP_VALUE0 *option=NULL;DWORD error=0,previous=0,exit_code=MAXDWORD;BOOL saved=FALSE,restored=TRUE;
    UINT64 filter_ids[4]={0},matched_filter=0;unsigned matched=0;FILETIME began;
    PROCESS_INFORMATION process={0};STARTUPINFOW startup={0};HANDLE inherited[3]={NULL,NULL,NULL};
    error=FwpmEngineOpen0(NULL,RPC_C_AUTHN_WINNT,NULL,NULL,&engine);if(error)goto cleanup;
    error=FwpmGetAppIdFromFileName0(probe,&app);if(error)goto cleanup;
    for(int i=0;i<4;++i){FWPM_FILTER0 *f=NULL;error=FwpmFilterGetByKey0(engine,&keys[i],&f);if(error)goto cleanup;BOOL owner=f->displayData.name&&!wcscmp(f->displayData.name,L"Proxy Harbor P0 relay fixture only")&&f->action.type==FWP_ACTION_BLOCK&&(f->flags&FWPM_FILTER_FLAG_PERSISTENT)&&!(f->flags&FWPM_FILTER_FLAG_DISABLED);BOOL identity=FALSE;for(UINT32 j=0;j<f->numFilterConditions;++j){FWPM_FILTER_CONDITION0 *c=&f->filterCondition[j];if(IsEqualGUID(&c->fieldKey,&FWPM_CONDITION_ALE_APP_ID)&&c->matchType==FWP_MATCH_EQUAL&&c->conditionValue.type==FWP_BYTE_BLOB_TYPE){FWP_BYTE_BLOB *b=c->conditionValue.byteBlob;identity=b&&b->data&&b->size==app->size&&!memcmp(b->data,app->data,app->size);}}filter_ids[i]=f->filterId;FwpmFreeMemory0((void **)&f);if(!owner||!identity){error=ERROR_INVALID_OWNER;goto cleanup;}}
    error=FwpmEngineGetOption0(engine,FWPM_ENGINE_COLLECT_NET_EVENTS,&option);if(error)goto cleanup;if(option->type!=FWP_UINT32||option->uint32>1){error=ERROR_INVALID_DATA;goto cleanup;}previous=option->uint32;
    HANDLE journal=CreateFileW(L"C:\\P0Lab\\.local\\p0\\net-event-recovery.json",GENERIC_WRITE,0,NULL,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,NULL);
    if(journal==INVALID_HANDLE_VALUE){error=GetLastError();goto cleanup;}
    char record[128];DWORD written;int length=sprintf_s(record,sizeof(record),"{\"guestOnly\":true,\"previousCollectNetEvents\":%lu}\n",previous);
    BOOL recorded=WriteFile(journal,record,(DWORD)length,&written,NULL)&&written==(DWORD)length&&FlushFileBuffers(journal);CloseHandle(journal);if(!recorded){error=ERROR_WRITE_FAULT;goto cleanup;}
    saved=TRUE;
    if(!previous){FWP_VALUE0 enabled={0};enabled.type=FWP_UINT32;enabled.uint32=1;error=FwpmEngineSetOption0(engine,FWPM_ENGINE_COLLECT_NET_EVENTS,&enabled);if(error)goto cleanup;}
    GetSystemTimeAsFileTime(&began);
    for(int i=0;i<3;++i){DWORD id=i==0?STD_INPUT_HANDLE:(i==1?STD_OUTPUT_HANDLE:STD_ERROR_HANDLE);HANDLE source=GetStdHandle(id);if(!source||source==INVALID_HANDLE_VALUE||!DuplicateHandle(GetCurrentProcess(),source,GetCurrentProcess(),&inherited[i],0,TRUE,DUPLICATE_SAME_ACCESS)){error=GetLastError();goto cleanup;}}
    startup.cb=sizeof(startup);startup.dwFlags=STARTF_USESTDHANDLES;startup.hStdInput=inherited[0];startup.hStdOutput=inherited[1];startup.hStdError=inherited[2];
    wchar_t command[]=L"\"C:\\P0Lab\\.local\\p0\\bin\\proxy-harbor-p0-probe.exe\" -public-wire -network udp4 -address 1.1.1.1:53";
    if(!CreateProcessW(probe,command,NULL,NULL,TRUE,CREATE_NO_WINDOW,NULL,L"C:\\P0Lab",&startup,&process)){error=GetLastError();goto cleanup;}
    if(WaitForSingleObject(process.hProcess,8000)!=WAIT_OBJECT_0){error=WAIT_TIMEOUT;goto cleanup;}
    if(!GetExitCodeProcess(process.hProcess,&exit_code)){error=GetLastError();goto cleanup;}
    for(int attempt=0;attempt<10&&!matched;++attempt){
        Sleep(200);FWPM_NET_EVENT_ENUM_TEMPLATE0 query={0};query.startTime=began;GetSystemTimeAsFileTime(&query.endTime);HANDLE enumeration=NULL;
        error=FwpmNetEventCreateEnumHandle0(engine,&query,&enumeration);if(error)goto cleanup;
        for(int page=0;page<16;++page){FWPM_NET_EVENT0 **events=NULL;UINT32 count=0;error=FwpmNetEventEnum0(engine,enumeration,256,&events,&count);if(error){if(events)FwpmFreeMemory0((void **)&events);break;}
            for(UINT32 i=0;i<count;++i){FWPM_NET_EVENT0 *e=events[i];UINT32 flags=FWPM_NET_EVENT_FLAG_APP_ID_SET|FWPM_NET_EVENT_FLAG_IP_PROTOCOL_SET|FWPM_NET_EVENT_FLAG_REMOTE_ADDR_SET|FWPM_NET_EVENT_FLAG_REMOTE_PORT_SET|FWPM_NET_EVENT_FLAG_IP_VERSION_SET;if(e->type!=FWPM_NET_EVENT_TYPE_CLASSIFY_DROP||!e->classifyDrop||(e->header.flags&flags)!=flags||e->header.ipVersion!=FWP_IP_VERSION_V4||e->header.ipProtocol!=IPPROTO_UDP||e->header.remoteAddrV4!=0x01010101||e->header.remotePort!=53||e->header.appId.size!=app->size||!e->header.appId.data||memcmp(e->header.appId.data,app->data,app->size))continue;for(int k=0;k<4;++k)if(e->classifyDrop->filterId==filter_ids[k]){++matched;matched_filter=filter_ids[k];break;}}
            if(events)FwpmFreeMemory0((void **)&events);if(count<256)break;
        }
        FwpmNetEventDestroyEnumHandle0(engine,enumeration);if(error)goto cleanup;
    }
cleanup:
    if(process.hProcess){if(WaitForSingleObject(process.hProcess,0)!=WAIT_OBJECT_0){TerminateProcess(process.hProcess,1);WaitForSingleObject(process.hProcess,1000);}CloseHandle(process.hProcess);CloseHandle(process.hThread);}
    for(int i=0;i<3;++i)if(inherited[i])CloseHandle(inherited[i]);
    if(saved){FWP_VALUE0 old={0};old.type=FWP_UINT32;old.uint32=previous;if(!previous)restored=FwpmEngineSetOption0(engine,FWPM_ENGINE_COLLECT_NET_EVENTS,&old)==ERROR_SUCCESS;FWP_VALUE0 *actual=NULL;if(restored)restored=FwpmEngineGetOption0(engine,FWPM_ENGINE_COLLECT_NET_EVENTS,&actual)==ERROR_SUCCESS;if(restored)restored=actual&&actual->type==FWP_UINT32&&actual->uint32==previous;if(actual)FwpmFreeMemory0((void **)&actual);if(restored)DeleteFileW(L"C:\\P0Lab\\.local\\p0\\net-event-recovery.json");}
    if(option)FwpmFreeMemory0((void **)&option);if(app)FwpmFreeMemory0((void **)&app);if(engine)FwpmEngineClose0(engine);
    printf("{\"netEventObservation\":true,\"windowsError\":%lu,\"matchedProjectDropEvents\":%u,\"matchedFilterId\":%llu,\"probeExitCode\":%lu,\"collectionRestored\":%s}\n",error,matched,matched_filter,exit_code,restored?"true":"false");
    return error||!restored||!matched||exit_code!=1?1:0;
}
