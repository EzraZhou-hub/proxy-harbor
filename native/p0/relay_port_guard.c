// Disposable P0 experiment: reserve one relay TCP port across relay failure.
// No driver and no arbitrary executable identity. Mutations are guest-only.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <fwpmu.h>
#include <stdio.h>
#include <wchar.h>

static const GUID sublayer={0x78c0ad16,0x2bd0,0x47bd,{0xb5,0xec,0x01,0x32,0xd7,0x3b,0x3e,0x8c}};
static const GUID keys[4]={
{0xc7abcf71,0xe42f,0x4276,{0x89,0x4c,0x6b,0xa6,0xab,0x08,0x03,0xe1}},
{0xc7abcf72,0xe42f,0x4276,{0x89,0x4c,0x6b,0xa6,0xab,0x08,0x03,0xe1}},
{0xc7abcf73,0xe42f,0x4276,{0x89,0x4c,0x6b,0xa6,0xab,0x08,0x03,0xe1}},
{0xc7abcf74,0xe42f,0x4276,{0x89,0x4c,0x6b,0xa6,0xab,0x08,0x03,0xe1}}};
static const wchar_t owner[]=L"Proxy Harbor P0 disposable relay port reservation";
static const wchar_t relay[]=L"C:\\P0Lab\\.local\\p0\\bin\\proxy-harbor-p0-relay.exe";
static const GUID *layer(int i) {
    const GUID *layers[]={&FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V4,&FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V6,&FWPM_LAYER_ALE_AUTH_LISTEN_V4,&FWPM_LAYER_ALE_AUTH_LISTEN_V6};
    return layers[i];
}
static BOOL guest_only(void) {
    wchar_t cwd[MAX_PATH],marker[32],image[MAX_PATH];
    return GetCurrentDirectoryW(MAX_PATH,cwd) && _wcsicmp(cwd,L"C:\\P0Lab")==0 &&
        GetEnvironmentVariableW(L"PROXY_HARBOR_P0_GUEST",marker,32) && wcscmp(marker,L"offline-lab")==0 &&
        GetModuleFileNameW(NULL,image,MAX_PATH) && _wcsicmp(image,L"C:\\P0Lab\\.local\\p0\\bin\\p0-port-guard.exe")==0;
}
static BOOL owned(const FWPM_FILTER0 *f,int i,const FWP_BYTE_BLOB *app,UINT16 *port) {
    if(!app || !IsEqualGUID(&f->filterKey,&keys[i]) || !IsEqualGUID(&f->layerKey,layer(i)) || !IsEqualGUID(&f->subLayerKey,&sublayer) ||
       !f->displayData.name || wcscmp(f->displayData.name,owner) || f->action.type!=FWP_ACTION_BLOCK ||
       !(f->flags&FWPM_FILTER_FLAG_PERSISTENT) || (f->flags&FWPM_FILTER_FLAG_DISABLED) ||
       f->numFilterConditions!=2 || !f->filterCondition || f->providerData.size!=sizeof(relay) ||
       !f->providerData.data || memcmp(f->providerData.data,relay,sizeof(relay))) return FALSE;
    BOOL found_app=FALSE,found_port=FALSE;
    for(UINT32 j=0;j<2;++j) {
        const FWPM_FILTER_CONDITION0 *c=&f->filterCondition[j];
        if(IsEqualGUID(&c->fieldKey,&FWPM_CONDITION_ALE_APP_ID)) {
            const FWP_BYTE_BLOB *b=c->conditionValue.byteBlob;
            found_app=c->matchType==FWP_MATCH_NOT_EQUAL && c->conditionValue.type==FWP_BYTE_BLOB_TYPE && b && b->data && b->size==app->size && !memcmp(b->data,app->data,b->size);
        } else if(IsEqualGUID(&c->fieldKey,&FWPM_CONDITION_IP_LOCAL_PORT)) {
            UINT16 value=c->conditionValue.uint16;
            found_port=c->matchType==FWP_MATCH_EQUAL && c->conditionValue.type==FWP_UINT16 && value>=1024 && (!*port || *port==value);
            if(found_port) *port=value;
        } else return FALSE;
    }
    return found_app && found_port;
}
static DWORD inventory(HANDLE engine,const FWP_BYTE_BLOB *app,unsigned *count,UINT16 *port) {
    *count=0;
    for(int i=0;i<4;++i) {
        FWPM_FILTER0 *f=NULL;
        DWORD e=FwpmFilterGetByKey0(engine,&keys[i],&f);
        if(e==FWP_E_FILTER_NOT_FOUND) continue;
        if(e) return e;
        BOOL valid=owned(f,i,app,port);
        FwpmFreeMemory0((void **)&f);
        if(!valid) return ERROR_INVALID_OWNER;
        ++*count;
    }
    return ERROR_SUCCESS;
}
int wmain(int argc,wchar_t **argv) {
    BOOL inspect=argc==2 && !wcscmp(argv[1],L"inspect");
    BOOL install=argc==3 && !wcscmp(argv[1],L"reserve-fixture-only");
    BOOL remove=argc==2 && !wcscmp(argv[1],L"remove-fixture-only");
    UINT16 port=0;
    if(install) {wchar_t *end=NULL;unsigned long value=wcstoul(argv[2],&end,10);if(!end || *end || value<1024 || value>65535)return 2;port=(UINT16)value;}
    if((!inspect && !install && !remove) || ((!inspect) && !guest_only())) {fputs("Fixed-path guest-only relay port experiment\n",stderr);return 2;}
    HANDLE engine=NULL;FWP_BYTE_BLOB *app=NULL;DWORD error=0;unsigned count=0;BOOL changed=FALSE,transaction=FALSE;
    error=FwpmGetAppIdFromFileName0(relay,&app);
    // The fixed C:\P0Lab fixture intentionally does not exist on the host.
    // With no matching keys, read-only inventory still succeeds. If any key
    // exists without a verifiable application identity, fail ownership checks.
    if(inspect && (error==ERROR_PATH_NOT_FOUND || error==ERROR_FILE_NOT_FOUND))error=ERROR_SUCCESS;
    if(!error) error=FwpmEngineOpen0(NULL,RPC_C_AUTHN_WINNT,NULL,NULL,&engine);
    if(error) goto cleanup;
    if(!inspect) {error=FwpmTransactionBegin0(engine,0);if(error)goto cleanup;transaction=TRUE;}
    error=inventory(engine,app,&count,&port);if(error || inspect)goto cleanup;
    FWPM_SUBLAYER0 *existing=NULL;
    error=FwpmSubLayerGetByKey0(engine,&sublayer,&existing);
    if(!error) {
        BOOL valid=existing->displayData.name && !wcscmp(existing->displayData.name,owner) && (existing->flags&FWPM_SUBLAYER_FLAG_PERSISTENT);
        FwpmFreeMemory0((void **)&existing);
        if(!valid) {error=ERROR_INVALID_OWNER;goto cleanup;}
    } else if(error==FWP_E_SUBLAYER_NOT_FOUND) {
        error=ERROR_SUCCESS;
        if(count) {error=ERROR_INVALID_STATE;goto cleanup;}
        if(install) {FWPM_SUBLAYER0 s={0};s.subLayerKey=sublayer;s.displayData.name=(wchar_t *)owner;s.flags=FWPM_SUBLAYER_FLAG_PERSISTENT;s.weight=0x7000;error=FwpmSubLayerAdd0(engine,&s,NULL);}
    }
    if(error)goto cleanup;
    if(install) {
        if(count!=0 && count!=4) {error=ERROR_INVALID_STATE;goto cleanup;}
        if(!count)for(int i=0;i<4 && !error;++i) {
            FWPM_FILTER_CONDITION0 c[2]={0};
            c[0].fieldKey=FWPM_CONDITION_ALE_APP_ID;c[0].matchType=FWP_MATCH_NOT_EQUAL;c[0].conditionValue.type=FWP_BYTE_BLOB_TYPE;c[0].conditionValue.byteBlob=app;
            c[1].fieldKey=FWPM_CONDITION_IP_LOCAL_PORT;c[1].matchType=FWP_MATCH_EQUAL;c[1].conditionValue.type=FWP_UINT16;c[1].conditionValue.uint16=port;
            FWPM_FILTER0 f={0};f.filterKey=keys[i];f.layerKey=*layer(i);f.subLayerKey=sublayer;f.displayData.name=(wchar_t *)owner;
            f.flags=FWPM_FILTER_FLAG_PERSISTENT;f.action.type=FWP_ACTION_BLOCK;f.weight.type=FWP_UINT8;f.weight.uint8=15;
            f.providerData.size=sizeof(relay);f.providerData.data=(UINT8 *)relay;f.numFilterConditions=2;f.filterCondition=c;
            error=FwpmFilterAdd0(engine,&f,NULL,NULL);
        }
        changed=count==0;
    } else {
        for(int i=0;i<4 && !error;++i) {DWORD e=FwpmFilterDeleteByKey0(engine,&keys[i]);if(e!=FWP_E_FILTER_NOT_FOUND)error=e;}
        if(!error) {DWORD e=FwpmSubLayerDeleteByKey0(engine,&sublayer);if(e!=FWP_E_SUBLAYER_NOT_FOUND)error=e;}
        changed=count!=0;
    }
    if(!error) {error=FwpmTransactionCommit0(engine);if(!error)transaction=FALSE;}
    if(!error)error=inventory(engine,app,&count,&port);
cleanup:
    if(transaction)FwpmTransactionAbort0(engine);
    if(engine)FwpmEngineClose0(engine);
    if(app)FwpmFreeMemory0((void **)&app);
    printf("{\"windowsError\":%lu,\"rulesPresent\":%u,\"port\":%u,\"systemChanged\":%s,\"scope\":\"one guest relay port, all other executable identities denied bind/listen\"}\n",error,count,port,(!error&&changed)?"true":"false");
    return error?1:0;
}
