// Security descriptor for the locked transparent candidate's local pipe.
// Restrict access to the current user and, when present, its exact package SID.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <sddl.h>
#include <stdio.h>

BOOL P0BuildPipeSecurityDescriptor(PSECURITY_DESCRIPTOR *descriptor) {
    HANDLE token=NULL;
    BYTE user_buffer[1024],container_buffer[256];
    DWORD size=0,is_container=0,error=ERROR_SUCCESS;
    LPWSTR user_sid=NULL,package_sid=NULL;
    wchar_t sddl[1024];
    *descriptor=NULL;
    if(!OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&token))return FALSE;
    if(!GetTokenInformation(token,TokenUser,user_buffer,sizeof(user_buffer),&size) ||
       !ConvertSidToStringSidW(((TOKEN_USER *)user_buffer)->User.Sid,&user_sid) ||
       !GetTokenInformation(token,TokenIsAppContainer,&is_container,sizeof(is_container),&size)) {error=GetLastError();goto cleanup;}
    if(is_container && (!GetTokenInformation(token,TokenAppContainerSid,container_buffer,sizeof(container_buffer),&size) ||
       !ConvertSidToStringSidW(((TOKEN_APPCONTAINER_INFORMATION *)container_buffer)->TokenAppContainer,&package_sid))) {error=GetLastError();goto cleanup;}
    if(package_sid) swprintf_s(sddl,1024,L"D:P(A;;0x12019f;;;%ls)(A;;0x12019f;;;%ls)S:(ML;;NW;;;LW)",user_sid,package_sid);
    else swprintf_s(sddl,1024,L"D:P(A;;0x12019f;;;%ls)S:(ML;;NW;;;LW)",user_sid);
    if(!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl,SDDL_REVISION_1,descriptor,NULL))error=GetLastError();
cleanup:
    if(user_sid)LocalFree(user_sid);
    if(package_sid)LocalFree(package_sid);
    if(token)CloseHandle(token);
    if(error)SetLastError(error);
    return error==ERROR_SUCCESS;
}
