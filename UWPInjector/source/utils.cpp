#include "utils.h"

#include <AccCtrl.h>
#include <Aclapi.h>
#include <Sddl.h>

#include <windows.h>

//----------------------------------------------------------------------------------
bool SetAccessControl(
    const wchar_t *FileName,
    const wchar_t *AccessString)
{
    PSECURITY_DESCRIPTOR SecurityDescriptor = nullptr;
    EXPLICIT_ACCESSW ExplicitAccess = { 0 };

    ACL* AccessControlCurrent = nullptr;
    ACL* AccessControlNew = nullptr;

    SECURITY_INFORMATION SecurityInfo = DACL_SECURITY_INFORMATION;
    PSID SecurityIdentifier = nullptr;

    bool ok = false;
    do 
    {
        if (GetNamedSecurityInfoW(
            FileName,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            nullptr,
            nullptr,
            &AccessControlCurrent,
            nullptr,
            &SecurityDescriptor) != ERROR_SUCCESS)
        {
            break;
        }

        ConvertStringSidToSidW(AccessString, &SecurityIdentifier);
        if (SecurityIdentifier == nullptr)
            break;

        ExplicitAccess.grfAccessPermissions = GENERIC_READ | GENERIC_EXECUTE;
        ExplicitAccess.grfAccessMode = SET_ACCESS;
        ExplicitAccess.grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
        ExplicitAccess.Trustee.TrusteeForm = TRUSTEE_IS_SID;
        ExplicitAccess.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
        ExplicitAccess.Trustee.ptstrName = reinterpret_cast<wchar_t*>(SecurityIdentifier);

        if (SetEntriesInAclW(
            1,
            &ExplicitAccess,
            AccessControlCurrent,
            &AccessControlNew) != ERROR_SUCCESS)
        {
            break;
        }

        auto pFileName = _wcsdup(FileName);
        if (pFileName == nullptr)
            break;

        SetNamedSecurityInfoW(
            pFileName,
            SE_FILE_OBJECT,
            SecurityInfo,
            nullptr,
            nullptr,
            AccessControlNew,
            nullptr);
        free(pFileName);
        ok = true;
    } while (false);

    if (SecurityDescriptor)
        LocalFree(reinterpret_cast<HLOCAL>(SecurityDescriptor));

    if (AccessControlNew)
        LocalFree(reinterpret_cast<HLOCAL>(AccessControlNew));

    return ok;
}

//----------------------------------------------------------------------------------
bool DLLInjectRemote(
    DWORD ProcessID,
    const std::wstring &DLLpath,
    std::wstring &err_msg)
{
    bool ok = false;
    HANDLE hProcess = nullptr;
    LPVOID lpRemoteDllPath = nullptr;
   
    do
    {
        if (ProcessID == 0)
        {
            err_msg = L"Invalid Process ID";
            break;
        }

        if (GetFileAttributesW(DLLpath.c_str()) == INVALID_FILE_ATTRIBUTES)
        {
            err_msg = L"DLL does not exist!";
            break;
        }

        auto ProcLoadLibrary = GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW");
        if (ProcLoadLibrary == nullptr)
        {
            err_msg = L"Unable to find LoadLibraryW procedure";
            break;
        }

        hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessID);
        if (hProcess == nullptr)
        {
            err_msg = L"Unable to open process";
            break;
        }

        const std::size_t DLLPathSize = ((DLLpath.size() + 1) * sizeof(wchar_t));
        lpRemoteDllPath = VirtualAllocEx(
            hProcess,
            nullptr,
            DLLPathSize,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_READWRITE);

        if (lpRemoteDllPath == nullptr)
        {
            err_msg = L"Unable to remotely allocate memory";
            break;
        }

        SIZE_T BytesWritten = 0;
        if (WriteProcessMemory(
            hProcess,
            lpRemoteDllPath,
            DLLpath.data(),
            DLLPathSize,
            &BytesWritten) == FALSE)
        {
            err_msg = L"Unable to write process memory";
            break;
        }

        if (BytesWritten != DLLPathSize)
        {
            err_msg = L"Failed to write remote DLL path name";
            break;
        }

        HANDLE RemoteThread = CreateRemoteThread(
            hProcess,
            nullptr,
            0,
            LPTHREAD_START_ROUTINE(ProcLoadLibrary),
            lpRemoteDllPath,
            0,
            nullptr);

        // Wait for remote thread to finish
        if (RemoteThread == nullptr)
        {
            err_msg = L"Unable to create remote thread";
            break;
        }

        // Explicitly wait for LoadLibraryW to complete before releasing memory
        // avoids causing a remote memory leak
        WaitForSingleObject(RemoteThread, INFINITE);
        CloseHandle(RemoteThread);
        ok = true;
    } while (false);

    if (lpRemoteDllPath != nullptr)
        VirtualFreeEx(hProcess, lpRemoteDllPath, 0, MEM_RELEASE);

    if (hProcess != nullptr)
        CloseHandle(hProcess);

    return ok;
}
