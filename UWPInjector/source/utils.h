#pragma once

#define SID_ALL_APP_PACKAGES L"S-1-15-2-1"

#include <string>
#include <cstdint>
#include <windows.h>

bool SetAccessControl(const wchar_t *FileName, const wchar_t *AccessString);

bool DLLInjectRemote(
    DWORD ProcessID,
    const std::wstring &DLLpath,
    std::wstring &err_str);
