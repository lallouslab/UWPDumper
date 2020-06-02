#include <iostream>
#include <iomanip>
#include <string>
#include <memory>
#include <chrono>
#include <conio.h>

#include <windows.h>
#include <psapi.h> //GetModuleFileNameEx
#include <TlHelp32.h>

// Setting DLL access controls
#include <AccCtrl.h>
#include <Aclapi.h>
#include <Sddl.h>

// UWP
#include <atlbase.h>
#include <appmodel.h>

// IPC
#include <UWP/DumperIPC.hpp>

#include "utils.h"
const wchar_t* DLLFile = L"UWPDumper.dll";

std::wstring GetRunningDirectory();

using ThreadCallback = bool(*)(std::uint32_t ThreadID, void* Data);

//----------------------------------------------------------------------------------
int main(int argc, char** argv, char** envp)
{
    std::uint32_t ProcessID = 0;

    if (argc > 1)
    {
        for (std::size_t i = 1; i < argc; ++i) 
        {
            if (std::string_view(argv[i]) == "-h")
            {
                std::cout << "use -p followed by a pid\n";
                system("pause");
                return 0;
            }
            else if (std::string_view(argv[i]) == "-p")
            {
                if (i != argc)
                {
                    ProcessID = (std::uint32_t)atoi(argv[i + 1]);
                }
                else
                {
                    std::cout << "-p must be followed by a pid\n";
                    system("pause");
                    return 0;
                }
            }
        }
    }

    // Enable VT100
    DWORD ConsoleMode;
    GetConsoleMode(
        GetStdHandle(STD_OUTPUT_HANDLE),
        &ConsoleMode);

    SetConsoleMode(
        GetStdHandle(STD_OUTPUT_HANDLE),
        ConsoleMode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
    
    SetConsoleOutputCP(437);

    std::wcout << "\033[92mUWPInjector Build date (" << __DATE__ << " : " << __TIME__ << ')' << std::endl;
    std::wcout << "\033[96m\t\033(0m\033(Bhttps://github.com/Wunkolo/UWPDumper\n";
    std::wcout << "\033[95m\033(0" << std::wstring(80, 'q') << "\033(B" << std::endl;

    IPC::SetClientProcess(GetCurrentProcessId());

    if (ProcessID == 0)
    {
        std::cout << "\033[93mCurrently running UWP Apps:" << std::endl;
        void* ProcessSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        PROCESSENTRY32 ProcessEntry;
        ProcessEntry.dwSize = sizeof(PROCESSENTRY32);

        if (Process32First(ProcessSnapshot, &ProcessEntry))
        {
            while (Process32Next(ProcessSnapshot, &ProcessEntry))
            {
                HANDLE ProcessHandle = OpenProcess(
                    PROCESS_QUERY_LIMITED_INFORMATION,
                    false,
                    ProcessEntry.th32ProcessID);

                if (ProcessHandle)
                {
                    std::uint32_t NameLength = 0;
                    std::int32_t ProcessCode = GetPackageFamilyName(
                        ProcessHandle,
                        &NameLength,
                        nullptr);

                    if (NameLength)
                    {
                        std::wcout
                            << "\033[92m"
                            << std::setw(12)
                            << ProcessEntry.th32ProcessID;

                        std::wcout
                            << "\033[96m"
                            << " \033(0x\033(B "
                            << ProcessEntry.szExeFile << " :\n\t\t\033(0m\033(B";
                        std::unique_ptr<wchar_t[]> PackageName(new wchar_t[NameLength]());

                        ProcessCode = GetPackageFamilyName(
                            ProcessHandle,
                            &NameLength,
                            PackageName.get());

                        if (ProcessCode != ERROR_SUCCESS)
                            std::wcout << "GetPackageFamilyName Error: " << ProcessCode;

                        std::wcout << PackageName.get() << std::endl;

                        PackageName.reset();
                    }
                }
                CloseHandle(ProcessHandle);
            }
        }
        else
        {
            std::cout << "\033[91mUnable to iterate active processes" << std::endl;
            _getch();
            return EXIT_FAILURE;
        }
        std::cout << "\033[93mEnter ProcessID: \033[92m";
        std::cin >> ProcessID;
    }

    SetAccessControl((GetRunningDirectory() + L'\\' + DLLFile).c_str(), SID_ALL_APP_PACKAGES);

    IPC::SetTargetProcess(ProcessID);

    std::cout << "\033[93mInjecting into remote process: ";
    std::wstring err_msg;
    if (!DLLInjectRemote(ProcessID, GetRunningDirectory() + L'\\' + DLLFile, err_msg))
    {
        std::wcout << err_msg << std::endl;
        std::cout << "\033[91mFailed" << std::endl;
        system("pause");
        return EXIT_FAILURE;
    }
    std::cout << "\033[92mSuccess!" << std::endl;

    std::cout << "\033[93mWaiting for remote thread IPC:" << std::endl;
    std::chrono::high_resolution_clock::time_point ThreadTimeout = std::chrono::high_resolution_clock::now() + std::chrono::seconds(5);
    while( IPC::GetTargetThread() == IPC::InvalidThread )
    {
        if ( std::chrono::high_resolution_clock::now() >= ThreadTimeout )
        {
            std::cout << "\033[91mRemote thread wait timeout: Unable to find target thread" << std::endl;
            _getch();
            return EXIT_FAILURE;
        }
    }

    std::cout << "Remote Dumper thread found: 0x" << std::hex << IPC::GetTargetThread() << std::endl;

    std::cout << "\033[0m" << std::flush;
    while (IPC::GetTargetThread() != IPC::InvalidThread)
    {
        while( IPC::MessageCount() > 0 )
            std::wcout << IPC::PopMessage() << "\033[0m";
    }
    _getch();
    return EXIT_SUCCESS;
}


//----------------------------------------------------------------------------------
std::wstring GetRunningDirectory()
{
    wchar_t RunPath[MAX_PATH];
    GetModuleFileNameW(GetModuleHandleW(nullptr), RunPath, MAX_PATH);
    PathRemoveFileSpecW(RunPath);
    return std::wstring(RunPath);
}
