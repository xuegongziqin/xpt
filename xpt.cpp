#include <windows.h>
#include <tlhelp32.h>
#include <winternl.h>
#include <string>
#include <vector>
#include <map>
#include <cctype>
#include <algorithm>
#include <fstream>
#include <iostream>
typedef NTSTATUS (NTAPI *pfnNtSetInformationProcess)(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength
);
typedef NTSTATUS (NTAPI *pRtlSetProcessIsCritical)(
    BOOLEAN NewValue,
    PBOOLEAN OldValue,
    BOOLEAN CheckFlag
);
static pfnNtSetInformationProcess GetNtSetInformationProcess()
{
    static pfnNtSetInformationProcess pfn = NULL;
    if (!pfn)
	{
        HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
        if (!hNtdll) hNtdll = LoadLibraryA("ntdll.dll");
        if (hNtdll)
            pfn = (pfnNtSetInformationProcess)GetProcAddress(hNtdll, "NtSetInformationProcess");
    }
    return pfn;
}
BOOL EnableDebugPrivilege()
{
    HANDLE hToken;
    TOKEN_PRIVILEGES tkp;
    LUID luid;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return FALSE;
    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid))
	{
        CloseHandle(hToken);
        return FALSE;
    }
    tkp.PrivilegeCount = 1;
    tkp.Privileges[0].Luid = luid;
    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    BOOL ret = AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof(tkp), NULL, NULL);
    CloseHandle(hToken);
    return (ret && GetLastError() == ERROR_SUCCESS);
}
BOOL ProtectMyself()
{
    HMODULE hDll = LoadLibraryA("ntdll.dll");
    if (!hDll) return FALSE;
    pRtlSetProcessIsCritical RtlSetProcessIsCritical = 
        (pRtlSetProcessIsCritical)GetProcAddress(hDll, "RtlSetProcessIsCritical");
    if (!RtlSetProcessIsCritical)
	{
        FreeLibrary(hDll);
        return FALSE;
    }
    if (!EnableDebugPrivilege())
	{
        FreeLibrary(hDll);
        return FALSE;
    }
    NTSTATUS status = RtlSetProcessIsCritical(TRUE, NULL, FALSE);
    FreeLibrary(hDll);
    return (status == 0);
}
BOOL RemoveProtection(int pid)
{
    pfnNtSetInformationProcess NtSetInformationProcess = GetNtSetInformationProcess();
    if (!NtSetInformationProcess) return FALSE;
    HANDLE hProcess = OpenProcess(PROCESS_SET_INFORMATION, FALSE, (DWORD)pid);
    if (!hProcess) return FALSE;
    ULONG BreakOnTermination = 0;
    NTSTATUS status = NtSetInformationProcess(
        hProcess,
        (PROCESSINFOCLASS)0x1D,
        &BreakOnTermination,
        sizeof(ULONG)
    );
    CloseHandle(hProcess);
    if (status == 0) return TRUE;
    else return FALSE;
}
std::vector<std::string> getRunningProcess()
{
    std::vector<std::string> processes;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE)
        return processes;

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);
    if (Process32FirstW(hSnapshot, &pe32))
    {
        do {
            int len = WideCharToMultiByte(CP_ACP, 0, pe32.szExeFile, -1, nullptr, 0, nullptr, nullptr);
            if (len > 0) {
                std::string procName(len, '\0');
                WideCharToMultiByte(CP_ACP, 0, pe32.szExeFile, -1, &procName[0], len, nullptr, nullptr);
                procName.resize(len - 1);
                processes.push_back(procName);
            }
        } while (Process32NextW(hSnapshot, &pe32));
    }
    CloseHandle(hSnapshot);
    return processes;
}
std::vector<int> getProcessPidByName(const std::string& procName)
{
    std::vector<int> pids;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE)
        return pids;
    int wlen = MultiByteToWideChar(CP_ACP, 0, procName.c_str(), -1, nullptr, 0);
    std::wstring wProcName(wlen - 1, L'\0');
    MultiByteToWideChar(CP_ACP, 0, procName.c_str(), -1, &wProcName[0], wlen);
    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);
    if (Process32FirstW(hSnapshot, &pe32))
    {
        do {
            if (_wcsicmp(pe32.szExeFile, wProcName.c_str()) == 0)
                pids.push_back(static_cast<int>(pe32.th32ProcessID));
        } while (Process32NextW(hSnapshot, &pe32));
    }
    CloseHandle(hSnapshot);
    return pids;
}
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
    std::map<std::string, bool> disallow;
    std::ifstream fin("key.ini");
    if (!fin) return 1;
    std::string proc;
    while (fin >> proc) disallow[proc] = true;
    fin.close();
    if (!EnableDebugPrivilege()) exit(1);
    ProtectMyself();
    while (true)
    {
        auto list = getRunningProcess();
        for (const auto& proc : list)
        {
            if (disallow[proc])
            {
                auto pids = getProcessPidByName(proc);
                for (int pid : pids)
                {
                	RemoveProtection(pid);
                    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
                    if (hProcess)
                    {
                        TerminateProcess(hProcess, 1);
                        CloseHandle(hProcess);
                    }
                }
            }
        }
        Sleep(500);
    }
}
