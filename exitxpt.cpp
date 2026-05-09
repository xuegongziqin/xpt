#include <windows.h>
#include <string>
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
                   LPSTR lpCmdLine, int nCmdShow)
{
    WCHAR tempPath[MAX_PATH];
    DWORD len = GetTempPathW(MAX_PATH, tempPath);
    if (len == 0 || len > MAX_PATH)
        return 1;
    std::wstring filePath = tempPath;
    filePath += L"wsusoffline.log";
    HANDLE hFile = CreateFileW(
        filePath.c_str(),
        GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    if (hFile == INVALID_HANDLE_VALUE)
        return 2;
    const char exitFlag[] = "EXIT114514";
    DWORD bytesWritten;
    BOOL ok = WriteFile(hFile, exitFlag, sizeof(exitFlag) - 1,
                        &bytesWritten, NULL);
    CloseHandle(hFile);
    return ok ? 0 : 3;
}
