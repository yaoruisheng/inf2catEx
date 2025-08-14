// Wrap target tool (e.g., inf2cat.exe), inject HookFileTime.dll,
// and pass spoof time via environment variable MYTIME.
// Usage example:
//   inf2catex /driver:E:\driver\Win64 /os:10_X64 /mytime 2005-08-14T12:34:56
//
// Notes:
// - We parse /mytime or -mytime and remove it from the child command line.
// - We set MYTIME in the parent process before CreateProcessW so the child
//   inherits it. In the DLL, read it via getenv("MYTIME") or GetEnvironmentVariableA.
// - Env var lookup on Windows is case-insensitive (MYTIME == mytime), but we set "MYTIME".

#include <windows.h>
#include <string>
#include <vector>
#include <cstdio>
#include <cctype>

static bool iequals(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i) {
        if (std::tolower(static_cast<unsigned char>(a[i])) !=
            std::tolower(static_cast<unsigned char>(b[i]))) return false;
    }
    return true;
}

int main(int argc, char* argv[]) {
    // Target tool name: "inf2cat.exe"
    std::string targetExe = "inf2cat.exe";

    std::string mytimeValue;                // Stores the /mytime value
    std::vector<std::string> passThrough;   // Other arguments to pass to child (excluding /mytime)

    // Parse command line: consume -mytime/ /mytime and its value, keep others unchanged
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (iequals(arg, "/mytime") || iequals(arg, "-mytime")) {
            if (i + 1 < argc) {
                mytimeValue = argv[++i]; // Get the time string
            } else {
                std::fprintf(stderr, "Error: /mytime requires a value (e.g. 2005-08-14T12:34:56)\n");
                return 2;
            }
        } else {
            passThrough.push_back(arg);
        }
    }

    // Concatenate remaining arguments to form child process command line
    std::string cmdLine = targetExe;
    for (const auto& s : passThrough) {
        cmdLine.push_back(' ');
        // Simple handling: quote if argument contains space
        bool needQuote = (s.find_first_of(" \t\"") != std::string::npos);
        if (needQuote) {
            cmdLine.push_back('"');
            // Simple escape: double internal quotes
            for (char c : s) cmdLine += (c == '"') ? "\"\"" : std::string(1, c);
            cmdLine.push_back('"');
        } else {
            cmdLine += s;
        }
    }

    // If /mytime is provided, set environment variable MYTIME (child inherits it)
    if (!mytimeValue.empty()) {
        if (!SetEnvironmentVariableA("MYTIME", mytimeValue.c_str())) {
            std::fprintf(stderr, "SetEnvironmentVariable(MYTIME) failed (%lu)\n", GetLastError());
            return 3;
        }
    } else {
        // Clear it if not provided to avoid inheriting old value (optional)
        SetEnvironmentVariableA("MYTIME", NULL);
    }

    // Create wide string buffer for CreateProcessW (writable)
    std::wstring wcmdLine(cmdLine.begin(), cmdLine.end());
    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};

    // Start child process suspended to inject DLL before execution
    if (!CreateProcessW(
            NULL,
            wcmdLine.empty() ? NULL : &wcmdLine[0],
            NULL, NULL,
            FALSE,
            CREATE_SUSPENDED, // Start suspended
            NULL,             // Inherit current environment (contains MYTIME)
            NULL,
            &si, &pi))
    {
        std::fprintf(stderr, "CreateProcess failed (%lu)\n", GetLastError());
        return 4;
    }

    // Get full path of the DLL to inject
    wchar_t dllPath[MAX_PATH];
    if (!GetFullPathNameW(L"HookFileTime.dll", MAX_PATH, dllPath, NULL)) {
        std::fprintf(stderr, "GetFullPathNameW failed (%lu)\n", GetLastError());
        TerminateProcess(pi.hProcess, 5);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return 5;
    }

    // Allocate memory in remote process and write DLL path (use actual length * sizeof(wchar_t))
    const size_t bytesToWrite = (wcslen(dllPath) + 1) * sizeof(wchar_t);
    LPVOID remoteDllPath = VirtualAllocEx(pi.hProcess, NULL, bytesToWrite, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteDllPath) {
        std::fprintf(stderr, "VirtualAllocEx failed (%lu)\n", GetLastError());
        TerminateProcess(pi.hProcess, 6);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return 6;
    }
    if (!WriteProcessMemory(pi.hProcess, remoteDllPath, dllPath, bytesToWrite, NULL)) {
        std::fprintf(stderr, "WriteProcessMemory failed (%lu)\n", GetLastError());
        VirtualFreeEx(pi.hProcess, remoteDllPath, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 7);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return 7;
    }

    // Get address of kernel32!LoadLibraryW (common method: use local process address)
    // Note: strictly speaking remote address may differ, but usually works; for absolute reliability,
    // use EnumProcessModulesEx/Toolhelp to find remote kernel32 base + RVA.
    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    FARPROC loadLibraryAddr = hKernel32 ? GetProcAddress(hKernel32, "LoadLibraryW") : nullptr;
    if (!loadLibraryAddr) {
        std::fprintf(stderr, "GetProcAddress(LoadLibraryW) failed (%lu)\n", GetLastError());
        VirtualFreeEx(pi.hProcess, remoteDllPath, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 8);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return 8;
    }

    // Create remote thread: LoadLibraryW(L"HookGetLocalTime.dll")
    HANDLE remoteThread = CreateRemoteThread(
        pi.hProcess, NULL, 0,
        reinterpret_cast<LPTHREAD_START_ROUTINE>(loadLibraryAddr),
        remoteDllPath, 0, NULL);
    if (!remoteThread) {
        std::fprintf(stderr, "CreateRemoteThread failed (%lu)\n", GetLastError());
        VirtualFreeEx(pi.hProcess, remoteDllPath, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 9);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return 9;
    }

    // Wait for DLL injection to complete
    DWORD waitResult = WaitForSingleObject(remoteThread, INFINITE);
    if (waitResult != WAIT_OBJECT_0) {
        std::fprintf(stderr, "WaitForSingleObject(remoteThread) failed (%lu)\n", GetLastError());
        VirtualFreeEx(pi.hProcess, remoteDllPath, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 10);
        CloseHandle(remoteThread);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return 10;
    }

    // Free remote memory
    VirtualFreeEx(pi.hProcess, remoteDllPath, 0, MEM_RELEASE);
    CloseHandle(remoteThread);

    // Resume main thread, start execution
    if (ResumeThread(pi.hThread) == (DWORD)-1) {
        std::fprintf(stderr, "ResumeThread failed (%lu)\n", GetLastError());
        TerminateProcess(pi.hProcess, 11);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return 11;
    }

    // Wait for child process to exit
    waitResult = WaitForSingleObject(pi.hProcess, INFINITE);
    if (waitResult != WAIT_OBJECT_0) {
        std::fprintf(stderr, "WaitForSingleObject(child) failed (%lu)\n", GetLastError());
        // Do not force termination, just cleanup
    }

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return 0;
}