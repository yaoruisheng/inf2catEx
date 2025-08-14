// HookFileTime.dll
#include <windows.h>   // WinAPI types, FILETIME, SYSTEMTIME, FileTimeToSystemTime
#include <detours.h>   // Detours API for function hooking
#include <cstdlib>     // getenv for reading environment variables
#include <cstdio>   // sscanf for parsing MYTIME environment variable


// ---------------- Original ----------------
static BOOL(WINAPI* TrueFileTimeToSystemTime)(const FILETIME* lpFileTime, LPSYSTEMTIME lpSystemTime) = FileTimeToSystemTime;

// ---------------- Helper ----------------
static bool ParseMyTime(const char* env, SYSTEMTIME* st) {
    if (!env || !st) return false;

    SYSTEMTIME now{};
    GetSystemTime(&now);  // fallback = current system time

    int year   = now.wYear;
    int month  = now.wMonth;
    int day    = now.wDay;
    int hour   = now.wHour;
    int minute = now.wMinute;
    int second = now.wSecond;

    // Only time "Thh[:mm[:ss]]"
    if (env[0] == 'T') {
        int matched = sscanf(env, "T%d:%d:%d", &hour, &minute, &second);
        // fill SYSTEMTIME
        st->wYear   = now.wYear;
        st->wMonth  = now.wMonth;
        st->wDay    = now.wDay;
        st->wHour   = (hour>=0 && hour<=23) ? hour : now.wHour;
        st->wMinute = (minute>=0 && minute<=59) ? minute : now.wMinute;
        st->wSecond = (second>=0 && second<=59) ? second : now.wSecond;
        return true;
    }

    // Full datetime "YYYY[-MM[-DD]]T[hh[:mm[:ss]]]"
    int matched = sscanf(env, "%d-%d-%dT%d:%d:%d", &year, &month, &day, &hour, &minute, &second);
    st->wYear   = (matched >= 1 && year > 0) ? year : now.wYear;
    st->wMonth  = (matched >= 2 && month >= 1 && month <= 12) ? month : now.wMonth;
    st->wDay    = (matched >= 3 && day >= 1 && day <= 31) ? day : now.wDay;
    st->wHour   = (matched >= 4 && hour >= 0 && hour <= 23) ? hour : now.wHour;
    st->wMinute = (matched >= 5 && minute >= 0 && minute <= 59) ? minute : now.wMinute;
    st->wSecond = (matched >= 6 && second >= 0 && second <= 59) ? second : now.wSecond;

    if (matched == 0) *st = now;  // fallback to current time

    return true;
}

// ---------------- Detour ----------------
BOOL WINAPI DetourFileTimeToSystemTime(const FILETIME* lpFileTime, LPSYSTEMTIME lpSystemTime) {
    BOOL ret = TrueFileTimeToSystemTime(lpFileTime, lpSystemTime);
    const char* mytime = getenv("MYTIME");
    if (mytime) {
        ParseMyTime(mytime, lpSystemTime);
    }
    return ret;
}

// ---------------- DllMain ----------------
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch(ul_reason_for_call) {
        case DLL_PROCESS_ATTACH:
            DetourRestoreAfterWith();
            DetourTransactionBegin();
            DetourUpdateThread(GetCurrentThread());
            DetourAttach(&(PVOID&)TrueFileTimeToSystemTime, DetourFileTimeToSystemTime);
            DetourTransactionCommit();
            break;
        case DLL_PROCESS_DETACH:
            DetourTransactionBegin();
            DetourUpdateThread(GetCurrentThread());
            DetourDetach(&(PVOID&)TrueFileTimeToSystemTime, DetourFileTimeToSystemTime);
            DetourTransactionCommit();
            break;
    }
    return TRUE;
}
