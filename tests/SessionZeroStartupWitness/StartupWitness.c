#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0A00
#include <windows.h>

// This test reaches its entry point with KERNEL32 as its sole static import.
// It probes only fixed System32 modules and reports each checkpoint over stdout.
static void Write(HANDLE output, const char *text, DWORD length)
{
    DWORD written = 0;
    if (!WriteFile(output, text, length, &written, NULL) || written != length)
        ExitProcess(64);
}

#define CHECKPOINT(text) Write(output, text "\n", sizeof(text))

static void Value(HANDLE output, const char *label, DWORD length, DWORD value)
{
    static const char digits[] = "0123456789ABCDEF";
    char text[] = "0x00000000\n";
    for (unsigned i = 0; i < 8; ++i)
        text[2 + i] = digits[(value >> (28 - 4 * i)) & 0xf];
    Write(output, label, length);
    Write(output, text, sizeof(text) - 1);
}

#define VALUE(label, value) Value(output, label "=", sizeof(label), value)
#define NOT_OBSERVED MAXDWORD

static void Fail(HANDLE output, DWORD exit_code)
{
    DWORD error = GetLastError();
    VALUE("WIN32", error);
    ExitProcess(exit_code);
}

#ifndef STARTUP_BRANCH_WITNESS
static DWORD MapImage(HANDLE file)
{
    HANDLE section = CreateFileMappingW(file, NULL, PAGE_READONLY | SEC_IMAGE_NO_EXECUTE, 0, 0, NULL);
    if (!section)
        return GetLastError();
    void *view = MapViewOfFile(section, FILE_MAP_READ, 0, 0, 0);
    DWORD error = view ? ERROR_SUCCESS : GetLastError();
    if (view)
        UnmapViewOfFile(view);
    CloseHandle(section);
    return error;
}

static void ObserveUser32Image(HANDLE output)
{
    static const wchar_t leaf[] = L"\\user32.dll";
    wchar_t path[MAX_PATH];
    UINT length = GetSystemDirectoryW(path, ARRAYSIZE(path));
    DWORD open_error = length ? ERROR_INSUFFICIENT_BUFFER : GetLastError();
    DWORD map_error = NOT_OBSERVED;
    if (length && length <= ARRAYSIZE(path) - ARRAYSIZE(leaf))
    {
        for (unsigned i = 0; i < ARRAYSIZE(leaf); ++i)
            path[length + i] = leaf[i];
        HANDLE file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE,
            NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        open_error = file == INVALID_HANDLE_VALUE ? GetLastError() : ERROR_SUCCESS;
        if (file != INVALID_HANDLE_VALUE)
        {
            map_error = MapImage(file);
            CloseHandle(file);
        }
    }
    VALUE("USER32_FILE", open_error);
    VALUE("USER32_MAP", map_error);
}

static DWORD ObserveLoad(const wchar_t *library)
{
    HMODULE module = LoadLibraryExW(library, NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!module)
        return GetLastError();
    FreeLibrary(module);
    return ERROR_SUCCESS;
}

static void DiagnoseUser32(HANDLE output)
{
    PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY policy;
    BOOL known = GetProcessMitigationPolicy(GetCurrentProcess(), ProcessSystemCallDisablePolicy,
        &policy, sizeof(policy));
    DWORD error = known ? ERROR_SUCCESS : GetLastError();
    VALUE("WIN32K_QUERY", error);
    VALUE("WIN32K_BLOCKED", known ? policy.DisallowWin32kSystemCalls : NOT_OBSERVED);
    ObserveUser32Image(output);
    VALUE("WIN32U_LOAD", ObserveLoad(L"win32u.dll"));
    VALUE("GDI32_LOAD", ObserveLoad(L"gdi32.dll"));
    VALUE("GDI32FULL_LOAD", ObserveLoad(L"gdi32full.dll"));
}

typedef HWND (WINAPI *DesktopWindowFunction)(void);

#ifdef STARTUP_PRIVATE_DESKTOP_WITNESS
typedef HWINSTA (WINAPI *ProcessWindowStationFunction)(void);
typedef HDESK (WINAPI *ThreadDesktopFunction)(DWORD);
typedef BOOL (WINAPI *UserObjectInformationFunction)(HANDLE, int, PVOID, DWORD, LPDWORD);

static BOOL ExactName(UserObjectInformationFunction read, HANDLE object, const wchar_t *expected, DWORD chars)
{
    wchar_t actual[64];
    DWORD used;
    if (!object || !read(object, UOI_NAME, actual, sizeof(actual), &used) || used != (chars + 1) * sizeof(wchar_t))
        return FALSE;
    for (DWORD i = 0; i < chars; ++i)
        if (actual[i] != expected[i])
            return FALSE;
    return actual[chars] == L'\0';
}

static BOOL PrivateDesktopSelected(HMODULE user)
{
    static const wchar_t prefix[] = L"CpcTask.";
    static const wchar_t desktop_name[] = L"Task";
    const DWORD prefix_length = ARRAYSIZE(prefix) - 1;
    const DWORD station_length = prefix_length + 32;
    STARTUPINFOW startup;
    GetStartupInfoW(&startup);
    const wchar_t *target = startup.lpDesktop;
    if (!target)
        return FALSE;
    for (DWORD i = 0; i < prefix_length; ++i)
        if (target[i] != prefix[i])
            return FALSE;
    for (DWORD i = prefix_length; i < station_length; ++i)
        if (!(target[i] >= L'0' && target[i] <= L'9') && !(target[i] >= L'a' && target[i] <= L'f'))
            return FALSE;
    if (target[station_length] != L'\\')
        return FALSE;
    for (DWORD i = 0; i < ARRAYSIZE(desktop_name); ++i)
        if (target[station_length + 1 + i] != desktop_name[i])
            return FALSE;

    ProcessWindowStationFunction station = (ProcessWindowStationFunction)(void *)GetProcAddress(user, "GetProcessWindowStation");
    ThreadDesktopFunction desktop = (ThreadDesktopFunction)(void *)GetProcAddress(user, "GetThreadDesktop");
    UserObjectInformationFunction read = (UserObjectInformationFunction)(void *)GetProcAddress(user, "GetUserObjectInformationW");
    if (!station || !desktop || !read)
        return FALSE;
    HWINSTA actual_station = station();
    USEROBJECTFLAGS flags;
    DWORD used;
    return actual_station && read(actual_station, UOI_FLAGS, &flags, sizeof(flags), &used) &&
        used == sizeof(flags) && !(flags.dwFlags & WSF_VISIBLE) &&
        ExactName(read, actual_station, target, station_length) &&
        ExactName(read, desktop(GetCurrentThreadId()), desktop_name, ARRAYSIZE(desktop_name) - 1);
}

#ifdef STARTUP_PRIVATE_TRACE_WITNESS
// These WIN32U entry points match the public USER32 thunks on the exact
// system image held by this diagnostic. Call only after the first load failed.
static DWORD ObservedName(UserObjectInformationFunction read, HANDLE object, const wchar_t *expected, DWORD chars)
{
    wchar_t actual[64];
    DWORD used;
    if (!object || !read(object, UOI_NAME, actual, sizeof(actual), &used) ||
        used < sizeof(wchar_t) || used > sizeof(actual) || used % sizeof(wchar_t) || actual[used / sizeof(wchar_t) - 1] != L'\0')
        return NOT_OBSERVED;
    if (used != (chars + 1) * sizeof(wchar_t))
        return 0;
    for (DWORD i = 0; i < chars; ++i)
        if (actual[i] != expected[i])
            return 0;
    return 1;
}

static void ObservePrivateWindowFailure(HANDLE output)
{
    HMODULE module = LoadLibraryExW(L"win32u.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
    ProcessWindowStationFunction station = module ? (ProcessWindowStationFunction)(void *)GetProcAddress(module, "NtUserGetProcessWindowStation") : NULL;
    ThreadDesktopFunction desktop = module ? (ThreadDesktopFunction)(void *)GetProcAddress(module, "NtUserGetThreadDesktop") : NULL;
    UserObjectInformationFunction read = module ? (UserObjectInformationFunction)(void *)GetProcAddress(module, "NtUserGetObjectInformation") : NULL;
    DWORD error = !module ? GetLastError() : station && desktop && read ? ERROR_SUCCESS : ERROR_PROC_NOT_FOUND;
    VALUE("WINDOW_QUERY", error);
    if (error)
        return;

    HWINSTA station_handle = station();
    HDESK desktop_handle = desktop(GetCurrentThreadId());
    VALUE("WINDOW_STATION_PRESENT", station_handle != NULL);
    VALUE("WINDOW_DESKTOP_PRESENT", desktop_handle != NULL);
    STARTUPINFOW startup;
    GetStartupInfoW(&startup);
    PCWSTR target = startup.lpDesktop;
    DWORD length = 0;
    if (target)
        while (length < 64 && target[length]) ++length;
    DWORD station_match = NOT_OBSERVED, desktop_match = NOT_OBSERVED;
    if (length == 45 && target[40] == L'\\') // CpcTask. + 32 digits + \Task.
    {
        station_match = ObservedName(read, station_handle, target, 40);
        desktop_match = ObservedName(read, desktop_handle, target + 41, 4);
    }
    VALUE("WINDOW_STATION_MATCH", station_match);
    VALUE("WINDOW_DESKTOP_MATCH", desktop_match);
}
#endif
#endif
#endif

void WINAPI StartupWitness(void)
{
    HANDLE output = GetStdHandle(STD_OUTPUT_HANDLE);
    if (!output || output == INVALID_HANDLE_VALUE)
        ExitProcess(64);
    CHECKPOINT("ENTRY");

#if defined(STARTUP_BRANCH_WITNESS) || defined(STARTUP_PRIVATE_TRACE_WITNESS)
    ULONGLONG deadline = GetTickCount64() + 4500;
    while (!IsDebuggerPresent())
    {
        if (GetTickCount64() >= deadline)
            ExitProcess(71);
        Sleep(10);
    }
#endif

#ifdef ORDINARY_WIN32K_CONTROL
    PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY control = {0};
    control.DisallowWin32kSystemCalls = 1;
    if (!SetProcessMitigationPolicy(ProcessSystemCallDisablePolicy, &control, sizeof(control)))
        Fail(output, 70);
#endif

    CHECKPOINT("BEFORE_USER32");
    HMODULE user = LoadLibraryExW(L"user32.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
#ifdef STARTUP_BRANCH_WITNESS
    if (!user)
        Fail(output, 65);
    CHECKPOINT("AFTER_USER32");
#else
    if (!user)
    {
        DWORD error = GetLastError();
        VALUE("WIN32", error);
#ifdef STARTUP_PRIVATE_TRACE_WITNESS
        ObservePrivateWindowFailure(output);
#else
        DiagnoseUser32(output);
#endif
        ExitProcess(65);
    }
    CHECKPOINT("AFTER_USER32");

    CHECKPOINT("BEFORE_DESKTOP");
#ifdef STARTUP_PRIVATE_DESKTOP_WITNESS
    if (!PrivateDesktopSelected(user))
    {
        SetLastError(ERROR_INVALID_DATA);
        Fail(output, 72);
    }
#endif
    DesktopWindowFunction desktop = (DesktopWindowFunction)(void *)GetProcAddress(user, "GetDesktopWindow");
    if (!desktop)
        Fail(output, 66);
    SetLastError(ERROR_SUCCESS);
    if (!desktop())
        Fail(output, 67);
    CHECKPOINT("AFTER_DESKTOP");

    CHECKPOINT("BEFORE_SHELL32");
    if (!LoadLibraryExW(L"shell32.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32))
        Fail(output, 68);
    CHECKPOINT("AFTER_SHELL32");

    CHECKPOINT("BEFORE_UCRT");
    if (!LoadLibraryExW(L"ucrtbase.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32))
        Fail(output, 69);
    CHECKPOINT("AFTER_UCRT");
#ifdef STARTUP_PRIVATE_DESKTOP_WITNESS
    CHECKPOINT("PRIVATE_DESKTOP_MATCHED");
#endif
    DiagnoseUser32(output);
#endif
    ExitProcess(0);
}
