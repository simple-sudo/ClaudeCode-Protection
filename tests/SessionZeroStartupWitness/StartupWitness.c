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

void WINAPI StartupWitness(void)
{
    HANDLE output = GetStdHandle(STD_OUTPUT_HANDLE);
    if (!output || output == INVALID_HANDLE_VALUE)
        ExitProcess(64);
    CHECKPOINT("ENTRY");

#ifdef ORDINARY_WIN32K_CONTROL
    PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY control = {0};
    control.DisallowWin32kSystemCalls = 1;
    if (!SetProcessMitigationPolicy(ProcessSystemCallDisablePolicy, &control, sizeof(control)))
        Fail(output, 70);
#endif

    CHECKPOINT("BEFORE_USER32");
    HMODULE user = LoadLibraryExW(L"user32.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!user)
    {
        DWORD error = GetLastError();
        VALUE("WIN32", error);
        DiagnoseUser32(output);
        ExitProcess(65);
    }
    CHECKPOINT("AFTER_USER32");

    CHECKPOINT("BEFORE_DESKTOP");
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
    DiagnoseUser32(output);
    ExitProcess(0);
}
