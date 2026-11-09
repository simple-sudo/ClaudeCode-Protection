#define WIN32_LEAN_AND_MEAN
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

static void Fail(HANDLE output, DWORD exit_code)
{
    static const char digits[] = "0123456789ABCDEF";
    char text[] = "WIN32=0x00000000\n";
    DWORD error = GetLastError();
    for (unsigned i = 0; i < 8; ++i)
        text[8 + i] = digits[(error >> (28 - 4 * i)) & 0xf];
    Write(output, text, sizeof(text) - 1);
    ExitProcess(exit_code);
}

typedef HWND (WINAPI *DesktopWindowFunction)(void);

void WINAPI StartupWitness(void)
{
    HANDLE output = GetStdHandle(STD_OUTPUT_HANDLE);
    if (!output || output == INVALID_HANDLE_VALUE)
        ExitProcess(64);
    CHECKPOINT("ENTRY");

    CHECKPOINT("BEFORE_USER32");
    HMODULE user = LoadLibraryExW(L"user32.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!user)
        Fail(output, 65);
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
    ExitProcess(0);
}
