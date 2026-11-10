#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0A00
#include <windows.h>

// Kernel32-only entry point. Private stdout carries actual probe bytes.
static void Write(HANDLE out, const char *text, DWORD length)
{
    DWORD written;
    if (!WriteFile(out, text, length, &written, NULL) || written != length) ExitProcess(64);
}
static void Hex(HANDLE out, const void *buffer, DWORD length)
{
    static const char digits[] = "0123456789ABCDEF";
    const unsigned char *bytes = buffer;
    char text[256];
    for (DWORD i = 0; i < length; ++i) {
        text[(i % 128) * 2] = digits[bytes[i] >> 4];
        text[(i % 128) * 2 + 1] = digits[bytes[i] & 15];
        if (i % 128 == 127) Write(out, text, sizeof(text));
    }
    if (length % 128) Write(out, text, (length % 128) * 2);
    Write(out, "\n", 1);
}
#define MARK(value) Write(out, value "\n", sizeof(value))
#define VALUE(label, value) do { DWORD n = (DWORD)(value); Write(out, label "=", sizeof(label)); Hex(out, &n, sizeof(n)); } while (0)

typedef struct { UINT count; void *rows; } AdapterList;
typedef struct { UINT handle; LUID luid; UINT sources; UINT precise; } Adapter;
typedef LONG (WINAPI *Enumerate)(AdapterList *);
typedef LONG (WINAPI *CloseAdapter)(const UINT *);
typedef HWND (WINAPI *GetDesktop)(void);

static void Wddm(HANDLE out)
{
    MARK("WDDM_ENTER");
    HMODULE user = LoadLibraryExW(L"user32.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
    VALUE("USER32_LOAD", user ? 0 : GetLastError());
    if (user) {
        GetDesktop desktop = (GetDesktop)(void *)GetProcAddress(user, "GetDesktopWindow");
        if (desktop) VALUE("DESKTOP_PRESENT", desktop() ? 1 : 0);
    }
    HMODULE module = LoadLibraryExW(L"win32u.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
    VALUE("WIN32U_LOAD", module ? 0 : GetLastError());
    if (!module) { if (user) FreeLibrary(user); return; }
    Enumerate read = (Enumerate)(void *)GetProcAddress(module, "NtGdiDdDDIEnumAdapters2");
    CloseAdapter close = (CloseAdapter)(void *)GetProcAddress(module, "NtGdiDdDDICloseAdapter");
    if (read && close) {
        AdapterList list = {0};
        Adapter rows[64];
        LONG status = read(&list);
        VALUE("WDDM_SIZE", status);
        if (status == 0 && list.count > 0 && list.count <= ARRAYSIZE(rows)) {
            UINT capacity = list.count;
            list.rows = rows;
            status = read(&list);
            VALUE("WDDM_READ", status);
            if (status == 0 && list.count <= capacity) {
                VALUE("WDDM_COUNT", list.count);
                for (UINT i = 0; i < list.count; ++i) {
                    Write(out, "WDDM_LUID=", 10);
                    Hex(out, &rows[i].luid, sizeof(rows[i].luid));
                    VALUE("WDDM_CLOSE", close(&rows[i].handle));
                }
            }
        }
    } else MARK("WDDM_EXPORT_MISSING");
    FreeLibrary(module);
    if (user) FreeLibrary(user);
}

typedef ULONG (WINAPI *PnpSize)(ULONG *, const wchar_t *, ULONG);
typedef ULONG (WINAPI *PnpList)(const wchar_t *, wchar_t *, ULONG, ULONG);
static void Pnp(HANDLE out)
{
    static const wchar_t display[] = L"{4d36e968-e325-11ce-bfc1-08002be10318}";
    MARK("PNP_ENTER");
    HMODULE module = LoadLibraryExW(L"cfgmgr32.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
    VALUE("PNP_LOAD", module ? 0 : GetLastError());
    if (!module) return;
    PnpSize size = (PnpSize)(void *)GetProcAddress(module, "CM_Get_Device_ID_List_SizeW");
    PnpList list = (PnpList)(void *)GetProcAddress(module, "CM_Get_Device_ID_ListW");
    if (size && list) {
        ULONG chars = 0;
        ULONG code = size(&chars, display, 0x300);
        VALUE("PNP_SIZE", code);
        if (code == 0 && chars > 0 && chars <= 4096) {
            SIZE_T bytes = chars * sizeof(wchar_t);
            wchar_t *buffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, bytes);
            if (!buffer) ExitProcess(65);
            code = list(display, buffer, chars, 0x300);
            VALUE("PNP_LIST", code);
            if (code == 0) { Write(out, "PNP_CONTENT=", 12); Hex(out, buffer, (DWORD)bytes); }
            HeapFree(GetProcessHeap(), 0, buffer);
        }
    } else MARK("PNP_EXPORT_MISSING");
    FreeLibrary(module);
}

typedef int (WINAPI *InitCuda)(UINT);
typedef int (WINAPI *GetCudaDevice)(int *, int);
typedef int (WINAPI *GetCudaUuid)(void *, int);
static void Cuda(HANDLE out)
{
    MARK("CUDA_ENTER");
    HMODULE module = LoadLibraryExW(L"nvcuda.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
    VALUE("CUDA_LOAD", module ? 0 : GetLastError());
    if (!module) return;
    InitCuda init = (InitCuda)(void *)GetProcAddress(module, "cuInit");
    GetCudaDevice device = (GetCudaDevice)(void *)GetProcAddress(module, "cuDeviceGet");
    GetCudaUuid uuid = (GetCudaUuid)(void *)GetProcAddress(module, "cuDeviceGetUuid_v2");
    if (init && device && uuid) {
        int code = init(0), ordinal = 0;
        VALUE("CUDA_INIT", code);
        if (code == 0) {
            code = device(&ordinal, 0);
            VALUE("CUDA_DEVICE", code);
            if (code == 0) {
                char value[16];
                code = uuid(value, ordinal);
                VALUE("CUDA_UUID_STATUS", code);
                if (code == 0) { Write(out, "CUDA_UUID=", 10); Hex(out, value, sizeof(value)); }
            }
        }
    } else MARK("CUDA_EXPORT_MISSING");
    FreeLibrary(module);
}

typedef int (WINAPI *NvmlCall)(void);
typedef int (WINAPI *NvmlHandle)(UINT, void **);
typedef int (WINAPI *NvmlUuid)(void *, char *, UINT);
static void Nvml(HANDLE out)
{
    MARK("NVML_ENTER");
    HMODULE module = LoadLibraryExW(L"nvml.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
    VALUE("NVML_LOAD", module ? 0 : GetLastError());
    if (!module) return;
    NvmlCall init = (NvmlCall)(void *)GetProcAddress(module, "nvmlInit_v2");
    NvmlCall shutdown = (NvmlCall)(void *)GetProcAddress(module, "nvmlShutdown");
    NvmlHandle handle = (NvmlHandle)(void *)GetProcAddress(module, "nvmlDeviceGetHandleByIndex_v2");
    NvmlUuid uuid = (NvmlUuid)(void *)GetProcAddress(module, "nvmlDeviceGetUUID");
    if (init && shutdown && handle && uuid) {
        int code = init();
        VALUE("NVML_INIT", code);
        if (code == 0) {
            void *device = NULL;
            code = handle(0, &device);
            VALUE("NVML_HANDLE", code);
            if (code == 0) {
                char value[96];
                code = uuid(device, value, sizeof(value));
                VALUE("NVML_UUID_STATUS", code);
                if (code == 0) {
                    DWORD bytes = 0;
                    while (bytes < sizeof(value) && value[bytes]) ++bytes;
                    if (bytes < sizeof(value)) { Write(out, "NVML_UUID=", 10); Hex(out, value, bytes); }
                }
            }
            VALUE("NVML_SHUTDOWN", shutdown());
        }
    } else MARK("NVML_EXPORT_MISSING");
    FreeLibrary(module);
}

void GpuWin32kNative(void)
{
    HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);
    if (out == INVALID_HANDLE_VALUE || !out) ExitProcess(64);
    MARK("ENTRY");
    PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY policy = {0};
#ifdef TEST_WIN32K_DISABLED
    policy.DisallowWin32kSystemCalls = 1;
    if (!SetProcessMitigationPolicy(ProcessSystemCallDisablePolicy, &policy, sizeof(policy))) {
        VALUE("SET_FAILED", GetLastError());
        ExitProcess(66);
    }
#endif
    if (!GetProcessMitigationPolicy(GetCurrentProcess(), ProcessSystemCallDisablePolicy, &policy, sizeof(policy))) ExitProcess(67);
    VALUE("WIN32K", policy.DisallowWin32kSystemCalls);
    Pnp(out);
    Nvml(out);
    Cuda(out);
    Wddm(out);
    MARK("FINISHED");
    ExitProcess(0);
}
