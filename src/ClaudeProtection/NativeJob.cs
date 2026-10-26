using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using System.Security.Principal;

namespace ClaudeProtection;

// The job controls only the suspended child and normally inherited descendants.
// It grants no network isolation. The handle is never inheritable.
internal sealed class NativeJob : IDisposable
{
    private IntPtr job;
    private IntPtr process;
    internal uint Pid { get; private set; }
    internal bool HasExited => process == IntPtr.Zero || WaitForSingleObject(process, 0) == 0;
    internal uint ExitCode { get { if (!GetExitCodeProcess(process, out var code)) throw Error(); return code; } }
    internal uint ActiveProcesses
    {
        get
        {
            if (!QueryInformationJobObject(job, 1, out var accounting, (uint)Marshal.SizeOf<BasicAccounting>(), IntPtr.Zero)) throw Error("QueryJobAccounting");
            return accounting.ActiveProcesses;
        }
    }
    internal uint[] ProcessIds
    {
        get
        {
            const int capacity = 32;
            int length = 8 + IntPtr.Size * capacity;
            var buffer = Marshal.AllocHGlobal(length);
            try
            {
                if (!QueryJobBuffer(job, 3, buffer, (uint)length, out _)) throw Error("QueryOwnedJobProcessIds");
                int count = Marshal.ReadInt32(buffer, 4);
                if (count < 0 || count > capacity) throw new InvalidDataException("Unexpected owned process count");
                return Enumerable.Range(0, count).Select(i => checked((uint)Marshal.ReadIntPtr(buffer, 8 + i * IntPtr.Size).ToInt64())).ToArray();
            }
            finally { Marshal.FreeHGlobal(buffer); }
        }
    }

    internal NativeJob(string executable, IEnumerable<string> args, string cwd, IReadOnlyDictionary<string, string>? overrides = null, IntPtr sandboxSid = default, IntPtr output = default, bool cleanEnvironment = false)
    {
        // Ordinary process creation from the old aggregate selftest is not
        // available until separately reviewed. Current callers are probes only.
        if (sandboxSid == IntPtr.Zero || output == IntPtr.Zero || !cleanEnvironment)
            throw new InvalidOperationException("Only explicit disposable sandbox jobs are supported");
        job = CreateJobObject(IntPtr.Zero, null);
        if (job == IntPtr.Zero) throw Error();
        try
        {
            var limits = new ExtendedLimits();
            limits.Basic.LimitFlags = 0x2000; // JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE. No breakaway.
            if (!SetInformationJobObject(job, 9, ref limits, (uint)Marshal.SizeOf<ExtendedLimits>())) throw Error();
            var env = Environment.GetEnvironmentVariables().Cast<System.Collections.DictionaryEntry>()
                .Where(e => !cleanEnvironment || new[] { "SystemRoot", "SystemDrive", "WINDIR", "COMSPEC", "ProgramFiles", "ProgramFiles(x86)", "PROCESSOR_ARCHITECTURE", "DOTNET_ROOT", "LOCALAPPDATA", "TEMP", "TMP", "USERPROFILE" }.Contains((string)e.Key, StringComparer.OrdinalIgnoreCase))
                .ToDictionary(e => (string)e.Key, e => (string?)e.Value ?? "", StringComparer.OrdinalIgnoreCase);
            if (overrides is not null) foreach (var pair in overrides) env[pair.Key] = pair.Value;
            var block = string.Join('\0', env.OrderBy(e => e.Key, StringComparer.OrdinalIgnoreCase).Select(e => e.Key + "=" + e.Value)) + "\0\0";
            var pointer = Marshal.StringToHGlobalUni(block);
            var info = new StartupInfoEx { Basic = new StartupInfo { Size = Marshal.SizeOf<StartupInfo>(), Flags = 0x100, StdInput = GetStdHandle(-10), StdOutput = output == IntPtr.Zero ? GetStdHandle(-11) : output, StdError = output == IntPtr.Zero ? GetStdHandle(-12) : output } };
            IntPtr capabilities = IntPtr.Zero;
            IntPtr handles = IntPtr.Zero;
            bool attributesInitialized = false;
            ProcessInfo created = default;
            try
            {
                if (sandboxSid != IntPtr.Zero)
                {
                    nuint length = 0;
                    if (output == IntPtr.Zero) throw new ArgumentException("Disposable sandbox requires an explicit output pipe");
                    _ = InitializeProcThreadAttributeList(IntPtr.Zero, 2, 0, ref length);
                    if (length == 0) throw Error();
                    info.Attributes = Marshal.AllocHGlobal(checked((int)length));
                    if (!InitializeProcThreadAttributeList(info.Attributes, 2, 0, ref length)) throw Error("InitializeAttributes");
                    attributesInitialized = true;
                    var caps = new SecurityCapabilities { Sid = sandboxSid };
                    capabilities = Marshal.AllocHGlobal(Marshal.SizeOf<SecurityCapabilities>());
                    Marshal.StructureToPtr(caps, capabilities, false);
                    if (!UpdateProcThreadAttribute(info.Attributes, 0, (IntPtr)0x20009, capabilities, (nuint)Marshal.SizeOf<SecurityCapabilities>(), IntPtr.Zero, IntPtr.Zero)) throw Error("SetSecurityCapabilities");
                    // Inherit only this disposable probe's output handle, not any
                    // other inheritable parent handles or the interactive terminal.
                    info.Basic.StdInput = IntPtr.Zero;
                    handles = Marshal.AllocHGlobal(IntPtr.Size);
                    Marshal.WriteIntPtr(handles, output);
                    if (!UpdateProcThreadAttribute(info.Attributes, 0, (IntPtr)0x20002, handles, (nuint)IntPtr.Size, IntPtr.Zero, IntPtr.Zero)) throw Error("SetHandleList");
                    info.Basic.Size = Marshal.SizeOf<StartupInfoEx>();
                }
                var command = new StringBuilder(string.Join(" ", new[] { executable }.Concat(args).Select(Quote)));
                uint flags = 0x4 | 0x400;
                if (sandboxSid != IntPtr.Zero) flags |= 0x80000;
                if (!CreateProcess(executable, command, IntPtr.Zero, IntPtr.Zero, true, flags, pointer, cwd, ref info, out created)) throw Error("CreateProcess");
                process = created.Process;
                Pid = created.ProcessId;
                if (!AssignProcessToJobObject(job, process)) throw Error("AssignJob");
                if (sandboxSid != IntPtr.Zero)
                {
                    var token = SandboxToken.Read(process);
                    if (!token.IsAppContainer || token.CapabilityCount != 0 || token.Sid != new SecurityIdentifier(sandboxSid).Value) throw new InvalidOperationException("Sandbox token verification failed before resume");
                }
                if (ResumeThread(created.Thread) == uint.MaxValue) throw Error();
            }
            catch
            {
                if (created.Process != IntPtr.Zero) TerminateProcess(created.Process, 125);
                throw;
            }
            finally
            {
                if (created.Thread != IntPtr.Zero) CloseHandle(created.Thread);
                if (info.Attributes != IntPtr.Zero) { if (attributesInitialized) DeleteProcThreadAttributeList(info.Attributes); Marshal.FreeHGlobal(info.Attributes); }
                if (capabilities != IntPtr.Zero) Marshal.FreeHGlobal(capabilities);
                if (handles != IntPtr.Zero) Marshal.FreeHGlobal(handles);
                Marshal.FreeHGlobal(pointer);
            }
        }
        catch { Dispose(); throw; }
    }

    internal static string Quote(string value)
    {
        if (value.IndexOf('\0') >= 0) throw new ArgumentException("NUL in argument");
        var output = new StringBuilder("\"");
        int slashes = 0;
        foreach (var c in value)
        {
            if (c == '\\') { slashes++; continue; }
            if (c == '"') output.Append('\\', slashes * 2 + 1);
            else output.Append('\\', slashes);
            output.Append(c); slashes = 0;
        }
        output.Append('\\', slashes * 2).Append('"');
        return output.ToString();
    }

    internal void Terminate() { if (job != IntPtr.Zero && !TerminateJobObject(job, 125)) throw Error(); }
    public void Dispose()
    {
        if (job != IntPtr.Zero) { CloseHandle(job); job = IntPtr.Zero; }
        if (process != IntPtr.Zero) { CloseHandle(process); process = IntPtr.Zero; }
    }
    private static Win32Exception Error(string stage = "NativeJob") { var result = new Win32Exception(Marshal.GetLastWin32Error()); result.Data["Stage"] = stage; return result; }
    [StructLayout(LayoutKind.Sequential)] private struct BasicLimits { public long PerProcess, PerJob; public uint LimitFlags; public UIntPtr MinWorkingSet, MaxWorkingSet; public uint ActiveProcessLimit; public UIntPtr Affinity; public uint Priority, Scheduling; }
    [StructLayout(LayoutKind.Sequential)] private struct IoCounters { public ulong ReadOps, WriteOps, OtherOps, ReadBytes, WriteBytes, OtherBytes; }
    [StructLayout(LayoutKind.Sequential)] private struct ExtendedLimits { public BasicLimits Basic; public IoCounters Io; public UIntPtr ProcessMemory, JobMemory, PeakProcessMemory, PeakJobMemory; }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)] private struct StartupInfo { public int Size; public string? Reserved, Desktop, Title; public int X, Y, XSize, YSize, XCountChars, YCountChars, FillAttribute; public uint Flags; public ushort ShowWindow, ReservedBytes; public IntPtr ReservedPointer, StdInput, StdOutput, StdError; }
    [StructLayout(LayoutKind.Sequential)] private struct ProcessInfo { public IntPtr Process, Thread; public uint ProcessId, ThreadId; }
    [StructLayout(LayoutKind.Sequential)] private struct StartupInfoEx { public StartupInfo Basic; public IntPtr Attributes; }
    [StructLayout(LayoutKind.Sequential)] private struct SecurityCapabilities { public IntPtr Sid, Capabilities; public uint Count, Reserved; }
    [StructLayout(LayoutKind.Sequential)] private struct BasicAccounting { public long User, Kernel, PeriodUser, PeriodKernel; public uint PageFaults, TotalProcesses, ActiveProcesses, TerminatedProcesses; }
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern IntPtr CreateJobObject(IntPtr attributes, string? name);
    [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool SetInformationJobObject(IntPtr job, int informationClass, ref ExtendedLimits limits, uint length);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool CreateProcess(string applicationName, StringBuilder commandLine, IntPtr processAttributes, IntPtr threadAttributes, bool inheritHandles, uint flags, IntPtr environment, string currentDirectory, ref StartupInfoEx startupInfo, out ProcessInfo processInformation);
    [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool InitializeProcThreadAttributeList(IntPtr list, int count, int flags, ref nuint size);
    [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool UpdateProcThreadAttribute(IntPtr list, uint flags, IntPtr attribute, IntPtr value, nuint size, IntPtr previous, IntPtr returned);
    [DllImport("kernel32.dll")] private static extern void DeleteProcThreadAttributeList(IntPtr list);
    [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);
    [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool QueryInformationJobObject(IntPtr job, int informationClass, out BasicAccounting accounting, uint length, IntPtr returned);
    [DllImport("kernel32.dll", EntryPoint = "QueryInformationJobObject", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool QueryJobBuffer(IntPtr job, int informationClass, IntPtr buffer, uint length, out uint returned);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern uint ResumeThread(IntPtr thread);
    [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool TerminateJobObject(IntPtr job, uint exitCode);
    [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool TerminateProcess(IntPtr process, uint exitCode);
    [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);
    [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool GetExitCodeProcess(IntPtr process, out uint exitCode);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern IntPtr GetStdHandle(int handle);
}
