using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace ClaudeCodeProtection.Workspaces;

// Narrow byte transfer, not an executor or privileged host-file service.
// Capture is ordinary-user only. The Broker can materialize bytes in a fresh
// child of its already owned task root; it never reads a caller's host paths.
internal static class WorkspaceFiles
{
    internal static void RequireOrdinaryUser()
    {
        using var user=WindowsIdentity.GetCurrent();
        if(new WindowsPrincipal(user).IsInRole(WindowsBuiltInRole.Administrator))throw new InvalidOperationException("Workspace maintenance must not be elevated");
    }
    internal static byte[] Capture(string root,IEnumerable<string> selected)
    {
        RequireOrdinaryUser();
        var names=selected.Take(WorkspaceBundle.MaxFiles+1).ToArray();
        // Validate all names/collisions before reading any project content.
        WorkspaceBundle.Create(names.Select(p=>(p,Array.Empty<byte>())));
        using var held=new HeldPaths();held.DirectoryChain(root);
        var files=new List<(string Path,FileStream Stream)>();
        foreach(var relative in names)
        {
            var path=Child(root,WorkspaceBundle.Relative(relative));held.DirectoryChain(Path.GetDirectoryName(path)!);
            files.Add((relative,held.ReadFile(path)));
        }
        long total=0;var contents=new List<(string Path,byte[] Content)>();
        foreach(var file in files)
        {
            if(file.Stream.Length>WorkspaceBundle.MaxFileBytes || (total+=file.Stream.Length)>WorkspaceBundle.MaxTotalBytes)
                throw new InvalidDataException("Workspace capture bounds");
            var bytes=new byte[checked((int)file.Stream.Length)];file.Stream.ReadExactly(bytes);contents.Add((file.Path,bytes));
        }
        return WorkspaceBundle.Create(contents).Serialize();
    }
    internal static byte[] ReadBundle(string path)
    {
        using var held=new HeldPaths();held.DirectoryChain(Path.GetDirectoryName(Local(path))!);using var file=held.ReadFile(path);
        if(file.Length is <1 or >WorkspaceBundle.MaxBundleBytes)throw new InvalidDataException("Workspace bundle file bounds");
        var bytes=new byte[checked((int)file.Length)];file.ReadExactly(bytes);_=WorkspaceBundle.Parse(bytes);return bytes;
    }
    internal static void WriteBundleNew(string path,byte[] bytes)
    {
        RequireOrdinaryUser();_=WorkspaceBundle.Parse(bytes);
        using var held=new HeldPaths();held.DirectoryChain(Path.GetDirectoryName(Local(path))!);
        using var file=held.NewFile(path);file.Write(bytes);file.Flush(true);
    }
    // Reserve a new ordinary-user result before UAC and hold its complete
    // ancestry. Cancel/failure leaves this owned empty/partial file for review;
    // never delete, overwrite, merge or silently reuse an existing output.
    internal sealed class BundleOutput : IDisposable
    {
        private readonly HeldPaths held=new();
        private readonly FileStream file;
        private bool completed;
        internal BundleOutput(string path)
        {
            try{held.DirectoryChain(Path.GetDirectoryName(Local(path))!);file=held.NewFile(path);}
            catch{held.Dispose();throw;}
        }
        internal void Complete(byte[] bytes)
        {
            if(completed || file.Position!=0 || file.Length!=0)throw new IOException("Fresh workspace output required");
            _=WorkspaceBundle.Parse(bytes);file.Write(bytes);file.Flush(true);completed=true;
        }
        public void Dispose()=>held.Dispose();
    }
    internal static BundleOutput ReserveBundleNew(string path)
    {RequireOrdinaryUser();return new(path);}
    internal static void ExtractResultNew(string destination,byte[] baselineBytes,byte[] resultBytes)
    {
        RequireOrdinaryUser();_=WorkspaceBundle.Compare(baselineBytes,resultBytes);
        var path=Local(destination);var parent=Path.GetDirectoryName(path)??throw new InvalidDataException("Fresh result directory required");
        // Every path has already been validated before the first mutation.
        // MaterializeNew never merges/overwrites/deletes an existing project.
        MaterializeNew(parent,WorkspaceBundle.Relative(Path.GetFileName(path)),resultBytes);
    }
    internal static byte[] ReadInput(Stream stream,int maximum)
    {
        if(maximum is <1 or >WorkspaceBundle.MaxBundleBytes)throw new InvalidDataException("Workspace stream bound refused");
        using var data=new MemoryStream();var buffer=new byte[65536];
        using var deadline=new CancellationTokenSource(TimeSpan.FromSeconds(15));
        while(true)
        {
            var size=stream.ReadAsync(buffer.AsMemory(0,(int)Math.Min(buffer.Length,maximum-data.Length+1)),deadline.Token)
                .AsTask().WaitAsync(deadline.Token).GetAwaiter().GetResult();
            if(size==0)return data.ToArray();
            if(data.Length+size>maximum)throw new InvalidDataException("Workspace input stream too large");
            data.Write(buffer,0,size);
        }
    }
    // Called by the existing session owner only after exact Job-zero and
    // quarantine. File lists come from this owned task tree, never host paths.
    internal static byte[] SnapshotResult(string taskRoot,string directory,byte[] baselineBytes)
    {
        var baseline=WorkspaceBundle.Parse(baselineBytes);
        if(baseline.BaseSHA256 is not null || WorkspaceBundle.Relative(directory).Contains('/'))throw new InvalidDataException("Workspace baseline required");
        var root=Child(taskRoot,directory);using var held=new HeldPaths();held.DirectoryChain(root);
        var pending=new Stack<string>();pending.Push(root);int directoryCount=0;long total=0;
        var files=new List<(string Path,FileStream Stream)>();
        while(pending.Count>0)
        {
            var parent=pending.Pop();
            // A fresh synchronous scan cursor on this already-held NTFS
            // directory, using the SAME names-only reader as lifecycle checks.
            using var scan=Open(parent,true,true,false);
            foreach(var name in WindowsDirectoryNames.Read(scan,WorkspaceBundle.MaxFiles*2+1))
            {
                var path=Child(parent,name);
                var relative=Path.GetRelativePath(root,path).Replace('\\','/');
                if(parent==root && Path.GetFileName(path).Equals(".git",StringComparison.OrdinalIgnoreCase))continue;
                _=WorkspaceBundle.Relative(relative);
                if((File.GetAttributes(path)&FileAttributes.Directory)!=0)
                {
                    if(++directoryCount>WorkspaceBundle.MaxFiles)throw new InvalidDataException("Workspace result directory bounds");
                    held.DirectoryChain(path);pending.Push(path);
                }
                else
                {
                    if(files.Count>=WorkspaceBundle.MaxFiles)throw new InvalidDataException("Workspace result inventory bounds");
                    var file=held.ReadFile(path);
                    if(file.Length>WorkspaceBundle.MaxFileBytes || (total+=file.Length)>WorkspaceBundle.MaxTotalBytes)throw new InvalidDataException("Workspace result content bounds");
                    files.Add((relative,file));
                }
            }
        }
        var result=WorkspaceBundle.Create(files.Select(f=>
        {var content=new byte[checked((int)f.Stream.Length)];f.Stream.ReadExactly(content);return(f.Path,content);}),WorkspaceBundle.Hash(baselineBytes)).Serialize();
        _=WorkspaceBundle.Compare(baselineBytes,result);return result;
    }
    // No adoption, overwrite, ACL expansion, recursion, host path or deletion.
    // Existing task root remains held by SessionResources throughout this call.
    internal static void MaterializeNew(string taskRoot,string directory,byte[] bytes)
    {
        var bundle=WorkspaceBundle.Parse(bytes);
        if(WorkspaceBundle.Relative(directory).Contains('/'))throw new InvalidDataException("One new project directory required");
        using var held=new HeldPaths();held.DirectoryChain(taskRoot);
        var root=Child(taskRoot,directory);held.NewDirectory(root);
        foreach(var entry in bundle.Files)
        {
            var path=Child(root,entry.Path);var relativeDirectory=Path.GetDirectoryName(path)!;
            held.NewDescendants(root,relativeDirectory);
            using var file=held.NewFile(path);file.Write(entry.Content);file.Flush(true);
        }
    }
    internal static string[] ReadSelection(string path)
    {
        RequireOrdinaryUser();using var held=new HeldPaths();held.DirectoryChain(Path.GetDirectoryName(Local(path))!);
        using var file=held.ReadFile(path);if(file.Length is <2 or >100000)throw new InvalidDataException("Workspace selection bounds");
        var bytes=new byte[checked((int)file.Length)];file.ReadExactly(bytes);
        var names=System.Text.Json.JsonSerializer.Deserialize<string[]>(bytes)??throw new InvalidDataException("Workspace selection missing");
        WorkspaceBundle.Create(names.Select(p=>(p,Array.Empty<byte>())));return names;
    }
    private static string Local(string path)
    {
        if(path.Length is <3 or >240 || !char.IsAsciiLetter(path[0]) || path[1]!=':' || path[2]!='\\' ||
            path.Contains('/') || path.AsSpan(2).Contains(':') || path.Contains('\0') || path.Contains("\\\\",StringComparison.Ordinal))
            throw new InvalidDataException("Bounded local workspace path required");
        var parts=path[3..].Split('\\',StringSplitOptions.RemoveEmptyEntries);
        if(parts.Any(p=>p is "." or ".." || p.EndsWith('.') || p.EndsWith(' ')))throw new InvalidDataException("Ambiguous local workspace path");
        var full=Path.GetFullPath(path);if(GetDriveType(full[..3])!=3)throw new InvalidDataException("Fixed local drive required");
        return full.Length==3?full:full.TrimEnd('\\');
    }
    private static string Child(string root,string relative)=>Local(Path.Combine(Local(root),relative.Replace('/','\\')));
    internal sealed class HeldPaths : IDisposable
    {
        private readonly Dictionary<string,SafeFileHandle> directories=new(StringComparer.OrdinalIgnoreCase);
        private readonly List<FileStream> files=new();
        internal void DirectoryChain(string path)
        {
            path=Local(path);if(directories.ContainsKey(path))return;
            if(path.Length>3)DirectoryChain(Path.GetDirectoryName(path)!);
            directories.Add(path,Open(path,true,false,false));
        }
        internal void NewDirectory(string path)
        {
            path=Local(path);
            if(!CreateDirectory(path,IntPtr.Zero))throw new Win32Exception(Marshal.GetLastWin32Error(),"Create fresh workspace directory");
            directories.Add(path,Open(path,true,false,false));
        }
        internal void NewDescendants(string root,string path)
        {
            if(path.Equals(root,StringComparison.OrdinalIgnoreCase) || directories.ContainsKey(path))return;
            if(!path.StartsWith(root+"\\",StringComparison.OrdinalIgnoreCase))throw new InvalidDataException("Workspace directory escaped");
            NewDescendants(root,Path.GetDirectoryName(path)!);NewDirectory(path);
        }
        internal FileStream ReadFile(string path)
        {var file=new FileStream(Open(Local(path),false,true,false),FileAccess.Read);files.Add(file);return file;}
        internal FileStream NewFile(string path)
        {var file=new FileStream(Open(Local(path),false,false,true),FileAccess.Write);files.Add(file);return file;}
        public void Dispose()
        {foreach(var file in files)file.Dispose();foreach(var directory in directories.Values.Reverse())directory.Dispose();}
    }
    private static SafeFileHandle Open(string path,bool directory,bool read,bool create)
    {
        var handle=CreateFile(path,0x80u|(read?0x80000000u:0u)|(create?0x40000000u:0u),1,IntPtr.Zero,create?1u:3u,
            0x00200000u|(directory?0x02000000u:0u),IntPtr.Zero);
        if(handle.IsInvalid){var error=Marshal.GetLastWin32Error();handle.Dispose();throw new Win32Exception(error,"Open workspace object");}
        try
        {
            if(!GetFileInformationByHandle(handle,out var info))throw new Win32Exception(Marshal.GetLastWin32Error(),"Workspace object identity");
            if((info.Attributes&0x400)!=0 || ((info.Attributes&0x10)!=0)!=directory || !directory && info.Links!=1)
                throw new InvalidDataException("Workspace reparse/type/hardlink refused");
            var final=new StringBuilder(32768);var size=GetFinalPathNameByHandle(handle,final,(uint)final.Capacity,0);
            if(size==0 || size>=final.Capacity || !final.ToString().Equals("\\\\?\\"+path,StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("Workspace final path differs");
            var fs=new StringBuilder(32);
            if(!GetVolumeInformationByHandle(handle,IntPtr.Zero,0,out _,out _,out _,fs,(uint)fs.Capacity) || fs.ToString()!="NTFS")
                throw new InvalidDataException("Workspace NTFS required");
            return handle;
        }
        catch{handle.Dispose();throw;}
    }
    [StructLayout(LayoutKind.Sequential)] private struct FileInfo
    {internal uint Attributes;internal System.Runtime.InteropServices.ComTypes.FILETIME Created,Accessed,Written;internal uint Volume,SizeHigh,SizeLow,Links,IndexHigh,IndexLow;}
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("kernel32.dll",EntryPoint="CreateFileW",CharSet=CharSet.Unicode,SetLastError=true)] private static extern SafeFileHandle CreateFile(string path,uint access,uint share,IntPtr security,uint disposition,uint flags,IntPtr template);
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("kernel32.dll",EntryPoint="CreateDirectoryW",CharSet=CharSet.Unicode,SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool CreateDirectory(string path,IntPtr security);
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("kernel32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool GetFileInformationByHandle(SafeFileHandle handle,out FileInfo info);
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("kernel32.dll",EntryPoint="GetFinalPathNameByHandleW",CharSet=CharSet.Unicode,SetLastError=true)] private static extern uint GetFinalPathNameByHandle(SafeFileHandle handle,StringBuilder path,uint length,uint flags);
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("kernel32.dll",EntryPoint="GetVolumeInformationByHandleW",CharSet=CharSet.Unicode,SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool GetVolumeInformationByHandle(SafeFileHandle handle,IntPtr label,uint labelSize,out uint serial,out uint max,out uint flags,StringBuilder fs,uint fsSize);
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("kernel32.dll",EntryPoint="GetDriveTypeW",CharSet=CharSet.Unicode)] private static extern uint GetDriveType(string root);
}
