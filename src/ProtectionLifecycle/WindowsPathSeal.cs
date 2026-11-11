using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32.SafeHandles;

[assembly: DefaultDllImportSearchPaths(DllImportSearchPath.System32)]

namespace ProtectionLifecycle;

internal enum PathPolicy { Source, TrustedAncestor, Protected, CreationParent }

// Only OPEN_EXISTING failures may create this exception. A metadata/ACL/final-
// path query returning the same numeric code remains a normal failure/UNKNOWN.
internal sealed class ExactPathAbsentException : Win32Exception
{
    internal string FailedPath { get; }
    internal ExactPathAbsentException(int code,string path):base(code,"OPEN_EXISTING reported an absent path")
    {FailedPath=path;Data["Stage"]="OpenExistingAbsent";}
}

// Handle-based, deliberately conservative NTFS policy. It is not a guarantee
// against another administrator, kernel code or a compromised bootstrap.
internal static class WindowsPathSeal
{
    private const uint ReadControl = 0x20000, ReadAttributes = 0x80;
    private const uint OpenReparse = 0x200000, BackupSemantics = 0x2000000;
    private const uint WriteDanger = 0x500d0156; // generic all/write, DELETE,
    // WRITE_DAC/WRITE_OWNER, data/append, EA, attributes and delete-child.
    private const uint AncestorDanger = 0x500d0040;
    private static readonly string[] TrustedOwners = {
        "S-1-5-18", "S-1-5-32-544",
        // Resolve the OS service identity, never a caller-supplied account.
        ((SecurityIdentifier)new NTAccount("NT SERVICE", "TrustedInstaller").Translate(typeof(SecurityIdentifier))).Value
    };
    internal static string Canonical(string path)
    {
        if (path.Length < 3 || !char.IsAsciiLetter(path[0]) || path[1] != ':' || path[2] != '\\' ||
            path.Contains('/') || path.AsSpan(2).Contains(':') || path.Contains('\0'))
            throw new InvalidDataException("Only local drive paths are accepted");
        var parts = path[3..].Split('\\', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Any(p => p is "." or ".." || p.EndsWith(' ') || p.EndsWith('.')))
            throw new InvalidDataException("Ambiguous path refused");
        var full = Path.GetFullPath(path);
        if (full.Length > 240) throw new InvalidDataException("Bounded path required");
        if (GetDriveType(full[..3]) != 3) throw new InvalidDataException("Fixed local volume required");
        return full.Length == 3 ? full : full.TrimEnd('\\');
    }
    internal static string Child(string parent, string relative)
    {
        // Relative values come only from the fixed asset catalog or validated IDs.
        if (Path.IsPathRooted(relative)) throw new InvalidDataException("Relative child required");
        var result = Canonical(Path.Combine(parent, relative.Replace('/', '\\')));
        if (!result.StartsWith(Canonical(parent).TrimEnd('\\') + "\\", StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Child escaped its fixed root");
        return result;
    }
    internal static SafeFileHandle Open(string path, bool directory, bool readData, bool writable = false)
        =>OpenBound(path,directory,readData,writable,shareWrite:false);
    // Read-only inspection handle for an object whose owner already holds a
    // write-capable handle with FILE_SHARE_READ only. This handle must allow
    // the owner's existing write access to coexist; the owner's share mode
    // continues to deny every foreign writer and neither handle shares delete.
    internal static SafeFileHandle OpenReadUnderWriteLease(string path)
        =>OpenBound(path,directory:false,readData:true,writable:false,shareWrite:true);
    private static SafeFileHandle OpenBound(string path,bool directory,bool readData,bool writable,bool shareWrite)
    {
        var access = ReadControl | ReadAttributes | (readData ? 0x80000000u : 0u) | (writable ? 0x40000000u : 0u);
        // Never share deletion. Only the fixed creator profile parent shares
        // writes. ACL/owner checks are independently required.
        var canonical=Canonical(path);
        var handle=CreateFile(canonical,access,shareWrite?3u:1u,IntPtr.Zero,3,OpenReparse|(directory?BackupSemantics:0),IntPtr.Zero);
        if(handle.IsInvalid)
        {
            var error=Error("OpenBoundPath");handle.Dispose();
            if(error.NativeErrorCode is 2 or 3)throw new ExactPathAbsentException(error.NativeErrorCode,canonical);
            throw error;
        }
        try { VerifyObject(handle, path, directory); return handle; }
        catch { handle.Dispose(); throw; }
    }
    internal static SafeFileHandle OpenForDelete(string path,bool directory)
    {
        var access=ReadControl|ReadAttributes|0x10000u|(directory?0u:0x80000000u);
        var canonical=Canonical(path);
        var handle=CreateFile(canonical,access,1,IntPtr.Zero,3,OpenReparse|(directory?BackupSemantics:0),IntPtr.Zero);
        if(handle.IsInvalid)
        {
            var error=Error("OpenExactDelete");handle.Dispose();
            if(error.NativeErrorCode is 2 or 3)throw new ExactPathAbsentException(error.NativeErrorCode,canonical);
            throw error;
        }
        try{VerifyObject(handle,path,directory);AssertAcl(handle,true);return handle;}
        catch{handle.Dispose();throw;}
    }
    // Created only in an already held task tree. Keep DELETE on the original
    // handle, with readers allowed but no foreign write or delete sharing.
    internal static SafeFileHandle CreateWithdrawableProbeFile(string path)
    {
        var handle=CreateFile(Canonical(path),0xc0010000u,1,IntPtr.Zero,1,OpenReparse,IntPtr.Zero);
        if(handle.IsInvalid){var error=Error("CreateWithdrawableProbeFile");handle.Dispose();throw error;}
        try{VerifyObject(handle,path,false);return handle;}
        catch{handle.Dispose();throw;}
    }
    // Windows servicing legitimately hardlinks this fixed OS executable into
    // WinSxS. Product/source payloads keep their single-link requirement. The
    // exception has no path parameter, write access or ACL-repair behavior.
    internal static SafeFileHandle OpenCheckNetIsolation()
    {
        var path=Child(Environment.GetFolderPath(Environment.SpecialFolder.System),"CheckNetIsolation.exe");
        var handle=CreateFile(path,ReadControl|ReadAttributes|0x80000000u,1,IntPtr.Zero,3,OpenReparse,IntPtr.Zero);
        if(handle.IsInvalid){var error=Error("OpenFixedWindowsLoopbackUtility");handle.Dispose();throw error;}
        try{VerifyObjectCore(handle,path,false,true);AssertAcl(handle,false,true);return handle;}
        catch(Exception ex){handle.Dispose();if(ex.Data["Stage"] is null)ex.Data["Stage"]="VerifyFixedWindowsLoopbackUtility";throw;}
    }
    internal static SafeFileHandle OpenPowerShell()
    {
        var path=Child(Environment.GetFolderPath(Environment.SpecialFolder.System),"WindowsPowerShell/v1.0/powershell.exe");
        var handle=CreateFile(path,ReadControl|ReadAttributes|0x80000000u,1,IntPtr.Zero,3,OpenReparse,IntPtr.Zero);
        if(handle.IsInvalid){var error=Error("OpenFixedWindowsPowerShell");handle.Dispose();throw error;}
        try{VerifyObjectCore(handle,path,false,true);AssertAcl(handle,false,true);return handle;}
        catch{handle.Dispose();throw;}
    }
    internal static SafeFileHandle OpenStartupTraceModule(string leaf)
    {
        var relative=leaf switch
        {
            "user32.dll" or "gdi32full.dll" or "win32u.dll" or "nvcuda.dll"=>leaf,
            "nvcuda64.dll"=>"DriverStore/FileRepository/nvltsi.inf_amd64_2ce37f1bf94224ed/nvcuda64.dll",
            _=>throw new InvalidDataException("Fixed startup trace module required")
        };
        var path=Child(Environment.GetFolderPath(Environment.SpecialFolder.System),relative);
        var handle=CreateFile(path,ReadControl|ReadAttributes|0x80000000u,1,IntPtr.Zero,3,OpenReparse,IntPtr.Zero);
        if(handle.IsInvalid){var error=Error("OpenStartupTraceModule");handle.Dispose();throw error;}
        try{VerifyObjectCore(handle,path,false,true);AssertAcl(handle,false,true);return handle;}
        catch{handle.Dispose();throw;}
    }
    // Git for Windows intentionally aliases its executable and dependency
    // DLLs with hardlinks. This is a READ-ONLY exception for a closed asset
    // set; source/payload/state/deletion paths retain the single-link rule.
    // Every alias shares the same NTFS object ACL. The caller additionally
    // holds the trusted Git ancestry and verifies each reviewed byte digest.
    internal static SafeFileHandle OpenReviewedGitAsset(string leaf)
    {
        var links=leaf switch {"git.exe"=>4u,"libiconv-2.dll" or "libintl-8.dll" or "libpcre2-8-0.dll" or "libwinpthread-1.dll" or "zlib1.dll"=>2u,
            _=>throw new InvalidDataException("Fixed reviewed Git asset required")};
        var path=Child(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),"Git/mingw64/bin/"+leaf);
        var handle=CreateFile(path,ReadControl|ReadAttributes|0x80000000u,1,IntPtr.Zero,3,OpenReparse,IntPtr.Zero);
        if(handle.IsInvalid){var error=Error("OpenReviewedGitAsset");handle.Dispose();throw error;}
        try
        {
            VerifyObjectCore(handle,path,false,true);AssertAcl(handle,false,true);
            if(!GetFileInformationByHandle(handle,out var info))throw Error("ReadGitAssetLinkCount");
            if(info.Links!=links)throw new InvalidDataException("Reviewed Git hardlink topology changed");
            return handle;
        }
        catch(Exception ex){handle.Dispose();if(ex.Data["Stage"] is null)ex.Data["Stage"]="VerifyReviewedGitAsset";throw;}
    }
    internal static string Identity(SafeFileHandle handle)
    {
        if(!GetFileInformationByHandle(handle,out var info))throw Error("ReadExactIdentity");
        return info.Volume.ToString("X8",System.Globalization.CultureInfo.InvariantCulture)+":"+
            info.IndexHigh.ToString("X8",System.Globalization.CultureInfo.InvariantCulture)+":"+info.IndexLow.ToString("X8",System.Globalization.CultureInfo.InvariantCulture);
    }
    internal static string[] EnumerateNames(PathLease parent,int maximum=32768)
    {
        parent.AssertHeld();
        var result=EnumerateNamesCore(parent.Path,parent.ObjectIdentity(),maximum);
        parent.AssertHeld();return result;
    }
    internal static string[] EnumerateNames(SafeFileHandle heldParent,string path,int maximum=32768)
    {
        VerifyObject(heldParent,path,true);
        var result=EnumerateNamesCore(path,Identity(heldParent),maximum);
        VerifyObject(heldParent,path,true);return result;
    }
    private static string[] EnumerateNamesCore(string path,string expectedIdentity,int maximum)
    {
        if(maximum is <1 or >32768)throw new ArgumentOutOfRangeException(nameof(maximum));
        // The original directory handle/ancestry stays held. A separate,
        // synchronous scan handle owns its cursor; no shared-cursor restart.
        // SHARE_DELETE only accommodates our already-held DELETE handle during
        // exact removal; that original handle still refuses foreign deletion.
        using var scan=CreateFile(Canonical(path),ReadControl|ReadAttributes|1u|0x100000u,1u|4u,
            IntPtr.Zero,3,OpenReparse|BackupSemantics,IntPtr.Zero);
        if(scan.IsInvalid)throw Error("OpenNamesOnlyDirectory");
        VerifyObject(scan,path,true);
        if(Identity(scan)!=expectedIdentity)throw new InvalidDataException("Enumeration directory was replaced");
        var result=ClaudeCodeProtection.Workspaces.WindowsDirectoryNames.Read(scan,maximum);
        VerifyObject(scan,path,true);
        if(Identity(scan)!=expectedIdentity)throw new InvalidDataException("Enumeration identity changed");
        return result;
    }
    internal static void MarkDelete(SafeFileHandle handle)
    {
        var disposition=new DeleteDisposition{Delete=1};
        if(!SetFileInformationByHandle(handle,4,ref disposition,(uint)Marshal.SizeOf<DeleteDisposition>()))throw Error("MarkExactDelete");
    }
    internal static void VerifyObject(SafeFileHandle handle, string expected, bool directory)
        =>VerifyObjectCore(handle,expected,directory,false);
    private static void VerifyObjectCore(SafeFileHandle handle,string expected,bool directory,bool allowSystemHardlinks)
    {
        if (!GetFileInformationByHandle(handle, out var info)) throw Error("ReadBoundIdentity");
        if ((info.Attributes & 0x400) != 0 || ((info.Attributes & 0x10) != 0) != directory ||
            (!directory && (info.Links==0 || (!allowSystemHardlinks && info.Links!=1))))
            throw new InvalidDataException("Reparse, object type or hardlink count refused");
        var buffer = new StringBuilder(32768);
        var length = GetFinalPathNameByHandle(handle, buffer, (uint)buffer.Capacity, 0);
        if (length == 0 || length >= buffer.Capacity) throw Error("ReadFinalPath");
        var final = buffer.ToString();
        if (!final.StartsWith("\\\\?\\", StringComparison.Ordinal) ||
            !string.Equals(Canonical(final[4..]), Canonical(expected), StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Opened path differs from requested identity");
        var fs = new StringBuilder(32);
        if (!GetVolumeInformationByHandle(handle, null, 0, out _, out _, out _, fs, (uint)fs.Capacity)) throw Error("ReadVolumeType");
        if (!string.Equals(fs.ToString(), "NTFS", StringComparison.Ordinal)) throw new InvalidDataException("Only NTFS is qualified for this boundary");
    }
    internal static void AssertAcl(SafeFileHandle handle,bool protectedObject,bool creationParent=false)
    {
        var status = GetSecurityInfo(handle, 1, 1 | 4, out _, out _, out var dacl, out _, out var descriptor);
        if (status != 0) throw new Win32Exception((int)status, "ReadHandleSecurity");
        try
        {
            if (descriptor == IntPtr.Zero || dacl == IntPtr.Zero) throw new InvalidDataException("Null security descriptor/DACL refused");
            var size = GetSecurityDescriptorLength(descriptor);
            if (size is 0 or > 65536) throw new InvalidDataException("Security descriptor size refused");
            var bytes = new byte[checked((int)size)]; Marshal.Copy(descriptor, bytes, 0, bytes.Length);
            var security = new RawSecurityDescriptor(bytes, 0);
            if (security.Owner is null || !TrustedOwners.Contains(security.Owner.Value, StringComparer.Ordinal) || security.DiscretionaryAcl is null)
                throw new InvalidDataException("Trusted owner and explicit DACL required");
            if (protectedObject && (security.ControlFlags & ControlFlags.DiscretionaryAclProtected) == 0)
                throw new InvalidDataException("Protected object must block inherited write grants");
            foreach (GenericAce ace in security.DiscretionaryAcl)
            {
                if((!protectedObject || creationParent) && (ace.AceFlags & AceFlags.InheritOnly)!=0)continue;
                if (ace is not CommonAce common || common.IsCallback) throw new InvalidDataException("Unreviewed ACE type refused");
                if (common.AceQualifier == AceQualifier.AccessDenied) continue; // Conservative: deny cannot grant mutation.
                if (common.AceQualifier != AceQualifier.AccessAllowed) throw new InvalidDataException("Unreviewed ACE qualifier");
                var mask = unchecked((uint)common.AccessMask);
                if((mask&((protectedObject || creationParent)?WriteDanger:AncestorDanger))!=0 &&
                    !TrustedOwners.Contains(common.SecurityIdentifier.Value, StringComparer.Ordinal))
                    throw new InvalidDataException("Untrusted mutation grant refused");
            }
        }
        finally { if (descriptor != IntPtr.Zero) LocalFree(descriptor); }
    }
    internal static CreationTag ReadCreationTag(SafeFileHandle handle)
    {
        AssertAcl(handle,true);
        var status=GetSecurityInfo(handle,1,1|4,out _,out _,out _,out _,out var descriptor);
        if(status!=0)throw new Win32Exception((int)status,"ReadCreationTagSecurity");
        try
        {
            if(descriptor==IntPtr.Zero)throw new InvalidDataException("Creation-tag descriptor missing");
            var size=GetSecurityDescriptorLength(descriptor);if(size is 0 or >65536)throw new InvalidDataException("Invalid creation-tag descriptor");
            var bytes=new byte[checked((int)size)];Marshal.Copy(descriptor,bytes,0,bytes.Length);
            var security=new RawSecurityDescriptor(bytes,0);CreationTag? found=null;
            foreach(GenericAce ace in security.DiscretionaryAcl??throw new InvalidDataException("Creation-tag DACL missing"))
            {
                if(ace is not CommonAce common)throw new InvalidDataException("Unreviewed creation-tag ACE");
                var tag=CreationTag.TryParse(common.SecurityIdentifier.Value);if(tag is null)continue;
                if(found is not null || common.IsCallback || common.AceFlags!=AceFlags.None || common.AceQualifier!=AceQualifier.AccessAllowed || common.AccessMask!=0x20000)
                    throw new InvalidDataException("Ambiguous or broadened creation tag");
                found=tag;
            }
            if(found is null)throw new InvalidDataException("Creation identity is missing; object is not adopted");
            if(found.Role is CreationRole.OfficialClaudeDirectory or CreationRole.OfficialClaudeExe)
                AssertOfficialStagingAudience(security.DiscretionaryAcl,found.Sid);
            return found;
        }
        finally{if(descriptor!=IntPtr.Zero)LocalFree(descriptor);}
    }
    internal static void AssertOfficialStagingAudience(RawAcl dacl,string tagSid)
    {
        foreach(GenericAce ace in dacl)
        {
            if(ace is not CommonAce common || common.IsCallback)throw new InvalidDataException("Unreviewed staging ACE");
            if(common.AceQualifier!=AceQualifier.AccessAllowed)continue;
            var sid=common.SecurityIdentifier.Value;
            if(sid is "S-1-5-18" or "S-1-5-32-544")continue;
            if(sid!=tagSid || common.AccessMask!=0x20000 || common.AceFlags!=AceFlags.None)
                throw new InvalidDataException("Official image staging must remain private to its owner");
        }
    }
    internal static PathLease LockDirectory(string path, PathPolicy policy)
        =>LockDirectoryCore(path,policy,shareFinalWrite:false);
    // CreateAppContainerProfile writes under the held Packages directory.
    // Keep it non-deletable without excluding the OS writer.
    internal static PathLease LockCreatorProfileParent(string path)
        =>LockDirectoryCore(path,PathPolicy.Source,shareFinalWrite:true);
    private static PathLease LockDirectoryCore(string path,PathPolicy policy,bool shareFinalWrite)
    {
        path = Canonical(path);
        var lease = new PathLease(path, policy);
        try
        {
            var current = path[..3];
            var prefixes = new List<string> { current };
            foreach (var part in path[3..].Split('\\', StringSplitOptions.RemoveEmptyEntries)) { current = Path.Combine(current, part); prefixes.Add(current); }
            foreach (var prefix in prefixes)
            {
                var last=string.Equals(prefix,path,StringComparison.OrdinalIgnoreCase);
                var handle=OpenBound(prefix,true,false,false,shareWrite:shareFinalWrite && last);lease.Add(handle);
                if(policy!=PathPolicy.Source)
                    AssertAcl(handle,policy==PathPolicy.Protected && last,policy==PathPolicy.CreationParent && last);
            }
            return lease;
        }
        catch { lease.Dispose(); throw; }
    }
    // Parent must already be held and checked. Do not adopt an existing directory
    // through this method, and never repair arbitrary preexisting directory ACLs.
    internal static PathLease CreateProtectedDirectory(PathLease parent, string leaf, bool publicRead,CreationTag? creation=null)
    {
        parent.AssertHeld();
        if (parent.Policy == PathPolicy.Source) throw new InvalidOperationException("Trusted parent required");
        if (leaf.Length is < 1 or > 64 || leaf.Any(c => !(c is >= 'a' and <= 'z' or >= '0' and <= '9' or '-' or >= 'A' and <= 'Z')))
            throw new InvalidDataException("Fixed directory leaf required");
        var path = Child(parent.Path, leaf);
        WithSecurity(publicRead, attributes => {
            if (!CreateDirectory(path, ref attributes)) throw Error("CreateProtectedDirectory");
        },creation);
        // If post-create validation fails, preserve the exact failed directory.
        // No broad cleanup or ACL normalization is attempted.
        var result=LockDirectory(path,PathPolicy.Protected);
        try{if(creation is not null)result.AssertCreationTag(creation);return result;}catch{result.Dispose();throw;}
    }
    internal static SafeFileHandle CreateProtectedFile(PathLease parent, string leaf, bool publicRead,CreationTag? creation=null)
    {
        parent.AssertHeld();
        if (parent.Policy != PathPolicy.Protected || Path.GetFileName(leaf) != leaf || leaf.Contains(':'))
            throw new InvalidOperationException("Protected parent and exact filename required");
        var path = Child(parent.Path, leaf);
        SafeFileHandle? handle = null;
        WithSecurity(publicRead, attributes => {
            handle = CreateFileWithSecurity(Canonical(path), 0xc0020080, 0, ref attributes, 1, 0x80000000 | OpenReparse, IntPtr.Zero);
            if (handle.IsInvalid) { var error=Error("CreateProtectedFile"); handle.Dispose(); throw error; }
        },creation);
        var result = handle ?? throw new InvalidOperationException("Missing new file handle");
        try { VerifyObject(result,path,false);AssertAcl(result,true);if(creation is not null && ReadCreationTag(result).Sid!=creation.Sid)throw new InvalidDataException("Created file tag differs");return result; }
        catch { result.Dispose(); throw; }
    }
    private static void WithSecurity(bool publicRead,Action<SecurityAttributes> action,CreationTag? creation=null)
    {
        // Public code is readable/executable by AppContainers as on standard
        // Program Files installations. Private state never receives this ACE.
        // Only newly created public PRODUCT code gains restricted-package RX.
        // Private state and existing host/runtime/device ACLs stay untouched.
        var sddl="O:BAG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"+(publicRead?"(A;OICI;GRGX;;;BU)(A;OICI;GRGX;;;S-1-15-2-1)(A;OICI;GRGX;;;S-1-15-2-2)":"")+(creation is null?"":"(A;;RC;;;"+creation.Sid+")");
        if (!ConvertStringSecurityDescriptorToSecurityDescriptor(sddl, 1, out var descriptor, out _)) throw Error("CreateSecurityDescriptor");
        try { action(new SecurityAttributes { Length = Marshal.SizeOf<SecurityAttributes>(), Descriptor = descriptor, Inherit=0 }); }
        finally { LocalFree(descriptor); }
    }
    internal static Win32Exception Error(string stage) { var error = new Win32Exception(Marshal.GetLastWin32Error()); error.Data["Stage"] = stage; return error; }
    [StructLayout(LayoutKind.Sequential)] private struct SecurityAttributes { internal int Length; internal IntPtr Descriptor; internal int Inherit; }
    [StructLayout(LayoutKind.Sequential)] private struct DeleteDisposition { internal byte Delete; }
    [StructLayout(LayoutKind.Sequential)] private struct ByHandleInfo {
        internal uint Attributes; internal System.Runtime.InteropServices.ComTypes.FILETIME Created, Accessed, Written;
        internal uint Volume, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;
    }
    [DllImport("kernel32.dll", EntryPoint="CreateFileW", CharSet=CharSet.Unicode, SetLastError=true)] private static extern SafeFileHandle CreateFile(string path, uint access, uint share, IntPtr security, uint disposition, uint flags, IntPtr template);
    [DllImport("kernel32.dll", EntryPoint="CreateFileW", CharSet=CharSet.Unicode, SetLastError=true)] private static extern SafeFileHandle CreateFileWithSecurity(string path, uint access, uint share, ref SecurityAttributes security, uint disposition, uint flags, IntPtr template);
    [DllImport("kernel32.dll", EntryPoint="CreateDirectoryW", CharSet=CharSet.Unicode, SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool CreateDirectory(string path, ref SecurityAttributes security);
    [DllImport("kernel32.dll", SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool GetFileInformationByHandle(SafeFileHandle handle, out ByHandleInfo info);
    [DllImport("kernel32.dll", SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool SetFileInformationByHandle(SafeFileHandle handle,int informationClass,ref DeleteDisposition information,uint size);
    [DllImport("kernel32.dll", EntryPoint="GetFinalPathNameByHandleW", CharSet=CharSet.Unicode, SetLastError=true)] private static extern uint GetFinalPathNameByHandle(SafeFileHandle handle, StringBuilder path, uint size, uint flags);
    [DllImport("kernel32.dll", EntryPoint="GetVolumeInformationByHandleW", CharSet=CharSet.Unicode, SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool GetVolumeInformationByHandle(SafeFileHandle handle, StringBuilder? volume, uint volumeSize, out uint serial, out uint maxComponent, out uint flags, StringBuilder fileSystem, uint fileSystemSize);
    [DllImport("kernel32.dll", EntryPoint="GetDriveTypeW", CharSet=CharSet.Unicode)] private static extern uint GetDriveType(string root);
    [DllImport("advapi32.dll")] private static extern uint GetSecurityInfo(SafeFileHandle handle, int type, uint info, out IntPtr owner, out IntPtr group, out IntPtr dacl, out IntPtr sacl, out IntPtr descriptor);
    [DllImport("advapi32.dll")] private static extern uint GetSecurityDescriptorLength(IntPtr descriptor);
    [DllImport("advapi32.dll", EntryPoint="ConvertStringSecurityDescriptorToSecurityDescriptorW", CharSet=CharSet.Unicode, SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(string text, uint revision, out IntPtr descriptor, out uint length);
    [DllImport("kernel32.dll")] private static extern IntPtr LocalFree(IntPtr memory);
}

internal sealed class PathLease : IDisposable
{
    private readonly List<SafeFileHandle> handles = new();
    private bool disposed;
    internal string Path { get; }
    internal PathPolicy Policy { get; }
    internal PathLease(string path, PathPolicy policy) { Path = path; Policy = policy; }
    internal void Add(SafeFileHandle handle) => handles.Add(handle);
    internal string ObjectIdentity(){AssertHeld();return WindowsPathSeal.Identity(handles[^1]);}
    internal CreationTag ReadCreationTag(){AssertHeld();return WindowsPathSeal.ReadCreationTag(handles[^1]);}
    internal void AssertCreationTag(CreationTag expected)
    {if(ReadCreationTag().Sid!=expected.Sid)throw new InvalidDataException("Directory creation identity differs");}
    internal void AssertHeld()
    {
        if (disposed || handles.Count == 0 || handles.Any(h => h.IsClosed || h.IsInvalid)) throw new ObjectDisposedException(nameof(PathLease));
        WindowsPathSeal.VerifyObject(handles[^1], Path, true);
        if (Policy != PathPolicy.Source)
            for(var i=0;i<handles.Count;i++)WindowsPathSeal.AssertAcl(handles[i],Policy==PathPolicy.Protected && i==handles.Count-1,Policy==PathPolicy.CreationParent && i==handles.Count-1);
    }
    public void Dispose() { if (disposed) return; disposed = true; for (var i=handles.Count-1;i>=0;i--) handles[i].Dispose(); }
}
