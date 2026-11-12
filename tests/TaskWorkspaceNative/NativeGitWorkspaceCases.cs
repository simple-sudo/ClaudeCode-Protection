using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

namespace ProtectionLifecycle;

internal static class NativeGitWorkspaceCases
{
    private const uint ReadControlAndAttributes=0x00020080u;
    private const uint ShareAll=0x00000007u;
    private const uint OpenExisting=3u;
    private const uint OpenReparsePoint=0x00200000u;
    private const uint BackupSemantics=0x02000000u;
    private const int FileObject=1;
    private const uint OwnerGroupDaclLabel=1u|2u|4u|16u;
    private const int ProjectPackageMask=0x001301bf;
    private const int ControlPackageMask=unchecked((int)0xA0000000);

    internal static void Run(string humanSid,string packageSid)
    {
        _=new SecurityIdentifier(humanSid);
        var package=new SecurityIdentifier(packageSid);
        if(!package.Value.StartsWith("S-1-15-2-",StringComparison.Ordinal))
            throw new InvalidDataException("Native Git workspace fixture requires an AppContainer package SID");

        var root=Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "CpcGitWorkspaceNative-"+Guid.NewGuid().ToString("N"));
        if(Directory.Exists(root)||File.Exists(root))
            throw new InvalidOperationException("Native Git workspace fixture root already exists");
        Directory.CreateDirectory(root);
        try
        {
            using(var parent=WindowsPathSeal.LockDirectory(root,PathPolicy.Source))
            using(var project=CreateDiagnosed(parent,"git-project",package.Value,true))
            using(var control=CreateDiagnosed(parent,"git-control",package.Value,false))
            {
                var projectPath=Path.Combine(root,"git-project");
                var controlPath=Path.Combine(root,"git-control");
                GitWorkspaceDescriptor.AssertPath(projectPath,package.Value,true);
                GitWorkspaceDescriptor.AssertPath(controlPath,package.Value,false);

                var nestedProject=Path.Combine(projectPath,"nested");
                Directory.CreateDirectory(nestedProject);
                var projectFile=Path.Combine(projectPath,"source.txt");
                var nestedProjectFile=Path.Combine(nestedProject,"child.txt");
                File.WriteAllText(projectFile,"project-source");
                File.WriteAllText(nestedProjectFile,"nested-project-source");

                var config=Path.Combine(controlPath,"empty-git-config");
                var hooks=Path.Combine(controlPath,"empty-git-hooks");
                var template=Path.Combine(controlPath,"empty-git-template");
                var pathspec=Path.Combine(controlPath,"git-selected-paths.bin");
                File.WriteAllText(config,string.Empty);
                Directory.CreateDirectory(hooks);
                Directory.CreateDirectory(template);
                File.WriteAllBytes(pathspec,new byte[]{0x61,0x00});

                var expectedControlNames=new[]{"empty-git-config","empty-git-hooks","empty-git-template","git-selected-paths.bin"};
                var actualControlNames=Directory.EnumerateFileSystemEntries(controlPath)
                    .Select(Path.GetFileName).Order(StringComparer.Ordinal).ToArray();
                if(!actualControlNames.SequenceEqual(expectedControlNames.Order(StringComparer.Ordinal),StringComparer.Ordinal))
                    throw new InvalidDataException("Native Git control directory fixture inventory mismatch");

                AssertInherited(projectFile,false,package.Value,humanSid,ProjectPackageMask,"project file");
                AssertInherited(nestedProject,true,package.Value,humanSid,ProjectPackageMask,"nested project directory");
                AssertInherited(nestedProjectFile,false,package.Value,humanSid,ProjectPackageMask,"nested project file");
                AssertInherited(config,false,package.Value,humanSid,ControlPackageMask,"global Git config");
                AssertInherited(hooks,true,package.Value,humanSid,ControlPackageMask,"hooks directory");
                AssertInherited(template,true,package.Value,humanSid,ControlPackageMask,"template directory");
                AssertInherited(pathspec,false,package.Value,humanSid,ControlPackageMask,"selected pathspec");

                GitWorkspaceDescriptor.AssertPath(projectPath,package.Value,true);
                GitWorkspaceDescriptor.AssertPath(controlPath,package.Value,false);
            }
        }
        finally
        {
            if(Directory.Exists(root))Directory.Delete(root,true);
        }

        Console.WriteLine("PASS native Git project/control DACL, OWNER RIGHTS and low-label inheritance");
    }

    private static PathLease CreateDiagnosed(PathLease parent,string leaf,string packageSid,bool packageWrite)
    {
        var path=WindowsPathSeal.Child(parent.Path,leaf);
        Console.WriteLine("NATIVE GIT create "+leaf);
        try
        {
            var lease=GitWorkspaceDescriptor.Create(parent,leaf,packageSid,packageWrite);
            Console.WriteLine("NATIVE GIT created "+leaf);
            return lease;
        }
        catch(Exception error)
        {
            Console.WriteLine("NATIVE GIT "+leaf+" create failed: "+error.GetType().Name+": "+error.Message);
            if(Directory.Exists(path))DumpDescriptor(path,leaf);
            throw;
        }
    }

    private static void DumpDescriptor(string path,string label)
    {
        var descriptor=ReadDescriptor(path,true);
        Console.WriteLine("NATIVE GIT "+label+" owner="+descriptor.Owner?.Value+
            " group="+descriptor.Group?.Value+" flags="+descriptor.ControlFlags);
        DumpAcl(label+" DACL",descriptor.DiscretionaryAcl);
        DumpAcl(label+" SACL",descriptor.SystemAcl);
    }

    private static void DumpAcl(string label,RawAcl? acl)
    {
        if(acl is null){Console.WriteLine("NATIVE GIT "+label+" <null>");return;}
        for(var i=0;i<acl.Count;i++)
        {
            var ace=acl[i];
            var bytes=new byte[ace.BinaryLength];
            ace.GetBinaryForm(bytes,0);
            var mask=bytes.Length>=8?BitConverter.ToInt32(bytes,4):0;
            var sid=ace is QualifiedAce qualified?qualified.SecurityIdentifier.Value:"<no-sid>";
            Console.WriteLine("NATIVE GIT "+label+"["+i+"] type=0x"+bytes[0].ToString("X2")+
                " flags=0x"+bytes[1].ToString("X2")+" mask=0x"+mask.ToString("X8")+" sid="+sid);
        }
    }

    private static void AssertInherited(string path,bool directory,string packageSid,string humanSid,int expectedPackageMask,string label)
    {
        var descriptor=ReadDescriptor(path,directory);
        if(!descriptor.ControlFlags.HasFlag(ControlFlags.DiscretionaryAclPresent) ||
            descriptor.ControlFlags.HasFlag(ControlFlags.DiscretionaryAclProtected))
            throw new InvalidDataException("Native Git child DACL inheritance flag mismatch: "+label);
        var dacl=descriptor.DiscretionaryAcl??throw new InvalidDataException("Native Git child DACL missing: "+label);
        var packageAce=FindSingleAllowedAce(dacl,packageSid,label+" package");
        if(packageAce.AccessMask!=expectedPackageMask ||
            !packageAce.AceFlags.HasFlag(AceFlags.Inherited) ||
            packageAce.AceFlags.HasFlag(AceFlags.InheritOnly))
            throw new InvalidDataException("Native Git package ACE inheritance/mask mismatch: "+label);
        if((packageAce.AccessMask&0x000c0000)!=0)
            throw new InvalidDataException("Native Git package ACE grants WRITE_DAC/WRITE_OWNER: "+label);

        var ownerRights=FindSingleAllowedAce(dacl,"S-1-3-4",label+" OWNER RIGHTS");
        if(ownerRights.AccessMask!=0x00020000 ||
            !ownerRights.AceFlags.HasFlag(AceFlags.Inherited) ||
            ownerRights.AceFlags.HasFlag(AceFlags.InheritOnly))
            throw new InvalidDataException("Native Git OWNER RIGHTS inheritance mismatch: "+label);

        if(ContainsSid(dacl,humanSid)||ContainsSid(dacl,"S-1-5-32-545"))
            throw new InvalidDataException("Native Git child unexpectedly grants human/Users SID: "+label);

        var sacl=descriptor.SystemAcl??throw new InvalidDataException("Native Git child mandatory label missing: "+label);
        if(!descriptor.ControlFlags.HasFlag(ControlFlags.SystemAclPresent))
            throw new InvalidDataException("Native Git child SACL-present flag missing: "+label);
        var labels=new List<(SecurityIdentifier Sid,int Mask,AceFlags Flags)>();
        for(var i=0;i<sacl.Count;i++)
        {
            var ace=sacl[i];
            var bytes=new byte[ace.BinaryLength];
            ace.GetBinaryForm(bytes,0);
            if(bytes.Length>=16 && bytes[0]==0x11)
                labels.Add((new SecurityIdentifier(bytes,8),BitConverter.ToInt32(bytes,4),(AceFlags)bytes[1]));
        }
        if(labels.Count!=1 || labels[0].Sid.Value!="S-1-16-4096" || labels[0].Mask!=1 ||
            !labels[0].Flags.HasFlag(AceFlags.Inherited))
            throw new InvalidDataException("Native Git low mandatory label inheritance mismatch: "+label);
    }

    private static CommonAce FindSingleAllowedAce(RawAcl dacl,string sid,string label)
    {
        var matches=new List<CommonAce>();
        for(var i=0;i<dacl.Count;i++)
        {
            if(dacl[i] is CommonAce ace && ace.AceQualifier==AceQualifier.AccessAllowed &&
                ace.SecurityIdentifier.Value==sid)
                matches.Add(ace);
        }
        if(matches.Count!=1)throw new InvalidDataException("Native Git expected exactly one "+label+" ACE");
        return matches[0];
    }

    private static bool ContainsSid(RawAcl dacl,string sid)
    {
        for(var i=0;i<dacl.Count;i++)
            if(dacl[i] is CommonAce ace && ace.SecurityIdentifier.Value==sid)return true;
        return false;
    }

    private static RawSecurityDescriptor ReadDescriptor(string path,bool directory)
    {
        var flags=OpenReparsePoint|(directory?BackupSemantics:0u);
        using var handle=CreateFile(path,ReadControlAndAttributes,ShareAll,IntPtr.Zero,OpenExisting,flags,IntPtr.Zero);
        if(handle.IsInvalid)throw new Win32Exception(Marshal.GetLastWin32Error(),"Open native Git child for security read");
        WindowsPathSeal.VerifyObject(handle,path,directory);
        var status=GetSecurityInfo(handle,FileObject,OwnerGroupDaclLabel,out _,out _,out _,out _,out var value);
        if(status!=0)throw new Win32Exception(unchecked((int)status),"Get native Git child security");
        try
        {
            if(value==IntPtr.Zero)throw new InvalidDataException("Native Git child security descriptor missing");
            var size=GetSecurityDescriptorLength(value);
            if(size is <20 or >65536)throw new InvalidDataException("Native Git child security descriptor bounds");
            var bytes=new byte[checked((int)size)];
            Marshal.Copy(value,bytes,0,bytes.Length);
            return new RawSecurityDescriptor(bytes,0);
        }
        finally
        {
            if(value!=IntPtr.Zero)LocalFree(value);
        }
    }

    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("kernel32.dll",EntryPoint="CreateFileW",CharSet=CharSet.Unicode,SetLastError=true)]
    private static extern SafeFileHandle CreateFile(string path,uint access,uint share,IntPtr security,uint disposition,uint flags,IntPtr template);
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("advapi32.dll",SetLastError=true)]
    private static extern uint GetSecurityInfo(SafeFileHandle handle,int objectType,uint securityInfo,
        out IntPtr owner,out IntPtr group,out IntPtr dacl,out IntPtr sacl,out IntPtr descriptor);
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("advapi32.dll")]
    private static extern uint GetSecurityDescriptorLength(IntPtr descriptor);
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(IntPtr memory);
}
