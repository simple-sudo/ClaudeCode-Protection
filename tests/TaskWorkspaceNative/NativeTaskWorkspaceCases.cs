using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;

namespace ProtectionLifecycle;

internal static class NativeTaskWorkspaceCases
{
    private const string ExactScope="EXACT_CREATED_CURRENT_USER_PROFILE_ONLY";
    private const string TaskScope="FRESH_DISPOSABLE_TASK_DIRECTORY_ONLY";

    internal static void Prepare(string humanSid,string packageName,string[] sessions)
    {
        if(sessions.Length!=5)throw new ArgumentException("Five native fixture sessions are required");
        _=new SecurityIdentifier(humanSid);
        var packageSid=DeriveAppContainerSid(packageName);
        var wrongPackageSid=DeriveAppContainerSid(packageName+".Wrong");
        var programFiles=Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        using var parent=WindowsPathSeal.LockDirectory(programFiles,PathPolicy.CreationParent);
        CreateWorkspace(sessions[0],humanSid,packageSid,lowLabel:true);
        CreateWorkspace(sessions[1],humanSid,packageSid,lowLabel:false);
        CreateWorkspace(sessions[2],humanSid,packageSid,lowLabel:true);
        var nonEmptyPath=SessionTaskWorkspace.PathFor(sessions[2]);
        File.WriteAllText(Path.Combine(nonEmptyPath,"native-fixture-child.txt"),"preserve-me");
        CreateWorkspace(sessions[3],humanSid,wrongPackageSid,lowLabel:true);
        CreateWorkspace(sessions[4],humanSid,packageSid,lowLabel:true);
        SetMediumLabel(SessionTaskWorkspace.PathFor(sessions[4]));
        Console.WriteLine("PASS prepared isolated native NTFS task-workspace fixtures");
    }

    internal static void Run(string expectedHumanSid,string packageName,string[] sessions)
    {
        if(sessions.Length!=5)throw new ArgumentException("Five native fixture sessions are required");
        using var identity=WindowsIdentity.GetCurrent();
        var humanSid=identity.User?.Value??throw new InvalidOperationException("Current Windows user SID unavailable");
        if(!string.Equals(humanSid,expectedHumanSid,StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Native recovery test did not run as the prepared standard user");
        var packageSid=DeriveAppContainerSid(packageName);
        var programFiles=Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        string parentIdentity;
        using(var parent=WindowsPathSeal.LockDirectory(programFiles,PathPolicy.CreationParent))
            parentIdentity=parent.ObjectIdentity();

        RunDeleteSuccess(sessions[0],humanSid,packageName,packageSid,parentIdentity,"exact low-integrity descriptor");
        RunDeleteSuccess(sessions[1],humanSid,packageName,packageSid,parentIdentity,"missing low-integrity label crash window");
        RunDeleteRefusal(sessions[2],humanSid,packageName,packageSid,parentIdentity,"non-empty directory");
        RunDeleteRefusal(sessions[3],humanSid,packageName,packageSid,parentIdentity,"package SID/DACL mismatch");
        RunDeleteRefusal(sessions[4],humanSid,packageName,packageSid,parentIdentity,"unexpected medium-integrity label");
        Console.WriteLine("PASS native NTFS task-workspace deletion, exact absence receipt and fail-closed preservation");
    }

    private static void CreateWorkspace(string session,string humanSid,string packageSid,bool lowLabel)
    {
        var path=SessionTaskWorkspace.PathFor(session);
        if(Directory.Exists(path)||File.Exists(path))throw new InvalidOperationException("Native test fixture path already exists");
        using var descriptor=new WorkspaceDescriptor(humanSid,packageSid,true);
        var attributes=descriptor.Attributes;
        if(!CreateDirectory(path,ref attributes))
            throw new WfpFailure("CreateNativeTaskWorkspaceFixture",unchecked((uint)Marshal.GetLastWin32Error()));
        if(lowLabel)descriptor.ApplyLowLabelAndVerify(path);
    }

    private static void RunDeleteSuccess(string session,string humanSid,string packageName,string packageSid,string parentIdentity,string label)
    {
        var path=SessionTaskWorkspace.PathFor(session);
        var (state,profile)=BuildState(session,humanSid,packageName,packageSid,parentIdentity);
        SessionTaskWorkspace.Cleanup(state,profile);
        SessionTaskWorkspace.AssertClosed(state,profile);
        if(Directory.Exists(path)||File.Exists(path))throw new InvalidOperationException("Native recovery left the task workspace present: "+label);
        if(state.ListLeaves("task-workspace-failure-"+profile.ProfileId+"-").Length!=0)
            throw new InvalidOperationException("Native recovery recorded a failure for successful case: "+label);
        Console.WriteLine("PASS native NTFS recovery: "+label);
    }

    private static void RunDeleteRefusal(string session,string humanSid,string packageName,string packageSid,string parentIdentity,string label)
    {
        var path=SessionTaskWorkspace.PathFor(session);
        var (state,profile)=BuildState(session,humanSid,packageName,packageSid,parentIdentity);
        Exception? failure=null;
        try{SessionTaskWorkspace.Cleanup(state,profile);}
        catch(Exception error){failure=error;}
        if(failure is null)throw new InvalidOperationException("Native recovery unexpectedly accepted "+label);
        if(!Directory.Exists(path))throw new InvalidOperationException("Native recovery removed a refused task workspace: "+label);
        if(state.ListLeaves("task-workspace-failure-"+profile.ProfileId+"-").Length!=1)
            throw new InvalidOperationException("Native recovery did not persist exactly one failure receipt: "+label);
        if(label=="non-empty directory" && !File.Exists(Path.Combine(path,"native-fixture-child.txt")))
            throw new InvalidOperationException("Native recovery changed the non-empty fixture");
        Console.WriteLine("PASS native NTFS refusal: "+label+" ("+failure.GetType().Name+")");
    }

    private static (ProtectedState State,ProfileStorageReceipt Profile) BuildState(string session,string humanSid,string packageName,string packageSid,string parentIdentity)
    {
        var state=new ProtectedState(packageSid);
        var profileId=Guid.NewGuid().ToString("N");
        var storageRoot=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),"Packages",packageName);
        var profile=new ProfileStorageReceipt(2,state.InstallationId,profileId,false,humanSid,packageName,packageSid,
            storageRoot,"00000001:00000002:00000003",parentIdentity,"FRESH_PROFILE_CREATED");
        var createdLeaf="profile-created-"+profileId+".json";
        state.WriteNew(createdLeaf,JsonSerializer.SerializeToUtf8Bytes(profile));
        var createdSHA256=state.Read(createdLeaf).SHA256;
        state.WriteNew("profile-delete-intent-"+profileId+".json",JsonSerializer.SerializeToUtf8Bytes(new {
            SchemaVersion=2,state.InstallationId,ProfileId=profileId,CreatedSHA256=createdSHA256,
            JobId=(string?)null,BindingSHA256=(string?)null,CompletionSHA256=(string?)null,
            Scope=ExactScope,NewProcessAdmissionAllowed=false
        }));
        state.WriteNew("task-workspace-intent-"+profileId+".json",JsonSerializer.SerializeToUtf8Bytes(
            new TaskWorkspaceIntent(1,state.InstallationId,profileId,session,createdSHA256,parentIdentity,TaskScope)));
        return(state,profile);
    }

    private static string DeriveAppContainerSid(string name)
    {
        var status=DeriveAppContainerSidFromAppContainerName(name,out var sid);
        if(status!=0||sid==IntPtr.Zero)throw new Win32Exception(status,"DeriveAppContainerSidFromAppContainerName failed");
        try
        {
            if(!ConvertSidToStringSid(sid,out var text))throw new Win32Exception(Marshal.GetLastWin32Error(),"ConvertSidToStringSid failed");
            try{return Marshal.PtrToStringUni(text)??throw new InvalidOperationException("AppContainer SID string missing");}
            finally{LocalFree(text);}
        }
        finally{LocalFree(sid);}
    }

    private static void SetMediumLabel(string path)
    {
        if(!ConvertStringSecurityDescriptorToSecurityDescriptor("S:(ML;OICI;NW;;;ME)",1,out var descriptor,out _))
            throw new Win32Exception(Marshal.GetLastWin32Error(),"Could not create medium label fixture");
        try
        {
            using var handle=CreateFile(path,0x000a0080,1,IntPtr.Zero,3,0x02200000,IntPtr.Zero);
            if(handle.IsInvalid)throw new Win32Exception(Marshal.GetLastWin32Error(),"Could not open medium-label fixture");
            if(!GetSecurityDescriptorSacl(descriptor,out var present,out var sacl,out _)||!present||sacl==IntPtr.Zero)
                throw new InvalidOperationException("Medium label fixture descriptor has no SACL");
            var status=SetSecurityInfo(handle,1,16,IntPtr.Zero,IntPtr.Zero,IntPtr.Zero,sacl);
            if(status!=0)throw new Win32Exception(unchecked((int)status),"Could not set medium integrity label fixture");
        }
        finally{LocalFree(descriptor);}
    }

    [DllImport("kernel32.dll",EntryPoint="CreateDirectoryW",CharSet=CharSet.Unicode,SetLastError=true)]
    [return:MarshalAs(UnmanagedType.Bool)] private static extern bool CreateDirectory(string path,ref KernelJobSeal.SecurityAttributes attributes);
    [DllImport("userenv.dll",CharSet=CharSet.Unicode,ExactSpelling=true)]
    private static extern int DeriveAppContainerSidFromAppContainerName(string name,out IntPtr sid);
    [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)]
    [return:MarshalAs(UnmanagedType.Bool)] private static extern bool ConvertSidToStringSid(IntPtr sid,out IntPtr text);
    [DllImport("advapi32.dll",EntryPoint="ConvertStringSecurityDescriptorToSecurityDescriptorW",CharSet=CharSet.Unicode,SetLastError=true)]
    [return:MarshalAs(UnmanagedType.Bool)] private static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(string text,uint revision,out IntPtr descriptor,out uint length);
    [DllImport("advapi32.dll",SetLastError=true)]
    [return:MarshalAs(UnmanagedType.Bool)] private static extern bool GetSecurityDescriptorSacl(IntPtr descriptor,[MarshalAs(UnmanagedType.Bool)] out bool present,out IntPtr sacl,[MarshalAs(UnmanagedType.Bool)] out bool defaulted);
    [DllImport("advapi32.dll")] private static extern uint SetSecurityInfo(SafeFileHandle handle,int type,uint information,IntPtr owner,IntPtr group,IntPtr dacl,IntPtr sacl);
    [DllImport("kernel32.dll",EntryPoint="CreateFileW",CharSet=CharSet.Unicode,SetLastError=true)]
    private static extern SafeFileHandle CreateFile(string path,uint access,uint share,IntPtr attributes,uint disposition,uint flags,IntPtr template);
    [DllImport("advapi32.dll",SetLastError=true)] private static extern IntPtr LocalFree(IntPtr value);
}
