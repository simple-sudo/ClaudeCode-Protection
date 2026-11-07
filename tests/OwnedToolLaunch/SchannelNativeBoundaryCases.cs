using System.Reflection;
using System.Runtime.InteropServices;
using System.Text.Json;

// Ordinary process-local control. No client certificate, peer input,
// transport, continued handshake, token export or product entry point.
internal static class SchannelNativeBoundaryCases
{
    private const string Package="Microsoft Unified Security Protocol Provider";
    private const int ContinueNeeded=0x00090312;

    internal static int Run(Assembly library)
    {
        if(RuntimeInformation.ProcessArchitecture!=Architecture.X64 ||
            Marshal.SizeOf<SchCredentials>()!=72 || Marshal.OffsetOf<SchCredentials>(nameof(SchCredentials.TlsParameters)).ToInt32()!=64 ||
            Marshal.SizeOf<PackageInfo>()!=32 ||
            Marshal.SizeOf<Buffer>()!=16 || Marshal.SizeOf<BufferDescriptor>()!=16)
            throw new PlatformNotSupportedException("Fixed x64 Schannel layouts required");
        var host=(string)library.GetType("ProtectionLifecycle.SessionProxy",true)!
            .GetField("Target",BindingFlags.Static|BindingFlags.NonPublic)!.GetRawConstantValue()!;

        var enumerate=EnumerateSecurityPackagesW(out var count,out var list);
        bool? listed=null;
        int? freeList=null;
        try
        {
            if(enumerate==0 && list!=IntPtr.Zero && count is >0 and <=256)
            {
                listed=false;
                for(var i=0;i<count;i++)
                {
                    var info=Marshal.PtrToStructure<PackageInfo>(IntPtr.Add(list,checked(i*Marshal.SizeOf<PackageInfo>())));
                    if(IsFixedPackage(info.Name)){listed=true;break;}
                }
            }
        }
        finally{if(list!=IntPtr.Zero)freeList=FreeContextBuffer(list);}

        var query=QuerySecurityPackageInfoW(Package,out var infoBuffer);
        int? freeInfo=infoBuffer==IntPtr.Zero?null:FreeContextBuffer(infoBuffer);

        var credentials=SecHandle.Invalid;
        var context=SecHandle.Invalid;
        // Manual server validation, no default client credentials, strong
        // encryption. One initial call only, so no peer cert is validated.
        var config=new SchCredentials {Version=5,SessionLifespan=uint.MaxValue,Flags=0x00400018};
        var acquire=AcquireCredentialsHandleW(IntPtr.Zero,Package,2,IntPtr.Zero,ref config,IntPtr.Zero,IntPtr.Zero,ref credentials,out _);
        int? initialize=null,freeToken=null,deleteContext=null,freeCredentials=null;
        uint? tokenLength=null,tokenType=null;
        var output=new Buffer {Type=2};
        var descriptorStorage=IntPtr.Zero;
        try
        {
            if(acquire==0 && credentials.Valid)
            {
                descriptorStorage=Marshal.AllocHGlobal(Marshal.SizeOf<Buffer>());
                Marshal.StructureToPtr(output,descriptorStorage,false);
                var descriptor=new BufferDescriptor {Count=1,Buffers=descriptorStorage};
                // CONFIDENTIALITY, ALLOCATE_MEMORY and MANUAL_CRED_VALIDATION.
                initialize=InitializeSecurityContextW(ref credentials,IntPtr.Zero,host,0x00080110,0,0x10,
                    IntPtr.Zero,0,ref context,ref descriptor,out _,out _);
                output=Marshal.PtrToStructure<Buffer>(descriptorStorage);
                tokenLength=output.Length;tokenType=output.Type;
            }
        }
        finally
        {
            if(output.Data!=IntPtr.Zero)freeToken=FreeContextBuffer(output.Data);
            if(descriptorStorage!=IntPtr.Zero)Marshal.FreeHGlobal(descriptorStorage);
            if(context.Valid)deleteContext=DeleteSecurityContext(ref context);
            if(credentials.Valid)freeCredentials=FreeCredentialsHandle(ref credentials);
        }
        var observed=enumerate==0 && listed==true && freeList==0 && query==0 && freeInfo==0 && acquire==0 &&
            initialize==ContinueNeeded && tokenLength is >0 and <=65536 && tokenType==2 && freeToken==0 && deleteContext==0 && freeCredentials==0;
        var classifiedPackageMiss=observed && ClassifyRuntimePackageMiss(library);
        Console.WriteLine(JsonSerializer.Serialize(new {Scope="ORDINARY_LOCAL_SCHANNEL_FIRST_TOKEN_ONLY",Enumerate=enumerate,Listed=listed,
            FreeList=freeList,Query=query,FreeInfo=freeInfo,Acquire=acquire,Initialize=initialize,TokenLength=tokenLength,TokenType=tokenType,
            FreeToken=freeToken,DeleteContext=deleteContext,FreeCredentials=freeCredentials,Observed=observed,
            ClassifiedRuntimePackageMiss=classifiedPackageMiss,NetworkRequestIssuedByProbe=false,ProtectedSession=false}));
        return observed && classifiedPackageMiss?0:3;
    }

    private static bool ClassifyRuntimePackageMiss(Assembly library)
    {
        var runtime=typeof(System.Net.Security.SslStream).Assembly;
        const BindingFlags statics=BindingFlags.Static|BindingFlags.NonPublic|BindingFlags.Public;
        var wrapper=runtime.GetType("System.Net.SSPIWrapper",true)!;
        var global=runtime.GetType("System.Net.GlobalSSPI",true)!;
        var module=global.GetField("SSPISecureChannel",statics)!.GetValue(null);
        try
        {
            // The production runtime uses this method to look up the fixed
            // Schannel package after enumeration. Only this control uses a
            // deliberately absent package name to obtain a real failure frame.
            _=wrapper.GetMethod("GetVerifyPackageInfo",statics)!.Invoke(null,new[]{module,"CPC_Ordinary_Fixture_No_Such_Package",true});
            return false;
        }
        catch(TargetInvocationException error)when(error.InnerException is NotSupportedException actual)
        {
            var type=library.GetType("ProtectionLifecycle.GatewayChildReport",true)!;
            var id=new string('a',32);
            var report=type.GetMethod("Result",statics)!.Invoke(null,new object?[]{id,"HTTPS_TLS_HANDSHAKE",125,null,actual})!;
            var json=JsonSerializer.SerializeToElement(report,type);
            var kind=json.GetProperty("Errors")[0].GetProperty("Kind").GetString();
            _=type.GetMethod("Parse",statics)!.Invoke(null,new object[]{json.GetRawText(),id,(uint)Environment.ProcessId,125u});
            return kind=="TLS_SCHANNEL_PACKAGE_MISSING";
        }
    }

    private static bool IsFixedPackage(IntPtr name)
    {
        if(name==IntPtr.Zero)return false;
        for(var i=0;i<Package.Length;i++)
            if(char.ToUpperInvariant((char)Marshal.ReadInt16(name,i*2))!=char.ToUpperInvariant(Package[i]))return false;
        return Marshal.ReadInt16(name,Package.Length*2)==0;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct PackageInfo {internal uint Capabilities;internal ushort Version,RpcId;internal uint MaximumToken;internal IntPtr Name,Comment;}
    [StructLayout(LayoutKind.Sequential)]
    private struct SchCredentials
    {
        internal uint Version,Format,CertificateCount;
        internal IntPtr Certificates,RootStore;
        internal uint MapperCount;
        internal IntPtr Mappers;
        internal uint SessionLifespan,Flags,TlsParameterCount;
        internal IntPtr TlsParameters;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct SecHandle
    {
        internal IntPtr Lower,Upper;
        internal static SecHandle Invalid=>new(){Lower=new(-1),Upper=new(-1)};
        internal bool Valid=>Lower!=new IntPtr(-1) && Upper!=new IntPtr(-1) && (Lower!=IntPtr.Zero || Upper!=IntPtr.Zero);
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct Buffer {internal uint Length,Type;internal IntPtr Data;}
    [StructLayout(LayoutKind.Sequential)]
    private struct BufferDescriptor {internal uint Version,Count;internal IntPtr Buffers;}

    [DllImport("secur32.dll",ExactSpelling=true),DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern int EnumerateSecurityPackagesW(out uint count,out IntPtr info);
    [DllImport("secur32.dll",ExactSpelling=true,CharSet=CharSet.Unicode),DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern int QuerySecurityPackageInfoW(string package,out IntPtr info);
    [DllImport("secur32.dll",ExactSpelling=true,CharSet=CharSet.Unicode),DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern int AcquireCredentialsHandleW(IntPtr principal,string package,uint use,IntPtr logon,ref SchCredentials config,
        IntPtr callback,IntPtr callbackArgument,ref SecHandle credential,out long expiry);
    [DllImport("secur32.dll",ExactSpelling=true,CharSet=CharSet.Unicode),DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern int InitializeSecurityContextW(ref SecHandle credential,IntPtr oldContext,string target,uint flags,uint reserved,
        uint representation,IntPtr input,uint reserved2,ref SecHandle context,ref BufferDescriptor output,out uint attributes,out long expiry);
    [DllImport("secur32.dll",ExactSpelling=true),DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern int DeleteSecurityContext(ref SecHandle context);
    [DllImport("secur32.dll",ExactSpelling=true),DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern int FreeCredentialsHandle(ref SecHandle credential);
    [DllImport("secur32.dll",ExactSpelling=true),DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern int FreeContextBuffer(IntPtr buffer);
}
