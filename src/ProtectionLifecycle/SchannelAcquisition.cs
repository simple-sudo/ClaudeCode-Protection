using System.Runtime.InteropServices;
using System.Text.Json;

namespace ProtectionLifecycle;

internal sealed record SchannelCall(string Role,int Status,bool ObjectReturned,int? ReleaseStatus,long StartedFileTime,long EndedFileTime)
{
    internal bool Closed=>ObjectReturned?ReleaseStatus==0:Status<0 && ReleaseStatus is null;
}

internal sealed record SchannelAcquisition(int SchemaVersion,string SessionId,int Pid,uint Tid,SchannelCall[] Calls)
{
    private static readonly string[] Roles={"QUERY_UNISP","ACQUIRE_GATEWAY_V5","ACQUIRE_MINIMAL_V5","ACQUIRE_TLS12_V5","ACQUIRE_TLS12_V4"};
    private const string Package="Microsoft Unified Security Protocol Provider";
    private const uint Tls12Client=0x00000800;
    private const uint ManualValidationNoDefaultStrong=0x00400018;
    // .NET 8.0.28 Windows client options for the fixed gateway: auxiliary
    // record, end-cert status request and stapled-status tolerance in SSPI.
    // Actual certificate verification in SslStream is separate.
    private const uint GatewayFlags=ManualValidationNoDefaultStrong|0x00201900;
    internal bool Complete=>Calls.Length==Roles.Length && Calls.All(call=>call.Closed);

    internal static SchannelAcquisition Observe(string session)
    {
        if(RuntimeInformation.ProcessArchitecture!=Architecture.X64 ||
            Marshal.SizeOf<ModernCredential>()!=72 || Marshal.OffsetOf<ModernCredential>(nameof(ModernCredential.TlsParameters)).ToInt32()!=64 ||
            Marshal.SizeOf<TlsParameters>()!=40 || Marshal.OffsetOf<TlsParameters>(nameof(TlsParameters.DisabledProtocols)).ToInt32()!=16 ||
            Marshal.SizeOf<LegacyCredential>()!=80 || Marshal.OffsetOf<LegacyCredential>(nameof(LegacyCredential.Protocols)).ToInt32()!=56 ||
            Marshal.SizeOf<SecHandle>()!=16)
            throw new PlatformNotSupportedException("Fixed x64 Schannel acquisition ABI required");
        session=Identifiers.Hex32(session);
        var calls=new List<SchannelCall>(Roles.Length);
        var thread=GetCurrentThreadId();
        for(int i=0;i<Roles.Length;i++)
        {
            long start=DateTime.UtcNow.ToFileTimeUtc();
            var (status,returned,release)=i switch {
                0=>QueryPackage(),
                1=>AcquireModern(GatewayFlags,false),
                2=>AcquireModern(ManualValidationNoDefaultStrong,false),
                3=>AcquireModern(GatewayFlags,true),
                4=>AcquireLegacyTls12(),
                _=>throw new InvalidOperationException("Unrecognized fixed acquisition step")
            };
            var call=new SchannelCall(Roles[i],status,returned,release,start,DateTime.UtcNow.ToFileTimeUtc());
            calls.Add(call);
            if(!call.Closed)break;
        }
        return new(1,session,Environment.ProcessId,thread,calls.ToArray());
    }

    internal static SchannelAcquisition Parse(string raw,string session,uint pid,long createdFileTime)
    {
        if(raw.Length is <1 or >4096)throw new InvalidDataException("Schannel evidence bounds refused");
        using var json=JsonDocument.Parse(raw,new JsonDocumentOptions{MaxDepth=4});
        StrictJson.Fields(json.RootElement,"SchemaVersion","SessionId","Pid","Tid","Calls");
        var rows=json.RootElement.GetProperty("Calls");
        if(rows.ValueKind!=JsonValueKind.Array || rows.GetArrayLength()<1 || rows.GetArrayLength()>Roles.Length)
            throw new InvalidDataException("Schannel evidence call count differs");
        foreach(var row in rows.EnumerateArray())
            StrictJson.Fields(row,"Role","Status","ObjectReturned","ReleaseStatus","StartedFileTime","EndedFileTime");
        var report=json.RootElement.Deserialize<SchannelAcquisition>()??throw new InvalidDataException("Schannel evidence absent");
        if(report.SchemaVersion!=1 || report.SessionId!=Identifiers.Hex32(session) || report.Pid<=0 || (uint)report.Pid!=pid ||
            report.Tid==0 || createdFileTime<=0)
            throw new InvalidDataException("Schannel evidence actor differs");
        long prior=createdFileTime;
        for(int i=0;i<report.Calls.Length;i++)
        {
            var call=report.Calls[i];
            if(call.Role!=Roles[i] || call.StartedFileTime<prior || call.EndedFileTime<call.StartedFileTime ||
                call.EndedFileTime-createdFileTime>TimeSpan.FromSeconds(30).Ticks ||
                call.ObjectReturned!=(call.ReleaseStatus is not null) ||
                !call.Closed && i+1!=report.Calls.Length)
                throw new InvalidDataException("Schannel evidence sequence differs");
            prior=call.EndedFileTime;
        }
        if(report.Calls.Length!=Roles.Length && report.Calls[^1].Closed)
            throw new InvalidDataException("Schannel evidence truncated");
        return report;
    }

    private static (int,bool,int?) QueryPackage()
    {
        var status=QuerySecurityPackageInfoW(Package,out var info);
        bool returned=info!=IntPtr.Zero;
        return (status,returned,returned?FreeContextBuffer(info):null);
    }

    private static (int,bool,int?) AcquireModern(uint flags,bool tls12)
    {
        var options=new ModernCredential{Version=5,Lifespan=uint.MaxValue,Flags=flags};
        if(!tls12)return AcquireModern(ref options);
        var parameter=new TlsParameters{DisabledProtocols=~Tls12Client};
        var pointer=Marshal.AllocHGlobal(Marshal.SizeOf<TlsParameters>());
        try
        {
            Marshal.StructureToPtr(parameter,pointer,false);
            options.ParameterCount=1;options.TlsParameters=pointer;
            return AcquireModern(ref options);
        }
        finally{Marshal.FreeHGlobal(pointer);}
    }

    private static (int,bool,int?) AcquireModern(ref ModernCredential options)
    {
        var credential=SecHandle.Invalid;
        var status=AcquireModernNative(IntPtr.Zero,Package,2,IntPtr.Zero,ref options,IntPtr.Zero,IntPtr.Zero,ref credential,out _);
        return Release(status,ref credential);
    }

    private static (int,bool,int?) AcquireLegacyTls12()
    {
        var options=new LegacyCredential{Version=4,Protocols=Tls12Client,Lifespan=uint.MaxValue,Flags=GatewayFlags};
        var credential=SecHandle.Invalid;
        var status=AcquireLegacyNative(IntPtr.Zero,Package,2,IntPtr.Zero,ref options,IntPtr.Zero,IntPtr.Zero,ref credential,out _);
        return Release(status,ref credential);
    }

    private static (int,bool,int?) Release(int status,ref SecHandle credential)
    {
        bool returned=credential.Valid;
        return (status,returned,returned?FreeCredentialsHandle(ref credential):null);
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ModernCredential
    {
        internal uint Version,Format,CertificateCount;
        internal IntPtr Certificates,RootStore;
        internal uint MapperCount;
        internal IntPtr Mappers;
        internal uint Lifespan,Flags,ParameterCount;
        internal IntPtr TlsParameters;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct TlsParameters
    {
        internal uint AlpnCount;
        internal IntPtr AlpnIds;
        internal uint DisabledProtocols,DisabledCryptoCount;
        internal IntPtr DisabledCrypto;
        internal uint Flags;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct LegacyCredential
    {
        internal uint Version,CertificateCount;
        internal IntPtr Certificates,RootStore;
        internal uint MapperCount;
        internal IntPtr Mappers;
        internal uint AlgorithmCount;
        internal IntPtr Algorithms;
        internal uint Protocols,MinimumCipherStrength,MaximumCipherStrength,Lifespan,Flags,Format;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct SecHandle
    {
        internal IntPtr Lower,Upper;
        internal static SecHandle Invalid=>new(){Lower=new(-1),Upper=new(-1)};
        internal bool Valid=>Lower!=new IntPtr(-1) && Upper!=new IntPtr(-1) && (Lower!=IntPtr.Zero || Upper!=IntPtr.Zero);
    }
    [DllImport("kernel32.dll",ExactSpelling=true),DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern uint GetCurrentThreadId();
    [DllImport("secur32.dll",ExactSpelling=true,CharSet=CharSet.Unicode),DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern int QuerySecurityPackageInfoW(string package,out IntPtr info);
    [DllImport("secur32.dll",EntryPoint="AcquireCredentialsHandleW",ExactSpelling=true,CharSet=CharSet.Unicode),DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern int AcquireModernNative(IntPtr principal,string package,uint use,IntPtr logon,ref ModernCredential options,
        IntPtr callback,IntPtr callbackArgument,ref SecHandle handle,out long expiry);
    [DllImport("secur32.dll",EntryPoint="AcquireCredentialsHandleW",ExactSpelling=true,CharSet=CharSet.Unicode),DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern int AcquireLegacyNative(IntPtr principal,string package,uint use,IntPtr logon,ref LegacyCredential options,
        IntPtr callback,IntPtr callbackArgument,ref SecHandle handle,out long expiry);
    [DllImport("secur32.dll",ExactSpelling=true),DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern int FreeCredentialsHandle(ref SecHandle handle);
    [DllImport("secur32.dll",ExactSpelling=true),DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern int FreeContextBuffer(IntPtr info);
}
