using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;

namespace ProtectionLifecycle;

internal sealed record WinsockReadTarget(string Path,int Access,string? ContentSHA256,string OriginalSecurity,string GrantedSecurity);
internal sealed record WinsockReadIntent(int SchemaVersion,string InstallationId,string SessionId,string JobId,string Release,
    string ManifestSHA256,string PackageSid,int ControlSet,WinsockReadTarget[] Targets);

// The original session owner alone holds these exact registry objects. No
// caller path/capability, inheritance, value writer or independent executor.
internal sealed class SessionWinsockReadAccess : IDisposable
{
    internal const string IntentPrefix="winsock-access-intent-";
    private const string ClosedPrefix="winsock-access-closed-";
    private const int MaxIntentBytes=262144;
    private const int GraphicsDriversSchema=4,GraphicsDriversRootSchema=5;
    private readonly ProtectedState state;
    private readonly WinsockReadIntent intent;
    private readonly SafeRegistryHandle[] keys;
    private bool applied,restored,disposed;
    internal string IntentSHA256 {get;}
    internal int KeyCount=>keys.Length;
    internal bool Restored=>restored;
    private SessionWinsockReadAccess(ProtectedState state,WinsockReadIntent intent,SafeRegistryHandle[] keys,string hash)
    {this.state=state;this.intent=intent;this.keys=keys;IntentSHA256=hash;}

    private static int CurrentControlSet()
    {
        using var key=SessionManifestReadAccess.OpenReviewedKey(@"SYSTEM\Select",false);
        using var view=View(key);
        if(view.GetValueKind("Current")!=RegistryValueKind.DWord || view.GetValue("Current") is not int value || value is <1 or >999)
            throw WfpNative.Contract("WinsockCurrentControlSetUnavailable");
        return value;
    }
    private static RegistryKey View(SafeRegistryHandle key)=>RegistryKey.FromHandle(new SafeRegistryHandle(key.DangerousGetHandle(),false),RegistryView.Registry64);
    private static SafeRegistryHandle Open(string path,bool write)
    {
        var key=SessionManifestReadAccess.OpenReviewedKey(path,write);
        try{AssertName(key,path);return key;}catch{key.Dispose();throw;}
    }
    private static void AssertName(SafeRegistryHandle key,string path)
    {
        var buffer=Marshal.AllocHGlobal(4096);
        try
        {
            if(NtQueryKey(key,3,buffer,4096,out var used)!=0 || used is <6 or >4096)
                throw WfpNative.Contract("WinsockRegistryIdentityUnavailable");
            var length=Marshal.ReadInt32(buffer);
            var expected=path.Length==0?@"\REGISTRY\MACHINE":@"\REGISTRY\MACHINE\"+path;
            if(length<2 || (length&1)!=0 || length>used-4 ||
                !string.Equals(Marshal.PtrToStringUni(buffer+4,length/2),expected,StringComparison.OrdinalIgnoreCase))
                throw WfpNative.Contract("WinsockRegistryIdentityChanged");
        }
        finally{Marshal.FreeHGlobal(buffer);}
    }
    // Fingerprint only the fixed catalog objects; the root gets READ_CONTROL
    // and never needs a value/subkey inventory for its grant contract.
    private static string? Content(SafeRegistryHandle key,string path)
    {
        if(path.Length==0)return null;
        using var view=View(key);
        var names=view.GetValueNames().Order(StringComparer.Ordinal).ToArray();
        var children=view.GetSubKeyNames().Order(StringComparer.Ordinal).ToArray();
        if(path.EndsWith(@"\Control\GraphicsDrivers",StringComparison.Ordinal))
            return GraphicsDriversContent(view,path,names,children);
        if(names.Length>16 || children.Length>16 || names.Any(n=>n.Length>64))throw WfpNative.Contract("WinsockCatalogInventoryBounds");
        string[] allowed;
        string[] expectedChildren;
        if(path.EndsWith(@"\Winsock\Parameters",StringComparison.Ordinal))
        {
            allowed=new[]{"Transports"};expectedChildren=Array.Empty<string>();
            if(view.GetValueKind("Transports")!=RegistryValueKind.MultiString || view.GetValue("Transports") is not string[] transports)
                throw WfpNative.Contract("WinsockTransportSelectionMissing");
            WinsockRegistryScope.RequireTransportSelection(transports);
        }
        else if(path.EndsWith(@"\Parameters\Winsock",StringComparison.Ordinal))
        {
            var ipv6=path.EndsWith(@"\Tcpip6\Parameters\Winsock",StringComparison.Ordinal);
            allowed=new[]{"UseDelayedAcceptance","MaxSockAddrLength","MinSockAddrLength","HelperDllName","ProviderGUID","OfflineCapable","Mapping"};
            expectedChildren=new[]{"0","1","2"};
            int Dword(string name)=>view.GetValueKind(name)==RegistryValueKind.DWord && view.GetValue(name) is int value?value:
                throw WfpNative.Contract("WinsockTransportDwordMissing");
            if(Dword("UseDelayedAcceptance")!=0 || Dword("OfflineCapable")!=1 || Dword("MinSockAddrLength")!=(ipv6?28:16) || Dword("MaxSockAddrLength")!=(ipv6?28:16) ||
                view.GetValueKind("HelperDllName")!=RegistryValueKind.ExpandString ||
                view.GetValue("HelperDllName",null,RegistryValueOptions.DoNotExpandEnvironmentNames) is not string helper ||
                helper!=(ipv6?@"%SystemRoot%\System32\wship6.dll":@"%SystemRoot%\System32\wshtcpip.dll") ||
                view.GetValueKind("ProviderGUID")!=RegistryValueKind.Binary || view.GetValue("ProviderGUID") is not byte[] provider ||
                !provider.SequenceEqual(Guid.Parse(ipv6?"f9eab0c0-26d4-11d0-bbbf-00aa006c34e4":"e70f1aa0-ab8b-11cf-8ca3-00805f48a192").ToByteArray()) ||
                view.GetValueKind("Mapping")!=RegistryValueKind.Binary || view.GetValue("Mapping") is not byte[] mapping)
                throw WfpNative.Contract("WinsockTransportDefinitionChanged");
            WinsockRegistryScope.RequireTransportMapping(mapping,ipv6?23:2);
            if(!names.Order(StringComparer.Ordinal).SequenceEqual(allowed.Order(StringComparer.Ordinal),StringComparer.Ordinal))
                throw WfpNative.Contract("WinsockTransportValueSetChanged");
        }
        else if(path.EndsWith(@"\Winsock\Setup Migration\Providers",StringComparison.Ordinal))
        {
            allowed=Array.Empty<string>();expectedChildren=new[]{"afunix","Psched","RFCOMM","Tcpip","Tcpip6","vmbus"};
            WinsockRegistryScope.RequireProviderSelection(children);
        }
        else if(path.EndsWith(@"\Winsock\Setup Migration\Providers\Tcpip6",StringComparison.Ordinal) ||
            path.EndsWith(@"\Winsock\Setup Migration\Providers\Tcpip",StringComparison.Ordinal))
        {
            allowed=new[]{"WinSock 2.0 Provider ID"};expectedChildren=Array.Empty<string>();
            if(view.GetValueKind(allowed[0])!=RegistryValueKind.Binary || view.GetValue(allowed[0]) is not byte[] provider)
                throw WfpNative.Contract("WinsockProviderIdMissing");
            WinsockRegistryScope.RequireProviderId(provider,path.EndsWith(@"\Tcpip6",StringComparison.Ordinal)?23:2);
        }
        else if(path.EndsWith(@"\Parameters",StringComparison.Ordinal))
        {
            allowed=new[]{"AutodialDLL","NameSpace_Callout","WinSock_Registry_Version","Current_NameSpace_Catalog","Current_Protocol_Catalog"};
            expectedChildren=new[]{"AppId_Catalog","NameSpace_Catalog5","Protocol_Catalog9"};
            if(view.GetValue("Current_Protocol_Catalog") is not string protocol || protocol!="Protocol_Catalog9" ||
                view.GetValue("Current_NameSpace_Catalog") is not string space || space!="NameSpace_Catalog5" ||
                view.GetValue("WinSock_Registry_Version") is not string version || version!="2.0")throw WfpNative.Contract("WinsockCatalogSelectionChanged");
        }
        else if(path.EndsWith(@"\Protocol_Catalog9",StringComparison.Ordinal) || path.EndsWith(@"\NameSpace_Catalog5",StringComparison.Ordinal))
        {
            allowed=path.EndsWith(@"\Protocol_Catalog9",StringComparison.Ordinal)?
                new[]{"Num_Catalog_Entries64","Num_Catalog_Entries","Next_Catalog_Entry_ID","Serial_Access_Num"}:
                new[]{"Num_Catalog_Entries64","Num_Catalog_Entries","Serial_Access_Num"};
            expectedChildren=new[]{"Catalog_Entries","Catalog_Entries64"};
            var expected=path.EndsWith(@"\Protocol_Catalog9",StringComparison.Ordinal)?WinsockRegistryScope.ProtocolEntries:WinsockRegistryScope.NamespaceEntries;
            if(view.GetValue("Num_Catalog_Entries64") is not int count || count!=expected)throw WfpNative.Contract("WinsockCatalogCountChanged");
        }
        else if(path.EndsWith(@"\Catalog_Entries64",StringComparison.Ordinal))
        {
            allowed=Array.Empty<string>();
            var count=path.Contains(@"\Protocol_Catalog9\",StringComparison.Ordinal)?WinsockRegistryScope.ProtocolEntries:WinsockRegistryScope.NamespaceEntries;
            expectedChildren=Enumerable.Range(1,count).Select(n=>n.ToString("D12",System.Globalization.CultureInfo.InvariantCulture)).ToArray();
        }
        else
        {
            allowed=path.Contains(@"\Protocol_Catalog9\",StringComparison.Ordinal)?new[]{"PackedCatalogItem","ProtocolName"}:
                new[]{"LibraryPath","DisplayString","ProviderId","SupportedNameSpace","Enabled","Version","StoresServiceClassInfo","ProviderInfo"};
            expectedChildren=Array.Empty<string>();
        }
        if(names.Except(allowed,StringComparer.Ordinal).Any() || !children.SequenceEqual(expectedChildren.Order(StringComparer.Ordinal)))
            throw WfpNative.Contract("WinsockCatalogShapeChanged");
        var values=new List<object>();
        foreach(var name in names)
        {
            var kind=view.GetValueKind(name);
            var value=view.GetValue(name,null,RegistryValueOptions.DoNotExpandEnvironmentNames);
            if(value is null || value is not (string or int or long or byte[] or string[]) || value is string text && text.Length>4096 || value is byte[] bytes && bytes.Length>8192 ||
                value is string[] strings && (strings.Length>16 || strings.Any(s=>s.Length>64)))
                throw WfpNative.Contract("WinsockCatalogValueBounds");
            values.Add(new{Name=name,Kind=(int)kind,Value=value});
        }
        return Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(new{Children=children,Values=values})));
    }

    private static string GraphicsDriversPath(int controlSet)
    {
        if(controlSet is <1 or >999)throw WfpNative.Contract("GraphicsDriversControlSetRefused");
        return @"SYSTEM\ControlSet"+controlSet.ToString("D3",System.Globalization.CultureInfo.InvariantCulture)+@"\Control\GraphicsDrivers";
    }
    private static WinsockRegistryScope.Target[] GraphicsDriversTargets(int controlSet,bool withRoot)
    {
        var leaf=new WinsockRegistryScope.Target(GraphicsDriversPath(controlSet),WinsockRegistryScope.CatalogAccess);
        return withRoot?[new("",WinsockRegistryScope.RootAccess),leaf]:[leaf];
    }
    private static bool IsGraphicsDrivers(int schema)=>schema is GraphicsDriversSchema or GraphicsDriversRootSchema;

    private static int[] GraphicsDriversValues(RegistryKey view,string[] names,string[] children)
    {
        string[] expectedValues=["DxgKrnlVersion","HwSchMode","MinDxgKrnlVersion","PlatformSupportMiracast","TdrDelay","TdrLevel"];
        string[] expectedChildren=["AdditionalModeLists","BasicDisplay","BlockList","Configuration","Connectivity","DCI",
            "FeatureSetUsage","InternalMonEdid","MonitorDataStore","ScaleFactors","TdrWatch","UseNewKey"];
        if(!names.SequenceEqual(expectedValues,StringComparer.Ordinal) || !children.SequenceEqual(expectedChildren,StringComparer.Ordinal))
            throw WfpNative.Contract("GraphicsDriversInventoryChanged");
        var values=new int[names.Length];
        for(var i=0;i<names.Length;i++)
        {
            if(view.GetValueKind(names[i])!=RegistryValueKind.DWord || view.GetValue(names[i]) is not int value)
                throw WfpNative.Contract("GraphicsDriversDwordRequired");
            values[i]=value;
        }
        return values;
    }

    private static string GraphicsDriversContent(RegistryKey view,string path,string[] names,string[] children)
    {
        var values=GraphicsDriversValues(view,names,children);
        var childSecurity=new string[children.Length];
        for(var i=0;i<children.Length;i++)
        {
            using var child=Open(path+"\\"+children[i],false);
            childSecurity[i]=SessionManifestReadAccess.ReadObjectSecurity(child);
        }
        return Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(new{names,values,children,childSecurity})));
    }

    internal static string InspectGraphicsDriversMetadata()
    {
        var controlSet=CurrentControlSet();var path=GraphicsDriversPath(controlSet);
        using var key=Open(path,false);
        var original=SessionManifestReadAccess.ReadObjectSecurity(key);
        const string fixturePackage="S-1-15-2-1-2-3-4-5-6-7";
        _=GraphicsDriversGrant(original,fixturePackage);
        using var root=Open("",false);
        var rootSecurity=SessionManifestReadAccess.ReadObjectSecurity(root);
        WinsockRegistryScope.RequireSupportedRootSecurity(rootSecurity);
        _=WinsockRegistryScope.AddReadAce(rootSecurity,fixturePackage,WinsockRegistryScope.RootAccess);
        using var view=View(key);
        var names=view.GetValueNames().Order(StringComparer.Ordinal).ToArray();
        var children=view.GetSubKeyNames().Order(StringComparer.Ordinal).ToArray();
        var values=GraphicsDriversValues(view,names,children);
        var childAclDenied=0;
        foreach(var childName in children)
        {
            try
            {
                using var child=Open(path+"\\"+childName,false);
                _=SessionManifestReadAccess.ReadObjectSecurity(child);
            }
            catch(Win32Exception ex)when(ex.NativeErrorCode==5){childAclDenied++;}
        }
        if(CurrentControlSet()!=controlSet)throw WfpNative.Contract("GraphicsDriversControlSetChanged");
        return JsonSerializer.Serialize(new{Scope="FIXED_GRAPHICS_DRIVERS_METADATA",ValueCount=values.Length,ChildCount=children.Length,ChildAclDenied=childAclDenied,
            SecuritySHA256=Convert.ToHexString(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(original))),
            RootSecuritySHA256=Convert.ToHexString(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(rootSecurity))),RegistryModified=false});
    }

    private static string GraphicsDriversGrant(string original,string packageSid)
    {
        WinsockRegistryScope.RequireSupportedRootSecurity(original);
        return WinsockRegistryScope.AddReadAce(original,packageSid,WinsockRegistryScope.CatalogAccess);
    }
    internal static string InspectCurrentMetadata()
        =>InspectMetadata(false);
    internal static string InspectTransportMetadata()
        =>InspectMetadata(true);
    internal static string InspectProviderMetadata()
        =>InspectMetadata(true,true);
    private static string InspectMetadata(bool transports,bool providers=false)
    {
        var controlSet=CurrentControlSet();var rows=new List<object>();
        foreach(var target in providers?WinsockRegistryScope.ProviderTargets(controlSet):
            transports?WinsockRegistryScope.TransportTargets(controlSet):WinsockRegistryScope.Targets(controlSet))
        {
            using var key=Open(target.Path,false);
            var original=SessionManifestReadAccess.ReadObjectSecurity(key);
            _=WinsockRegistryScope.AddReadAce(original,"S-1-15-2-1-2-3-4-5-6-7",target.Access);
            var flags=new RawSecurityDescriptor(original).ControlFlags;
            rows.Add(new{target.Path,target.Access,SecurityControl=flags.ToString(),ContentSHA256=Content(key,target.Path),SecuritySHA256=Convert.ToHexString(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(original)))});
        }
        if(CurrentControlSet()!=controlSet)throw WfpNative.Contract("WinsockMetadataControlSetChanged");
        return JsonSerializer.Serialize(new{Scope="FIXED_X64_WINSOCK_REGISTRY_METADATA_ONLY",ControlSet=controlSet,Targets=rows,
            RegistryModified=false,StateRead=false,StateModified=false,PackageCapabilityAdded=false});
    }
    internal static SessionWinsockReadAccess Prepare(ProtectedState state,VerifiedVersion version,OwnedKernelJob job,string sessionId,bool transports=false,bool providers=false)
    {
        if(providers && !transports)throw WfpNative.Contract("WinsockProviderRequiresTransportScope");
        return PrepareCore(state,version,job,sessionId,providers?3:transports?2:1);
    }
    internal static SessionWinsockReadAccess PrepareGraphicsDrivers(ProtectedState state,VerifiedVersion version,OwnedKernelJob job)
    {
        if(version.Package.SchemaVersion is not (PackageAssetCatalog.SessionZeroCudaGraphicsReadSchema or PackageAssetCatalog.SessionZeroCudaGraphicsRootSchema) || job.SessionZeroCreatorSid is null)
            throw WfpNative.Contract("GraphicsDriversAccessRequiresFixedCudaJob");
        var schema=version.Package.SchemaVersion==PackageAssetCatalog.SessionZeroCudaGraphicsRootSchema?GraphicsDriversRootSchema:GraphicsDriversSchema;
        return PrepareCore(state,version,job,job.JobId,schema);
    }
    private static SessionWinsockReadAccess PrepareCore(ProtectedState state,VerifiedVersion version,OwnedKernelJob job,string sessionId,int schema)
    {
        ProtectedState.RequireAdministrator();state.AssertHeld();version.AssertHeld(state);AssertNoPending(state);
        if(!job.AtomicAdmissionReserved)throw WfpNative.Contract("WinsockAccessRequiresOriginalAtomicJob");
        var controlSet=CurrentControlSet();using var package=new InstallationPackageSid(state);
        var opened=new List<SafeRegistryHandle>();var targets=new List<WinsockReadTarget>();
        try
        {
            var scope=schema switch
            {
                GraphicsDriversSchema or GraphicsDriversRootSchema=>GraphicsDriversTargets(controlSet,schema==GraphicsDriversRootSchema),
                3=>WinsockRegistryScope.ProviderTargets(controlSet),
                2=>WinsockRegistryScope.TransportTargets(controlSet),
                _=>WinsockRegistryScope.Targets(controlSet)
            };
            foreach(var target in scope)
            {
                var key=Open(target.Path,true);opened.Add(key);
                var original=SessionManifestReadAccess.ReadObjectSecurity(key);
                if(target.Path.Length==0)WinsockRegistryScope.RequireSupportedRootSecurity(original);
                var granted=IsGraphicsDrivers(schema) && target.Path.Length!=0?GraphicsDriversGrant(original,package.Value):
                    WinsockRegistryScope.AddReadAce(original,package.Value,target.Access);
                if(new RawSecurityDescriptor(granted).BinaryLength>SessionManifestReadAccess.MaxSecurityDescriptorBytes)
                    throw WfpNative.Contract("WinsockGrantedSecurityBounds");
                targets.Add(new(target.Path,target.Access,Content(key,target.Path),original,granted));
            }
            if(CurrentControlSet()!=controlSet)throw WfpNative.Contract("WinsockControlSetChangedBeforeIntent");
            var intent=new WinsockReadIntent(schema,state.InstallationId,Identifiers.Hex32(sessionId),job.JobId,version.Package.Release,
                version.Package.ManifestHash,package.Value,controlSet,targets.ToArray());
            Validate(intent,state.InstallationId,package.Value);
            var bytes=JsonSerializer.SerializeToUtf8Bytes(intent);if(bytes.Length>MaxIntentBytes)throw WfpNative.Contract("WinsockIntentBounds");
            var hash=state.WriteNew(IntentPrefix+intent.SessionId+".json",bytes);
            return new(state,intent,opened.ToArray(),hash);
        }
        catch{foreach(var key in opened)key.Dispose();throw;}
    }
    internal void Apply()
    {
        ProtectedState.RequireAdministrator();state.AssertHeld();
        if(disposed || applied || restored)throw WfpNative.Contract("WinsockAccessAlreadyConsumed");
        AssertContent();
        for(var i=0;i<keys.Length;i++)if(Read(i)!=intent.Targets[i].OriginalSecurity)throw WfpNative.Contract("WinsockSecurityChangedBeforeGrant");
        // Root last: standard API mapping opens only after every leaf is ready.
        foreach(var i in Enumerable.Range(1,keys.Length-1).Append(0))
        {
            if(Read(i)!=intent.Targets[i].OriginalSecurity)throw WfpNative.Contract("WinsockSecurityChangedBeforeOwnWrite");
            Write(keys[i],intent.Targets[i].GrantedSecurity);
            if(Read(i)!=intent.Targets[i].GrantedSecurity)throw WfpNative.Contract("WinsockGrantNotObserved");
        }
        applied=true;AssertHeld();
    }
    private string Read(int i){AssertName(keys[i],intent.Targets[i].Path);return SessionManifestReadAccess.ReadObjectSecurity(keys[i]);}
    private static void Write(SafeRegistryHandle key,string security)
    {
        var flags=new RawSecurityDescriptor(security).ControlFlags;
        var protect=(flags&ControlFlags.DiscretionaryAclProtected)!=0;
        SessionManifestReadAccess.WriteSecurity(key,security,protect,
            // P+AI transport mappings retain both bits only when the input
            // carries AR+AI as well as the explicit protection information.
            // Qualified with native own-parent/child exact grant/restore.
            requestAutoInheritance:(flags&ControlFlags.DiscretionaryAclAutoInherited)!=0);
    }
    private void AssertContent()
    {
        if(CurrentControlSet()!=intent.ControlSet)throw WfpNative.Contract("WinsockActiveControlSetDrift");
        for(var i=0;i<keys.Length;i++)if(Content(keys[i],intent.Targets[i].Path)!=intent.Targets[i].ContentSHA256)
            throw WfpNative.Contract("WinsockCatalogContentDrift");
    }
    internal void AssertHeld()
    {
        state.AssertHeld();
        if(disposed || restored || !applied || state.Read(IntentPrefix+intent.SessionId+".json",MaxIntentBytes).SHA256!=IntentSHA256)
            throw WfpNative.Contract("WinsockLeaseNotCurrent");
        for(var i=0;i<keys.Length;i++)if(Read(i)!=intent.Targets[i].GrantedSecurity)throw WfpNative.Contract("WinsockLeaseSecurityDrift");
        AssertContent();
    }
    internal void RestoreAfterClosedJob(JobSnapshot snapshot)
    {
        if(disposed || restored || snapshot.JobId!=intent.JobId || !snapshot.ExpectedLimits || !snapshot.ObservedZero)
            throw WfpNative.Contract("WinsockRestoreRequiresOriginalJobZero");
        Restore(state,intent,IntentSHA256,keys);restored=true;
    }
    internal void AssertGraphicsDriversBoundary()
    {
        if(!IsGraphicsDrivers(intent.SchemaVersion) || !restored)throw WfpNative.Contract("GraphicsDriversRestoreNotVerified");
        AssertContent();
    }
    private static void Restore(ProtectedState state,WinsockReadIntent intent,string hash,SafeRegistryHandle[] keys)
    {
        ProtectedState.RequireAdministrator();state.AssertHeld();
        var job=OwnedJobIntent.ReadAll(state).SingleOrDefault(j=>j.JobId==intent.JobId)??throw WfpNative.Contract("WinsockOriginalJobMissing");
        if(job.Release!=intent.Release || job.ManifestSHA256!=intent.ManifestSHA256 || AtomicJobCompletion.ReadClosed(state,job) is null)
            throw WfpNative.Contract("WinsockRestoreRequiresDurableClosedJob");
        string Read(int i){AssertName(keys[i],intent.Targets[i].Path);return SessionManifestReadAccess.ReadObjectSecurity(keys[i]);}
        string Decide(int i)=>SessionManifestReadAccess.RestoreDecision(Read(i),intent.Targets[i].OriginalSecurity,intent.Targets[i].GrantedSecurity);
        for(var i=0;i<keys.Length;i++)_=Decide(i);
        // Root first, after closed/zero. Never normalize or merge unknown ACLs.
        for(var i=0;i<keys.Length;i++)if(Decide(i)=="REMOVE_EXACT_OWN_READ_GRANT")Write(keys[i],intent.Targets[i].OriginalSecurity);
        for(var i=0;i<keys.Length;i++)if(Read(i)!=intent.Targets[i].OriginalSecurity)throw WfpNative.Contract("WinsockOriginalSecurityNotRestored");
        state.WriteNew(ClosedPrefix+intent.SessionId+".json",JsonSerializer.SerializeToUtf8Bytes(new{SchemaVersion=1,state.InstallationId,
            intent.SessionId,intent.JobId,IntentSHA256=hash,Status=ClosedStatus(intent)}));
    }
    private static string ClosedStatus(WinsockReadIntent intent)=>intent.SchemaVersion switch
    {
        GraphicsDriversRootSchema=>"EXACT_ORIGINAL_GRAPHICS_DRIVER_AND_HIVE_DACLS_AFTER_CLOSED_JOB",
        GraphicsDriversSchema=>"EXACT_ORIGINAL_GRAPHICS_DRIVERS_DACL_AFTER_CLOSED_JOB",
        _=>"EXACT_ORIGINAL_WINSOCK_DACLS_AFTER_CLOSED_JOB"
    };
    internal static void Validate(WinsockReadIntent intent,string installation,string package)
    {
        if(intent.SchemaVersion is not (1 or 2 or 3 or GraphicsDriversSchema or GraphicsDriversRootSchema) || intent.InstallationId!=installation || intent.PackageSid!=package ||
            intent.Targets is null || intent.Targets.Length!=(intent.SchemaVersion switch {1=>25,2=>28,3=>31,GraphicsDriversSchema=>1,_=>2}))
            throw WfpNative.Contract("WinsockIntentScopeMismatch");
        _=Identifiers.Hex32(intent.SessionId);_=Identifiers.Hex32(intent.JobId);_=Identifiers.Hex32(intent.Release);_=Identifiers.Hash(intent.ManifestSHA256);
        if(intent.Targets.Any(t=>t is null))throw WfpNative.Contract("WinsockIntentTargetMissing");
        var targets=intent.Targets.Select(t=>new WinsockRegistryScope.Target(t.Path,t.Access)).ToArray();
        if(intent.SchemaVersion==1)WinsockRegistryScope.RequireExactTargets(intent.ControlSet,targets);
        else if(intent.SchemaVersion==2)WinsockRegistryScope.RequireExactTransportTargets(intent.ControlSet,targets);
        else if(intent.SchemaVersion==3)WinsockRegistryScope.RequireExactProviderTargets(intent.ControlSet,targets);
        else if(intent.SessionId!=intent.JobId || !targets.SequenceEqual(GraphicsDriversTargets(intent.ControlSet,intent.SchemaVersion==GraphicsDriversRootSchema)))
            throw WfpNative.Contract("GraphicsDriversIntentScopeMismatch");
        foreach(var target in intent.Targets)
        {
            if(target.Path.Length==0)WinsockRegistryScope.RequireSupportedRootSecurity(target.OriginalSecurity);
            if(target.Path.Length==0?target.ContentSHA256 is not null:target.ContentSHA256 is null)
                throw WfpNative.Contract("WinsockIntentContentScopeMismatch");
            if(target.ContentSHA256 is not null)_=Identifiers.Hash(target.ContentSHA256);
            var granted=IsGraphicsDrivers(intent.SchemaVersion) && target.Path.Length!=0?GraphicsDriversGrant(target.OriginalSecurity,package):
                WinsockRegistryScope.AddReadAce(target.OriginalSecurity,package,target.Access);
            if(granted!=target.GrantedSecurity)
                throw WfpNative.Contract("WinsockIntentGrantMismatch");
        }
    }
    internal static void RequireCurrentRootControl()
    {
        using var root=Open("",false);
        WinsockRegistryScope.RequireSupportedRootSecurity(SessionManifestReadAccess.ReadObjectSecurity(root));
    }
    private static IReadOnlyList<(WinsockReadIntent Intent,string Hash)> Pending(ProtectedState state)
    {
        state.AssertHeld();using var package=new InstallationPackageSid(state);var pending=new List<(WinsockReadIntent,string)>();
        foreach(var leaf in state.ListLeaves(IntentPrefix))
        {
            var raw=state.Read(leaf,MaxIntentBytes);using var doc=JsonDocument.Parse(raw.Bytes,new JsonDocumentOptions{MaxDepth=5});
            StrictJson.Fields(doc.RootElement,"SchemaVersion","InstallationId","SessionId","JobId","Release","ManifestSHA256","PackageSid","ControlSet","Targets");
            foreach(var target in doc.RootElement.GetProperty("Targets").EnumerateArray())StrictJson.Fields(target,"Path","Access","ContentSHA256","OriginalSecurity","GrantedSecurity");
            var intent=JsonSerializer.Deserialize<WinsockReadIntent>(raw.Bytes)??throw WfpNative.Contract("WinsockIntentMissing");Validate(intent,state.InstallationId,package.Value);
            if(leaf!=IntentPrefix+intent.SessionId+".json")throw WfpNative.Contract("WinsockIntentLeafRefused");
            var closed=state.ReadOptional(ClosedPrefix+intent.SessionId+".json");
            if(closed is null){pending.Add((intent,raw.SHA256));continue;}
            using var c=JsonDocument.Parse(closed.Bytes);var r=c.RootElement;
            StrictJson.Fields(r,"SchemaVersion","InstallationId","SessionId","JobId","IntentSHA256","Status");
            if(r.GetProperty("SchemaVersion").GetInt32()!=1 || StrictJson.Text(r,"InstallationId")!=state.InstallationId ||
                StrictJson.Text(r,"SessionId")!=intent.SessionId || StrictJson.Text(r,"JobId")!=intent.JobId || StrictJson.Text(r,"IntentSHA256")!=raw.SHA256 ||
                StrictJson.Text(r,"Status")!=ClosedStatus(intent))throw WfpNative.Contract("WinsockRestorationReceiptMismatch");
        }
        if(pending.Count>1)throw WfpNative.Contract("WinsockOverlappingIntentsRefused");return pending;
    }
    internal static void AssertNoPending(ProtectedState state)
    {if(Pending(state).Count!=0)throw WfpNative.Contract("WinsockAccessRequiresExplicitRecovery");}
    internal static (int ExitCode,string Report) Inspect(ProtectedState state,bool graphicsDrivers=false)
    {
        var pending=Pending(state).Where(item=>IsGraphicsDrivers(item.Intent.SchemaVersion)==graphicsDrivers).ToArray();
        var name=graphicsDrivers?"GRAPHICS_DRIVERS":"WINSOCK";
        return(pending.Length==0?0:2,JsonSerializer.Serialize(new{SchemaVersion=1,Status=pending.Length==0?"NO_PENDING_"+name+"_READ_ACCESS":name+"_READ_RECOVERY_DECISION_REQUIRED",
            Pending=pending.Select(p=>new{p.Intent.SessionId,p.Intent.JobId,KeyCount=p.Intent.Targets.Length}),StateModified=false,RegistryModified=false}));
    }
    internal static (int ExitCode,string Report) Recover(ProtectedState state,bool graphicsDrivers=false)
    {
        ProtectedState.RequireAdministrator();state.AssertHeld();InstallationLoopbackLease.AssertClosedHistory(state);
        foreach(var job in OwnedJobIntent.ReadAll(state))if(!SessionZeroCreatorRecovery.IsAdmissionResolved(state,job))throw WfpNative.Contract("WinsockRecoveryRequiresAllAdmissionsClosed");
        var plans=FencePlan.ReadAll(state);if(plans.Count==0)throw WfpNative.Contract("WinsockRecoveryRequiresQuarantine");
        foreach(var plan in plans){using var fence=PersistentFence.OpenExisting(state,plan.Data.FenceId);if(!fence.Observe().FullQuarantineObserved)throw WfpNative.Contract("WinsockRecoveryRequiresQuarantine");}
        var pending=Pending(state);
        if(pending.Any(item=>IsGraphicsDrivers(item.Intent.SchemaVersion)!=graphicsDrivers))
            throw WfpNative.Contract("RegistryRecoveryRequiresMatchingScope");
        foreach(var item in pending)
        {
            var opened=new List<SafeRegistryHandle>();
            try{foreach(var target in item.Intent.Targets)opened.Add(Open(target.Path,true));Restore(state,item.Intent,item.Hash,opened.ToArray());}
            finally{foreach(var key in opened)key.Dispose();}
        }
        AssertNoPending(state);
        return(0,JsonSerializer.Serialize(new{SchemaVersion=1,Status=graphicsDrivers?"EXACT_GRAPHICS_DRIVERS_READ_ACCESS_RECOVERED":"EXACT_WINSOCK_READ_ACCESS_RECOVERED",
            Count=pending.Count,JobCreated=false,ProcessCreated=false,NetworkPolicyModified=false}));
    }
    public void Dispose()
    {
        if(disposed)return;disposed=true;foreach(var key in keys)key.Dispose();
        if(!restored)throw WfpNative.Contract("WinsockAccessRequiresExplicitRecovery");
    }
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("ntdll.dll",ExactSpelling=true)] private static extern int NtQueryKey(SafeRegistryHandle key,int information,IntPtr buffer,uint size,out uint used);
}
