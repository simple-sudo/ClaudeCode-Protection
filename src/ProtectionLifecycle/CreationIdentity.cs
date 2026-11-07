using System.Buffers.Binary;
using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;

namespace ProtectionLifecycle;

internal enum CreationRole : uint
{
    StateRoot=1,CodeRoot=2,Versions=3,Release=4,Bin=5,Current=6,Center=7,Admin=8,
    CodeMarker=9,VersionMarker=10,PackageManifest=11,
    DailyExe=12,DailyDll=13,DailyDeps=14,DailyRuntime=15,DailyReader=16,
    CenterExe=17,CenterDll=18,CenterDeps=19,CenterRuntime=20,
    BrokerExe=21,BrokerDll=22,BrokerDeps=23,BrokerRuntime=24,BrokerLifecycle=25,
    StateIdentity=26,OwnedJob=27,BrokerOpenSslCrypto=28,BrokerOpenSslLibrary=29
}

// A non-inherited READ_CONTROL-only ACE serves as an object tag. No account,
// service, token, capability or write grant is created. Its numeric SID is
// metadata; it is NOT proof of a Windows service identity or package approval.
// The full proof also requires protected ownership/ACL and the private ledger.
internal sealed class CreationTag
{
    private const uint Namespace=0x43504300;
    internal CreationRole Role { get; }
    internal string Id { get; }
    internal string Sid { get; }
    private CreationTag(CreationRole role,string id,string sid){Role=role;Id=id;Sid=sid;}
    internal static CreationTag For(CreationRole role,string id)
    {
        id=Identifiers.Hex32(id);
        if(!Enum.IsDefined(role) || id==new string('0',32))throw new InvalidDataException("Invalid creation role/id");
        var bytes=Convert.FromHexString(id);
        var components=new[]{Namespace|(uint)role,BinaryPrimitives.ReadUInt32BigEndian(bytes.AsSpan(0,4)),
            BinaryPrimitives.ReadUInt32BigEndian(bytes.AsSpan(4,4)),BinaryPrimitives.ReadUInt32BigEndian(bytes.AsSpan(8,4)),BinaryPrimitives.ReadUInt32BigEndian(bytes.AsSpan(12,4))};
        var sid="S-1-5-80-"+string.Join("-",components.Select(n=>n.ToString(CultureInfo.InvariantCulture)));
        return new(role,id,sid);
    }
    internal static CreationTag? TryParse(string sid)
    {
        var parts=sid.Split('-');
        if(parts.Length<5 || parts[0]!="S" || parts[1]!="1" || parts[2]!="5" || parts[3]!="80" ||
            !uint.TryParse(parts[4],NumberStyles.None,CultureInfo.InvariantCulture,out var magic) || (magic&0xffffff00)!=Namespace)return null;
        if(parts.Length!=9 || !Enum.IsDefined((CreationRole)(magic&0xff)))throw new InvalidDataException("Malformed product creation tag");
        var bytes=new byte[16];
        for(var i=0;i<4;i++)
        {
            if(!uint.TryParse(parts[5+i],NumberStyles.None,CultureInfo.InvariantCulture,out var value))throw new InvalidDataException("Malformed tag component");
            BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(i*4,4),value);
        }
        var tag=For((CreationRole)(magic&0xff),Convert.ToHexString(bytes).ToLowerInvariant());
        if(tag.Sid!=sid)throw new InvalidDataException("Noncanonical creation tag");return tag;
    }
    internal static CreationRole AssetRole(string id)=>id switch {
        "daily-exe"=>CreationRole.DailyExe,"daily-dll"=>CreationRole.DailyDll,"daily-deps"=>CreationRole.DailyDeps,"daily-runtime"=>CreationRole.DailyRuntime,"daily-reader"=>CreationRole.DailyReader,
        "center-exe"=>CreationRole.CenterExe,"center-dll"=>CreationRole.CenterDll,"center-deps"=>CreationRole.CenterDeps,"center-runtime"=>CreationRole.CenterRuntime,
        "broker-exe"=>CreationRole.BrokerExe,"broker-dll"=>CreationRole.BrokerDll,"broker-deps"=>CreationRole.BrokerDeps,"broker-runtime"=>CreationRole.BrokerRuntime,"broker-lifecycle"=>CreationRole.BrokerLifecycle,
        PackageAssetCatalog.OpenSslCryptoId=>CreationRole.BrokerOpenSslCrypto,PackageAssetCatalog.OpenSslLibraryId=>CreationRole.BrokerOpenSslLibrary,
        _=>throw new InvalidDataException("Unknown creation asset")};
    internal static CreationRole DirectoryRole(string role)=>role switch {
        "versions"=>CreationRole.Versions,"release"=>CreationRole.Release,"bin"=>CreationRole.Bin,"current"=>CreationRole.Current,"center"=>CreationRole.Center,"admin"=>CreationRole.Admin,
        _=>throw new InvalidDataException("Unknown directory creation role")};
}

internal sealed record CreationScope(string OperationId,string Release,string ManifestSHA256,string IntentSHA256,IReadOnlyList<PayloadFile> Files,string Phase);
internal sealed record CompletionObservation(string Tag,string ObjectIdentity,long Length,string SHA256);

internal static class CreationIdentity
{
    internal static CreationScope ReadScope(ProtectedState state,string operation)
    {
        operation=Identifiers.Hex32(operation);state.AssertHeld();
        // Reject the wrong operation before invoking the full reader: uninstall
        // proofs themselves read cleanup scopes and must not recurse here.
        using(var plan=JsonDocument.Parse(state.Read("plan-"+operation+".json",16384).Bytes))
            if(StrictJson.Text(plan.RootElement,"Operation") is not ("install" or "update"))throw new InvalidDataException("Creation is not owned by install/update");
        var journal=LifecycleJournal.Read(state,operation);
        if(journal.RecordCount<1)throw new InvalidDataException("Object creation requires a durable operation begin record");
        var raw=state.Read("stage-intent-"+operation+".json",32768);
        using var doc=JsonDocument.Parse(raw.Bytes,new JsonDocumentOptions{MaxDepth=6});var root=doc.RootElement;
        StrictJson.Fields(root,"SchemaVersion","InstallationId","OperationId","Release","ManifestSHA256","Assets");
        var release=Identifiers.Hex32(StrictJson.Text(root,"Release"));
        if(StrictJson.Text(root,"InstallationId")!=state.InstallationId || StrictJson.Text(root,"OperationId")!=operation || journal.Target!=release)
            throw new InvalidDataException("Creation intent ownership differs");
        var files=PackagePolicy.ParseInventory(root.GetProperty("Assets"),root.GetProperty("SchemaVersion").GetInt32(),"Id");
        return new(operation,release,Identifiers.Hash(StrictJson.Text(root,"ManifestSHA256")),raw.SHA256,files,journal.Phase);
    }
    internal static CreationScope AssertStageTag(ProtectedState state,CreationTag tag,CreationRole expected,string? release)
    {
        if(tag.Role!=expected)throw new InvalidDataException("Creation role differs");
        var scope=ReadScope(state,tag.Id);
        if(release is not null && scope.Release!=Identifiers.Hex32(release))throw new InvalidDataException("Creation release differs");
        return scope;
    }
    internal static string ExpectedPath(ProtectedState state,CreationTag tag)
    {
        var layout=FixedLayout.FromWindows();
        if(tag.Role is CreationRole.StateRoot or CreationRole.CodeRoot or CreationRole.StateIdentity)
        {
            if(tag.Id!=state.InstallationId)throw new InvalidDataException("Root creation identity belongs to another installation");
            return tag.Role==CreationRole.StateRoot?layout.StateRoot:tag.Role==CreationRole.CodeRoot?layout.CodeRoot:WindowsPathSeal.Child(layout.StateRoot,"installation.json");
        }
        var scope=AssertStageTag(state,tag,tag.Role,null);var version=layout.Version(scope.Release);
        return tag.Role switch {
            CreationRole.Versions=>layout.Versions,CreationRole.CodeMarker=>WindowsPathSeal.Child(layout.CodeRoot,"installation.json"),
            CreationRole.Release=>version,CreationRole.Bin=>WindowsPathSeal.Child(version,"bin"),CreationRole.Current=>WindowsPathSeal.Child(version,"bin/current"),
            CreationRole.Center=>WindowsPathSeal.Child(version,"bin/center"),CreationRole.Admin=>WindowsPathSeal.Child(version,"bin/admin"),
            CreationRole.VersionMarker=>WindowsPathSeal.Child(version,"version.json"),CreationRole.PackageManifest=>WindowsPathSeal.Child(version,"package.json"),
            _=>WindowsPathSeal.Child(version,scope.Files.Single(f=>CreationTag.AssetRole(f.Asset.Id)==tag.Role).Asset.Path)
        };
    }
    internal static void AssertRoot(PathLease root,ProtectedState state,CreationRole role)
    {
        using var parent=WindowsPathSeal.LockDirectory(Path.GetDirectoryName(root.Path)!,PathPolicy.CreationParent);
        var expected=role==CreationRole.CodeRoot?FixedLayout.FromWindows().CodeRoot:role==CreationRole.StateRoot?FixedLayout.FromWindows().StateRoot:throw new InvalidDataException("Fixed root role required");
        if(!string.Equals(root.Path,expected,StringComparison.OrdinalIgnoreCase))throw new InvalidDataException("Root location differs");
        root.AssertCreationTag(CreationTag.For(role,state.InstallationId));
    }
    internal static void AssertDirectory(PathLease directory,ProtectedState state,string role,string? release)
    {_=AssertStageTag(state,directory.ReadCreationTag(),CreationTag.DirectoryRole(role),release);}
    internal static void AssertFileScope(ProtectedState state,SafeFileHandle handle,CreationRole expected,string? release)
    {
        var tag=WindowsPathSeal.ReadCreationTag(handle);_=AssertStageTag(state,tag,expected,release);
        WindowsPathSeal.VerifyObject(handle,ExpectedPath(state,tag),false);
    }
    internal static PathLease CreateDirectory(PathLease parent,string leaf,bool publicRead,ProtectedState state,string operation,string role,string? release)
    {
        var tag=CreationTag.For(CreationTag.DirectoryRole(role),operation);_=AssertStageTag(state,tag,tag.Role,release);
        if(!string.Equals(WindowsPathSeal.Child(parent.Path,leaf),ExpectedPath(state,tag),StringComparison.OrdinalIgnoreCase))throw new InvalidDataException("Creation directory path differs from fixed role");
        return WindowsPathSeal.CreateProtectedDirectory(parent,leaf,publicRead,tag);
    }
    internal static SafeFileHandle CreateAsset(PathLease parent,string leaf,ProtectedState state,string operation,string release,PayloadFile expected)
    {
        var tag=CreationTag.For(CreationTag.AssetRole(expected.Asset.Id),operation);var scope=AssertStageTag(state,tag,tag.Role,release);
        if(!scope.Files.Any(f=>f.Asset.Id==expected.Asset.Id && f.Length==expected.Length && f.SHA256==expected.SHA256))throw new InvalidDataException("Creation asset differs from approved intent");
        if(!string.Equals(WindowsPathSeal.Child(parent.Path,leaf),ExpectedPath(state,tag),StringComparison.OrdinalIgnoreCase))throw new InvalidDataException("Creation asset path differs from fixed role");
        return WindowsPathSeal.CreateProtectedFile(parent,leaf,true,tag);
    }
    internal static string CompletionLeaf(CreationTag tag)=>"object-complete-"+tag.Id+"-"+((uint)tag.Role).ToString("D2",CultureInfo.InvariantCulture)+".json";
    internal static void RecordComplete(ProtectedState state,FileStream stream,CreationTag expected)
    {
        stream.Flush(true);var observed=ObserveComplete(state,stream,expected);
        var body=JsonSerializer.SerializeToUtf8Bytes(new {SchemaVersion=1,InstallationId=state.InstallationId,Tag=observed.Tag,ObjectIdentity=observed.ObjectIdentity,
            observed.Length,observed.SHA256,Status="BYTES_VERIFIED"});
        var old=state.ReadOptional(CompletionLeaf(expected));
        if(old is null)state.WriteNew(CompletionLeaf(expected),body);
        else CompletionReceipts.AssertMatches(state,expected,old,observed);
    }
    internal static CompletionObservation ObserveComplete(ProtectedState state,FileStream stream,CreationTag expected)
    {
        state.AssertHeld();var handle=stream.SafeFileHandle;
        WindowsPathSeal.VerifyObject(handle,ExpectedPath(state,expected),false);
        WindowsPathSeal.AssertAcl(handle,true);
        if(WindowsPathSeal.ReadCreationTag(handle).Sid!=expected.Sid)throw new InvalidDataException("Completed object identity differs");
        var length=stream.Length;
        var scope=AssertStageTag(state,expected,expected.Role,null);string expectedHash;long? expectedLength;
        if(expected.Role==CreationRole.PackageManifest){expectedHash=scope.ManifestSHA256;expectedLength=null;if(length>PackagePolicy.MaxManifestBytes)throw new InvalidDataException("Completed manifest too large");}
        else if(expected.Role is CreationRole.CodeMarker or CreationRole.VersionMarker)
        {
            var bytes=expected.Role==CreationRole.CodeMarker?JsonSerializer.SerializeToUtf8Bytes(new StateIdentity(1,state.InstallationId)):
                JsonSerializer.SerializeToUtf8Bytes(new VersionReceipt(1,state.InstallationId,scope.Release,scope.ManifestSHA256));
            expectedHash=Convert.ToHexString(SHA256.HashData(bytes));expectedLength=bytes.Length;
        }
        else
        {
            var asset=scope.Files.SingleOrDefault(f=>CreationTag.AssetRole(f.Asset.Id)==expected.Role)??throw new InvalidDataException("Unreviewed completion role");
            expectedHash=asset.SHA256;expectedLength=asset.Length;
        }
        if(length<1 || length>PackagePolicy.MaxAssetBytes || (expectedLength is not null && length!=expectedLength))throw new InvalidDataException("Actual created length differs from authorized scope");
        stream.Position=0;var hash=Convert.ToHexString(SHA256.HashData(stream));
        if(hash!=expectedHash)throw new InvalidDataException("Actual created bytes differ from authorized scope");
        return new(expected.Sid,WindowsPathSeal.Identity(handle),length,Identifiers.Hash(hash));
    }
    internal static void WriteMetadata(PathLease parent,string leaf,ProtectedState state,string operation,string? release,CreationRole role,byte[] bytes)
    {
        if(role is not (CreationRole.CodeMarker or CreationRole.VersionMarker or CreationRole.PackageManifest))throw new InvalidDataException("Fixed metadata role required");
        var tag=CreationTag.For(role,operation);_=AssertStageTag(state,tag,role,release);
        if(!string.Equals(WindowsPathSeal.Child(parent.Path,leaf),ExpectedPath(state,tag),StringComparison.OrdinalIgnoreCase))throw new InvalidDataException("Metadata path differs from fixed role");
        using var handle=WindowsPathSeal.CreateProtectedFile(parent,leaf,true,tag);
        using var stream=new FileStream(handle,FileAccess.ReadWrite,65536,false);stream.Write(bytes);stream.Flush(true);stream.Position=0;
        var hash=Convert.ToHexString(SHA256.HashData(stream));
        if(hash!=Convert.ToHexString(SHA256.HashData(bytes)))throw new IOException("Created metadata verification failed");
        RecordComplete(state,stream,tag);
    }
}
