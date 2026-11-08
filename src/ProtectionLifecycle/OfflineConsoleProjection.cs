using System.Text.Json;

namespace ProtectionLifecycle;

// Bounded content evidence for this fixed self-developed worker only. Child
// strings are data, never paths the elevated owner can open or act on.
internal sealed record OfflineConsoleProjection(int SchemaVersion,string SessionId,int Pid,string? Temp,string? Tmp,string? LocalAppData)
{
    private const int MaximumFieldLength=240;
    internal static OfflineConsoleProjection Capture(string session)=>new(1,session,Environment.ProcessId,
        Environment.GetEnvironmentVariable("TEMP"),Environment.GetEnvironmentVariable("TMP"),Environment.GetEnvironmentVariable("LOCALAPPDATA"));

    internal string? Read(string name)=>name switch {
        "TEMP"=>Temp,"TMP"=>Tmp,"LOCALAPPDATA"=>LocalAppData,_=>Environment.GetEnvironmentVariable(name)
    };

    internal byte[] Encode()
    {
        AssertBounds();
        var bytes=JsonSerializer.SerializeToUtf8Bytes(this);
        if(bytes.Length>OfflineConsoleStreams.MaximumBytes)throw WfpNative.Contract("OfflineConsoleProjectionSize");
        return bytes;
    }

    internal static OfflineConsoleProjection Parse(byte[] bytes,string session,uint pid)
    {
        if(bytes.Length is <1 or >OfflineConsoleStreams.MaximumBytes)throw WfpNative.Contract("OfflineConsoleProjectionSize");
        using var document=JsonDocument.Parse(bytes,new JsonDocumentOptions{MaxDepth=2});
        StrictJson.Fields(document.RootElement,"SchemaVersion","SessionId","Pid","Temp","Tmp","LocalAppData");
        var projection=JsonSerializer.Deserialize<OfflineConsoleProjection>(bytes)??throw WfpNative.Contract("OfflineConsoleProjectionMissing");
        if(projection.SchemaVersion!=1 || projection.SessionId!=session || pid==0 || projection.Pid!=pid)
            throw WfpNative.Contract("OfflineConsoleProjectionActorMismatch");
        projection.AssertBounds();
        return projection;
    }

    private void AssertBounds()
    {
        if(new[]{Temp,Tmp,LocalAppData}.Any(value=>value is not null && (value.Length>MaximumFieldLength || value.Contains('\0'))))
            throw WfpNative.Contract("OfflineConsoleProjectionFieldBounds");
    }

    internal static string Classify(string? actual,string expected,string workspace,string host)
    {
        if(actual is null)return "ABSENT";
        if(actual.Length==0)return "EMPTY";
        if(string.Equals(actual,expected,StringComparison.OrdinalIgnoreCase))return "OWNED_EXACT";
        if(string.Equals(actual,expected+"\\",StringComparison.OrdinalIgnoreCase))return "OWNED_TRAILING_SEPARATOR";
        if(string.Equals(actual,workspace,StringComparison.OrdinalIgnoreCase))return "TASK_WORKSPACE";
        if(host.Length!=0 && string.Equals(Path.TrimEndingDirectorySeparator(actual),Path.TrimEndingDirectorySeparator(host),StringComparison.OrdinalIgnoreCase))
            return "HOST_DEFAULT";
        return "OTHER";
    }
}
