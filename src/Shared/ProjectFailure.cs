using System.Text.Json;

namespace ClaudeCodeProtection.Workspaces;

// Advisory failure data only. No exception text, compiler message, host path,
// source excerpt, stack, admission or cleanup authority crosses this contract.
internal sealed record ProjectCompilerDiagnostic(string Code,int? SourceIndex,int Line,int Column);
internal sealed record ProjectTaskFailure(string Stage,ProjectCompilerDiagnostic[] Diagnostics);
internal sealed class ProjectTaskException : Exception
{
    internal ProjectTaskFailure Failure {get;}
    internal ProjectTaskException(ProjectTaskFailure failure):base("Explicit project task failed")
    {ProjectFailureContract.Validate(failure);Failure=failure;}
}
internal static class ProjectFailureContract
{
    private const string Prefix="CPC_PROJECT_FAILURE_V1:";
    internal static void Validate(ProjectTaskFailure value,int sourceCount=32)
    {
        if(sourceCount is <1 or >32 || value.Stage is not ("Compile" or "Entry" or "Run" or "Tests") ||
            value.Diagnostics is null || value.Diagnostics.Length>8 || value.Stage!="Compile" && value.Diagnostics.Length!=0)
            throw new InvalidDataException("Project failure scope differs");
        foreach(var diagnostic in value.Diagnostics)
            if(diagnostic is null || diagnostic.Code is not {Length:6} || !diagnostic.Code.StartsWith("CS",StringComparison.Ordinal) ||
                diagnostic.Code.AsSpan(2).ContainsAnyExceptInRange('0','9') ||
                diagnostic.SourceIndex is int index && (index<0 || index>=sourceCount) ||
                (diagnostic.SourceIndex is null?diagnostic.Line!=0 || diagnostic.Column!=0:diagnostic.Line is <1 or >1000000 || diagnostic.Column is <1 or >1000000))
                throw new InvalidDataException("Project compiler diagnostic differs");
    }
    internal static ProjectTaskFailure Parse(JsonElement value,int sourceCount=32)
    {
        HostPrivacyContract.Fields(value,"Stage","Diagnostics");
        var array=value.GetProperty("Diagnostics");
        if(array.ValueKind!=JsonValueKind.Array || array.GetArrayLength()>8)throw new InvalidDataException("Project diagnostic bounds");
        foreach(var item in array.EnumerateArray())HostPrivacyContract.Fields(item,"Code","SourceIndex","Line","Column");
        var result=JsonSerializer.Deserialize<ProjectTaskFailure>(value.GetRawText())??throw new InvalidDataException("Project failure missing");
        Validate(result,sourceCount);return result;
    }
    internal static string Encode(ProjectTaskFailure value)
    {Validate(value);return Prefix+JsonSerializer.Serialize(value);}
    internal static ProjectTaskFailure? ReadToolError(string stdout,string stderr,int sourceCount)
    {
        var text=stderr.TrimEnd('\r','\n');
        if(stdout.Length!=0 || text.Length>2048 || !text.StartsWith(Prefix,StringComparison.Ordinal))return null;
        try{using var json=JsonDocument.Parse(text[Prefix.Length..],new JsonDocumentOptions{MaxDepth=4});return Parse(json.RootElement,sourceCount);}
        catch(Exception error)when(error is JsonException or InvalidDataException or InvalidOperationException or FormatException or KeyNotFoundException){return null;}
    }
}
