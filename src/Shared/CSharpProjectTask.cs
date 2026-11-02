using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace ClaudeCodeProtection.Workspaces;

internal sealed record CSharpProjectEdit(string Path,string Before,string After);
internal sealed record CSharpProjectOutput(string Path,int MaxBytes);
internal sealed record CSharpProjectDefinition(int SchemaVersion,string Kind,string[] Sources,
    CSharpProjectEdit[] Edits,string EntryType,string TestType,int ExpectedTests,
    [property:JsonIgnore(Condition=JsonIgnoreCondition.WhenWritingNull)] string[]? DataFiles=null,
    [property:JsonIgnore(Condition=JsonIgnoreCondition.WhenWritingNull)] CSharpProjectOutput[]? GeneratedFiles=null);

// Explicit caller code task, separate from DATA and the embedded sample. This
// manifest is data: no MSBuild imports, package restore, commands or host paths.
internal sealed class CSharpProjectTask
{
    internal const string Manifest="cpc-project.json",Kind="CSHARP_LITERAL_EDIT_BUILD_RUN_TEST_V1";
    internal const string DataKind="CSHARP_LITERAL_EDIT_DATA_BUILD_RUN_TEST_V2",ResultDirectory="cpc-results";
    internal static bool IsKind(string? kind)=>kind is Kind or DataKind;
    internal const string OutputDirectory="cpc-output";
    internal static readonly string[] Outputs={"cpc-output/CpcProject.dll","cpc-output/run-result.json",
        "cpc-output/test-result.txt","cpc-output/stdout.txt","cpc-output/stderr.txt"};
    private static readonly UTF8Encoding Utf8=new(false,true);
    internal CSharpProjectDefinition Definition {get;}
    internal WorkspaceBundle Baseline {get;}
    internal string BaselineSHA256 {get;}
    internal CSharpProjectOutput[] GeneratedFiles=>Definition.GeneratedFiles??Array.Empty<CSharpProjectOutput>();
    internal string[] ResultPaths=>Baseline.Files.Select(f=>f.Path).Concat(Outputs).Concat(GeneratedFiles.Select(f=>f.Path)).ToArray();
    private CSharpProjectTask(CSharpProjectDefinition definition,WorkspaceBundle baseline,string digest)
    {Definition=definition;Baseline=baseline;BaselineSHA256=digest;}
    internal static CSharpProjectTask Parse(byte[] bytes)
    {
        var baseline=WorkspaceBundle.Parse(bytes);
        if(baseline.BaseSHA256 is not null || baseline.Files.Length is <2 or >128 || baseline.Files.Sum(f=>(long)f.Content.Length)>6*1024*1024 || baseline.Files.Any(f=>
            f.Path.Equals(OutputDirectory,StringComparison.OrdinalIgnoreCase) || f.Path.StartsWith(OutputDirectory+"/",StringComparison.OrdinalIgnoreCase)))
            throw new InvalidDataException("Caller project baseline/output inventory refused");
        var manifests=baseline.Files.Where(f=>f.Path==Manifest).ToArray();
        if(manifests.Length!=1 || manifests[0].Content.Length is <1 or >65536)throw new InvalidDataException("Explicit CSharp project manifest required");
        using var json=JsonDocument.Parse(manifests[0].Content,new JsonDocumentOptions{MaxDepth=5});
        var schema=json.RootElement.GetProperty("SchemaVersion").GetInt32();
        var fields=new[]{"SchemaVersion","Kind","Sources","Edits","EntryType","TestType","ExpectedTests"};
        Fields(json.RootElement,schema==2?fields.Concat(new[]{"DataFiles","GeneratedFiles"}).ToArray():fields);
        if(json.RootElement.GetProperty("Edits").ValueKind!=JsonValueKind.Array || json.RootElement.GetProperty("Edits").GetArrayLength()>32)
            throw new InvalidDataException("Caller project edit bounds");
        foreach(var edit in json.RootElement.GetProperty("Edits").EnumerateArray())Fields(edit,"Path","Before","After");
        if(schema==2)
        {
            var generated=json.RootElement.GetProperty("GeneratedFiles");
            if(generated.ValueKind!=JsonValueKind.Array || generated.GetArrayLength()>32)throw new InvalidDataException("Caller generated file bounds");
            foreach(var file in generated.EnumerateArray())Fields(file,"Path","MaxBytes");
        }
        var definition=JsonSerializer.Deserialize<CSharpProjectDefinition>(manifests[0].Content)??throw new InvalidDataException("Caller project manifest missing");
        if(!(definition.SchemaVersion==1 && definition.Kind==Kind || definition.SchemaVersion==2 && definition.Kind==DataKind) ||
            definition.Sources is null || definition.Sources.Length is <1 or >32 ||
            definition.Edits is null || definition.Edits.Length is <1 or >32 || definition.ExpectedTests is <1 or >256 ||
            !TypeName(definition.EntryType) || !TypeName(definition.TestType) || definition.EntryType==definition.TestType)
            throw new InvalidDataException("Caller project task contract refused");
        var names=new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach(var path in definition.Sources)
        {
            if(WorkspaceBundle.Relative(path)!=path || !path.EndsWith(".cs",StringComparison.Ordinal) || !names.Add(path) ||
                !baseline.Files.Any(f=>f.Path==path))throw new InvalidDataException("Caller source inventory refused");
            _=Utf8.GetString(baseline.Files.Single(f=>f.Path==path).Content);
        }
        if(schema==2)
        {
            if(definition.DataFiles is null || definition.DataFiles.Length>64 || definition.GeneratedFiles is null || definition.GeneratedFiles.Length>32)
                throw new InvalidDataException("Explicit data/result selection required");
            foreach(var path in definition.DataFiles)
                if(WorkspaceBundle.Relative(path)!=path || !names.Add(path) || !baseline.Files.Any(f=>f.Path==path))
                    throw new InvalidDataException("Caller data inventory refused");
            if(!names.Add(Manifest) || baseline.Files.Length!=names.Count || baseline.Files.Any(f=>!names.Contains(f.Path)))
                throw new InvalidDataException("Only declared sources and data can enter the project");
            foreach(var output in definition.GeneratedFiles)
                if(output is null || WorkspaceBundle.Relative(output.Path)!=output.Path || !output.Path.StartsWith(ResultDirectory+"/",StringComparison.Ordinal) ||
                    output.MaxBytes is <1 or >WorkspaceBundle.MaxFileBytes || !names.Add(output.Path))
                    throw new InvalidDataException("Caller generated file declaration refused");
            if(baseline.Files.Any(f=>f.Path.Equals(ResultDirectory,StringComparison.OrdinalIgnoreCase) || f.Path.StartsWith(ResultDirectory+"/",StringComparison.OrdinalIgnoreCase)) ||
                baseline.Files.Sum(f=>(long)f.Content.Length)+definition.GeneratedFiles.Sum(f=>(long)f.MaxBytes)+WorkspaceBundle.MaxFileBytes+65536>WorkspaceBundle.MaxTotalBytes)
                throw new InvalidDataException("Caller generated file budget or fresh namespace refused");
            // Reuse canonical directory/file collision validation before work.
            _=WorkspaceBundle.Create(names.Concat(Outputs).Select(p=>(p,Array.Empty<byte>())));
        }
        foreach(var edit in definition.Edits)
            if(edit is null || !definition.Sources.Contains(edit.Path,StringComparer.Ordinal) || edit.Before is null || edit.Before.Length is <1 or >16384 ||
                edit.After is null || edit.After.Length>16384)throw new InvalidDataException("Caller literal edit refused");
        var task=new CSharpProjectTask(definition,baseline,WorkspaceBundle.Hash(bytes));
        _=task.ModifiedFiles();return task;
    }
    private static bool TypeName(string? name)=>name is {Length:>0 and <=256} && name.Split('.').Length<=12 && name.Split('.').All(part=>
        part.Length is >0 and <=80 && (char.IsAsciiLetter(part[0]) || part[0]=='_') && part.All(c=>char.IsAsciiLetterOrDigit(c) || c=='_'));
    internal WorkspaceFile[] ModifiedFiles()
    {
        var files=Baseline.Files.ToDictionary(f=>f.Path,StringComparer.Ordinal);
        foreach(var edit in Definition.Edits)
        {
            var text=Utf8.GetString(files[edit.Path].Content);var index=text.IndexOf(edit.Before,StringComparison.Ordinal);
            if(index<0 || text.IndexOf(edit.Before,index+1,StringComparison.Ordinal)>=0)throw new InvalidDataException("Caller edit must match exactly once");
            var bytes=Utf8.GetBytes(string.Concat(text.AsSpan(0,index),edit.After,text.AsSpan(index+edit.Before.Length)));
            if(bytes.Length>WorkspaceBundle.MaxFileBytes)throw new InvalidDataException("Caller edited source bounds");
            files[edit.Path]=new(edit.Path,bytes,WorkspaceBundle.Hash(bytes));
        }
        return Baseline.Files.Select(f=>files[f.Path]).ToArray();
    }
    internal void VerifyResult(byte[] bytes)
    {
        var result=WorkspaceBundle.Parse(bytes);
        if(result.BaseSHA256!=BaselineSHA256 || result.Files.Length!=ResultPaths.Length ||
            !new HashSet<string>(result.Files.Select(f=>f.Path),StringComparer.Ordinal).SetEquals(ResultPaths))
            throw new InvalidDataException("Caller project result inventory differs");
        foreach(var expected in ModifiedFiles())
            if(!result.Files.Single(f=>f.Path==expected.Path).Content.AsSpan().SequenceEqual(expected.Content))throw new InvalidDataException("Caller project result source edit differs");
        byte[] File(string path)=>result.Files.Single(f=>f.Path==path).Content;
        var assembly=File(Outputs[0]);if(assembly.Length is <512 or >1024*1024)throw new InvalidDataException("Caller project assembly bounds");
        using(var memory=new MemoryStream(assembly,false))using(var pe=new System.Reflection.PortableExecutable.PEReader(memory))
            if(!pe.HasMetadata)throw new InvalidDataException("Caller project assembly metadata missing");
        using(var json=JsonDocument.Parse(File(Outputs[1])))
        {
            var r=json.RootElement;Fields(r,"SchemaVersion","ExitCode","TestsPassed");
            if(r.GetProperty("SchemaVersion").GetInt32()!=1 || r.GetProperty("ExitCode").GetInt32()!=0 || r.GetProperty("TestsPassed").GetInt32()!=Definition.ExpectedTests)
                throw new InvalidDataException("Caller project run/tests differ");
        }
        if(!File(Outputs[2]).AsSpan().SequenceEqual(Encoding.ASCII.GetBytes(Definition.ExpectedTests.ToString(System.Globalization.CultureInfo.InvariantCulture))))
            throw new InvalidDataException("Caller project test count differs");
        foreach(var path in Outputs.Skip(3)){var output=File(path);if(output.Length>16384)throw new InvalidDataException("Caller project text output bounds");_=Utf8.GetString(output);}
        foreach(var output in GeneratedFiles)
            if(File(output.Path).Length>output.MaxBytes)throw new InvalidDataException("Caller generated file exceeds reviewed size limit");
    }
    private static void Fields(JsonElement value,params string[] expected)
    {
        if(value.ValueKind!=JsonValueKind.Object)throw new InvalidDataException("Caller project object required");
        var actual=value.EnumerateObject().Select(p=>p.Name).ToArray();
        if(actual.Length!=expected.Length || !actual.OrderBy(n=>n,StringComparer.Ordinal).SequenceEqual(expected.OrderBy(n=>n,StringComparer.Ordinal)))
            throw new InvalidDataException("Caller project fields differ");
    }
}
