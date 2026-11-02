using System.Text;
using System.Text.Json;
using ClaudeCodeProtection.Workspaces;

namespace ProtectionCenter;

internal sealed record CallerProjectRun(string Directory,string InputPath,string ResultPath);

// Ordinary UI data preparation. The actual execution still belongs solely to
// the current installed daily -> original elevated Broker/Job/LPAC chain.
internal sealed class CallerProjectSession
{
    private readonly byte[] input;
    private readonly CSharpProjectTask task;
    internal string InputSHA256=>task.BaselineSHA256;
    internal int ExpectedTests=>task.Definition.ExpectedTests;
    internal string ReviewText {get;}
    private CallerProjectSession(byte[] input)
    {
        this.input=input;task=CSharpProjectTask.Parse(input);
        var text=new StringBuilder();
        text.AppendLine($"项目已准备：{task.Definition.Sources.Length} 份源码，{task.Definition.Edits.Length} 项修改，预期 {ExpectedTests} 项测试。");
        text.AppendLine("开始开发会运行这份项目代码，需要你确认 Windows 权限提示。");
        text.AppendLine("原项目保留；本次结果写入你选择位置下的新目录。");
        text.AppendLine();
        foreach(var source in task.Definition.Sources)text.AppendLine("源码："+source);
        foreach(var data in task.Definition.DataFiles??Array.Empty<string>())text.AppendLine("数据："+data);
        foreach(var output in task.GeneratedFiles)text.AppendLine($"结果：{output.Path}（最多 {output.MaxBytes} 字节）");
        var editNumber=0;
        foreach(var edit in task.Definition.Edits)
        {
            text.AppendLine();text.AppendLine("修改 "+(++editNumber)+"："+edit.Path);
            text.AppendLine("原文字："+JsonSerializer.Serialize(edit.Before));text.AppendLine("新文字："+JsonSerializer.Serialize(edit.After));
        }
        text.AppendLine();text.AppendLine("运行："+task.Definition.EntryType+".Run()");text.AppendLine("测试："+task.Definition.TestType+".Run()");
        text.AppendLine("输入指纹："+InputSHA256);ReviewText=text.ToString();
    }
    internal static CallerProjectSession OpenBundle(string path)
    {WorkspaceFiles.RequireOrdinaryUser();WorkspaceFiles.RequireExternalProjectPath(path);return new(WorkspaceFiles.ReadBundle(path));}
    internal static CallerProjectSession Create(string directory,string[] sources,CSharpProjectEdit[] edits,string entryType,string testType,int expectedTests,
        string[]? dataFiles=null,CSharpProjectOutput[]? generatedFiles=null)
    {
        // Explicit selected files only: no recursive discovery, project-file
        // evaluation, restore, commands, or writes into the original project.
        WorkspaceFiles.RequireOrdinaryUser();
        if(sources.Length is <1 or >32 || sources.Any(p=>!p.EndsWith(".cs",StringComparison.Ordinal)))
            throw new InvalidDataException("Select one to 32 CSharp source files");
        var extended=dataFiles is not null || generatedFiles is not null;
        dataFiles=extended?dataFiles??Array.Empty<string>():null;generatedFiles=extended?generatedFiles??Array.Empty<CSharpProjectOutput>():null;
        if(dataFiles is {Length:>64} || generatedFiles is {Length:>32})throw new InvalidDataException("Project data/result count exceeds limit");
        var captured=WorkspaceBundle.Parse(WorkspaceFiles.Capture(directory,sources.Concat(dataFiles??Array.Empty<string>())));
        var definition=new CSharpProjectDefinition(extended?2:1,extended?CSharpProjectTask.DataKind:CSharpProjectTask.Kind,sources,edits,entryType,testType,expectedTests,dataFiles,generatedFiles);
        var bytes=WorkspaceBundle.Create(captured.Files.Select(f=>(f.Path,f.Content)).Append(
            (CSharpProjectTask.Manifest,JsonSerializer.SerializeToUtf8Bytes(definition)))).Serialize();
        return new(bytes);
    }
    // Result files are data. Verify the exact previous task before carrying only
    // its declared sources/data into a fresh baseline; never import its DLL or
    // generated outputs, and never reuse its completion/admission as permission.
    internal static CallerProjectRevision OpenRevision(string inputPath,string resultPath)
    {
        var previous=OpenBundle(inputPath);
        WorkspaceFiles.RequireExternalProjectPath(resultPath);
        return previous.CreateRevision(WorkspaceFiles.ReadBundle(resultPath));
    }
    internal CallerProjectRevision CreateRevision(byte[] result)=>new(task,result);
    internal static CallerProjectSession FromRevision(WorkspaceFile[] files,CSharpProjectDefinition definition)
    {
        WorkspaceFiles.RequireOrdinaryUser();
        return new(WorkspaceBundle.Create(files.Select(f=>(f.Path,f.Content)).Append(
            (CSharpProjectTask.Manifest,JsonSerializer.SerializeToUtf8Bytes(definition)))).Serialize());
    }
    internal void SaveBundle(string path)=>WorkspaceFiles.WriteBundleNew(path,input);
    internal static CallerProjectSession OpenFolder(string directory)
    {
        WorkspaceFiles.RequireOrdinaryUser();
        var first=WorkspaceBundle.Parse(WorkspaceFiles.Capture(directory,new[]{CSharpProjectTask.Manifest})).Files.Single().Content;
        if(first.Length>65536)throw new InvalidDataException("Project manifest bounds");
        using var json=JsonDocument.Parse(first,new JsonDocumentOptions{MaxDepth=5});
        var sources=json.RootElement.GetProperty("Sources");
        if(sources.ValueKind!=JsonValueKind.Array || sources.GetArrayLength() is <1 or >32)throw new InvalidDataException("Project source selection bounds");
        var selected=sources.EnumerateArray().Select(s=>WorkspaceBundle.Relative(s.GetString()??throw new InvalidDataException("Project source missing"))).ToArray();
        if(selected.Any(s=>!s.EndsWith(".cs",StringComparison.Ordinal)))throw new InvalidDataException("Only declared CSharp source files selected");
        var dataFiles=Array.Empty<string>();
        if(json.RootElement.GetProperty("SchemaVersion").GetInt32()==2)
        {
            var data=json.RootElement.GetProperty("DataFiles");
            if(data.ValueKind!=JsonValueKind.Array || data.GetArrayLength()>64)throw new InvalidDataException("Project data selection bounds");
            dataFiles=data.EnumerateArray().Select(s=>WorkspaceBundle.Relative(s.GetString()??throw new InvalidDataException("Project data path missing"))).ToArray();
        }
        var bytes=WorkspaceFiles.Capture(directory,selected.Concat(dataFiles).Append(CSharpProjectTask.Manifest));
        if(!WorkspaceBundle.Parse(bytes).Files.Single(f=>f.Path==CSharpProjectTask.Manifest).Content.AsSpan().SequenceEqual(first))
            throw new InvalidDataException("Project manifest changed during selection");
        return new(bytes);
    }
    internal CallerProjectRun PlanRun(string parent)
    {
        WorkspaceFiles.RequireExternalProjectPath(parent);
        var leaf="project-run-"+DateTime.UtcNow.ToString("yyyyMMdd-HHmmss")+"-"+Guid.NewGuid().ToString("N");
        var directory=Path.Combine(parent,leaf);var baseline=Path.Combine(directory,"input.bundle.json");
        return new(directory,baseline,Path.Combine(directory,"result.bundle.json"));
    }
    internal void WriteInput(CallerProjectRun run)
    {
        WorkspaceFiles.RequireOrdinaryUser();
        if(run.InputPath!=Path.Combine(run.Directory,"input.bundle.json") || run.ResultPath!=Path.Combine(run.Directory,"result.bundle.json"))throw new InvalidDataException("Project run paths differ");
        WorkspaceFiles.MaterializeNew(Path.GetDirectoryName(run.Directory)??throw new InvalidDataException("Project output parent missing"),Path.GetFileName(run.Directory),WorkspaceBundle.Create(Array.Empty<(string,byte[])>()).Serialize());
        WorkspaceFiles.WriteBundleNew(run.InputPath,input);
    }
    // Only consume the result returned by BackendClient's held installed
    // ordinary client. A disk JSON report alone never proves protected work.
    internal WorkspaceResultSession AcceptResult(CallerProjectRun run,BackendResult result)
    {
        if(result.ExitCode!=0 || result.Error.Length!=0 || result.Output.Length is <1 or >65536)throw new InvalidDataException("Project completion not confirmed");
        using var json=JsonDocument.Parse(result.Output,new JsonDocumentOptions{MaxDepth=5});var r=json.RootElement;
        HostPrivacyContract.Fields(r,"Status","SessionId","BaseSHA256","ResultSHA256","FileCount","Changes","OriginalProjectModified","ProjectCodeExecuted",
            "HostPrivacy","OwnerSealedBeforeCode","FormalAdmissionIssued","NetworkOpened","UACAutoConfirmed");
        var session=r.GetProperty("SessionId").GetString();
        if(session is not {Length:32} || session.Any(c=>c is not (>= '0' and <= '9' or >= 'a' and <= 'f')) ||
            r.GetProperty("Status").GetString()!="CALLER_CSHARP_PROJECT_RESULT_RECEIVED" || r.GetProperty("BaseSHA256").GetString()!=InputSHA256 ||
            !r.GetProperty("OwnerSealedBeforeCode").GetBoolean() || !r.GetProperty("ProjectCodeExecuted").GetBoolean() ||
            r.GetProperty("OriginalProjectModified").GetBoolean() || r.GetProperty("FormalAdmissionIssued").GetBoolean() ||
            r.GetProperty("NetworkOpened").GetBoolean() || r.GetProperty("UACAutoConfirmed").GetBoolean())throw new InvalidDataException("Project completion scope differs");
        _=HostPrivacyContract.Parse(r.GetProperty("HostPrivacy"),session,true);
        var bytes=WorkspaceFiles.ReadBundle(run.ResultPath);task.VerifyResult(bytes);
        if(WorkspaceBundle.Hash(bytes)!=r.GetProperty("ResultSHA256").GetString() || r.GetProperty("FileCount").GetInt32()!=task.ResultPaths.Length)
            throw new InvalidDataException("Project completion digest/inventory differs");
        var changes=r.GetProperty("Changes");foreach(var change in changes.EnumerateArray())HostPrivacyContract.Fields(change,"Path","Kind","BeforeSHA256","AfterSHA256");
        var reported=JsonSerializer.Deserialize<WorkspaceChange[]>(changes.GetRawText())??throw new InvalidDataException("Project changes missing");
        if(!reported.SequenceEqual(WorkspaceBundle.Compare(input,bytes)))throw new InvalidDataException("Project reported changes differ");
        return WorkspaceResultSession.FromSnapshots(input,bytes);
    }
    internal static string FailureMessage(BackendResult result)
    {
        var error=result.Error.TrimEnd('\r','\n');
        if(result.ExitCode==125 && (error=="Operation failed: Win32Exception; code=1223; stage=" || error=="Operation failed: Win32Exception; code=1223; stage=UAC_START"))
            return "Windows取消了启动请求，本次任务未确认完成。记录已保留；如需重新操作，请在新的权限提示中确认。";
        return "本次项目任务未确认完成（返回码"+result.ExitCode+"）。请保留运行目录；已有文件不会被自动覆盖或删除。";
    }
    internal string DescribeFailure(BackendResult result)
    {
        var fallback=FailureMessage(result);
        if(result.ExitCode is not (3 or 125) || result.Error.Length!=0 || result.Output.Length is <1 or >16384)return fallback;
        try
        {
            using var json=JsonDocument.Parse(result.Output,new JsonDocumentOptions{MaxDepth=5});var r=json.RootElement;
            HostPrivacyContract.Fields(r,"Status","SessionId","BaseSHA256","FailureStage","FailureKind","FailureCode","CreationEvidence","StopEvidence",
                "HostPrivacy","OwnerSealedBeforeCode","ProjectFailure","ResultReleased","AutomaticRetry");
            if(r.GetProperty("Status").GetString()!="CALLER_CSHARP_PROJECT_NOT_CONFIRMED" || r.GetProperty("BaseSHA256").GetString()!=InputSHA256 ||
                r.GetProperty("FailureStage").GetString()!="processing" || r.GetProperty("FailureKind").GetString()!="ProjectTaskFailed" ||
                !r.GetProperty("OwnerSealedBeforeCode").GetBoolean() || r.GetProperty("ResultReleased").GetBoolean() || r.GetProperty("AutomaticRetry").GetBoolean())return fallback;
            var session=r.GetProperty("SessionId").GetString()??"";
            _=HostPrivacyContract.Parse(r.GetProperty("HostPrivacy"),session,true);
            var failure=ProjectFailureContract.Parse(r.GetProperty("ProjectFailure"),task.Definition.Sources.Length);
            var text=new StringBuilder(failure.Stage switch {
                "Compile"=>"项目编译失败。请按错误码和源码位置检查代码。",
                "Entry"=>"项目运行或测试入口不符合要求，请检查公开 static int Run() 声明。",
                "Run"=>"项目运行失败或未返回0，请检查入口代码。",
                _=>"项目测试失败或通过项数不符合声明，请检查测试代码。"});
            foreach(var diagnostic in failure.Diagnostics)
                text.AppendLine().Append(diagnostic.Code).Append(diagnostic.SourceIndex is int index?
                    $"  {task.Definition.Sources[index]}：第{diagnostic.Line}行，第{diagnostic.Column}列":"  编译设置或引用");
            return text.AppendLine().Append("本次结果未导出；请保留运行目录，不会自动重试。").ToString();
        }
        catch(Exception error)when(error is JsonException or InvalidDataException or InvalidOperationException or KeyNotFoundException or FormatException){return fallback;}
    }
}

// Immutable ordinary-data continuation, including the original per-output limits.
internal sealed class CallerProjectRevision
{
    private readonly WorkspaceFile[] files;
    private readonly CSharpProjectDefinition definition;
    internal string PreviousResultSHA256 {get;}
    internal string[] Sources=>definition.Sources.ToArray();
    internal string[] DataFiles=>(definition.DataFiles??Array.Empty<string>()).ToArray();
    internal CSharpProjectOutput[] GeneratedFiles=>(definition.GeneratedFiles??Array.Empty<CSharpProjectOutput>()).ToArray();
    internal string EntryType=>definition.EntryType;
    internal string TestType=>definition.TestType;
    internal int ExpectedTests=>definition.ExpectedTests;
    internal CallerProjectRevision(CSharpProjectTask previous,byte[] result)
    {
        var snapshot=result.ToArray();previous.VerifyResult(snapshot);
        PreviousResultSHA256=WorkspaceBundle.Hash(snapshot);
        // Parse our own immutable manifest so no caller-owned arrays are retained.
        definition=JsonSerializer.Deserialize<CSharpProjectDefinition>(previous.Baseline.Files.Single(f=>f.Path==CSharpProjectTask.Manifest).Content)
            ??throw new InvalidDataException("Previous project definition missing");
        var names=definition.Sources.Concat(definition.DataFiles??Array.Empty<string>()).ToHashSet(StringComparer.Ordinal);
        files=WorkspaceBundle.Parse(snapshot).Files.Where(f=>names.Contains(f.Path)).ToArray();
    }
    internal string ReadSource(string path)
    {
        if(!definition.Sources.Contains(path,StringComparer.Ordinal))throw new InvalidDataException("Only declared source can be previewed");
        return new UTF8Encoding(false,true).GetString(files.Single(f=>f.Path==path).Content);
    }
    internal CallerProjectSession Prepare(CSharpProjectEdit[] edits,int? expectedTests=null)
        =>CallerProjectSession.FromRevision(files,definition with {Edits=edits,ExpectedTests=expectedTests??definition.ExpectedTests});
}
