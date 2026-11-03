using System.Reflection;
using System.Runtime.ExceptionServices;
using System.Text;
using System.Text.Json;
using ClaudeCodeProtection.Workspaces;
using ProtectionCenter;

internal static class ProjectTaskEditCases
{
    private static WorkspaceFile Source(string path,string text)=>new(path,Encoding.UTF8.GetBytes(text),"");
    private static CSharpProjectDefinition Definition()=>new(1,CSharpProjectTask.Kind,new[]{"Entry.cs","Checks.cs"},
        new[]{new CSharpProjectEdit("Entry.cs","return -1;","return 0;")},"Demo.Entry","Demo.Checks",1);
    internal static int Run(string root)
    {
        var checks=0;
        void Require(bool value,string reason){if(!value)throw new InvalidDataException(reason);checks++;}
        void Refuse(Action action){try{action();}catch(InvalidDataException){checks++;return;}throw new InvalidDataException("Invalid task edit accepted");}
        var definition=Definition();
        var original=CallerProjectSession.FromRevision(new[]{Source("Entry.cs","namespace Demo; public static class Entry {public static int Run(){return -1;}}"),
            Source("Checks.cs","namespace Demo; public static class Checks {public static int Run(){return 1;}}"),Source("README.md","OWN_REVIEWED_COMPANION")},definition);
        var saved=Path.Combine(root,"edit-original-task.json");original.SaveBundle(saved);
        var imported=CallerProjectSession.OpenBundle(saved);var draft=imported.EditTask();
        Require(draft.EditsExistingTask && draft.PreviousResultSHA256 is null && draft.SourceTaskSHA256==imported.InputSHA256,"draft needs no result/completion authority");
        Require(draft.ReadSource("Entry.cs").Contains("return -1;") && draft.InitialEdits.SequenceEqual(definition.Edits),"draft starts with original source and existing edit plan");
        File.WriteAllText(saved,"OWN_LATER_PATH_REPLACEMENT");
        var exposed=draft.InitialEdits;exposed[0]=new("Checks.cs","return 1;","return 99;");
        var sourceNames=draft.Sources;sourceNames[0]="unselected.cs";
        Require(draft.InitialEdits.SequenceEqual(definition.Edits) && draft.Sources.SequenceEqual(definition.Sources),"returned arrays cannot mutate draft");
        var unchanged=draft.Prepare(draft.InitialEdits);
        Require(unchanged.InputSHA256==original.InputSHA256,"untouched canonical task preserves snapshot despite saved-path replacement");
        var edits=new[]{new CSharpProjectEdit("Entry.cs","return -1;","return 0;"),new CSharpProjectEdit("Checks.cs","return 1;","return 2;")};
        var edited=draft.Prepare(edits,2);var output=Path.Combine(root,"edited-task.json");edited.SaveBundle(output);
        var task=CSharpProjectTask.Parse(WorkspaceFiles.ReadBundle(output));
        Require(task.Baseline.Files.Single(f=>f.Path=="README.md").Content.AsSpan().SequenceEqual("OWN_REVIEWED_COMPANION"u8),"V1 companion file retained");
        Require(task.Definition.Edits.SequenceEqual(edits) && task.Definition.ExpectedTests==2 && edited.InputSHA256!=original.InputSHA256,"multi-file edits and new test count reviewed under new digest");
        Require(Encoding.UTF8.GetString(task.Baseline.Files.Single(f=>f.Path=="Entry.cs").Content).Contains("return -1;") &&
            Encoding.UTF8.GetString(task.ModifiedFiles().Single(f=>f.Path=="Entry.cs").Content).Contains("return 0;"),"editing changes plan rather than silently applying old edits to baseline");
        Require(draft.Prepare(draft.InitialEdits,entryType:"Demo.NewEntry",testType:"Demo.NewChecks").ReviewText.Contains("Demo.NewEntry.Run()"),"explicit entry/test corrections reviewed");
        Refuse(()=>draft.Prepare(edits,entryType:"Demo.Entry;command"));
        Refuse(()=>draft.Prepare(edits,testType:"Demo.Entry"));
        Refuse(()=>draft.Prepare(edits,257));
        Refuse(()=>draft.Prepare(Array.Empty<CSharpProjectEdit>()));
        Refuse(()=>draft.Prepare(new[]{new CSharpProjectEdit("Entry.cs","absent","replacement")}));
        Refuse(()=>draft.ReadSource("README.md"));
        var dataDefinition=definition with {SchemaVersion=2,Kind=CSharpProjectTask.DataKind,DataFiles=new[]{"input.bin"},GeneratedFiles=new[]{new CSharpProjectOutput("cpc-results/report.json",128)}};
        var data=CallerProjectSession.FromRevision(new[]{Source("Entry.cs","namespace Demo; public static class Entry {public static int Run(){return -1;}}"),
            Source("Checks.cs","namespace Demo; public static class Checks {public static int Run(){return 1;}}"),new WorkspaceFile("input.bin",new byte[]{0,128,255},"")},dataDefinition);
        var dataDraft=data.EditTask();var limits=dataDraft.GeneratedFiles;limits[0]=new("cpc-results/report.json",1048576);
        var next=dataDraft.Prepare(edits,2);var dataPath=Path.Combine(root,"edited-data-task.json");next.SaveBundle(dataPath);
        var parsed=CSharpProjectTask.Parse(WorkspaceFiles.ReadBundle(dataPath));
        Require(parsed.Definition.SchemaVersion==2 && parsed.GeneratedFiles.Single().MaxBytes==128 && parsed.Definition.DataFiles!.SequenceEqual(new[]{"input.bin"}),"V2 original data selection and output limit retained");
        Require(parsed.Baseline.Files.Single(f=>f.Path=="input.bin").Content.AsSpan().SequenceEqual(new byte[]{0,128,255}) && parsed.Baseline.Files.Length==4,"binary snapshot retained without result/generated files");
        Refuse(()=>dataDraft.Prepare(new[]{new CSharpProjectEdit("input.bin","x","y")}));
        Require(dataDraft.Prepare(dataDraft.InitialEdits).InputSHA256==data.InputSHA256 && original.InputSHA256==imported.InputSHA256,"editing/cancelling does not alter old task object");
        var second=next.EditTask();Require(second.InitialEdits.SequenceEqual(edits) && second.Prepare(second.InitialEdits).InputSHA256==next.InputSHA256,"repeated edit reopens latest plan without applying it twice");
        return checks;
    }
    internal static object RunOrdinaryCompiler()
    {
        WorkspaceFiles.RequireOrdinaryUser();
        var library=Assembly.LoadFrom(Path.Combine(AppContext.BaseDirectory,"ProtectionLifecycle.dll"));
        var execute=library.GetType("ProtectionLifecycle.CallerCSharpProject",true)!.GetMethod("BuildAndRun",BindingFlags.Static|BindingFlags.NonPublic)!;
        void Build(string folder,byte[] input)
        {try{execute.Invoke(null,new object[]{Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),"ClaudeCodeProtection-PowerShell-7.4.22"),folder,input});}
         catch(TargetInvocationException e)when(e.InnerException is not null){ExceptionDispatchInfo.Capture(e.InnerException).Throw();throw;}}
        var root=Path.Combine(Path.GetTempPath(),"cpc-edit-compile-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(root);
        var files=new[]{Source("Entry.cs", """using System.IO; namespace Demo; public static class Entry {public static int Run(){var value=System.IO.File.ReadAllText("data/value.txt");if(value!="7")throw new System.Exception();Directory.CreateDirectory("cpc-results");System.IO.File.WriteAllText("cpc-results/summary.txt",value);return -1;}}"""),
            Source("Checks.cs","namespace Demo; public static class Checks {public static int Run(){return 1;}}"),Source("data/value.txt","7")};
        var definition=Definition() with {SchemaVersion=2,Kind=CSharpProjectTask.DataKind,Edits=new[]{new CSharpProjectEdit("Entry.cs","return -1;","return MissingValue;")},DataFiles=new[]{"data/value.txt"},GeneratedFiles=new[]{new CSharpProjectOutput("cpc-results/summary.txt",128)}};
        var failed=CallerProjectSession.FromRevision(files,definition);var inputPath=Path.Combine(root,"failed-input.json");failed.SaveBundle(inputPath);
        var badBytes=WorkspaceFiles.ReadBundle(inputPath);WorkspaceFiles.MaterializeNew(root,"failed-project",badBytes);
        var failedBeforeCwd=Environment.CurrentDirectory;var compileFailed=false;
        try{Build(Path.Combine(root,"failed-project"),badBytes);}catch(Exception error)when(error.GetType().FullName=="ClaudeCodeProtection.Workspaces.ProjectTaskException")
        {
            var failure=error.GetType().GetProperty("Failure",BindingFlags.Instance|BindingFlags.NonPublic|BindingFlags.Public)!.GetValue(error)!;
            compileFailed=(string)failure.GetType().GetProperty("Stage")!.GetValue(failure)! =="Compile";
        }
        if(!compileFailed || Environment.CurrentDirectory!=failedBeforeCwd)throw new InvalidDataException("Ordinary compile failure or CWD restoration unconfirmed");
        var draft=CallerProjectSession.OpenBundle(inputPath).EditTask();var queue=new ProjectEditQueue(draft.Sources);
        foreach(var edit in draft.InitialEdits)queue.Add(edit);
        queue.Update(0,new("Entry.cs","return -1;","return 0;"));queue.Add(new("Checks.cs","return 1;","return 2;"));
        var repaired=draft.Prepare(queue.Snapshot(),2);var repairedPath=Path.Combine(root,"repaired-input.json");repaired.SaveBundle(repairedPath);
        var repairedBytes=WorkspaceFiles.ReadBundle(repairedPath);WorkspaceFiles.MaterializeNew(root,"repaired-project",repairedBytes);
        Build(Path.Combine(root,"repaired-project"),repairedBytes);
        var result=WorkspaceFiles.SnapshotResult(root,"repaired-project",repairedBytes);var task=CSharpProjectTask.Parse(repairedBytes);task.VerifyResult(result);
        var output=Path.Combine(root,"exported");WorkspaceFiles.ExtractResultNew(output,repairedBytes,result);
        if(Environment.CurrentDirectory!=failedBeforeCwd || File.ReadAllText(Path.Combine(output,"cpc-results","summary.txt"))!="7" ||
            File.ReadAllText(Path.Combine(output,"data","value.txt"))!="7" || File.ReadAllText(Path.Combine(output,"cpc-output","test-result.txt"))!="2" ||
            !WorkspaceFiles.ReadBundle(inputPath).AsSpan().SequenceEqual(badBytes))throw new InvalidDataException("Ordinary edited-task result differs");
        return new{Status="ORDINARY_FAILED_TASK_EDIT_COMPILE_TEST_AND_RECOVER_PASSED",CompileFailureObserved=true,OriginalTaskUnchanged=true,
            RepairedInputSHA256=repaired.InputSHA256,Tests=2,Files=WorkspaceBundle.Parse(result).Files.Length,DataPreserved=true,GeneratedFileLimit=128,
            Fixture=root,ProtectedSession=false,UAC=false,NetworkUsed=false,ResultUsedAsCodeOutsideOwnCompiler=false};
    }
}
