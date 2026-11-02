using System.Text;
using ClaudeCodeProtection.Workspaces;
using ProtectionCenter;

internal static class ProjectEditQueueCases
{
    internal static int Run(string fixture)
    {
        var checks=0;
        void Require(bool value,string reason){if(!value)throw new InvalidDataException(reason);checks++;}
        void Refuse(Action action,string reason){try{action();}catch(InvalidDataException){checks++;return;}throw new InvalidDataException("Accepted "+reason);}
        var sourceNames=new[]{"Entry.cs","Checks.cs"};var queue=new ProjectEditQueue(sourceNames);sourceNames[0]="foreign.cs";
        var implementation=new CSharpProjectEdit("Entry.cs","return -1;","return 0;");
        var test=new CSharpProjectEdit("Checks.cs","return 1;","return Entry.Run()==0 ? 1 : 0;");
        Require(!queue.IsPending(-1,new("Entry.cs","","")) && queue.IsPending(-1,implementation),"new editor draft cannot disappear silently");
        queue.Add(implementation);queue.Add(test);
        Require(!queue.IsPending(1,test) && queue.IsPending(1,test with {After="changed"}) && queue.IsPending(0,test),"only unchanged selected editor draft is saved");
        var snapshot=queue.Snapshot();snapshot[0]=implementation with {Path="foreign.cs"};
        Require(queue.Snapshot()[0]==implementation,"mutating returned array cannot replace reviewed edit");
        Refuse(()=>queue.Update(0,implementation with {Path="foreign.cs"}),"foreign source update");
        Require(queue.Snapshot()[0]==implementation,"invalid update is atomic");
        Refuse(()=>queue.Add(implementation with {Path="entry.cs"}),"source case substitution");
        Refuse(()=>queue.Add(implementation with {Before=""}),"empty before text");
        Refuse(()=>queue.Add(implementation with {After=new string('x',16385)}),"oversized after text");
        Refuse(()=>queue.Move(0,-1),"reorder beyond beginning");
        Refuse(()=>queue.Move(0,2),"nonadjacent reorder");
        var folder=Path.Combine(fixture,"multi-edit-project");Directory.CreateDirectory(folder);
        File.WriteAllText(Path.Combine(folder,"Entry.cs"),"namespace Demo; public static class Entry {public static int Run(){return -1;}}");
        File.WriteAllText(Path.Combine(folder,"Checks.cs"),"namespace Demo; public static class Checks {public static int Run(){return 1;}}");
        CallerProjectSession Prepare(ProjectEditQueue edits)=>CallerProjectSession.Create(folder,new[]{"Entry.cs","Checks.cs"},edits.Snapshot(),"Demo.Entry","Demo.Checks",1);
        var prepared=Prepare(queue);var bundlePath=Path.Combine(fixture,"multi-edit-task.json");prepared.SaveBundle(bundlePath);
        var parsed=CSharpProjectTask.Parse(WorkspaceFiles.ReadBundle(bundlePath));
        Require(parsed.Definition.Edits.SequenceEqual(queue.Snapshot()) && prepared.ReviewText.Contains("修改 1：Entry.cs") && prepared.ReviewText.Contains("修改 2：Checks.cs"),"review and persisted task preserve both ordered edits");
        Require(Encoding.UTF8.GetString(parsed.ModifiedFiles().Single(f=>f.Path=="Entry.cs").Content).Contains("return 0;") &&
            Encoding.UTF8.GetString(parsed.ModifiedFiles().Single(f=>f.Path=="Checks.cs").Content).Contains("Entry.Run()==0 ? 1 : 0"),"implementation and test change in the same prepared task");
        Require(CallerProjectSession.OpenBundle(bundlePath).InputSHA256==prepared.InputSHA256,"multi-edit snapshot reopens without any execution");
        queue.Update(1,test with {After="return Entry.Run()!=0 ? 0 : 1;"});
        Require(Prepare(queue).InputSHA256!=prepared.InputSHA256 && parsed.Definition.Edits[1]==test,"editing draft changes next digest but not prior saved task");
        queue.Remove(1);Require(queue.Count==1 && queue.Snapshot()[0]==implementation,"remove only selected edit");
        Refuse(()=>queue.Remove(1),"stale selection");
        var sequence=new ProjectEditQueue(new[]{"Entry.cs","Checks.cs"});
        sequence.Add(implementation with {After="return 1;"});sequence.Add(implementation with {Before="return 1;"});
        Require(Prepare(sequence).ReviewText.Contains("2 项修改"),"same-file sequential edits accepted in declared order");
        Require(sequence.Move(1,-1)==0,"move returns selected edit new position");
        Refuse(()=>Prepare(sequence),"wrong sequential order cannot prepare task");
        sequence.Move(0,1);Require(Prepare(sequence).ReviewText.Contains("2 项修改"),"restoring order restores valid preparation");
        var bounded=new ProjectEditQueue(new[]{"Entry.cs"});for(var i=0;i<32;i++)bounded.Add(implementation);
        Refuse(()=>bounded.Add(implementation),"33rd edit");Require(bounded.Count==32,"refused append preserves maximum inventory");
        Refuse(()=>new ProjectEditQueue(new[]{"Entry.cs","entry.cs"}),"case-colliding sources");
        Refuse(()=>new ProjectEditQueue(new[]{"../Entry.cs"}),"source traversal");
        return checks;
    }
}
