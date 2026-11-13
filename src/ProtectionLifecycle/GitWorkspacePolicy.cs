using System.Diagnostics;
using System.Text;
using ClaudeCodeProtection.Workspaces;

namespace ProtectionLifecycle;

internal static class GitWorkspacePolicy
{
    internal static string GitControlDirectory(string workspace)=>WindowsPathSeal.Child(workspace,"git-control");
    internal static string GitControlPath(string workspace,string leaf)
    {
        if(leaf is not ("empty-git-config" or "empty-git-hooks" or "empty-git-template" or "git-selected-paths.bin"))
            throw new InvalidDataException("Fixed Git control leaf required");
        return WindowsPathSeal.Child(GitControlDirectory(workspace),leaf);
    }
    internal static void AssertGitControlReady(string workspace,bool hasPathspec)
    {
        var root=GitControlDirectory(workspace);
        using(var held=WindowsPathSeal.Open(root,true,false))
        {
            var actual=WindowsPathSeal.EnumerateNames(held,root,8);
            var expected=hasPathspec
                ?new[]{"empty-git-config","empty-git-hooks","empty-git-template","git-selected-paths.bin"}
                :new[]{"empty-git-config","empty-git-hooks","empty-git-template"};
            if(actual.Length!=expected.Length || actual.Any(name=>!expected.Contains(name,StringComparer.Ordinal)))
                throw WfpNative.Contract("GitControlInventoryMismatch");
        }
        foreach(var leaf in new[]{"empty-git-hooks","empty-git-template"})
        {
            var path=GitControlPath(workspace,leaf);
            using var directory=WindowsPathSeal.Open(path,true,false);
            if(WindowsPathSeal.EnumerateNames(directory,path,1).Length!=0)
                throw WfpNative.Contract("GitControlDirectoryNotEmpty");
        }
        var config=GitControlPath(workspace,"empty-git-config");
        using(var file=new FileStream(WindowsPathSeal.Open(config,false,true),FileAccess.Read,64,false))
            if(file.Length!=0)throw WfpNative.Contract("GitGlobalConfigNotEmpty");
        if(hasPathspec)
        {
            using var file=new FileStream(WindowsPathSeal.Open(GitControlPath(workspace,"git-selected-paths.bin"),false,true),FileAccess.Read,128*1024,false);
            if(file.Length is <1 or >128*1024)throw WfpNative.Contract("GitPathspecBounds");
        }
    }
    internal static string[][] WorkflowCommands(ResourceProbePlan plan,string workspace,WorkspaceGitPlan workflow)
    {
        workflow.Validate();var repo=WindowsPathSeal.Child(workspace,"git-project");
        var template=GitControlPath(workspace,"empty-git-template");
        var selection=GitControlPath(workspace,"git-selected-paths.bin");
        return new[]{
            new[]{"hash-object","--stdin"},
            new[]{"init","--quiet","--initial-branch=main","--object-format=sha1","--template="+template,repo},
            new[]{"--literal-pathspecs","-C",repo,"add","--force","--pathspec-from-file="+selection,"--pathspec-file-nul"},
            new[]{"-C",repo,"diff","--cached","--check","--no-ext-diff","--no-textconv","--no-color"},
            new[]{"-C",repo,"diff","--cached","--numstat","-z","--no-ext-diff","--no-textconv","--no-color"},
            new[]{"-C",repo,"commit","--quiet","--no-gpg-sign","-m",workflow.CommitMessage},
            new[]{"-C",repo,"log","-1","--format=%H%x00%T%x00%an%x00%ae%x00%at%x00%s","HEAD"},
            new[]{"-C",repo,"status","--porcelain=v2","-z","--untracked-files=all"},
            new[]{"-C",repo,"fsck","--full","--strict","--no-reflogs","--no-progress"},
            new[]{"hash-object","--",plan.Fixture},
            new[]{"hash-object","--",WindowsPathSeal.Child(workspace,"all-packages-only.json")}
        };
    }
    internal static bool SelectedPathspecMatches(string workspace,WorkspaceBundle project)
    {
        var path=GitControlPath(workspace,"git-selected-paths.bin");
        var expected=Encoding.ASCII.GetBytes(string.Join('\0',project.Files.Select(f=>f.Path))+"\0");
        using var file=new FileStream(WindowsPathSeal.OpenReadUnderWriteLease(path),FileAccess.Read,4096,false);
        if(file.Length!=expected.Length)return false;
        var actual=new byte[expected.Length];file.ReadExactly(actual);return actual.AsSpan().SequenceEqual(expected);
    }
    internal static bool WorkflowCommandAllowed(ResourceProbePlan plan,string workspace,string[] tail)
    {
        var project=WorkspaceBundle.Parse(plan.ProjectBundle);var workflow=project.GitPlan;
        if(workflow is null)return false;
        AssertGitControlReady(workspace,true);
        var commands=WorkflowCommands(plan,workspace,workflow);
        if(!commands.Any(command=>command.SequenceEqual(tail)))return false;
        return !commands[2].SequenceEqual(tail) || SelectedPathspecMatches(workspace,project);
    }
    internal static bool WorkflowSequenceMatches(ResourceProbePlan plan,string workspace,int sequence,string[] arguments)
    {
        var project=WorkspaceBundle.Parse(plan.ProjectBundle);var workflow=project.GitPlan;
        if(workflow is null)return true;
        var prefix=StartWorkflow(workspace,plan.GitDirectory,workflow).ArgumentList.ToArray();
        if(arguments.Length<prefix.Length || !arguments.Take(prefix.Length).SequenceEqual(prefix))return false;
        var tail=arguments.Skip(prefix.Length).ToArray();var commands=WorkflowCommands(plan,workspace,workflow);
        return sequence>=1 && sequence<=commands.Length && commands[sequence-1].SequenceEqual(tail) &&
            WorkflowCommandAllowed(plan,workspace,tail);
    }
    
    internal static ProcessStartInfo Start(string workspace,string directory,params string[] arguments)
    {
        var start=new ProcessStartInfo(WindowsPathSeal.Child(directory,"git.exe")){UseShellExecute=false,CreateNoWindow=true,WorkingDirectory=workspace,
            RedirectStandardInput=true,RedirectStandardOutput=true,RedirectStandardError=true,StandardInputEncoding=new UTF8Encoding(false),StandardOutputEncoding=new UTF8Encoding(false),StandardErrorEncoding=new UTF8Encoding(false)};
        start.Environment.Clear();
        foreach(var name in new[]{"SystemRoot","windir","SystemDrive","PROCESSOR_ARCHITECTURE"})
        {var value=Environment.GetEnvironmentVariable(name);if(value is not null)start.Environment[name]=value;}
        foreach(var name in new[]{"TEMP","TMP","HOME","USERPROFILE","LOCALAPPDATA","XDG_CONFIG_HOME"})start.Environment[name]=workspace;
        start.Environment["PATH"]=directory+";"+Environment.SystemDirectory;
        start.Environment["GIT_EXEC_PATH"]=directory;start.Environment["GIT_CONFIG_NOSYSTEM"]="1";start.Environment["GIT_ATTR_NOSYSTEM"]="1";
        start.Environment["GIT_CONFIG_GLOBAL"]=GitControlPath(workspace,"empty-git-config");start.Environment["GIT_CONFIG_COUNT"]="0";
        start.Environment["GIT_CEILING_DIRECTORIES"]=workspace;start.Environment["GIT_DISCOVERY_ACROSS_FILESYSTEM"]="0";
        start.Environment["GIT_TERMINAL_PROMPT"]="0";start.Environment["GCM_INTERACTIVE"]="never";start.Environment["GIT_NO_LAZY_FETCH"]="1";
        foreach(var name in new[]{"GIT_AUTHOR_NAME","GIT_COMMITTER_NAME"})start.Environment[name]="CPC Qualification";
        foreach(var name in new[]{"GIT_AUTHOR_EMAIL","GIT_COMMITTER_EMAIL"})start.Environment[name]="offline@invalid.example";
        foreach(var name in new[]{"GIT_AUTHOR_DATE","GIT_COMMITTER_DATE"})start.Environment[name]="2026-10-28T00:00:00+00:00";
        start.Environment["LC_ALL"]="C";start.Environment["LANG"]="C";
        foreach(var arg in new[]{"--no-pager","-c","credential.helper=","-c","protocol.allow=never","-c","core.autocrlf=false","-c","core.whitespace=cr-at-eol","-c","core.filemode=false",
            "-c","core.fsmonitor=false","-c","maintenance.auto=false","-c","gc.auto=0","-c","commit.gpgsign=false","-c","i18n.commitEncoding=UTF-8",
            "-c","core.hooksPath="+GitControlPath(workspace,"empty-git-hooks"),"-c","safe.directory="+WindowsPathSeal.Child(workspace,"git-project")}.Concat(arguments))start.ArgumentList.Add(arg);
        return start;
    }
    internal static ProcessStartInfo StartWorkflow(string workspace,string directory,WorkspaceGitPlan workflow,params string[] arguments)
    {
        workflow.Validate();var start=Start(workspace,directory,arguments);
        foreach(var name in new[]{"GIT_AUTHOR_NAME","GIT_COMMITTER_NAME"})start.Environment[name]=WorkspaceGitPlan.AuthorName;
        foreach(var name in new[]{"GIT_AUTHOR_EMAIL","GIT_COMMITTER_EMAIL"})start.Environment[name]=WorkspaceGitPlan.AuthorEmail;
        foreach(var name in new[]{"GIT_AUTHOR_DATE","GIT_COMMITTER_DATE"})start.Environment[name]=workflow.CommitDateUtc;
        return start;
    }
}
