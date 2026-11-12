using System.Buffers.Binary;
using System.Diagnostics;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using ClaudeCodeProtection.Workspaces;

namespace ProtectionLifecycle;

internal sealed partial class SessionGitToolchain
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
}
