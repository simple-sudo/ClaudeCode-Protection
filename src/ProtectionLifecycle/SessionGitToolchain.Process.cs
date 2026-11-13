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
internal static GitToolchainReport RunChild(ResourceProbePlan plan,string workspace)
    {
        bool hashMatched=false,committed=false,denied=false,allPackagesDenied=false;string? commit=null;int? denialExit=null,allPackagesExit=null;var stage="VERIFY_GIT_INPUTS";
        try
        {
            if(plan.GitAssetSetSHA256!=AssetSetSHA256)throw WfpNative.Contract("GitResourcePlanMismatch");
            foreach(var asset in Assets)
            {
                // The manager holds the ancestry and each complete asset.
                // This side performs ordinary file I/O, no privileged metadata.
                using var file=File.OpenRead(WindowsPathSeal.Child(plan.GitDirectory,asset.Name));
                if(file.Length is <1 or >16*1024*1024 || Convert.ToHexString(SHA256.HashData(file))!=asset.Hash)throw WfpNative.Contract("ChildGitAssetChanged");
            }
            var selectedProject=WorkspaceBundle.Parse(plan.ProjectBundle);
            if(selectedProject.GitPlan is { } workflow)return RunWorkflowChild(plan,workspace,selectedProject,workflow);
            GitWorkspacePolicy.AssertGitControlReady(workspace,false);
            stage="HASH_INPUT_WITH_INSPECTED_GIT";
            using(var process=AtomicChild.StartInheritedTool(GitWorkspacePolicy.Start(workspace,plan.GitDirectory,"hash-object","--stdin")))
            {
                var stdout=ResourceChildRunner.ReadBounded(process.StandardOutput);var stderr=ResourceChildRunner.ReadBounded(process.StandardError);
                Signal(workspace,"git-ready",plan.Nonce);
                var clock=Stopwatch.StartNew();
                while(!File.Exists(WindowsPathSeal.Child(workspace,"git-go.signal")))
                {
                    if(process.HasExited){RecordResult(workspace,Finish(process,stdout,stderr));throw WfpNative.Contract("GitExitedBeforeInputAdmission");}
                    if(clock.ElapsedMilliseconds>=8000)throw WfpNative.Contract("GitInspectionGateExpired");Thread.Sleep(20);
                }
                if(File.ReadAllText(WindowsPathSeal.Child(workspace,"git-go.txt"))!=plan.Nonce)throw WfpNative.Contract("GitGateBindingMismatch");
                process.StandardInput.Write(Encoding.UTF8.GetString(plan.Input));process.StandardInput.Close();
                var result=Finish(process,stdout,stderr);
                RecordResult(workspace,result);Require(result);
                hashMatched=result.Exit==0 && result.Out.Trim()==BlobId(plan.Input) && result.Error.Length==0;
                if(!hashMatched)throw WfpNative.Contract("GitInputHashMismatch");
            }
            var repo=WindowsPathSeal.Child(workspace,"git-project");
            var template=GitWorkspacePolicy.GitControlPath(workspace,"empty-git-template");
            var project=WorkspaceBundle.Parse(plan.ProjectBundle);
            foreach(var file in project.Files)
                if(!File.ReadAllBytes(WindowsPathSeal.Child(repo,file.Path)).AsSpan().SequenceEqual(file.Content))throw WfpNative.Contract("GitProjectInputChanged");
            stage="GIT_INIT";Require(Run(workspace,plan.GitDirectory,"init","--quiet","--initial-branch=qualification","--template="+template,repo));
            // Highest-precedence info attributes override project-controlled
            // transformations. Data processing preserves exact selected bytes,
            // independent of .gitattributes or .gitignore in the source bundle.
            var info=WindowsPathSeal.Child(repo,".git/info");Directory.CreateDirectory(info);
            File.WriteAllText(WindowsPathSeal.Child(info,"attributes"),"* -text -filter -ident -working-tree-encoding !diff !whitespace\n",new UTF8Encoding(false));
            // NUL pathspec input avoids Windows command-line length limits
            // for a real multi-file project. Validated ASCII names cannot
            // contain NUL or Git pathspec magic; no expansion is performed.
            var selection=WindowsPathSeal.Child(WindowsPathSeal.Child(repo,".git"),"cpc-selected-paths.bin");
            File.WriteAllBytes(selection,Encoding.ASCII.GetBytes(string.Join('\0',project.Files.Select(f=>f.Path))+"\0"));
            stage="GIT_ADD";Require(Run(workspace,plan.GitDirectory,"--literal-pathspecs","-C",repo,"add","--force","--pathspec-from-file="+selection,"--pathspec-file-nul"));
            stage="GIT_COMMIT";Require(Run(workspace,plan.GitDirectory,"-C",repo,"commit","--quiet","--no-gpg-sign","-m",CommitMessage));
            stage="READ_COMMIT";var head=Run(workspace,plan.GitDirectory,"-C",repo,"rev-parse","--verify","HEAD");Require(head);commit=head.Out.Trim();
            if(!IsObjectId(commit))throw WfpNative.Contract("GitHeadMissing");
            // The trusted owner verifies every committed blob and complete
            // tree below. Text-decoding `git show` cannot prove binary data.
            committed=true;
            stage="GIT_PRIVATE_FIXTURE_DENIAL";var negative=Run(workspace,plan.GitDirectory,"hash-object","--",plan.Fixture);denialExit=negative.Exit;
            denied=negative.Exit==128 && negative.Out.Length==0 && negative.Error.TrimEnd().EndsWith(": Permission denied",StringComparison.Ordinal);
            if(!denied)throw WfpNative.Contract("GitPrivateFixtureDenialNotConfirmed");
            stage="GIT_ALL_PACKAGES_FIXTURE_DENIAL";var aap=Run(workspace,plan.GitDirectory,"hash-object","--",WindowsPathSeal.Child(workspace,"all-packages-only.json"));allPackagesExit=aap.Exit;
            allPackagesDenied=aap.Exit==128 && aap.Out.Length==0 && aap.Error.TrimEnd().EndsWith(": Permission denied",StringComparison.Ordinal);
            if(!allPackagesDenied)throw WfpNative.Contract("GitAllPackagesFixtureDenialNotConfirmed");
            return new(hashMatched,committed,commit,denied,denialExit,allPackagesDenied,allPackagesExit,null,null,null);
        }
        catch(Exception ex){return new(hashMatched,committed,commit,denied,denialExit,allPackagesDenied,allPackagesExit,stage+(ex.Data["Stage"] is string nativeStage?"/"+nativeStage:""),ex.GetType().Name,ex is System.ComponentModel.Win32Exception native?native.NativeErrorCode:ex.HResult);}
    }
    private static GitToolchainReport RunWorkflowChild(ResourceProbePlan plan,string workspace,WorkspaceBundle project,WorkspaceGitPlan workflow)
    {
        bool hashMatched=false,committed=false,denied=false,allPackagesDenied=false;string? commitId=null;
        int? denialExit=null,allPackagesExit=null;var stage="VERIFY_GIT_WORKFLOW_INPUT";
        try
        {
            GitWorkspacePolicy.AssertGitControlReady(workspace,true);
            var commands=GitWorkspacePolicy.WorkflowCommands(plan,workspace,workflow);
            stage="HASH_INPUT_WITH_INSPECTED_GIT";
            using(var process=AtomicChild.StartInheritedTool(GitWorkspacePolicy.StartWorkflow(workspace,plan.GitDirectory,workflow,commands[0])))
            {
                var stdout=ReadBounded(process.StandardOutput,4096);var stderr=ReadBounded(process.StandardError,4096);
                Signal(workspace,"git-ready",plan.Nonce);var clock=Stopwatch.StartNew();
                while(!File.Exists(WindowsPathSeal.Child(workspace,"git-go.signal")))
                {
                    if(process.HasExited){RecordResult(workspace,Finish(process,stdout,stderr));throw WfpNative.Contract("GitExitedBeforeInputAdmission");}
                    if(clock.ElapsedMilliseconds>=8000)throw WfpNative.Contract("GitInspectionGateExpired");Thread.Sleep(20);
                }
                if(File.ReadAllText(WindowsPathSeal.Child(workspace,"git-go.txt"))!=plan.Nonce)throw WfpNative.Contract("GitGateBindingMismatch");
                process.StandardInput.Write(Encoding.UTF8.GetString(plan.Input));process.StandardInput.Close();
                var result=Finish(process,stdout,stderr);RecordResult(workspace,result);Require(result);
                hashMatched=result.Exit==0 && result.Out.Trim()==BlobId(plan.Input) && result.Error.Length==0;
                if(!hashMatched)throw WfpNative.Contract("GitInputHashMismatch");
            }
            var repo=WindowsPathSeal.Child(workspace,"git-project");
            foreach(var file in project.Files)
                if(!File.ReadAllBytes(WindowsPathSeal.Child(repo,file.Path)).AsSpan().SequenceEqual(file.Content))
                    throw WfpNative.Contract("GitProjectInputChanged");
            if(!GitWorkspacePolicy.SelectedPathspecMatches(workspace,project))throw WfpNative.Contract("GitPathspecInputMismatch");
            stage="GIT_INIT";RequireWorkflow(RunWorkflow(workspace,plan.GitDirectory,workflow,commands[1]));
            stage="GIT_PREPARE_ATTRIBUTES";
            var info=WindowsPathSeal.Child(repo,".git/info");Directory.CreateDirectory(info);
            File.WriteAllText(WindowsPathSeal.Child(info,"attributes"),"* -text -filter -ident -working-tree-encoding !diff !whitespace\n",new UTF8Encoding(false));
            stage="GIT_ADD";RequireWorkflow(RunWorkflow(workspace,plan.GitDirectory,workflow,commands[2]));
            stage="GIT_DIFF_CHECK";var check=RunWorkflow(workspace,plan.GitDirectory,workflow,commands[3]);RequireWorkflow(check);
            if(check.Out.Length!=0)throw WfpNative.Contract("GitWhitespaceCheckOutputUnexpected");
            stage="GIT_DIFF_NUMSTAT";var numstat=RunWorkflow(workspace,plan.GitDirectory,workflow,commands[4]);RequireWorkflow(numstat);
            var metrics=ParseNumstat(numstat.Out,project);
            stage="GIT_COMMIT";var commit=RunWorkflow(workspace,plan.GitDirectory,workflow,commands[5]);RequireWorkflow(commit);
            if(commit.Out.Length!=0)throw WfpNative.Contract("GitCommitOutputUnexpected");
            stage="GIT_LOG";var log=RunWorkflow(workspace,plan.GitDirectory,workflow,commands[6]);RequireWorkflow(log);
            var fields=log.Out.TrimEnd('\r','\n').Split('\0');
            if(fields.Length!=6 || !IsObjectId(fields[0]) || !IsObjectId(fields[1]) ||
                fields[2]!=WorkspaceGitPlan.AuthorName || fields[3]!=WorkspaceGitPlan.AuthorEmail ||
                !long.TryParse(fields[4],System.Globalization.NumberStyles.None,System.Globalization.CultureInfo.InvariantCulture,out var commitTime) ||
                commitTime!=workflow.CommitUnixTime || fields[5]!=workflow.CommitMessage)
                throw WfpNative.Contract("GitWorkflowCommitMetadataMismatch");
            commitId=fields[0];var treeId=fields[1];committed=true;
            stage="GIT_STATUS_AFTER_COMMIT";var after=RunWorkflow(workspace,plan.GitDirectory,workflow,commands[7]);RequireWorkflow(after);
            var clean=after.Out.Length==0;
            if(!clean)throw WfpNative.Contract("GitWorkflowWorktreeNotClean");
            stage="GIT_OBJECT_INTEGRITY";var fsck=RunWorkflow(workspace,plan.GitDirectory,workflow,commands[8]);RequireWorkflow(fsck);
            if(fsck.Out.Length!=0 || fsck.Error.Length!=0)throw WfpNative.Contract("GitObjectIntegrityOutputUnexpected");
            stage="GIT_PRIVATE_FIXTURE_DENIAL";var negative=RunWorkflow(workspace,plan.GitDirectory,workflow,commands[9]);denialExit=negative.Exit;
            denied=negative.Exit==128 && negative.Out.Length==0 && negative.Error.TrimEnd().EndsWith(": Permission denied",StringComparison.Ordinal);
            if(!denied)throw WfpNative.Contract("GitPrivateFixtureDenialNotConfirmed");
            stage="GIT_ALL_PACKAGES_FIXTURE_DENIAL";var aap=RunWorkflow(workspace,plan.GitDirectory,workflow,commands[10]);allPackagesExit=aap.Exit;
            allPackagesDenied=aap.Exit==128 && aap.Out.Length==0 && aap.Error.TrimEnd().EndsWith(": Permission denied",StringComparison.Ordinal);
            if(!allPackagesDenied)throw WfpNative.Contract("GitAllPackagesFixtureDenialNotConfirmed");
            var observation=new GitWorkflowObservation(WorkspaceBundle.GitPlanHash(workflow),workflow.BranchName,commitId,treeId,
                workflow.CommitMessage,WorkspaceGitPlan.AuthorName,WorkspaceGitPlan.AuthorEmail,commitTime,project.Files.Length,
                metrics.AddedLines,metrics.DeletedLines,metrics.BinaryFiles,clean,true);
            return new(hashMatched,committed,commitId,denied,denialExit,allPackagesDenied,allPackagesExit,null,null,null){Workflow=observation};
        }
        catch(Exception ex)
        {
            return new(hashMatched,committed,commitId,denied,denialExit,allPackagesDenied,allPackagesExit,
                stage+(ex.Data["Stage"] is string nativeStage?"/"+nativeStage:""),ex.GetType().Name,
                ex is System.ComponentModel.Win32Exception native?native.NativeErrorCode:ex.HResult);
        }
    }
    private static (int AddedLines,int DeletedLines,int BinaryFiles) ParseNumstat(string output,WorkspaceBundle project)
    {
        var records=output.Split('\0',StringSplitOptions.RemoveEmptyEntries);
        if(records.Length!=project.Files.Length)throw WfpNative.Contract("GitNumstatInventoryMismatch");
        var expected=project.Files.Select(f=>f.Path).ToHashSet(StringComparer.Ordinal);
        int added=0,deleted=0,binary=0;
        foreach(var record in records)
        {
            var first=record.IndexOf('\t');var second=first<0?-1:record.IndexOf('\t',first+1);
            if(first<1 || second<=first+1 || second==record.Length-1)throw WfpNative.Contract("GitNumstatRecordMalformed");
            var add=record[..first];var remove=record[(first+1)..second];var path=record[(second+1)..];
            if(!expected.Remove(path))throw WfpNative.Contract("GitNumstatPathMismatch");
            if(add=="-" && remove=="-"){binary++;continue;}
            if(!int.TryParse(add,System.Globalization.NumberStyles.None,System.Globalization.CultureInfo.InvariantCulture,out var a) ||
                !int.TryParse(remove,System.Globalization.NumberStyles.None,System.Globalization.CultureInfo.InvariantCulture,out var d) ||
                a<0 || d<0 || added>100000000-a || deleted>100000000-d)throw WfpNative.Contract("GitNumstatCountBounds");
            added+=a;deleted+=d;
        }
        if(expected.Count!=0)throw WfpNative.Contract("GitNumstatFilesMissing");
        return(added,deleted,binary);
    }
    private static (int Exit,string Out,string Error) RunWorkflow(string workspace,string directory,WorkspaceGitPlan workflow,params string[] args)
    {
        using var process=AtomicChild.StartInheritedTool(GitWorkspacePolicy.StartWorkflow(workspace,directory,workflow,args));process.StandardInput.Close();
        var result=Finish(process,ReadBounded(process.StandardOutput,256*1024),ReadBounded(process.StandardError,64*1024));
        RecordResult(workspace,result);return result;
    }
    private static async Task<string> ReadBounded(StreamReader reader,int maximum)
    {
        var text=new StringBuilder();var buffer=new char[4096];
        while(true)
        {
            var count=await reader.ReadAsync(buffer.AsMemory());
            if(count==0)return text.ToString();
            if(text.Length+count>maximum)throw WfpNative.Contract("GitWorkflowOutputBounds");
            text.Append(buffer,0,count);
        }
    }
    private static void RequireWorkflow((int Exit,string Out,string Error) result)
    {if(result.Exit!=0 || result.Error.Length!=0)throw WfpNative.Contract("GitWorkflowCommandFailed");}
    private static void Signal(string workspace,string stem,string nonce)
    {
        File.WriteAllText(WindowsPathSeal.Child(workspace,stem+".txt"),nonce,new UTF8Encoding(false));
        File.WriteAllText(WindowsPathSeal.Child(workspace,stem+".signal"),"");
    }

}
