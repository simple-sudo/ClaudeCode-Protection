using System.Diagnostics;
using System.Reflection;
using System.Runtime.ExceptionServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Security.Cryptography;
using System.Text;

internal static class GitWorkflowExecutionCases
{
    private sealed record CommandResult(int Exit,string Out,string Error);
    private const BindingFlags InstanceFlags=BindingFlags.Instance|BindingFlags.Public|BindingFlags.NonPublic;
    private const BindingFlags StaticFlags=BindingFlags.Static|BindingFlags.Public|BindingFlags.NonPublic;

    internal static void Run(Assembly library)
    {
        using var identity=WindowsIdentity.GetCurrent();
        var owner=identity.User??throw new InvalidOperationException("Ordinary test owner SID missing");
        if(new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))
            throw new InvalidOperationException("Ordinary-user Git execution test must not run elevated");

        var nonce=Guid.NewGuid().ToString("N");
        var root=Path.Combine(Path.GetTempPath(),"cpc-git-workflow-execution-"+nonce);
        string? privateFixture=null,allPackagesFixture=null;
        Exception? primaryFailure=null;
        try
        {
            Directory.CreateDirectory(root);
            // This is an ordinary-user Git semantics test, not product asset
            // qualification. Stage the runner's actual git.exe and keep its
            // installation runtime directories on this test process PATH so
            // Windows can resolve that distribution's own DLL dependencies.
            // Product execution still requires the separately pinned six-file set.
            var sourceGitRoot=FindGitRoot();
            var gitDirectory=Path.Combine(root,"Git","mingw64","bin");
            Directory.CreateDirectory(gitDirectory);
            var sourceDirectories=new[]{Path.Combine(sourceGitRoot,"mingw64","bin"),Path.Combine(sourceGitRoot,"bin"),
                Path.Combine(sourceGitRoot,"usr","bin"),Path.Combine(sourceGitRoot,"cmd")}.Where(Directory.Exists).ToArray();
            var sourceGitExecutable=sourceDirectories.Select(directory=>Path.Combine(directory,"git.exe")).FirstOrDefault(File.Exists)
                ??throw new FileNotFoundException("Git runner executable was not found under "+sourceGitRoot);
            var sourceExecPath=new[]{Path.Combine(sourceGitRoot,"mingw64","libexec","git-core"),
                Path.Combine(sourceGitRoot,"libexec","git-core")}.FirstOrDefault(Directory.Exists)
                ??Path.GetDirectoryName(sourceGitExecutable)!;

            var bundleType=library.GetType("ClaudeCodeProtection.Workspaces.WorkspaceBundle",true)!;
            var gitType=library.GetType("ProtectionLifecycle.SessionGitToolchain",true)!;
            var planType=library.GetType("ProtectionLifecycle.ResourceProbePlan",true)!;
            var dataFiles=new (string Path,byte[] Content)[]
            {
                (".gitattributes",Encoding.UTF8.GetBytes("*.cs text eol=lf\n*.bin filter=must-not-run\n")),
                (".gitignore",Encoding.UTF8.GetBytes("ignored.txt\n")),
                ("README.md",Encoding.UTF8.GetBytes("Offline Git execution fixture\r\nsecond line\r\n")),
                ("assets/payload.bin",new byte[]{0,255,1,128,13,10,0,42}),
                ("empty.txt",Array.Empty<byte>()),
                ("ignored.txt",Encoding.UTF8.GetBytes("force-added despite ignore\n")),
                ("src/main.cs",Encoding.UTF8.GetBytes("class Sample\r\n{\r\n}\r\n"))
            };
            var data=InvokeStatic(bundleType,"Create",dataFiles,null)!;
            var dataBytes=(byte[])InvokeInstance(data,"Serialize")!;
            var taskBytes=(byte[])InvokeStatic(bundleType,"CreateGitWorkflow",dataBytes,"Offline workspace import #42")!;
            var task=InvokeStatic(bundleType,"Parse",taskBytes)!;
            var workflow=Get(task,"GitPlan")??throw new InvalidDataException("GitPlan missing");
            var assetSet=(string)GetStatic(gitType,"AssetSetSHA256")!;
            var plan=Activator.CreateInstance(planType,InstanceFlags,null,new object?[]
            {
                3,nonce,new string('b',32),new string('c',32),Environment.ProcessId,new string('A',64),
                assetSet,Hash(taskBytes),Path.GetFullPath(root)
            },null)??throw new InvalidOperationException("ResourceProbePlan construction failed");
            InvokeInstance(plan,"Validate");
            var workspace=(string)InvokeInstance(plan,"Workspace","")!;
            Directory.CreateDirectory(workspace);
            ProcessStartInfo StartRunnerWorkflow(string[] command)
            {
                var start=StartWorkflow(gitType,workspace,plan,workflow,command);
                // Execute the original in-place image: moving Git for Windows
                // changes its loader-relative layout and can break DLL binding.
                start.FileName=sourceGitExecutable;
                start.Environment["GIT_EXEC_PATH"]=sourceExecPath;
                start.Environment["PATH"]=string.Join(Path.PathSeparator,sourceDirectories.Append(Environment.SystemDirectory));
                return start;
            }
            File.WriteAllBytes(Path.Combine(workspace,"project-input.json"),taskBytes);
            var projectBytes=(byte[])Get(plan,"ProjectBundle")!;
            Require(projectBytes.AsSpan().SequenceEqual(taskBytes),"exact input bundle remains byte-bound");
            var project=InvokeStatic(bundleType,"Parse",projectBytes)!;
            var projectFiles=(Array)Get(project,"Files")!;
            Require(projectFiles.Length==dataFiles.Length,"all selected project files materialized");

            var control=Path.Combine(workspace,"git-control");Directory.CreateDirectory(control);
            Directory.CreateDirectory(Path.Combine(control,"empty-git-template"));
            Directory.CreateDirectory(Path.Combine(control,"empty-git-hooks"));
            File.WriteAllBytes(Path.Combine(control,"empty-git-config"),Array.Empty<byte>());
            var selectedPaths=projectFiles.Cast<object>().Select(file=>(string)Get(file,"Path")!).ToArray();
            var pathspec=Path.Combine(control,"git-selected-paths.bin");
            File.WriteAllBytes(pathspec,Encoding.ASCII.GetBytes(string.Join('\0',selectedPaths)+"\0"));
            VerifyGitWorkspaceBoundary(library,owner);
            InvokeStatic(gitType,"AssertGitControlReady",workspace,true);
            VerifyGitControlMutationGuards(gitType,workspace);
            foreach(var file in projectFiles)
            {
                var relative=(string)Get(file,"Path")!;
                var destination=Path.Combine(workspace,"git-project",relative.Replace('/','\\'));
                Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
                File.WriteAllBytes(destination,(byte[])Get(file,"Content")!);
            }
            var repository=Path.Combine(workspace,"git-project");
            Require((bool)InvokeStatic(gitType,"SelectedPathspecMatches",workspace,project)!,"owner pathspec exactly matches selected files");

            var fixtureDirectory=Path.Combine(root,"ClaudeCodeProtection-State");
            Directory.CreateDirectory(fixtureDirectory);
            privateFixture=(string)Get(plan,"Fixture")!;
            allPackagesFixture=Path.Combine(workspace,"all-packages-only.json");
            File.WriteAllText(privateFixture,"PRIVATE NON-SECRET DENIAL FIXTURE",new UTF8Encoding(false));
            File.WriteAllText(allPackagesFixture,"ALL-PACKAGES NON-SECRET DENIAL FIXTURE",new UTF8Encoding(false));
            var commands=(string[][])InvokeStatic(gitType,"WorkflowCommands",plan,workspace,workflow)!;
            Require(commands.Length==11,"fixed bounded 11-command workflow");

            var input=(byte[])Get(plan,"Input")!;
            var hashInput=Run(StartRunnerWorkflow(commands[0]),input);
            var expectedBlob=(string)InvokeStatic(gitType,"BlobId",input)!;
            if(hashInput.Exit!=0 || hashInput.Error.Length!=0 || hashInput.Out.Trim()!=expectedBlob)
                throw new InvalidDataException("real Git hash-object failed: exit="+hashInput.Exit+
                    "; stdout="+hashInput.Out[..Math.Min(hashInput.Out.Length,512)]+
                    "; stderr="+hashInput.Error[..Math.Min(hashInput.Error.Length,512)]+
                    "; expected="+expectedBlob);

            var init=Run(StartRunnerWorkflow(commands[1]));
            Require(init.Exit==0 && init.Out.Length==0 && init.Error.Length==0,"real Git init creates fresh SHA-1 main repository");
            var info=Path.Combine(repository,".git","info");
            Directory.CreateDirectory(info);
            File.WriteAllText(Path.Combine(info,"attributes"),"* -text -filter -ident -working-tree-encoding\n",new UTF8Encoding(false));

            var add=Run(StartRunnerWorkflow(commands[2]));
            Require(add.Exit==0 && add.Out.Length==0 && add.Error.Length==0,"real Git add accepts exact NUL pathspec");
            var diffCheckStart=StartRunnerWorkflow(commands[3]);
            Require(diffCheckStart.ArgumentList.Contains("core.whitespace=cr-at-eol"),"fixed CRLF-aware whitespace validation policy");
            var diffCheck=Run(diffCheckStart);
            if(diffCheck.Exit!=0 || diffCheck.Out.Length!=0 || diffCheck.Error.Length!=0)
                throw new InvalidDataException("real Git diff --cached --check failed: exit="+diffCheck.Exit+
                    "; stdout="+diffCheck.Out[..Math.Min(diffCheck.Out.Length,512)]+
                    "; stderr="+diffCheck.Error[..Math.Min(diffCheck.Error.Length,512)]);
            var numstat=Run(StartRunnerWorkflow(commands[4]));
            Require(numstat.Exit==0 && numstat.Error.Length==0,"real Git diff --cached --numstat succeeds");
            var metrics=InvokeStatic(gitType,"ParseNumstat",numstat.Out,project)!;
            var added=(int)metrics.GetType().GetField("Item1")!.GetValue(metrics)!;
            var deleted=(int)metrics.GetType().GetField("Item2")!.GetValue(metrics)!;
            var binary=(int)metrics.GetType().GetField("Item3")!.GetValue(metrics)!;
            Require(binary==1,"binary file is reported as binary, not text-transformed");

            var commit=Run(StartRunnerWorkflow(commands[5]));
            Require(commit.Exit==0 && commit.Out.Length==0 && commit.Error.Length==0,"real Git commit succeeds with fixed identity/date");
            var log=Run(StartRunnerWorkflow(commands[6]));
            Require(log.Exit==0 && log.Error.Length==0,"real Git log returns commit metadata");
            var fields=log.Out.TrimEnd('\r','\n').Split('\0');
            Require(fields.Length==6,"real Git log returns the six fixed metadata fields");
            Require(fields[2]=="Local Workspace" && fields[3]=="local@invalid.example" && fields[5]==(string)Get(workflow,"CommitMessage")!,
                "real Git log identity and exact message match the immutable plan");
            if(!long.TryParse(fields[4],System.Globalization.NumberStyles.None,System.Globalization.CultureInfo.InvariantCulture,out var commitTime))
                throw new InvalidDataException("Git workflow execution: commit timestamp is malformed");
            Require(commitTime==(long)Get(workflow,"CommitUnixTime")!,"real Git commit timestamp matches the immutable plan");
            var commitId=fields[0];
            var treeId=fields[1];
            var status=Run(StartRunnerWorkflow(commands[7]));
            Require(status.Exit==0 && status.Out.Length==0 && status.Error.Length==0,"real Git status confirms a clean worktree");
            var fsck=Run(StartRunnerWorkflow(commands[8]));
            Require(fsck.Exit==0 && fsck.Out.Length==0 && fsck.Error.Length==0,"real Git fsck --full --strict succeeds");

            SetReadDenied(privateFixture,owner);
            SetReadDenied(allPackagesFixture,owner);
            Require(AccessDenied(privateFixture) && AccessDenied(allPackagesFixture),"both negative-control fixtures deny ordinary reads");
            var privateDenial=Run(StartRunnerWorkflow(commands[9]));
            Require(privateDenial.Exit==128 && privateDenial.Out.Length==0 &&
                privateDenial.Error.TrimEnd().EndsWith(": Permission denied",StringComparison.Ordinal),
                "real Git cannot read the private-state fixture");
            var allPackagesDenial=Run(StartRunnerWorkflow(commands[10]));
            Require(allPackagesDenial.Exit==128 && allPackagesDenial.Out.Length==0 &&
                allPackagesDenial.Error.TrimEnd().EndsWith(": Permission denied",StringComparison.Ordinal),
                "real Git cannot read the all-packages-only fixture");

            var planHash=(string)InvokeStatic(bundleType,"GitPlanHash",workflow)!;
            var observationType=library.GetType("ProtectionLifecycle.GitWorkflowObservation",true)!;
            var observation=Activator.CreateInstance(observationType,InstanceFlags,null,new object?[]
            {
                planHash,(string)Get(workflow,"BranchName")!,commitId,treeId,(string)Get(workflow,"CommitMessage")!,
                "Local Workspace","local@invalid.example",commitTime,projectFiles.Length,added,deleted,binary,true,true
            },null)??throw new InvalidOperationException("Git workflow observation construction failed");
            var reportType=library.GetType("ProtectionLifecycle.GitToolchainReport",true)!;
            var report=Activator.CreateInstance(reportType,InstanceFlags,null,new object?[]
            {
                true,true,commitId,true,privateDenial.Exit,true,allPackagesDenial.Exit,null,null,null
            },null)??throw new InvalidOperationException("Git toolchain report construction failed");
            reportType.GetProperty("Workflow",InstanceFlags)!.SetValue(report,observation);
            var receipt=InvokeStatic(gitType,"AssertRepository",workspace,plan,report)!;

            var resultData=InvokeStatic(bundleType,"Create",dataFiles,Hash(taskBytes))!;
            var resultBytes=(byte[])InvokeInstance(resultData,"Serialize")!;
            var receiptBytes=(byte[])InvokeStatic(bundleType,"AttachGitReceipt",resultBytes,taskBytes,receipt)!;
            var changes=(Array)InvokeStatic(bundleType,"Compare",taskBytes,receiptBytes)!;
            Require(changes.Length==0,"owner-verified GitReceipt binds the exact input and unchanged selected bytes");
            Require(!File.ReadAllText(Path.Combine(repository,".git","config")).Contains("[remote ",StringComparison.OrdinalIgnoreCase),
                "fresh repository contains no remote configuration");

            var branchRef=Path.Combine(repository,".git","refs","heads","main");
            var originalRef=File.ReadAllText(branchRef);
            var refTamperRefused=false;
            try
            {
                File.WriteAllText(branchRef,new string('0',40)+"\n",new UTF8Encoding(false));
                try{_=InvokeStatic(gitType,"AssertRepository",workspace,plan,report);}
                catch(InvalidDataException){refTamperRefused=true;}
                catch(TargetInvocationException error)when(error.InnerException is InvalidDataException){refTamperRefused=true;}
            }
            finally{File.WriteAllText(branchRef,originalRef,new UTF8Encoding(false));}
            Require(refTamperRefused,"owner verifier refuses a branch ref that no longer names the verified commit");

            Console.WriteLine("PASS ordinary-user real Git execution using the hosted runner Git executable and its runtime PATH: hash-object/init/add/diff-check/numstat/commit/log/status/fsck and both denial controls; independent owner commit/tree/blob/ref verification and exact GitReceipt binding; CRLF, binary, empty and ignored selected files preserved. ORDINARY-USER COMMAND/VERIFIER EVIDENCE ONLY: runner Git semantics, not product pinned-asset qualification; no product Broker, Owned Job, LPAC, UAC, host policy or Claude execution.");
        }
        catch(Exception error)
        {
            primaryFailure=error;
            Console.Error.WriteLine("Git workflow primary failure: "+error.GetType().Name+"; code="+error.HResult+"; "+error.Message);
            throw;
        }
        finally
        {
            Exception? cleanupFailure=null;
            foreach(var fixturePath in new[]{privateFixture,allPackagesFixture})
                if(fixturePath is not null && File.Exists(fixturePath))
                    try{SetReadAllowed(fixturePath,owner);}catch(Exception error){cleanupFailure??=error;}
            if(Directory.Exists(root))
            {
                try
                {
                    var readOnlyFiles=Directory.EnumerateFiles(root,"*",SearchOption.AllDirectories)
                        .Where(file=>(File.GetAttributes(file)&FileAttributes.ReadOnly)!=0).ToArray();
                    Console.WriteLine("Git workflow fixture cleanup read-only files: "+readOnlyFiles.Length);
                    foreach(var file in readOnlyFiles)File.SetAttributes(file,FileAttributes.Normal);
                    Directory.Delete(root,true);
                }
                catch(Exception error){cleanupFailure??=error;}
            }
            if(cleanupFailure is not null)
            {
                Console.Error.WriteLine("Git workflow fixture cleanup failure: "+cleanupFailure.GetType().Name+"; code="+cleanupFailure.HResult);
                if(primaryFailure is null)throw cleanupFailure;
            }
        }
    }

    private static void VerifyGitWorkspaceBoundary(Assembly library,SecurityIdentifier owner)
    {
        var descriptorType=library.GetType("ProtectionLifecycle.GitWorkspaceDescriptor",true)!;
        var packageSid="S-1-15-2-1234567890-2345678901-3456789012";
        var projectDacl=(string)InvokeStatic(descriptorType,"BuildDaclSddl",packageSid,true)!;
        var controlDacl=(string)InvokeStatic(descriptorType,"BuildDaclSddl",packageSid,false)!;
        var project=new RawSecurityDescriptor(projectDacl);var control=new RawSecurityDescriptor(controlDacl);
        Require(project.Owner?.Value=="S-1-5-32-544" && control.Owner?.Value=="S-1-5-32-544",
            "private Git directory roots are owned by the elevated Administrators principal");
        Require(project.Group?.Value=="S-1-5-18" && control.Group?.Value=="S-1-5-18","private Git directories use the fixed SYSTEM group");
        Require(project.ControlFlags.HasFlag(ControlFlags.DiscretionaryAclProtected) &&
            control.ControlFlags.HasFlag(ControlFlags.DiscretionaryAclProtected),"private Git DACLs block parent ACL inheritance");
        var projectAcl=project.DiscretionaryAcl??throw new InvalidDataException("Project DACL missing");
        var controlAcl=control.DiscretionaryAcl??throw new InvalidDataException("Control DACL missing");
        var projectPackage=projectAcl.OfType<CommonAce>().Single(ace=>ace.SecurityIdentifier.Value==packageSid);
        var controlPackage=controlAcl.OfType<CommonAce>().Single(ace=>ace.SecurityIdentifier.Value==packageSid);
        var ownerRights=projectAcl.OfType<CommonAce>().Single(ace=>ace.SecurityIdentifier.Value=="S-1-3-4");
        Require(projectPackage.AccessMask==0x001301bf && (projectPackage.AccessMask&0x000c0000)==0 &&
            (projectPackage.AccessMask&0x00000006)==0x00000006,
            "LPAC project access permits file/directory mutation but excludes WRITE_DAC and WRITE_OWNER");
        Require(controlPackage.AccessMask==unchecked((int)0xA0000000u),"LPAC Git control access is generic read/execute only");
        Require(ownerRights.AccessMask==0x00020000 &&
            (ownerRights.AceFlags&(AceFlags.ObjectInherit|AceFlags.ContainerInherit))==(AceFlags.ObjectInherit|AceFlags.ContainerInherit),
            "inherited OWNER RIGHTS ACE removes implicit WRITE_DAC from file and directory owners");
        Require(!projectAcl.OfType<CommonAce>().Any(ace=>ace.SecurityIdentifier.Value==owner.Value) &&
            !controlAcl.OfType<CommonAce>().Any(ace=>ace.SecurityIdentifier.Value==owner.Value),
            "ordinary user receives no direct Git project/control access grant");
        Require(projectAcl.OfType<CommonAce>().Any(ace=>ace.SecurityIdentifier.Value=="S-1-5-18" && ace.AccessMask==0x001f01ff) &&
            projectAcl.OfType<CommonAce>().Any(ace=>ace.SecurityIdentifier.Value=="S-1-5-32-544" && ace.AccessMask==0x001f01ff),
            "SYSTEM and elevated Broker retain full management access");
    }

    private static void VerifyGitControlMutationGuards(Type gitType,string workspace)
    {
        var hooks=Path.Combine(workspace,"git-control","empty-git-hooks");
        var config=Path.Combine(workspace,"git-control","empty-git-config");
        var extra=Path.Combine(workspace,"git-control","unexpected-control");
        var hook=Path.Combine(hooks,"pre-commit");
        File.WriteAllText(hook,"#!/bin/sh\nexit 0\n");
        var hookRefused=false;
        try{InvokeStatic(gitType,"AssertGitControlReady",workspace,true);}
        catch(InvalidDataException){hookRefused=true;}
        finally{File.Delete(hook);}
        Require(hookRefused,"non-empty hooks directory fails closed");
        File.WriteAllText(config,"[filter \"attack\"]\nclean = cmd.exe /c whoami\n");
        var configRefused=false;
        try{InvokeStatic(gitType,"AssertGitControlReady",workspace,true);}
        catch(InvalidDataException){configRefused=true;}
        finally{File.WriteAllBytes(config,Array.Empty<byte>());}
        Require(configRefused,"non-empty global Git config fails closed");
        File.WriteAllText(extra,"unexpected");
        var extraRefused=false;
        try{InvokeStatic(gitType,"AssertGitControlReady",workspace,true);}
        catch(InvalidDataException){extraRefused=true;}
        finally{File.Delete(extra);}
        Require(extraRefused,"unexpected Git control entry fails closed");
        InvokeStatic(gitType,"AssertGitControlReady",workspace,true);
    }

    private static string FindGitRoot()
    {
        var roots=new[]{Environment.GetEnvironmentVariable("ProgramFiles"),Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86)}.Where(p=>!string.IsNullOrWhiteSpace(p)).Distinct(StringComparer.OrdinalIgnoreCase);
        foreach(var root in roots)
        {
            var candidate=Path.Combine(root!,"Git");
            if(File.Exists(Path.Combine(candidate,"mingw64","bin","git.exe")) ||
                File.Exists(Path.Combine(candidate,"bin","git.exe")))return candidate;
        }
        var path=Environment.GetEnvironmentVariable("PATH")??"";
        foreach(var entry in path.Split(Path.PathSeparator,StringSplitOptions.RemoveEmptyEntries))
        {
            var directory=entry.Trim().Trim('"');
            if(!File.Exists(Path.Combine(directory,"git.exe")))continue;
            DirectoryInfo? current;
            try{current=new DirectoryInfo(Path.GetFullPath(directory));}catch{continue;}
            for(var depth=0;current is not null && depth<6;depth++,current=current.Parent)
                if(string.Equals(current.Name,"Git",StringComparison.OrdinalIgnoreCase) &&
                    (Directory.Exists(Path.Combine(current.FullName,"bin")) || Directory.Exists(Path.Combine(current.FullName,"mingw64","bin"))))
                    return current.FullName;
        }
        throw new FileNotFoundException("Git for Windows root was not found under Program Files\\Git or any PATH entry containing git.exe");
    }

    private static ProcessStartInfo StartWorkflow(Type gitType,string workspace,object plan,object workflow,string[] command)
        =>(ProcessStartInfo)InvokeStatic(gitType,"StartWorkflow",workspace,(string)Get(plan,"GitDirectory")!,workflow,command)!;

    private static CommandResult Run(ProcessStartInfo start,byte[]? input=null)
    {
        using var process=new Process{StartInfo=start};
        if(!process.Start())throw new IOException("Git process did not start");
        var stdout=process.StandardOutput.ReadToEndAsync();
        var stderr=process.StandardError.ReadToEndAsync();
        if(input is not null)
        {
            process.StandardInput.BaseStream.Write(input);
            process.StandardInput.BaseStream.Flush();
        }
        process.StandardInput.Close();
        if(!process.WaitForExit(15000))
        {
            try{process.Kill(true);}catch{}
            try{process.WaitForExit(2000);}catch{}
            throw new TimeoutException("Ordinary-user Git command exceeded the 15-second test deadline");
        }
        return new(process.ExitCode,stdout.GetAwaiter().GetResult(),stderr.GetAwaiter().GetResult());
    }

    private static void SetReadDenied(string path,SecurityIdentifier owner)
    {
        var security=new FileSecurity();
        security.SetOwner(owner);
        security.SetAccessRuleProtection(true,false);
        security.AddAccessRule(new FileSystemAccessRule(owner,FileSystemRights.FullControl,AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule(owner,FileSystemRights.ReadData,AccessControlType.Deny));
        FileSystemAclExtensions.SetAccessControl(new FileInfo(path),security);
    }

    private static void SetReadAllowed(string path,SecurityIdentifier owner)
    {
        var security=new FileSecurity();
        security.SetOwner(owner);
        security.SetAccessRuleProtection(true,false);
        security.AddAccessRule(new FileSystemAccessRule(owner,FileSystemRights.FullControl,AccessControlType.Allow));
        FileSystemAclExtensions.SetAccessControl(new FileInfo(path),security);
    }

    private static bool AccessDenied(string path)
    {
        try{using var file=File.OpenRead(path);return false;}
        catch(UnauthorizedAccessException){return true;}
    }

    private static string Hash(byte[] bytes)=>Convert.ToHexString(SHA256.HashData(bytes));
    private static void Require(bool value,string reason){if(!value)throw new InvalidDataException("Git workflow execution: "+reason);}

    private static object? Get(object instance,string name)
        =>instance.GetType().GetProperty(name,InstanceFlags)?.GetValue(instance)
            ??instance.GetType().GetField(name,InstanceFlags)?.GetValue(instance);

    private static object? GetStatic(Type type,string name)
        =>type.GetProperty(name,StaticFlags)?.GetValue(null)
            ??type.GetField(name,StaticFlags)?.GetValue(null);

    private static object? InvokeStatic(Type type,string name,params object?[] values)
        =>Invoke(type.GetMethod(name,StaticFlags)??throw new MissingMethodException(type.FullName,name),null,values);

    private static object? InvokeInstance(object instance,string name,params object?[] values)
        =>Invoke(instance.GetType().GetMethod(name,InstanceFlags)??throw new MissingMethodException(instance.GetType().FullName,name),instance,values);

    private static object? Invoke(MethodInfo method,object? target,object?[] values)
    {
        try{return method.Invoke(target,values);}
        catch(TargetInvocationException error)when(error.InnerException is not null)
        {ExceptionDispatchInfo.Capture(error.InnerException).Throw();throw;}
    }
}
