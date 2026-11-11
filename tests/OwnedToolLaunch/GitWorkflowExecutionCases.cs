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
        try
        {
            Directory.CreateDirectory(root);
            // GitHub-hosted Windows images expose Git from Git\\bin, while the
            // product's reviewed runtime layout is Git\\mingw64\\bin. Stage only
            // the six runtime files needed by this ordinary-user semantics test.
            // This does not qualify or replace the product's pinned asset hashes.
            var sourceGitRoot=FindGitRoot();
            var gitDirectory=Path.Combine(root,"Git","mingw64","bin");
            Directory.CreateDirectory(gitDirectory);
            var sourceDirectories=new[]{Path.Combine(sourceGitRoot,"mingw64","bin"),Path.Combine(sourceGitRoot,"bin"),Path.Combine(sourceGitRoot,"usr","bin")};
            var requiredAssets=new[]{"git.exe","libiconv-2.dll","libintl-8.dll","libpcre2-8-0.dll","libwinpthread-1.dll","zlib1.dll"};
            foreach(var asset in requiredAssets)
            {
                var source=sourceDirectories.Select(directory=>Path.Combine(directory,asset)).FirstOrDefault(File.Exists);
                if(source is null)throw new FileNotFoundException("Git runner asset was not found: "+asset+"; checked "+string.Join("; ",sourceDirectories));
                File.Copy(source,Path.Combine(gitDirectory,asset),true);
            }
            Require(requiredAssets.All(asset=>File.Exists(Path.Combine(gitDirectory,asset))),"all six staged Git runtime assets");

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
            File.WriteAllBytes(Path.Combine(workspace,"project-input.json"),taskBytes);
            var projectBytes=(byte[])Get(plan,"ProjectBundle")!;
            Require(projectBytes.AsSpan().SequenceEqual(taskBytes),"exact input bundle remains byte-bound");
            var project=InvokeStatic(bundleType,"Parse",projectBytes)!;
            var projectFiles=(Array)Get(project,"Files")!;
            Require(projectFiles.Length==dataFiles.Length,"all selected project files materialized");

            Directory.CreateDirectory(Path.Combine(workspace,"empty-git-template"));
            Directory.CreateDirectory(Path.Combine(workspace,"empty-git-hooks"));
            File.WriteAllBytes(Path.Combine(workspace,"empty-git-config"),Array.Empty<byte>());
            var selectedPaths=projectFiles.Cast<object>().Select(file=>(string)Get(file,"Path")!).ToArray();
            var pathspec=Path.Combine(workspace,"git-selected-paths.bin");
            File.WriteAllBytes(pathspec,Encoding.ASCII.GetBytes(string.Join('\0',selectedPaths)+"\0"));
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
            var hashInput=Run(StartWorkflow(gitType,workspace,plan,workflow,commands[0]),input);
            Require(hashInput.Exit==0 && hashInput.Error.Length==0,"real Git hash-object --stdin succeeds");
            var expectedBlob=(string)InvokeStatic(gitType,"BlobId",input)!;
            Require(hashInput.Out.Trim()==expectedBlob,"real Git input blob digest matches production calculation");

            var init=Run(StartWorkflow(gitType,workspace,plan,workflow,commands[1]));
            Require(init.Exit==0 && init.Out.Length==0 && init.Error.Length==0,"real Git init creates fresh SHA-1 main repository");
            var info=Path.Combine(repository,".git","info");
            Directory.CreateDirectory(info);
            File.WriteAllText(Path.Combine(info,"attributes"),"* -text -filter -ident -working-tree-encoding\n",new UTF8Encoding(false));

            var add=Run(StartWorkflow(gitType,workspace,plan,workflow,commands[2]));
            Require(add.Exit==0 && add.Out.Length==0 && add.Error.Length==0,"real Git add accepts exact NUL pathspec");
            var diffCheck=Run(StartWorkflow(gitType,workspace,plan,workflow,commands[3]));
            Require(diffCheck.Exit==0 && diffCheck.Out.Length==0 && diffCheck.Error.Length==0,"real Git diff --cached --check succeeds");
            var numstat=Run(StartWorkflow(gitType,workspace,plan,workflow,commands[4]));
            Require(numstat.Exit==0 && numstat.Error.Length==0,"real Git diff --cached --numstat succeeds");
            var metrics=InvokeStatic(gitType,"ParseNumstat",numstat.Out,project)!;
            var added=(int)metrics.GetType().GetField("Item1")!.GetValue(metrics)!;
            var deleted=(int)metrics.GetType().GetField("Item2")!.GetValue(metrics)!;
            var binary=(int)metrics.GetType().GetField("Item3")!.GetValue(metrics)!;
            Require(binary==1,"binary file is reported as binary, not text-transformed");

            var commit=Run(StartWorkflow(gitType,workspace,plan,workflow,commands[5]));
            Require(commit.Exit==0 && commit.Out.Length==0 && commit.Error.Length==0,"real Git commit succeeds with fixed identity/date");
            var log=Run(StartWorkflow(gitType,workspace,plan,workflow,commands[6]));
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
            var status=Run(StartWorkflow(gitType,workspace,plan,workflow,commands[7]));
            Require(status.Exit==0 && status.Out.Length==0 && status.Error.Length==0,"real Git status confirms a clean worktree");
            var fsck=Run(StartWorkflow(gitType,workspace,plan,workflow,commands[8]));
            Require(fsck.Exit==0 && fsck.Out.Length==0 && fsck.Error.Length==0,"real Git fsck --full --strict succeeds");

            SetReadDenied(privateFixture,owner);
            SetReadDenied(allPackagesFixture,owner);
            Require(AccessDenied(privateFixture) && AccessDenied(allPackagesFixture),"both negative-control fixtures deny ordinary reads");
            var privateDenial=Run(StartWorkflow(gitType,workspace,plan,workflow,commands[9]));
            Require(privateDenial.Exit==128 && privateDenial.Out.Length==0 &&
                privateDenial.Error.TrimEnd().EndsWith(": Permission denied",StringComparison.Ordinal),
                "real Git cannot read the private-state fixture");
            var allPackagesDenial=Run(StartWorkflow(gitType,workspace,plan,workflow,commands[10]));
            Require(allPackagesDenial.Exit==128 && allPackagesDenial.Out.Length==0 &&
                allPackagesDenial.Error.TrimEnd().EndsWith(": Permission denied",StringComparison.Ordinal),
                "real Git cannot read the all-packages-only fixture");

            var planHash=(string)InvokeStatic(gitType,"GitPlanHash",workflow)!;
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

            Console.WriteLine("PASS ordinary-user real Git execution using the hosted runner Git distribution: hash-object/init/add/diff-check/numstat/commit/log/status/fsck and both denial controls; independent owner commit/tree/blob/ref verification and exact GitReceipt binding; CRLF, binary, empty and ignored selected files preserved. ORDINARY-USER COMMAND/VERIFIER EVIDENCE ONLY: runner Git semantics, not product pinned-asset qualification; no product Broker, Owned Job, LPAC, UAC, host policy or Claude execution.");
        }
        finally
        {
            foreach(var path in new[]{privateFixture,allPackagesFixture})
                if(path is not null && File.Exists(path))
                    try{SetReadAllowed(path,owner);}catch{}
            if(Directory.Exists(root))Directory.Delete(root,true);
        }
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
