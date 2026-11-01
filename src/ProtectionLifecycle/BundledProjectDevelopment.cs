using System.Diagnostics;
using System.Reflection;
using System.Runtime.ExceptionServices;
using System.Runtime.Loader;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using ClaudeCodeProtection.Workspaces;

namespace ProtectionLifecycle;

// An explicit project-code execution task on the ORIGINAL confined Broker
// image. Never inferred from DATA input, never loaded into its elevated owner.
internal static class BundledProjectDevelopment
{
    private const string Sample="alpha beta\n\n gamma delta epsilon\n";
    private const string Extension="public static int CountWords(string text) => text.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries).Length;";
    private const string Checks="if (Counter.CountWords(\"\") != 0) throw new Exception(\"empty words\");\n"+
        "if (Counter.CountWords(\"alpha beta\\n gamma delta epsilon\\n\") != 5) throw new Exception(\"multiple words\");\n"+
        "if (Counter.CountWords(\"a\\u2003b\\t c\") != 3) throw new Exception(\"unicode whitespace\");\npassed += 3;";
    internal static byte[] Baseline()=>TextSummarySource.Baseline();
    internal static string BaselineHash=>TextSummarySource.BaselineHash;
    private static byte[] Modified(WorkspaceFile file)
    {
        var marker=file.Path switch {"TextSummary.cs"=>"// CPC_WORD_COUNT_EXTENSION","ProjectTests.cs"=>"// CPC_WORD_COUNT_CHECKS",_=>null};
        if(marker is null)return file.Content;
        var text=new UTF8Encoding(false,true).GetString(file.Content);
        if(text.Split(marker,StringSplitOptions.None).Length!=2)throw WfpNative.Contract("BundledProjectEditMarkerDiffers");
        return Encoding.UTF8.GetBytes(text.Replace(marker,file.Path=="TextSummary.cs"?Extension:Checks,StringComparison.Ordinal));
    }
    internal static void VerifyResult(byte[] bytes)
    {
        var baseline=Baseline();_=WorkspaceBundle.Compare(baseline,bytes);var result=WorkspaceBundle.Parse(bytes);
        var originals=WorkspaceBundle.Parse(baseline).Files;
        if(result.Files.Length!=originals.Length+3)throw WfpNative.Contract("DevelopmentResultInventoryDiffers");
        foreach(var file in originals)
            if(!result.Files.Single(f=>f.Path==file.Path).Content.AsSpan().SequenceEqual(Modified(file)))throw WfpNative.Contract("DevelopmentSourceEditDiffers");
        if(!result.Files.Single(f=>f.Path=="run-result.json").Content.AsSpan().SequenceEqual("{\"Lines\":2,\"Words\":5}"u8) ||
            !result.Files.Single(f=>f.Path=="test-result.txt").Content.AsSpan().SequenceEqual("6"u8))throw WfpNative.Contract("DevelopmentExecutionResultDiffers");
        var artifact=result.Files.Single(f=>f.Path=="TextSummary.dll").Content;
        if(artifact.Length is <512 or >1024*1024)throw WfpNative.Contract("DevelopmentAssemblyBounds");
        using var memory=new MemoryStream(artifact,false);using var pe=new System.Reflection.PortableExecutable.PEReader(memory);
        if(!pe.HasMetadata)throw WfpNative.Contract("DevelopmentAssemblyMetadataMissing");
    }
    internal static ProcessStartInfo Start(ResourceProbePlan plan,string workspace)
    {
        plan.Validate();if(!plan.DevelopProject)throw WfpNative.Contract("ExplicitProjectDevelopmentRequired");
        var start=new ProcessStartInfo(plan.ExpectedChildImage){UseShellExecute=false,CreateNoWindow=true,WorkingDirectory=workspace,RedirectStandardInput=true,RedirectStandardOutput=true,RedirectStandardError=true};
        start.Environment.Clear();
        foreach(var name in new[]{"SystemRoot","windir","SystemDrive","PROCESSOR_ARCHITECTURE"})
            if(Environment.GetEnvironmentVariable(name) is string value)start.Environment[name]=value;
        foreach(var name in new[]{"TEMP","TMP","LOCALAPPDATA","USERPROFILE"})start.Environment[name]=workspace;
        start.Environment["PATH"]=Environment.SystemDirectory;
        start.Environment["DOTNET_ROOT"]=WindowsPathSeal.Child(plan.ProgramFilesRoot,"dotnet");
        start.Environment["CPC_RESOURCE_PLAN"]=JsonSerializer.Serialize(plan);
        start.ArgumentList.Add("resource-project");start.ArgumentList.Add(plan.Nonce);return start;
    }
    internal static int Run(string[] arguments)
    {
        try
        {
            var actual=AtomicChild.AssertRestrictedToolSelf();
            var plan=ResourceProbePlan.Parse(Environment.GetEnvironmentVariable("CPC_RESOURCE_PLAN")??throw WfpNative.Contract("ProjectPlanMissing"));
            using var package=InstallationPackageSid.FromInstallationId(plan.InstallationId);
            if(!plan.DevelopProject || actual!=package.Value || !arguments.SequenceEqual(new[]{plan.Nonce}) ||
                !string.Equals(Environment.ProcessPath,plan.ExpectedChildImage,StringComparison.OrdinalIgnoreCase))throw WfpNative.Contract("ProjectOriginalOwnerBindingMissing");
            var workspace=plan.Workspace(package.Value);
            if(!string.Equals(Path.GetFullPath(Environment.CurrentDirectory),workspace,StringComparison.OrdinalIgnoreCase))throw WfpNative.Contract("ProjectWorkingDirectoryDiffers");
            File.WriteAllText(Path.Combine(workspace,"tool-ready.txt"),plan.Nonce,Encoding.ASCII);
            File.WriteAllText(Path.Combine(workspace,"tool-ready.signal"),"");var clock=Stopwatch.StartNew();
            while(!File.Exists(Path.Combine(workspace,"tool-go.signal"))){if(clock.ElapsedMilliseconds>=8000)throw new TimeoutException("Original project owner gate");Thread.Sleep(20);}
            if(File.ReadAllText(Path.Combine(workspace,"tool-go.txt"))!=plan.Nonce)throw WfpNative.Contract("ProjectOwnerGateBindingDiffers");
            HostPrivacyProbe.RunRestricted(plan,workspace,"project");
            File.WriteAllText(Path.Combine(workspace,"project-privacy-ready.txt"),plan.Nonce,Encoding.ASCII);
            File.WriteAllText(Path.Combine(workspace,"project-privacy-ready.signal"),"");clock.Restart();
            while(!File.Exists(Path.Combine(workspace,"project-execution-go.signal"))){if(clock.ElapsedMilliseconds>=8000)throw new TimeoutException("Original owner privacy sealing gate");Thread.Sleep(20);}
            if(File.ReadAllText(Path.Combine(workspace,"project-execution-go.txt"))!=plan.Nonce)throw WfpNative.Contract("ProjectExecutionGateBindingDiffers");
            if(plan.CallerProjectKind is not null)CallerCSharpProject.BuildAndRun(plan.PowerShellDirectory,Path.Combine(workspace,"git-project"),plan.ProjectBundle);
            else BuildAndRun(plan.PowerShellDirectory,Path.Combine(workspace,"git-project"));
            foreach(var fixture in new[]{plan.Fixture,Path.Combine(workspace,"all-packages-only.json")})
            {
                bool denied=false;try{using var file=File.OpenRead(fixture);}catch(UnauthorizedAccessException){denied=true;}
                if(!denied)throw WfpNative.Contract("ProjectOwnFixtureReadNotDenied");
            }
            File.WriteAllBytes(Path.Combine(workspace,"tool-output.txt"),plan.Input);return 0;
        }
        catch(Exception error){Console.Error.WriteLine(error);return 125;}
    }
    // Shared by the confined tool and the ordinary own-project fixture. This
    // never invokes PowerShell, MSBuild, project imports, packages or a child.
    internal static void BuildAndRun(string tools,string project)
    {
        var baseline=WorkspaceBundle.Parse(Baseline());
        foreach(var file in baseline.Files)
            if(!File.ReadAllBytes(Path.Combine(project,file.Path)).AsSpan().SequenceEqual(file.Content))throw WfpNative.Contract("DevelopmentProjectBaselineChanged");
        foreach(var file in baseline.Files.Where(f=>f.Path is "TextSummary.cs" or "ProjectTests.cs"))
        {
            using var output=new FileStream(Path.Combine(project,file.Path),FileMode.Open,FileAccess.Write,FileShare.None);
            var changed=Modified(file);output.SetLength(0);output.Write(changed);output.Flush(true);
        }
        var assemblyPath=Compile(tools,project,"TextSummary",new[]{"TextSummary.cs","ProjectTests.cs"},"TextSummary.dll");
        var compiled=AssemblyLoadContext.Default.LoadFromAssemblyPath(assemblyPath);
        var counter=compiled.GetType("TextSummary.Counter",true)!;
        var lines=(int)counter.GetMethod("CountLines")!.Invoke(null,new[]{Sample})!;
        var words=(int)counter.GetMethod("CountWords")!.Invoke(null,new[]{Sample})!;
        var tests=(int)compiled.GetType("TextSummary.ProjectTests",true)!.GetMethod("Run")!.Invoke(null,null)!;
        if(lines!=2 || words!=5 || tests!=6)throw WfpNative.Contract("DevelopmentRunOrTestsFailed");
        WriteNew("run-result.json",JsonSerializer.SerializeToUtf8Bytes(new{Lines=lines,Words=words}));WriteNew("test-result.txt",Encoding.ASCII.GetBytes(tests.ToString(System.Globalization.CultureInfo.InvariantCulture)));
        void WriteNew(string name,byte[] bytes){using var file=new FileStream(Path.Combine(project,name),FileMode.CreateNew,FileAccess.Write,FileShare.None);file.Write(bytes);file.Flush(true);}
    }
    internal static string Compile(string tools,string project,string assemblyName,string[] sourceNames,string outputName)
    {
        var assets=SessionPowerShellToolchain.ReadAssets().Files;
        Assembly Load(string name)
        {
            var asset=assets.Single(a=>a.Path==name);var path=Path.Combine(tools,name);
            using(var input=File.OpenRead(path))if(input.Length!=asset.Length || Convert.ToHexString(SHA256.HashData(input))!=asset.SHA256)throw WfpNative.Contract("DevelopmentCompilerAssetChanged");
            return AssemblyLoadContext.Default.LoadFromAssemblyPath(path);
        }
        var common=Load("Microsoft.CodeAnalysis.dll");var csharp=Load("Microsoft.CodeAnalysis.CSharp.dll");
        var treeType=common.GetType("Microsoft.CodeAnalysis.SyntaxTree",true)!;
        var referenceType=common.GetType("Microsoft.CodeAnalysis.MetadataReference",true)!;
        var parse=csharp.GetType("Microsoft.CodeAnalysis.CSharp.CSharpSyntaxTree",true)!.GetMethods()
            .Single(m=>m.Name=="ParseText" && m.GetParameters()[0].ParameterType==typeof(string) && m.GetParameters().Skip(1).All(p=>p.HasDefaultValue));
        var trees=Array.CreateInstance(treeType,sourceNames.Length);int index=0;
        foreach(var name in sourceNames)trees.SetValue(Invoke(parse,null,File.ReadAllText(WindowsPathSeal.Child(project,name))),index++);
        var referenceAssets=assets.Where(a=>a.Path.StartsWith("ref/",StringComparison.Ordinal) && a.Path.EndsWith(".dll",StringComparison.Ordinal)).ToArray();
        if(referenceAssets.Length<50)throw WfpNative.Contract("DevelopmentReferenceSetMissing");
        var references=Array.CreateInstance(referenceType,referenceAssets.Length);
        var fromFile=referenceType.GetMethods().Single(m=>m.Name=="CreateFromFile" && m.GetParameters().Skip(1).All(p=>p.HasDefaultValue));index=0;
        foreach(var asset in referenceAssets)
        {
            var path=WindowsPathSeal.Child(tools,asset.Path);
            using(var input=File.OpenRead(path))if(input.Length!=asset.Length || Convert.ToHexString(SHA256.HashData(input))!=asset.SHA256)throw WfpNative.Contract("DevelopmentReferenceChanged");
            references.SetValue(Invoke(fromFile,null,path),index++);
        }
        var optionsType=csharp.GetType("Microsoft.CodeAnalysis.CSharp.CSharpCompilationOptions",true)!;
        var outputKind=Enum.Parse(common.GetType("Microsoft.CodeAnalysis.OutputKind",true)!,"DynamicallyLinkedLibrary");
        var constructor=optionsType.GetConstructors().Where(c=>c.GetParameters()[0].ParameterType==outputKind.GetType() && c.GetParameters().Skip(1).All(p=>p.HasDefaultValue)).OrderByDescending(c=>c.GetParameters().Length).First();
        var options=Invoke(constructor,null,outputKind);
        var create=csharp.GetType("Microsoft.CodeAnalysis.CSharp.CSharpCompilation",true)!.GetMethods().Single(m=>m.Name=="Create" && m.GetParameters().Length==4);
        var compilation=create.Invoke(null,new[]{assemblyName,trees,references,options})!;
        var emit=compilation.GetType().GetMethods().Where(m=>m.Name=="Emit" && m.GetParameters()[0].ParameterType==typeof(Stream) && m.GetParameters().Skip(1).All(p=>p.HasDefaultValue)).OrderByDescending(m=>m.GetParameters().Length).First();
        var assemblyPath=WindowsPathSeal.Child(project,outputName);
        using(var output=new FileStream(assemblyPath,FileMode.CreateNew,FileAccess.Write,FileShare.None))
        {
            var result=Invoke(emit,compilation,output)!;
            if(result.GetType().GetProperty("Success")!.GetValue(result) is not true)throw WfpNative.Contract("DevelopmentCompilationFailed");
            output.Flush(true);
        }
        return assemblyPath;
    }
    private static object? Invoke(MethodBase method,object? target,params object?[] required)
    {
        var parameters=method.GetParameters();var values=new object?[parameters.Length];required.CopyTo(values,0);
        for(int i=required.Length;i<values.Length;i++)
        {
            if(!parameters[i].HasDefaultValue)throw WfpNative.Contract("DevelopmentCompilerSignatureChanged");
            var value=parameters[i].DefaultValue;
            values[i]=value is Missing or DBNull?(parameters[i].ParameterType.IsValueType?Activator.CreateInstance(parameters[i].ParameterType):null):value;
        }
        try{return method is ConstructorInfo constructor?constructor.Invoke(values):method.Invoke(target,values);}
        catch(TargetInvocationException error)when(error.InnerException is not null){ExceptionDispatchInfo.Capture(error.InnerException).Throw();throw;}
    }
}
