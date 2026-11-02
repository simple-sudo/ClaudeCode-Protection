using System.Reflection;
using System.Runtime.Loader;
using System.Text;
using System.Text.Json;
using ClaudeCodeProtection.Workspaces;

namespace ProtectionLifecycle;

// Runs only in the original confined compiler after the owner sealed privacy
// gate. Ordinary qualification uses only its new reviewed nonsecret fixture.
internal static class CallerCSharpProject
{
    internal static void BuildAndRun(string tools,string project,byte[] baseline)
    {
        var task=CSharpProjectTask.Parse(baseline);
        foreach(var file in task.Baseline.Files)
            if(!File.ReadAllBytes(WindowsPathSeal.Child(project,file.Path)).AsSpan().SequenceEqual(file.Content))throw WfpNative.Contract("CallerProjectInputChanged");
        foreach(var file in task.ModifiedFiles())
        {
            if(!task.Definition.Sources.Contains(file.Path,StringComparer.Ordinal))continue;
            using var output=new FileStream(WindowsPathSeal.Child(project,file.Path),FileMode.Open,FileAccess.Write,FileShare.None);
            output.SetLength(0);output.Write(file.Content);output.Flush(true);
        }
        var directory=WindowsPathSeal.Child(project,CSharpProjectTask.OutputDirectory);
        if(Directory.Exists(directory) || File.Exists(directory))throw WfpNative.Contract("CallerProjectFreshOutputRequired");
        Directory.CreateDirectory(directory);
        var path=BundledProjectDevelopment.Compile(tools,project,"CpcProject",task.Definition.Sources,CSharpProjectTask.Outputs[0]);
        var stdout=new BoundedText();var stderr=new BoundedText();var originalOut=Console.Out;var originalError=Console.Error;var originalDirectory=Environment.CurrentDirectory;
        int exit,tests;
        try
        {
            Console.SetOut(stdout);Console.SetError(stderr);
            // Identity/privacy gates ran in the fixed task root. User project
            // relative I/O now belongs in its copied project, never the host.
            Directory.SetCurrentDirectory(project);
            var compiled=AssemblyLoadContext.Default.LoadFromAssemblyPath(path);
            int Run(string type,string stage)
            {
                var method=compiled.GetType(type,false)?.GetMethod("Run",BindingFlags.Public|BindingFlags.Static|BindingFlags.DeclaredOnly,null,Type.EmptyTypes,null);
                if(method is null || method.ReturnType!=typeof(int) || method.ContainsGenericParameters)throw new ProjectTaskException(new("Entry",Array.Empty<ProjectCompilerDiagnostic>()));
                try{return (int)method.Invoke(null,null)!;}
                catch(TargetInvocationException){throw new ProjectTaskException(new(stage,Array.Empty<ProjectCompilerDiagnostic>()));}
            }
            exit=Run(task.Definition.EntryType,"Run");
            if(exit!=0)throw new ProjectTaskException(new("Run",Array.Empty<ProjectCompilerDiagnostic>()));
            tests=Run(task.Definition.TestType,"Tests");
            if(tests!=task.Definition.ExpectedTests)throw new ProjectTaskException(new("Tests",Array.Empty<ProjectCompilerDiagnostic>()));
        }
        finally{Console.SetOut(originalOut);Console.SetError(originalError);Directory.SetCurrentDirectory(originalDirectory);}
        Write(CSharpProjectTask.Outputs[1],JsonSerializer.SerializeToUtf8Bytes(new{SchemaVersion=1,ExitCode=exit,TestsPassed=tests}));
        Write(CSharpProjectTask.Outputs[2],Encoding.ASCII.GetBytes(tests.ToString(System.Globalization.CultureInfo.InvariantCulture)));
        Write(CSharpProjectTask.Outputs[3],Encoding.UTF8.GetBytes(stdout.ToString()));Write(CSharpProjectTask.Outputs[4],Encoding.UTF8.GetBytes(stderr.ToString()));
        void Write(string relative,byte[] bytes){using var file=new FileStream(WindowsPathSeal.Child(project,relative),FileMode.CreateNew,FileAccess.Write,FileShare.None);file.Write(bytes);file.Flush(true);}
    }
    private sealed class BoundedText : TextWriter
    {
        private readonly StringBuilder text=new();
        public override Encoding Encoding=>Encoding.UTF8;
        public override void Write(char value){lock(text){if(text.Length>=4096)throw new IOException("Caller project console output bound");text.Append(value);}}
        public override string ToString(){lock(text)return text.ToString();}
    }
}
