using System.Reflection;
using System.Runtime.ExceptionServices;
using System.Security.Cryptography;

internal static class ControlFileGateCases
{
    internal static void Run(Assembly library)
    {
        const BindingFlags flags=BindingFlags.NonPublic|BindingFlags.Static;var checks=0;
        var type=library.GetType("ProtectionLifecycle.HostPrivacyProbe",true)!;
        object? Call(string name,params object?[] args)
        {try{return type.GetMethod(name,flags)!.Invoke(null,args);}catch(TargetInvocationException e)when(e.InnerException is not null){ExceptionDispatchInfo.Capture(e.InnerException).Throw();throw;}}
        void Require(bool value){if(!value)throw new InvalidDataException("Control file fixture differs");checks++;}
        void Refuse(Action action){try{action();}catch(InvalidDataException){checks++;return;}throw new InvalidDataException("Foreign control target accepted");}
        var programFiles=Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);var release=new string('a',32);
        for(var i=23;i<33;i++)
        {
            var path=(string)Call("ControlFilePath",programFiles,release,i)!;
            var leaf=i<27?"ClaudeCodeProtection-State/installation.json":i<30?"ClaudeCodeProtection-State/current.json":"ClaudeCodeProtection/versions/"+release+"/bin/admin/ProtectionLifecycle.dll";
            Require(path==Path.Combine(programFiles,leaf.Replace('/','\\')));
            Call("RequireControlFileTarget",path,0,programFiles,release,i);checks++;
            Refuse(()=>Call("RequireControlFileTarget",path+".foreign",0,programFiles,release,i));
            Refuse(()=>Call("RequireControlFileTarget",path,1,programFiles,release,i));
            Refuse(()=>Call("RequireControlFileTarget",null,0,programFiles,release,i));
        }
        Refuse(()=>Call("ControlFilePath",programFiles,release,22));Refuse(()=>Call("ControlFilePath",programFiles,release,33));
        Refuse(()=>Call("ControlFilePath",programFiles,"../foreign",23));
        var root=Path.Combine(AppContext.BaseDirectory,"own-control-file-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(root);
        var file=Path.Combine(root,"nonsecret.bin");File.WriteAllBytes(file,new byte[]{1,3,5,7});var digest=SHA256.HashData(File.ReadAllBytes(file));
        using(var held=new FileStream(file,FileMode.Open,FileAccess.Read,FileShare.ReadWrite|FileShare.Delete))
        {
            foreach(var i in Enumerable.Range(23,10))
            {
                var contract=library.GetType("ClaudeCodeProtection.Workspaces.HostPrivacyContract",true)!;
                var right=(uint)contract.GetMethod("ControlFileAccess",flags)!.Invoke(null,new object[]{i})!;
                Call("AssertControlFileMaintenanceAccess",held.SafeFileHandle,right);checks++;
                Require((int)Call("ControlFileOpen",file,i)! ==0);
            }
            Refuse(()=>Call("AssertControlFileMaintenanceAccess",held.SafeFileHandle,0x1fffffu));
        }
        using(var locked=new FileStream(file,FileMode.Open,FileAccess.Read,FileShare.Read))
        {
            Call("AssertControlFileMaintenanceAccess",locked.SafeFileHandle,2u);checks++;
            Require((int)Call("ControlFileOpen",file,24)! ==32); // not ACCESS_DENIED
        }
        Require(digest.AsSpan().SequenceEqual(SHA256.HashData(File.ReadAllBytes(file))));
        Console.WriteLine($"PASS {checks} control-file binding/read-only own DACL-positive/minimal opens; restrictive share gives32 while DACL allows, never5; fixture unchanged. Own ordinary file only, no installation/private state/ACL mutation/UAC/Job/LPAC. Retained fixture={root}");
    }
}
