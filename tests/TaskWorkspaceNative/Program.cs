namespace ProtectionLifecycle;

internal static class Program
{
    private static int Main(string[] args)
    {
        try
        {
            if(args.Length!=8)throw new ArgumentException("Expected mode, user SID, package name and five session identifiers");
            var sessions=args.Skip(3).ToArray();
            if(args[0]=="prepare")NativeTaskWorkspaceCases.Prepare(args[1],args[2],sessions);
            else if(args[0]=="run")NativeTaskWorkspaceCases.Run(args[1],args[2],sessions);
            else throw new ArgumentException("Mode must be prepare or run");
            return 0;
        }
        catch(Exception error)
        {
            Console.Error.WriteLine(error.GetType().Name+": "+error.Message);
            return 1;
        }
    }
}
