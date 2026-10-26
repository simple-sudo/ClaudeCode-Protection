namespace ProtectionBroker;

// No installer, process launcher, arbitrary admin command channel or automatic
// elevation. Normal build/launch gates remain closed pending qualification.
internal static class Program
{
    private static int Main(string[] args)
    {
        if (args.Length != 1 || args[0] != "quarantine")
        {
            Console.Error.WriteLine("ProtectionBroker quarantine | reinstates installation quarantine and stops registered jobs; requires the verified installed current broker and an existing elevated token");
            return 64;
        }
        try
        {
            var result = ProtectionLifecycle.InstalledBroker.Quarantine();
            Console.WriteLine(result.Report);
            return result.ExitCode;
        }
        catch (Exception ex)
        {
            var code = ex is System.ComponentModel.Win32Exception native ? native.NativeErrorCode : ex.HResult;
            // Do not disclose protected state, arguments or private paths.
            Console.Error.WriteLine("Quarantine not confirmed: " + ex.GetType().Name + "; code=" + code);
            return 125;
        }
    }
}
