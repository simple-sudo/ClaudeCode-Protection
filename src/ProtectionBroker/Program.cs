namespace ProtectionBroker;

// No installer, process launcher, arbitrary admin command channel or automatic
// elevation. Normal build/launch gates remain closed pending qualification.
internal static class Program
{
    private static int Main(string[] args)
    {
        if (args.Length != 1 || args[0] is not ("quarantine" or "inspect-runtime" or "inspect-wfp" or "qualify-wfp-objects" or "inspect-installed-fence" or "qualify-admission" or "admission-child"))
        {
            Console.Error.WriteLine("ProtectionBroker inspect-runtime | inspect-wfp; inspect-installed-fence (installed read-only); quarantine | qualify-admission (installed); qualify-wfp-objects (protected qualification host). Management requires existing elevation.");
            return 64;
        }
        try
        {
            if(args[0]=="admission-child")return ProtectionLifecycle.InstalledBroker.RunAdmissionCanary();
            var result = args[0] switch {
                "inspect-runtime" => ProtectionLifecycle.InstalledBroker.InspectRuntime(),
                "inspect-wfp" => ProtectionLifecycle.InstalledBroker.InspectWfp(),
                "qualify-wfp-objects" => ProtectionLifecycle.WfpObjectContract.Qualify(),
                "inspect-installed-fence" => ProtectionLifecycle.InstalledBroker.InspectInstalledFence(),
                "qualify-admission" => ProtectionLifecycle.InstalledBroker.QualifyAtomicAdmission(),
                _ => ProtectionLifecycle.InstalledBroker.Quarantine()
            };
            Console.WriteLine(result.Report);
            return result.ExitCode;
        }
        catch (Exception ex)
        {
            var code = ex is System.ComponentModel.Win32Exception native ? native.NativeErrorCode : ex.HResult;
            // Do not disclose protected state, arguments or private paths.
            Console.Error.WriteLine("Operation not confirmed: " + ex.GetType().Name + "; code=" + code);
            return 125;
        }
    }
}
