namespace ProtectionBroker;

// No installer, process launcher, arbitrary admin command channel or automatic
// elevation. Normal build/launch gates remain closed pending qualification.
internal static class Program
{
    private static int Main(string[] args)
    {
        if(args.Length==5 && args[0]=="configure-session-environment")
        {
            try
            {
                var configured=ProtectionLifecycle.InstalledBroker.ConfigureEnvironmentExpectations(args[1],args[2],args[3],args[4]);
                Console.WriteLine(configured.Report);return configured.ExitCode;
            }
            catch(Exception ex){Console.Error.WriteLine("Environment intent not confirmed: "+ex.GetType().Name+"; code="+ex.HResult);return 125;}
        }
        if (args.Length != 1 || args[0] is not ("inspect-session-environment" or "launch" or "session-synthetic" or "quarantine" or "inspect-runtime" or "inspect-wfp" or "qualify-wfp-objects" or "inspect-installed-fence" or "qualify-admission" or "qualify-network" or "qualify-gpu" or "qualify-watchdog" or "admission-child"))
        {
            Console.Error.WriteLine("ProtectionBroker inspect-runtime | inspect-wfp; inspect-installed-fence (installed read-only); quarantine | qualify-admission | qualify-network | qualify-gpu | qualify-watchdog (installed); qualify-wfp-objects (protected qualification host). Management requires existing elevation.");
            Console.Error.WriteLine("Installed intent management: inspect-session-environment | configure-session-environment EXPECTED_SHA_OR_none WINDOWS_TIMEZONE USER_LOCALE SYSTEM_LOCALE. This never changes Windows settings or grants launch.");
            return 64;
        }
        // Incident hold precedes elevation, installed-state access and every
        // native qualification call. Clearing it requires a reviewed source
        // change after crash investigation, never a flag or cached PASS.
        if (args[0] is "session-synthetic" or "qualify-wfp-objects" or "qualify-admission" or "qualify-network" or "qualify-gpu" or "qualify-watchdog")
        {
            Console.Error.WriteLine("SYSTEM_VALIDATION_BLOCKED: 0x1E crash investigation and artifact clearance are required. No qualification was started.");
            return 125;
        }
        try
        {
            if(args[0]=="admission-child")return ProtectionLifecycle.InstalledBroker.RunAdmissionCanary();
            var result = args[0] switch {
                "launch" => ProtectionLifecycle.InstalledBroker.LaunchDevelopmentSession(),
                "inspect-session-environment" => ProtectionLifecycle.InstalledBroker.InspectEnvironmentExpectations(),
                "session-synthetic" => ProtectionLifecycle.InstalledBroker.RunSyntheticSession(),
                "inspect-runtime" => ProtectionLifecycle.InstalledBroker.InspectRuntime(),
                "inspect-wfp" => ProtectionLifecycle.InstalledBroker.InspectWfp(),
                "qualify-wfp-objects" => ProtectionLifecycle.WfpObjectContract.Qualify(),
                "inspect-installed-fence" => ProtectionLifecycle.InstalledBroker.InspectInstalledFence(),
                "qualify-admission" => ProtectionLifecycle.InstalledBroker.QualifyAtomicAdmission(),
                "qualify-network" => ProtectionLifecycle.InstalledBroker.QualifyNetwork(),
                "qualify-gpu" => ProtectionLifecycle.InstalledBroker.QualifyGpu(),
                "qualify-watchdog" => ProtectionLifecycle.InstalledBroker.QualifyWatchdog(),
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
