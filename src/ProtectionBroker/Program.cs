namespace ProtectionBroker;

// No installer, process launcher, arbitrary admin command channel or automatic
// elevation. Normal build/launch gates remain closed pending qualification.
internal static class Program
{
    private static int Main(string[] args)
    {
        if(args.Length>1 && args[0]=="resource-powershell")
            return ProtectionLifecycle.InstalledBroker.RunRestrictedPowerShell(args.Skip(1).ToArray());
        if(args.Length==4 && args[0]=="process-workspace-pipe")
        {
            try
            {
                if(!int.TryParse(args[1],System.Globalization.NumberStyles.None,System.Globalization.CultureInfo.InvariantCulture,out var owner) || owner<=0)return 64;
                return ProtectionLifecycle.InstalledBroker.ProcessWorkspacePipe(owner,args[2],args[3]);
            }
            catch(Exception ex){Console.Error.WriteLine("Workspace data channel not confirmed: "+ex.GetType().Name+"; code="+ex.HResult);return 125;}
        }
        if(args.Length==2 && args[0]=="process-workspace-data" || args.Length==3 && args[0]=="export-workspace-data")
        {
            try
            {
                if(args[0]=="process-workspace-data")
                {var data=ProtectionLifecycle.InstalledBroker.ProcessWorkspaceData(args[1]);Console.WriteLine(data.Report);return data.ExitCode;}
                var bytes=ProtectionLifecycle.InstalledBroker.ExportWorkspaceData(args[1],args[2]);
                using var output=Console.OpenStandardOutput();output.Write(bytes);output.Flush();return 0;
            }
            catch(Exception ex){Console.Error.WriteLine("Workspace data operation not confirmed: "+ex.GetType().Name+"; code="+ex.HResult);return 125;}
        }
        if(args.Length==5 && args[0]=="configure-session-environment")
        {
            try
            {
                var configured=ProtectionLifecycle.InstalledBroker.ConfigureEnvironmentExpectations(args[1],args[2],args[3],args[4]);
                Console.WriteLine(configured.Report);return configured.ExitCode;
            }
            catch(Exception ex){Console.Error.WriteLine("Environment intent not confirmed: "+ex.GetType().Name+"; code="+ex.HResult);return 125;}
        }
        if (args.Length != 1 || args[0] is not ("inspect-etw-provider-access" or "recover-etw-provider-access" or "inspect-manifest-read-access" or "recover-manifest-read-access" or "qualify-toolchain" or "recover-session-resources" or "inspect-resource-recovery" or "recover-unstarted-session-resources" or "qualify-resource-recovery" or "qualify-resources" or "migrate-session-network" or "inspect-session-environment" or "launch" or "session-synthetic" or "quarantine" or "inspect-runtime" or "inspect-wfp" or "qualify-wfp-objects" or "inspect-installed-fence" or "qualify-admission" or "qualify-network" or "qualify-gpu" or "qualify-watchdog" or "admission-child"))
        {
            Console.Error.WriteLine("ProtectionBroker inspect-runtime | inspect-wfp; inspect-installed-fence (installed read-only); quarantine | qualify-admission | qualify-network | qualify-gpu | qualify-watchdog (installed); qualify-wfp-objects (protected qualification host). Management requires existing elevation.");
            Console.Error.WriteLine("Installed intent management: inspect-session-environment | configure-session-environment EXPECTED_SHA_OR_none WINDOWS_TIMEZONE USER_LOCALE SYSTEM_LOCALE. This never changes Windows settings or grants launch.");
            Console.Error.WriteLine("Installed inactive network maintenance: migrate-session-network (closed admissions, full quarantine; no launch permission).");
            Console.Error.WriteLine("Installed bounded qualification: qualify-resources (fixed offline workspace/PowerShell/denial fixture only; no formal launch or network grant).");
            Console.Error.WriteLine("Installed resource recovery: recover-session-resources; qualify-resource-recovery (fixed closed-Job cleanup checkpoint only; no forced crash).");
            Console.Error.WriteLine("Installed toolchain qualification: qualify-toolchain (fixed reviewed Git; offline init/add/commit in a fresh task workspace only).");
            Console.Error.WriteLine("Resource recovery: inspect-resource-recovery (read only); recover-unstarted-session-resources (explicit v2 creation with no process binding only).");
            Console.Error.WriteLine("Fixed OS manifest-read resource: inspect-manifest-read-access (read only); recover-manifest-read-access (exact original DACL, closed Job and quarantine required).");
            Console.Error.WriteLine("Installed data maintenance: process-workspace-data EXACT_INPUT_SHA256 (redirected bundle bytes); export-workspace-data SESSION EXACT_RESULT_SHA256 (raw bundle stdout). No project code execution or network grant.");
            return 64;
        }
        // The current artifact has not obtained bounded runtime/install
        // clearance. Authorization to perform qualification is not clearance
        // for an arbitrary invocation or a session permit.
        if (args[0] is "migrate-session-network" or "session-synthetic" or "qualify-wfp-objects" or "qualify-admission" or "qualify-network" or "qualify-gpu" or "qualify-watchdog")
        {
            Console.Error.WriteLine("SYSTEM_ARTIFACT_NOT_QUALIFIED: bounded runtime/install clearance is required. No system operation was started.");
            return 125;
        }
        try
        {
            if(args[0]=="admission-child")return ProtectionLifecycle.InstalledBroker.RunAdmissionCanary();
            var result = args[0] switch {
                "qualify-toolchain" => ProtectionLifecycle.InstalledBroker.QualifyToolchain(),
                "recover-session-resources" => ProtectionLifecycle.InstalledBroker.RecoverSessionResources(),
                "inspect-resource-recovery" => ProtectionLifecycle.InstalledBroker.InspectResourceRecovery(),
                "recover-unstarted-session-resources" => ProtectionLifecycle.InstalledBroker.RecoverUnstartedSessionResources(),
                "inspect-etw-provider-access" => ProtectionLifecycle.InstalledBroker.InspectEtwProviderAccess(),
                "recover-etw-provider-access" => ProtectionLifecycle.InstalledBroker.RecoverEtwProviderAccess(),
                "inspect-manifest-read-access" => ProtectionLifecycle.InstalledBroker.InspectManifestReadAccess(),
                "recover-manifest-read-access" => ProtectionLifecycle.InstalledBroker.RecoverManifestReadAccess(),
                "qualify-resource-recovery" => ProtectionLifecycle.InstalledBroker.QualifyResourceRecovery(),
                "qualify-resources" => ProtectionLifecycle.InstalledBroker.QualifyResources(),
                "migrate-session-network" => ProtectionLifecycle.InstalledBroker.MigrateSessionNetwork(),
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
