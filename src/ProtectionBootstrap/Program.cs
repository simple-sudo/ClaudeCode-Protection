if(args.Length!=1 || args[0] is not ("install-inactive" or "update-inactive"))
{
    Console.Error.WriteLine("Usage: ProtectionBootstrap update-inactive (reviewed protected bootstrap only); install-inactive remains unqualified");return 64;
}
// Human authorization has reopened bounded qualification. Only the existing
// inactive-update owner is reviewed here: fixed protected host, embedded exact
// package, pinned prior version, closed admissions and quarantined resources.
// This is neither a runtime clearance nor a general installation unlock.
if(args[0]=="install-inactive")
{
    Console.Error.WriteLine("SYSTEM_ARTIFACT_NOT_QUALIFIED: fresh installation is outside this inactive-update qualification scope.");
    return 125;
}
try
{
    var result=ProtectionLifecycle.BootstrapInstaller.UpdatePinnedInactive();
    Console.WriteLine(result.Report);return result.ExitCode;
}
catch(Exception ex)
{
    // Private paths, state bytes and command arguments do not belong in UI.
    Console.Error.WriteLine("Inactive update not confirmed: "+ex.GetType().Name+"; code="+ex.HResult);
    return 125;
}
