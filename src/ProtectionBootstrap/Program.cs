if(args.Length!=1 || args[0] is not ("install-inactive" or "update-inactive" or "recover-reviewed-timezone-read-access" or "recover-reviewed-legacy-creator"))
{
    Console.Error.WriteLine("Usage: ProtectionBootstrap update-inactive | recover-reviewed-timezone-read-access | recover-reviewed-legacy-creator (reviewed protected bootstrap only)");return 64;
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
    var result=args[0] switch {
        "recover-reviewed-timezone-read-access"=>ProtectionLifecycle.BootstrapInstaller.RecoverReviewedTimeZoneReadAccess(),
        "recover-reviewed-legacy-creator"=>ProtectionLifecycle.BootstrapInstaller.RecoverReviewedLegacyCreator(),
        _=>ProtectionLifecycle.BootstrapInstaller.UpdatePinnedInactiveWithFeedback()
    };
    (result.ExitCode==0?Console.Out:Console.Error).WriteLine(result.Report);
    return result.ExitCode;
}
catch(Exception ex)
{
    // Private paths, state bytes and command arguments do not belong in UI.
    var operation=args[0] switch {
        "recover-reviewed-timezone-read-access"=>"Timezone recovery",
        "recover-reviewed-legacy-creator"=>"Creator recovery",
        _=>"Inactive update"
    };
    Console.Error.WriteLine(operation+" not confirmed: "+ex.GetType().Name+"; code="+ex.HResult+"; stage=START");
    return 125;
}
