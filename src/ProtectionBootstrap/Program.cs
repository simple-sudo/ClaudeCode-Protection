if(args.Length!=1 || args[0] is not ("install-inactive" or "update-inactive"))
{
    Console.Error.WriteLine("Usage: ProtectionBootstrap install-inactive | update-inactive (currently blocked by incident hold)");return 64;
}
// The current integration has no installation clearance following 0x1E.
// Historical pinned installers remain in Lifecycle; direct entry must not
// bypass the incident hold or mutate the installed selection.
Console.Error.WriteLine("SYSTEM_VALIDATION_BLOCKED: Installation/update is suspended pending crash investigation and artifact clearance. No installation was started.");
return 125;
