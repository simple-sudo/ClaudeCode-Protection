using ProtectionLifecycle;
using System.Text.Json;

if(args.Length!=1 || args[0] is not ("install-inactive" or "update-inactive"))
{
    Console.Error.WriteLine("Usage: ProtectionBootstrap install-inactive | update-inactive (pinned original never-admitted installation only)");return 64;
}
try
{
    var result=args[0]=="install-inactive"?BootstrapInstaller.InstallFresh():BootstrapInstaller.UpdateNeverAdmitted();Console.WriteLine(result.Report);return result.ExitCode;
}
catch(Exception ex)
{
    Console.Error.WriteLine(JsonSerializer.Serialize(new {Status="INSTALL_NOT_COMPLETED",FailureType=ex.GetType().Name,Failures=Describe(ex),ProtectionQualified=false}));
    return 125;
}
static object Describe(Exception ex)=>new {Type=ex.GetType().Name,ex.Message,Code=ex is System.ComponentModel.Win32Exception native?native.NativeErrorCode:(int?)null,
    Stage=ex.Data["Stage"]?.ToString(),Inner=ex.InnerException is null?null:Describe(ex.InnerException)};
