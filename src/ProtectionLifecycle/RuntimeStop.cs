using System.Diagnostics;
using System.IO.Pipes;
using System.Text;
using System.Text.Json;

namespace ProtectionLifecycle;

internal sealed record RuntimeStop(string SessionId,string Reason,bool AdmissionClosed,bool QuarantineObservedBeforeStop,
    long QuarantineAtMs,long JobStopAtMs,JobSnapshot? FinalJob,WfpErrorEvidence[] Failures)
{
    internal const string ResourceTerminalReason="OFFLINE_RESOURCE_QUALIFICATION_TERMINAL";
    internal const string GpuTerminalReason="FIXED_GPU_QUALIFICATION_TERMINAL";
    internal const string HostGpuTerminalReason="FIXED_HOST_GPU_REFERENCE_TERMINAL";
    internal const string OfflineConsoleTerminalReason="FIXED_OFFLINE_CONSOLE_TERMINAL";
    internal static string OfflineTlsTerminalReason(OfflineTlsProbe probe)=>probe switch {
        OfflineTlsProbe.Schannel=>"FIXED_OFFLINE_SCHANNEL_ACQUISITION_TERMINAL",
        OfflineTlsProbe.OpenSsl=>"FIXED_OFFLINE_OPENSSL_EXCHANGE_TERMINAL",
        _=>throw WfpNative.Contract("UnknownOfflineTlsProbe")
    };

    internal bool ConfirmsClosedResources(string sessionId,string jobId) =>
        Reason==ResourceTerminalReason && ConfirmsClosedJob(sessionId,jobId);

    internal bool ConfirmsClosedGpu(string sessionId,string jobId) =>
        Reason==GpuTerminalReason && ConfirmsClosedJob(sessionId,jobId);
    internal bool ConfirmsClosedHostGpu(string sessionId,string jobId) =>
        Reason==HostGpuTerminalReason && ConfirmsClosedJob(sessionId,jobId);
    internal bool ConfirmsClosedOfflineTls(OfflineTlsProbe probe,string sessionId,string jobId) =>
        Reason==OfflineTlsTerminalReason(probe) && ConfirmsClosedJob(sessionId,jobId);
    internal bool ConfirmsClosedOfflineConsole(string sessionId,string jobId) =>
        Reason==OfflineConsoleTerminalReason && ConfirmsClosedJob(sessionId,jobId);

    private bool ConfirmsClosedJob(string sessionId,string jobId) =>
        SessionId==sessionId && AdmissionClosed && QuarantineObservedBeforeStop &&
        QuarantineAtMs>=0 && JobStopAtMs>=QuarantineAtMs && Failures is {Length:0} &&
        FinalJob is {ExpectedLimits:true,ObservedZero:true} final && final.JobId==jobId;

    internal bool MatchesResourceExport(RuntimeStop reported,JobSnapshot terminal,JobSnapshot completion,string sessionId,string jobId)
    {
        if(!ConfirmsClosedResources(sessionId,jobId) || !reported.ConfirmsClosedResources(sessionId,jobId) ||
            QuarantineAtMs!=reported.QuarantineAtMs || JobStopAtMs!=reported.JobStopAtMs)return false;
        var at=FinalJob!.AtUtc;
        return !string.IsNullOrEmpty(at) && reported.FinalJob!.AtUtc==at &&
            MatchesZero(terminal) && MatchesZero(completion);

        bool MatchesZero(JobSnapshot value)=>value.JobId==jobId && value.ExpectedLimits && value.ObservedZero && value.AtUtc==at;
    }
}
