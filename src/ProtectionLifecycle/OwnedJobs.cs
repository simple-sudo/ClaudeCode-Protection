// Concrete kernel owner. Atomic admission reserves one creation using JOB_LIST;
// there is no post-creation Assign or PID-based termination fallback.
internal sealed partial class OwnedKernelJob : IDisposable
{
    internal const uint RequiredLimits=0x2000; // KILL_ON_JOB_CLOSE; no breakaway flags.
    private readonly ProtectedState state;
    private readonly OwnedJobIntent intent;
    private readonly SafeJobHandle handle;
    private readonly PrivateJobNamespace? jobNamespace;
    private readonly string? originalIntentHash;
    private bool disposed;
    private bool admissionClaimed,admissionClosed;
    private bool creatorGrantAttempted,creatorReleaseConfirmed;
    internal string JobId=>intent.JobId;
    internal string SessionZeroCreatorSid=>intent.CreatorServiceSid??throw WfpNative.Contract("SessionZeroCreatorJobRequired");
    internal bool AtomicAdmissionReserved=>admissionClaimed;
    private OwnedKernelJob(ProtectedState state,OwnedJobIntent intent,SafeJobHandle handle,PrivateJobNamespace? jobNamespace,string? originalIntentHash=null)
    {this.state=state;this.intent=intent;this.handle=handle;this.jobNamespace=jobNamespace;this.originalIntentHash=originalIntentHash;}

    private void AssertHeld()
    {
        if(disposed || handle.IsClosed || handle.IsInvalid)throw new ObjectDisposedException(nameof(OwnedKernelJob));
        state.AssertHeld();jobNamespace?.AssertHeld();KernelJobSeal.AssertOwned(handle,intent);
    }

    public void Dispose(){if(disposed)return;disposed=true;try{handle.Dispose();}finally{jobNamespace?.Dispose();}} // Closing is not a zero-process observation.
    private static Win32Exception Error(string stage){var result=new Win32Exception(Marshal.GetLastWin32Error());result.Data["Stage"]=stage;return result;}
}
