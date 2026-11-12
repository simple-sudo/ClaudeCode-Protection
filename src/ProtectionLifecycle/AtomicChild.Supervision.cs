using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

namespace ProtectionLifecycle;

// Runtime observation of the exact AtomicChild owned by the admission object.
// This partial owns no process/thread handle and cannot resume or replace it.
internal sealed partial class AtomicChild
{
    internal SecurityIdentifier? OfflineConsoleUserSid { get;private set; }
    internal SessionZeroStartupWitness.Win32kObservation? BeforeResumeWin32k {get;private set;}
    internal SessionZeroStartupWitness.SystemCallFilterObservation? BeforeResumeSystemCallFilter {get;private set;}


}
