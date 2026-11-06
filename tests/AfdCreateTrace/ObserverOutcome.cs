using System.IO;

namespace AfdObserverProtocol;

internal enum ObserverStage
{
    Inputs=1,FreshRootCheck,DriverOpen,DriverHash,TokenBefore,SafetyBefore,CreateOwnedDirectory,
    DirectorySeal,StartNewTrace,ConfirmOwnTrace,EnableFixedProvider,EvidenceReadback,PublishReady,
    Observe,StopOwnTrace,TokenAfter,TerminalPublication,AdministrativeIdentityRequired
}

// A finite, nonsecret error channel that survives UAC shell launch. A failed
// process cannot always publish a file before creating/sealing its fresh root.
// This carries only the first failed stage, never raw Token/path/error text.
// It does not attest trace ownership, Stop success or absence of side effects.
internal static class ObserverOutcome
{
    private const uint Tag=0x43500000;
    internal static int Failure(ObserverStage stage)
    {
        if(!Enum.IsDefined(stage))throw new InvalidDataException("ObserverStageInvalid");
        return checked((int)(Tag|(uint)stage));
    }
    internal static ObserverStage? Decode(int code)
    {
        var value=unchecked((uint)code);
        if((value&0xffffff00)!=Tag)return null;
        var stage=(ObserverStage)(value&0xff);
        return Enum.IsDefined(stage)?stage:null;
    }
}
