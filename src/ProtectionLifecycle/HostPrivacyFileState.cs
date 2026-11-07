using System.ComponentModel;
using System.Runtime.InteropServices;

namespace ProtectionLifecycle;

internal sealed partial class HostPrivacyProbe
{
    private sealed record FileState(string Identity,int MissingParentDepth);
    private static bool IsMissing(Exception error)=>error is Win32Exception native?native.NativeErrorCode is 2 or 3:
        error is IOException && (error.HResult==unchecked((int)0x80070002) || error.HResult==unchecked((int)0x80070003));
    // Only the fixed reset-settings slot can select absence. This is metadata,
    // not an ACL denial or permission to read another resource. At most the
    // immediate parent or user-profile grandparent may serve as its anchor.
    private static FileState ObserveFileState(string path,bool allowMissing)
    {
        try{return new(FileIdentity(path),0);}
        catch(Exception error)when(allowMissing && IsMissing(error)){}
        var parent=Path.GetDirectoryName(path)??throw WfpNative.Contract("ResetFileParentRequired");
        for(var depth=1;depth<=2;depth++)
        {
            string identity;
            try{identity=DirectoryIdentity(parent);}
            catch(Exception error)when(depth==1 && IsMissing(error))
            {parent=Path.GetDirectoryName(parent)??throw WfpNative.Contract("ResetFileParentRequired");continue;}
            // Recheck the exact original path after observing the anchor;
            // creation during capture is a conflict, never a new snapshot.
            var missing=false;
            try{_=FileIdentity(path);}
            catch(Exception error)when(IsMissing(error)){missing=true;}
            if(!missing)throw WfpNative.Contract("ResetFileAppearedDuringCapture");
            return new(identity,depth);
        }
        throw WfpNative.Contract("ResetFileAbsenceUnconfirmed");
    }
    private static string DirectoryIdentity(string path)
    {
        for(var p=path;p is not null;p=Path.GetDirectoryName(p))
            if((File.GetAttributes(p)&FileAttributes.ReparsePoint)!=0)throw WfpNative.Contract("HostPrivacyRedirectedTargetRefused");
        using var handle=CreateFile(path,0x80,7,IntPtr.Zero,3,0x42200000,IntPtr.Zero);
        if(handle.IsInvalid || !GetFileInformationByHandle(handle,out var info))throw new Win32Exception(Marshal.GetLastWin32Error(),"Reset target parent metadata");
        if((info.Attributes&0x410)!=0x10)throw WfpNative.Contract("ResetFileOrdinaryParentRequired");
        return info.Volume.ToString("X8")+info.IndexHigh.ToString("X8")+info.IndexLow.ToString("X8");
    }
    private static void RequireMissingTarget(bool allowMissing,int depth)
    {
        if(depth!=0 && (!allowMissing || depth is not (1 or 2)))
            throw WfpNative.Contract("ResetFileOptionalTargetDiffers");
    }
    private static void AssertFileStateCurrent(Target target)
    {
        var allowMissing=target.Check.AllowsOwnerObservedAbsence;
        RequireMissingTarget(allowMissing,target.MissingParentDepth);
        var observed=ObserveFileState(target.Path,allowMissing);
        if(observed.Identity!=target.Identity || observed.MissingParentDepth!=target.MissingParentDepth)
            throw WfpNative.Contract("HostPrivacyFileStateChanged");
    }
}
