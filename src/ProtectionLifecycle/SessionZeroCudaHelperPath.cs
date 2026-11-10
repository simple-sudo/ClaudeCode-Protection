namespace ProtectionLifecycle;

// Control transfers in one helper of the SHA-256 pinned NVIDIA image.
// Calls are followed only at their in-helper continuation.
internal sealed class SessionZeroCudaHelperPath
{
    internal const int Caller=0x3a04d3,Entry=0x207a40;
    private const int EarlyAllocationFailure=0x207a77,FailureCleanup=0x20844f;
    private const int FailedObjectCleanup=0x208444,SharedFailureStatus=0x20844c;
    private const int Return=0x20847d;
    private readonly record struct Branch(int Rva,int Target=0,int FallThrough=0);
    private static readonly Branch[] Branches=
    [
        new(0x207a75,0x207a81,0x207a77),
        new(0x207a7c,0x20846a),
        new(0x207aff,0x207b16,0x207b01),
        new(0x207b14,0x207b23),
        new(0x207b4d,0x207b64,0x207b4f),
        new(0x207b62,0x207b71),
        new(0x207b9b,0x207bb2,0x207b9d),
        new(0x207bb0,0x207bbf),
        new(0x207be9,0x207c00,0x207beb),
        new(0x207bfe,0x207c0d),
        new(0x207c37,0x207c4e,0x207c39),
        new(0x207c4c,0x207c5b),
        new(0x207c85,0x207c9c,0x207c87),
        new(0x207c9a,0x207ca9),
        new(0x207cc1,0x207cf1,0x207cc3),
        new(0x207ce6,0x207d3e,0x207ce8),
        new(0x207cef,0x207d3a),
        new(0x207d1f,0x207d2c,0x207d21),
        new(0x207d6e,0x20844f,0x207d74),
        new(0x207d8d,0x20844f,0x207d93),
        new(0x207dc3,0x207e7b,0x207dc9),
        new(0x207e04,0x207e22,0x207e06),
        new(0x207e0e,0x207ebe,0x207e14),
        new(0x207e1c,0x207ebe,0x207e22),
        new(0x207e2a,0x207e89,0x207e2c),
        new(0x207e2f,0x207e89,0x207e31),
        new(0x207e79,0x207eba,0x207e7b),
        new(0x207e84,0x20844f),
        new(0x207ef9,0x20844f,0x207eff),
        new(0x207f10,0x20844f,0x207f16),
        new(0x207f29,0x207f67,0x207f2b),
        new(0x207f4f,0x207f62,0x207f51),
        new(0x207f65,0x207fc3),
        new(0x207f6a,0x207fb5,0x207f6c),
        new(0x207f7f,0x207fb5,0x207f81),
        new(0x207f84,0x207fb5,0x207f86),
        new(0x207f89,0x207f35,0x207f8b),
        new(0x207f8e,0x207faa,0x207f90),
        new(0x207f93,0x207f9f,0x207f95),
        new(0x207f9a,0x20844f),
        new(0x207fa8,0x207fc3),
        new(0x207fb3,0x207fc3),
        new(0x207fd7,0x207fec,0x207fd9),
        new(0x207fdc,0x207fec,0x207fde),
        new(0x207fea,0x208010),
        new(0x207fee,0x20800a,0x207ff0),
        new(0x207ff3,0x20800a,0x207ff5),
        new(0x207ff8,0x20800a,0x207ffa),
        new(0x208008,0x208010),
        new(0x208055,0x208061,0x208057),
        new(0x20805c,0x20844f),
        new(0x20806d,0x2080a2,0x20806f),
        new(0x208076,0x208088,0x208078),
        new(0x20807e,0x2080a2,0x208080),
        new(0x208086,0x2080a2,0x208088),
        new(0x2080a8,0x2080ba,0x2080aa),
        new(0x2080c0,0x2080d2,0x2080c2),
        new(0x2080df,0x20844f,0x2080e5),
        new(0x2080ff,0x20844f,0x208105),
        new(0x208116,0x20844f,0x20811c),
        new(0x20812a,0x20813b,0x20812c),
        new(0x208133,0x20813b,0x208135),
        new(0x208139,0x20813d),
        new(0x208158,0x20844f,0x20815e),
        new(0x20817c,0x20844f,0x208182),
        new(0x208193,0x20844f,0x208199),
        new(0x2081aa,0x20844f,0x2081b0),
        new(0x2081c1,0x20844f,0x2081c7),
        new(0x2081e2,0x20844f,0x2081e8),
        new(0x208206,0x20844f,0x20820c),
        new(0x208224,0x20844f,0x20822a),
        new(0x20824d,0x20844c,0x208253),
        new(0x208265,0x20844f,0x20826b),
        new(0x208295,0x20844f,0x20829b),
        new(0x2082c5,0x2082dc,0x2082c7),
        new(0x2082da,0x2082e9),
        new(0x208309,0x208399,0x20830f),
        new(0x20835d,0x20844f,0x208363),
        new(0x208397,0x2083ac),
        new(0x20839c,0x2083b0,0x20839e),
        new(0x2083c3,0x20844c,0x2083c9),
        new(0x2083f3,0x208401,0x2083f5),
        new(0x2083ff,0x208404),
        new(0x208442,0x20847e,0x208444),
        new(0x20847d),
        new(0x2084cd,0x20844f,0x2084cf),
        new(0x2084da,0x20852b,0x2084dc),
        new(0x2084ec,0x208519,0x2084ee),
        new(0x208501,0x208519,0x208503),
        new(0x20850d,0x20853b,0x20850f),
        new(0x20852e,0x208534,0x208530),
        new(0x208536,0x20845a),
        new(0x208545,0x208527),
    ];
    private Branch pending;
    private int count;
    private int? failureBranch, failureLanding;
    private bool completed;

    internal sealed record Evidence(int ObservedEdges,bool ReachedReviewedExit,int? FailureBranchRva,int? FailureLandingRva,
        uint? HelperReturnCode);
    internal uint? ReturnCode {get;set;}
    internal Evidence Snapshot()=>new(count,completed && ReturnCode.HasValue,failureBranch,failureLanding,ReturnCode);

    internal void Advance(SessionZeroStartupBranchTrace.Breakpoints registers,long imageBase,int slot,int rva)
    {
        registers.Disarm(1-slot);
        if(rva==Caller)
        {
            if(pending.Rva!=0 || count!=0)throw WfpNative.Contract("CudaHelperCallRepeated");
            rva=Entry;
        }
        else
        {
            if((rva!=pending.Target && rva!=pending.FallThrough) || ++count>96)
                throw WfpNative.Contract("CudaHelperEdgeUnbound");
            if(rva is EarlyAllocationFailure or FailureCleanup or FailedObjectCleanup or SharedFailureStatus)
            {
                failureBranch=pending.Rva;
                failureLanding=rva;
                completed=true;
                return;
            }
        }

        pending=Array.Find(Branches,branch=>branch.Rva>=rva);
        if(pending.Rva==Return)
        {
            completed=true;
            return;
        }
        if(pending.Target==0)throw WfpNative.Contract("CudaHelperBranchUnavailable");
        registers.Arm(0,checked(imageBase+pending.Target));
        if(pending.FallThrough!=0)registers.Arm(1,checked(imageBase+pending.FallThrough));
    }
}
