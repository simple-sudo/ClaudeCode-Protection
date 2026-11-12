using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text.Json;

namespace ProtectionLifecycle;

internal sealed record FenceRoleObservation(string Role,bool Present,bool Persistent,bool PolicyMatches,ulong? ObservedId);
internal sealed record FenceObservation(string FenceId,bool SubLayerPresent,bool SubLayerHealthy,FenceRoleObservation[] Roles,string AtUtc,
    string Scope,bool LaunchQualified,bool ProxyQualified,bool RebootQualified,ushort? ObservedSubLayerWeight)
{
    internal bool AllAbsent=>!SubLayerPresent && Roles.All(r=>!r.Present);
    internal bool FullQuarantineObserved=>SubLayerHealthy && Roles.Length==6 && Roles.All(r=>r.Present && r.Persistent && r.PolicyMatches);
    internal bool IPv4ProxyOnlyObserved=>SubLayerHealthy && Roles.Length==6 && Roles.Select((r,i)=>i==4?!r.Present:r.Present && r.Persistent && r.PolicyMatches).All(ok=>ok);
}
