namespace ProtectionLifecycle;

// Describes one existing, compiled offline resource operation. This is an
// immutable task-shape value, not an admission permit, resource owner or
// authorization decision. ProtectedSession remains the sole session owner.
internal enum ResourceExecutionKind
{
    WorkspaceQualification,
    GitToolchainQualification,
    BundledProjectDevelopment,
    CallerProjectBuild,
    WorkspaceDataProcessing,
    RecoveryQualification
}

internal sealed class ResourceExecutionIntent
{
    internal ResourceExecutionKind Kind { get; }
    internal Action? AssertCaller { get; }
    internal bool IncludeGit => Kind is ResourceExecutionKind.GitToolchainQualification or
        ResourceExecutionKind.BundledProjectDevelopment or ResourceExecutionKind.CallerProjectBuild or
        ResourceExecutionKind.WorkspaceDataProcessing;
    internal bool DevelopProject => Kind is ResourceExecutionKind.BundledProjectDevelopment or ResourceExecutionKind.CallerProjectBuild;
    internal bool CallerProject => Kind == ResourceExecutionKind.CallerProjectBuild;
    internal bool DeferCleanup => Kind == ResourceExecutionKind.RecoveryQualification;
    internal bool RequiresWorkspaceInput => Kind is ResourceExecutionKind.BundledProjectDevelopment or
        ResourceExecutionKind.CallerProjectBuild or ResourceExecutionKind.WorkspaceDataProcessing;

    private ResourceExecutionIntent(ResourceExecutionKind kind,Action? assertCaller)
    {
        if(kind==ResourceExecutionKind.CallerProjectBuild && assertCaller is null)
            throw new ArgumentNullException(nameof(assertCaller));
        if((kind is ResourceExecutionKind.WorkspaceQualification or ResourceExecutionKind.GitToolchainQualification or
            ResourceExecutionKind.RecoveryQualification) && assertCaller is not null)
            throw new ArgumentException("CallerRecheckNotApplicableForResourceOperation",nameof(assertCaller));
        Kind=kind;AssertCaller=assertCaller;
    }

    internal static ResourceExecutionIntent ForWorkspaceQualification()=>new(ResourceExecutionKind.WorkspaceQualification,null);
    internal static ResourceExecutionIntent ForGitToolchainQualification()=>new(ResourceExecutionKind.GitToolchainQualification,null);
    internal static ResourceExecutionIntent ForBundledProjectDevelopment(Action? assertCaller=null)
        =>new(ResourceExecutionKind.BundledProjectDevelopment,assertCaller);
    internal static ResourceExecutionIntent ForCallerProjectBuild(Action assertCaller)
        =>new(ResourceExecutionKind.CallerProjectBuild,assertCaller);
    internal static ResourceExecutionIntent ForWorkspaceDataProcessing(Action? assertCaller=null)
        =>new(ResourceExecutionKind.WorkspaceDataProcessing,assertCaller);
    internal static ResourceExecutionIntent ForRecoveryQualification()=>new(ResourceExecutionKind.RecoveryQualification,null);

    internal void AssertInput(byte[]? workspaceInput)
    {
        if(RequiresWorkspaceInput!=(workspaceInput is not null))
            throw WfpNative.Contract("ResourceExecutionIntentInputMismatch");
    }
}
