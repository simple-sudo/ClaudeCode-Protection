using System.Buffers.Binary;
using System.Diagnostics;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using ClaudeCodeProtection.Workspaces;

namespace ProtectionLifecycle;

internal sealed record GitWorkflowObservation(string PlanSHA256,string BranchName,string CommitId,string TreeId,string CommitMessage,
    string AuthorName,string AuthorEmail,long CommitUnixTime,int FileCount,int AddedLines,int DeletedLines,int BinaryFileCount,
    bool CleanAfterCommit,bool ObjectIntegrityObserved);
internal sealed record GitToolchainReport(bool InputHashMatched,bool InitAddCommitObserved,string? CommitId,
    bool PrivateFixtureReadRefused,int? DenialExit,bool AllPackagesFixtureReadRefused,int? AllPackagesDenialExit,string? FailureStage,string? FailureType,int? FailureCode)
{
    [JsonIgnore(Condition=JsonIgnoreCondition.WhenWritingNull)]
    public GitWorkflowObservation? Workflow {get;init;}
}
