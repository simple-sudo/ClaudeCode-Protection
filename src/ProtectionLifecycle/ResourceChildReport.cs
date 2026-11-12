using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;
using ClaudeCodeProtection.Workspaces;

namespace ProtectionLifecycle;

internal sealed record ResourceAccessCase(string Role,string Status,int? Error);
internal sealed record ResourceChildReport(int SchemaVersion,int Pid,string Nonce,bool WorkspaceWriteReadMatched,int? ToolExit,
    ResourceAccessCase[] Cases,string? FailureType,int? FailureCode,string? FailureStage,string? ToolDiagnostic,GitToolchainReport? Git,ToolCreationEvidence? CreationEvidence=null,bool OwnedCompilationObserved=false,
    [property:System.Text.Json.Serialization.JsonIgnore(Condition=System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)] ProjectTaskFailure? ProjectFailure=null);
