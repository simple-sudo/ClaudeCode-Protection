global using System.IO;
using System.Text;
using ClaudeCodeProtection.Workspaces;

namespace ProtectionCenter;

// Ordinary data review only. Keep the exact selected bytes through extraction;
// never reopen mutable input paths after showing the user their changes.
internal sealed class WorkspaceResultSession
{
    private readonly byte[] baseline, result;
    internal string BaselineSHA256 { get; }
    internal string ResultSHA256 { get; }
    internal int FileCount { get; }
    internal string ReviewText { get; }

    private WorkspaceResultSession(byte[] baseline, byte[] result)
    {
        var changes = WorkspaceBundle.Compare(baseline, result);
        this.baseline = baseline; this.result = result;
        BaselineSHA256 = WorkspaceBundle.Hash(baseline);
        ResultSHA256 = WorkspaceBundle.Hash(result);
        FileCount = WorkspaceBundle.Parse(result).Files.Length;
        var text = new StringBuilder();
        text.AppendLine($"结果文件校验通过，共 {FileCount} 个文件、{changes.Length} 项变化。");
        text.AppendLine("提取只写入新目录；原项目保留，结果中的程序不会被运行。");
        text.AppendLine("文件校验不代表本次保护会话、敏感资源隔离或正式准入已经验收。");
        text.AppendLine();
        foreach (var change in changes)
        {
            var kind = change.Kind switch { "ADD" => "新增", "MODIFY" => "修改", "DELETE" => "删除", _ => throw new InvalidDataException("Unknown workspace change") };
            text.AppendLine($"{kind}  {change.Path}");
        }
        if (changes.Length == 0) text.AppendLine("文件内容没有变化。");
        text.AppendLine();
        text.AppendLine("输入摘要：" + BaselineSHA256);
        text.AppendLine("结果摘要：" + ResultSHA256);
        ReviewText = text.ToString();
    }

    internal static WorkspaceResultSession Open(string baselinePath, string resultPath)
    {
        WorkspaceFiles.RequireOrdinaryUser();
        return new(WorkspaceFiles.ReadBundle(baselinePath), WorkspaceFiles.ReadBundle(resultPath));
    }

    internal void ExtractNew(string destination)
        => WorkspaceFiles.ExtractResultNew(destination, baseline, result);
}
