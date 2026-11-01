using System.Text;
using System.Text.Json;
using ClaudeCodeProtection.Workspaces;
using ProtectionCenter;

// Only a new, nonsecret ordinary-user fixture beside these test artifacts.
// No GUI/application entry, executable payload, host target or protected owner.
WorkspaceFiles.RequireOrdinaryUser();
var root = Path.Combine(AppContext.BaseDirectory, "fixture-" + Guid.NewGuid().ToString("N"));
if (Directory.Exists(root)) throw new IOException("Fresh fixture required");
Directory.CreateDirectory(root);
var checks = new List<string>();
void Require(bool value, string reason)
{ if (!value) throw new InvalidDataException(reason); checks.Add(reason); }
void Refuse(Action action, string reason)
{
    try { action(); }
    catch (Exception error) when (error is IOException or InvalidDataException or UnauthorizedAccessException or System.ComponentModel.Win32Exception or JsonException)
    { checks.Add(reason); return; }
    throw new InvalidDataException(reason);
}
var before = WorkspaceBundle.Create(new[] { ("Counter.cs", Encoding.UTF8.GetBytes("original-nonsecret")), ("obsolete.txt", "remove"u8.ToArray()) }).Serialize();
var after = WorkspaceBundle.Create(new[] { ("Counter.cs", Encoding.UTF8.GetBytes("modified-nonsecret")), ("added.txt", "added-nonsecret"u8.ToArray()) }, WorkspaceBundle.Hash(before)).Serialize();
var baselinePath = Path.Combine(root, "baseline.json"); var resultPath = Path.Combine(root, "result.json");
WorkspaceFiles.WriteBundleNew(baselinePath, before); WorkspaceFiles.WriteBundleNew(resultPath, after);
var session = WorkspaceResultSession.Open(baselinePath, resultPath);
Require(session.BaselineSHA256 == WorkspaceBundle.Hash(before) && session.ResultSHA256 == WorkspaceBundle.Hash(after), "review binds exact selected bytes");
Require(session.FileCount == 2 && session.ReviewText.Contains("新增  added.txt") && session.ReviewText.Contains("修改  Counter.cs") && session.ReviewText.Contains("删除  obsolete.txt"), "three change kinds visible");
Require(!session.ReviewText.Contains("modified-nonsecret") && !session.ReviewText.Contains("original-nonsecret"), "review does not display file contents");
Require(session.ReviewText.Contains("不代表本次保护会话"), "data review does not claim protected execution or admission");
// Mutate both original paths after review: extraction must use reviewed bytes.
var replacement = WorkspaceBundle.Create(new[] { ("unreviewed.txt", "different-nonsecret"u8.ToArray()) }).Serialize();
File.WriteAllBytes(baselinePath, replacement); File.WriteAllBytes(resultPath, replacement);
var destination = Path.Combine(root, "extracted"); session.ExtractNew(destination);
Require(File.ReadAllBytes(Path.Combine(destination, "Counter.cs")).AsSpan().SequenceEqual("modified-nonsecret"u8) && File.ReadAllBytes(Path.Combine(destination, "added.txt")).AsSpan().SequenceEqual("added-nonsecret"u8), "input path replacement cannot alter reviewed extraction");
Require(!File.Exists(Path.Combine(destination, "obsolete.txt")) && !File.Exists(Path.Combine(destination, "unreviewed.txt")), "deleted and later unreviewed files absent");
Refuse(() => session.ExtractNew(destination), "existing export destination refuses overwrite");
Require(File.ReadAllText(Path.Combine(destination, "Counter.cs")) == "modified-nonsecret", "refused overwrite preserves prior export");
File.WriteAllBytes(resultPath, after);
Refuse(() => WorkspaceResultSession.Open(baselinePath, resultPath), "wrong baseline refuses review");
File.WriteAllBytes(baselinePath, before); File.WriteAllText(resultPath, "{\"SchemaVersion\":1");
Refuse(() => WorkspaceResultSession.Open(baselinePath, resultPath), "malformed result refuses review");
var unchanged = WorkspaceBundle.Create(WorkspaceBundle.Parse(before).Files.Select(f => (f.Path, f.Content)), WorkspaceBundle.Hash(before)).Serialize();
File.WriteAllBytes(resultPath, unchanged);
Require(WorkspaceResultSession.Open(baselinePath, resultPath).ReviewText.Contains("文件内容没有变化"), "unchanged result remains valid data review");
Console.WriteLine(JsonSerializer.Serialize(new { Status = "OWN_NONSECRET_CENTER_RESULT_SESSION_PASSED", Checks = checks, Fixture = root, ProductEntryExecuted = false, ResultCodeExecuted = false, Elevated = false, HostTargetsRead = false, NetworkUsed = false, FixtureRetained = true }));
