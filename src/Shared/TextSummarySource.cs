namespace ClaudeCodeProtection.Workspaces;

// Data only: both installed callers carry the same reviewed sample bytes.
// No tool, compiler, project assembly or elevated library is loaded here.
internal static class TextSummarySource
{
    internal static byte[] Baseline()
    {
        var assembly=typeof(TextSummarySource).Assembly;
        return WorkspaceBundle.Create(new[]{"TextSummary.csproj","TextSummary.cs","ProjectTests.cs","README.md"}.Select(name=>
        {
            using var input=assembly.GetManifestResourceStream("ClaudeCodeProtection.TextSummary."+name)
                ??throw new InvalidDataException("Bundled project source missing");
            if(input.Length is <1 or >16384)throw new InvalidDataException("Bundled project source bounds");
            var bytes=new byte[checked((int)input.Length)];input.ReadExactly(bytes);return(name,bytes);
        })).Serialize();
    }
    internal static string BaselineHash=>WorkspaceBundle.Hash(Baseline());
    internal static void RequireBaseline(byte[] bytes)
    {
        if(!bytes.AsSpan().SequenceEqual(Baseline()))throw new InvalidDataException("Only the bundled TextSummary baseline is supported");
    }
}
