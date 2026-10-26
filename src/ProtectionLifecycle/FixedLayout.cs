namespace ProtectionLifecycle;

// No destination/root parameter is accepted from a command line, manifest or
// caller environment override. Resolve Windows special folders at execution.
internal sealed class FixedLayout
{
    internal string CodeRoot { get; }
    internal string StateRoot { get; }
    internal string Versions => Path.Combine(CodeRoot, "versions");
    private FixedLayout(string programFiles)
    {
        CodeRoot = WindowsPathSeal.Canonical(Path.Combine(programFiles, "ClaudeCodeProtection"));
        // Separate private sibling: retained by code uninstall. A container
        // whose parent allows ordinary-user creation is not a trust anchor.
        StateRoot=WindowsPathSeal.Canonical(Path.Combine(programFiles,"ClaudeCodeProtection-State"));
    }
    internal static FixedLayout FromWindows()
    {
        if (!OperatingSystem.IsWindows() || !Environment.Is64BitProcess)
            throw new PlatformNotSupportedException("The protected lifecycle requires Windows x64");
        var code = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        if(string.IsNullOrWhiteSpace(code))
            throw new InvalidOperationException("Windows installation folders unavailable");
        return new(code);
    }
    internal string Version(string release) => Path.Combine(Versions, Identifiers.Hex32(release));
}

internal static class Identifiers
{
    internal static string Hex32(string value) => value.Length == 32 && value.All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f')
        ? value : throw new InvalidDataException("Expected lowercase 32-digit identifier");
    internal static string Hash(string value) => value.Length == 64 && value.All(c => c is >= '0' and <= '9' or >= 'A' and <= 'F')
        ? value : throw new InvalidDataException("Expected uppercase SHA-256");
    internal static string ObjectIdentity(string value)
    {
        var parts=value.Split(':');
        if(parts.Length!=3 || parts.Any(p=>p.Length!=8 || p.Any(c=>!(c is >= '0' and <= '9' or >= 'A' and <= 'F'))))
            throw new InvalidDataException("Invalid bounded NTFS identity");
        return value;
    }
    internal static string StateLeaf(string value)
    {
        if (value.Length is < 1 or > 160 || value is "." or ".." || value[0] == '.' ||
            value.Any(c => !(c is >= 'a' and <= 'z' or >= '0' and <= '9' or '-' or '.')) ||
            !value.EndsWith(".json", StringComparison.Ordinal)) throw new InvalidDataException("Invalid internal state leaf");
        var stem=value.Split('.')[0];
        if(stem is "con" or "prn" or "aux" or "nul" ||
            (stem.Length==4 && (stem.StartsWith("com",StringComparison.Ordinal) || stem.StartsWith("lpt",StringComparison.Ordinal)) && stem[3] is >= '1' and <= '9'))
            throw new InvalidDataException("DOS device leaf refused");
        return value;
    }
}
