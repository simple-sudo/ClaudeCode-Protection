using System.Buffers.Binary;
using System.Diagnostics;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using ClaudeCodeProtection.Workspaces;

namespace ProtectionLifecycle;

internal sealed partial class SessionGitToolchain
{
internal static ProcessStartInfo StartIndependentInit(string workspace) =>
        Start(workspace,DirectoryPath,"init","--quiet","--template=","--initial-branch=cpc-offline","git-project");

    internal static ProcessStartInfo StartIndependentCommit(string workspace) =>
        Start(workspace,DirectoryPath,"-C",WindowsPathSeal.Child(workspace,"git-project"),"commit","--quiet","--no-gpg-sign","-a","-m",CommitMessage);

    private static WorkspaceBundle IndependentCommitFiles()=>WorkspaceBundle.Create(new (string,byte[])[]{
        ("note.txt","edited by the fixed qualification fixture\n"u8.ToArray()),
        ("sample/payload.bin",new byte[]{0,13,10,0xff,0x80,1})
    });

    internal static void PrepareIndependentCommit(string workspace)
    {
        var repository=WindowsPathSeal.Child(workspace,"git-project");
        var metadata=WindowsPathSeal.Child(repository,".git");
        Directory.CreateDirectory(WindowsPathSeal.Child(metadata,"refs/heads"));
        WriteNew(WindowsPathSeal.Child(metadata,"HEAD"),"ref: refs/heads/qualification\n"u8);
        WriteNew(WindowsPathSeal.Child(metadata,"config"),
            "[core]\n\trepositoryformatversion = 0\n\tfilemode = false\n\tbare = false\n\tlogallrefupdates = false\n"u8);

        // Git index v2 with deliberately stale stat data. Both paths start
        // tracked at the same baseline blob, then commit -a must stage the
        // different worktree bytes. This fixture needs only one Git process.
        var baseline="baseline\n"u8.ToArray();
        var baselineId=BlobId(baseline);
        var objectDirectory=Directory.CreateDirectory(WindowsPathSeal.Child(metadata,"objects/"+baselineId[..2])).FullName;
        using(var output=new FileStream(WindowsPathSeal.Child(objectDirectory,baselineId[2..]),FileMode.CreateNew,FileAccess.Write,FileShare.None))
        using(var encoder=new ZLibStream(output,CompressionLevel.Fastest))
        {
            encoder.Write(Encoding.ASCII.GetBytes("blob "+baseline.Length+"\0"));
            encoder.Write(baseline);
        }

        var files=IndependentCommitFiles().Files;
        using var index=new MemoryStream();
        index.Write("DIRC"u8);
        Span<byte> integer=stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(integer,2);
        index.Write(integer);
        BinaryPrimitives.WriteInt32BigEndian(integer,files.Length);
        index.Write(integer);
        Span<byte> entry=stackalloc byte[62];
        entry.Clear();
        BinaryPrimitives.WriteUInt32BigEndian(entry[24..],0x81a4); // regular file, mode 0644
        BinaryPrimitives.WriteInt32BigEndian(entry[36..],baseline.Length);
        Convert.FromHexString(baselineId).CopyTo(entry[40..]);
        foreach(var file in files)
        {
            var path=WindowsPathSeal.Child(repository,file.Path);
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            WriteNew(path,file.Content);
            var name=Encoding.ASCII.GetBytes(file.Path);
            BinaryPrimitives.WriteUInt16BigEndian(entry[60..],checked((ushort)name.Length));
            index.Write(entry);
            index.Write(name);
            index.Write(new byte[8-(entry.Length+name.Length)%8]);
        }
        index.Write(SHA1.HashData(index.GetBuffer().AsSpan(0,checked((int)index.Length))));
        WriteNew(WindowsPathSeal.Child(metadata,"index"),index.ToArray());
    }

    private static void WriteNew(string path,ReadOnlySpan<byte> bytes)
    {
        using var output=new FileStream(path,FileMode.CreateNew,FileAccess.Write,FileShare.None);
        output.Write(bytes);
    }

    internal static bool IndependentCommitObserved(string workspace)
    {
        using var repository=WindowsPathSeal.LockDirectory(WindowsPathSeal.Child(workspace,"git-project/.git"),PathPolicy.Source);
        using var head=new FileStream(WindowsPathSeal.Open(WindowsPathSeal.Child(repository.Path,"HEAD"),false,true),FileAccess.Read);
        ReadOnlySpan<byte> expected="ref: refs/heads/qualification\n"u8;
        if(head.Length!=expected.Length)return false;
        Span<byte> content=stackalloc byte[expected.Length];
        head.ReadExactly(content);
        if(!expected.SequenceEqual(content))return false;
        AssertCommit(workspace,IndependentCommitFiles(),ReadQualificationRef(workspace));
        repository.AssertHeld();
        return true;
    }

    internal static bool IndependentInitObserved(string workspace)
    {
        using var repository=WindowsPathSeal.LockDirectory(WindowsPathSeal.Child(workspace,"git-project/.git"),PathPolicy.Source);
        using var objects=WindowsPathSeal.LockDirectory(WindowsPathSeal.Child(repository.Path,"objects"),PathPolicy.Source);
        using var refs=WindowsPathSeal.LockDirectory(WindowsPathSeal.Child(repository.Path,"refs/heads"),PathPolicy.Source);
        using var head=new FileStream(WindowsPathSeal.Open(WindowsPathSeal.Child(repository.Path,"HEAD"),false,true),FileAccess.Read);
        ReadOnlySpan<byte> expected="ref: refs/heads/cpc-offline\n"u8;
        if(head.Length!=expected.Length)return false;
        Span<byte> content=stackalloc byte[expected.Length];
        head.ReadExactly(content);
        repository.AssertHeld();objects.AssertHeld();refs.AssertHeld();
        return expected.SequenceEqual(content);
    }
    private static (int Exit,string Out,string Error) Run(string workspace,string directory,params string[] args)
    {
        using var process=AtomicChild.StartInheritedTool(Start(workspace,directory,args));process.StandardInput.Close();
        var result=Finish(process,SessionResources.ReadBounded(process.StandardOutput),SessionResources.ReadBounded(process.StandardError));
        RecordResult(workspace,result);return result;
    }
}
