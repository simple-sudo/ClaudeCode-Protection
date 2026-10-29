using System.Buffers.Binary;
using System.Text;

namespace ProtectionLifecycle;

internal static class DirectoryNamePageCases
{
    internal static void Run()
    {
        Require(DirectoryNamePage.Parse(Page(".","..","alpha.json","项目.bin"))
            .SequenceEqual(new[]{"alpha.json","项目.bin"}),"complete Unicode names; no dot traversal");
        Require(DirectoryNamePage.Parse(Page(".","..")).Length==0,"empty directory names");
        Require(DirectoryNamePage.Parse(Page(new string('a',255)))[0].Length==255,"NTFS maximum name");
        Reject(Array.Empty<byte>(),"empty success page");
        Reject(new byte[13],"truncated header");
        Reject(new byte[65537],"oversized page");
        var page=Page("a");
        foreach(var length in new uint[]{0,1,3,512,uint.MaxValue})
        {
            var bad=(byte[])page.Clone();BinaryPrimitives.WriteUInt32LittleEndian(bad.AsSpan(8),length);
            Reject(bad,"invalid filename byte length "+length);
        }
        var truncated=Page("abc");Array.Resize(ref truncated,16);Reject(truncated,"declared name exceeds page");
        foreach(var next in new uint[]{1,4,12,15,17,4096,uint.MaxValue})
        {
            var bad=Page("a","b");BinaryPrimitives.WriteUInt32LittleEndian(bad,next);
            Reject(bad,"invalid/overlapping continuation "+next);
        }
        var hidden=Page("a","b");BinaryPrimitives.WriteUInt32LittleEndian(hidden,0);Reject(hidden,"hidden trailing record");
        var invalidUnicode=Page("a");invalidUnicode[12]=0;invalidUnicode[13]=0xd8;Reject(invalidUnicode,"unpaired UTF16 surrogate");
        foreach(var name in new[]{"a\0b","a\u0001b","..\\x","x/y","x:stream","x*","x?","x\"","x|","x<","x>","x.","x "})
            Reject(Page(name),"ambiguous leaf "+name.Replace('\0','_'));
        Console.WriteLine("DirectoryNamePage: complete/Unicode/dot/max-length and malformed length/offset/truncation/encoding/path cases passed; no native query");
    }
    private static void Require(bool value,string label){if(!value)throw new Exception("DirectoryNamePage: "+label);}
    private static void Reject(byte[] page,string label)
    {
        try{_=DirectoryNamePage.Parse(page);}catch(InvalidDataException){return;}
        throw new Exception("DirectoryNamePage accepted "+label);
    }
    private static byte[] Page(params string[] names)
    {
        var encoded=names.Select(Encoding.Unicode.GetBytes).ToArray();
        var sizes=encoded.Select(n=>(12+n.Length+3)&~3).ToArray();var page=new byte[sizes.Sum()];var offset=0;
        for(var index=0;index<names.Length;index++)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(page.AsSpan(offset),index==names.Length-1?0u:(uint)sizes[index]);
            BinaryPrimitives.WriteUInt32LittleEndian(page.AsSpan(offset+8),(uint)encoded[index].Length);
            encoded[index].CopyTo(page,offset+12);offset+=sizes[index];
        }
        return page;
    }
}
