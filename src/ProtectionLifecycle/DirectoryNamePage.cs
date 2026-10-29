using System.Buffers.Binary;
using System.Text;

namespace ProtectionLifecycle;

// FILE_NAMES_INFORMATION, not FILE_FULL_DIR_INFORMATION. Names are discovery
// only: callers still reopen each selected object and verify identity/ACL/tag.
internal static class DirectoryNamePage
{
    private static readonly Encoding Utf16=new UnicodeEncoding(false,false,true);
    internal static string[] Parse(ReadOnlySpan<byte> page)
    {
        if(page.Length is <14 or >65536)throw new InvalidDataException("Directory name page size refused");
        var names=new List<string>();var offset=0;
        while(true)
        {
            var entry=page[offset..];
            if(entry.Length<14)throw new InvalidDataException("Truncated directory name header");
            var next=BinaryPrimitives.ReadUInt32LittleEndian(entry);
            var length=BinaryPrimitives.ReadUInt32LittleEndian(entry[8..]);
            if(length is <2 or >510 || (length&1)!=0 || length>entry.Length-12)
                throw new InvalidDataException("Truncated/invalid directory name length");
            var end=12+(int)length;
            string name;
            try{name=Utf16.GetString(entry.Slice(12,(int)length));}
            catch(DecoderFallbackException ex){throw new InvalidDataException("Invalid directory name encoding",ex);}
            if(name.Any(c=>c<' ') || name.IndexOfAny(new[]{'\\','/',':','*','?','"','<','>','|'})>=0 ||
                name is not ("." or "..") && (name.EndsWith(' ') || name.EndsWith('.')))
                throw new InvalidDataException("Ambiguous directory leaf refused");
            if(name is not ("." or ".."))names.Add(name);
            if(next==0)
            {
                if(entry.Length-end>3)throw new InvalidDataException("Unexpected directory name trailing data");
                return names.ToArray();
            }
            if((next&3)!=0 || next<end || next>entry.Length-14)
                throw new InvalidDataException("Invalid directory name continuation");
            offset=checked(offset+(int)next);
        }
    }
}
