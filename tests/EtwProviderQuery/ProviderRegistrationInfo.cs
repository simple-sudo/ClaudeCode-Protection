using System.Buffers.Binary;

internal sealed record ProviderRegistration(uint Pid,uint Flags,uint EnableCount);

// TRACE_GUID_INFO + TRACE_PROVIDER_INSTANCE_INFO + TRACE_ENABLE_INFO. Only
// counts and process IDs are retained; never decode logger IDs or event data.
internal static class ProviderRegistrationInfo
{
    internal static ProviderRegistration[] Parse(ReadOnlySpan<byte> bytes)
    {
        if(bytes.Length is <8 or >65536)throw new InvalidDataException("RegistrationInfoBounds");
        var count=BinaryPrimitives.ReadUInt32LittleEndian(bytes);
        if(count>256 || BinaryPrimitives.ReadUInt32LittleEndian(bytes[4..])!=0)throw new InvalidDataException("RegistrationHeaderRefused");
        var entries=new List<ProviderRegistration>();var offset=8;
        for(var index=0;index<count;index++)
        {
            if(bytes.Length-offset<16)throw new InvalidDataException("RegistrationInstanceTruncated");
            var instance=bytes[offset..];var next=BinaryPrimitives.ReadUInt32LittleEndian(instance);
            var enabled=BinaryPrimitives.ReadUInt32LittleEndian(instance[4..]);
            var pid=BinaryPrimitives.ReadUInt32LittleEndian(instance[8..]);var flags=BinaryPrimitives.ReadUInt32LittleEndian(instance[12..]);
            if(enabled>64 || (flags&~3u)!=0 || (flags&2)==0 && pid==0)throw new InvalidDataException("RegistrationInstanceRefused");
            var length=checked(16+(int)enabled*32);
            if(length>instance.Length)throw new InvalidDataException("RegistrationEnableInfoTruncated");
            var last=index==count-1;
            if(last?next!=0:next<length || next>instance.Length || next%8!=0)throw new InvalidDataException("RegistrationNextOffsetRefused");
            var consumed=last?length:checked((int)next);
            if(instance[length..consumed].IndexOfAnyExcept((byte)0)>=0)throw new InvalidDataException("RegistrationPaddingRefused");
            entries.Add(new(pid,flags,enabled));offset=checked(offset+consumed);
        }
        if(offset!=bytes.Length)throw new InvalidDataException("RegistrationTrailingBytes");
        return entries.ToArray();
    }
    internal static void QualifyParser()
    {
        byte[] One(uint pid,uint flags,uint enabled)
        {
            var bytes=new byte[24+checked((int)enabled*32)];
            BinaryPrimitives.WriteUInt32LittleEndian(bytes,1);
            BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(12),enabled);
            BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(16),pid);
            BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(20),flags);return bytes;
        }
        void Require(bool value){if(!value)throw new InvalidOperationException("RegistrationParserCaseFailed");}
        void Refuse(byte[] bytes)
        {
            try{_=Parse(bytes);}catch(InvalidDataException){return;}
            throw new InvalidOperationException("RegistrationParserExpectedRefusal");
        }
        Require(Parse(new byte[8]).Length==0);
        var one=One(42,0,1);Require(Parse(one).Single()==new ProviderRegistration(42,0,1));
        Require(Parse(One(0,2,1)).Single().Flags==2);
        var two=new byte[one.Length+16];one.CopyTo(two,0);
        BinaryPrimitives.WriteUInt32LittleEndian(two,2);
        BinaryPrimitives.WriteUInt32LittleEndian(two.AsSpan(8),48);
        BinaryPrimitives.WriteUInt32LittleEndian(two.AsSpan(one.Length+8),81);
        Require(Parse(two).Select(e=>e.Pid).SequenceEqual(new uint[]{42,81}));
        Refuse(new byte[7]);Refuse(new byte[9]);Refuse(One(0,0,0));Refuse(One(42,4,0));Refuse(one[..^1]);
        var bad=one.ToArray();BinaryPrimitives.WriteUInt32LittleEndian(bad,257);Refuse(bad);
        bad=one.ToArray();BinaryPrimitives.WriteUInt32LittleEndian(bad.AsSpan(4),1);Refuse(bad);
        bad=one.ToArray();BinaryPrimitives.WriteUInt32LittleEndian(bad.AsSpan(12),uint.MaxValue);Refuse(bad);
        foreach(var next in new uint[]{0,8,47,49,uint.MaxValue}){bad=two.ToArray();BinaryPrimitives.WriteUInt32LittleEndian(bad.AsSpan(8),next);Refuse(bad);}
        bad=one.ToArray();BinaryPrimitives.WriteUInt32LittleEndian(bad.AsSpan(8),16);Refuse(bad);
        var padded=new byte[two.Length+8];two.AsSpan(0,one.Length).CopyTo(padded);two.AsSpan(one.Length).CopyTo(padded.AsSpan(one.Length+8));
        BinaryPrimitives.WriteUInt32LittleEndian(padded.AsSpan(8),56);Require(Parse(padded).Length==2);
        padded[one.Length]=1;Refuse(padded);
    }
}
