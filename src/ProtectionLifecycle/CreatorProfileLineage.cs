using System.Buffers.Binary;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace ProtectionLifecycle;

internal static class CreatorProfileLineage
{
    internal enum Evidence { Unknown=0, NoMatchingCreation=8192, Match=24576, Conflict=40960 }
    private const uint FileCreate=0x100,DirectoryAttribute=0x10,ReparseAttribute=0x400;
    private const uint Structural=FileCreate|0x200|0x1000|0x2000|0x10000|0x80000|0x100000;
    private const uint QueryJournal=0x000900f4,ReadJournal=0x000900bb;
    private const int OutputSize=64*1024,ReadLimit=64*1024*1024;
    private static readonly UnicodeEncoding FileNames=new(false,false,true);

    internal static Evidence Observe(string name,string parentIdentity,string rootIdentity,long from,long through)
    {
        var parent=DecodeIdentity(parentIdentity);
        var root=DecodeIdentity(rootIdentity);
        var drive=new DriveInfo("C:");
        if(parent.Volume!=root.Volume || parent.File==root.File || drive.DriveFormat!="NTFS" || drive.DriveType!=DriveType.Fixed)
            return Evidence.Unknown;
        using var volume=CreateFile(@"\\.\C:",0x80000000,7,IntPtr.Zero,3,0,IntPtr.Zero);
        if(volume.IsInvalid)throw Error("Open fixed NTFS volume for read");
        var initial=ReadState(volume);
        var start=Math.Max(initial.First,initial.LowestValid);
        if(start>=initial.Next || initial.Next-start>512L*1024*1024)return Evidence.Unknown;
        var scan=new Scan(name,parent.File,root.File,from,through);
        var buffer=new byte[OutputSize];
        var input=new byte[48];
        BinaryPrimitives.WriteUInt32LittleEndian(input.AsSpan(8),Structural);
        BinaryPrimitives.WriteUInt64LittleEndian(input.AsSpan(32),initial.Id);
        BinaryPrimitives.WriteUInt16LittleEndian(input.AsSpan(40),2);
        BinaryPrimitives.WriteUInt16LittleEndian(input.AsSpan(42),2);
        var cursor=start;
        var budget=0;
        var clock=Stopwatch.StartNew();
        while(cursor<initial.Next)
        {
            if(budget>=ReadLimit || clock.Elapsed>=TimeSpan.FromSeconds(15))return Evidence.Unknown;
            BinaryPrimitives.WriteInt64LittleEndian(input,cursor);
            var length=Control(volume,ReadJournal,input,buffer,Math.Min(buffer.Length,ReadLimit-budget));
            budget+=length;
            cursor=scan.ReadChunk(buffer.AsSpan(0,length),cursor,initial.Next);
        }
        var final=ReadState(volume);
        if(final.Id!=initial.Id || final.Next<initial.Next || Math.Max(final.First,final.LowestValid)>(scan.CreationUsn??start))
            return Evidence.Unknown;
        return scan.Result;
    }

    private static (uint Volume,ulong File) DecodeIdentity(string value)
    {
        if(value.Length!=26 || value[8]!=':' || value[17]!=':')throw new InvalidDataException("Unexpected file identity format");
        var volume=uint.Parse(value.AsSpan(0,8),NumberStyles.HexNumber,CultureInfo.InvariantCulture);
        var file=(ulong)uint.Parse(value.AsSpan(9,8),NumberStyles.HexNumber,CultureInfo.InvariantCulture)<<32 |
            uint.Parse(value.AsSpan(18,8),NumberStyles.HexNumber,CultureInfo.InvariantCulture);
        if(file==0)throw new InvalidDataException("Empty file identity");
        return(volume,file);
    }

    private sealed record JournalState(ulong Id,long First,long Next,long LowestValid);
    private static JournalState ReadState(SafeFileHandle volume)
    {
        var data=new byte[80];
        var length=Control(volume,QueryJournal,[],data,data.Length);
        if(length<56 || length>56 && (length<60 || BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(56))>2 ||
            BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(58))<2) ||
            length>=80 && BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(60))!=0)
            throw new InvalidDataException("Unexpected journal layout or range tracking");
        var id=BinaryPrimitives.ReadUInt64LittleEndian(data);
        var first=BinaryPrimitives.ReadInt64LittleEndian(data.AsSpan(8));
        var next=BinaryPrimitives.ReadInt64LittleEndian(data.AsSpan(16));
        var lowest=BinaryPrimitives.ReadInt64LittleEndian(data.AsSpan(24));
        if(id==0 || first<0 || lowest<0 || next<first || next<lowest)throw new InvalidDataException("Journal bounds invalid");
        return new(id,first,next,lowest);
    }

    internal sealed class Scan(string name,ulong parent,ulong target,long from,long through)
    {
        internal long? CreationUsn {get;private set;}
        private bool conflict;
        internal Evidence Result=>conflict?Evidence.Conflict:CreationUsn is null?Evidence.NoMatchingCreation:Evidence.Match;

        internal long ReadChunk(ReadOnlySpan<byte> bytes,long cursor,long end)
        {
            if(bytes.Length<8)throw new InvalidDataException("Missing journal continuation");
            var next=BinaryPrimitives.ReadInt64LittleEndian(bytes);
            if(next<=cursor)throw new InvalidDataException("Journal cursor did not advance");
            bytes=bytes[8..];
            var previous=cursor-1;
            while(!bytes.IsEmpty)
            {
                if(bytes.Length<60)throw new InvalidDataException("Truncated journal record");
                var length=checked((int)BinaryPrimitives.ReadUInt32LittleEndian(bytes));
                if(length<60 || length>bytes.Length || (length&7)!=0 || BinaryPrimitives.ReadUInt16LittleEndian(bytes[4..])!=2 ||
                    BinaryPrimitives.ReadUInt16LittleEndian(bytes[6..])!=0)throw new InvalidDataException("Unexpected journal record layout");
                var usn=BinaryPrimitives.ReadInt64LittleEndian(bytes[24..]);
                if(usn<=previous || usn>=next)throw new InvalidDataException("Unexpected journal record position");
                if(usn<end)ObserveRecord(bytes[..length],usn);
                previous=usn;
                bytes=bytes[length..];
            }
            return next;
        }

        private void ObserveRecord(ReadOnlySpan<byte> record,long usn)
        {
            var file=BinaryPrimitives.ReadUInt64LittleEndian(record[8..]);
            var directory=BinaryPrimitives.ReadUInt64LittleEndian(record[16..]);
            var reason=BinaryPrimitives.ReadUInt32LittleEndian(record[40..]);
            if((reason&Structural)==0)throw new InvalidDataException("Unexpected journal reason");
            if(file==parent && CreationUsn is not null)conflict=true;
            if(file!=target && directory!=parent)return;
            var nameSize=BinaryPrimitives.ReadUInt16LittleEndian(record[56..]);
            var nameOffset=BinaryPrimitives.ReadUInt16LittleEndian(record[58..]);
            if(nameOffset<60 || nameSize is <2 or >510 || (nameOffset&1)!=0 || (nameSize&1)!=0 || nameOffset+nameSize>record.Length)
                throw new InvalidDataException("Invalid file name bounds");
            var exact=directory==parent && string.Equals(FileNames.GetString(record.Slice(nameOffset,nameSize)),name,StringComparison.OrdinalIgnoreCase);
            var stamp=BinaryPrimitives.ReadInt64LittleEndian(record[32..]);
            var duringOperation=stamp>=from && stamp<=through;
            if(file!=target)
            {
                if(exact && (duringOperation || CreationUsn is not null))conflict=true;
                return;
            }
            var attributes=BinaryPrimitives.ReadUInt32LittleEndian(record[52..]);
            if(!exact || (reason&(Structural&~FileCreate))!=0 || (attributes&(DirectoryAttribute|ReparseAttribute))!=DirectoryAttribute)
            {
                conflict=true;
                return;
            }
            if(CreationUsn is null)
            {
                if(duringOperation)CreationUsn=usn;
                else conflict=true;
            }
        }
    }

    private static int Control(SafeFileHandle volume,uint code,byte[] input,byte[] output,int capacity)
    {
        if(!DeviceIoControl(volume,code,input,input.Length,output,capacity,out var returned,IntPtr.Zero))throw Error("Read NTFS journal metadata");
        if(returned<0 || returned>capacity)throw new InvalidDataException("Journal response length exceeds buffer");
        return returned;
    }
    private static Win32Exception Error(string operation)=>new(Marshal.GetLastWin32Error(),operation);
    [DllImport("kernel32.dll",EntryPoint="CreateFileW",CharSet=CharSet.Unicode,SetLastError=true)]
    private static extern SafeFileHandle CreateFile(string path,uint access,uint share,IntPtr security,uint disposition,uint flags,IntPtr template);
    [DllImport("kernel32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)]
    private static extern bool DeviceIoControl(SafeFileHandle device,uint code,byte[] input,int inputLength,[Out] byte[] output,int outputLength,out int returned,IntPtr overlapped);
}
