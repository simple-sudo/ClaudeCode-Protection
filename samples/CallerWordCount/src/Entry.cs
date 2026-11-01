using System;
using System.IO;
namespace CallerExample;
public static class Entry
{
    public static int Run()
    {
        if(!File.Exists("src/Counter.cs"))return 2;
        var count=Counter.CountWords("one two three");
        Console.Write("words="+count);
        return count==3?0:1;
    }
}
