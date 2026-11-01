using System;
namespace CallerExample;
public static class Entry
{
    public static int Run()
    {
        var count=Counter.CountWords("one two three");
        Console.Write("words="+count);
        return count==3?0:1;
    }
}
