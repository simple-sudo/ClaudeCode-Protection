using System;
namespace CallerExample;
public static class Checks
{
    public static int Run()
    {
        if(Counter.CountWords("")!=0)throw new Exception("empty input");
        if(Counter.CountWords("one two three")!=3)throw new Exception("three words");
        if(Counter.CountWords("one\u2003two\tthree")!=3)throw new Exception("unicode spaces");
        return 3;
    }
}
