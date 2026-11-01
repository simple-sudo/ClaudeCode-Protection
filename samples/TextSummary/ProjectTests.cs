using System;

namespace TextSummary;

public static class ProjectTests
{
    public static int Run()
    {
        if (Counter.CountLines("") != 0) throw new Exception("empty lines");
        if (Counter.CountLines("a\n\n b\n") != 2) throw new Exception("nonempty lines");
        if (Counter.CountLines(" \t\r\n") != 0) throw new Exception("whitespace lines");
        int passed = 3;
        // CPC_WORD_COUNT_CHECKS
        return passed;
    }
}
