using System;

namespace TextSummary;

public static class Counter
{
    public static int CountLines(string text)
    {
        int count = 0;
        foreach (string line in text.Split('\n'))
            if (!string.IsNullOrWhiteSpace(line)) count++;
        return count;
    }

    // CPC_WORD_COUNT_EXTENSION
}
