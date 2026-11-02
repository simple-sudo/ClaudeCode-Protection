using System;
using System.IO;
using System.Text.Json;

namespace DataReport;
public static class Checks
{
    public static int Run()
    {
        if(Entry.Total(new[]{3,4,5})!=12) throw new Exception("Total");
        if(Entry.Total(Array.Empty<int>())!=0) throw new Exception("Empty");
        using var result=JsonDocument.Parse(File.ReadAllText("cpc-results/summary.json"));
        if(result.RootElement.GetProperty("Count").GetInt32()!=3 || result.RootElement.GetProperty("Total").GetInt32()!=12)
            throw new Exception("Report");
        return 3;
    }
}
