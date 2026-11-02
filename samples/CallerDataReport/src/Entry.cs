using System.IO;
using System.Linq;
using System.Text.Json;

namespace DataReport;
public static class Entry
{
    public static int Total(int[] values) { return values[0]; }
    public static int Run()
    {
        var values=JsonSerializer.Deserialize<int[]>(File.ReadAllText("data/values.json"));
        if(values is null) return 1;
        Directory.CreateDirectory("cpc-results");
        File.WriteAllText("cpc-results/summary.json",JsonSerializer.Serialize(new {Count=values.Length,Total=Total(values)}));
        return 0;
    }
}
