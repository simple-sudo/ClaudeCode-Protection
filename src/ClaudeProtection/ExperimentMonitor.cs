using System.Diagnostics;

namespace ClaudeProtection;

internal static class ExperimentMonitor
{
    internal static async Task Wait(NativeJob job, string baseline, Func<string> readFingerprint, TimeSpan timeout, int interval = 200)
    {
        var watch = Stopwatch.StartNew();
        try
        {
            while (!job.HasExited)
            {
                if (watch.Elapsed > timeout) throw new TimeoutException("Owned probe timed out");
                if (readFingerprint() != baseline) throw new InvalidOperationException("System proxy drift detected; owned probe stopped without rewriting global settings");
                await Task.Delay(interval);
            }
        }
        catch { job.Terminate(); throw; }
    }
}
