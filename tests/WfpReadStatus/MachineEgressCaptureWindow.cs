internal enum MachineEgressCaptureDirection { Unknown, Inbound, Outbound }

internal readonly record struct MachineEgressCaptureFrame(uint Component, long Timestamp,
    MachineEgressCaptureDirection Direction, ReadOnlyMemory<byte> Ethernet);

// Component identity and loss accounting come from the capture owner, using
// the same clock as the observation window. Neither is inferred from bytes.
internal sealed class MachineEgressCaptureWindow
{
    private readonly uint component;
    private readonly long start, end;
    private readonly MachineEgressFrameMatch match;
    private bool indeterminate;
    internal int MatchedFrames { get; private set; }

    internal MachineEgressCaptureWindow(uint component, long start, long end, MachineEgressFrameMatch match)
    {
        ArgumentNullException.ThrowIfNull(match);
        if (component == 0 || start < 0 || end <= start)
            throw new ArgumentException("Invalid machine egress capture window");
        this.component = component;
        this.start = start;
        this.end = end;
        this.match = match;
    }

    internal void Observe(MachineEgressCaptureFrame frame)
    {
        if (frame.Timestamp < start || frame.Timestamp > end) return;
        if (frame.Component == 0)
        {
            indeterminate = true;
            return;
        }
        if (frame.Component != component || frame.Direction == MachineEgressCaptureDirection.Inbound) return;

        var result = match.Classify(frame.Ethernet.Span);
        if (result == MachineEgressFrameResult.Unrelated) return;
        if (result == MachineEgressFrameResult.Indeterminate || frame.Direction != MachineEgressCaptureDirection.Outbound)
            indeterminate = true;
        else
            MatchedFrames = checked(MatchedFrames + 1);
    }

    internal bool IsComplete(long captureStart, long captureEnd, ulong? lostRecords) =>
        captureStart >= 0 && captureStart <= start && captureEnd >= end && lostRecords == 0 && !indeterminate;
}
