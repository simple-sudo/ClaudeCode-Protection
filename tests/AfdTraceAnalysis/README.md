# AFD create event decoding and correlation

Ordinary deterministic analysis, separate from the privileged capture observer.
No ETW control, device access, Token change or network API.
The executable runs L1 parser/correlation fixtures and one fixed ordinary own
child to verify the full Win32 error-stage exit code survives without a file or
UAC. Its only argument mode, `--own-stage-exit`, returns that constant stage.
It also reads only its own creation time using GetProcessTimes and the current
process pseudo handle; no OpenProcess, PID argument or DACL change is used.
Filter tests allocate only fixed event1000 data and make no tracing call.
`AfdAnalysisBridge.Analyze` accepts data, never a path or execution request.

Checks the fixed provider, event 1000/version 0, ordered nine-field manifest,
numeric widths and UTC timestamps. DTDs, duplicate fields, malformed scalars and
oversized inputs are rejected. Kernel pointer values are parsed for shape but
omitted from the decoded projection. Unknown locations remain UNKNOWN.

Three separately timed synchronous AFD requests must have the same actor PID and
creation time, ordered nonoverlapping windows, and nonzero native thread IDs.
Correlation requires payload PID, header PID, header TID and the precise FILETIME
call window. Matching statuses and expected marker locations are observations,
not proof of a unique failure cause. No event is UNKNOWN, never proof that a
branch did not execute. Trace loss/wrap and original-owner result/actor binding
must be checked separately by the trusted fixed reader.

Matched-image mappings include1006 (endpoint allocated) and1013
(AfdCompleteTLEndpCreate). The latter logs completion status for success OR
failure; retain EnterExit/status/time rather than labelling the location alone
as denial. Real observed0→C0000022 is a scoped transport-completion finding,
not a unique root cause. UTC conversion accepts an already-UTC DateTime or the
original ISO-Z string, preserving fractional ticks; local/unspecified time is
refused. Do not culture-format and reparse PowerShell JSON DateTime objects.

The TCPIP decoder uses the locally inspected provider2F07E2EE… contracts for
1001/v0,1010–1012/v0–1,1013/v0–2 and1562/v0. It validates ordered field sets,
DWORD widths, full UInt64 ProcessStartKey and bounded socket-address bytes;
kernel endpoint pointers are omitted. A start key is NOT interpreted as a
creation FILETIME. Correlation retains exact header/payload PID/TID/call-window
requirements and never declares unique root cause or network admission.

The timed probe uses the original NativeBoundary request bytes and access masks;
the older matrices/schema remain unchanged. These additions do not qualify
Socket/HTTPS, privacy L3, an installed native lifecycle or official Claude.
