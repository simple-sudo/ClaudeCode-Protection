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

The timed probe uses the original NativeBoundary request bytes and access masks;
the older matrices/schema remain unchanged. These additions do not qualify
Socket/HTTPS, privacy L3, an installed native lifecycle or official Claude.
