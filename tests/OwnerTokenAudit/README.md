# Own-token audit diagnostics

`selftest` combines bounded privilege-buffer fixtures with three query-only
observations of its own ordinary identity. The variable privilege buffer is
prefilled with 00/A5/5A before each actual read; all returned bytes and flags
participate in its SHA256. Missing or failed observations remain UNKNOWN.

Comparison identifies identity-field changes, added/removed/attribute-changed
LUIDs, or raw-byte changes with equal entries. Reordering is diagnostic detail,
never an accepted replacement for the original strict raw equality gate.
It also reads the local runtime's initializer metadata (without invoking it)
and starts two fixed ordinary copies of itself: exit259 and bounded input wait
then exit7. Only original returned handles are observed; no PID attach, foreign
token, privilege adjustment, termination, protected process or system retry.
The real ordinary before/after raw privilege checks must still match.

The next finite owner can use StartedProcessObservation to avoid .NET8
ProcessManager's implicit SeDebugPrivilege enable while reading ExitCode.
This does not identify the ambiguous old stage8 failure or establish the new
alternative under elevation. All frozen failed helpers remain unchanged.
Reference layout: [TOKEN_PRIVILEGES](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-token_privileges),
[GetTokenInformation](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-gettokeninformation).
