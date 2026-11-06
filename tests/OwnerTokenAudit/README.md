# Own-token audit diagnostics

`selftest` combines bounded privilege-buffer fixtures with three query-only
observations of its own ordinary identity. The variable privilege buffer is
prefilled with 00/A5/5A before each actual read; all returned bytes and flags
participate in its SHA256. Missing or failed observations remain UNKNOWN.

Comparison identifies identity-field changes, added/removed/attribute-changed
LUIDs, or raw-byte changes with equal entries. Reordering is diagnostic detail,
never an accepted replacement for the original strict raw equality gate.
This does not grant admission, read linked/foreign tokens, adjust privileges,
launch a protected process or retry any prior system operation.

This is preparation for better fixed-owner receipts, not evidence identifying
the old elevated stage8 failure. The frozen failed helper is unchanged.
Reference layout: [TOKEN_PRIVILEGES](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-token_privileges),
[GetTokenInformation](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-gettokeninformation).
