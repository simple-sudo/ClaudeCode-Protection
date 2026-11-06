# Existing WFP diagnostic reads

Independent development diagnostic, not a product launcher or admission path.
`--inspect` checks x64 value layout without opening WFP; `--check-selection`
checks identity/image/time matching without native history reads.
`--read-fixed` reads only existing engine collection/keyword options and closes
its own connection. Denied options remain UNKNOWN, not disabled or PASS.

`ExistingEvents.cs` has no public CLI. A separately frozen fixed entry point may
compile one reviewed historical selection. It never enables collection,
subscribes, starts a trace, changes filters, or starts a protected process.
At most 16 pages of 128 existing events and 16 selected drops are examined;
selection requires package SID, user SID, image suffix and a <=5-second window.
The 15-second scheduling limit is checked between synchronous Windows calls;
it is not a hard cancellation guarantee for a stalled RPC.

HEADER2 provides no PID/TID. Selected history cannot independently prove exact
actor identity, history completeness, or a unique cause. Missing/evicted events
and disabled collection remain UNKNOWN. Selected filter/layer IDs are read from
the current engine; a current filter is not proof of its historical identity.
All raw evidence stays local. Nothing here grants a network capability or
relaxes the installed original owner's privacy/Job/WFP checks.
