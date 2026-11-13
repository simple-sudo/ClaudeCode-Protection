# Existing WFP diagnostic reads

Independent development diagnostic, not a product launcher or admission path.
`--inspect` checks x64 value layout without opening WFP; `--check-selection`
checks identity/image/time matching without native history reads.
`--read-fixed` reads only existing engine collection/keyword options and closes
its own connection. Denied options remain UNKNOWN, not disabled or PASS.

`--check-machine-egress-delivery` uses exclusive Windows loopback listeners
on ephemeral ports. It observes three distinct markers for each IPv4/IPv6,
TCP/UDP and new/existing socket case. The decision checks use synthetic WFP
and physical capture evidence. This command opens no WFP session.

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

`MachineEgressDropReader` selects existing outbound classify drops by the
original held filter ID, layer, short FILETIME window and exact TCP/UDP
endpoints. Its in-memory layout and matching fixtures run with
`--check-machine-egress-policy`. Native enumeration has no command-line entry
and requires a fixed run owner to supply the observed tuple and generation.
An event has no payload marker or PID. A tuple/time match can corroborate a
drop, and cannot distinguish retransmission of older data on the same flow.

The policy fixtures also exercise the Ethernet frame matcher and capture
window. A capture owner must provide the physical component identity,
direction, timebase and loss count. Matching headers are enough to identify
a payload-free SYN. Unknown direction, ambiguous fragments and missing loss
accounting cannot support a zero-delivery result.
