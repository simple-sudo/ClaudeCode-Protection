# Exact capability observation

Ordinary source-linked security checks for the original owner's capability
reader. Exercises bounded TOKEN_GROUPS parsing, native SID offsets/lengths,
duplicates, identity/attribute substitution, immutable observations, and a
real query of only the test process's own token. No token mutation, process
creation, WFP, network, registry, elevation or protected execution occurs.

Production `AtomicChild.ReadToken` now obtains the count through this actual
SID/attribute reader. Existing normal root/tool/runtime/gateway flows still
require zero capabilities. A distinct fixed gateway qualification now selects
the exact internetClient singleton in source; it has no daily/GUI/formal or
caller-configurable selection. Its new build/install/native run requires its
own fixed qualification and human decision. Synthetic nonzero buffers are L1 evidence;
the real own-token query is an ordinary zero-capability observation. They do
not establish an LPAC network result or capability-exposure safety.
