# Exact capability observation

Ordinary source-linked security checks for the original owner's capability
reader. Exercises bounded TOKEN_GROUPS parsing, native SID offsets/lengths,
duplicates, identity/attribute substitution, immutable observations, and a
real query of only the test process's own token. No token mutation, process
creation, WFP, network, registry, elevation or protected execution occurs.

Production `AtomicChild.ReadToken` now obtains the count through this actual
SID/attribute reader. All existing root/tool/runtime/gateway checks still
require zero capabilities. The exact internetClient singleton predicate is
preparation for a separately reviewed fixed qualification, with no production
caller or grant path. Synthetic nonzero capability buffers are L1 evidence;
the real own-token query is an ordinary zero-capability observation. They do
not establish an LPAC network result or capability-exposure safety.
