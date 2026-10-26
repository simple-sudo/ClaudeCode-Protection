# Deliberate hard stop while the revised source lacks staged qualification.
# User reports cleanup complete, no reboot, Kaspersky showing normal.
# That report does not identify the cause or qualify revised source.
# Do not add an environment switch, command-line override, expiry or automatic reset.
# Clearing this stop requires a reviewed source change and appropriate validation.
# This file performs no process, network, registry, firewall or filesystem mutation.
throw 'SECURITY_REVIEW_REQUIRED: Project build/execution is suspended after a Kaspersky detection. See docs/INCIDENT-20261025-KASPERSKY.md. No operation was started.'

