# Caller-owned C# project example

This ordinary source tree declares one exact edit in `cpc-project.json`.
It compiles the three selected C# files with the installed pinned Roslyn and
reference set, then calls public static `int Run()` on Entry and Checks.
No project imports, package restore, command string or host path is accepted.

The result retains the input files with the declared edit and adds five files
under `cpc-output`: a managed DLL, run/test results and bounded stdout/stderr.
It does not overwrite this source tree. This example has three tests, distinct
from the earlier embedded six-test TextSummary qualification.

The new installed caller-project operation is not yet qualified. Do not run
this example through an old grant or treat ordinary tests as LPAC proof.
