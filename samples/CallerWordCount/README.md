# Caller-owned C# project example

This ordinary source tree declares one exact edit in `cpc-project.json`.
It compiles the three selected C# files with the installed pinned Roslyn and
reference set, then calls public static `int Run()` on Entry and Checks.
No project imports, package restore, command string or host path is accepted.
The working-tree Entry also checks relative access to `src/Counter.cs`; this
targets the subsequent project-working-directory repair. The earlier native
42f qualification retains its original frozen 9F07 bytes without this check.

The result retains the input files with the declared edit and adds five files
under `cpc-output`: a managed DLL, run/test results and bounded stdout/stderr.
It does not overwrite this source tree. This example has three tests, distinct
from the earlier embedded six-test TextSummary qualification.

The original frozen caller task passed native 42f qualification. Its evidence
does not qualify this later relative-I/O variant. Do not reuse consumed grants
or treat ordinary tests as proof for a new protected execution.
