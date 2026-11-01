# TextSummary

A small .NET 8 library for counting nonempty lines in text. `ProjectTests.Run()`
checks empty, multiline and whitespace-only input without external packages.

The protected development task adds `Counter.CountWords(string)` with Unicode
whitespace handling and three regression cases, builds the library, executes
its tests and runs both counters on the same input. The exported result includes
the modified project sources, compiled library and fixed run/test results.

The product compiles the explicit source files with its pinned Roslyn and
reference assemblies. It does not evaluate this project file with MSBuild or
load caller-controlled build tasks, packages, analyzers or generators.
