# Managed artifact metadata review

Developer-only, read-only .NET 8 utility. Pass explicit managed assembly paths; stdout contains SHA256, native imports and module-initializer checks. It reads PE metadata without loading the target assembly or invoking its entry point. It requires x64 managed PE files and rejects module initializers.

This tool does not grant permission to execute a reviewed binary or establish runtime protection. Use the existing fixed offline build controls and inspect exact dependencies before running new artifacts. No install, elevation, policy changes or network access.

For the exact ProtectionBootstrap.ApprovedPackage.json resource, the output also reports its bounded embedded-byte digest; it rejects external/duplicate approvals. Absence is null and does not grant package approval.
