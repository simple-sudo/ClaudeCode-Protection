using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace ProtectionLifecycle;

// Hosted-only integration fixture. It creates a real LPAC process with the
// same three creation attributes used by AtomicAdmission: package SID,
// ALL_APPLICATION_PACKAGES_POLICY=OPT_OUT, and Job assignment at creation.
// It then exercises the production GitWorkspaceDescriptor on real NTFS.
// LowBox MIC permits a medium-IL object when its DACL grants the package SID;
// the fixture verifies both that positive case and a same-IL DACL-denied case.
// This does not invoke the installed Broker or claim product Job/LPAC E2E.
internal static class NativeGitLpacAccessCases
{
    private const string AdministratorsSid = "S-1-5-32-544";
    private const string SystemSid = "S-1-5-18";
    private const string OwnerRightsSid = "S-1-3-4";
    private const string UsersSid = "S-1-5-32-545";
    private const string LowIntegritySid = "S-1-16-4096";
    private const string MediumIntegritySid = "S-1-16-8192";
    private const int FileObject = 1;
    private const uint ShareAll = 0x00000007;
    private const uint OpenExisting = 3;
    private const uint OpenReparsePoint = 0x00200000;
    private const uint BackupSemantics = 0x02000000;
    private const uint ReadControlAndAttributes = 0x00020080;
    private const int ProjectPackageMask = 0x001301bf;
    private const int ControlPackageMask = 0x001200a9;
    private const uint CreateSuspendedExtendedUnicodeNoWindow = 0x08080404;
    private const uint ProcThreadAttributeSecurityCapabilities = 0x20009;
    private const uint ProcThreadAttributeJobList = 0x2000d;
    private const uint ProcThreadAttributeAllApplicationPackagesPolicy = 0x2000f;

    internal static void Run(string humanSid, string packageName, string expectedPackageSid)
    {
        _ = new SecurityIdentifier(humanSid);
        var package = new SecurityIdentifier(expectedPackageSid);
        if (!package.Value.StartsWith("S-1-15-2-", StringComparison.Ordinal) || packageName.Length is < 1 or > 64)
            throw new InvalidDataException("LpacGitWorkspaceProfileInputInvalid");

        using var identity = WindowsIdentity.GetCurrent();
        if (!new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))
            throw new InvalidOperationException("LpacGitWorkspaceRequiresElevatedHostedFixture");

        var profileStatus = CreateAppContainerProfile(packageName, "ClaudeCodeProtection Git workspace LPAC fixture",
            "Ephemeral hosted NTFS and LPAC access qualification", IntPtr.Zero, 0, out var profileSid);
        if (profileStatus != 0)
        {
            if (profileSid != IntPtr.Zero) _ = FreeSid(profileSid);
            throw new InvalidOperationException("LpacGitWorkspaceProfileCreateFailed:" + profileStatus.ToString("X8", System.Globalization.CultureInfo.InvariantCulture));
        }

        var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        if (string.IsNullOrWhiteSpace(programFiles))
            throw new InvalidDataException("LpacGitWorkspaceProgramFilesRootMissing");
        var root = Path.Combine(programFiles, "CpcGitLpacAccess-" + Guid.NewGuid().ToString("N"));
        try
        {
            if (profileSid == IntPtr.Zero || new SecurityIdentifier(profileSid).Value != package.Value)
                throw new InvalidDataException("LpacGitWorkspaceProfileSidMismatch");

            // Match the production SessionTaskWorkspace root: a fresh, writable,
            // Low-integrity task directory under the publicly traversable Program Files parent.
            CreateProtectedDirectory(root, package.Value, ProjectPackageMask, LowIntegritySid, humanSid);
            using (var parent = WindowsPathSeal.LockDirectory(root, PathPolicy.Source))
            using (var project = GitWorkspaceDescriptor.Create(parent, "git-project", package.Value, true))
            using (var control = GitWorkspaceDescriptor.Create(parent, "git-control", package.Value, false))
            {
                var projectPath = Path.Combine(root, "git-project");
                var controlPath = Path.Combine(root, "git-control");
                GitWorkspaceDescriptor.AssertPath(projectPath, package.Value, true);
                GitWorkspaceDescriptor.AssertPath(controlPath, package.Value, false);

                var projectSource = Path.Combine(projectPath, "source.txt");
                File.WriteAllText(projectSource, "project-source", new UTF8Encoding(false));
                AssertInheritedFile(projectSource, package.Value, humanSid, ProjectPackageMask, LowIntegritySid);
                File.WriteAllText(Path.Combine(controlPath, "empty-git-config"), string.Empty, new UTF8Encoding(false));
                Directory.CreateDirectory(Path.Combine(controlPath, "empty-git-hooks"));
                Directory.CreateDirectory(Path.Combine(controlPath, "empty-git-template"));
                File.WriteAllBytes(Path.Combine(controlPath, "git-selected-paths.bin"), new byte[] { 0x61, 0x00 });

                var expectedControlNames = new[]
                {
                    "empty-git-config", "empty-git-hooks", "empty-git-template", "git-selected-paths.bin"
                };
                var actualControlNames = Directory.EnumerateFileSystemEntries(controlPath)
                    .Select(Path.GetFileName).Order(StringComparer.Ordinal).ToArray();
                if (!actualControlNames.SequenceEqual(expectedControlNames.Order(StringComparer.Ordinal), StringComparer.Ordinal))
                    throw new InvalidDataException("LpacGitWorkspaceControlInventoryMismatch");

                var mediumPath = Path.Combine(root, "medium-write");
                CreateProtectedDirectory(mediumPath, package.Value, ProjectPackageMask, MediumIntegritySid, humanSid);
                var mediumFile = Path.Combine(mediumPath, "medium.txt");
                File.WriteAllText(mediumFile, "medium-original", new UTF8Encoding(false));
                AssertInheritedFile(mediumFile, package.Value, humanSid, ProjectPackageMask, MediumIntegritySid);

                // Same Medium IL, but package read-only DACL. This proves that
                // the ACL, not an assumed LowBox MIC write-up rule, protects data.
                var mediumReadOnlyPath = Path.Combine(root, "medium-readonly");
                CreateProtectedDirectory(mediumReadOnlyPath, package.Value, ControlPackageMask, MediumIntegritySid, humanSid);
                var mediumReadOnlyFile = Path.Combine(mediumReadOnlyPath, "medium-readonly.txt");
                File.WriteAllText(mediumReadOnlyFile, "medium-readonly-original", new UTF8Encoding(false));
                AssertInheritedFile(mediumReadOnlyFile, package.Value, humanSid, ControlPackageMask, MediumIntegritySid);

                RunActualLpacProcess(root, package.Value);

                if (File.ReadAllText(Path.Combine(projectPath, "lpac-write.txt")) != "project-write" + Environment.NewLine ||
                    File.ReadAllText(Path.Combine(projectPath, "lpac-created", "nested.txt")) != "nested" + Environment.NewLine)
                    throw new InvalidDataException("LpacGitWorkspaceProjectWriteNotObserved");
                if (File.ReadAllText(Path.Combine(projectPath, "source.txt")) != "project-source")
                    throw new InvalidDataException("LpacGitWorkspaceProjectSourceChanged");
                if (File.ReadAllText(Path.Combine(controlPath, "empty-git-config")) != string.Empty ||
                    !File.ReadAllBytes(Path.Combine(controlPath, "git-selected-paths.bin")).SequenceEqual(new byte[] { 0x61, 0x00 }) ||
                    Directory.Exists(Path.Combine(controlPath, "lpac-created")))
                    throw new InvalidDataException("LpacGitWorkspaceControlWriteWasNotDenied");
                if (File.ReadAllText(mediumFile) != "medium-tamper" + Environment.NewLine)
                    throw new InvalidDataException("LpacGitWorkspaceLowBoxMediumPackageGrantMismatch");
                if (File.ReadAllText(mediumReadOnlyFile) != "medium-readonly-original")
                    throw new InvalidDataException("LpacGitWorkspaceMediumReadOnlyDaclWriteWasNotDenied");
                if (File.ReadAllText(Path.Combine(root, "lpac-root-write.txt")) != "root-write" + Environment.NewLine)
                    throw new InvalidDataException("LpacGitWorkspaceRootWriteNotObserved");
                var expectedRootNames = new[] { "git-control", "git-project", "lpac-root-write.txt", "medium-readonly", "medium-write" };
                if (!Directory.EnumerateFileSystemEntries(root).Select(Path.GetFileName)
                    .Order(StringComparer.Ordinal).SequenceEqual(expectedRootNames.Order(StringComparer.Ordinal), StringComparer.Ordinal))
                    throw new InvalidDataException("LpacGitWorkspaceRootInventoryChanged");
                var expectedProjectNames = new[] { "lpac-created", "lpac-write.txt", "source.txt" };
                if (!Directory.EnumerateFileSystemEntries(projectPath).Select(Path.GetFileName)
                    .Order(StringComparer.Ordinal).SequenceEqual(expectedProjectNames.Order(StringComparer.Ordinal), StringComparer.Ordinal))
                    throw new InvalidDataException("LpacGitWorkspaceProjectInventoryMismatch");
                if (!Directory.EnumerateFileSystemEntries(controlPath).Select(Path.GetFileName)
                    .Order(StringComparer.Ordinal).SequenceEqual(expectedControlNames.Order(StringComparer.Ordinal), StringComparer.Ordinal) ||
                    Directory.EnumerateFileSystemEntries(mediumPath).Select(Path.GetFileName).SingleOrDefault() != "medium.txt" ||
                    Directory.EnumerateFileSystemEntries(mediumReadOnlyPath).Select(Path.GetFileName).SingleOrDefault() != "medium-readonly.txt")
                    throw new InvalidDataException("LpacGitWorkspaceProtectedInventoryChanged");

                Console.WriteLine("PASS actual LPAC token: AppContainer, exact package SID, zero capabilities, Low Integrity, access-check mask 2, pre-resume Job membership");
                Console.WriteLine("PASS actual LPAC NTFS access: project read/write; Git control read-only; Medium-IL package grant honored; Medium-IL read-only DACL denies write");
            }
        }
        finally
        {
            try
            {
                if (Directory.Exists(root)) Directory.Delete(root, true);
            }
            finally
            {
                try
                {
                    var deleteStatus = DeleteAppContainerProfile(packageName);
                    if (deleteStatus != 0)
                        throw new InvalidOperationException("LpacGitWorkspaceProfileDeleteFailed:" + deleteStatus.ToString("X8", System.Globalization.CultureInfo.InvariantCulture));
                }
                finally
                {
                    if (profileSid != IntPtr.Zero) _ = FreeSid(profileSid);
                }
            }
        }
    }

    private static void RunActualLpacProcess(string root, string packageSid)
    {
        if (Marshal.SizeOf<StartupInfo>() != 104 || Marshal.SizeOf<StartupInfoEx>() != 112 ||
            Marshal.SizeOf<SecurityCapabilities>() != 24 || Marshal.SizeOf<SecurityAttributes>() != 24)
            throw new PlatformNotSupportedException("LpacGitWorkspaceNativeLayoutMismatch");

        var commandImage = Path.Combine(Environment.SystemDirectory, "cmd.exe");
        if (!File.Exists(commandImage)) throw new FileNotFoundException("LpacGitWorkspaceCommandImageMissing");

        using var job = CreateJobObject(IntPtr.Zero, null);
        if (job.IsInvalid) throw Error("LpacGitWorkspaceCreateJob");

        var package = new SecurityIdentifier(packageSid);
        var packageBytes = new byte[package.BinaryLength];
        package.GetBinaryForm(packageBytes, 0);
        IntPtr packagePointer = IntPtr.Zero, attributes = IntPtr.Zero, capabilities = IntPtr.Zero;
        IntPtr jobList = IntPtr.Zero, policy = IntPtr.Zero, environment = IntPtr.Zero, probeEnvironment = IntPtr.Zero;
        IntPtr processDescriptor = IntPtr.Zero, threadDescriptor = IntPtr.Zero;
        SafeProcessHandle? process = null;
        SafeWaitHandle? thread = null;
        var initialized = false;
        var childCreated = false;
        var childCompleted = false;
        try
        {
            packagePointer = Marshal.AllocHGlobal(packageBytes.Length);
            Marshal.Copy(packageBytes, 0, packagePointer, packageBytes.Length);
            nuint attributeSize = 0;
            _ = InitializeProcThreadAttributeList(IntPtr.Zero, 3, 0, ref attributeSize);
            if (attributeSize is 0 or > 65536) throw new InvalidDataException("LpacGitWorkspaceAttributeListBounds");
            attributes = Marshal.AllocHGlobal(checked((int)attributeSize));
            if (!InitializeProcThreadAttributeList(attributes, 3, 0, ref attributeSize))
                throw Error("LpacGitWorkspaceInitializeAttributes");
            initialized = true;

            capabilities = Marshal.AllocHGlobal(Marshal.SizeOf<SecurityCapabilities>());
            Marshal.StructureToPtr(new SecurityCapabilities
            {
                AppContainerSid = packagePointer,
                Capabilities = IntPtr.Zero,
                CapabilityCount = 0,
                Reserved = 0
            }, capabilities, false);
            if (!UpdateProcThreadAttribute(attributes, 0, (IntPtr)ProcThreadAttributeSecurityCapabilities,
                capabilities, (nuint)Marshal.SizeOf<SecurityCapabilities>(), IntPtr.Zero, IntPtr.Zero))
                throw Error("LpacGitWorkspaceBindPackage");

            policy = Marshal.AllocHGlobal(sizeof(uint));
            Marshal.WriteInt32(policy, 1); // ALL_APPLICATION_PACKAGES_POLICY_OPT_OUT (LPAC).
            if (!UpdateProcThreadAttribute(attributes, 0, (IntPtr)ProcThreadAttributeAllApplicationPackagesPolicy,
                policy, sizeof(uint), IntPtr.Zero, IntPtr.Zero))
                throw Error("LpacGitWorkspaceBindLpacPolicy");

            jobList = Marshal.AllocHGlobal(IntPtr.Size);
            Marshal.WriteIntPtr(jobList, job.DangerousGetHandle());
            if (!UpdateProcThreadAttribute(attributes, 0, (IntPtr)ProcThreadAttributeJobList,
                jobList, (nuint)IntPtr.Size, IntPtr.Zero, IntPtr.Zero))
                throw Error("LpacGitWorkspaceBindJob");

            var initialCwdPath = Path.Combine(root, "lpac-start-cwd.txt");
            var finalCwdPath = Path.Combine(root, "lpac-final-cwd.txt");
            var projectSourcePath = Path.Combine(root, "git-project", "source.txt");
            var projectReadCopyPath = Path.Combine(root, "lpac-project-read.bin");
            var controlConfigReadCopyPath = Path.Combine(root, "lpac-control-config-read.bin");
            var controlPathspecReadCopyPath = Path.Combine(root, "lpac-control-pathspec-read.bin");
            var mediumReadCopyPath = Path.Combine(root, "lpac-medium-read.bin");
            var mediumReadOnlyFilePath = Path.Combine(root, "medium-readonly", "medium-readonly.txt");
            var mediumReadOnlyReadCopyPath = Path.Combine(root, "lpac-medium-readonly-read.bin");
            var mediumWritePayloadPath = Path.Combine(root, "lpac-medium-write-payload.bin");
            var controlConfigPath = Path.Combine(root, "git-control", "empty-git-config");
            var controlPathspecPath = Path.Combine(root, "git-control", "git-selected-paths.bin");
            var mediumFilePath = Path.Combine(root, "medium-write", "medium.txt");
            var projectWritePath = Path.Combine(root, "git-project", "lpac-write.txt");
            var projectCreatedPath = Path.Combine(root, "git-project", "lpac-created");
            var projectNestedPath = Path.Combine(projectCreatedPath, "nested.txt");
            var controlWritePath = controlConfigPath;
            var controlCreatedPath = Path.Combine(root, "git-control", "lpac-created");
            var mediumWritePath = mediumFilePath;
            static string Quote(string path) => "\"" + path + "\"";
            // Use exact bytes rather than cmd.exe ECHO redirection, which can
            // preserve a space before the redirection operator in file content.
            File.WriteAllBytes(mediumWritePayloadPath, Encoding.ASCII.GetBytes("medium-tamper"));
            var script =
                "echo %CD%>" + Quote(initialCwdPath) + " & " +
                "echo %CD%>" + Quote(finalCwdPath) + " & " +
                "echo root-write>" + Quote(Path.Combine(root, "lpac-root-write.txt")) + " & " +
                "copy /b " + Quote(projectSourcePath) + " " + Quote(projectReadCopyPath) + " || exit /b 11 & " +
                "copy /b " + Quote(controlConfigPath) + " " + Quote(controlConfigReadCopyPath) + " || exit /b 12 & " +
                "copy /b " + Quote(controlPathspecPath) + " " + Quote(controlPathspecReadCopyPath) + " || exit /b 13 & " +
                "copy /b " + Quote(mediumFilePath) + " " + Quote(mediumReadCopyPath) + " || exit /b 14 & " +
                "copy /b " + Quote(mediumReadOnlyFilePath) + " " + Quote(mediumReadOnlyReadCopyPath) + " || exit /b 15 & " +
                "echo project-write>" + Quote(projectWritePath) + " & " +
                "mkdir " + Quote(projectCreatedPath) + " & " +
                "echo nested>" + Quote(projectNestedPath) + " & " +
                "echo control-tamper>" + Quote(controlWritePath) + " & " +
                "mkdir " + Quote(controlCreatedPath) + " & " +
                "copy /b /y " + Quote(mediumWritePayloadPath) + " " + Quote(mediumWritePath) + " >nul & " +
                "copy /b /y " + Quote(mediumWritePayloadPath) + " " + Quote(mediumReadOnlyFilePath) + " >nul & " +
                "exit /b 0";
            // Keep the already-observed inline cmd /c execution path. The fixed
            // command uses only generated workspace paths and fixed operations;
            // absolute file paths separate CWD from ACL access; both CWD observations must match the CreateProcess path.
            var commandLine = "\"" + commandImage + "\" /d /q /c \"" + script + "\"";
            var values = new SortedDictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var name in new[] { "SystemRoot", "windir", "SystemDrive" })
            {
                var value = Environment.GetEnvironmentVariable(name);
                if (value is not null) values[name] = value;
            }
            var driveRoot = Path.GetPathRoot(root);
            if (driveRoot is null || driveRoot.Length < 2 || driveRoot[1] != ':')
                throw new InvalidDataException("LpacGitWorkspaceCurrentDriveInvalid");
            values["=" + driveRoot[..2]] = root;
            values["ComSpec"] = commandImage;
            values["PATH"] = Environment.SystemDirectory;
            // Match AtomicAdmission.SetPrivateRuntimeDirectories: TEMP/TMP,
            // USERPROFILE and LOCALAPPDATA all point at the fresh task-workspace
            // root, never the host profile. LOCALAPPDATA is isolated below to
            // prove the native 0xCB dependency by a one-variable A/B.
            var privateRuntimeDirectory = root;
            values["TEMP"] = privateRuntimeDirectory;
            values["TMP"] = privateRuntimeDirectory;
            values["USERPROFILE"] = privateRuntimeDirectory;
            var blockWithoutLocalAppData = string.Join('\0', values.Select(pair => pair.Key + "=" + pair.Value)) + "\0";
            probeEnvironment = Marshal.StringToHGlobalUni(blockWithoutLocalAppData);
            const string sessionObjectSddl = "O:BAD:P(A;;0x001fffff;;;SY)(A;;0x001fffff;;;BA)";
            if (!ConvertStringSecurityDescriptorToSecurityDescriptor(sessionObjectSddl, 1, out processDescriptor, out _) ||
                !ConvertStringSecurityDescriptorToSecurityDescriptor(sessionObjectSddl, 1, out threadDescriptor, out _))
                throw Error("LpacGitWorkspaceBuildProcessSecurity");
            var processSecurity = new SecurityAttributes
            {
                Length = Marshal.SizeOf<SecurityAttributes>(),
                Descriptor = processDescriptor,
                InheritHandle = 0
            };
            var threadSecurity = new SecurityAttributes
            {
                Length = Marshal.SizeOf<SecurityAttributes>(),
                Descriptor = threadDescriptor,
                InheritHandle = 0
            };
            var startup = new StartupInfoEx
            {
                Basic = new StartupInfo { Size = (uint)Marshal.SizeOf<StartupInfoEx>() },
                Attributes = attributes
            };

            // Minimal A/B: same LPAC package, LPAC policy, Job-at-creation,
            // process/thread descriptors, image, command line and cwd.
            // The only environment difference is LOCALAPPDATA.
            if (!CreateProcess(commandImage, new StringBuilder(commandLine), ref processSecurity, ref threadSecurity, false,
                CreateSuspendedExtendedUnicodeNoWindow, probeEnvironment, root, ref startup, out var probeInfo))
            {
                var probeError = Marshal.GetLastWin32Error();
                if (probeError != 203)
                    throw new InvalidOperationException("LpacGitWorkspaceMissingLocalAppDataProbeUnexpected:Win32=0x" +
                        probeError.ToString("X8", System.Globalization.CultureInfo.InvariantCulture), new Win32Exception(probeError));
                Console.WriteLine("PASS LPAC CreateProcess A/B: omitting LOCALAPPDATA returns ERROR_ENVVAR_NOT_FOUND (203)");
            }
            else
            {
                childCreated = true;
                process = new SafeProcessHandle(probeInfo.Process, true);
                thread = new SafeWaitHandle(probeInfo.Thread, true);
                if (process.IsInvalid || thread.IsInvalid)
                    throw new InvalidDataException("LpacGitWorkspaceMissingLocalAppDataProbeHandlesInvalid");
                if (!TerminateProcess(process, 0xC000013A)) throw Error("LpacGitWorkspaceTerminateUnexpectedProbe");
                var probeWait = WaitForSingleObject(process, 5000);
                if (probeWait != 0) throw Error("LpacGitWorkspaceWaitUnexpectedProbe");
                childCompleted = true;
                thread.Dispose(); thread = null;
                process.Dispose(); process = null;
                childCreated = false; childCompleted = false;
                Console.WriteLine("INFO LPAC CreateProcess A/B: omission did not reproduce 203 on this runner");
            }

            values["LOCALAPPDATA"] = privateRuntimeDirectory;
            var block = string.Join('\0', values.Select(pair => pair.Key + "=" + pair.Value)) + "\0";
            environment = Marshal.StringToHGlobalUni(block);
            if (!CreateProcess(commandImage, new StringBuilder(commandLine), ref processSecurity, ref threadSecurity, false,
                CreateSuspendedExtendedUnicodeNoWindow, environment, root, ref startup, out var info))
            {
                var nativeError = Marshal.GetLastWin32Error();
                var parentJobQuery = IsProcessInJob(GetCurrentProcess(), IntPtr.Zero, out var parentInJob);
                throw new InvalidOperationException("LpacGitWorkspaceCreateSuspendedChild:Win32=0x" +
                    nativeError.ToString("X8", System.Globalization.CultureInfo.InvariantCulture) +
                    ";LocalAppDataPresent=True;LocalAppDataPrivateWorkspace=True" +
                    ";ParentJobQuery=" + parentJobQuery.ToString() + ";ParentInJob=" + parentInJob.ToString(),
                    new Win32Exception(nativeError));
            }
            childCreated = true;
            Console.WriteLine("PASS LPAC CreateProcessW: LOCALAPPDATA and USERPROFILE bound to the private writable workspace");
            process = new SafeProcessHandle(info.Process, true);
            thread = new SafeWaitHandle(info.Thread, true);
            if (process.IsInvalid || thread.IsInvalid)
                throw new InvalidDataException("LpacGitWorkspaceCreatedHandleMissing");
            if (!IsProcessInJob(process, job, out var inJob) || !inJob)
                throw new InvalidDataException("LpacGitWorkspaceJobBindingNotObserved");

            if (!OpenProcessToken(process, 0x000a, out var token))
                throw Error("LpacGitWorkspaceOpenPrimaryToken");
            using (token)
            {
                var isAppContainer = ReadTokenDword(token, 29) == 1;
                var actualPackageSid = ReadTokenSid(token, 31);
                var capabilityCount = ReadTokenCount(token, 30);
                var integritySid = ReadTokenSid(token, 25);
                // TokenMandatoryPolicy is TOKEN_INFORMATION_CLASS 27.
                // Integrity SID alone does not prove NO_WRITE_UP is active.
                var mandatoryPolicy = ReadTokenDword(token, 27);
                var packageAccess = ProbeApplicationPackageAccess(token);
                if (!isAppContainer || actualPackageSid != packageSid || capabilityCount != 0 ||
                    integritySid != LowIntegritySid || packageAccess != 2)
                    throw new InvalidDataException("LpacGitWorkspaceTokenQualificationFailed");

                var programFiles = Path.GetDirectoryName(root) ?? throw new InvalidDataException("LpacGitWorkspaceProgramFilesParentMissing");
                var driveVolumeRoot = Path.GetPathRoot(root) ?? throw new InvalidDataException("LpacGitWorkspaceDriveRootMissing");
                var pathProbes = new[]
                {
                    "drive-root-open=" + ProbeOpenAsLpac(token, driveVolumeRoot, true, 0x20),
                    "program-files-traverse=" + ProbeOpenAsLpac(token, programFiles, true, 0x20),
                    "task-root-traverse=" + ProbeOpenAsLpac(token, root, true, 0x20),
                    "task-root-add-file=" + ProbeOpenAsLpac(token, root, true, 0x22),
                    "project-dir-read-write=" + ProbeOpenAsLpac(token, Path.Combine(root, "git-project"), true, 0x27),
                    "project-source-read-data=" + ProbeOpenAsLpac(token, Path.Combine(root, "git-project", "source.txt"), false, 0x1),
                    "project-source-generic-read=" + ProbeOpenAsLpac(token, Path.Combine(root, "git-project", "source.txt"), false, 0x80000000),
                    "control-dir-read=" + ProbeOpenAsLpac(token, Path.Combine(root, "git-control"), true, 0x21),
                    "control-dir-add-file=" + ProbeOpenAsLpac(token, Path.Combine(root, "git-control"), true, 0x22)
                };
                var mediumWriteProbe = ProbeOpenAsLpac(token, Path.Combine(root, "medium-write", "medium.txt"), false, 0x2);
                var mediumReadOnlyReadProbe = ProbeOpenAsLpac(token, mediumReadOnlyFilePath, false, 0x1);
                var mediumReadOnlyWriteProbe = ProbeOpenAsLpac(token, mediumReadOnlyFilePath, false, 0x2);
                pathProbes = pathProbes.Append("medium-file-write-data=" + mediumWriteProbe)
                    .Append("medium-readonly-file-read-data=" + mediumReadOnlyReadProbe)
                    .Append("medium-readonly-file-write-data=" + mediumReadOnlyWriteProbe).ToArray();
                Console.WriteLine("INFO LPAC token mandatory policy: 0x" +
                    mandatoryPolicy.ToString("X8", System.Globalization.CultureInfo.InvariantCulture));
                if ((mandatoryPolicy & 0x1) == 0 || (mandatoryPolicy & ~0x3) != 0)
                    throw new InvalidDataException("LpacGitWorkspaceMandatoryPolicyMismatch:0x" +
                        mandatoryPolicy.ToString("X8", System.Globalization.CultureInfo.InvariantCulture));
                if (mediumWriteProbe != "PASS" || mediumReadOnlyReadProbe != "PASS" ||
                    mediumReadOnlyWriteProbe != "Win32=0x00000005")
                    throw new InvalidDataException("LpacGitWorkspaceMediumIntegrityDaclProbeMismatch:" + string.Join(";", pathProbes));
                Console.WriteLine("INFO LPAC path access probes (actual token impersonation): " + string.Join(";", pathProbes));
            }

            var resume = ResumeThread(thread);
            if (resume != 1) throw Error("LpacGitWorkspaceResumeChild");
            var wait = WaitForSingleObject(process, 60000);
            if (wait == 258) throw new TimeoutException("LpacGitWorkspaceChildTimeout");
            if (wait != 0) throw Error("LpacGitWorkspaceWaitChild");
            childCompleted = true;
            if (!GetExitCodeProcess(process, out var exitCode)) throw Error("LpacGitWorkspaceReadChildExit");
            if (exitCode != 0)
            {
                var copyDiagnostics = "project=" + File.Exists(projectReadCopyPath) +
                    ";controlConfig=" + File.Exists(controlConfigReadCopyPath) +
                    ";controlPathspec=" + File.Exists(controlPathspecReadCopyPath) +
                    ";medium=" + File.Exists(mediumReadCopyPath) +
                    ";mediumReadOnly=" + File.Exists(mediumReadOnlyReadCopyPath) +
                    ";mediumPayload=" + File.Exists(mediumWritePayloadPath);
                var failedInitialCwdPath = Path.Combine(root, "lpac-start-cwd.txt");
                var failedFinalCwdPath = Path.Combine(root, "lpac-final-cwd.txt");
                var failedInitialCwd = File.Exists(failedInitialCwdPath) ? File.ReadAllText(failedInitialCwdPath).Trim() : "missing";
                var failedFinalCwd = File.Exists(failedFinalCwdPath) ? File.ReadAllText(failedFinalCwdPath).Trim() : "missing";
                var rootWriteObserved = File.Exists(Path.Combine(root, "lpac-root-write.txt"));
                throw new InvalidDataException("LpacGitWorkspaceChildCommandFailed:" +
                    exitCode.ToString(System.Globalization.CultureInfo.InvariantCulture) +
                    ";ReadCopies=" + copyDiagnostics + ";RootWriteObserved=" + rootWriteObserved +
                    ";InitialCwd=" + failedInitialCwd + ";FinalCwd=" + failedFinalCwd);
            }
            var expectedCwd = Path.TrimEndingDirectorySeparator(Path.GetFullPath(root));
            var initialCwd = File.ReadAllText(initialCwdPath).Trim();
            var finalCwd = File.ReadAllText(finalCwdPath).Trim();
            if (!string.Equals(Path.TrimEndingDirectorySeparator(Path.GetFullPath(initialCwd)), expectedCwd, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("LpacGitWorkspaceInitialCurrentDirectoryMismatch");
            if (!string.Equals(Path.TrimEndingDirectorySeparator(Path.GetFullPath(finalCwd)), expectedCwd, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("LpacGitWorkspaceChildCurrentDirectoryMismatch");
            var readMismatches = new List<string>();
            CheckReadCopy("project", projectSourcePath, projectReadCopyPath, readMismatches);
            CheckReadCopy("control-config", controlConfigPath, controlConfigReadCopyPath, readMismatches);
            CheckReadCopy("control-pathspec", controlPathspecPath, controlPathspecReadCopyPath, readMismatches);
            CheckReadCopy("medium-readonly", mediumReadOnlyFilePath, mediumReadOnlyReadCopyPath, readMismatches);
            if (readMismatches.Count != 0)
                throw new InvalidDataException("LpacGitWorkspaceReadCopyContentMismatch:" + string.Join(";", readMismatches));
            if (!File.ReadAllBytes(mediumFilePath).SequenceEqual(Encoding.ASCII.GetBytes("medium-tamper")) ||
                File.ReadAllText(mediumReadCopyPath) != "medium-original" ||
                File.ReadAllText(mediumReadOnlyFilePath) != "medium-readonly-original")
                throw new InvalidDataException("LpacGitWorkspaceLowBoxMediumAccessResultMismatch");
            File.Delete(mediumWritePayloadPath);
            File.Delete(projectReadCopyPath);
            File.Delete(controlConfigReadCopyPath);
            File.Delete(controlPathspecReadCopyPath);
            File.Delete(mediumReadCopyPath);
            File.Delete(mediumReadOnlyReadCopyPath);
            File.Delete(initialCwdPath);
            File.Delete(finalCwdPath);
        }
        finally
        {
            if (childCreated && !childCompleted)
            {
                if (process is not null && !process.IsClosed && !process.IsInvalid)
                {
                    _ = TerminateProcess(process, 0xC000013A);
                    _ = WaitForSingleObject(process, 5000);
                }
                _ = TerminateJobObject(job, 0xC000013A);
            }
            thread?.Dispose();
            process?.Dispose();
            if (initialized) DeleteProcThreadAttributeList(attributes);
            if (environment != IntPtr.Zero) Marshal.FreeHGlobal(environment);
            if (probeEnvironment != IntPtr.Zero) Marshal.FreeHGlobal(probeEnvironment);
            if (policy != IntPtr.Zero) Marshal.FreeHGlobal(policy);
            if (jobList != IntPtr.Zero) Marshal.FreeHGlobal(jobList);
            if (capabilities != IntPtr.Zero) Marshal.FreeHGlobal(capabilities);
            if (attributes != IntPtr.Zero) Marshal.FreeHGlobal(attributes);
            if (packagePointer != IntPtr.Zero) Marshal.FreeHGlobal(packagePointer);
            if (threadDescriptor != IntPtr.Zero) _ = LocalFree(threadDescriptor);
            if (processDescriptor != IntPtr.Zero) _ = LocalFree(processDescriptor);
        }
    }

    private static void CheckReadCopy(string label, string sourcePath, string copyPath, List<string> mismatches)
    {
        var source = File.ReadAllBytes(sourcePath);
        var copy = File.ReadAllBytes(copyPath);
        if (!source.AsSpan().SequenceEqual(copy))
            mismatches.Add(label + ":source=" + Convert.ToHexString(source) + ":copy=" + Convert.ToHexString(copy));
    }

    private static string ProbeOpenAsLpac(SafeAccessTokenHandle primaryToken, string path, bool directory, uint access)
    {
        if (!DuplicateTokenEx(primaryToken, 0x000c, IntPtr.Zero, 2, 2, out var impersonation))
        {
            var error = Marshal.GetLastWin32Error();
            return "DuplicateTokenEx=0x" + error.ToString("X8", System.Globalization.CultureInfo.InvariantCulture);
        }
        using (impersonation)
        {
            if (!ImpersonateLoggedOnUser(impersonation))
            {
                var error = Marshal.GetLastWin32Error();
                return "Impersonate=0x" + error.ToString("X8", System.Globalization.CultureInfo.InvariantCulture);
            }
            try
            {
                var flags = OpenReparsePoint | (directory ? BackupSemantics : 0u);
                using var handle = CreateFile(path, access, ShareAll, IntPtr.Zero, OpenExisting, flags, IntPtr.Zero);
                if (handle.IsInvalid)
                {
                    var error = Marshal.GetLastWin32Error();
                    return "Win32=0x" + error.ToString("X8", System.Globalization.CultureInfo.InvariantCulture);
                }
                return "PASS";
            }
            finally
            {
                if (!RevertToSelf()) throw Error("LpacGitWorkspaceRevertAfterPathProbe");
            }
        }
    }

    private static uint ProbeApplicationPackageAccess(SafeAccessTokenHandle token)
    {
        var descriptor = new RawSecurityDescriptor(
            "O:SYG:SYD:P(A;;0x3;;;WD)(A;;0x1;;;S-1-15-2-1)(A;;0x2;;;S-1-15-2-2)");
        var bytes = new byte[descriptor.BinaryLength];
        descriptor.GetBinaryForm(bytes, 0);
        if (!DuplicateTokenEx(token, 8, IntPtr.Zero, 1, 2, out var query))
            throw Error("LpacGitWorkspaceDuplicateQueryToken");
        using (query)
        {
            var mapping = new GenericMapping();
            var privileges = new byte[64];
            uint size = (uint)privileges.Length;
            if (!AccessCheck(bytes, query, 0x02000000, ref mapping, privileges, ref size, out var granted, out var allowed))
                throw Error("LpacGitWorkspaceAccessCheck");
            if (size > privileges.Length || !allowed || granted is < 1 or > 3)
                throw new InvalidDataException("LpacGitWorkspaceAccessCheckResultInvalid");
            return granted;
        }
    }

    private static int ReadTokenDword(SafeAccessTokenHandle token, int informationClass)
    {
        var buffer = ReadTokenBuffer(token, informationClass, out var size);
        try
        {
            if (size != sizeof(int)) throw new InvalidDataException("LpacGitWorkspaceTokenDwordSizeInvalid");
            return Marshal.ReadInt32(buffer);
        }
        finally { Marshal.FreeHGlobal(buffer); }
    }

    private static int ReadTokenCount(SafeAccessTokenHandle token, int informationClass)
    {
        var buffer = ReadTokenBuffer(token, informationClass, out var size);
        try
        {
            if (size < sizeof(int)) throw new InvalidDataException("LpacGitWorkspaceTokenCountSizeInvalid");
            var count = Marshal.ReadInt32(buffer);
            if (count < 0 || count > 4096 || (count != 0 && size < 8 + count * 16))
                throw new InvalidDataException("LpacGitWorkspaceTokenCountBounds");
            return count;
        }
        finally { Marshal.FreeHGlobal(buffer); }
    }

    private static string ReadTokenSid(SafeAccessTokenHandle token, int informationClass)
    {
        var buffer = ReadTokenBuffer(token, informationClass, out var size);
        try
        {
            var sid = Marshal.ReadIntPtr(buffer);
            if (sid == IntPtr.Zero) throw new InvalidDataException("LpacGitWorkspaceTokenSidMissing");
            var offset = sid.ToInt64() - buffer.ToInt64();
            if (offset < 0 || offset > (long)size - 8)
                throw new InvalidDataException("LpacGitWorkspaceTokenSidBounds");
            var revision = Marshal.ReadByte(sid);
            var subAuthorities = Marshal.ReadByte(sid, 1);
            if (revision != 1 || subAuthorities > 15 || offset + 8 + subAuthorities * 4 > size)
                throw new InvalidDataException("LpacGitWorkspaceTokenSidBounds");
            return new SecurityIdentifier(sid).Value;
        }
        finally { Marshal.FreeHGlobal(buffer); }
    }

    private static IntPtr ReadTokenBuffer(SafeAccessTokenHandle token, int informationClass, out uint size)
    {
        if (GetTokenInformation(token, informationClass, IntPtr.Zero, 0, out size) ||
            Marshal.GetLastWin32Error() != 122 || size is < 4 or > 65536)
            throw new InvalidDataException("LpacGitWorkspaceTokenBufferBounds");
        var buffer = Marshal.AllocHGlobal(checked((int)size));
        if (!GetTokenInformation(token, informationClass, buffer, size, out var returned) || returned != size)
        {
            Marshal.FreeHGlobal(buffer);
            throw Error("LpacGitWorkspaceReadTokenInformation");
        }
        return buffer;
    }

    private static void CreateProtectedDirectory(string path, string packageSid, int packageMask, string integritySid, string humanSid)
    {
        var daclText = "O:BAG:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x" +
            packageMask.ToString("X8", System.Globalization.CultureInfo.InvariantCulture) +
            ";;;" + packageSid + ")(A;OICI;RC;;;S-1-3-4)";
        if (!ConvertStringSecurityDescriptorToSecurityDescriptor(daclText, 1, out var daclDescriptor, out _))
            throw Error("LpacGitWorkspaceBuildDacl");
        try
        {
            var attributes = new SecurityAttributes
            {
                Length = Marshal.SizeOf<SecurityAttributes>(),
                Descriptor = daclDescriptor,
                InheritHandle = 0
            };
            if (!CreateDirectoryNative(path, ref attributes)) throw Error("LpacGitWorkspaceCreateDirectory");
            using var handle = OpenDirectoryForSecurity(path);
            WindowsPathSeal.VerifyObject(handle, path, true);
            if (!GetSecurityDescriptorDacl(daclDescriptor, out var present, out var dacl, out _) ||
                !present || dacl == IntPtr.Zero)
                throw new InvalidDataException("LpacGitWorkspaceDaclMissing");
            var daclStatus = SetSecurityInfo(handle, FileObject, 0x80000004u, IntPtr.Zero, IntPtr.Zero, dacl, IntPtr.Zero);
            if (daclStatus != 0) throw new Win32Exception(unchecked((int)daclStatus), "LpacGitWorkspaceApplyDacl");

            var labelText = "S:(ML;OICI;NW;;;" + integritySid + ")";
            if (!ConvertStringSecurityDescriptorToSecurityDescriptor(labelText, 1, out var labelDescriptor, out _))
                throw Error("LpacGitWorkspaceBuildLabel");
            try
            {
                if (!GetSecurityDescriptorSacl(labelDescriptor, out var labelPresent, out var sacl, out _) ||
                    !labelPresent || sacl == IntPtr.Zero)
                    throw new InvalidDataException("LpacGitWorkspaceLabelMissing");
                var labelStatus = SetSecurityInfo(handle, FileObject, 16, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, sacl);
                if (labelStatus != 0) throw new Win32Exception(unchecked((int)labelStatus), "LpacGitWorkspaceApplyLabel");
            }
            finally { _ = LocalFree(labelDescriptor); }
        }
        finally { _ = LocalFree(daclDescriptor); }

        AssertDirectoryDescriptor(path, packageSid, packageMask, integritySid, humanSid);
    }

    private static SafeFileHandle OpenDirectoryForSecurity(string path)
    {
        var handle = CreateFile(path, 0x000e0080, ShareAll, IntPtr.Zero, OpenExisting,
            OpenReparsePoint | BackupSemantics, IntPtr.Zero);
        if (handle.IsInvalid) throw Error("LpacGitWorkspaceOpenDirectorySecurity");
        return handle;
    }

    private static void AssertDirectoryDescriptor(string path, string packageSid, int packageMask, string integritySid, string humanSid)
    {
        var descriptor = ReadDescriptor(path, true);
        if (descriptor.Owner?.Value != AdministratorsSid || descriptor.Group?.Value != SystemSid ||
            !descriptor.ControlFlags.HasFlag(ControlFlags.DiscretionaryAclPresent) ||
            !descriptor.ControlFlags.HasFlag(ControlFlags.DiscretionaryAclProtected) ||
            !descriptor.ControlFlags.HasFlag(ControlFlags.DiscretionaryAclAutoInherited))
            throw new InvalidDataException("LpacGitWorkspaceDirectoryDescriptorFlagsMismatch");
        var dacl = descriptor.DiscretionaryAcl ?? throw new InvalidDataException("LpacGitWorkspaceDirectoryDaclMissing");
        var packageAce = FindSingleAllowedAce(dacl, packageSid);
        if (packageAce.AccessMask != packageMask || (packageAce.AccessMask & 0x000c0000) != 0)
            throw new InvalidDataException("LpacGitWorkspaceDirectoryPackageMaskMismatch");
        var ownerRights = FindSingleAllowedAce(dacl, OwnerRightsSid);
        if (ownerRights.AccessMask != 0x00020000 ||
            !ownerRights.AceFlags.HasFlag(AceFlags.ObjectInherit) ||
            !ownerRights.AceFlags.HasFlag(AceFlags.ContainerInherit))
            throw new InvalidDataException("LpacGitWorkspaceDirectoryOwnerRightsMismatch");
        if (ContainsSid(dacl, humanSid) || ContainsSid(dacl, UsersSid))
            throw new InvalidDataException("LpacGitWorkspaceDirectoryHumanAcePresent");
        AssertLabel(descriptor, integritySid, false);
    }

    private static void AssertInheritedFile(string path, string packageSid, string humanSid, int packageMask, string integritySid)
    {
        var descriptor = ReadDescriptor(path, false);
        if (!descriptor.ControlFlags.HasFlag(ControlFlags.DiscretionaryAclPresent) ||
            descriptor.ControlFlags.HasFlag(ControlFlags.DiscretionaryAclProtected) ||
            !descriptor.ControlFlags.HasFlag(ControlFlags.DiscretionaryAclAutoInherited))
            throw new InvalidDataException("LpacGitWorkspaceFileInheritanceFlagsMismatch");
        var dacl = descriptor.DiscretionaryAcl ?? throw new InvalidDataException("LpacGitWorkspaceFileDaclMissing");
        var packageAce = FindSingleAllowedAce(dacl, packageSid);
        if (packageAce.AccessMask != packageMask || !packageAce.AceFlags.HasFlag(AceFlags.Inherited) ||
            packageAce.AceFlags.HasFlag(AceFlags.InheritOnly) || (packageAce.AccessMask & 0x000c0000) != 0)
            throw new InvalidDataException("LpacGitWorkspaceFilePackageInheritanceMismatch");
        var ownerRights = FindSingleAllowedAce(dacl, OwnerRightsSid);
        if (ownerRights.AccessMask != 0x00020000 || !ownerRights.AceFlags.HasFlag(AceFlags.Inherited))
            throw new InvalidDataException("LpacGitWorkspaceFileOwnerRightsInheritanceMismatch");
        if (ContainsSid(dacl, humanSid) || ContainsSid(dacl, UsersSid))
            throw new InvalidDataException("LpacGitWorkspaceFileHumanAcePresent");
        AssertLabel(descriptor, integritySid, true);
    }

    private static void AssertLabel(RawSecurityDescriptor descriptor, string integritySid, bool inherited)
    {
        var sacl = descriptor.SystemAcl ?? throw new InvalidDataException("LpacGitWorkspaceSaclMissing");
        if (!descriptor.ControlFlags.HasFlag(ControlFlags.SystemAclPresent))
            throw new InvalidDataException("LpacGitWorkspaceSaclPresentFlagMissing");
        var labels = new List<(string Sid, int Mask, AceFlags Flags)>();
        for (var i = 0; i < sacl.Count; i++)
        {
            var ace = sacl[i];
            var bytes = new byte[ace.BinaryLength];
            ace.GetBinaryForm(bytes, 0);
            if (bytes.Length >= 16 && bytes[0] == 0x11)
                labels.Add((new SecurityIdentifier(bytes, 8).Value, BitConverter.ToInt32(bytes, 4), (AceFlags)bytes[1]));
        }
        if (labels.Count != 1 || labels[0].Sid != integritySid || labels[0].Mask != 1 ||
            labels[0].Flags.HasFlag(AceFlags.Inherited) != inherited)
            throw new InvalidDataException("LpacGitWorkspaceMandatoryLabelMismatch");
    }

    private static CommonAce FindSingleAllowedAce(RawAcl dacl, string sid)
    {
        var matches = new List<CommonAce>();
        for (var i = 0; i < dacl.Count; i++)
            if (dacl[i] is CommonAce ace && ace.AceQualifier == AceQualifier.AccessAllowed &&
                ace.SecurityIdentifier.Value == sid)
                matches.Add(ace);
        if (matches.Count != 1) throw new InvalidDataException("LpacGitWorkspaceExpectedSingleAceMissing");
        return matches[0];
    }

    private static bool ContainsSid(RawAcl dacl, string sid)
    {
        for (var i = 0; i < dacl.Count; i++)
            if (dacl[i] is CommonAce ace && ace.SecurityIdentifier.Value == sid) return true;
        return false;
    }

    private static RawSecurityDescriptor ReadDescriptor(string path, bool directory)
    {
        var flags = OpenReparsePoint | (directory ? BackupSemantics : 0u);
        using var handle = CreateFile(path, ReadControlAndAttributes, ShareAll, IntPtr.Zero, OpenExisting, flags, IntPtr.Zero);
        if (handle.IsInvalid) throw Error("LpacGitWorkspaceReadDescriptor");
        WindowsPathSeal.VerifyObject(handle, path, directory);
        var status = GetSecurityInfo(handle, FileObject, 1u | 2u | 4u | 16u, out _, out _, out _, out _, out var value);
        if (status != 0) throw new Win32Exception(unchecked((int)status), "LpacGitWorkspaceGetSecurityInfo");
        try
        {
            if (value == IntPtr.Zero) throw new InvalidDataException("LpacGitWorkspaceDescriptorMissing");
            var size = GetSecurityDescriptorLength(value);
            if (size is < 20 or > 65536) throw new InvalidDataException("LpacGitWorkspaceDescriptorBounds");
            var bytes = new byte[checked((int)size)];
            Marshal.Copy(value, bytes, 0, bytes.Length);
            return new RawSecurityDescriptor(bytes, 0);
        }
        finally { if (value != IntPtr.Zero) _ = LocalFree(value); }
    }

    private static InvalidOperationException Error(string operation)
    {
        var code = Marshal.GetLastWin32Error();
        return new InvalidOperationException(operation + ":Win32=0x" +
            code.ToString("X8", System.Globalization.CultureInfo.InvariantCulture), new Win32Exception(code));
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SecurityAttributes
    {
        internal int Length;
        internal IntPtr Descriptor;
        internal int InheritHandle;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct SecurityCapabilities
    {
        internal IntPtr AppContainerSid;
        internal IntPtr Capabilities;
        internal uint CapabilityCount;
        internal uint Reserved;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct StartupInfo
    {
        internal uint Size;
        internal IntPtr Reserved, Desktop, Title;
        internal uint X, Y, XSize, YSize, XCountChars, YCountChars, FillAttribute, Flags;
        internal ushort ShowWindow, Reserved2;
        internal IntPtr Reserved2Pointer, StandardInput, StandardOutput, StandardError;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct StartupInfoEx
    {
        internal StartupInfo Basic;
        internal IntPtr Attributes;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct ProcessInformation
    {
        internal IntPtr Process, Thread;
        internal uint ProcessId, ThreadId;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct GenericMapping
    {
        internal uint GenericRead, GenericWrite, GenericExecute, GenericAll;
    }

    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("userenv.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern int CreateAppContainerProfile(string name, string display, string description,
        IntPtr capabilities, uint capabilityCount, out IntPtr appContainerSid);
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("userenv.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern int DeleteAppContainerProfile(string name);
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern IntPtr FreeSid(IntPtr sid);
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(string text, uint revision,
        out IntPtr descriptor, out uint length);
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetSecurityDescriptorDacl(IntPtr descriptor, [MarshalAs(UnmanagedType.Bool)] out bool present,
        out IntPtr dacl, [MarshalAs(UnmanagedType.Bool)] out bool defaulted);
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetSecurityDescriptorSacl(IntPtr descriptor, [MarshalAs(UnmanagedType.Bool)] out bool present,
        out IntPtr sacl, [MarshalAs(UnmanagedType.Bool)] out bool defaulted);
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern uint GetSecurityInfo(SafeFileHandle handle, int objectType, uint securityInfo,
        out IntPtr owner, out IntPtr group, out IntPtr dacl, out IntPtr sacl, out IntPtr descriptor);
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern uint SetSecurityInfo(SafeFileHandle handle, int objectType, uint securityInfo,
        IntPtr owner, IntPtr group, IntPtr dacl, IntPtr sacl);
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("advapi32.dll")]
    private static extern uint GetSecurityDescriptorLength(IntPtr descriptor);
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(IntPtr memory);
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("kernel32.dll", EntryPoint = "CreateDirectoryW", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateDirectoryNative(string path, ref SecurityAttributes attributes);
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("kernel32.dll", EntryPoint = "CreateFileW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFile(string path, uint access, uint share, IntPtr security,
        uint disposition, uint flags, IntPtr template);
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("kernel32.dll", EntryPoint = "CreateProcessW", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateProcess(string image, StringBuilder command, ref SecurityAttributes processSecurity,
        ref SecurityAttributes threadSecurity, [MarshalAs(UnmanagedType.Bool)] bool inheritHandles, uint flags, IntPtr environment,
        string currentDirectory, ref StartupInfoEx startup, out ProcessInformation processInformation);
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool InitializeProcThreadAttributeList(IntPtr list, int count, uint flags, ref nuint size);
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool UpdateProcThreadAttribute(IntPtr list, uint flags, IntPtr attribute, IntPtr value,
        nuint size, IntPtr previousValue, IntPtr returnSize);
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("kernel32.dll")]
    private static extern void DeleteProcThreadAttributeList(IntPtr list);
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern SafeFileHandle CreateJobObject(IntPtr security, string? name);
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool IsProcessInJob(SafeProcessHandle process, SafeFileHandle job,
        [MarshalAs(UnmanagedType.Bool)] out bool result);
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool IsProcessInJob(IntPtr process, IntPtr job,
        [MarshalAs(UnmanagedType.Bool)] out bool result);
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool TerminateJobObject(SafeFileHandle job, uint exitCode);
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool TerminateProcess(SafeProcessHandle process, uint exitCode);
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint ResumeThread(SafeWaitHandle thread);
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint WaitForSingleObject(SafeProcessHandle handle, uint milliseconds);
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetExitCodeProcess(SafeProcessHandle process, out uint exitCode);
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool OpenProcessToken(SafeProcessHandle process, uint access, out SafeAccessTokenHandle token);
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetTokenInformation(SafeAccessTokenHandle token, int informationClass,
        IntPtr information, uint informationLength, out uint returnLength);
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DuplicateTokenEx(SafeAccessTokenHandle existingToken, uint desiredAccess,
        IntPtr tokenAttributes, int impersonationLevel, int tokenType, out SafeAccessTokenHandle newToken);
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ImpersonateLoggedOnUser(SafeAccessTokenHandle token);
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool RevertToSelf();
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool AccessCheck(byte[] securityDescriptor, SafeAccessTokenHandle clientToken,
        uint desiredAccess, ref GenericMapping genericMapping, [Out] byte[] privilegeSet,
        ref uint privilegeSetLength, out uint grantedAccess, [MarshalAs(UnmanagedType.Bool)] out bool accessStatus);
}
