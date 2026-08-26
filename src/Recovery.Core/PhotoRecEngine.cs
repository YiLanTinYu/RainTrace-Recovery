using System.Diagnostics;
using System.Text.RegularExpressions;

namespace Recovery.Core;

public sealed record PhotoRecRunOptions(
    string SourcePath,
    string DestinationBase,
    string WorkingDirectory,
    IReadOnlyList<string> FileFamilies,
    bool FreeSpaceOnly = true,
    bool TreatSourceAsWholeDevice = false,
    int? PartitionNumber = null);

public sealed record PhotoRecRecoveredFile(string Path, string Extension, ulong Size);

public sealed record PhotoRecRunResult(
    int ExitCode,
    string LogPath,
    IReadOnlyList<string> OutputDirectories,
    IReadOnlyList<PhotoRecRecoveredFile> Files,
    int RejectedFiles,
    string Summary)
{
    public bool CompletedNormally => ExitCode == 0;
}

/// <summary>
/// Process boundary for the GPL PhotoRec engine. Source media is supplied only as an input argument;
/// all writes are confined to the selected destination and working directories.
/// </summary>
public static partial class PhotoRecEngine
{
    public static bool IsAvailable(string executablePath) =>
        File.Exists(executablePath) && string.Equals(Path.GetFileName(executablePath), "photorec_win.exe", StringComparison.OrdinalIgnoreCase);

    public static IReadOnlyList<string> BuildArguments(PhotoRecRunOptions options)
    {
        if (string.IsNullOrWhiteSpace(options.SourcePath)) throw new ArgumentException("PhotoRec source path is required.", nameof(options));
        if (string.IsNullOrWhiteSpace(options.DestinationBase)) throw new ArgumentException("PhotoRec destination is required.", nameof(options));
        if (options.FileFamilies.Count == 0) throw new ArgumentException("At least one PhotoRec file family is required.", nameof(options));

        var families = options.FileFamilies
            .Select(RecoveryCapabilityRegistry.NormalizePhotoRecFamily)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        var unsupported = families.Where(value => !RecoveryCapabilityRegistry.IsPhotoRecFamilyAllowed(value)).ToArray();
        if (unsupported.Length > 0) throw new ArgumentException($"Unsupported PhotoRec file families: {string.Join(", ", unsupported)}", nameof(options));

        var commands = new List<string>();
        if (options.TreatSourceAsWholeDevice) commands.Add("partition_none");
        commands.AddRange(["options", "paranoid", "keep_corrupted_file_no", "fileopt", "everything", "disable"]);
        foreach (var family in families) { commands.Add(family); commands.Add("enable"); }
        commands.Add(options.FreeSpaceOnly ? "freespace" : "wholespace");
        if (options.PartitionNumber is > 0) commands.Add(options.PartitionNumber.Value.ToString(System.Globalization.CultureInfo.InvariantCulture));
        commands.Add("search");

        var logPath = Path.Combine(Path.GetFullPath(options.WorkingDirectory), "photorec.log");
        return ["/log", "/logname", logPath, "/d", Path.GetFullPath(options.DestinationBase), "/cmd", options.SourcePath, string.Join(',', commands)];
    }

    public static async Task<PhotoRecRunResult> RunAsync(
        string executablePath,
        PhotoRecRunOptions options,
        IProgress<ScanProgress>? progress = null,
        CancellationToken cancellationToken = default)
        => await RunAsync(executablePath, options, progress, stableFileProgress: null, cancellationToken);

    /// <summary>
    /// Runs PhotoRec and reports files that are safe to import while the process is still running.
    /// A file is reported once, after two consecutive unchanged-size probes both obtained an
    /// exclusive read handle. The final result still contains every output left by this run.
    /// </summary>
    public static async Task<PhotoRecRunResult> RunAsync(
        string executablePath,
        PhotoRecRunOptions options,
        IProgress<ScanProgress>? progress,
        IProgress<PhotoRecRecoveredFile>? stableFileProgress,
        CancellationToken cancellationToken = default)
    {
        if (!IsAvailable(executablePath)) throw new FileNotFoundException("photorec_win.exe was not found.", executablePath);
        var workingDirectory = Path.GetFullPath(options.WorkingDirectory);
        var destinationBase = Path.GetFullPath(options.DestinationBase);
        Directory.CreateDirectory(workingDirectory);
        Directory.CreateDirectory(Path.GetDirectoryName(destinationBase) ?? destinationBase);
        var preExistingOutputDirectories = SnapshotOutputDirectories(destinationBase);
        var probeStates = new Dictionary<string, OutputProbeState>(StringComparer.OrdinalIgnoreCase);
        var reportedPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        var startInfo = new ProcessStartInfo
        {
            FileName = Path.GetFullPath(executablePath),
            WorkingDirectory = workingDirectory,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };
        var executableDirectory = Path.GetDirectoryName(startInfo.FileName)!;
        if (File.Exists(Path.Combine(executableDirectory, "63", "cygwin")))
            startInfo.Environment["TERMINFO"] = executableDirectory;
        foreach (var argument in BuildArguments(options)) startInfo.ArgumentList.Add(argument);

        using var process = new Process { StartInfo = startInfo };
        if (!process.Start()) throw new InvalidOperationException("PhotoRec process could not be started.");
        var standardOutput = DrainAsync(process.StandardOutput);
        var standardError = DrainAsync(process.StandardError);
        var stopwatch = Stopwatch.StartNew();
        try
        {
            while (!process.HasExited)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var runOutputDirectories = FindRunOutputDirectories(destinationBase, preExistingOutputDirectories);
                var stagedCount = ProbeStableOutputs(runOutputDirectories, probeStates, reportedPaths, stableFileProgress);
                progress?.Report(new("PhotoRec", 0, 0, stagedCount,
                    $"PhotoRec 正在扫描未分配空间，已运行 {stopwatch.Elapsed:mm\\:ss}，稳定候选 {stagedCount:N0} 个；可随时取消。"));
                await Task.Delay(1000, cancellationToken);
            }
            await process.WaitForExitAsync(cancellationToken);
        }
        catch
        {
            if (!process.HasExited) process.Kill(entireProcessTree: true);
            try { await process.WaitForExitAsync(CancellationToken.None); } catch { }
            throw;
        }

        await Task.WhenAll(standardOutput, standardError);
        var outputDirectories = FindRunOutputDirectories(destinationBase, preExistingOutputDirectories);
        // PhotoRec has closed its output handles. Two final consecutive probes let files written
        // immediately before process exit satisfy the same stability rule as in-progress files.
        ProbeStableOutputs(outputDirectories, probeStates, reportedPaths, stableFileProgress);
        ProbeStableOutputs(outputDirectories, probeStates, reportedPaths, stableFileProgress);
        var logPath = Path.Combine(workingDirectory, "photorec.log");
        var log = File.Exists(logPath) ? await File.ReadAllTextAsync(logPath, cancellationToken) : string.Empty;
        var files = EnumerateOutputs(outputDirectories);
        var rejectedMatch = RejectedFilesRegex().Match(log);
        var rejected = rejectedMatch.Success ? int.Parse(rejectedMatch.Groups[1].Value, System.Globalization.CultureInfo.InvariantCulture) : 0;
        var summary = process.ExitCode == 0
            ? $"PhotoRec 正常完成：恢复 {files.Count:N0} 个文件，拒绝 {rejected:N0} 个无效候选。"
            : $"PhotoRec 退出代码 {process.ExitCode}：已保留 {files.Count:N0} 个阶段性结果。";
        return new(process.ExitCode, logPath, outputDirectories, files, rejected, summary);
    }

    /// <summary>
    /// Re-discovers outputs left by an interrupted earlier run. The caller can import these before
    /// starting a replacement PhotoRec stage, preventing the new-run baseline from hiding files
    /// that became stable immediately before cancellation.
    /// </summary>
    public static async Task<IReadOnlyList<PhotoRecRecoveredFile>> FindStableExistingOutputsAsync(
        string destinationBase,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(destinationBase);
        var directories = SnapshotOutputDirectories(Path.GetFullPath(destinationBase));
        if (directories.Count == 0) return [];
        var states = new Dictionary<string, OutputProbeState>(StringComparer.OrdinalIgnoreCase);
        var reported = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        ProbeStableOutputs(directories, states, reported, stableFileProgress: null);
        await Task.Delay(250, cancellationToken);
        ProbeStableOutputs(directories, states, reported, stableFileProgress: null);
        return EnumerateOutputs(directories)
            .Where(file => reported.Contains(file.Path))
            .ToArray();
    }

    private static IReadOnlyList<string> SnapshotOutputDirectories(string destinationBase)
    {
        var parent = Path.GetDirectoryName(destinationBase);
        if (string.IsNullOrEmpty(parent) || !Directory.Exists(parent)) return [];
        var prefix = Path.GetFileName(destinationBase) + ".";
        // Fail before starting PhotoRec if the baseline cannot be enumerated. Treating a failed
        // baseline as empty could make an old recup directory look like output from this run.
        return Directory.EnumerateDirectories(parent, prefix + "*", SearchOption.TopDirectoryOnly)
            .Where(directory => IsPhotoRecOutputDirectory(directory, prefix))
            .Select(Path.GetFullPath)
            .ToArray();
    }

    private static IReadOnlyList<string> FindRunOutputDirectories(
        string destinationBase,
        IReadOnlyList<string> preExistingOutputDirectories)
    {
        var parent = Path.GetDirectoryName(destinationBase);
        if (string.IsNullOrEmpty(parent) || !Directory.Exists(parent)) return [];
        var prefix = Path.GetFileName(destinationBase) + ".";
        var preExisting = preExistingOutputDirectories.ToHashSet(StringComparer.OrdinalIgnoreCase);
        try
        {
            return Directory.EnumerateDirectories(parent, prefix + "*", SearchOption.TopDirectoryOnly)
                .Where(directory => IsPhotoRecOutputDirectory(directory, prefix))
                .Select(Path.GetFullPath)
                .Where(directory => !preExisting.Contains(directory))
                .OrderBy(directory => directory, StringComparer.OrdinalIgnoreCase)
                .ToArray();
        }
        catch (IOException) { return []; }
        catch (UnauthorizedAccessException) { return []; }
    }

    private static bool IsPhotoRecOutputDirectory(string directory, string prefix)
    {
        var name = Path.GetFileName(directory);
        if (!name.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)) return false;
        var suffix = name.AsSpan(prefix.Length);
        return suffix.Length > 0 && suffix.IndexOfAnyExceptInRange('0', '9') < 0;
    }

    private static int ProbeStableOutputs(
        IReadOnlyList<string> outputDirectories,
        IDictionary<string, OutputProbeState> probeStates,
        ISet<string> reportedPaths,
        IProgress<PhotoRecRecoveredFile>? stableFileProgress)
    {
        foreach (var path in EnumerateOutputPaths(outputDirectories))
        {
            if (reportedPaths.Contains(path)) continue;

            try
            {
                var file = new FileInfo(path);
                if (!file.Exists) continue;
                var size = file.Length;
                using (new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.None, bufferSize: 1, FileOptions.SequentialScan)) { }

                var consecutiveStableProbes = 1;
                if (probeStates.TryGetValue(path, out var previous) && previous.Size == size && previous.WasExclusive)
                {
                    consecutiveStableProbes = previous.ConsecutiveStableProbes + 1;
                }

                probeStates[path] = new(size, WasExclusive: true, consecutiveStableProbes);
                if (consecutiveStableProbes < 2 || !reportedPaths.Add(path)) continue;

                stableFileProgress?.Report(new(
                    file.FullName,
                    file.Extension.TrimStart('.').ToLowerInvariant(),
                    checked((ulong)size)));
            }
            catch (IOException)
            {
                ResetProbeState(path, probeStates);
            }
            catch (UnauthorizedAccessException)
            {
                ResetProbeState(path, probeStates);
            }
        }

        return reportedPaths.Count;
    }

    private static void ResetProbeState(string path, IDictionary<string, OutputProbeState> probeStates)
    {
        try
        {
            var file = new FileInfo(path);
            probeStates[path] = new(file.Exists ? file.Length : -1, WasExclusive: false, ConsecutiveStableProbes: 0);
        }
        catch (IOException)
        {
            probeStates.Remove(path);
        }
        catch (UnauthorizedAccessException)
        {
            probeStates.Remove(path);
        }
    }

    private static IReadOnlyList<PhotoRecRecoveredFile> EnumerateOutputs(IReadOnlyList<string> outputDirectories) =>
        EnumerateOutputPaths(outputDirectories)
            .Select(path => new FileInfo(path))
            .Where(file => file.Exists)
            .Select(file => new PhotoRecRecoveredFile(
                file.FullName,
                file.Extension.TrimStart('.').ToLowerInvariant(),
                checked((ulong)file.Length)))
            .OrderBy(file => file.Path, StringComparer.OrdinalIgnoreCase)
            .ToArray();

    private static IEnumerable<string> EnumerateOutputPaths(IReadOnlyList<string> outputDirectories)
    {
        foreach (var directory in outputDirectories)
        {
            IEnumerable<string> paths;
            try
            {
                paths = Directory.EnumerateFiles(directory, "*", SearchOption.AllDirectories).ToArray();
            }
            catch (IOException)
            {
                continue;
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            foreach (var path in paths)
            {
                if (!string.Equals(Path.GetFileName(path), "report.xml", StringComparison.OrdinalIgnoreCase)) yield return path;
            }
        }
    }

    private sealed record OutputProbeState(long Size, bool WasExclusive, int ConsecutiveStableProbes);

    private static async Task DrainAsync(StreamReader reader)
    {
        var buffer = new char[8192];
        while (await reader.ReadAsync(buffer) > 0) { }
    }

    [GeneratedRegex(@"([0-9]+) invalid files? found and rejected", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex RejectedFilesRegex();
}
