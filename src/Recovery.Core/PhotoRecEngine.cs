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
    private static readonly HashSet<string> AllowedFamilies = new(StringComparer.OrdinalIgnoreCase)
    {
        "jpg", "png", "bmp", "pdf", "zip", "doc", "xls", "ppt", "mov", "mp4", "riff", "tif", "gif"
    };

    public static bool IsAvailable(string executablePath) =>
        File.Exists(executablePath) && string.Equals(Path.GetFileName(executablePath), "photorec_win.exe", StringComparison.OrdinalIgnoreCase);

    public static IReadOnlyList<string> BuildArguments(PhotoRecRunOptions options)
    {
        if (string.IsNullOrWhiteSpace(options.SourcePath)) throw new ArgumentException("PhotoRec source path is required.", nameof(options));
        if (string.IsNullOrWhiteSpace(options.DestinationBase)) throw new ArgumentException("PhotoRec destination is required.", nameof(options));
        if (options.FileFamilies.Count == 0) throw new ArgumentException("At least one PhotoRec file family is required.", nameof(options));

        var families = options.FileFamilies
            .Select(value => value.Trim().TrimStart('.').ToLowerInvariant())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        var unsupported = families.Where(value => !AllowedFamilies.Contains(value)).ToArray();
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
    {
        if (!IsAvailable(executablePath)) throw new FileNotFoundException("photorec_win.exe was not found.", executablePath);
        var workingDirectory = Path.GetFullPath(options.WorkingDirectory);
        var destinationBase = Path.GetFullPath(options.DestinationBase);
        Directory.CreateDirectory(workingDirectory);
        Directory.CreateDirectory(Path.GetDirectoryName(destinationBase) ?? destinationBase);
        var startedUtc = DateTime.UtcNow;

        var startInfo = new ProcessStartInfo
        {
            FileName = Path.GetFullPath(executablePath),
            WorkingDirectory = workingDirectory,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };
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
                var stagedCount = CountOutputs(destinationBase, startedUtc);
                progress?.Report(new("PhotoRec", 0, 0, stagedCount,
                    $"PhotoRec 正在扫描未分配空间，已运行 {stopwatch.Elapsed:mm\\:ss}，暂存 {stagedCount:N0} 个文件；可随时取消。"));
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
        var logPath = Path.Combine(workingDirectory, "photorec.log");
        var log = File.Exists(logPath) ? await File.ReadAllTextAsync(logPath, cancellationToken) : string.Empty;
        var files = EnumerateOutputs(destinationBase, startedUtc);
        var directories = files.Select(file => Path.GetDirectoryName(file.Path)!).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        var rejectedMatch = RejectedFilesRegex().Match(log);
        var rejected = rejectedMatch.Success ? int.Parse(rejectedMatch.Groups[1].Value, System.Globalization.CultureInfo.InvariantCulture) : 0;
        var summary = process.ExitCode == 0
            ? $"PhotoRec 正常完成：恢复 {files.Count:N0} 个文件，拒绝 {rejected:N0} 个无效候选。"
            : $"PhotoRec 退出代码 {process.ExitCode}：已保留 {files.Count:N0} 个阶段性结果。";
        return new(process.ExitCode, logPath, directories, files, rejected, summary);
    }

    private static IReadOnlyList<PhotoRecRecoveredFile> EnumerateOutputs(string destinationBase, DateTime startedUtc)
    {
        var parent = Path.GetDirectoryName(destinationBase);
        if (string.IsNullOrEmpty(parent) || !Directory.Exists(parent)) return [];
        var prefix = Path.GetFileName(destinationBase) + ".";
        return Directory.EnumerateDirectories(parent, prefix + "*", SearchOption.TopDirectoryOnly)
            .Where(directory => Directory.GetCreationTimeUtc(directory) >= startedUtc.AddSeconds(-2))
            .SelectMany(directory => Directory.EnumerateFiles(directory, "*", SearchOption.AllDirectories))
            .Select(path => new FileInfo(path))
            .Where(file => file.Exists && !string.Equals(file.Name, "report.xml", StringComparison.OrdinalIgnoreCase))
            .Select(file => new PhotoRecRecoveredFile(file.FullName, file.Extension.TrimStart('.').ToLowerInvariant(), checked((ulong)file.Length)))
            .OrderBy(file => file.Path, StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    private static int CountOutputs(string destinationBase, DateTime startedUtc)
    {
        try
        {
            var parent = Path.GetDirectoryName(destinationBase);
            if (string.IsNullOrEmpty(parent) || !Directory.Exists(parent)) return 0;
            var prefix = Path.GetFileName(destinationBase) + ".";
            return Directory.EnumerateDirectories(parent, prefix + "*", SearchOption.TopDirectoryOnly)
                .Where(directory => Directory.GetCreationTimeUtc(directory) >= startedUtc.AddSeconds(-2))
                .Sum(directory => Directory.EnumerateFiles(directory, "*", SearchOption.AllDirectories)
                    .Count(path => !string.Equals(Path.GetFileName(path), "report.xml", StringComparison.OrdinalIgnoreCase)));
        }
        catch (IOException) { return 0; }
        catch (UnauthorizedAccessException) { return 0; }
    }

    private static async Task DrainAsync(StreamReader reader)
    {
        var buffer = new char[8192];
        while (await reader.ReadAsync(buffer) > 0) { }
    }

    [GeneratedRegex(@"([0-9]+) invalid files? found and rejected", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex RejectedFilesRegex();
}
