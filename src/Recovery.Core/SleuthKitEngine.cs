using System.Diagnostics;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace Recovery.Core;

public sealed record SleuthKitScanOptions(
    string SourcePath,
    ulong PartitionOffsetBytes = 0,
    uint SectorSize = 512,
    string? FileSystemType = null,
    bool IncludeDirectories = false,
    bool Recursive = true);

public sealed record SleuthKitCandidate(
    string MetadataAddress,
    string OriginalPath,
    ulong Size,
    bool IsDirectory,
    DateTime? ModifiedUtc)
{
    public IReadOnlyList<string> AlternateMetadataAddresses { get; init; } = [];
}

public sealed record SleuthKitScanResult(
    int ExitCode,
    IReadOnlyList<SleuthKitCandidate> Candidates,
    string StandardError,
    string DetectedEncoding)
{
    public bool CompletedNormally => ExitCode == 0;
}

public sealed record SleuthKitRecoveryResult(
    int ExitCode,
    string OutputPath,
    ulong BytesWritten,
    string StandardError)
{
    public bool CompletedNormally => ExitCode == 0;
}

public sealed record SleuthKitSamples(byte[] Head, byte[] Tail, ulong BytesRead, string Sha256);

/// <summary>
/// Safe process boundary for The Sleuth Kit. TSK owns file-system interpretation while
/// RainTrace owns source/destination policy, result merging and validation.
/// </summary>
public static class SleuthKitEngine
{
    private const string DeletedSuffix = " (deleted)";

    public static bool IsAvailable(string binDirectory) =>
        File.Exists(Path.Combine(Path.GetFullPath(binDirectory), "fls.exe")) &&
        File.Exists(Path.Combine(Path.GetFullPath(binDirectory), "icat.exe"));

    public static async Task<string> GetVersionAsync(
        string binDirectory,
        CancellationToken cancellationToken = default)
    {
        EnsureAvailable(binDirectory);
        var result = await RunCapturedAsync(
            Path.Combine(Path.GetFullPath(binDirectory), "fls.exe"),
            ["-V"], cancellationToken);
        if (result.ExitCode != 0)
            throw new InvalidOperationException($"TSK version check failed: {Decode(result.StandardError).Text.Trim()}");
        return Decode(result.StandardOutput).Text.Trim();
    }

    public static async Task<SleuthKitScanResult> ScanDeletedAsync(
        string binDirectory,
        SleuthKitScanOptions options,
        CancellationToken cancellationToken = default,
        IProgress<ScanProgress>? progress = null,
        TimeSpan? maximumRuntime = null)
    {
        EnsureAvailable(binDirectory);
        ValidateOptions(options);

        var arguments = new List<string>();
        if (options.Recursive) arguments.Add("-r");
        arguments.AddRange(["-d", "-p", "-m", "/"]);
        AppendFileSystemArguments(arguments, options);
        arguments.Add(Path.GetFullPath(options.SourcePath));
        var result = await RunMactimeScanAsync(
            Path.Combine(Path.GetFullPath(binDirectory), "fls.exe"), arguments,
            options.IncludeDirectories, cancellationToken, progress, maximumRuntime);
        return new(result.ExitCode, CollapseDuplicates(result.Candidates), result.StandardError, result.EncodingName);
    }

    public static async Task<SleuthKitRecoveryResult> RecoverAsync(
        string binDirectory,
        SleuthKitScanOptions options,
        SleuthKitCandidate candidate,
        string outputPath,
        CancellationToken cancellationToken = default)
    {
        EnsureAvailable(binDirectory);
        ValidateOptions(options);
        if (candidate.IsDirectory) throw new ArgumentException("TSK cannot recover a directory as a byte stream.", nameof(candidate));
        if (string.IsNullOrWhiteSpace(candidate.MetadataAddress)) throw new ArgumentException("Metadata address is required.", nameof(candidate));

        var fullOutputPath = Path.GetFullPath(outputPath);
        Directory.CreateDirectory(Path.GetDirectoryName(fullOutputPath) ?? throw new ArgumentException("Output path has no parent directory.", nameof(outputPath)));
        var arguments = BuildIcatArguments(options, candidate.MetadataAddress);

        var startInfo = CreateStartInfo(Path.Combine(Path.GetFullPath(binDirectory), "icat.exe"), arguments);
        using var process = new Process { StartInfo = startInfo };
        if (!process.Start()) throw new InvalidOperationException("TSK icat process could not be started.");
        var errorTask = ReadAllBytesAsync(process.StandardError.BaseStream, cancellationToken);
        try
        {
            await using (var destination = new FileStream(fullOutputPath, FileMode.CreateNew, FileAccess.Write, FileShare.None, 1024 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan))
                await process.StandardOutput.BaseStream.CopyToAsync(destination, 1024 * 1024, cancellationToken);
            await process.WaitForExitAsync(cancellationToken);
        }
        catch
        {
            if (!process.HasExited) process.Kill(entireProcessTree: true);
            try { await process.WaitForExitAsync(CancellationToken.None); } catch { }
            if (File.Exists(fullOutputPath)) File.Delete(fullOutputPath);
            throw;
        }

        var error = Decode(await errorTask).Text.Trim();
        var length = checked((ulong)new FileInfo(fullOutputPath).Length);
        if (process.ExitCode != 0)
        {
            File.Delete(fullOutputPath);
            throw new InvalidOperationException($"TSK icat recovery failed ({process.ExitCode}): {error}");
        }
        return new(process.ExitCode, fullOutputPath, length, error);
    }

    public static async Task<byte[]> ReadPrefixAsync(
        string binDirectory,
        SleuthKitScanOptions options,
        SleuthKitCandidate candidate,
        int maximumBytes = RecoveryPreview.DefaultMaximumBytes,
        CancellationToken cancellationToken = default)
    {
        EnsureAvailable(binDirectory);
        ValidateOptions(options);
        ValidateContentCandidate(candidate);
        if (maximumBytes <= 0) throw new ArgumentOutOfRangeException(nameof(maximumBytes));
        var requested = checked((int)Math.Min(candidate.Size, (ulong)maximumBytes));
        if (requested == 0) return [];

        var startInfo = CreateStartInfo(Path.Combine(Path.GetFullPath(binDirectory), "icat.exe"),
            BuildIcatArguments(options, candidate.MetadataAddress));
        using var process = new Process { StartInfo = startInfo };
        if (!process.Start()) throw new InvalidOperationException("TSK icat preview process could not be started.");
        var errorTask = ReadAllBytesAsync(process.StandardError.BaseStream, cancellationToken);
        var result = new byte[requested];
        var written = 0;
        var truncated = (ulong)requested < candidate.Size;
        try
        {
            while (written < requested)
            {
                var read = await process.StandardOutput.BaseStream.ReadAsync(result.AsMemory(written, requested - written), cancellationToken);
                if (read == 0) break;
                written += read;
            }
            if (truncated && !process.HasExited) process.Kill(entireProcessTree: true);
            await process.WaitForExitAsync(cancellationToken);
        }
        catch
        {
            if (!process.HasExited) process.Kill(entireProcessTree: true);
            try { await process.WaitForExitAsync(CancellationToken.None); } catch { }
            throw;
        }
        var error = Decode(await errorTask).Text.Trim();
        if (written != requested) throw new EndOfStreamException($"TSK preview returned {written:N0} of {requested:N0} requested bytes. {error}");
        if (!truncated && process.ExitCode != 0) throw new InvalidOperationException($"TSK icat preview failed ({process.ExitCode}): {error}");
        return result;
    }

    public static async Task<SleuthKitSamples> ReadSamplesAsync(
        string binDirectory,
        SleuthKitScanOptions options,
        SleuthKitCandidate candidate,
        int sampleBytes = 64 * 1024,
        ulong maximumStreamBytes = 512UL * 1024 * 1024,
        IProgress<ScanProgress>? progress = null,
        CancellationToken cancellationToken = default)
    {
        EnsureAvailable(binDirectory);
        ValidateOptions(options);
        ValidateContentCandidate(candidate);
        if (sampleBytes <= 0) throw new ArgumentOutOfRangeException(nameof(sampleBytes));
        if (candidate.Size > maximumStreamBytes)
            throw new NotSupportedException($"TSK preflight is limited to files no larger than {maximumStreamBytes:N0} bytes.");
        var sampleLength = checked((int)Math.Min(candidate.Size, (ulong)sampleBytes));
        if (sampleLength == 0) return new([], [], 0, Convert.ToHexString(SHA256.HashData([])).ToLowerInvariant());

        var startInfo = CreateStartInfo(Path.Combine(Path.GetFullPath(binDirectory), "icat.exe"),
            BuildIcatArguments(options, candidate.MetadataAddress));
        using var process = new Process { StartInfo = startInfo };
        if (!process.Start()) throw new InvalidOperationException("TSK icat preflight process could not be started.");
        var errorTask = ReadAllBytesAsync(process.StandardError.BaseStream, cancellationToken);
        var head = new byte[sampleLength];
        var tail = new byte[sampleLength];
        var headWritten = 0;
        var tailCount = 0;
        ulong total = 0;
        var buffer = new byte[1024 * 1024];
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        try
        {
            int read;
            while ((read = await process.StandardOutput.BaseStream.ReadAsync(buffer, cancellationToken)) > 0)
            {
                if (headWritten < head.Length)
                {
                    var copy = Math.Min(read, head.Length - headWritten);
                    buffer.AsSpan(0, copy).CopyTo(head.AsSpan(headWritten));
                    headWritten += copy;
                }
                UpdateTail(tail, ref tailCount, buffer.AsSpan(0, read));
                hash.AppendData(buffer.AsSpan(0, read));
                total += checked((ulong)read);
                progress?.Report(new("TSK preflight", total, candidate.Size, 1, candidate.OriginalPath));
            }
            await process.WaitForExitAsync(cancellationToken);
        }
        catch
        {
            if (!process.HasExited) process.Kill(entireProcessTree: true);
            try { await process.WaitForExitAsync(CancellationToken.None); } catch { }
            throw;
        }
        var error = Decode(await errorTask).Text.Trim();
        if (process.ExitCode != 0) throw new InvalidOperationException($"TSK icat preflight failed ({process.ExitCode}): {error}");
        if (total != candidate.Size) throw new EndOfStreamException($"TSK returned {total:N0} bytes; metadata declares {candidate.Size:N0} bytes.");
        if (tailCount < tail.Length) Array.Resize(ref tail, tailCount);
        return new(head, tail, total, Convert.ToHexString(hash.GetHashAndReset()).ToLowerInvariant());
    }

    internal static IReadOnlyList<SleuthKitCandidate> ParseMactime(string output, bool includeDirectories)
    {
        var candidates = new List<SleuthKitCandidate>();
        using var reader = new StringReader(output);
        while (reader.ReadLine() is { } line)
        {
            if (TryParseMactimeLine(line, includeDirectories, out var candidate)) candidates.Add(candidate);
        }
        return candidates;
    }

    private static bool TryParseMactimeLine(string line, bool includeDirectories, out SleuthKitCandidate candidate)
    {
        candidate = null!;
        if (string.IsNullOrWhiteSpace(line)) return false;
        var fields = line.Split('|');
        if (fields.Length < 11) return false;
        var path = fields[1].Trim();
        if (!path.EndsWith(DeletedSuffix, StringComparison.OrdinalIgnoreCase)) return false;
        path = path[..^DeletedSuffix.Length].TrimStart('/').Replace('/', Path.DirectorySeparatorChar);
        var metadataAddress = fields[2].Trim();
        var mode = fields[3].Trim();
        var isDirectory = mode.StartsWith("d/", StringComparison.OrdinalIgnoreCase);
        if (isDirectory && !includeDirectories) return false;
        if (string.IsNullOrWhiteSpace(path) || string.IsNullOrWhiteSpace(metadataAddress)) return false;
        if (!ulong.TryParse(fields[6], NumberStyles.None, CultureInfo.InvariantCulture, out var size)) return false;
        DateTime? modifiedUtc = null;
        if (long.TryParse(fields[8], NumberStyles.Integer, CultureInfo.InvariantCulture, out var epochSeconds) && epochSeconds > 0)
        {
            try { modifiedUtc = DateTimeOffset.FromUnixTimeSeconds(epochSeconds).UtcDateTime; }
            catch (ArgumentOutOfRangeException) { }
        }
        candidate = new(metadataAddress, path, size, isDirectory, modifiedUtc);
        return true;
    }

    internal static IReadOnlyList<SleuthKitCandidate> CollapseDuplicates(IReadOnlyList<SleuthKitCandidate> candidates) =>
        candidates
            .GroupBy(candidate => (candidate.OriginalPath.ToUpperInvariant(), candidate.Size, candidate.IsDirectory, candidate.ModifiedUtc))
            .Select(group => group.First() with
            {
                AlternateMetadataAddresses = group.Skip(1).Select(candidate => candidate.MetadataAddress)
                    .Distinct(StringComparer.OrdinalIgnoreCase).ToArray()
            })
            .OrderBy(candidate => candidate.OriginalPath, StringComparer.OrdinalIgnoreCase)
            .ToArray();

    private static void AppendFileSystemArguments(List<string> arguments, SleuthKitScanOptions options)
    {
        if (!string.IsNullOrWhiteSpace(options.FileSystemType))
        {
            arguments.Add("-f");
            arguments.Add(options.FileSystemType.Trim());
        }
        if (options.SectorSize != 512)
        {
            arguments.Add("-b");
            arguments.Add(options.SectorSize.ToString(CultureInfo.InvariantCulture));
        }
        if (options.PartitionOffsetBytes != 0)
        {
            if (options.PartitionOffsetBytes % options.SectorSize != 0)
                throw new ArgumentException("Partition offset must be aligned to the supplied sector size.", nameof(options));
            arguments.Add("-o");
            arguments.Add((options.PartitionOffsetBytes / options.SectorSize).ToString(CultureInfo.InvariantCulture));
        }
    }

    private static IReadOnlyList<string> BuildIcatArguments(SleuthKitScanOptions options, string metadataAddress)
    {
        var arguments = new List<string> { "-r", "-R" };
        AppendFileSystemArguments(arguments, options);
        arguments.Add(Path.GetFullPath(options.SourcePath));
        arguments.Add(metadataAddress);
        return arguments;
    }

    private static void ValidateContentCandidate(SleuthKitCandidate candidate)
    {
        if (candidate.IsDirectory) throw new ArgumentException("TSK cannot read a directory as a byte stream.", nameof(candidate));
        if (string.IsNullOrWhiteSpace(candidate.MetadataAddress)) throw new ArgumentException("Metadata address is required.", nameof(candidate));
    }

    private static void UpdateTail(byte[] tail, ref int tailCount, ReadOnlySpan<byte> data)
    {
        if (data.Length >= tail.Length)
        {
            data[^tail.Length..].CopyTo(tail);
            tailCount = tail.Length;
            return;
        }
        if (tailCount + data.Length <= tail.Length)
        {
            data.CopyTo(tail.AsSpan(tailCount));
            tailCount += data.Length;
            return;
        }
        var discard = tailCount + data.Length - tail.Length;
        tail.AsSpan(discard, tailCount - discard).CopyTo(tail);
        tailCount -= discard;
        data.CopyTo(tail.AsSpan(tailCount));
        tailCount += data.Length;
    }

    private static void ValidateOptions(SleuthKitScanOptions options)
    {
        if (string.IsNullOrWhiteSpace(options.SourcePath)) throw new ArgumentException("TSK source path is required.", nameof(options));
        if (!File.Exists(options.SourcePath) && !options.SourcePath.StartsWith(@"\\.\PhysicalDrive", StringComparison.OrdinalIgnoreCase))
            throw new FileNotFoundException("TSK source image was not found.", options.SourcePath);
        if (options.SectorSize == 0) throw new ArgumentOutOfRangeException(nameof(options), "Sector size must be greater than zero.");
    }

    private static void EnsureAvailable(string binDirectory)
    {
        if (!IsAvailable(binDirectory)) throw new DirectoryNotFoundException("The Sleuth Kit fls.exe and icat.exe were not found.");
    }

    private static ProcessStartInfo CreateStartInfo(string executablePath, IEnumerable<string> arguments)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = executablePath,
            WorkingDirectory = Path.GetDirectoryName(executablePath)!,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };
        foreach (var argument in arguments) startInfo.ArgumentList.Add(argument);
        return startInfo;
    }

    private static async Task<(int ExitCode, byte[] StandardOutput, byte[] StandardError)> RunCapturedAsync(
        string executablePath,
        IEnumerable<string> arguments,
        CancellationToken cancellationToken,
        IProgress<ScanProgress>? progress = null,
        TimeSpan? maximumRuntime = null)
    {
        using var process = new Process { StartInfo = CreateStartInfo(executablePath, arguments) };
        if (!process.Start()) throw new InvalidOperationException($"TSK process could not be started: {Path.GetFileName(executablePath)}");
        var outputTask = ReadAllBytesAsync(process.StandardOutput.BaseStream, cancellationToken);
        var errorTask = ReadAllBytesAsync(process.StandardError.BaseStream, cancellationToken);
        var stopwatch = Stopwatch.StartNew();
        try
        {
            while (!process.HasExited)
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (maximumRuntime is { } limit && stopwatch.Elapsed >= limit)
                    throw new TimeoutException($"TSK metadata scan exceeded {limit.TotalSeconds:N0} seconds.");
                var totalSeconds = maximumRuntime is { } maximum ? checked((ulong)Math.Max(1, maximum.TotalSeconds)) : 0UL;
                progress?.Report(new("TSK metadata", checked((ulong)stopwatch.Elapsed.TotalSeconds), totalSeconds, 0,
                    $"TSK 正在只读解析文件系统目录，已运行 {stopwatch.Elapsed:mm\\:ss}；可随时取消。"));
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
        return (process.ExitCode, await outputTask, await errorTask);
    }

    private static async Task<(int ExitCode, IReadOnlyList<SleuthKitCandidate> Candidates, string StandardError, string EncodingName)> RunMactimeScanAsync(
        string executablePath,
        IEnumerable<string> arguments,
        bool includeDirectories,
        CancellationToken cancellationToken,
        IProgress<ScanProgress>? progress,
        TimeSpan? maximumRuntime)
    {
        var (encoding, encodingName) = GetNativeOutputEncoding();
        using var process = new Process { StartInfo = CreateStartInfo(executablePath, arguments) };
        if (!process.Start()) throw new InvalidOperationException($"TSK process could not be started: {Path.GetFileName(executablePath)}");
        using var outputReader = new StreamReader(process.StandardOutput.BaseStream, encoding, false, 64 * 1024, leaveOpen: true);
        using var errorReader = new StreamReader(process.StandardError.BaseStream, encoding, false, 4096, leaveOpen: true);
        var candidates = new List<SleuthKitCandidate>();
        var parsedCount = 0;
        var outputTask = ReadMactimeCandidatesAsync(outputReader, includeDirectories, candidates,
            () => Interlocked.Increment(ref parsedCount), cancellationToken);
        var errorTask = errorReader.ReadToEndAsync(cancellationToken);
        var stopwatch = Stopwatch.StartNew();
        try
        {
            while (!process.HasExited)
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (maximumRuntime is { } limit && stopwatch.Elapsed >= limit)
                    throw new TimeoutException($"TSK metadata scan exceeded {limit.TotalSeconds:N0} seconds.");
                var totalSeconds = maximumRuntime is { } maximum ? checked((ulong)Math.Max(1, maximum.TotalSeconds)) : 0UL;
                var currentCount = Volatile.Read(ref parsedCount);
                progress?.Report(new("TSK metadata", checked((ulong)stopwatch.Elapsed.TotalSeconds), totalSeconds, currentCount,
                    $"TSK 正在流式解析文件系统目录，已运行 {stopwatch.Elapsed:mm\\:ss}，发现 {currentCount:N0} 条；可随时取消。"));
                await Task.Delay(1000, cancellationToken);
            }
            await process.WaitForExitAsync(cancellationToken);
            await outputTask;
        }
        catch
        {
            if (!process.HasExited) process.Kill(entireProcessTree: true);
            try { await process.WaitForExitAsync(CancellationToken.None); } catch { }
            try { await outputTask; } catch { }
            throw;
        }
        return (process.ExitCode, candidates, (await errorTask).Trim(), encodingName);
    }

    private static async Task ReadMactimeCandidatesAsync(
        StreamReader reader,
        bool includeDirectories,
        List<SleuthKitCandidate> candidates,
        Action candidateAdded,
        CancellationToken cancellationToken)
    {
        while (await reader.ReadLineAsync(cancellationToken) is { } line)
            if (TryParseMactimeLine(line, includeDirectories, out var candidate))
            {
                candidates.Add(candidate);
                candidateAdded();
            }
    }

    private static (Encoding Encoding, string Name) GetNativeOutputEncoding()
    {
        Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
        var codePage = CultureInfo.CurrentCulture.TextInfo.ANSICodePage;
        if (codePage is 0 or 65001) return (new UTF8Encoding(false, true), "UTF-8");
        var encoding = Encoding.GetEncoding(codePage, EncoderFallback.ReplacementFallback, DecoderFallback.ReplacementFallback);
        return (encoding, codePage == 936 ? "GBK/CP936" : $"{encoding.WebName}/CP{codePage}");
    }

    private static async Task<byte[]> ReadAllBytesAsync(Stream stream, CancellationToken cancellationToken)
    {
        using var buffer = new MemoryStream();
        await stream.CopyToAsync(buffer, cancellationToken);
        return buffer.ToArray();
    }

    private static (string Text, string Name) Decode(byte[] bytes)
    {
        if (bytes.Length == 0) return (string.Empty, "empty");
        try { return (new UTF8Encoding(false, true).GetString(bytes), "UTF-8"); }
        catch (DecoderFallbackException)
        {
            Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
            return (Encoding.GetEncoding(936, EncoderFallback.ReplacementFallback, DecoderFallback.ReplacementFallback).GetString(bytes), "GBK/CP936");
        }
    }
}
