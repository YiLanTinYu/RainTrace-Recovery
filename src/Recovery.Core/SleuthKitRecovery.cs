using System.Security.Cryptography;

namespace Recovery.Core;

public static partial class RecoveryWriter
{
    public static async Task<RecoveryResult> RecoverSleuthKitAsync(
        string binDirectory,
        SleuthKitScanOptions scanOptions,
        SleuthKitCandidate candidate,
        string destinationRoot,
        IProgress<ScanProgress>? progress = null,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(destinationRoot)) throw new ArgumentException("A destination directory is required.", nameof(destinationRoot));
        var root = Path.GetFullPath(destinationRoot);
        Directory.CreateDirectory(root);
        var components = candidate.OriginalPath
            .Split(['/', '\\'], StringSplitOptions.RemoveEmptyEntries)
            .Where(component => component is not "." and not "..")
            .Select(NtfsScanner.SanitizePathComponent)
            .ToArray();
        if (components.Length == 0) components = [$"tsk-{candidate.MetadataAddress}.bin"];
        var selected = await SelectSleuthKitPhysicalCandidateAsync(binDirectory, scanOptions, candidate, progress, cancellationToken);
        var proposed = Path.Combine([root, .. components]);
        var output = EnsureUniqueSleuthKitPath(proposed);
        progress?.Report(new("TSK recovery", 0, candidate.Size, 1, candidate.OriginalPath));
        var recovered = await SleuthKitEngine.RecoverAsync(binDirectory, scanOptions, selected, output, cancellationToken);
        await using var stream = new FileStream(output, FileMode.Open, FileAccess.Read, FileShare.Read,
            1024 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan);
        var digest = Convert.ToHexString(await SHA256.HashDataAsync(stream, cancellationToken)).ToLowerInvariant();
        progress?.Report(new("TSK recovery", recovered.BytesWritten, candidate.Size, 1, candidate.OriginalPath));
        var result = await FinalizeResultAsync(output, recovered.BytesWritten, digest,
            recovered.BytesWritten == candidate.Size, cancellationToken);
        if (!string.Equals(selected.MetadataAddress, candidate.MetadataAddress, StringComparison.OrdinalIgnoreCase))
            result = result with { IntegrityMessage = $"{result.IntegrityMessage} TSK主记录预检未通过，已自动改用备用元数据地址 {selected.MetadataAddress}。" };
        return result;
    }

    private static async Task<SleuthKitCandidate> SelectSleuthKitPhysicalCandidateAsync(
        string binDirectory,
        SleuthKitScanOptions options,
        SleuthKitCandidate candidate,
        IProgress<ScanProgress>? progress,
        CancellationToken cancellationToken)
    {
        var choices = new[] { candidate.MetadataAddress }.Concat(candidate.AlternateMetadataAddresses)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Select(address => candidate with { MetadataAddress = address, AlternateMetadataAddresses = [] })
            .ToArray();
        if (choices.Length == 1 || !FileIntegrityValidator.SupportsSampleValidation(Path.GetExtension(candidate.OriginalPath).TrimStart('.')))
            return candidate;
        foreach (var choice in choices)
        {
            var validation = await FileIntegrityValidator.ValidateSleuthKitCandidateAsync(
                binDirectory, options, choice, progress, cancellationToken);
            if (validation.State == FileIntegrityState.Valid) return choice;
            if (validation.State == FileIntegrityState.NotChecked) return candidate;
        }
        return candidate;
    }

    private static string EnsureUniqueSleuthKitPath(string path)
    {
        if (!File.Exists(path) && !Directory.Exists(path)) return path;
        var directory = Path.GetDirectoryName(path) ?? string.Empty;
        var stem = Path.GetFileNameWithoutExtension(path);
        var extension = Path.GetExtension(path);
        for (var index = 1; index < 100_000; index++)
        {
            var candidate = Path.Combine(directory, $"{stem} ({index}){extension}");
            if (!File.Exists(candidate) && !Directory.Exists(candidate)) return candidate;
        }
        throw new IOException("Unable to allocate a unique TSK recovery filename.");
    }
}

public static partial class FileIntegrityValidator
{
    public static bool SupportsSampleValidation(string extension) =>
        RecoveryCapabilityRegistry.SupportsPreflight(extension);

    public static async Task<FileIntegrityResult> ValidateSleuthKitCandidateAsync(
        string binDirectory,
        SleuthKitScanOptions options,
        SleuthKitCandidate candidate,
        IProgress<ScanProgress>? progress = null,
        CancellationToken cancellationToken = default)
    {
        var extension = Path.GetExtension(candidate.OriginalPath).TrimStart('.').ToLowerInvariant();
        if (!SupportsSampleValidation(extension)) return new(FileIntegrityState.NotChecked, "此文件类型暂未提供恢复前结构预检。");
        try
        {
            var samples = await SleuthKitEngine.ReadSamplesAsync(binDirectory, options, candidate,
                progress: progress, cancellationToken: cancellationToken);
            return ValidateSamples(extension, candidate.Size, samples.Head, samples.Tail);
        }
        catch (NotSupportedException ex) { return new(FileIntegrityState.NotChecked, ex.Message); }
        catch (Exception ex) when (ex is IOException or InvalidDataException or EndOfStreamException or OverflowException or ArgumentOutOfRangeException or InvalidOperationException)
        {
            return new(FileIntegrityState.Damaged, $"TSK无法读取预检数据：{ex.Message}");
        }
    }
}
