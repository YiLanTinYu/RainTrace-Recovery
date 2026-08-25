using System.Security.Cryptography;

namespace Recovery.Core;

public static partial class RecoveryWriter
{
    public static async Task<RecoveryResult> RecoverStagedAsync(
        RecoveryCandidate candidate,
        string destinationRoot,
        IProgress<ScanProgress>? progress = null,
        CancellationToken cancellationToken = default)
    {
        if (candidate.Discovery != RecoveryDiscovery.PhotoRecFile || string.IsNullOrWhiteSpace(candidate.StagedRecoveryPath))
            throw new InvalidOperationException("Candidate is not a PhotoRec staged recovery.");
        var sourcePath = Path.GetFullPath(candidate.StagedRecoveryPath);
        if (!File.Exists(sourcePath)) throw new FileNotFoundException("PhotoRec staged file is no longer available.", sourcePath);

        var root = Path.GetFullPath(destinationRoot);
        Directory.CreateDirectory(root);
        var extension = candidate.Extension.Length == 0 ? "other" : candidate.Extension;
        var directory = Path.Combine(root, "PhotoRec Recovery", extension);
        Directory.CreateDirectory(directory);
        var output = EnsureUniqueStagedPath(Path.Combine(directory, NtfsScanner.SanitizePathComponent(candidate.Name)));

        await using var input = new FileStream(sourcePath, FileMode.Open, FileAccess.Read, FileShare.Read,
            1024 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan);
        await using var outputStream = new FileStream(output, FileMode.CreateNew, FileAccess.Write, FileShare.None,
            1024 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan);
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var buffer = new byte[1024 * 1024];
        ulong written = 0;
        int read;
        while ((read = await input.ReadAsync(buffer, cancellationToken)) > 0)
        {
            await outputStream.WriteAsync(buffer.AsMemory(0, read), cancellationToken);
            hash.AppendData(buffer.AsSpan(0, read));
            written += checked((ulong)read);
            progress?.Report(new("Copying PhotoRec result", written, candidate.Size, 1, candidate.Name));
        }
        await outputStream.FlushAsync(cancellationToken);
        var digest = Convert.ToHexString(hash.GetHashAndReset()).ToLowerInvariant();
        await outputStream.DisposeAsync();
        return await FinalizeResultAsync(output, written, digest, written == candidate.Size, cancellationToken);
    }

    private static string EnsureUniqueStagedPath(string path)
    {
        if (!File.Exists(path)) return path;
        var directory = Path.GetDirectoryName(path) ?? string.Empty;
        var stem = Path.GetFileNameWithoutExtension(path);
        var extension = Path.GetExtension(path);
        for (var index = 1; index < 100_000; index++)
        {
            var candidate = Path.Combine(directory, $"{stem} ({index}){extension}");
            if (!File.Exists(candidate)) return candidate;
        }
        throw new IOException("Unable to allocate a unique PhotoRec recovery filename.");
    }
}
