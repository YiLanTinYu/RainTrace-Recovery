using System.Security.Cryptography;
using System.Text.Json;

namespace Recovery.Core;

public sealed record ImagingCheckpoint(string SourceId, ulong SourceLength, string? SourceFingerprint, ulong CompletedBytes, int ReadErrors, DateTime UpdatedUtc);
public sealed record ImagingResult(string ImagePath, ulong BytesProcessed, int ReadErrors, string Sha256, bool Complete);

public sealed class DiskImager
{
    private const int BlockSize = 4 * 1024 * 1024;
    private readonly IBlockDevice _source;
    private readonly IProgress<ScanProgress>? _progress;

    public DiskImager(IBlockDevice source, IProgress<ScanProgress>? progress = null)
    {
        _source = source;
        _progress = progress;
    }

    public async Task<ImagingResult> CreateImageAsync(string imagePath, CancellationToken cancellationToken = default)
    {
        var fullPath = Path.GetFullPath(imagePath);
        Directory.CreateDirectory(Path.GetDirectoryName(fullPath)!);
        var checkpointPath = fullPath + ".state.json";
        var sourceFingerprint = await ComputeSourceFingerprintAsync(cancellationToken);
        ulong completed = 0;
        var errors = 0;
        if (File.Exists(checkpointPath) && File.Exists(fullPath))
        {
            var saved = JsonSerializer.Deserialize<ImagingCheckpoint>(await File.ReadAllTextAsync(checkpointPath, cancellationToken));
            if (saved is not null && saved.SourceId == _source.Id && saved.SourceLength == _source.Length &&
                string.Equals(saved.SourceFingerprint, sourceFingerprint, StringComparison.Ordinal))
            {
                completed = Math.Min(saved.CompletedBytes, checked((ulong)new FileInfo(fullPath).Length));
                errors = saved.ReadErrors;
            }
        }

        await using var output = new FileStream(fullPath, completed == 0 ? FileMode.Create : FileMode.Open, FileAccess.Write, FileShare.Read, BlockSize, FileOptions.Asynchronous | FileOptions.SequentialScan);
        output.Position = checked((long)completed);
        var buffer = new byte[BlockSize];
        while (completed < _source.Length)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var count = checked((int)Math.Min((ulong)buffer.Length, _source.Length - completed));
            var successful = false;
            for (var attempt = 0; attempt < 2 && !successful; attempt++)
            {
                try
                {
                    await _source.ReadExactlyAsync(completed, buffer.AsMemory(0, count), cancellationToken);
                    successful = true;
                }
                catch (IOException) when (attempt == 0)
                {
                    await Task.Delay(50, cancellationToken);
                }
                catch (IOException)
                {
                    buffer.AsSpan(0, count).Clear();
                    errors++;
                }
            }
            await output.WriteAsync(buffer.AsMemory(0, count), cancellationToken);
            completed += checked((ulong)count);
            if (completed % (256UL * 1024 * 1024) < (ulong)BlockSize || completed == _source.Length)
            {
                await output.FlushAsync(cancellationToken);
                var checkpoint = new ImagingCheckpoint(_source.Id, _source.Length, sourceFingerprint, completed, errors, DateTime.UtcNow);
                await File.WriteAllTextAsync(checkpointPath, JsonSerializer.Serialize(checkpoint, new JsonSerializerOptions { WriteIndented = true }), cancellationToken);
            }
            _progress?.Report(new("Creating image", completed, _source.Length, 0, $"Read errors: {errors:N0}"));
        }
        await output.FlushAsync(cancellationToken);
        output.Close();
        var sha = await ComputeSha256Async(fullPath, cancellationToken);
        return new(fullPath, completed, errors, sha, completed == _source.Length);
    }

    private static async Task<string> ComputeSha256Async(string path, CancellationToken cancellationToken)
    {
        await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, BlockSize, FileOptions.Asynchronous | FileOptions.SequentialScan);
        var hash = await SHA256.HashDataAsync(stream, cancellationToken);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    private async Task<string> ComputeSourceFingerprintAsync(CancellationToken cancellationToken)
    {
        const int sampleSize = 64 * 1024;
        var firstLength = checked((int)Math.Min((ulong)sampleSize, _source.Length));
        var lastLength = checked((int)Math.Min((ulong)sampleSize, _source.Length > (ulong)firstLength ? _source.Length - (ulong)firstLength : 0));
        var sample = new byte[firstLength + lastLength + sizeof(ulong)];
        if (firstLength > 0) await _source.ReadExactlyAsync(0, sample.AsMemory(0, firstLength), cancellationToken);
        if (lastLength > 0) await _source.ReadExactlyAsync(_source.Length - (ulong)lastLength, sample.AsMemory(firstLength, lastLength), cancellationToken);
        BitConverter.TryWriteBytes(sample.AsSpan(firstLength + lastLength), _source.Length);
        return Convert.ToHexString(SHA256.HashData(sample)).ToLowerInvariant();
    }
}
