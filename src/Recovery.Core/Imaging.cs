using System.Security.Cryptography;
using System.Text.Json;

namespace Recovery.Core;

public sealed record ImagingBadRange(ulong Offset, ulong Length, long ReadAttempts, long RetryAttempts);

public sealed record ImagingCheckpoint(string SourceId, ulong SourceLength, string? SourceFingerprint, ulong CompletedBytes, int ReadErrors, DateTime UpdatedUtc)
{
    public int SchemaVersion { get; init; } = 2;
    public uint LogicalSectorSize { get; init; }
    public long RetryAttempts { get; init; }
    public ImagingBadRange[] BadRanges { get; init; } = [];
}

public sealed record ImagingBadSectorMap(
    int SchemaVersion,
    string SourceId,
    ulong SourceLength,
    uint LogicalSectorSize,
    ulong BytesProcessed,
    int ReadErrors,
    long RetryAttempts,
    ulong UnreadableBytes,
    IReadOnlyList<ImagingBadRange> BadRanges,
    DateTime UpdatedUtc,
    bool Complete);

public sealed record ImagingResult(string ImagePath, ulong BytesProcessed, int ReadErrors, string Sha256, bool Complete)
{
    public string CheckpointPath { get; init; } = string.Empty;
    public string BadSectorMapPath { get; init; } = string.Empty;
    public long RetryAttempts { get; init; }
    public ulong UnreadableBytes { get; init; }
    public IReadOnlyList<ImagingBadRange> BadRanges { get; init; } = Array.Empty<ImagingBadRange>();
}

public sealed class DiskImager
{
    private const int BlockSize = 4 * 1024 * 1024;
    private const int SplitReadSize = 64 * 1024;
    private const int AttemptsPerRead = 2;
    private const ulong CheckpointByteInterval = 256UL * 1024 * 1024;
    private static readonly TimeSpan CheckpointTimeInterval = TimeSpan.FromSeconds(5);
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

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
        var badSectorMapPath = fullPath + ".badmap.json";
        var sourceFingerprint = await ComputeSourceFingerprintAsync(cancellationToken);
        var sectorSize = GetLogicalSectorSize();
        ulong completed = 0;
        var statistics = new ImagingStatistics();
        var badRanges = new List<ImagingBadRange>();

        var imageExists = File.Exists(fullPath);
        var checkpointExists = File.Exists(checkpointPath);
        var badMapExists = File.Exists(badSectorMapPath);
        if (imageExists != checkpointExists || (!imageExists && badMapExists))
            throw ExistingImageCannotResume(fullPath,
                "镜像、检查点或坏区地图不成套，无法确认已有数据属于当前源介质");

        if (imageExists && checkpointExists)
        {
            var saved = await LoadCheckpointAsync(checkpointPath, cancellationToken);
            var existingLength = checked((ulong)new FileInfo(fullPath).Length);
            if (saved is null || saved.SourceLength != _source.Length ||
                !string.Equals(saved.SourceFingerprint, sourceFingerprint, StringComparison.Ordinal) ||
                (saved.LogicalSectorSize != 0 && saved.LogicalSectorSize != (uint)sectorSize) ||
                saved.CompletedBytes > _source.Length || saved.CompletedBytes > existingLength ||
                existingLength > _source.Length)
                throw ExistingImageCannotResume(fullPath,
                    "已有检查点与当前介质的容量、扇区、内容指纹或镜像长度不一致");

            // SourceId contains a Windows physical-drive path and may legitimately change after
            // unplug/reinsert. The path is diagnostic only; length + sector size + content
            // fingerprint are the stable resume identity.
            completed = saved.CompletedBytes;
            if (completed != _source.Length)
                completed = completed / (uint)sectorSize * (uint)sectorSize;
            statistics.ReadErrors = saved.ReadErrors;
            statistics.RetryAttempts = Math.Max(0, saved.RetryAttempts);
            badRanges.AddRange(NormalizeBadRanges(saved.BadRanges, completed));
        }

        await using var output = new FileStream(
            fullPath,
            imageExists ? FileMode.Open : FileMode.CreateNew,
            FileAccess.Write,
            FileShare.Read,
            BlockSize,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        output.SetLength(checked((long)completed));
        output.Position = checked((long)completed);

        var buffer = new byte[BlockSize];
        var lastCheckpointBytes = completed;
        var lastCheckpointUtc = DateTime.UtcNow;
        try
        {
            while (completed < _source.Length)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var count = checked((int)Math.Min((ulong)buffer.Length, _source.Length - completed));
                var target = buffer.AsMemory(0, count);
                target.Span.Clear();
                await ReadConservativelyAsync(completed, target, sectorSize, statistics, badRanges, cancellationToken);
                await output.WriteAsync(target, cancellationToken);
                completed += checked((ulong)count);

                var now = DateTime.UtcNow;
                if (completed == _source.Length ||
                    completed - lastCheckpointBytes >= CheckpointByteInterval ||
                    now - lastCheckpointUtc >= CheckpointTimeInterval)
                {
                    await output.FlushAsync(cancellationToken);
                    await SaveStateAsync(checkpointPath, badSectorMapPath, sourceFingerprint, completed,
                        sectorSize, statistics, badRanges, now, cancellationToken);
                    lastCheckpointBytes = completed;
                    lastCheckpointUtc = now;
                }

                _progress?.Report(new(
                    "正在创建镜像",
                    completed,
                    _source.Length,
                    0,
                    $"不可读扇区：{statistics.ReadErrors:N0}；重试：{statistics.RetryAttempts:N0}"));
            }
        }
        catch (OperationCanceledException)
        {
            output.SetLength(checked((long)completed));
            await output.FlushAsync(CancellationToken.None);
            await SaveStateAsync(checkpointPath, badSectorMapPath, sourceFingerprint, completed,
                sectorSize, statistics, badRanges, DateTime.UtcNow, CancellationToken.None);
            throw;
        }

        await output.FlushAsync(cancellationToken);
        output.SetLength(checked((long)_source.Length));
        await SaveStateAsync(checkpointPath, badSectorMapPath, sourceFingerprint, completed,
            sectorSize, statistics, badRanges, DateTime.UtcNow, cancellationToken);
        output.Close();

        var sha = await ComputeSha256Async(fullPath, cancellationToken);
        var immutableBadRanges = badRanges.ToArray();
        return new(fullPath, completed, statistics.ReadErrors, sha, completed == _source.Length)
        {
            CheckpointPath = checkpointPath,
            BadSectorMapPath = badSectorMapPath,
            RetryAttempts = statistics.RetryAttempts,
            UnreadableBytes = SumUnreadableBytes(immutableBadRanges),
            BadRanges = immutableBadRanges
        };
    }

    private static InvalidOperationException ExistingImageCannotResume(string imagePath, string reason) =>
        new($"{reason}。为保护已有镜像，雨痕没有修改任何文件。请选择新的镜像路径，或在人工确认后同时移走旧镜像及其 .state.json/.badmap.json 文件。\n路径：{imagePath}");

    private async Task ReadConservativelyAsync(
        ulong offset,
        Memory<byte> destination,
        int sectorSize,
        ImagingStatistics statistics,
        List<ImagingBadRange> badRanges,
        CancellationToken cancellationToken)
    {
        if ((await TryReadWithRetryAsync(offset, destination, statistics, cancellationToken)).Success)
            return;

        var splitThreshold = Math.Max(SplitReadSize, sectorSize);
        if (destination.Length > splitThreshold)
        {
            var firstLength = GetAlignedSplitLength(destination.Length, sectorSize);
            await ReadConservativelyAsync(offset, destination[..firstLength], sectorSize, statistics, badRanges, cancellationToken);
            await ReadConservativelyAsync(offset + checked((ulong)firstLength), destination[firstLength..], sectorSize, statistics, badRanges, cancellationToken);
            return;
        }

        for (var relativeOffset = 0; relativeOffset < destination.Length; relativeOffset += sectorSize)
        {
            var length = Math.Min(sectorSize, destination.Length - relativeOffset);
            var sector = destination.Slice(relativeOffset, length);
            var sectorOffset = offset + checked((ulong)relativeOffset);
            var sectorRead = await TryReadWithRetryAsync(sectorOffset, sector, statistics, cancellationToken);
            if (sectorRead.Success)
                continue;

            sector.Span.Clear();
            statistics.ReadErrors = statistics.ReadErrors == int.MaxValue ? int.MaxValue : statistics.ReadErrors + 1;
            AddBadRange(badRanges, sectorOffset, checked((ulong)length), sectorRead.Attempts, Math.Max(0, sectorRead.Attempts - 1));
        }
    }

    private async Task<ReadAttemptResult> TryReadWithRetryAsync(
        ulong offset,
        Memory<byte> destination,
        ImagingStatistics statistics,
        CancellationToken cancellationToken)
    {
        var attemptsMade = 0;
        for (var attempt = 0; attempt < AttemptsPerRead; attempt++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            attemptsMade++;
            if (attempt > 0)
            {
                statistics.RetryAttempts++;
                await Task.Delay(50, cancellationToken);
            }

            try
            {
                await ReadExactlyForImagingAsync(offset, destination, cancellationToken);
                return new(true, attemptsMade);
            }
            catch (IOException) when (attempt + 1 < AttemptsPerRead)
            {
                // Retry once at the same size before degrading to smaller reads.
            }
            catch (IOException)
            {
                return new(false, attemptsMade);
            }
        }

        return new(false, attemptsMade);
    }

    private async Task SaveStateAsync(
        string checkpointPath,
        string badSectorMapPath,
        string sourceFingerprint,
        ulong completed,
        int sectorSize,
        ImagingStatistics statistics,
        List<ImagingBadRange> badRanges,
        DateTime updatedUtc,
        CancellationToken cancellationToken)
    {
        var ranges = badRanges.ToArray();
        var checkpoint = new ImagingCheckpoint(
            _source.Id,
            _source.Length,
            sourceFingerprint,
            completed,
            statistics.ReadErrors,
            updatedUtc)
        {
            LogicalSectorSize = checked((uint)sectorSize),
            RetryAttempts = statistics.RetryAttempts,
            BadRanges = ranges
        };
        await WriteJsonAtomicallyAsync(checkpointPath, checkpoint, cancellationToken);

        var map = new ImagingBadSectorMap(
            1,
            _source.Id,
            _source.Length,
            checked((uint)sectorSize),
            completed,
            statistics.ReadErrors,
            statistics.RetryAttempts,
            SumUnreadableBytes(ranges),
            ranges,
            updatedUtc,
            completed == _source.Length);
        await WriteJsonAtomicallyAsync(badSectorMapPath, map, cancellationToken);
    }

    private static async Task<ImagingCheckpoint?> LoadCheckpointAsync(string path, CancellationToken cancellationToken)
    {
        await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 64 * 1024,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        try
        {
            return await JsonSerializer.DeserializeAsync<ImagingCheckpoint>(stream, JsonOptions, cancellationToken);
        }
        catch (JsonException ex)
        {
            throw new InvalidDataException($"Imaging checkpoint is invalid: {path}", ex);
        }
    }

    private static async Task WriteJsonAtomicallyAsync<T>(string path, T value, CancellationToken cancellationToken)
    {
        var temporaryPath = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            await using (var stream = new FileStream(temporaryPath, FileMode.CreateNew, FileAccess.Write, FileShare.None,
                64 * 1024, FileOptions.Asynchronous | FileOptions.WriteThrough))
            {
                await JsonSerializer.SerializeAsync(stream, value, JsonOptions, cancellationToken);
                await stream.FlushAsync(cancellationToken);
            }
            File.Move(temporaryPath, path, true);
        }
        finally
        {
            if (File.Exists(temporaryPath))
                File.Delete(temporaryPath);
        }
    }

    private int GetLogicalSectorSize()
    {
        var sectorSize = _source.LogicalSectorSize == 0 ? 512u : _source.LogicalSectorSize;
        if (sectorSize > BlockSize)
            throw new InvalidOperationException($"Unsupported logical sector size: {sectorSize:N0} bytes.");
        return checked((int)sectorSize);
    }

    private static int GetAlignedSplitLength(int length, int sectorSize)
    {
        var half = length / 2;
        var aligned = half / sectorSize * sectorSize;
        if (aligned == 0)
            aligned = Math.Min(sectorSize, length - 1);
        if (aligned >= length)
            aligned = length / 2;
        return aligned;
    }

    private static void AddBadRange(
        List<ImagingBadRange> ranges,
        ulong offset,
        ulong length,
        long readAttempts,
        long retryAttempts)
    {
        if (length == 0) return;
        if (ranges.Count > 0)
        {
            var previous = ranges[^1];
            if (previous.Offset <= ulong.MaxValue - previous.Length && previous.Offset + previous.Length == offset)
            {
                ranges[^1] = previous with
                {
                    Length = checked(previous.Length + length),
                    ReadAttempts = checked(previous.ReadAttempts + readAttempts),
                    RetryAttempts = checked(previous.RetryAttempts + retryAttempts)
                };
                return;
            }
        }
        ranges.Add(new(offset, length, readAttempts, retryAttempts));
    }

    private static IReadOnlyList<ImagingBadRange> NormalizeBadRanges(ImagingBadRange[]? savedRanges, ulong completed)
    {
        if (savedRanges is null || savedRanges.Length == 0 || completed == 0)
            return Array.Empty<ImagingBadRange>();

        var normalized = new List<ImagingBadRange>();
        foreach (var range in savedRanges.OrderBy(item => item.Offset))
        {
            if (range.Length == 0 || range.Offset >= completed) continue;
            var length = Math.Min(range.Length, completed - range.Offset);
            AddBadRange(normalized, range.Offset, length, Math.Max(0, range.ReadAttempts), Math.Max(0, range.RetryAttempts));
        }
        return normalized;
    }

    private static ulong SumUnreadableBytes(IEnumerable<ImagingBadRange> ranges)
    {
        ulong total = 0;
        foreach (var range in ranges)
            total = checked(total + range.Length);
        return total;
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
        try
        {
            if (firstLength > 0) await _source.ReadExactlyAsync(0, sample.AsMemory(0, firstLength), cancellationToken);
            if (lastLength > 0) await _source.ReadExactlyAsync(_source.Length - (ulong)lastLength, sample.AsMemory(firstLength, lastLength), cancellationToken);
            BitConverter.TryWriteBytes(sample.AsSpan(firstLength + lastLength), _source.Length);
            return Convert.ToHexString(SHA256.HashData(sample)).ToLowerInvariant();
        }
        catch (IOException)
        {
            // Preserve the legacy fingerprint when both samples are readable. If either sample is damaged,
            // derive a deterministic degraded fingerprint instead of preventing imaging from starting.
            sample.AsSpan().Clear();
            var sectorSize = GetLogicalSectorSize();
            var firstSectors = (firstLength + sectorSize - 1) / sectorSize;
            var lastSectors = (lastLength + sectorSize - 1) / sectorSize;
            var readability = new byte[firstSectors + lastSectors + 4];
            readability[^4] = (byte)'B';
            readability[^3] = (byte)'A';
            readability[^2] = (byte)'D';
            readability[^1] = 1;
            await ReadFingerprintRangeAsync(0, sample.AsMemory(0, firstLength), sectorSize, readability.AsMemory(0, firstSectors), cancellationToken);
            await ReadFingerprintRangeAsync(_source.Length - (ulong)lastLength, sample.AsMemory(firstLength, lastLength),
                sectorSize, readability.AsMemory(firstSectors, lastSectors), cancellationToken);
            BitConverter.TryWriteBytes(sample.AsSpan(firstLength + lastLength), _source.Length);
            var fingerprintData = new byte[sample.Length + readability.Length];
            sample.CopyTo(fingerprintData, 0);
            readability.CopyTo(fingerprintData, sample.Length);
            return Convert.ToHexString(SHA256.HashData(fingerprintData)).ToLowerInvariant();
        }
    }

    private async Task ReadFingerprintRangeAsync(
        ulong offset,
        Memory<byte> destination,
        int sectorSize,
        Memory<byte> readability,
        CancellationToken cancellationToken)
    {
        for (var relativeOffset = 0; relativeOffset < destination.Length; relativeOffset += sectorSize)
        {
            var sectorIndex = relativeOffset / sectorSize;
            var length = Math.Min(sectorSize, destination.Length - relativeOffset);
            var sector = destination.Slice(relativeOffset, length);
            var readable = false;
            for (var attempt = 0; attempt < AttemptsPerRead && !readable; attempt++)
            {
                cancellationToken.ThrowIfCancellationRequested();
                try
                {
                    await ReadExactlyForImagingAsync(offset + checked((ulong)relativeOffset), sector, cancellationToken);
                    readable = true;
                }
                catch (IOException) when (attempt + 1 < AttemptsPerRead)
                {
                    await Task.Delay(50, cancellationToken);
                }
                catch (IOException)
                {
                    sector.Span.Clear();
                }
            }
            readability.Span[sectorIndex] = readable ? (byte)1 : (byte)0;
        }
    }

    private async ValueTask ReadExactlyForImagingAsync(ulong offset, Memory<byte> buffer, CancellationToken cancellationToken)
    {
        var total = 0;
        while (total < buffer.Length)
        {
            var read = _source is IPreciseBlockDevice precise
                ? await precise.ReadPreciseAsync(offset + checked((ulong)total), buffer[total..], cancellationToken)
                : await _source.ReadAsync(offset + checked((ulong)total), buffer[total..], cancellationToken);
            if (read == 0) throw new EndOfStreamException($"Unexpected end of device at byte {offset + checked((ulong)total):N0}");
            total += read;
        }
    }

    private sealed class ImagingStatistics
    {
        public int ReadErrors { get; set; }
        public long RetryAttempts { get; set; }
    }

    private readonly record struct ReadAttemptResult(bool Success, int Attempts);
}
