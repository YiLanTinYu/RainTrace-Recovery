using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace Recovery.Core;

public sealed record ExFatBootSector(
    uint BytesPerSector,
    uint SectorsPerCluster,
    uint FatOffsetSectors,
    uint FatLengthSectors,
    uint ClusterHeapOffsetSectors,
    uint ClusterCount,
    uint RootDirectoryCluster,
    byte NumberOfFats,
    ushort VolumeFlags)
{
    public uint ClusterSize => checked(BytesPerSector * SectorsPerCluster);
    public uint ActiveFat => NumberOfFats == 2 ? (uint)(VolumeFlags & 1) : 0;

    public static ExFatBootSector Parse(ReadOnlySpan<byte> boot)
    {
        if (boot.Length < 512 || !boot.Slice(3, 8).SequenceEqual("EXFAT   "u8) || boot[510] != 0x55 || boot[511] != 0xAA)
            throw new InvalidDataException("The partition does not contain a valid exFAT boot sector.");
        var bytesShift = boot[108];
        var clusterShift = boot[109];
        if (bytesShift is < 9 or > 12 || clusterShift > 25 - bytesShift)
            throw new InvalidDataException("The exFAT sector or cluster size is invalid.");
        var bytesPerSector = 1u << bytesShift;
        var sectorsPerCluster = 1u << clusterShift;
        var fatOffset = BinaryPrimitives.ReadUInt32LittleEndian(boot[80..84]);
        var fatLength = BinaryPrimitives.ReadUInt32LittleEndian(boot[84..88]);
        var heapOffset = BinaryPrimitives.ReadUInt32LittleEndian(boot[88..92]);
        var clusterCount = BinaryPrimitives.ReadUInt32LittleEndian(boot[92..96]);
        var root = BinaryPrimitives.ReadUInt32LittleEndian(boot[96..100]);
        var flags = BinaryPrimitives.ReadUInt16LittleEndian(boot[106..108]);
        var fats = boot[110];
        if (fatOffset == 0 || fatLength == 0 || heapOffset == 0 || clusterCount == 0 || root < 2 || root >= clusterCount + 2 || fats is < 1 or > 2)
            throw new InvalidDataException("The exFAT volume geometry is invalid.");
        return new(bytesPerSector, sectorsPerCluster, fatOffset, fatLength, heapOffset, clusterCount, root, fats, flags);
    }
}

public sealed class ExFatScanResult
{
    internal ExFatScanResult(ExFatBootSector boot, ulong partitionOffset, IReadOnlyList<RecoveryCandidate> candidates)
    {
        Boot = boot;
        PartitionOffset = partitionOffset;
        Candidates = candidates;
    }

    public ExFatBootSector Boot { get; }
    public ulong PartitionOffset { get; }
    public IReadOnlyList<RecoveryCandidate> Candidates { get; }

    public static ExFatScanResult CreateRecoveryContext(ExFatBootSector boot, ulong partitionOffset) =>
        new(boot, partitionOffset, []);
}

public sealed class ExFatScanner
{
    private const ulong MaximumDirectoryBytes = 256UL * 1024 * 1024;
    private const int DeepMetadataBlockSize = 8 * 1024 * 1024;
    private const int DeepMetadataOverlap = 1024;
    private const ulong ExFatDirectoryEntrySize = 32;
    private readonly IBlockDevice _device;
    private readonly ulong _partitionOffset;
    private readonly IProgress<ScanProgress>? _progress;
    private readonly IProgress<RecoveryCandidate>? _deepCandidateProgress;
    private readonly ulong? _bootSectorOffset;
    private ExFatBootSector _boot = null!;
    private ulong _fatOffset;
    private ulong _clusterHeapOffset;
    private readonly HashSet<uint> _visitedDirectories = [];
    private readonly List<RecoveryCandidate> _candidates = [];
    private readonly HashSet<string> _candidateKeys = new(StringComparer.OrdinalIgnoreCase);
    private (IReadOnlyList<DataExtent> Extents, ulong Length)? _allocationBitmap;
    private ulong _directoryBytesRead;

    public ExFatScanner(IBlockDevice device, ulong partitionOffset, IProgress<ScanProgress>? progress = null, ulong? bootSectorOffset = null)
        : this(device, partitionOffset, progress, bootSectorOffset, null)
    {
    }

    public ExFatScanner(IBlockDevice device, ulong partitionOffset, IProgress<ScanProgress>? progress,
        ulong? bootSectorOffset, IProgress<RecoveryCandidate>? deepCandidateProgress)
    {
        _device = device;
        _partitionOffset = partitionOffset;
        _progress = progress;
        _bootSectorOffset = bootSectorOffset;
        _deepCandidateProgress = deepCandidateProgress;
    }

    public async Task<ExFatScanResult> ScanAsync(ScanOptions? options = null, CancellationToken cancellationToken = default)
    {
        options ??= new();
        var bootBytes = new byte[512];
        await _device.ReadExactlyAsync(_bootSectorOffset ?? _partitionOffset, bootBytes, cancellationToken);
        _boot = ExFatBootSector.Parse(bootBytes);
        _fatOffset = checked(_partitionOffset + ((ulong)_boot.FatOffsetSectors + (ulong)_boot.ActiveFat * _boot.FatLengthSectors) * _boot.BytesPerSector);
        _clusterHeapOffset = checked(_partitionOffset + (ulong)_boot.ClusterHeapOffsetSectors * _boot.BytesPerSector);
        await ScanDirectoryAsync(_boot.RootDirectoryCluster, null, false, string.Empty, options.IncludeActiveFiles, cancellationToken);
        if (options.ExFatDeepMetadataScan)
        {
            // A non-zero StartOffset resumes only the deep-metadata stage. The caller already
            // owns the candidates from completed stages, so do not return the directory scan's
            // candidates again when it combines this result with its persisted candidate index.
            // The directory walk above is still useful because it loads the allocation bitmap
            // used by recoverability scoring.
            if (options.StartOffset != 0)
            {
                _candidates.Clear();
                _candidateKeys.Clear();
            }
            await ScanDeepMetadataAsync(options.StartOffset, cancellationToken);
        }
        if (options.EvaluateRecoverability) await ScoreCandidatesAsync(cancellationToken);
        DeduplicateLogicalCandidates();
        _progress?.Report(new("exFAT 元数据扫描", 1, 1, _candidates.Count, $"找到 {_candidates.Count:N0} 个删除文件"));
        return new(_boot, _partitionOffset, _candidates.ToArray());
    }

    private void DeduplicateLogicalCandidates()
    {
        if (_candidates.Count < 2) return;
        var groups = new Dictionary<string, List<RecoveryCandidate>>(StringComparer.OrdinalIgnoreCase);
        var keyOrder = new List<string>();
        foreach (var candidate in _candidates)
        {
            // Different physical locations can be successive copies of the same logical file.
            // exFAT retains their deleted entry sets, so use the original path, exact length and
            // filesystem timestamp as the user-visible identity while preserving every physical
            // alternative for recovery fallback.
            var key = $"{candidate.OriginalPath}\0{candidate.Size}\0{candidate.ModifiedUtc?.Ticks ?? long.MinValue}";
            if (!groups.TryGetValue(key, out var group))
            {
                groups[key] = group = [];
                keyOrder.Add(key);
            }
            group.Add(candidate);
        }
        if (groups.Count == _candidates.Count) return;
        _candidates.Clear();
        foreach (var key in keyOrder)
        {
            var group = groups[key];
            var winner = group
                .OrderBy(candidate => QualityRank(candidate.Quality))
                .ThenBy(candidate => candidate.SourceOffset)
                .First();
            winner.AlternateCandidates = group.Where(candidate => !ReferenceEquals(candidate, winner)).ToArray();
            if (winner.AlternateCandidates.Count > 0)
                winner.QualityReason += $" 已合并 {group.Count:N0} 条同一文件的历史目录记录，并保留其余物理副本用于恢复失败时自动回退。";
            _candidates.Add(winner);
        }
    }

    private static int QualityRank(RecoveryQuality quality) => quality switch
    {
        RecoveryQuality.Excellent => 0,
        RecoveryQuality.Good => 1,
        RecoveryQuality.Partial => 2,
        RecoveryQuality.Unknown => 3,
        RecoveryQuality.Poor => 4,
        RecoveryQuality.Overwritten => 5,
        RecoveryQuality.TrimmedOrZeroed => 6,
        _ => 7
    };

    private async Task ScanDeepMetadataAsync(ulong startOffset, CancellationToken cancellationToken)
    {
        var volumeBytes = checked((ulong)_boot.ClusterCount * _boot.ClusterSize);
        var volumeEnd = checked(_clusterHeapOffset + volumeBytes);
        var resumeOffset = startOffset == 0 ? _clusterHeapOffset : startOffset;
        if (resumeOffset < _clusterHeapOffset || resumeOffset > volumeEnd)
            throw new ArgumentOutOfRangeException(nameof(startOffset), startOffset,
                $"The exFAT deep-scan resume offset must be between {_clusterHeapOffset:N0} and {volumeEnd:N0} bytes.");

        if (resumeOffset == volumeEnd)
        {
            _progress?.Report(new("exFAT 深度元数据扫描", volumeBytes, volumeBytes, _candidates.Count, "深度元数据扫描已完成",
                CheckpointPosition: volumeEnd, CheckpointTotal: volumeEnd));
            return;
        }

        // Re-read at most one full scanner block before the checkpoint so an entry set near a
        // block boundary has the same parsing context as an uninterrupted scan. Candidates from
        // this replay window are filtered against resumeOffset below.
        var relativeResume = resumeOffset - _clusterHeapOffset;
        var entryAlignedResume = relativeResume - relativeResume % ExFatDirectoryEntrySize;
        var processed = entryAlignedResume - entryAlignedResume % (ulong)DeepMetadataBlockSize;
        var buffer = new byte[DeepMetadataBlockSize + DeepMetadataOverlap];
        var seenOffsets = new HashSet<ulong>();
        var known = _candidates.Select(item => $"{item.Name}\0{item.Size}\0{item.SourceOffset}").ToHashSet(StringComparer.OrdinalIgnoreCase);
        var carry = 0;
        while (processed < volumeBytes)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var requested = checked((int)Math.Min((ulong)DeepMetadataBlockSize, volumeBytes - processed));
            var read = await _device.ReadAsync(checked(_clusterHeapOffset + processed), buffer.AsMemory(carry, requested), cancellationToken);
            if (read <= 0) break;
            var valid = carry + read;
            var baseOffset = checked(_clusterHeapOffset + processed - (ulong)carry);
            var nextCarry = Math.Min(DeepMetadataOverlap, valid);
            var physicalReadEnd = checked(processed + (ulong)read);
            var stableThrough = physicalReadEnd >= volumeBytes
                ? volumeEnd
                : checked(_clusterHeapOffset + physicalReadEnd - (ulong)nextCarry);
            for (var local = 0; local + 96 <= valid; local += 32)
            {
                var entryType = buffer[local];
                if ((entryType & 0x7F) != 0x05 || (entryType & 0x80) != 0) continue;
                var secondaryCount = buffer[local + 1];
                if (secondaryCount is < 2 or > 18) continue;
                var setLength = checked((secondaryCount + 1) * 32);
                if (local + setLength > valid) continue;
                var absoluteEntry = checked(baseOffset + (ulong)local);
                if (absoluteEntry < resumeOffset) continue;
                // Keep the overlap window pending until the next read. Otherwise a checkpoint
                // could advance past the primary entry of a set whose secondary entries have not
                // been read yet. On the final block every complete set is stable.
                if (absoluteEntry >= stableThrough) continue;
                if ((absoluteEntry - _clusterHeapOffset) % 32 != 0 || !seenOffsets.Add(absoluteEntry)) continue;
                var parsedEntry = ParseEntrySet(buffer, local, valid, requireExactNameEntryCount: true);
                if (parsedEntry is not { } parsed || parsed.IsDirectory) continue;
                var name = parsed.Name;
                var firstCluster = parsed.FirstCluster;
                var dataSize = parsed.DataSize;
                var noFat = parsed.NoFatChain;
                var modifiedUtc = parsed.ModifiedUtc;
                if (dataSize > checked((ulong)_boot.ClusterCount * _boot.ClusterSize) || (dataSize > 0 && !IsValidCluster(firstCluster))) continue;
                IReadOnlyList<DataExtent> extents = [];
                if (dataSize > 0)
                {
                    try { extents = await BuildExtentsAsync(firstCluster, dataSize, noFat, false, cancellationToken); }
                    catch (InvalidDataException) { extents = []; }
                }
                var sourceOffset = extents.Count > 0 ? ExtentPhysicalOffset(extents[0]) : absoluteEntry;
                var key = $"{name}\0{dataSize}\0{sourceOffset}";
                if (!known.Add(key)) continue;
                var candidate = new RecoveryCandidate
                {
                    RecordNumber = checked((long)(absoluteEntry / 32)), Name = name,
                    OriginalPath = Path.Combine("exFAT 深度扫描", name), Size = dataSize, IsDeleted = true,
                    Extents = extents, ModifiedUtc = modifiedUtc,
                    FileSystem = FileSystemKind.ExFat, Discovery = RecoveryDiscovery.ExFatDeepMetadata,
                    SourceOffset = sourceOffset, Quality = RecoveryQuality.Unknown,
                    QualityReason = "从exFAT簇区中发现通过条目组合、校验和及范围验证的残留删除记录。"
                };
                _candidates.Add(candidate);
                // Fully parsed candidates are published before the enclosing block's byte
                // checkpoint, allowing callers to persist the candidate index first.
                _deepCandidateProgress?.Report(candidate);
            }
            processed = physicalReadEnd;
            carry = nextCarry;
            buffer.AsSpan(valid - carry, carry).CopyTo(buffer);
            _progress?.Report(new("exFAT 深度元数据扫描", stableThrough - _clusterHeapOffset, volumeBytes, _candidates.Count,
                $"已安全检查 {(stableThrough - _clusterHeapOffset) / (1024 * 1024):N0} MiB",
                CheckpointPosition: stableThrough, CheckpointTotal: volumeEnd));
        }
    }

    internal void InitializeForRecovery(ExFatBootSector boot)
    {
        _boot = boot;
        _fatOffset = checked(_partitionOffset + ((ulong)_boot.FatOffsetSectors + (ulong)_boot.ActiveFat * _boot.FatLengthSectors) * _boot.BytesPerSector);
        _clusterHeapOffset = checked(_partitionOffset + (ulong)_boot.ClusterHeapOffsetSectors * _boot.BytesPerSector);
    }

    private async Task ScanDirectoryAsync(uint firstCluster, ulong? dataLength, bool noFatChain, string parentPath,
        bool includeActiveFiles, CancellationToken cancellationToken)
    {
        if (!IsValidCluster(firstCluster) || !_visitedDirectories.Add(firstCluster)) return;
        IReadOnlyList<DataExtent> extents;
        try { extents = await BuildExtentsAsync(firstCluster, dataLength, noFatChain, true, cancellationToken); }
        catch (InvalidDataException) { return; }
        var capacity = extents.Aggregate(0UL, (sum, extent) => checked(sum + (ulong)extent.ClusterCount * _boot.ClusterSize));
        var bytesToRead = Math.Min(dataLength ?? capacity, Math.Min(capacity, MaximumDirectoryBytes));
        if (bytesToRead == 0 || bytesToRead > int.MaxValue) return;
        const ulong totalDirectoryBudget = 1024UL * 1024 * 1024;
        if (_directoryBytesRead > totalDirectoryBudget - Math.Min(bytesToRead, totalDirectoryBudget)) return;
        _directoryBytesRead += bytesToRead;
        _progress?.Report(new("exFAT 目录遍历", _directoryBytesRead, totalDirectoryBudget, _candidates.Count,
            $"{(string.IsNullOrEmpty(parentPath) ? "根目录" : parentPath)} · {bytesToRead:N0} 字节"));
        var directory = new byte[checked((int)bytesToRead)];
        await ReadExtentsExactlyAsync(extents, 0, directory, cancellationToken);

        for (var offset = 0; offset + 32 <= directory.Length; offset += 32)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var entryType = directory[offset];
            if (entryType == 0) break;
            if ((entryType & 0x7F) == 0x01 && (entryType & 0x80) != 0 && parentPath.Length == 0)
            {
                if ((directory[offset + 1] & 1) != _boot.ActiveFat) continue;
                var first = BinaryPrimitives.ReadUInt32LittleEndian(directory.AsSpan(offset + 20, 4));
                var length = BinaryPrimitives.ReadUInt64LittleEndian(directory.AsSpan(offset + 24, 8));
                if (IsValidCluster(first) && length > 0)
                {
                    try { _allocationBitmap = (await BuildExtentsAsync(first, length, false, false, cancellationToken), length); }
                    catch (InvalidDataException) { }
                }
                continue;
            }
            if ((entryType & 0x7F) != 0x05) continue;
            var secondaryCount = directory[offset + 1];
            var setLength = checked((secondaryCount + 1) * 32);
            if (secondaryCount < 2 || offset + setLength > directory.Length) continue;
            var parsedEntry = ParseEntrySet(directory, offset, directory.Length, requireExactNameEntryCount: false);
            if (parsedEntry is not { } parsed) continue;
            var deleted = parsed.Deleted;
            var name = parsed.Name;
            var isDirectory = parsed.IsDirectory;
            var firstDataCluster = parsed.FirstCluster;
            var dataSize = parsed.DataSize;
            var noFat = parsed.NoFatChain;
            var modifiedUtc = parsed.ModifiedUtc;
            var maximumVolumeData = checked((ulong)_boot.ClusterCount * _boot.ClusterSize);
            if (dataSize > maximumVolumeData || (isDirectory && dataSize > MaximumDirectoryBytes)) continue;
            if (dataSize > 0 && !IsValidCluster(firstDataCluster)) continue;
            IReadOnlyList<DataExtent> fileExtents = [];
            if (dataSize > 0)
            {
                try { fileExtents = await BuildExtentsAsync(firstDataCluster, dataSize, noFat, isDirectory, cancellationToken); }
                catch (InvalidDataException) when (!isDirectory) { fileExtents = []; }
                catch (InvalidDataException) { continue; }
            }
            var fullPath = string.IsNullOrEmpty(parentPath) ? name : Path.Combine(parentPath, name);
            if (isDirectory)
            {
                if (dataSize > 0)
                    await ScanDirectoryAsync(firstDataCluster, dataSize, noFat, fullPath, includeActiveFiles, cancellationToken);
                continue;
            }
            if (!deleted && !includeActiveFiles) continue;
            var storageOffset = checked(_partitionOffset + (ulong)offset);
            var sourceOffset = fileExtents.Count > 0 ? ExtentPhysicalOffset(fileExtents[0]) : storageOffset;
            // exFAT can retain several valid deleted entry sets for the same file after repeated
            // copy/delete cycles. They are metadata history, not separate recoverable payloads.
            // Keep distinct files that merely share a name, but collapse records that resolve to
            // the same path, length and physical data location.
            var candidateKey = $"{fullPath}\0{dataSize}\0{sourceOffset}";
            if (!_candidateKeys.Add(candidateKey))
            {
                offset += setLength - 32;
                continue;
            }
            _candidates.Add(new RecoveryCandidate
            {
                RecordNumber = checked((long)(storageOffset / 32)),
                Name = name,
                OriginalPath = fullPath,
                Size = dataSize,
                IsDeleted = deleted,
                IsResident = false,
                Extents = fileExtents,
                ModifiedUtc = modifiedUtc,
                FileSystem = FileSystemKind.ExFat,
                Discovery = RecoveryDiscovery.ExFatMetadata,
                SourceOffset = sourceOffset,
                Quality = RecoveryQuality.Unknown,
                QualityReason = noFat ? "exFAT directory metadata reports a contiguous allocation." : "exFAT directory metadata reports a FAT cluster chain."
            });
            _progress?.Report(new("exFAT 元数据扫描", checked((ulong)offset), checked((ulong)directory.Length), _candidates.Count, fullPath));
            offset += setLength - 32;
        }
    }

    private async Task<IReadOnlyList<DataExtent>> BuildExtentsAsync(uint firstCluster, ulong? dataLength, bool noFatChain,
        bool directory, CancellationToken cancellationToken)
    {
        if (!IsValidCluster(firstCluster)) throw new InvalidDataException("Invalid exFAT first cluster.");
        var neededClusters = dataLength.HasValue ? checked((dataLength.Value + _boot.ClusterSize - 1) / _boot.ClusterSize) : 0;
        if (noFatChain)
        {
            if (!dataLength.HasValue || neededClusters == 0 || firstCluster - 2 + neededClusters > _boot.ClusterCount)
                throw new InvalidDataException("Invalid contiguous exFAT allocation.");
            return [new((long)firstCluster - 2, checked((long)neededClusters))];
        }

        var clusters = new List<uint>();
        var seen = new HashSet<uint>();
        var current = firstCluster;
        var maximum = dataLength.HasValue ? Math.Max(neededClusters, 1) : Math.Min((ulong)_boot.ClusterCount, MaximumDirectoryBytes / _boot.ClusterSize + 1);
        while (IsValidCluster(current) && seen.Add(current) && (ulong)clusters.Count < maximum)
        {
            clusters.Add(current);
            if (dataLength.HasValue && (ulong)clusters.Count >= neededClusters) break;
            var next = await ReadFatEntryAsync(current, cancellationToken);
            if (next == uint.MaxValue || next >= 0xFFFFFFF8) break;
            if (!IsValidCluster(next))
            {
                if (!directory && dataLength.HasValue && (ulong)clusters.Count < neededClusters)
                    throw new InvalidDataException("The deleted exFAT FAT chain is no longer available.");
                break;
            }
            current = next;
        }
        if (clusters.Count == 0 || (dataLength.HasValue && (ulong)clusters.Count < neededClusters))
            throw new InvalidDataException("The exFAT cluster chain is incomplete.");
        return CompressClusters(clusters);
    }

    private async Task<uint> ReadFatEntryAsync(uint cluster, CancellationToken cancellationToken)
    {
        var bytes = new byte[4];
        await _device.ReadExactlyAsync(checked(_fatOffset + (ulong)cluster * 4), bytes, cancellationToken);
        return BinaryPrimitives.ReadUInt32LittleEndian(bytes);
    }

    private static IReadOnlyList<DataExtent> CompressClusters(IReadOnlyList<uint> clusters)
    {
        var extents = new List<DataExtent>();
        var start = clusters[0];
        var count = 1u;
        for (var i = 1; i < clusters.Count; i++)
        {
            if (clusters[i] == start + count) { count++; continue; }
            extents.Add(new((long)start - 2, count));
            start = clusters[i];
            count = 1;
        }
        extents.Add(new((long)start - 2, count));
        return extents;
    }

    private async Task ScoreCandidatesAsync(CancellationToken cancellationToken)
    {
        foreach (var candidate in _candidates)
        {
            try { await ScoreCandidateAsync(candidate, cancellationToken); }
            catch (IOException ex)
            {
                candidate.Quality = RecoveryQuality.Unknown;
                candidate.QualityReason = $"The exFAT metadata was parsed, but the device stopped responding during quality checks: {ex.Message}";
                break;
            }
        }
    }

    private async Task ScoreCandidateAsync(RecoveryCandidate candidate, CancellationToken cancellationToken)
    {
        if (candidate.Size == 0)
        {
            candidate.Quality = RecoveryQuality.Good;
            candidate.QualityReason = "The deleted exFAT entry describes an empty file.";
            return;
        }
        if (candidate.Extents.Count == 0)
        {
            candidate.Quality = RecoveryQuality.Poor;
            candidate.QualityReason = "The original exFAT file name and size remain, but its FAT cluster chain is no longer available.";
            return;
        }
        var overwritten = false;
        if (_allocationBitmap is { } bitmap)
        {
            foreach (var extent in candidate.Extents)
            {
                if (await IsAnyBitmapClusterAllocatedAsync(bitmap, checked((ulong)extent.LogicalCluster),
                    checked((ulong)extent.ClusterCount), cancellationToken)) overwritten = true;
                if (overwritten) break;
            }
        }
        if (overwritten)
        {
            candidate.Quality = RecoveryQuality.Overwritten;
            candidate.QualityReason = "One or more original exFAT clusters are currently allocated to another file.";
            return;
        }
        var sampleLength = checked((int)Math.Min(candidate.Size, 64UL * 1024));
        var sample = new byte[sampleLength];
        await ReadExtentsExactlyAsync(candidate.Extents, 0, sample, cancellationToken);
        if (sample.Length > 0 && sample.AsSpan().IndexOfAnyExcept((byte)0) < 0)
        {
            candidate.Quality = RecoveryQuality.TrimmedOrZeroed;
            candidate.QualityReason = "The exFAT metadata remains, but the original data area reads as all zeroes.";
        }
        else
        {
            candidate.Quality = RecoveryQuality.Good;
            candidate.QualityReason = _allocationBitmap is null
                ? "The exFAT metadata and allocation are readable; no allocation bitmap was available for reuse checks."
                : "The exFAT metadata is intact and all original clusters are currently free.";
        }
    }

    private async Task<bool> IsAnyBitmapClusterAllocatedAsync((IReadOnlyList<DataExtent> Extents, ulong Length) bitmap,
        ulong firstZeroBasedCluster, ulong clusterCount, CancellationToken cancellationToken)
    {
        const int pageBytes = 64 * 1024;
        var page = new byte[pageBytes + 1];
        var current = firstZeroBasedCluster;
        var remaining = clusterCount;
        while (remaining > 0)
        {
            var firstBit = checked((int)(current % 8));
            var bits = Math.Min(remaining, checked((ulong)pageBytes * 8 - (ulong)firstBit));
            var byteIndex = current / 8;
            var byteCount = checked((int)(((ulong)firstBit + bits + 7) / 8));
            if (byteIndex + (ulong)byteCount > bitmap.Length) return true;
            await ReadExtentsExactlyAsync(bitmap.Extents, byteIndex, page.AsMemory(0, byteCount), cancellationToken);
            var lastUsedBits = checked((int)(((ulong)firstBit + bits) % 8));
            for (var index = 0; index < byteCount; index++)
            {
                var mask = 0xFF;
                if (index == 0) mask &= 0xFF << firstBit;
                if (index == byteCount - 1 && lastUsedBits != 0) mask &= (1 << lastUsedBits) - 1;
                if ((page[index] & mask) != 0) return true;
            }
            current += bits;
            remaining -= bits;
        }
        return false;
    }

    internal async Task ReadExtentsExactlyAsync(IReadOnlyList<DataExtent> extents, ulong logicalOffset, Memory<byte> destination,
        CancellationToken cancellationToken)
    {
        var remaining = destination;
        var skip = logicalOffset;
        foreach (var extent in extents)
        {
            var extentBytes = checked((ulong)extent.ClusterCount * _boot.ClusterSize);
            if (skip >= extentBytes) { skip -= extentBytes; continue; }
            var within = skip;
            var take = checked((int)Math.Min((ulong)remaining.Length, extentBytes - within));
            await _device.ReadExactlyAsync(checked(ExtentPhysicalOffset(extent) + within), remaining[..take], cancellationToken);
            remaining = remaining[take..];
            skip = 0;
            if (remaining.IsEmpty) return;
        }
        throw new EndOfStreamException("The exFAT allocation is shorter than the requested data.");
    }

    private ulong ExtentPhysicalOffset(DataExtent extent) => checked(_clusterHeapOffset + (ulong)extent.LogicalCluster * _boot.ClusterSize);
    private bool IsValidCluster(uint cluster) => cluster >= 2 && cluster < _boot.ClusterCount + 2;

    private static bool ValidateEntrySetChecksum(ReadOnlySpan<byte> set, bool deleted)
    {
        var expected = BinaryPrimitives.ReadUInt16LittleEndian(set.Slice(2, 2));
        return ComputeEntrySetChecksum(set, deleted) == expected || (deleted && ComputeEntrySetChecksum(set, false) == expected);
    }

    private static ParsedEntrySet? ParseEntrySet(byte[] source, int offset, int availableLength,
        bool requireExactNameEntryCount)
    {
        if (offset < 0 || offset + 32 > availableLength || availableLength > source.Length) return null;
        var entryType = source[offset];
        if ((entryType & 0x7F) != 0x05) return null;
        var secondaryCount = source[offset + 1];
        var setLength = checked((secondaryCount + 1) * 32);
        if (secondaryCount < 2 || offset + setLength > availableLength) return null;

        var set = source.AsSpan(offset, setLength);
        var deleted = (entryType & 0x80) == 0;
        if (!ValidateEntrySetChecksum(set, deleted)) return null;
        var stream = set.Slice(32, 32);
        if ((stream[0] & 0x7F) != 0x40) return null;
        var nameLength = stream[3];
        var requiredNames = (nameLength + 14) / 15;
        if (nameLength is < 1 or > 255 ||
            (requireExactNameEntryCount ? secondaryCount != 1 + requiredNames : secondaryCount < 1 + requiredNames))
            return null;

        var nameBuilder = new StringBuilder(requiredNames * 15);
        for (var n = 0; n < requiredNames; n++)
        {
            var nameEntry = set.Slice(64 + n * 32, 32);
            if ((nameEntry[0] & 0x7F) != 0x41) return null;
            nameBuilder.Append(Encoding.Unicode.GetString(nameEntry.Slice(2, 30)));
        }
        if (nameBuilder.Length < nameLength) return null;
        var name = nameBuilder.ToString(0, nameLength);
        if (string.IsNullOrWhiteSpace(name) || name.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0) return null;

        var attributes = BinaryPrimitives.ReadUInt16LittleEndian(set.Slice(4, 2));
        return new(
            name,
            deleted,
            (attributes & 0x10) != 0,
            BinaryPrimitives.ReadUInt32LittleEndian(stream.Slice(20, 4)),
            BinaryPrimitives.ReadUInt64LittleEndian(stream.Slice(24, 8)),
            (stream[1] & 0x02) != 0,
            ParseTimestamp(set.Slice(12, 4), set[21], set[23]),
            setLength);
    }

    private readonly record struct ParsedEntrySet(
        string Name,
        bool Deleted,
        bool IsDirectory,
        uint FirstCluster,
        ulong DataSize,
        bool NoFatChain,
        DateTime? ModifiedUtc,
        int SetLength);

    private static ushort ComputeEntrySetChecksum(ReadOnlySpan<byte> set, bool restoreInUseBits)
    {
        ushort checksum = 0;
        for (var index = 0; index < set.Length; index++)
        {
            if (index is 2 or 3) continue;
            var value = set[index];
            if (restoreInUseBits && index % 32 == 0) value |= 0x80;
            checksum = (ushort)(((checksum & 1) != 0 ? 0x8000 : 0) + (checksum >> 1) + value);
        }
        return checksum;
    }

    private static DateTime? ParseTimestamp(ReadOnlySpan<byte> timestampBytes, byte tenMilliseconds, byte utcOffset)
    {
        var value = BinaryPrimitives.ReadUInt32LittleEndian(timestampBytes);
        var second = checked((int)(value & 0x1F) * 2 + Math.Min(tenMilliseconds, (byte)199) / 100);
        var minute = checked((int)((value >> 5) & 0x3F));
        var hour = checked((int)((value >> 11) & 0x1F));
        var day = checked((int)((value >> 16) & 0x1F));
        var month = checked((int)((value >> 21) & 0x0F));
        var year = checked((int)((value >> 25) & 0x7F) + 1980);
        try
        {
            var local = new DateTime(year, month, day, hour, minute, Math.Min(second, 59), DateTimeKind.Unspecified);
            if ((utcOffset & 0x80) == 0) return local;
            var signedOffset = unchecked((sbyte)(utcOffset << 1)) >> 1;
            return new DateTimeOffset(local, TimeSpan.FromMinutes(signedOffset * 15)).UtcDateTime;
        }
        catch (ArgumentOutOfRangeException) { return null; }
    }
}

public static partial class RecoveryWriter
{
    public static async Task<RecoveryResult> RecoverExFatAsync(IBlockDevice source, ExFatScanResult scan,
        RecoveryCandidate candidate, string destinationRoot, IProgress<ScanProgress>? progress = null,
        CancellationToken cancellationToken = default)
    {
        if (candidate.FileSystem != FileSystemKind.ExFat || !candidate.IsDeleted)
            throw new InvalidOperationException("Only deleted exFAT metadata candidates can be recovered by this operation.");
        if (candidate.Size > 0 && candidate.Extents.Count == 0)
            throw new InvalidOperationException("The original file name remains, but the deleted exFAT FAT chain is unavailable, so this candidate cannot be recovered reliably.");
        var root = Path.GetFullPath(destinationRoot);
        Directory.CreateDirectory(root);
        var relative = string.IsNullOrWhiteSpace(candidate.OriginalPath) ? candidate.Name : candidate.OriginalPath;
        var components = relative.Split([Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar], StringSplitOptions.RemoveEmptyEntries)
            .Where(component => component is not "." and not "..")
            .Select(NtfsScanner.SanitizePathComponent).ToArray();
        var output = EnsureUniqueExFatPath(Path.Combine(root, Path.Combine(components)));
        Directory.CreateDirectory(Path.GetDirectoryName(output)!);
        await using var file = new FileStream(output, FileMode.CreateNew, FileAccess.Write, FileShare.None, 1024 * 1024,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var buffer = new byte[1024 * 1024];
        var scanner = new ExFatScanner(source, scan.PartitionOffset);
        scanner.InitializeForRecovery(scan.Boot);
        ulong written = 0;
        while (written < candidate.Size)
        {
            var count = checked((int)Math.Min((ulong)buffer.Length, candidate.Size - written));
            await scanner.ReadExtentsExactlyAsync(candidate.Extents, written, buffer.AsMemory(0, count), cancellationToken);
            await file.WriteAsync(buffer.AsMemory(0, count), cancellationToken);
            hash.AppendData(buffer.AsSpan(0, count));
            written += checked((ulong)count);
            progress?.Report(new("正在恢复 exFAT 文件", written, candidate.Size, 1, candidate.Name));
        }
        await file.FlushAsync(cancellationToken);
        var digest = Convert.ToHexString(hash.GetHashAndReset()).ToLowerInvariant();
        await file.DisposeAsync();
        return await FinalizeResultAsync(output, written, digest, written == candidate.Size, cancellationToken);
    }

    private static string EnsureUniqueExFatPath(string path)
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
        throw new IOException("Unable to allocate a unique exFAT recovery path.");
    }
}
