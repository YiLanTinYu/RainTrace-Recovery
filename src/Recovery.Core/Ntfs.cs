using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace Recovery.Core;

public sealed record NtfsBootSector(
    ushort BytesPerSector,
    byte SectorsPerCluster,
    uint ClusterSize,
    ulong TotalSectors,
    long MftLcn,
    long MftMirrorLcn,
    uint FileRecordSize,
    uint IndexRecordSize)
{
    public static NtfsBootSector Parse(ReadOnlySpan<byte> data)
    {
        if (data.Length < 512 || !data.Slice(3, 8).SequenceEqual("NTFS    "u8))
            throw new InvalidDataException("The selected partition is not NTFS.");
        var bytesPerSector = BinaryPrimitives.ReadUInt16LittleEndian(data[11..13]);
        var sectorsPerCluster = data[13];
        if (!IsPowerOfTwo(bytesPerSector) || bytesPerSector < 512 || !IsPowerOfTwo(sectorsPerCluster))
            throw new InvalidDataException("Invalid NTFS sector or cluster geometry.");
        var clusterSize = checked((uint)bytesPerSector * sectorsPerCluster);
        var totalSectors = BinaryPrimitives.ReadUInt64LittleEndian(data[40..48]);
        var mftLcn = BinaryPrimitives.ReadInt64LittleEndian(data[48..56]);
        var mirrorLcn = BinaryPrimitives.ReadInt64LittleEndian(data[56..64]);
        var recordSize = DecodeRecordSize(unchecked((sbyte)data[64]), clusterSize);
        var indexSize = DecodeRecordSize(unchecked((sbyte)data[68]), clusterSize);
        // A valid NTFS volume can use 1 KiB FILE records on a native 4 KiB
        // logical-sector device. FILE record size is independent of the BPB
        // sector size and only needs to be a supported power of two.
        if (recordSize is < 512 or > 65536 || !IsPowerOfTwo(recordSize))
            throw new InvalidDataException("Unsupported NTFS file record size.");
        return new(bytesPerSector, sectorsPerCluster, clusterSize, totalSectors, mftLcn, mirrorLcn, recordSize, indexSize);
    }

    private static uint DecodeRecordSize(sbyte encoded, uint clusterSize) => encoded < 0
        ? checked(1u << -encoded)
        : checked((uint)encoded * clusterSize);

    private static bool IsPowerOfTwo(uint value) => value != 0 && (value & (value - 1)) == 0;
}

internal sealed record NtfsFileName(string Name, long ParentRecord, byte Namespace, DateTime? ModifiedUtc);
internal sealed record NtfsDataAttribute(bool Resident, byte[]? ResidentData, IReadOnlyList<DataExtent> Extents, ulong RealSize, bool Sparse, string? Name);

internal sealed class NtfsRecord
{
    public long Number { get; init; }
    public ushort Sequence { get; init; }
    public bool InUse { get; init; }
    public bool IsDirectory { get; init; }
    public IReadOnlyList<NtfsFileName> Names { get; init; } = [];
    public IReadOnlyList<NtfsDataAttribute> DataAttributes { get; init; } = [];

    public NtfsFileName? PreferredName => Names
        .OrderBy(n => n.Namespace == 2 ? 1 : 0)
        .FirstOrDefault(n => n.Name is not "." and not "..");

    public NtfsDataAttribute? DefaultData => DataAttributes.FirstOrDefault(a => string.IsNullOrEmpty(a.Name));
}

internal static class NtfsRecordParser
{
    private const uint AttributeFileName = 0x30;
    private const uint AttributeData = 0x80;
    private const uint AttributeEnd = 0xFFFFFFFF;

    public static NtfsRecord? Parse(ReadOnlySpan<byte> raw, long fallbackNumber, ushort bytesPerSector)
    {
        if (raw.Length < 64 || !raw[..4].SequenceEqual("FILE"u8)) return null;
        var record = raw.ToArray();
        if (!ApplyFixup(record, bytesPerSector)) return null;
        var sequence = BinaryPrimitives.ReadUInt16LittleEndian(record.AsSpan(16, 2));
        var firstAttribute = checked((int)BinaryPrimitives.ReadUInt16LittleEndian(record.AsSpan(20, 2)));
        var flags = BinaryPrimitives.ReadUInt16LittleEndian(record.AsSpan(22, 2));
        var usedSize = BinaryPrimitives.ReadUInt32LittleEndian(record.AsSpan(24, 4));
        var recordNumber = record.Length >= 48 ? BinaryPrimitives.ReadUInt32LittleEndian(record.AsSpan(44, 4)) : 0;
        if (recordNumber == 0 && fallbackNumber != 0) recordNumber = checked((uint)fallbackNumber);
        if (firstAttribute < 24 || firstAttribute >= record.Length) return null;
        var limit = Math.Min(record.Length, checked((int)usedSize));
        var names = new List<NtfsFileName>();
        var dataAttributes = new List<NtfsDataAttribute>();

        for (var offset = firstAttribute; offset + 16 <= limit;)
        {
            var type = BinaryPrimitives.ReadUInt32LittleEndian(record.AsSpan(offset, 4));
            if (type == AttributeEnd) break;
            var length = BinaryPrimitives.ReadUInt32LittleEndian(record.AsSpan(offset + 4, 4));
            if (length < 24 || offset + length > limit) break;
            var nonResident = record[offset + 8] != 0;
            var nameLength = record[offset + 9];
            var nameOffset = BinaryPrimitives.ReadUInt16LittleEndian(record.AsSpan(offset + 10, 2));
            string? attributeName = null;
            if (nameLength > 0 && nameOffset >= 16 && nameOffset + nameLength * 2 <= length)
                attributeName = Encoding.Unicode.GetString(record, offset + nameOffset, nameLength * 2);

            if (type == AttributeFileName && !nonResident)
            {
                var valueLength = BinaryPrimitives.ReadUInt32LittleEndian(record.AsSpan(offset + 16, 4));
                var valueOffset = BinaryPrimitives.ReadUInt16LittleEndian(record.AsSpan(offset + 20, 2));
                if (valueLength >= 66 && valueOffset + valueLength <= length)
                {
                    var value = record.AsSpan(offset + valueOffset, checked((int)valueLength));
                    var parentRef = ReadFileReference(value[..8]);
                    var modified = ReadFileTime(value[16..24]);
                    var fileNameLength = value[64];
                    var fileNamespace = value[65];
                    if (66 + fileNameLength * 2 <= value.Length)
                    {
                        var name = Encoding.Unicode.GetString(value.Slice(66, fileNameLength * 2));
                        if (!string.IsNullOrWhiteSpace(name)) names.Add(new(name, parentRef, fileNamespace, modified));
                    }
                }
            }
            else if (type == AttributeData)
            {
                if (!nonResident)
                {
                    var valueLength = BinaryPrimitives.ReadUInt32LittleEndian(record.AsSpan(offset + 16, 4));
                    var valueOffset = BinaryPrimitives.ReadUInt16LittleEndian(record.AsSpan(offset + 20, 2));
                    if (valueOffset + valueLength <= length)
                    {
                        var value = record.AsSpan(offset + valueOffset, checked((int)valueLength)).ToArray();
                        dataAttributes.Add(new(true, value, [], valueLength, false, attributeName));
                    }
                }
                else if (length >= 64)
                {
                    var runOffset = BinaryPrimitives.ReadUInt16LittleEndian(record.AsSpan(offset + 32, 2));
                    var realSize = BinaryPrimitives.ReadUInt64LittleEndian(record.AsSpan(offset + 48, 8));
                    if (runOffset < length)
                    {
                        var extents = ParseRunList(record.AsSpan(offset + runOffset, checked((int)length - runOffset)));
                        dataAttributes.Add(new(false, null, extents, realSize, extents.Any(e => e.Sparse), attributeName));
                    }
                }
            }
            offset += checked((int)length);
        }

        return new NtfsRecord
        {
            Number = recordNumber,
            Sequence = sequence,
            InUse = (flags & 0x0001) != 0,
            IsDirectory = (flags & 0x0002) != 0,
            Names = names,
            DataAttributes = dataAttributes
        };
    }

    private static bool ApplyFixup(Span<byte> record, ushort bytesPerSector)
    {
        var usaOffset = BinaryPrimitives.ReadUInt16LittleEndian(record[4..6]);
        var usaCount = BinaryPrimitives.ReadUInt16LittleEndian(record[6..8]);
        if (usaCount < 2 || usaOffset + usaCount * 2 > record.Length) return false;
        var protectedBlocks = usaCount - 1;
        if (record.Length % protectedBlocks != 0) return false;
        var fixupBlockSize = record.Length / protectedBlocks;
        // Windows uses 512-byte USA boundaries for 1 KiB FILE records even
        // when the NTFS BPB reports a 4 KiB logical sector. Derive the actual
        // boundary from the record and USA count, while keeping strict bounds.
        if (fixupBlockSize < 512 || fixupBlockSize > bytesPerSector ||
            (fixupBlockSize & (fixupBlockSize - 1)) != 0) return false;
        var updateSequence = BinaryPrimitives.ReadUInt16LittleEndian(record.Slice(usaOffset, 2));
        for (var i = 1; i < usaCount; i++)
        {
            var sectorEnd = i * fixupBlockSize - 2;
            if (sectorEnd + 2 > record.Length || BinaryPrimitives.ReadUInt16LittleEndian(record.Slice(sectorEnd, 2)) != updateSequence)
                return false;
            record.Slice(usaOffset + i * 2, 2).CopyTo(record.Slice(sectorEnd, 2));
        }
        return true;
    }

    private static long ReadFileReference(ReadOnlySpan<byte> value)
    {
        ulong raw = 0;
        for (var i = 0; i < 6; i++) raw |= (ulong)value[i] << (i * 8);
        return checked((long)raw);
    }

    private static DateTime? ReadFileTime(ReadOnlySpan<byte> value)
    {
        var raw = BinaryPrimitives.ReadInt64LittleEndian(value);
        if (raw <= 0) return null;
        try { return DateTime.FromFileTimeUtc(raw); }
        catch (ArgumentOutOfRangeException) { return null; }
    }

    internal static IReadOnlyList<DataExtent> ParseRunList(ReadOnlySpan<byte> runs)
    {
        var result = new List<DataExtent>();
        long currentLcn = 0;
        for (var index = 0; index < runs.Length;)
        {
            var header = runs[index++];
            if (header == 0) break;
            var lengthBytes = header & 0x0F;
            var offsetBytes = header >> 4;
            if (lengthBytes is 0 or > 8 || offsetBytes > 8 || index + lengthBytes + offsetBytes > runs.Length)
                throw new InvalidDataException("Invalid NTFS runlist.");
            ulong count = 0;
            for (var i = 0; i < lengthBytes; i++) count |= (ulong)runs[index + i] << (i * 8);
            index += lengthBytes;
            if (count == 0 || count > long.MaxValue) throw new InvalidDataException("Invalid NTFS run length.");
            if (offsetBytes == 0)
            {
                result.Add(new(0, checked((long)count), true));
                continue;
            }
            long delta = 0;
            for (var i = 0; i < offsetBytes; i++) delta |= (long)runs[index + i] << (i * 8);
            if ((runs[index + offsetBytes - 1] & 0x80) != 0 && offsetBytes < 8) delta |= -1L << (offsetBytes * 8);
            index += offsetBytes;
            currentLcn = checked(currentLcn + delta);
            if (currentLcn < 0) throw new InvalidDataException("Negative NTFS LCN.");
            result.Add(new(currentLcn, checked((long)count), false));
        }
        return result;
    }
}

internal static class NtfsExtentReader
{
    public static async ValueTask ReadExactlyAsync(IBlockDevice device, ulong partitionOffset, uint clusterSize, IReadOnlyList<DataExtent> extents, ulong fileOffset, Memory<byte> output, CancellationToken cancellationToken)
    {
        var remaining = output;
        ulong streamPosition = 0;
        foreach (var extent in extents)
        {
            var extentBytes = checked((ulong)extent.ClusterCount * clusterSize);
            if (fileOffset >= streamPosition + extentBytes)
            {
                streamPosition += extentBytes;
                continue;
            }
            var within = fileOffset > streamPosition ? fileOffset - streamPosition : 0;
            var available = extentBytes - within;
            var take = checked((int)Math.Min((ulong)remaining.Length, available));
            if (extent.Sparse) remaining.Span[..take].Clear();
            else
            {
                var physical = checked(partitionOffset + (ulong)extent.LogicalCluster * clusterSize + within);
                await device.ReadExactlyAsync(physical, remaining[..take], cancellationToken);
            }
            remaining = remaining[take..];
            fileOffset += checked((ulong)take);
            streamPosition += extentBytes;
            if (remaining.IsEmpty) return;
        }
        if (!remaining.IsEmpty) throw new EndOfStreamException("NTFS attribute runlist ended before the requested data.");
    }
}

public sealed class NtfsScanResult
{
    internal NtfsScanResult(NtfsBootSector boot, ulong partitionOffset, IReadOnlyList<DataExtent> mftExtents, IReadOnlyList<RecoveryCandidate> candidates,
        ulong currentMftRecords, ulong parsedCurrentMftRecords, ulong deepRecordsExamined, ulong parsedDeepRecords)
    {
        Boot = boot;
        PartitionOffset = partitionOffset;
        MftExtents = mftExtents;
        Candidates = candidates;
        CurrentMftRecords = currentMftRecords;
        ParsedCurrentMftRecords = parsedCurrentMftRecords;
        DeepRecordsExamined = deepRecordsExamined;
        ParsedDeepRecords = parsedDeepRecords;
    }
    public NtfsBootSector Boot { get; }
    public ulong PartitionOffset { get; }
    internal IReadOnlyList<DataExtent> MftExtents { get; }
    public IReadOnlyList<RecoveryCandidate> Candidates { get; }
    public ulong CurrentMftRecords { get; }
    public ulong ParsedCurrentMftRecords { get; }
    public ulong DeepRecordsExamined { get; }
    public ulong ParsedDeepRecords { get; }

    public static NtfsScanResult CreateRecoveryContext(NtfsBootSector boot, ulong partitionOffset) =>
        new(boot, partitionOffset, [], [], 0, 0, 0, 0);
}

public sealed class NtfsScanner
{
    private readonly IBlockDevice _device;
    private readonly ulong _partitionOffset;
    private readonly IProgress<ScanProgress>? _progress;
    private readonly ulong? _bootSectorOffset;
    private readonly Action<RecoveryCandidate>? _candidateAvailable;

    public NtfsScanner(
        IBlockDevice device,
        ulong partitionOffset,
        IProgress<ScanProgress>? progress = null,
        ulong? bootSectorOffset = null)
        : this(device, partitionOffset, progress, bootSectorOffset, null)
    {
    }

    public NtfsScanner(
        IBlockDevice device,
        ulong partitionOffset,
        IProgress<ScanProgress>? progress,
        ulong? bootSectorOffset,
        Action<RecoveryCandidate>? candidateAvailable)
    {
        _device = device;
        _partitionOffset = partitionOffset;
        _progress = progress;
        _bootSectorOffset = bootSectorOffset;
        _candidateAvailable = candidateAvailable;
    }

    public async Task<NtfsScanResult> ScanAsync(ScanOptions options, CancellationToken cancellationToken = default)
    {
        var bootBytes = new byte[512];
        await _device.ReadExactlyAsync(_bootSectorOffset ?? _partitionOffset, bootBytes, cancellationToken);
        var boot = NtfsBootSector.Parse(bootBytes);
        var mftRecordZero = await ReadMftRecordZeroAsync(boot, cancellationToken);
        var firstMftOffset = mftRecordZero.FirstMftOffset;
        var mftData = mftRecordZero.Data;
        var recordCount = Math.Min(mftData.RealSize / boot.FileRecordSize, 100_000_000UL);
        var directories = new Dictionary<long, (string Name, long Parent)> { [5] = (string.Empty, 5) };
        var candidates = new List<RecoveryCandidate>();
        var recordBuffer = new byte[boot.FileRecordSize];
        ulong parsedCurrentRecords = 0;

        for (ulong index = 0; index < recordCount; index++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            await NtfsExtentReader.ReadExactlyAsync(_device, _partitionOffset, boot.ClusterSize, mftData.Extents, index * boot.FileRecordSize, recordBuffer, cancellationToken);
            var record = NtfsRecordParser.Parse(recordBuffer, checked((long)index), boot.BytesPerSector);
            if (record is null) continue;
            parsedCurrentRecords++;
            var name = record.PreferredName;
            if (record.IsDirectory && name is not null) directories[record.Number] = (name.Name, name.ParentRecord);
            if ((!record.InUse || options.IncludeActiveFiles) && name is not null && !record.IsDirectory)
            {
                candidates.Add(CreateCandidate(record, name, boot, firstMftOffset + index * boot.FileRecordSize,
                    !record.InUse, RecoveryDiscovery.NtfsCurrentMft));
            }
            if ((index & 0x3FF) == 0)
                _progress?.Report(new("Scanning NTFS MFT", index, recordCount, candidates.Count, $"MFT record {index:N0} of {recordCount:N0}"));
        }

        foreach (var candidate in candidates)
            candidate.OriginalPath = BuildPath(candidate.ParentRecordNumber, candidate.Name, directories);

        ulong deepRecordsExamined = 0;
        ulong parsedDeepRecords = 0;
        if (options.FullDiskMetadataScan)
        {
            var deep = await ScanWholeVolumeForMftAsync(
                boot,
                mftData.Extents,
                mftData.RealSize,
                directories,
                candidates,
                options.StartOffset,
                cancellationToken);
            deepRecordsExamined = deep.Examined;
            parsedDeepRecords = deep.Parsed;
        }
        else if (options.DeepMetadataScan && options.DeepMetadataBytes > 0)
        {
            var deep = await ScanDeepMftAsync(
                boot,
                mftData.RealSize,
                firstMftOffset,
                directories,
                candidates,
                options.DeepMetadataBytes,
                options.StartOffset,
                cancellationToken);
            deepRecordsExamined = deep.Examined;
            parsedDeepRecords = deep.Parsed;
        }

        NtfsBitmapAccessor? bitmap = null;
        try
        {
            var bitmapRecordBytes = new byte[boot.FileRecordSize];
            await NtfsExtentReader.ReadExactlyAsync(_device, _partitionOffset, boot.ClusterSize, mftData.Extents, 6UL * boot.FileRecordSize, bitmapRecordBytes, cancellationToken);
            var bitmapRecord = NtfsRecordParser.Parse(bitmapRecordBytes, 6, boot.BytesPerSector);
            var bitmapData = bitmapRecord?.DefaultData;
            if (bitmapData is { Resident: false, Extents.Count: > 0 })
                bitmap = new(_device, _partitionOffset, boot.ClusterSize, bitmapData.Extents, bitmapData.RealSize);
        }
        catch (Exception ex) when (ex is InvalidDataException or EndOfStreamException)
        {
            bitmap = null;
        }

        for (var i = 0; i < candidates.Count; i++)
        {
            try { await ScoreAsync(candidates[i], boot, bitmap, cancellationToken); }
            catch (Exception ex) when (ex is IOException or InvalidDataException or EndOfStreamException or OverflowException)
            {
                candidates[i].Quality = RecoveryQuality.Poor;
                candidates[i].QualityReason = $"候选元数据有效，但读取原数据簇失败：{ex.Message}";
            }
            if ((i & 0x3F) == 0)
                _progress?.Report(new("Assessing recoverability", checked((ulong)i), checked((ulong)candidates.Count), candidates.Count, candidates[i].Name));
        }
        _progress?.Report(new("Complete", recordCount, recordCount, candidates.Count, $"Found {candidates.Count:N0} candidate files"));
        return new(boot, _partitionOffset, mftData.Extents, candidates, recordCount, parsedCurrentRecords, deepRecordsExamined, parsedDeepRecords);
    }

    private async Task<MftRecordZeroContext> ReadMftRecordZeroAsync(NtfsBootSector boot, CancellationToken cancellationToken)
    {
        Exception? primaryFailure = null;
        try
        {
            return await ReadAndValidateMftRecordZeroAsync(boot, boot.MftLcn, false, cancellationToken);
        }
        catch (Exception ex) when (IsRecoverableMftRecordFailure(ex))
        {
            primaryFailure = ex;
        }

        try
        {
            var mirror = await ReadAndValidateMftRecordZeroAsync(boot, boot.MftMirrorLcn, true, cancellationToken);
            _progress?.Report(new("NTFS 镜像元数据回退", 0, 0, 0,
                "主 $MFT 记录 0 不可读，已通过只读 $MFTMirr 定位当前 MFT。"));
            return mirror;
        }
        catch (Exception ex) when (IsRecoverableMftRecordFailure(ex))
        {
            throw new InvalidDataException(
                $"The NTFS master file table record is unreadable. Primary: {primaryFailure?.Message} Mirror: {ex.Message}", ex);
        }
    }

    private async Task<MftRecordZeroContext> ReadAndValidateMftRecordZeroAsync(
        NtfsBootSector boot,
        long recordLcn,
        bool fromMirror,
        CancellationToken cancellationToken)
    {
        var recordOffset = GetValidatedRecordOffset(boot, recordLcn, fromMirror ? "$MFTMirr" : "$MFT");
        var recordBytes = new byte[boot.FileRecordSize];
        await _device.ReadExactlyAsync(recordOffset, recordBytes, cancellationToken);
        var record = NtfsRecordParser.Parse(recordBytes, 0, boot.BytesPerSector)
            ?? throw new InvalidDataException($"The NTFS {((fromMirror) ? "$MFTMirr" : "$MFT")} record 0 is invalid.");
        var data = ValidateMftRecordZero(record, boot, fromMirror);
        var firstExtent = data.Extents[0];
        var firstMftOffset = checked(_partitionOffset + (ulong)firstExtent.LogicalCluster * boot.ClusterSize);
        return new(record, data, firstMftOffset, fromMirror);
    }

    private ulong GetValidatedRecordOffset(NtfsBootSector boot, long recordLcn, string sourceName)
    {
        if (recordLcn < 0)
            throw new InvalidDataException($"The NTFS {sourceName} location is negative.");
        var volumeLength = GetValidatedVolumeLength(boot);
        var relativeOffset = checked((ulong)recordLcn * boot.ClusterSize);
        if (relativeOffset > volumeLength || boot.FileRecordSize > volumeLength - relativeOffset)
            throw new InvalidDataException($"The NTFS {sourceName} record lies outside the declared volume.");
        var absoluteOffset = checked(_partitionOffset + relativeOffset);
        if (absoluteOffset > _device.Length || boot.FileRecordSize > _device.Length - absoluteOffset)
            throw new InvalidDataException($"The NTFS {sourceName} record lies outside the source device.");
        return absoluteOffset;
    }

    private static NtfsDataAttribute ValidateMftRecordZero(NtfsRecord record, NtfsBootSector boot, bool fromMirror)
    {
        var sourceName = fromMirror ? "$MFTMirr" : "$MFT";
        if (record.Number != 0 || record.Sequence == 0 || !record.InUse || record.IsDirectory)
            throw new InvalidDataException($"The NTFS {sourceName} copy is not a trustworthy MFT record 0.");
        var data = record.DefaultData;
        if (data is null || data.Resident || data.Sparse || data.Extents.Count == 0 || data.RealSize < boot.FileRecordSize ||
            data.RealSize % boot.FileRecordSize != 0)
            throw new InvalidDataException($"The NTFS {sourceName} record 0 has no trustworthy MFT runlist.");

        var volumeLength = GetValidatedVolumeLength(boot);
        var totalClusters = volumeLength / boot.ClusterSize;
        ulong describedBytes = 0;
        foreach (var extent in data.Extents)
        {
            if (extent.Sparse || extent.LogicalCluster < 0 || extent.ClusterCount <= 0)
                throw new InvalidDataException($"The NTFS {sourceName} MFT runlist contains an invalid extent.");
            var start = (ulong)extent.LogicalCluster;
            var count = (ulong)extent.ClusterCount;
            if (start >= totalClusters || count > totalClusters - start)
                throw new InvalidDataException($"The NTFS {sourceName} MFT runlist extends beyond the declared volume.");
            describedBytes = checked(describedBytes + count * boot.ClusterSize);
        }
        if (describedBytes < data.RealSize)
            throw new InvalidDataException($"The NTFS {sourceName} MFT runlist is shorter than its declared data size.");
        return data;
    }

    private static ulong GetValidatedVolumeLength(NtfsBootSector boot)
    {
        var volumeLength = checked(boot.TotalSectors * boot.BytesPerSector);
        if (volumeLength < boot.FileRecordSize || boot.ClusterSize == 0)
            throw new InvalidDataException("Invalid NTFS volume geometry.");
        return volumeLength;
    }

    private static bool IsRecoverableMftRecordFailure(Exception exception) =>
        exception is IOException or InvalidDataException or EndOfStreamException or OverflowException or ArgumentOutOfRangeException;

    private sealed record MftRecordZeroContext(
        NtfsRecord Record,
        NtfsDataAttribute Data,
        ulong FirstMftOffset,
        bool FromMirror);

    private async Task<(ulong Examined, ulong Parsed)> ScanWholeVolumeForMftAsync(
        NtfsBootSector boot,
        IReadOnlyList<DataExtent> currentMftExtents,
        ulong currentMftLength,
        IReadOnlyDictionary<long, (string Name, long Parent)> currentDirectories,
        List<RecoveryCandidate> allCandidates,
        ulong resumeOffset,
        CancellationToken cancellationToken)
    {
        var volumeLength = checked(boot.TotalSectors * boot.BytesPerSector);
        var volumeStart = _partitionOffset;
        var volumeEnd = Math.Min(_device.Length, checked(volumeStart + volumeLength));
        const int scanBlockSize = 8 * 1024 * 1024;
        var requestedStart = ValidateResumeOffset(resumeOffset, volumeStart, volumeEnd);
        if (requestedStart == volumeEnd) return (0, 0);
        var scanStart = resumeOffset == 0
            ? volumeStart
            : AlignDown(requestedStart, volumeStart, scanBlockSize);
        var candidateFloor = resumeOffset == 0 ? volumeStart : requestedStart;
        var overlap = checked((int)boot.FileRecordSize - 1);
        var buffer = new byte[scanBlockSize + overlap];
        var currentMftRanges = new List<(ulong Start, ulong End)>();
        var remainingCurrentMftBytes = currentMftLength;
        foreach (var extent in currentMftExtents)
        {
            if (remainingCurrentMftBytes == 0) break;
            var extentBytes = checked((ulong)extent.ClusterCount * boot.ClusterSize);
            var usedBytes = Math.Min(remainingCurrentMftBytes, extentBytes);
            if (!extent.Sparse && extent.LogicalCluster >= 0 && usedBytes > 0)
            {
                var start = checked(_partitionOffset + (ulong)extent.LogicalCluster * boot.ClusterSize);
                currentMftRanges.Add((start, checked(start + usedBytes)));
            }
            remainingCurrentMftBytes -= usedBytes;
        }
        var directories = new Dictionary<long, (string Name, long Parent)>(currentDirectories);
        var historical = new List<RecoveryCandidate>();
        var seenRecords = new HashSet<ulong>();
        var seenCandidates = new HashSet<string>(StringComparer.Ordinal);
        var seenRecoveryCandidates = new HashSet<string>(
            allCandidates.Select(BuildStableCandidateIdentity),
            StringComparer.OrdinalIgnoreCase);
        var totalClusters = volumeLength / boot.ClusterSize;
        ulong parsed = 0;
        var carry = 0;

        for (var position = scanStart; position < volumeEnd;)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var completedThisBlock = new List<RecoveryCandidate>();
            var requested = checked((int)Math.Min((ulong)scanBlockSize, volumeEnd - position));
            var read = await _device.ReadAsync(position, buffer.AsMemory(carry, requested), cancellationToken);
            if (read <= 0) break;
            var valid = carry + read;
            var baseOffset = position - checked((ulong)carry);
            var search = 0;
            while (search + 4 <= valid)
            {
                var relative = buffer.AsSpan(search, valid - search).IndexOf("FILE"u8);
                if (relative < 0) break;
                var index = search + relative;
                search = index + 4;
                if (index + boot.FileRecordSize > valid) continue;
                var absolute = checked(baseOffset + (ulong)index);
                if ((absolute - volumeStart) % boot.BytesPerSector != 0 || !seenRecords.Add(absolute)) continue;
                if (currentMftRanges.Any(range => absolute < range.End && absolute + boot.FileRecordSize > range.Start)) continue;

                NtfsRecord? record;
                try { record = NtfsRecordParser.Parse(buffer.AsSpan(index, checked((int)boot.FileRecordSize)), -1, boot.BytesPerSector); }
                catch (Exception ex) when (ex is InvalidDataException or OverflowException or ArgumentOutOfRangeException) { continue; }
                if (record is null || record.Number is < 16 or > 100_000_000 || record.Sequence == 0) continue;
                parsed++;
                var name = record.PreferredName;
                if (name is null) continue;
                if (record.IsDirectory)
                {
                    directories[record.Number] = (name.Name, name.ParentRecord);
                    continue;
                }
                if (absolute < candidateFloor) continue;
                var data = record.DefaultData;
                if (data is { Resident: false } && data.Extents.Any(extent => !IsPlausibleExtent(extent, totalClusters))) continue;
                if (data is { RealSize: > 0 } && data.RealSize > volumeLength) continue;
                var firstLcn = data is { Extents.Count: > 0 } ? data.Extents[0].LogicalCluster : -1;
                var key = $"{record.Number}:{record.Sequence}:{name.Name}:{data?.RealSize ?? 0}:{firstLcn}";
                if (!seenCandidates.Add(key)) continue;
                var candidate = CreateCandidate(record, name, boot, absolute, !record.InUse, RecoveryDiscovery.NtfsFullDiskMft);
                if (!seenRecoveryCandidates.Add(BuildStableCandidateIdentity(candidate))) continue;
                historical.Add(candidate);
                completedThisBlock.Add(candidate);
            }

            position += checked((ulong)read);
            carry = Math.Min(overlap, valid);
            buffer.AsSpan(valid - carry, carry).CopyTo(buffer);
            PublishCandidates(completedThisBlock, directories);
            _progress?.Report(new("NTFS 全盘旧 MFT 搜索", position - volumeStart, volumeEnd - volumeStart, historical.Count,
                $"已扫描 {(position - volumeStart) / (1024 * 1024):N0} MiB，有效旧记录 {parsed:N0}",
                CheckpointPosition: position, CheckpointTotal: volumeEnd));
        }

        foreach (var candidate in historical)
        {
            candidate.OriginalPath = BuildPath(candidate.ParentRecordNumber, candidate.Name, directories);
            allCandidates.Add(candidate);
        }
        return ((volumeEnd - scanStart) / boot.FileRecordSize, parsed);
    }

    private async Task<(ulong Examined, ulong Parsed)> ScanDeepMftAsync(
        NtfsBootSector boot,
        ulong currentMftLength,
        ulong firstMftOffset,
        IReadOnlyDictionary<long, (string Name, long Parent)> currentDirectories,
        List<RecoveryCandidate> allCandidates,
        ulong maximumBytes,
        ulong resumeOffset,
        CancellationToken cancellationToken)
    {
        var recordSize = checked((ulong)boot.FileRecordSize);
        var alignedCurrentLength = checked((currentMftLength + recordSize - 1) / recordSize * recordSize);
        var naturalStart = checked(firstMftOffset + alignedCurrentLength);
        var volumeLength = checked(boot.TotalSectors * boot.BytesPerSector);
        var volumeStart = _partitionOffset;
        var volumeEnd = Math.Min(_device.Length, checked(_partitionOffset + volumeLength));
        var requestedStart = ValidateResumeOffset(resumeOffset, volumeStart, volumeEnd);
        if (naturalStart >= volumeEnd) return (0, 0);
        var end = Math.Min(volumeEnd, checked(naturalStart + Math.Min(maximumBytes, volumeEnd - naturalStart)));
        var candidateFloor = resumeOffset == 0 ? naturalStart : Math.Max(naturalStart, requestedStart);
        if (candidateFloor >= end) return (0, 0);
        var start = AlignDown(candidateFloor, naturalStart, recordSize);
        const int preferredBlock = 8 * 1024 * 1024;
        var blockSize = checked((int)((ulong)preferredBlock / recordSize * recordSize));
        var buffer = new byte[blockSize];
        var deepDirectories = new Dictionary<long, (string Name, long Parent)>(currentDirectories);
        var deepCandidates = new List<RecoveryCandidate>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var seenRecoveryCandidates = new HashSet<string>(
            allCandidates.Select(BuildStableCandidateIdentity),
            StringComparer.OrdinalIgnoreCase);
        ulong examined = 0;
        ulong parsed = 0;
        var totalClusters = volumeLength / boot.ClusterSize;

        for (var position = start; position < end;)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var completedThisBlock = new List<RecoveryCandidate>();
            var count = checked((int)Math.Min((ulong)buffer.Length, end - position));
            count -= count % checked((int)recordSize);
            if (count == 0) break;
            await _device.ReadExactlyAsync(position, buffer.AsMemory(0, count), cancellationToken);
            for (var slot = 0; slot < count; slot += checked((int)recordSize))
            {
                examined++;
                var fallback = checked((long)((position + (ulong)slot - firstMftOffset) / recordSize));
                var record = ParseDeepRecord(buffer, slot, checked((int)recordSize), fallback, boot.BytesPerSector);
                if (record is null || record.Number is < 16 or > 100_000_000 || record.Sequence == 0) continue;
                parsed++;
                var name = record.PreferredName;
                if (name is null) continue;
                if (record.IsDirectory)
                {
                    deepDirectories[record.Number] = (name.Name, name.ParentRecord);
                    continue;
                }
                var recordOffset = checked(position + (ulong)slot);
                if (recordOffset < candidateFloor) continue;
                var data = record.DefaultData;
                if (data is { Resident: false } && data.Extents.Any(extent => !IsPlausibleExtent(extent, totalClusters)))
                    continue;
                if (data is { RealSize: > 0 } && data.RealSize > volumeLength) continue;
                var firstLcn = data is { Extents.Count: > 0 } ? data.Extents[0].LogicalCluster : -1;
                var key = $"{record.Number}:{record.Sequence}:{name.Name}:{data?.RealSize ?? 0}:{firstLcn}";
                if (!seen.Add(key)) continue;
                var candidate = CreateCandidate(record, name, boot, recordOffset, !record.InUse, RecoveryDiscovery.NtfsDeepMft);
                if (!seenRecoveryCandidates.Add(BuildStableCandidateIdentity(candidate))) continue;
                deepCandidates.Add(candidate);
                completedThisBlock.Add(candidate);
            }
            position += checked((ulong)count);
            PublishCandidates(completedThisBlock, deepDirectories);
            _progress?.Report(new("NTFS 深度元数据扫描", position - start, end - start, deepCandidates.Count,
                $"已检查旧 MFT 记录槽 {examined:N0}，有效旧记录 {parsed:N0}",
                CheckpointPosition: position, CheckpointTotal: end));
        }

        foreach (var candidate in deepCandidates)
        {
            candidate.OriginalPath = BuildPath(candidate.ParentRecordNumber, candidate.Name, deepDirectories);
            allCandidates.Add(candidate);
        }
        return (examined, parsed);
    }

    private static NtfsRecord? ParseDeepRecord(byte[] buffer, int offset, int recordSize, long fallbackNumber,
        ushort bytesPerSector)
    {
        var raw = buffer.AsSpan(offset, recordSize);
        if (!raw[..4].SequenceEqual("FILE"u8)) return null;
        try
        {
            return NtfsRecordParser.Parse(raw, fallbackNumber, bytesPerSector);
        }
        catch (Exception ex) when (ex is InvalidDataException or OverflowException or ArgumentOutOfRangeException)
        {
            return null;
        }
    }

    private static ulong ValidateResumeOffset(ulong resumeOffset, ulong volumeStart, ulong volumeEnd)
    {
        if (resumeOffset == 0) return volumeStart;
        if (resumeOffset < volumeStart || resumeOffset > volumeEnd)
            throw new InvalidDataException("The NTFS scan resume offset lies outside the selected volume.");
        return resumeOffset;
    }

    private static ulong AlignDown(ulong value, ulong origin, ulong alignment)
    {
        if (alignment == 0 || value <= origin) return origin;
        return checked(origin + (value - origin) / alignment * alignment);
    }

    private void PublishCandidates(
        IEnumerable<RecoveryCandidate> candidates,
        IReadOnlyDictionary<long, (string Name, long Parent)> directories)
    {
        if (_candidateAvailable is null) return;
        foreach (var candidate in candidates)
        {
            candidate.OriginalPath = BuildPath(candidate.ParentRecordNumber, candidate.Name, directories);
            _candidateAvailable(candidate);
        }
    }

    private static string BuildStableCandidateIdentity(RecoveryCandidate candidate) => string.Join('|',
        (int)candidate.FileSystem,
        candidate.RecordNumber,
        candidate.ParentRecordNumber,
        candidate.Name,
        candidate.Size,
        candidate.IsResident,
        candidate.SourceOffset);

    private static bool IsPlausibleExtent(DataExtent extent, ulong totalClusters)
    {
        if (extent.Sparse) return extent.ClusterCount > 0;
        if (extent.LogicalCluster < 0 || extent.ClusterCount <= 0) return false;
        var start = (ulong)extent.LogicalCluster;
        var count = (ulong)extent.ClusterCount;
        return start <= totalClusters && count <= totalClusters - start;
    }

    private RecoveryCandidate CreateCandidate(NtfsRecord record, NtfsFileName name, NtfsBootSector boot, ulong recordStorageOffset,
        bool deleted, RecoveryDiscovery discovery)
    {
        var data = record.DefaultData;
        return new RecoveryCandidate
        {
            RecordNumber = record.Number,
            Name = name.Name,
            ParentRecordNumber = name.ParentRecord,
            Size = data?.RealSize ?? 0,
            IsDirectory = false,
            IsDeleted = deleted,
            IsResident = data?.Resident ?? false,
            ResidentData = data?.ResidentData,
            Extents = data?.Extents ?? [],
            ModifiedUtc = name.ModifiedUtc,
            FileSystem = FileSystemKind.Ntfs,
            Discovery = discovery,
            SourceOffset = data is { Resident: false, Extents.Count: > 0 } && !data.Extents[0].Sparse
                ? checked(_partitionOffset + (ulong)data.Extents[0].LogicalCluster * boot.ClusterSize)
                : recordStorageOffset
        };
    }

    private async Task ScoreAsync(RecoveryCandidate candidate, NtfsBootSector boot, NtfsBitmapAccessor? bitmap, CancellationToken cancellationToken)
    {
        if (candidate.IsResident)
        {
            candidate.Quality = RecoveryQuality.Excellent;
            candidate.QualityReason = "File content is resident in the MFT record.";
            return;
        }
        if (candidate.Extents.Count == 0 || candidate.Size == 0)
        {
            candidate.Quality = RecoveryQuality.Poor;
            candidate.QualityReason = "No recoverable unnamed data attribute was found.";
            return;
        }
        if (candidate.Extents.Any(e => e.Sparse))
        {
            candidate.Quality = RecoveryQuality.Partial;
            candidate.QualityReason = "The file contains sparse or unavailable extents.";
            return;
        }
        if (bitmap is null)
        {
            candidate.Quality = RecoveryQuality.Unknown;
            candidate.QualityReason = "The NTFS allocation bitmap could not be read.";
            return;
        }
        foreach (var extent in candidate.Extents)
        {
            if (await bitmap.AnyAllocatedAsync(extent.LogicalCluster, extent.ClusterCount, cancellationToken))
            {
                candidate.Quality = RecoveryQuality.Overwritten;
                candidate.QualityReason = "One or more original clusters are currently allocated and may be overwritten.";
                return;
            }
        }
        candidate.Quality = RecoveryQuality.Good;
        candidate.QualityReason = "All original clusters are currently unallocated.";
        var sampleLength = checked((int)Math.Min(candidate.Size, 64UL * 1024));
        if (sampleLength > 0)
        {
            var sample = new byte[sampleLength];
            await NtfsExtentReader.ReadExactlyAsync(_device, _partitionOffset, boot.ClusterSize, candidate.Extents, 0, sample, cancellationToken);
            if (sample.All(b => b == 0))
            {
                candidate.Quality = RecoveryQuality.TrimmedOrZeroed;
                candidate.QualityReason = "The beginning of the file reads as all zeroes; SSD TRIM or overwrite is likely.";
            }
        }
    }

    private static string BuildPath(long parent, string name, IReadOnlyDictionary<long, (string Name, long Parent)> directories)
    {
        var components = new Stack<string>();
        components.Push(SanitizePathComponent(name));
        var visited = new HashSet<long>();
        while (parent != 5 && parent >= 0 && visited.Add(parent) && components.Count < 256)
        {
            if (!directories.TryGetValue(parent, out var directory))
            {
                components.Push("Lost+Found");
                break;
            }
            components.Push(SanitizePathComponent(directory.Name));
            parent = directory.Parent;
        }
        return string.Join(Path.DirectorySeparatorChar, components.Where(c => c.Length > 0));
    }

    internal static string SanitizePathComponent(string name)
    {
        var invalid = Path.GetInvalidFileNameChars();
        var chars = name.Select(c => invalid.Contains(c) || c < 32 ? '_' : c).ToArray();
        var sanitized = new string(chars).Trim().TrimEnd('.');
        return string.IsNullOrEmpty(sanitized) ? "unnamed" : sanitized;
    }
}

internal sealed class NtfsBitmapAccessor
{
    private const int PageSize = 64 * 1024;
    private const int MaxPages = 64;
    private readonly IBlockDevice _device;
    private readonly ulong _partitionOffset;
    private readonly uint _clusterSize;
    private readonly IReadOnlyList<DataExtent> _extents;
    private readonly ulong _length;
    private readonly Dictionary<ulong, byte[]> _pages = [];
    private readonly Queue<ulong> _order = [];

    public NtfsBitmapAccessor(IBlockDevice device, ulong partitionOffset, uint clusterSize, IReadOnlyList<DataExtent> extents, ulong length)
    {
        _device = device;
        _partitionOffset = partitionOffset;
        _clusterSize = clusterSize;
        _extents = extents;
        _length = length;
    }

    public async ValueTask<bool> AnyAllocatedAsync(long firstCluster, long clusterCount, CancellationToken cancellationToken)
    {
        if (firstCluster < 0 || clusterCount <= 0) return true;
        var firstBit = checked((ulong)firstCluster);
        var endBit = checked(firstBit + (ulong)clusterCount);
        for (var bit = firstBit; bit < endBit;)
        {
            var byteOffset = bit / 8;
            if (byteOffset >= _length) return true;
            var pageIndex = byteOffset / PageSize;
            var page = await GetPageAsync(pageIndex, cancellationToken);
            var pageStartByte = pageIndex * PageSize;
            var localByte = checked((int)(byteOffset - pageStartByte));
            var pageEndBit = Math.Min(endBit, checked((pageStartByte + (ulong)page.Length) * 8));
            while (bit < pageEndBit)
            {
                var value = page[checked((int)(bit / 8 - pageStartByte))];
                var startInByte = checked((int)(bit & 7));
                var bits = checked((int)Math.Min(8UL - (ulong)startInByte, pageEndBit - bit));
                var mask = ((1 << bits) - 1) << startInByte;
                if ((value & mask) != 0) return true;
                bit += checked((ulong)bits);
            }
        }
        return false;
    }

    private async ValueTask<byte[]> GetPageAsync(ulong pageIndex, CancellationToken cancellationToken)
    {
        if (_pages.TryGetValue(pageIndex, out var existing)) return existing;
        var offset = checked(pageIndex * PageSize);
        var size = checked((int)Math.Min((ulong)PageSize, _length - offset));
        var page = new byte[size];
        await NtfsExtentReader.ReadExactlyAsync(_device, _partitionOffset, _clusterSize, _extents, offset, page, cancellationToken);
        if (_pages.Count >= MaxPages)
        {
            var old = _order.Dequeue();
            _pages.Remove(old);
        }
        _pages[pageIndex] = page;
        _order.Enqueue(pageIndex);
        return page;
    }
}

public sealed record RecoveryResult(string OutputPath, ulong BytesWritten, string Sha256, bool Complete,
    FileIntegrityState Integrity = FileIntegrityState.NotChecked, string IntegrityMessage = "",
    JpegSalvageResult? Salvage = null)
{
    public bool Usable => Complete && (Integrity != FileIntegrityState.Damaged || Salvage?.State == JpegSalvageState.Salvaged);
}

public static partial class RecoveryWriter
{
    public static async Task<RecoveryResult> RecoverNtfsAsync(IBlockDevice source, NtfsScanResult scan, RecoveryCandidate candidate, string destinationRoot, IProgress<ScanProgress>? progress = null, CancellationToken cancellationToken = default)
    {
        if (!candidate.IsDeleted) throw new InvalidOperationException("Only deleted files are recovered by this operation.");
        if (string.IsNullOrWhiteSpace(destinationRoot)) throw new ArgumentException("A destination directory is required.", nameof(destinationRoot));
        var root = Path.GetFullPath(destinationRoot);
        Directory.CreateDirectory(root);
        var relative = string.IsNullOrWhiteSpace(candidate.OriginalPath) ? NtfsScanner.SanitizePathComponent(candidate.Name) : candidate.OriginalPath;
        var output = EnsureUniquePath(Path.Combine(root, relative));
        var parent = Path.GetDirectoryName(output);
        if (parent is not null) Directory.CreateDirectory(parent);

        await using var file = new FileStream(output, FileMode.CreateNew, FileAccess.Write, FileShare.None, 1024 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan);
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        ulong written = 0;
        var complete = true;
        if (candidate.IsResident)
        {
            var data = candidate.ResidentData ?? [];
            await file.WriteAsync(data, cancellationToken);
            hash.AppendData(data);
            written = checked((ulong)data.Length);
        }
        else
        {
            var buffer = new byte[1024 * 1024];
            while (written < candidate.Size)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var count = checked((int)Math.Min((ulong)buffer.Length, candidate.Size - written));
                try
                {
                    await NtfsExtentReader.ReadExactlyAsync(source, scan.PartitionOffset, scan.Boot.ClusterSize, candidate.Extents, written, buffer.AsMemory(0, count), cancellationToken);
                }
                catch (Exception ex) when (ex is IOException or EndOfStreamException)
                {
                    complete = false;
                    break;
                }
                await file.WriteAsync(buffer.AsMemory(0, count), cancellationToken);
                hash.AppendData(buffer.AsSpan(0, count));
                written += checked((ulong)count);
                progress?.Report(new("Recovering", written, candidate.Size, 1, candidate.Name));
            }
        }
        await file.FlushAsync(cancellationToken);
        var digest = Convert.ToHexString(hash.GetHashAndReset()).ToLowerInvariant();
        await file.DisposeAsync();
        return await FinalizeResultAsync(output, written, digest, complete && written == candidate.Size, cancellationToken);
    }

    private static string EnsureUniquePath(string path)
    {
        if (!File.Exists(path) && !Directory.Exists(path)) return path;
        var directory = Path.GetDirectoryName(path) ?? string.Empty;
        var name = Path.GetFileNameWithoutExtension(path);
        var extension = Path.GetExtension(path);
        for (var i = 1; i < 100_000; i++)
        {
            var candidate = Path.Combine(directory, $"{name} ({i}){extension}");
            if (!File.Exists(candidate) && !Directory.Exists(candidate)) return candidate;
        }
        throw new IOException("Unable to allocate a unique recovery filename.");
    }
}
