using System.Buffers.Binary;
using System.Text;

namespace Recovery.Core;

public static class PartitionScanner
{
    private static readonly Guid MicrosoftBasicData = new("EBD0A0A2-B9E5-4433-87C0-68B6B72699C7");
    private const int MaximumEbrLinks = 4096;

    public static async Task<IReadOnlyList<PartitionDescriptor>> ScanAsync(IBlockDevice device, CancellationToken cancellationToken = default)
    {
        var sectorSize = checked((int)device.LogicalSectorSize);
        if (sectorSize < 512 || sectorSize > 65536) throw new InvalidDataException("Unsupported logical sector size.");
        var sector = new byte[sectorSize];
        await device.ReadExactlyAsync(0, sector, cancellationToken);

        // GPT has its own signatures and CRCs, so it must not depend on a surviving protective
        // MBR. Sector zero is often the first sector damaged by an accidental initialization;
        // in that case the primary or end-of-disk backup GPT can still describe every range.
        var totalLbas = device.Length / device.LogicalSectorSize;
        var primaryGpt = totalLbas > 1
            ? await TryReadGptAsync(device, 1, fromBackup: false, cancellationToken)
            : null;
        if (primaryGpt is not null) return primaryGpt;
        var backupGpt = totalLbas > 1
            ? await TryReadGptAsync(device, totalLbas - 1, fromBackup: true, cancellationToken)
            : null;
        if (backupGpt is not null) return backupGpt;

        if (sector[510] != 0x55 || sector[511] != 0xAA)
            return [await CreateWholeDeviceDescriptorAsync(device, "整块介质（分区表无效）", cancellationToken)];

        var entries = new List<MbrEntry>(4);
        for (var i = 0; i < 4; i++)
            entries.Add(ReadMbrEntry(sector, i));

        var protective = entries.Any(entry => entry.Type == 0xEE);
        if (!protective)
        {
            var mbr = await ReadMbrPartitionsAsync(device, entries, cancellationToken);
            return mbr.Count > 0
                ? mbr
                : [await CreateWholeDeviceDescriptorAsync(device, "整盘文件系统", cancellationToken)];
        }

        return [new PartitionDescriptor(1, 0, device.Length, Guid.Empty, Guid.Empty,
            "GPT损坏：整盘只读搜索范围", FileSystemKind.Unknown, false, Evidence: new(
                ScanTargetOrigin.WholeDevice, true, false, false, false,
                "主、备 GPT 均未通过CRC校验，仅保留整盘只读搜索范围。"))];
    }

    private static async Task<PartitionDescriptor> CreateWholeDeviceDescriptorAsync(
        IBlockDevice device, string name, CancellationToken cancellationToken)
    {
        var fileSystem = await DetectFileSystemAsync(device, 0, cancellationToken);
        return new(1, 0, device.Length, Guid.Empty, Guid.Empty, name, fileSystem, false,
            Evidence: new PartitionEvidence(ScanTargetOrigin.WholeDevice, true,
                fileSystem != FileSystemKind.Unknown, false, false,
                fileSystem == FileSystemKind.Unknown
                    ? "分区表无效且整盘文件系统引导结构未通过验证。"
                    : "介质没有可用分区表，但整盘文件系统引导结构验证通过。"));
    }

    public static async Task<FileSystemKind> DetectFileSystemAsync(IBlockDevice device, ulong offset, CancellationToken cancellationToken = default)
    {
        var boot = new byte[512];
        if (offset + 512 > device.Length) return FileSystemKind.Unknown;
        await device.ReadExactlyAsync(offset, boot, cancellationToken);
        if (boot[510] != 0x55 || boot[511] != 0xAA) return FileSystemKind.Unknown;
        try
        {
            if (boot.AsSpan(3, 8).SequenceEqual("NTFS    "u8))
            {
                _ = NtfsBootSector.Parse(boot);
                return FileSystemKind.Ntfs;
            }
            if (boot.AsSpan(3, 8).SequenceEqual("EXFAT   "u8))
            {
                _ = ExFatBootSector.Parse(boot);
                return FileSystemKind.ExFat;
            }
            if (boot.AsSpan(82, 8).StartsWith("FAT32"u8))
            {
                _ = Fat32BootSector.Parse(boot);
                return FileSystemKind.Fat32;
            }
        }
        catch (Exception exception) when (exception is InvalidDataException or OverflowException or ArgumentOutOfRangeException)
        {
            return FileSystemKind.Unknown;
        }
        if (boot.AsSpan(54, 8).StartsWith("FAT16"u8)) return FileSystemKind.Fat16;
        if (boot.AsSpan(54, 8).StartsWith("FAT12"u8)) return FileSystemKind.Fat12;
        return FileSystemKind.Unknown;
    }

    /// <summary>
    /// Enriches table-provided ranges whose primary boot sector is unreadable or invalid. Only
    /// well-known in-volume backup locations are probed and every parsed geometry must remain
    /// inside the original partition range. The source is never modified.
    /// </summary>
    public static async Task<IReadOnlyList<PartitionDescriptor>> EnrichWithBackupStructuresAsync(
        IBlockDevice device,
        IEnumerable<PartitionDescriptor> partitions,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(device);
        ArgumentNullException.ThrowIfNull(partitions);
        var result = new List<PartitionDescriptor>();
        foreach (var partition in partitions)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (partition.FileSystem != FileSystemKind.Unknown || partition.Length < 512 ||
                partition.Offset > device.Length || partition.Length > device.Length - partition.Offset)
            {
                result.Add(partition);
                continue;
            }

            var recovered = await TryProbeBackupStructureAsync(device, partition, cancellationToken);
            result.Add(recovered is null
                ? partition
                : partition with
                {
                    FileSystem = recovered.FileSystem,
                    BootSectorOffset = recovered.BootSectorOffset,
                    Name = $"{partition.Name}（备用引导识别）",
                    Evidence = new PartitionEvidence(ScanTargetOrigin.BackupBootSector, true, false, true,
                        false, "主引导不可用，已验证卷内备用引导结构和声明容量。")
                });
        }
        return result;
    }

    private static async Task<BackupStructureProbe?> TryProbeBackupStructureAsync(
        IBlockDevice device,
        PartitionDescriptor partition,
        CancellationToken cancellationToken)
    {
        // NTFS keeps a copy at the last sector of the volume.
        var logicalSector = Math.Max(512UL, device.LogicalSectorSize);
        if (partition.Length >= logicalSector)
        {
            var offset = checked(partition.Offset + partition.Length - logicalSector);
            var bytes = await TryReadBootBytesAsync(device, offset, cancellationToken);
            if (bytes is not null && TryValidateNtfsBackup(bytes, partition.Length))
                return new(FileSystemKind.Ntfs, offset);
        }

        // exFAT's backup boot region starts at relative sector 12.
        var exFatOffsetDelta = checked(12UL * logicalSector);
        if (exFatOffsetDelta <= partition.Length - 512)
        {
            var offset = checked(partition.Offset + exFatOffsetDelta);
            var bytes = await TryReadBootBytesAsync(device, offset, cancellationToken);
            if (bytes is not null && TryValidateExFatBackup(bytes, partition.Length))
                return new(FileSystemKind.ExFat, offset);
        }

        // FAT32 commonly uses reserved-sector 6. If the damaged primary still retains BPB hints,
        // include its declared bytes-per-sector and backup-sector index as additional probes.
        var primaryBytes = await TryReadBootBytesAsync(device, partition.Offset, cancellationToken);
        var hints = GetFat32BackupHints(primaryBytes, device.LogicalSectorSize);
        foreach (var hint in hints)
        {
            ulong relative;
            try { relative = checked((ulong)hint.BackupSector * hint.BytesPerSector); }
            catch (OverflowException) { continue; }
            if (relative == 0 || relative > partition.Length - 512) continue;
            var offset = checked(partition.Offset + relative);
            var bytes = await TryReadBootBytesAsync(device, offset, cancellationToken);
            if (bytes is not null && TryValidateFat32Backup(bytes, partition.Length, hint.BackupSector))
                return new(FileSystemKind.Fat32, offset);
        }
        return null;
    }

    private static async Task<byte[]?> TryReadBootBytesAsync(
        IBlockDevice device,
        ulong offset,
        CancellationToken cancellationToken)
    {
        if (offset > device.Length || device.Length - offset < 512) return null;
        var bytes = new byte[512];
        try
        {
            await device.ReadExactlyAsync(offset, bytes, cancellationToken);
            return bytes;
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception exception) when (exception is IOException or EndOfStreamException or ArgumentOutOfRangeException)
        {
            return null;
        }
    }

    private static bool TryValidateNtfsBackup(byte[] bytes, ulong partitionLength)
    {
        try
        {
            var boot = NtfsBootSector.Parse(bytes);
            var volumeLength = checked(boot.TotalSectors * boot.BytesPerSector);
            var tolerance = Math.Max((ulong)boot.BytesPerSector, 4096UL);
            return volumeLength <= partitionLength && partitionLength - volumeLength < tolerance;
        }
        catch (Exception exception) when (exception is InvalidDataException or OverflowException or ArgumentOutOfRangeException)
        {
            return false;
        }
    }

    private static bool TryValidateExFatBackup(byte[] bytes, ulong partitionLength)
    {
        try
        {
            var boot = ExFatBootSector.Parse(bytes);
            var volumeLength = checked(ReadUInt64(bytes, 72) * boot.BytesPerSector);
            return volumeLength > 0 && volumeLength <= partitionLength;
        }
        catch (Exception exception) when (exception is InvalidDataException or OverflowException or ArgumentOutOfRangeException)
        {
            return false;
        }
    }

    private static bool TryValidateFat32Backup(byte[] bytes, ulong partitionLength, ushort expectedBackupSector)
    {
        try
        {
            var boot = Fat32BootSector.Parse(bytes);
            var volumeLength = checked((ulong)boot.TotalSectors * boot.BytesPerSector);
            return volumeLength > 0 && volumeLength <= partitionLength && expectedBackupSector < boot.ReservedSectors &&
                (boot.BackupBootSector is 0 or ushort.MaxValue || boot.BackupBootSector == expectedBackupSector);
        }
        catch (Exception exception) when (exception is InvalidDataException or OverflowException or ArgumentOutOfRangeException)
        {
            return false;
        }
    }

    private static IReadOnlyList<Fat32BackupHint> GetFat32BackupHints(byte[]? primaryBytes, uint logicalSectorSize)
    {
        var sectorSizes = new HashSet<ushort> { 512, 1024, 2048, 4096 };
        var backupSectors = new HashSet<ushort> { 6 };
        if (logicalSectorSize <= ushort.MaxValue && IsSupportedFatSectorSize((ushort)logicalSectorSize))
            sectorSizes.Add((ushort)logicalSectorSize);
        if (primaryBytes is { Length: >= 52 })
        {
            var declaredSectorSize = ReadUInt16(primaryBytes, 11);
            var declaredBackup = ReadUInt16(primaryBytes, 50);
            if (IsSupportedFatSectorSize(declaredSectorSize)) sectorSizes.Add(declaredSectorSize);
            if (declaredBackup is > 0 and <= 128) backupSectors.Add(declaredBackup);
        }
        return backupSectors.SelectMany(backup => sectorSizes.Select(size => new Fat32BackupHint(backup, size))).ToArray();
    }

    private static bool IsSupportedFatSectorSize(ushort value) => value is 512 or 1024 or 2048 or 4096;
    private static ushort ReadUInt16(byte[] bytes, int offset) => BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(offset, 2));
    private static ulong ReadUInt64(byte[] bytes, int offset) => BinaryPrimitives.ReadUInt64LittleEndian(bytes.AsSpan(offset, 8));

    private sealed record BackupStructureProbe(FileSystemKind FileSystem, ulong BootSectorOffset);
    private readonly record struct Fat32BackupHint(ushort BackupSector, ushort BytesPerSector);

    public static async Task<IReadOnlyList<PartitionDescriptor>> FindLostPartitionsAsync(
        IBlockDevice device, IReadOnlyList<PartitionDescriptor>? known = null,
        IProgress<ScanProgress>? progress = null, CancellationToken cancellationToken = default,
        ulong resumeBytePosition = 0)
        => await FindLostPartitionsAsync(device, known, progress, cancellationToken, resumeBytePosition, null);

    public static async Task<IReadOnlyList<PartitionDescriptor>> FindLostPartitionsAsync(
        IBlockDevice device, IReadOnlyList<PartitionDescriptor>? known,
        IProgress<ScanProgress>? progress, CancellationToken cancellationToken,
        ulong resumeBytePosition,
        Func<PartitionDescriptor, CancellationToken, ValueTask>? candidateDiscovered)
    {
        const int blockSize = 8 * 1024 * 1024;
        var sectorSize = checked((int)device.LogicalSectorSize);
        if (sectorSize < 512 || sectorSize > 65536) throw new InvalidDataException("Unsupported logical sector size.");
        if (resumeBytePosition > device.Length)
            throw new ArgumentOutOfRangeException(nameof(resumeBytePosition), "Resume position is outside the source device.");

        var sectorSizeBytes = checked((ulong)sectorSize);
        var resumeRemainder = resumeBytePosition % sectorSizeBytes;
        var resumeAdvance = resumeRemainder == 0 ? 0 : sectorSizeBytes - resumeRemainder;
        var alignedResumePosition = resumeAdvance > device.Length - resumeBytePosition
            ? device.Length
            : resumeBytePosition + resumeAdvance;
        var alignedBlockSize = blockSize - blockSize % sectorSize;

        var buffer = new byte[alignedBlockSize + sectorSize];
        var found = new List<PartitionDescriptor>();
        var knownRanges = (known ?? []).Where(item => item.FileSystem != FileSystemKind.Unknown)
            .Select(item => (item.Offset, End: checked(item.Offset + item.Length))).ToList();
        var position = alignedResumePosition;
        progress?.Report(new("搜索丢失分区", position, device.Length, found.Count,
            resumeBytePosition == 0 ? "开始搜索丢失分区" : $"从 {position:N0} 字节处继续搜索",
            CheckpointPosition: position, CheckpointTotal: device.Length));
        while (position < device.Length)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var count = checked((int)Math.Min((ulong)alignedBlockSize, device.Length - position));
            await device.ReadExactlyAsync(position, buffer.AsMemory(0, count), cancellationToken);
            for (var local = 0; local + 512 <= count; local += sectorSize)
            {
                var absolute = position + checked((ulong)local);
                if (knownRanges.Any(range => absolute >= range.Offset && absolute < range.End) ||
                    found.Any(item => absolute >= item.Offset && absolute < item.Offset + item.Length)) continue;
                var detected = TryDescribeBootSector(buffer, local, out var fileSystem, out var length);
                if (detected && length > 0 && length <= device.Length - absolute)
                {
                    var candidate = new PartitionDescriptor(found.Count + 1, absolute, length, Guid.Empty, Guid.Empty,
                        $"检测到的丢失 {fileSystem} 分区", fileSystem, false, Evidence: new(
                            ScanTargetOrigin.PrimaryBootSector, true, true, false, false,
                            "在未占用范围发现并验证文件系统主引导结构。"));
                    found.Add(candidate);
                    if (candidateDiscovered is not null)
                        await candidateDiscovered(candidate, cancellationToken);
                    continue;
                }
                if (!TryDescribeBackupBootSector(buffer, local, absolute, device.Length, out var originalStart, out fileSystem, out length)) continue;
                if (knownRanges.Any(range => originalStart >= range.Offset && originalStart < range.End) ||
                    found.Any(item => originalStart >= item.Offset && originalStart < item.Offset + item.Length)) continue;
                var backupCandidate = new PartitionDescriptor(found.Count + 1, originalStart, length, Guid.Empty, Guid.Empty,
                    $"由备份引导区定位的丢失 {fileSystem} 分区", fileSystem, false, absolute, new(
                        ScanTargetOrigin.BackupBootSector, true, false, true, false,
                        "由通过结构校验的备用引导区反推出分区起点和长度。"));
                found.Add(backupCandidate);
                if (candidateDiscovered is not null)
                    await candidateDiscovered(backupCandidate, cancellationToken);
            }
            position += checked((ulong)count);
            progress?.Report(new("搜索丢失分区", position, device.Length, found.Count, $"已发现 {found.Count} 个候选分区",
                CheckpointPosition: position, CheckpointTotal: device.Length));
        }
        return found;
    }

    private static bool TryDescribeBootSector(ReadOnlySpan<byte> boot, out FileSystemKind fileSystem, out ulong length)
    {
        fileSystem = FileSystemKind.Unknown; length = 0;
        try
        {
            if (boot.Slice(3, 8).SequenceEqual("NTFS    "u8))
            {
                var parsed = NtfsBootSector.Parse(boot); fileSystem = FileSystemKind.Ntfs;
                length = checked(parsed.TotalSectors * parsed.BytesPerSector); return true;
            }
            if (boot.Slice(3, 8).SequenceEqual("EXFAT   "u8))
            {
                var parsed = ExFatBootSector.Parse(boot); fileSystem = FileSystemKind.ExFat;
                length = checked(BinaryPrimitives.ReadUInt64LittleEndian(boot[72..80]) * parsed.BytesPerSector); return true;
            }
            if (boot.Slice(82, 5).SequenceEqual("FAT32"u8))
            {
                var parsed = Fat32BootSector.Parse(boot); fileSystem = FileSystemKind.Fat32;
                length = checked((ulong)parsed.TotalSectors * parsed.BytesPerSector); return true;
            }
        }
        catch (Exception ex) when (ex is InvalidDataException or OverflowException or ArgumentOutOfRangeException) { }
        return false;
    }

    private static bool TryDescribeBootSector(byte[] buffer, int offset, out FileSystemKind fileSystem, out ulong length)
        => TryDescribeBootSector(buffer.AsSpan(offset, 512), out fileSystem, out length);

    private static async Task<IReadOnlyList<PartitionDescriptor>> ReadMbrPartitionsAsync(
        IBlockDevice device, IReadOnlyList<MbrEntry> entries, CancellationToken cancellationToken)
    {
        var totalLbas = device.Length / device.LogicalSectorSize;
        var candidates = new List<PartitionCandidate>();
        var occupied = new List<LbaRange>();

        // Validate ordinary primary partitions first. This makes overlap handling independent of
        // their slot order and prevents a malformed extended container from hiding a valid primary.
        foreach (var entry in entries.Where(entry => entry.IsDataPartition))
        {
            if (!TryCreateRange(entry.FirstLba, entry.SectorCount, totalLbas, out var range) ||
                occupied.Any(existing => existing.Overlaps(range))) continue;

            occupied.Add(range);
            candidates.Add(new PartitionCandidate(
                range,
                PartitionDiscoverySource.MbrPrimary,
                $"MBR主分区表第 {entry.Slot + 1} 项，类型 0x{entry.Type:X2}",
                null));
        }

        var extendedContainers = new List<LbaRange>();
        foreach (var entry in entries.Where(entry => entry.IsExtendedPartition))
        {
            if (!TryCreateRange(entry.FirstLba, entry.SectorCount, totalLbas, out var container) ||
                occupied.Any(existing => existing.Overlaps(container)) ||
                extendedContainers.Any(existing => existing.Overlaps(container))) continue;

            extendedContainers.Add(container);
            await ReadEbrChainAsync(device, container, occupied, candidates, cancellationToken);
        }

        var result = new List<PartitionDescriptor>(candidates.Count);
        foreach (var candidate in candidates)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var offset = checked(candidate.Range.Start * device.LogicalSectorSize);
            var length = checked(candidate.Range.Length * device.LogicalSectorSize);
            var fileSystem = length >= 512
                ? await DetectFileSystemAsync(device, offset, cancellationToken)
                : FileSystemKind.Unknown;
            var name = candidate.Source == PartitionDiscoverySource.MbrPrimary
                ? $"MBR 主分区 {result.Count + 1}"
                : $"MBR 逻辑分区 {result.Count + 1}";
            var origin = candidate.Source == PartitionDiscoverySource.MbrPrimary
                ? ScanTargetOrigin.PrimaryPartitionTable
                : ScanTargetOrigin.ExtendedPartition;
            result.Add(new PartitionDescriptor(
                result.Count + 1,
                offset,
                length,
                Guid.Empty,
                Guid.Empty,
                name,
                fileSystem,
                false,
                Evidence: new PartitionEvidence(origin, true, fileSystem != FileSystemKind.Unknown,
                    false, false, candidate.Evidence)));
        }

        return result;
    }

    private static async Task ReadEbrChainAsync(
        IBlockDevice device,
        LbaRange container,
        List<LbaRange> occupied,
        List<PartitionCandidate> candidates,
        CancellationToken cancellationToken)
    {
        var sectorSize = checked((int)device.LogicalSectorSize);
        var sector = new byte[sectorSize];
        var visited = new HashSet<ulong>();
        var currentEbrLba = container.Start;

        for (var linkIndex = 0; linkIndex < MaximumEbrLinks; linkIndex++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!container.Contains(currentEbrLba) || !visited.Add(currentEbrLba) ||
                occupied.Any(range => range.Contains(currentEbrLba))) break;

            try
            {
                await device.ReadExactlyAsync(checked(currentEbrLba * device.LogicalSectorSize), sector, cancellationToken);
            }
            catch (Exception ex) when (ex is IOException or EndOfStreamException or ArgumentOutOfRangeException or OverflowException)
            {
                break;
            }

            if (sector[510] != 0x55 || sector[511] != 0xAA) break;

            // The first EBR entry describes the logical volume relative to this EBR.
            var logicalEntry = ReadMbrEntry(sector, 0);
            if (logicalEntry.IsDataPartition && logicalEntry.FirstLba > 0 &&
                TryAdd(currentEbrLba, logicalEntry.FirstLba, out var logicalStart) &&
                TryCreateRange(logicalStart, logicalEntry.SectorCount, container.End, out var logicalRange) &&
                logicalRange.Start >= container.Start && logicalRange.End <= container.End &&
                !logicalRange.Contains(currentEbrLba) &&
                !occupied.Any(existing => existing.Overlaps(logicalRange)))
            {
                occupied.Add(logicalRange);
                candidates.Add(new PartitionCandidate(
                    logicalRange,
                    PartitionDiscoverySource.EbrLogical,
                    $"EBR 链第 {linkIndex + 1} 个逻辑分区，EBR LBA {currentEbrLba}，类型 0x{logicalEntry.Type:X2}",
                    container.Start));
            }

            // The second entry points to the next EBR relative to the extended container start.
            var nextEntry = ReadMbrEntry(sector, 1);
            if (!nextEntry.IsExtendedPartition || nextEntry.FirstLba == 0 || nextEntry.SectorCount == 0 ||
                !TryAdd(container.Start, nextEntry.FirstLba, out var nextEbrLba) ||
                !TryCreateRange(nextEbrLba, nextEntry.SectorCount, container.End, out var linkRange) ||
                linkRange.Start < container.Start || linkRange.End > container.End ||
                !container.Contains(nextEbrLba) || visited.Contains(nextEbrLba) ||
                occupied.Any(range => range.Contains(nextEbrLba))) break;

            currentEbrLba = nextEbrLba;
        }
    }

    private static MbrEntry ReadMbrEntry(ReadOnlySpan<byte> sector, int slot)
    {
        var entry = sector.Slice(446 + slot * 16, 16);
        return new MbrEntry(
            slot,
            entry[4],
            BinaryPrimitives.ReadUInt32LittleEndian(entry[8..12]),
            BinaryPrimitives.ReadUInt32LittleEndian(entry[12..16]));
    }

    private static bool TryCreateRange(ulong startLba, ulong sectorCount, ulong upperExclusive, out LbaRange range)
    {
        range = default;
        if (startLba == 0 || sectorCount == 0 || startLba >= upperExclusive || sectorCount > upperExclusive - startLba)
            return false;
        range = new LbaRange(startLba, startLba + sectorCount);
        return true;
    }

    private static bool TryAdd(ulong left, ulong right, out ulong result)
    {
        result = 0;
        if (right > ulong.MaxValue - left) return false;
        result = left + right;
        return true;
    }

    private static bool TryDescribeBackupBootSector(ReadOnlySpan<byte> boot, ulong absolute, ulong deviceLength,
        out ulong originalStart, out FileSystemKind fileSystem, out ulong length)
    {
        originalStart = 0; fileSystem = FileSystemKind.Unknown; length = 0;
        try
        {
            if (boot.Slice(3, 8).SequenceEqual("NTFS    "u8))
            {
                var parsed = NtfsBootSector.Parse(boot);
                length = checked(parsed.TotalSectors * parsed.BytesPerSector);
                var end = checked(absolute + parsed.BytesPerSector);
                if (end < length) return false;
                originalStart = end - length; fileSystem = FileSystemKind.Ntfs;
            }
            else if (boot.Slice(3, 8).SequenceEqual("EXFAT   "u8))
            {
                var parsed = ExFatBootSector.Parse(boot);
                length = checked(BinaryPrimitives.ReadUInt64LittleEndian(boot[72..80]) * parsed.BytesPerSector);
                var backupDistance = checked(12UL * parsed.BytesPerSector);
                if (absolute < backupDistance) return false;
                originalStart = absolute - backupDistance; fileSystem = FileSystemKind.ExFat;
            }
            else if (boot.Slice(82, 5).SequenceEqual("FAT32"u8))
            {
                var parsed = Fat32BootSector.Parse(boot);
                if (parsed.BackupBootSector is 0 or ushort.MaxValue || parsed.BackupBootSector >= parsed.ReservedSectors)
                    return false;
                length = checked((ulong)parsed.TotalSectors * parsed.BytesPerSector);
                var backupDistance = checked((ulong)parsed.BackupBootSector * parsed.BytesPerSector);
                if (absolute < backupDistance) return false;
                originalStart = absolute - backupDistance; fileSystem = FileSystemKind.Fat32;
            }
            else return false;
            return length > 0 && originalStart % parsedSectorAlignment(boot, fileSystem) == 0 && originalStart <= deviceLength && length <= deviceLength - originalStart;
        }
        catch (Exception ex) when (ex is InvalidDataException or OverflowException or ArgumentOutOfRangeException or DivideByZeroException) { return false; }

        static ulong parsedSectorAlignment(ReadOnlySpan<byte> value, FileSystemKind kind) => kind switch
        {
            FileSystemKind.ExFat => 1UL << value[108],
            _ => BinaryPrimitives.ReadUInt16LittleEndian(value[11..13])
        };
    }

    private static bool TryDescribeBackupBootSector(byte[] buffer, int offset, ulong absolute, ulong deviceLength,
        out ulong originalStart, out FileSystemKind fileSystem, out ulong length)
        => TryDescribeBackupBootSector(buffer.AsSpan(offset, 512), absolute, deviceLength,
            out originalStart, out fileSystem, out length);

    private static async Task<IReadOnlyList<PartitionDescriptor>?> TryReadGptAsync(
        IBlockDevice device, ulong headerLba, bool fromBackup, CancellationToken cancellationToken)
    {
        try
        {
            var sectorSize = checked((int)device.LogicalSectorSize);
            var totalLbas = device.Length / device.LogicalSectorSize;
            if (headerLba >= totalLbas) return null;
            var header = new byte[sectorSize];
            await device.ReadExactlyAsync(checked(headerLba * device.LogicalSectorSize), header, cancellationToken);
            if (!header.AsSpan(0, 8).SequenceEqual("EFI PART"u8)) return null;
            var headerSize = BinaryPrimitives.ReadUInt32LittleEndian(header.AsSpan(12, 4));
            var storedHeaderCrc = BinaryPrimitives.ReadUInt32LittleEndian(header.AsSpan(16, 4));
            if (headerSize < 92 || headerSize > sectorSize || storedHeaderCrc == 0) return null;
            var copy = header.AsSpan(0, checked((int)headerSize)).ToArray();
            copy.AsSpan(16, 4).Clear();
            if (ComputeCrc32(copy) != storedHeaderCrc) return null;
            var currentLba = BinaryPrimitives.ReadUInt64LittleEndian(header.AsSpan(24, 8));
            var alternateLba = BinaryPrimitives.ReadUInt64LittleEndian(header.AsSpan(32, 8));
            if (currentLba != headerLba || alternateLba >= totalLbas || alternateLba == currentLba) return null;
            var entriesLba = BinaryPrimitives.ReadUInt64LittleEndian(header.AsSpan(72, 8));
            var entryCount = BinaryPrimitives.ReadUInt32LittleEndian(header.AsSpan(80, 4));
            var entrySize = BinaryPrimitives.ReadUInt32LittleEndian(header.AsSpan(84, 4));
            if (entrySize < 128 || entrySize > 4096 || entryCount == 0 || entryCount > 16384) return null;
            var tableLength = checked((ulong)entryCount * entrySize);
            var tableOffset = checked(entriesLba * device.LogicalSectorSize);
            if (tableLength > 64UL * 1024 * 1024 || tableOffset > device.Length || tableLength > device.Length - tableOffset) return null;
            var table = new byte[checked((int)tableLength)]; await device.ReadExactlyAsync(tableOffset, table, cancellationToken);
            var storedTableCrc = BinaryPrimitives.ReadUInt32LittleEndian(header.AsSpan(88, 4));
            if (storedTableCrc == 0 || ComputeCrc32(table) != storedTableCrc) return null;

            var result = new List<PartitionDescriptor>();
            for (uint index = 0; index < entryCount; index++)
            {
                var entry = ParseGptEntry(table, index, entrySize);
                if (entry is null || entry.LastLba < entry.FirstLba || entry.LastLba >= totalLbas) continue;
                var partOffset = checked(entry.FirstLba * device.LogicalSectorSize);
                var length = checked((entry.LastLba - entry.FirstLba + 1) * device.LogicalSectorSize);
                var fileSystem = entry.TypeGuid == MicrosoftBasicData ? await DetectFileSystemAsync(device, partOffset, cancellationToken) : FileSystemKind.Unknown;
                var fallbackName = fromBackup ? $"GPT备份表分区 {result.Count + 1}" : $"GPT分区 {result.Count + 1}";
                result.Add(new PartitionDescriptor(result.Count + 1, partOffset, length, entry.TypeGuid, entry.PartitionGuid,
                    string.IsNullOrWhiteSpace(entry.Name) ? fallbackName : fromBackup ? $"{entry.Name}（GPT备份表）" : entry.Name, fileSystem, true,
                    Evidence: new PartitionEvidence(fromBackup ? ScanTargetOrigin.BackupPartitionTable : ScanTargetOrigin.PrimaryPartitionTable,
                        true, fileSystem != FileSystemKind.Unknown, fromBackup, false,
                        fromBackup ? "主GPT不可用，备份GPT头和分区项CRC验证通过。" : "主GPT头和分区项CRC验证通过。")));
            }
            return result;
        }
        catch (Exception ex) when (ex is IOException or InvalidDataException or EndOfStreamException or OverflowException or ArgumentOutOfRangeException) { return null; }
    }

    private static GptEntry? ParseGptEntry(byte[] table, uint index, uint entrySize)
    {
        var entry = table.AsSpan(checked((int)((ulong)index * entrySize)), checked((int)entrySize));
        var typeGuid = new Guid(entry.Slice(0, 16));
        if (typeGuid == Guid.Empty) return null;
        var partitionGuid = new Guid(entry.Slice(16, 16));
        var firstLba = BinaryPrimitives.ReadUInt64LittleEndian(entry.Slice(32, 8));
        var lastLba = BinaryPrimitives.ReadUInt64LittleEndian(entry.Slice(40, 8));
        var nameLength = Math.Min(72, checked((int)entrySize - 56));
        var name = Encoding.Unicode.GetString(entry.Slice(56, nameLength)).TrimEnd('\0');
        return new(typeGuid, partitionGuid, firstLba, lastLba, name);
    }

    private sealed record GptEntry(Guid TypeGuid, Guid PartitionGuid, ulong FirstLba, ulong LastLba, string Name);

    private static uint ComputeCrc32(ReadOnlySpan<byte> bytes)
    {
        var crc = 0xFFFFFFFFu;
        foreach (var value in bytes)
        {
            crc ^= value;
            for (var bit = 0; bit < 8; bit++) crc = (crc & 1) != 0 ? (crc >> 1) ^ 0xEDB88320u : crc >> 1;
        }
        return ~crc;
    }

    private enum PartitionDiscoverySource { MbrPrimary, EbrLogical }

    // This internal representation deliberately keeps discovery source and evidence separate
    // from PartitionDescriptor so future public evidence models can be added without changing
    // the existing ScanAsync contract or persisted PartitionDescriptor JSON shape.
    private sealed record PartitionCandidate(
        LbaRange Range,
        PartitionDiscoverySource Source,
        string Evidence,
        ulong? ContainerStartLba);

    private readonly record struct MbrEntry(int Slot, byte Type, uint FirstLba, uint SectorCount)
    {
        public bool IsExtendedPartition => Type is 0x05 or 0x0F or 0x85;
        public bool IsDataPartition => Type != 0 && Type != 0xEE && !IsExtendedPartition && SectorCount != 0;
    }

    private readonly record struct LbaRange(ulong Start, ulong End)
    {
        public ulong Length => End - Start;
        public bool Contains(ulong lba) => lba >= Start && lba < End;
        public bool Overlaps(LbaRange other) => Start < other.End && other.Start < End;
    }
}
