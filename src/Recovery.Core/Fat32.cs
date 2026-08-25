using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace Recovery.Core;

public sealed record Fat32BootSector(
    ushort BytesPerSector, byte SectorsPerCluster, ushort ReservedSectors, byte NumberOfFats,
    uint FatSizeSectors, uint RootCluster, uint TotalSectors)
{
    public ushort ExtendedFlags { get; init; }
    public ushort BackupBootSector { get; init; }
    public uint ClusterSize => checked((uint)BytesPerSector * SectorsPerCluster);
    public ulong FatOffset => checked((ulong)ReservedSectors * BytesPerSector);
    public ulong DataOffset => checked(((ulong)ReservedSectors + (ulong)NumberOfFats * FatSizeSectors) * BytesPerSector);
    public uint ClusterCount => checked((uint)(((ulong)TotalSectors * BytesPerSector - DataOffset) / ClusterSize));
    public bool FatMirroringDisabled => (ExtendedFlags & 0x0080) != 0;
    public int ActiveFatIndex => ExtendedFlags & 0x000F;

    public static Fat32BootSector Parse(ReadOnlySpan<byte> boot)
    {
        if (boot.Length < 512 || boot[510] != 0x55 || boot[511] != 0xAA || !boot.Slice(82, 5).SequenceEqual("FAT32"u8))
            throw new InvalidDataException("The partition does not contain a valid FAT32 boot sector.");
        var bytesPerSector = BinaryPrimitives.ReadUInt16LittleEndian(boot[11..13]);
        var sectorsPerCluster = boot[13];
        var reserved = BinaryPrimitives.ReadUInt16LittleEndian(boot[14..16]);
        var fats = boot[16];
        var total = BinaryPrimitives.ReadUInt32LittleEndian(boot[32..36]);
        var fatSize = BinaryPrimitives.ReadUInt32LittleEndian(boot[36..40]);
        var extendedFlags = BinaryPrimitives.ReadUInt16LittleEndian(boot[40..42]);
        var root = BinaryPrimitives.ReadUInt32LittleEndian(boot[44..48]);
        var backupBoot = BinaryPrimitives.ReadUInt16LittleEndian(boot[50..52]);
        if (bytesPerSector is < 512 or > 4096 || (bytesPerSector & (bytesPerSector - 1)) != 0 ||
            sectorsPerCluster == 0 || (sectorsPerCluster & (sectorsPerCluster - 1)) != 0 || reserved == 0 || fats is < 1 or > 2 ||
            total == 0 || fatSize == 0 || root < 2)
            throw new InvalidDataException("The FAT32 geometry is invalid.");
        var dataStartSector = checked((ulong)reserved + (ulong)fats * fatSize);
        if (dataStartSector >= total)
            throw new InvalidDataException("The FAT32 data area is outside the volume.");
        var clusterCount = ((ulong)total - dataStartSector) / sectorsPerCluster;
        if (clusterCount == 0 || root >= clusterCount + 2)
            throw new InvalidDataException("The FAT32 root cluster is outside the data area.");
        var fatEntryCapacity = checked((ulong)fatSize * bytesPerSector / 4);
        if (fatEntryCapacity < clusterCount + 2)
            throw new InvalidDataException("The FAT32 allocation table is too small for the declared volume.");
        return new(bytesPerSector, sectorsPerCluster, reserved, fats, fatSize, root, total)
        {
            ExtendedFlags = extendedFlags,
            BackupBootSector = backupBoot
        };
    }
}

public enum Fat32BootCopy
{
    Primary,
    Backup
}

public sealed record Fat32FatCopyStatus(int CopyNumber, bool IsReadable, bool IsValid, string Reason);

public sealed record Fat32ResilienceContext(
    Fat32BootCopy BootCopy,
    ulong BootOffset,
    int PreferredFatCopy,
    IReadOnlyList<Fat32FatCopyStatus> FatCopies,
    bool UsedSecondFatForAnyChain,
    IReadOnlyList<string> Diagnostics)
{
    public bool UsedBackupBootSector => BootCopy == Fat32BootCopy.Backup;
}

public sealed class Fat32ScanResult
{
    internal Fat32ScanResult(Fat32BootSector boot, ulong partitionOffset, IReadOnlyList<RecoveryCandidate> candidates,
        Fat32ResilienceContext? resilience = null)
        => (Boot, PartitionOffset, Candidates, Resilience) = (boot, partitionOffset, candidates,
            resilience ?? CreateDefaultResilience(partitionOffset));
    public Fat32BootSector Boot { get; }
    public ulong PartitionOffset { get; }
    public IReadOnlyList<RecoveryCandidate> Candidates { get; }
    public Fat32ResilienceContext Resilience { get; }
    public static Fat32ScanResult CreateRecoveryContext(Fat32BootSector boot, ulong partitionOffset) => new(boot, partitionOffset, []);

    private static Fat32ResilienceContext CreateDefaultResilience(ulong partitionOffset) =>
        new(Fat32BootCopy.Primary, partitionOffset, 1, [], false, []);
}

public sealed class Fat32Scanner
{
    private const uint EndOfChain = 0x0FFFFFF8;
    private readonly IBlockDevice _device;
    private readonly ulong _partitionOffset;
    private readonly IProgress<ScanProgress>? _progress;
    private Fat32BootSector _boot = null!;
    private byte[] _primaryFat = [];
    private byte[] _secondaryFat = [];
    private int _preferredFatIndex;
    private bool _usedSecondFatForAnyChain;
    private readonly List<string> _diagnostics = [];
    private readonly List<RecoveryCandidate> _candidates = [];
    private readonly HashSet<uint> _visitedDirectories = [];

    public Fat32Scanner(IBlockDevice device, ulong partitionOffset, IProgress<ScanProgress>? progress = null)
        => (_device, _partitionOffset, _progress) = (device, partitionOffset, progress);

    public async Task<Fat32ScanResult> ScanAsync(CancellationToken cancellationToken = default)
    {
        var bootSelection = await ReadBootSectorAsync(cancellationToken);
        _boot = bootSelection.Boot;
        ValidateVolumeBounds(_boot);
        var fatBytes = checked((ulong)_boot.FatSizeSectors * _boot.BytesPerSector);
        if (fatBytes > 512UL * 1024 * 1024) throw new InvalidDataException("The FAT32 allocation table is unreasonably large.");
        var fatStatuses = await ReadAndAssessFatCopiesAsync(checked((int)fatBytes), cancellationToken);
        SelectPreferredFat(fatStatuses);
        await ScanDirectoryAsync(_boot.RootCluster, string.Empty, false, cancellationToken);
        var resilience = new Fat32ResilienceContext(
            bootSelection.Copy,
            bootSelection.Offset,
            _preferredFatIndex + 1,
            fatStatuses,
            _usedSecondFatForAnyChain,
            _diagnostics.ToArray());
        return new(_boot, _partitionOffset, _candidates, resilience);
    }

    private async Task<BootSelection> ReadBootSectorAsync(CancellationToken cancellationToken)
    {
        var primaryBytes = new byte[512];
        string primaryFailure;
        try
        {
            await _device.ReadExactlyAsync(_partitionOffset, primaryBytes, cancellationToken);
            var primary = Fat32BootSector.Parse(primaryBytes);
            ValidateVolumeBounds(primary);
            return new(primary, Fat32BootCopy.Primary, _partitionOffset);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception exception) when (exception is IOException or InvalidDataException or OverflowException or ArgumentOutOfRangeException)
        {
            primaryFailure = exception.Message;
        }

        var declaredBytesPerSector = BinaryPrimitives.ReadUInt16LittleEndian(primaryBytes.AsSpan(11, 2));
        var declaredBackupSector = BinaryPrimitives.ReadUInt16LittleEndian(primaryBytes.AsSpan(50, 2));
        var sectorSizes = new HashSet<ushort>();
        if (IsSupportedSectorSize(declaredBytesPerSector)) sectorSizes.Add(declaredBytesPerSector);
        if (_device.LogicalSectorSize <= ushort.MaxValue && IsSupportedSectorSize((ushort)_device.LogicalSectorSize))
            sectorSizes.Add((ushort)_device.LogicalSectorSize);
        sectorSizes.UnionWith([512, 1024, 2048, 4096]);

        var backupSectors = new HashSet<ushort> { 6 };
        if (declaredBackupSector is > 0 and <= 128) backupSectors.Add(declaredBackupSector);
        var failures = new List<string>();
        foreach (var backupSector in backupSectors)
        {
            foreach (var sectorSize in sectorSizes)
            {
                cancellationToken.ThrowIfCancellationRequested();
                ulong relativeOffset;
                ulong absoluteOffset;
                try
                {
                    relativeOffset = checked((ulong)backupSector * sectorSize);
                    absoluteOffset = checked(_partitionOffset + relativeOffset);
                }
                catch (OverflowException)
                {
                    continue;
                }
                if (absoluteOffset == _partitionOffset || absoluteOffset > _device.Length || _device.Length - absoluteOffset < 512)
                    continue;
                var backupBytes = new byte[512];
                try
                {
                    await _device.ReadExactlyAsync(absoluteOffset, backupBytes, cancellationToken);
                    var backup = Fat32BootSector.Parse(backupBytes);
                    ValidateVolumeBounds(backup);
                    if (backupSector >= backup.ReservedSectors)
                        throw new InvalidDataException("The candidate backup boot sector is outside the reserved area.");
                    if (backup.BackupBootSector is not 0 and not ushort.MaxValue && backup.BackupBootSector != backupSector)
                        throw new InvalidDataException("The backup boot-sector index does not match its BPB.");
                    _diagnostics.Add($"主FAT32引导区无效（{primaryFailure}），已只读使用备用引导区：保留区第 {backupSector} 扇区。");
                    return new(backup, Fat32BootCopy.Backup, absoluteOffset);
                }
                catch (OperationCanceledException)
                {
                    throw;
                }
                catch (Exception exception) when (exception is IOException or InvalidDataException or OverflowException or ArgumentOutOfRangeException)
                {
                    failures.Add($"sector={backupSector}, bytes={sectorSize}: {exception.Message}");
                }
            }
        }

        var detail = failures.Count == 0 ? "未找到可读取的备用位置。" : string.Join(" | ", failures.Take(4));
        throw new InvalidDataException($"The primary FAT32 boot sector is invalid and no valid backup was found. Primary: {primaryFailure} Backup: {detail}");
    }

    private void ValidateVolumeBounds(Fat32BootSector boot)
    {
        if (_partitionOffset > _device.Length)
            throw new InvalidDataException("The FAT32 partition offset is outside the source device.");
        var volumeBytes = checked((ulong)boot.TotalSectors * boot.BytesPerSector);
        if (volumeBytes > _device.Length - _partitionOffset)
            throw new InvalidDataException("The FAT32 volume extends beyond the source device.");
    }

    private async Task<IReadOnlyList<Fat32FatCopyStatus>> ReadAndAssessFatCopiesAsync(int fatByteCount,
        CancellationToken cancellationToken)
    {
        var statuses = new List<Fat32FatCopyStatus>(_boot.NumberOfFats);
        for (var index = 0; index < _boot.NumberOfFats; index++)
        {
            byte[] fat = [];
            try
            {
                fat = new byte[fatByteCount];
                var offset = checked(_partitionOffset + _boot.FatOffset + (ulong)index * (ulong)fatByteCount);
                await _device.ReadExactlyAsync(offset, fat, cancellationToken);
                var assessment = AssessFatCopy(fat);
                statuses.Add(new(index + 1, true, assessment.IsValid, assessment.Reason));
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception exception) when (exception is IOException or OverflowException or ArgumentOutOfRangeException)
            {
                fat = [];
                statuses.Add(new(index + 1, false, false, $"读取失败：{exception.Message}"));
            }
            if (index == 0) _primaryFat = fat;
            else _secondaryFat = fat;
        }
        return statuses;
    }

    private FatAssessment AssessFatCopy(byte[] fat)
    {
        if (fat.Length < 12) return new(false, "FAT长度不足，无法读取保留项。");
        var first = GetFat(fat, 0);
        var second = GetFat(fat, 1);
        var mediaDescriptor = first & 0xFF;
        var validMediaDescriptor = mediaDescriptor == 0xF0 || mediaDescriptor is >= 0xF8 and <= 0xFF;
        if ((first & 0x0FFFFF00) != 0x0FFFFF00 || !validMediaDescriptor)
            return new(false, "FAT保留项0无效。");
        if (second < EndOfChain)
            return new(false, "FAT保留项1无效。");
        var rootNext = GetFat(fat, _boot.RootCluster);
        var rootValid = rootNext >= EndOfChain || rootNext is >= 2 and < 0x0FFFFFF0 && rootNext < _boot.ClusterCount + 2;
        if (!rootValid)
            return new(false, "根目录簇链起始项无效。");
        return new(true, "保留项和根目录簇链起始项有效。");
    }

    private void SelectPreferredFat(IReadOnlyList<Fat32FatCopyStatus> statuses)
    {
        if (!_primaryFat.Any() && !_secondaryFat.Any())
            throw new InvalidDataException("No FAT32 allocation table copy could be read.");

        if (_boot.FatMirroringDisabled)
        {
            var active = _boot.ActiveFatIndex;
            if (active < statuses.Count && statuses[active].IsValid)
            {
                _preferredFatIndex = active;
                if (active == 1)
                {
                    _usedSecondFatForAnyChain = true;
                    AddDiagnosticOnce("FAT镜像已禁用，BPB指定FAT2为活动分配表。");
                }
                return;
            }
            AddDiagnosticOnce("BPB指定的活动FAT无效，已根据两份FAT的结构检查选择可用副本。");
        }

        if (statuses.Count > 0 && statuses[0].IsValid)
        {
            _preferredFatIndex = 0;
            return;
        }
        if (statuses.Count > 1 && statuses[1].IsValid)
        {
            _preferredFatIndex = 1;
            _usedSecondFatForAnyChain = true;
            AddDiagnosticOnce("FAT1基本结构无效，已只读回退到FAT2。");
            return;
        }

        _preferredFatIndex = _primaryFat.Length > 0 ? 0 : 1;
        if (_preferredFatIndex == 1) _usedSecondFatForAnyChain = true;
        AddDiagnosticOnce("可读取的FAT副本均未通过基本结构检查；仅按可验证的簇链范围继续扫描。");
    }

    private static bool IsSupportedSectorSize(ushort size) => size is >= 512 and <= 4096 && (size & (size - 1)) == 0;

    private static bool IsBetterChain(FatChainResolution candidate, FatChainResolution current)
    {
        if (candidate.IsValid != current.IsValid) return candidate.IsValid;
        if (candidate.UsedContiguousFallback != current.UsedContiguousFallback) return !candidate.UsedContiguousFallback;
        return candidate.Extents.Count > current.Extents.Count;
    }

    private void AddDiagnosticOnce(string message)
    {
        if (!_diagnostics.Contains(message, StringComparer.Ordinal)) _diagnostics.Add(message);
    }

    private async Task ScanDirectoryAsync(uint firstCluster, string path, bool deletedDirectory, CancellationToken cancellationToken)
    {
        if (firstCluster < 2 || firstCluster >= _boot.ClusterCount + 2 || !_visitedDirectories.Add(firstCluster)) return;
        var directoryChain = ResolveChain(firstCluster, 256UL * 1024 * 1024, allowContiguousFallback: false, expectEndOfChain: true);
        var clusters = directoryChain.Extents;
        var pendingLfn = new List<byte[]>();
        foreach (var cluster in clusters)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var data = new byte[_boot.ClusterSize];
            var directoryCluster = checked((uint)cluster.LogicalCluster);
            await _device.ReadExactlyAsync(ClusterOffset(directoryCluster), data, cancellationToken);
            for (var offset = 0; offset + 32 <= data.Length; offset += 32)
            {
                var parsedEntry = ParseDirectoryEntry(data, offset, pendingLfn);
                if (parsedEntry.Kind == FatDirectoryEntryKind.End) break;
                if (parsedEntry.Kind == FatDirectoryEntryKind.Skip) continue;
                var deleted = parsedEntry.Deleted;
                var directory = parsedEntry.IsDirectory;
                var first = parsedEntry.FirstCluster;
                var size = parsedEntry.Size;
                var name = parsedEntry.Name;
                if (string.IsNullOrWhiteSpace(name) || name is "." or "..") continue;
                var fullPath = string.IsNullOrEmpty(path) ? name : Path.Combine(path, name);
                if (directory)
                {
                    if (first >= 2) await ScanDirectoryAsync(first, fullPath, deletedDirectory || deleted, cancellationToken);
                    continue;
                }
                if (!deleted || size == 0 || first < 2) continue;
                var required = ((ulong)size + _boot.ClusterSize - 1) / _boot.ClusterSize;
                var fileChain = ResolveChain(first, size, allowContiguousFallback: true, expectEndOfChain: false);
                var extents = fileChain.Extents.Take(checked((int)Math.Min(required, int.MaxValue))).ToArray();
                var inferred = fileChain.UsedContiguousFallback && required > 1;
                var selectedFat = GetFatCopy(fileChain.FatIndex);
                var allocated = extents.Any(extent => GetFat(selectedFat, checked((uint)extent.LogicalCluster)) != 0);
                var quality = allocated ? RecoveryQuality.Overwritten : inferred ? RecoveryQuality.Partial : RecoveryQuality.Good;
                var fatReason = fileChain.FatIndex == 1 ? "FAT1链无效或不完整，已使用FAT2只读解析。" : string.Empty;
                var chainReason = fileChain.IsValid ? string.Empty : " 簇链未完整终止，结果按可验证范围返回。";
                _candidates.Add(new RecoveryCandidate
                {
                    RecordNumber = checked((long)(ClusterOffset(directoryCluster) + (ulong)offset)), Name = name, OriginalPath = fullPath,
                    Size = size, IsDeleted = true, Extents = extents, FileSystem = FileSystemKind.Fat32,
                    SourceOffset = ClusterOffset(first), Discovery = RecoveryDiscovery.FatMetadata, Quality = quality,
                    QualityReason = string.Join(' ', new[]
                    {
                        allocated ? "一个或多个原簇已重新分配。" : inferred ? "FAT链已清除，按连续簇推断；原文件若有碎片可能不完整。" : "原FAT簇链仍可用。",
                        fatReason,
                        chainReason
                    }.Where(reason => !string.IsNullOrWhiteSpace(reason))),
                    ModifiedUtc = parsedEntry.ModifiedUtc
                });
                _progress?.Report(new("扫描 FAT32 元数据", ClusterOffset(directoryCluster), _device.Length, _candidates.Count, fullPath));
            }
        }
    }

    private static ParsedFatDirectoryEntry ParseDirectoryEntry(byte[] data, int offset, List<byte[]> pendingLfn)
    {
        var entry = data.AsSpan(offset, 32);
        if (entry[0] == 0x00)
        {
            pendingLfn.Clear();
            return new(FatDirectoryEntryKind.End, false, false, 0, 0, string.Empty, null);
        }
        if (entry[11] == 0x0F)
        {
            pendingLfn.Add(entry.ToArray());
            return new(FatDirectoryEntryKind.Skip, false, false, 0, 0, string.Empty, null);
        }
        if ((entry[11] & 0x08) != 0)
        {
            pendingLfn.Clear();
            return new(FatDirectoryEntryKind.Skip, false, false, 0, 0, string.Empty, null);
        }

        var deleted = entry[0] == 0xE5;
        var directory = (entry[11] & 0x10) != 0;
        var first = ((uint)BinaryPrimitives.ReadUInt16LittleEndian(entry[20..22]) << 16) |
                    BinaryPrimitives.ReadUInt16LittleEndian(entry[26..28]);
        var size = BinaryPrimitives.ReadUInt32LittleEndian(entry[28..32]);
        var name = DecodeLongName(pendingLfn, deleted) ?? DecodeShortName(entry, deleted);
        var modifiedUtc = DecodeModified(entry);
        pendingLfn.Clear();
        return new(FatDirectoryEntryKind.Entry, deleted, directory, first, size, name, modifiedUtc);
    }

    private enum FatDirectoryEntryKind
    {
        End,
        Skip,
        Entry
    }

    private readonly record struct ParsedFatDirectoryEntry(
        FatDirectoryEntryKind Kind,
        bool Deleted,
        bool IsDirectory,
        uint FirstCluster,
        uint Size,
        string Name,
        DateTime? ModifiedUtc);

    private FatChainResolution ResolveChain(uint firstCluster, ulong byteLength, bool allowContiguousFallback, bool expectEndOfChain)
    {
        var needed = Math.Max(1UL, (byteLength + _boot.ClusterSize - 1) / _boot.ClusterSize);
        var preferred = WalkChain(GetFatCopy(_preferredFatIndex), _preferredFatIndex, firstCluster, needed,
            allowContiguousFallback, expectEndOfChain);
        var alternateIndex = _preferredFatIndex == 0 ? 1 : 0;
        var alternateFat = GetFatCopy(alternateIndex);
        if (alternateFat.Length == 0) return preferred;
        var alternate = WalkChain(alternateFat, alternateIndex, firstCluster, needed, allowContiguousFallback, expectEndOfChain);
        var selected = IsBetterChain(alternate, preferred) ? alternate : preferred;
        if (selected.FatIndex == 1)
        {
            _usedSecondFatForAnyChain = true;
            if (preferred.FatIndex == 0 && selected != preferred)
                AddDiagnosticOnce("FAT1中的一条或多条簇链无效或不完整，扫描时已对相应链回退到FAT2。");
        }
        return selected;
    }

    private FatChainResolution WalkChain(byte[] fat, int fatIndex, uint firstCluster, ulong needed,
        bool allowContiguousFallback, bool expectEndOfChain)
    {
        if (fat.Length == 0) return new([], fatIndex, false, false, "FAT副本不可读。");
        var extents = new List<DataExtent>(checked((int)Math.Min(needed, 4096UL)));
        var current = firstCluster;
        var seen = new HashSet<uint>();
        var contiguousFallback = false;
        for (ulong index = 0; index < needed; index++)
        {
            if (current < 2 || current >= _boot.ClusterCount + 2)
                return new(extents, fatIndex, contiguousFallback, false, "簇号超出数据区。 ");
            if (!seen.Add(current))
                return new(extents, fatIndex, contiguousFallback, false, "簇链存在循环。 ");
            extents.Add(new DataExtent(current, 1));
            var next = GetFat(fat, current);
            if (next >= EndOfChain)
            {
                var valid = expectEndOfChain || index + 1 >= needed;
                return new(extents, fatIndex, contiguousFallback, valid, valid ? null : "簇链提前结束。");
            }
            if (next == 0)
            {
                if (!allowContiguousFallback)
                    return new(extents, fatIndex, contiguousFallback, false, "簇链在空闲项处中断。");
                contiguousFallback = true;
                current++;
            }
            else if (next is >= 2 and < 0x0FFFFFF0 && next < _boot.ClusterCount + 2) current = next;
            else return new(extents, fatIndex, contiguousFallback, false, "簇链包含保留、坏簇或越界项。");
        }
        return new(extents, fatIndex, contiguousFallback, !expectEndOfChain, expectEndOfChain ? "目录链达到安全读取上限。" : null);
    }

    internal void InitializeForRecovery(Fat32BootSector boot) => _boot = boot;
    internal ulong ClusterOffset(uint cluster) => checked(_partitionOffset + _boot.DataOffset + (ulong)(cluster - 2) * _boot.ClusterSize);
    private static uint GetFat(byte[] fat, uint cluster)
    {
        var offset = checked((int)((ulong)cluster * 4));
        return offset + 4 <= fat.Length ? BinaryPrimitives.ReadUInt32LittleEndian(fat.AsSpan(offset, 4)) & 0x0FFFFFFF : EndOfChain;
    }

    private byte[] GetFatCopy(int index) => index == 1 ? _secondaryFat : _primaryFat;

    private sealed record BootSelection(Fat32BootSector Boot, Fat32BootCopy Copy, ulong Offset);
    private sealed record FatAssessment(bool IsValid, string Reason);
    private sealed record FatChainResolution(IReadOnlyList<DataExtent> Extents, int FatIndex,
        bool UsedContiguousFallback, bool IsValid, string? Reason);

    private static string? DecodeLongName(List<byte[]> entries, bool deleted)
    {
        if (entries.Count == 0 || (!deleted && entries.All(entry => (entry[0] & 0x1F) == 0))) return null;
        var ordered = deleted ? entries.AsEnumerable().Reverse() : entries.OrderBy(entry => entry[0] & 0x1F);
        var bytes = new List<byte>();
        foreach (var entry in ordered)
        {
            bytes.AddRange(entry.AsSpan(1, 10).ToArray()); bytes.AddRange(entry.AsSpan(14, 12).ToArray()); bytes.AddRange(entry.AsSpan(28, 4).ToArray());
        }
        var name = Encoding.Unicode.GetString(bytes.ToArray()).Split('\0', '\uffff')[0];
        return string.IsNullOrWhiteSpace(name) ? null : NtfsScanner.SanitizePathComponent(name);
    }

    private static string DecodeShortName(ReadOnlySpan<byte> entry, bool deleted)
    {
        var stem = Encoding.ASCII.GetString(entry[0..8]).Trim();
        if (deleted && stem.Length > 0) stem = "_" + stem[1..];
        var extension = Encoding.ASCII.GetString(entry[8..11]).Trim();
        return NtfsScanner.SanitizePathComponent(string.IsNullOrEmpty(extension) ? stem : $"{stem}.{extension}");
    }

    private static DateTime? DecodeModified(ReadOnlySpan<byte> entry)
    {
        var time = BinaryPrimitives.ReadUInt16LittleEndian(entry[22..24]);
        var date = BinaryPrimitives.ReadUInt16LittleEndian(entry[24..26]);
        if (date == 0) return null;
        try { return new DateTime(1980 + (date >> 9), (date >> 5) & 15, date & 31, time >> 11, (time >> 5) & 63, (time & 31) * 2, DateTimeKind.Local).ToUniversalTime(); }
        catch (ArgumentOutOfRangeException) { return null; }
    }
}

public static partial class RecoveryWriter
{
    public static async Task<RecoveryResult> RecoverFat32Async(IBlockDevice source, Fat32ScanResult scan, RecoveryCandidate candidate,
        string destinationRoot, IProgress<ScanProgress>? progress = null, CancellationToken cancellationToken = default)
    {
        if (candidate.FileSystem != FileSystemKind.Fat32 || !candidate.IsDeleted) throw new InvalidOperationException("Only deleted FAT32 candidates can be recovered.");
        var output = EnsureUniqueFatPath(Path.Combine(Path.GetFullPath(destinationRoot), candidate.OriginalPath));
        Directory.CreateDirectory(Path.GetDirectoryName(output)!);
        await using var file = new FileStream(output, FileMode.CreateNew, FileAccess.Write, FileShare.None, 1024 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan);
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var buffer = new byte[1024 * 1024]; ulong written = 0;
        foreach (var extent in candidate.Extents)
        {
            var cluster = checked((uint)extent.LogicalCluster);
            var remaining = Math.Min((ulong)scan.Boot.ClusterSize, candidate.Size - written);
            var offset = checked(scan.PartitionOffset + scan.Boot.DataOffset + (ulong)(cluster - 2) * scan.Boot.ClusterSize);
            while (remaining > 0)
            {
                var count = checked((int)Math.Min((ulong)buffer.Length, remaining));
                await source.ReadExactlyAsync(offset, buffer.AsMemory(0, count), cancellationToken);
                await file.WriteAsync(buffer.AsMemory(0, count), cancellationToken); hash.AppendData(buffer.AsSpan(0, count));
                offset += (ulong)count; remaining -= (ulong)count; written += (ulong)count;
                progress?.Report(new("正在恢复 FAT32 文件", written, candidate.Size, 1, candidate.Name));
            }
            if (written >= candidate.Size) break;
        }
        await file.FlushAsync(cancellationToken);
        var digest = Convert.ToHexString(hash.GetHashAndReset()).ToLowerInvariant();
        await file.DisposeAsync();
        return await FinalizeResultAsync(output, written, digest, written == candidate.Size, cancellationToken);
    }

    private static string EnsureUniqueFatPath(string path)
    {
        if (!File.Exists(path)) return path;
        var directory = Path.GetDirectoryName(path) ?? string.Empty; var stem = Path.GetFileNameWithoutExtension(path); var extension = Path.GetExtension(path);
        for (var i = 1; i < 100000; i++) { var next = Path.Combine(directory, $"{stem} ({i}){extension}"); if (!File.Exists(next)) return next; }
        throw new IOException("Unable to allocate a unique FAT32 recovery path.");
    }
}
