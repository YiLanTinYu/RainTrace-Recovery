using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace Recovery.Core;

public sealed record Fat32BootSector(
    ushort BytesPerSector, byte SectorsPerCluster, ushort ReservedSectors, byte NumberOfFats,
    uint FatSizeSectors, uint RootCluster, uint TotalSectors)
{
    public uint ClusterSize => checked((uint)BytesPerSector * SectorsPerCluster);
    public ulong FatOffset => checked((ulong)ReservedSectors * BytesPerSector);
    public ulong DataOffset => checked(((ulong)ReservedSectors + (ulong)NumberOfFats * FatSizeSectors) * BytesPerSector);
    public uint ClusterCount => checked((uint)(((ulong)TotalSectors * BytesPerSector - DataOffset) / ClusterSize));

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
        var root = BinaryPrimitives.ReadUInt32LittleEndian(boot[44..48]);
        if (bytesPerSector is < 512 or > 4096 || (bytesPerSector & (bytesPerSector - 1)) != 0 ||
            sectorsPerCluster == 0 || (sectorsPerCluster & (sectorsPerCluster - 1)) != 0 || reserved == 0 || fats is < 1 or > 2 ||
            total == 0 || fatSize == 0 || root < 2)
            throw new InvalidDataException("The FAT32 geometry is invalid.");
        return new(bytesPerSector, sectorsPerCluster, reserved, fats, fatSize, root, total);
    }
}

public sealed class Fat32ScanResult
{
    internal Fat32ScanResult(Fat32BootSector boot, ulong partitionOffset, IReadOnlyList<RecoveryCandidate> candidates)
        => (Boot, PartitionOffset, Candidates) = (boot, partitionOffset, candidates);
    public Fat32BootSector Boot { get; }
    public ulong PartitionOffset { get; }
    public IReadOnlyList<RecoveryCandidate> Candidates { get; }
    public static Fat32ScanResult CreateRecoveryContext(Fat32BootSector boot, ulong partitionOffset) => new(boot, partitionOffset, []);
}

public sealed class Fat32Scanner
{
    private const uint EndOfChain = 0x0FFFFFF8;
    private readonly IBlockDevice _device;
    private readonly ulong _partitionOffset;
    private readonly IProgress<ScanProgress>? _progress;
    private Fat32BootSector _boot = null!;
    private byte[] _fat = [];
    private readonly List<RecoveryCandidate> _candidates = [];
    private readonly HashSet<uint> _visitedDirectories = [];

    public Fat32Scanner(IBlockDevice device, ulong partitionOffset, IProgress<ScanProgress>? progress = null)
        => (_device, _partitionOffset, _progress) = (device, partitionOffset, progress);

    public async Task<Fat32ScanResult> ScanAsync(CancellationToken cancellationToken = default)
    {
        var bootBytes = new byte[512];
        await _device.ReadExactlyAsync(_partitionOffset, bootBytes, cancellationToken);
        _boot = Fat32BootSector.Parse(bootBytes);
        var fatBytes = checked((ulong)_boot.FatSizeSectors * _boot.BytesPerSector);
        if (fatBytes > 512UL * 1024 * 1024) throw new InvalidDataException("The FAT32 allocation table is unreasonably large.");
        _fat = new byte[checked((int)fatBytes)];
        await _device.ReadExactlyAsync(checked(_partitionOffset + _boot.FatOffset), _fat, cancellationToken);
        await ScanDirectoryAsync(_boot.RootCluster, string.Empty, false, cancellationToken);
        return new(_boot, _partitionOffset, _candidates);
    }

    private async Task ScanDirectoryAsync(uint firstCluster, string path, bool deletedDirectory, CancellationToken cancellationToken)
    {
        if (firstCluster < 2 || firstCluster >= _boot.ClusterCount + 2 || !_visitedDirectories.Add(firstCluster)) return;
        var clusters = BuildChain(firstCluster, 256UL * 1024 * 1024, deletedDirectory).ToArray();
        var pendingLfn = new List<byte[]>();
        foreach (var cluster in clusters)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var data = new byte[_boot.ClusterSize];
            var directoryCluster = checked((uint)cluster.LogicalCluster);
            await _device.ReadExactlyAsync(ClusterOffset(directoryCluster), data, cancellationToken);
            for (var offset = 0; offset + 32 <= data.Length; offset += 32)
            {
                var entry = data.AsSpan(offset, 32);
                if (entry[0] == 0x00) { pendingLfn.Clear(); break; }
                if (entry[11] == 0x0F) { pendingLfn.Add(entry.ToArray()); continue; }
                if ((entry[11] & 0x08) != 0) { pendingLfn.Clear(); continue; }
                var deleted = entry[0] == 0xE5;
                var directory = (entry[11] & 0x10) != 0;
                var first = ((uint)BinaryPrimitives.ReadUInt16LittleEndian(entry[20..22]) << 16) | BinaryPrimitives.ReadUInt16LittleEndian(entry[26..28]);
                var size = BinaryPrimitives.ReadUInt32LittleEndian(entry[28..32]);
                var name = DecodeLongName(pendingLfn, deleted) ?? DecodeShortName(entry, deleted);
                pendingLfn.Clear();
                if (string.IsNullOrWhiteSpace(name) || name is "." or "..") continue;
                var fullPath = string.IsNullOrEmpty(path) ? name : Path.Combine(path, name);
                if (directory)
                {
                    if (first >= 2) await ScanDirectoryAsync(first, fullPath, deletedDirectory || deleted, cancellationToken);
                    continue;
                }
                if (!deleted || size == 0 || first < 2) continue;
                var required = ((ulong)size + _boot.ClusterSize - 1) / _boot.ClusterSize;
                var extents = BuildChain(first, size, true).Take(checked((int)Math.Min(required, int.MaxValue))).ToArray();
                var inferred = GetFat(first) == 0 && required > 1;
                var allocated = extents.Any(extent => GetFat(checked((uint)extent.LogicalCluster)) != 0);
                var quality = allocated ? RecoveryQuality.Overwritten : inferred ? RecoveryQuality.Partial : RecoveryQuality.Good;
                _candidates.Add(new RecoveryCandidate
                {
                    RecordNumber = checked((long)(ClusterOffset(directoryCluster) + (ulong)offset)), Name = name, OriginalPath = fullPath,
                    Size = size, IsDeleted = true, Extents = extents, FileSystem = FileSystemKind.Fat32,
                    SourceOffset = ClusterOffset(first), Discovery = RecoveryDiscovery.FatMetadata, Quality = quality,
                    QualityReason = allocated ? "一个或多个原簇已重新分配。" : inferred ? "FAT链已清除，按连续簇推断；原文件若有碎片可能不完整。" : "原FAT簇链仍可用。",
                    ModifiedUtc = DecodeModified(entry)
                });
                _progress?.Report(new("扫描 FAT32 元数据", ClusterOffset(directoryCluster), _device.Length, _candidates.Count, fullPath));
            }
        }
    }

    private IEnumerable<DataExtent> BuildChain(uint firstCluster, ulong byteLength, bool allowContiguousFallback)
    {
        var needed = Math.Max(1UL, (byteLength + _boot.ClusterSize - 1) / _boot.ClusterSize);
        var current = firstCluster;
        var seen = new HashSet<uint>();
        for (ulong index = 0; index < needed && current >= 2 && current < _boot.ClusterCount + 2 && seen.Add(current); index++)
        {
            yield return new DataExtent(current, 1);
            var next = GetFat(current);
            if (next >= EndOfChain) yield break;
            if (next == 0)
            {
                if (!allowContiguousFallback) yield break;
                current++;
            }
            else if (next is >= 2 and < EndOfChain) current = next;
            else yield break;
        }
    }

    internal void InitializeForRecovery(Fat32BootSector boot) => _boot = boot;
    internal ulong ClusterOffset(uint cluster) => checked(_partitionOffset + _boot.DataOffset + (ulong)(cluster - 2) * _boot.ClusterSize);
    private uint GetFat(uint cluster)
    {
        var offset = checked((int)((ulong)cluster * 4));
        return offset + 4 <= _fat.Length ? BinaryPrimitives.ReadUInt32LittleEndian(_fat.AsSpan(offset, 4)) & 0x0FFFFFFF : EndOfChain;
    }

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
