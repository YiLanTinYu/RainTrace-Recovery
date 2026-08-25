using System.Buffers.Binary;
using System.Text;

namespace Recovery.Core;

public static class PartitionScanner
{
    private static readonly Guid MicrosoftBasicData = new("EBD0A0A2-B9E5-4433-87C0-68B6B72699C7");

    public static async Task<IReadOnlyList<PartitionDescriptor>> ScanAsync(IBlockDevice device, CancellationToken cancellationToken = default)
    {
        var sectorSize = checked((int)device.LogicalSectorSize);
        if (sectorSize < 512 || sectorSize > 65536) throw new InvalidDataException("Unsupported logical sector size.");
        var sector = new byte[sectorSize];
        await device.ReadExactlyAsync(0, sector, cancellationToken);
        if (sector[510] != 0x55 || sector[511] != 0xAA)
            return [new PartitionDescriptor(1, 0, device.Length, Guid.Empty, Guid.Empty, "Whole device", await DetectFileSystemAsync(device, 0, cancellationToken), false)];

        var protective = false;
        var mbr = new List<PartitionDescriptor>();
        for (var i = 0; i < 4; i++)
        {
            var entry = sector.AsSpan(446 + i * 16, 16);
            var type = entry[4];
            var firstLba = BinaryPrimitives.ReadUInt32LittleEndian(entry[8..12]);
            var sectors = BinaryPrimitives.ReadUInt32LittleEndian(entry[12..16]);
            if (type == 0xEE) protective = true;
            if (type == 0 || sectors == 0 || type == 0xEE) continue;
            var offset = checked((ulong)firstLba * device.LogicalSectorSize);
            var length = checked((ulong)sectors * device.LogicalSectorSize);
            mbr.Add(new PartitionDescriptor(mbr.Count + 1, offset, length, Guid.Empty, Guid.Empty, $"MBR partition {mbr.Count + 1}", await DetectFileSystemAsync(device, offset, cancellationToken), false));
        }

        if (!protective) return mbr.Count > 0 ? mbr : [new PartitionDescriptor(1, 0, device.Length, Guid.Empty, Guid.Empty, "Whole device", await DetectFileSystemAsync(device, 0, cancellationToken), false)];

        var primary = await TryReadGptAsync(device, 1, fromBackup: false, cancellationToken);
        if (primary is not null) return primary;
        var totalLbas = device.Length / device.LogicalSectorSize;
        var backup = totalLbas > 1 ? await TryReadGptAsync(device, totalLbas - 1, fromBackup: true, cancellationToken) : null;
        if (backup is not null) return backup;
        return [new PartitionDescriptor(1, 0, device.Length, Guid.Empty, Guid.Empty, "GPT损坏：整盘只读搜索范围", FileSystemKind.Unknown, false)];
    }

    public static async Task<FileSystemKind> DetectFileSystemAsync(IBlockDevice device, ulong offset, CancellationToken cancellationToken = default)
    {
        var boot = new byte[512];
        if (offset + 512 > device.Length) return FileSystemKind.Unknown;
        await device.ReadExactlyAsync(offset, boot, cancellationToken);
        if (boot.AsSpan(3, 8).SequenceEqual("NTFS    "u8)) return FileSystemKind.Ntfs;
        if (boot.AsSpan(3, 8).SequenceEqual("EXFAT   "u8)) return FileSystemKind.ExFat;
        if (boot.AsSpan(82, 8).StartsWith("FAT32"u8)) return FileSystemKind.Fat32;
        if (boot.AsSpan(54, 8).StartsWith("FAT16"u8)) return FileSystemKind.Fat16;
        if (boot.AsSpan(54, 8).StartsWith("FAT12"u8)) return FileSystemKind.Fat12;
        return FileSystemKind.Unknown;
    }

    public static async Task<IReadOnlyList<PartitionDescriptor>> FindLostPartitionsAsync(
        IBlockDevice device, IReadOnlyList<PartitionDescriptor>? known = null,
        IProgress<ScanProgress>? progress = null, CancellationToken cancellationToken = default)
    {
        const int blockSize = 8 * 1024 * 1024;
        var sectorSize = checked((int)device.LogicalSectorSize);
        var buffer = new byte[blockSize + sectorSize];
        var found = new List<PartitionDescriptor>();
        var knownRanges = (known ?? []).Where(item => item.FileSystem != FileSystemKind.Unknown)
            .Select(item => (item.Offset, End: checked(item.Offset + item.Length))).ToList();
        ulong position = 0;
        while (position < device.Length)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var count = checked((int)Math.Min((ulong)blockSize, device.Length - position));
            await device.ReadExactlyAsync(position, buffer.AsMemory(0, count), cancellationToken);
            for (var local = 0; local + 512 <= count; local += sectorSize)
            {
                var absolute = position + checked((ulong)local);
                if (knownRanges.Any(range => absolute >= range.Offset && absolute < range.End) ||
                    found.Any(item => absolute >= item.Offset && absolute < item.Offset + item.Length)) continue;
                var boot = buffer.AsSpan(local, 512);
                var detected = TryDescribeBootSector(boot, out var fileSystem, out var length);
                if (detected && length > 0 && length <= device.Length - absolute)
                {
                    found.Add(new PartitionDescriptor(found.Count + 1, absolute, length, Guid.Empty, Guid.Empty,
                        $"检测到的丢失 {fileSystem} 分区", fileSystem, false));
                    continue;
                }
                if (!TryDescribeBackupBootSector(boot, absolute, device.Length, out var originalStart, out fileSystem, out length)) continue;
                if (knownRanges.Any(range => originalStart >= range.Offset && originalStart < range.End) ||
                    found.Any(item => originalStart >= item.Offset && originalStart < item.Offset + item.Length)) continue;
                found.Add(new PartitionDescriptor(found.Count + 1, originalStart, length, Guid.Empty, Guid.Empty,
                    $"由备份引导区定位的丢失 {fileSystem} 分区", fileSystem, false, absolute));
            }
            position += checked((ulong)count);
            progress?.Report(new("搜索丢失分区", position, device.Length, found.Count, $"已发现 {found.Count} 个候选分区"));
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
            else return false;
            return length > 0 && originalStart % parsedSectorAlignment(boot, fileSystem) == 0 && originalStart <= deviceLength && length <= deviceLength - originalStart;
        }
        catch (Exception ex) when (ex is InvalidDataException or OverflowException or ArgumentOutOfRangeException or DivideByZeroException) { return false; }

        static ulong parsedSectorAlignment(ReadOnlySpan<byte> value, FileSystemKind kind) => kind == FileSystemKind.Ntfs
            ? BinaryPrimitives.ReadUInt16LittleEndian(value[11..13])
            : 1UL << value[108];
    }

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
            if (headerSize != 0)
            {
                if (headerSize < 92 || headerSize > sectorSize) return null;
                if (storedHeaderCrc != 0)
                {
                    var copy = header.AsSpan(0, checked((int)headerSize)).ToArray(); copy.AsSpan(16, 4).Clear();
                    if (ComputeCrc32(copy) != storedHeaderCrc) return null;
                }
            }
            var currentLba = BinaryPrimitives.ReadUInt64LittleEndian(header.AsSpan(24, 8));
            if (currentLba != 0 && currentLba != headerLba) return null;
            var entriesLba = BinaryPrimitives.ReadUInt64LittleEndian(header.AsSpan(72, 8));
            var entryCount = BinaryPrimitives.ReadUInt32LittleEndian(header.AsSpan(80, 4));
            var entrySize = BinaryPrimitives.ReadUInt32LittleEndian(header.AsSpan(84, 4));
            if (entrySize < 128 || entrySize > 4096 || entryCount == 0 || entryCount > 16384) return null;
            var tableLength = checked((ulong)entryCount * entrySize);
            var tableOffset = checked(entriesLba * device.LogicalSectorSize);
            if (tableLength > 64UL * 1024 * 1024 || tableOffset > device.Length || tableLength > device.Length - tableOffset) return null;
            var table = new byte[checked((int)tableLength)]; await device.ReadExactlyAsync(tableOffset, table, cancellationToken);
            var storedTableCrc = BinaryPrimitives.ReadUInt32LittleEndian(header.AsSpan(88, 4));
            if (storedTableCrc != 0 && ComputeCrc32(table) != storedTableCrc) return null;

            var result = new List<PartitionDescriptor>();
            for (uint index = 0; index < entryCount; index++)
            {
                var entry = table.AsSpan(checked((int)((ulong)index * entrySize)), checked((int)entrySize));
                var typeGuid = new Guid(entry.Slice(0, 16)); if (typeGuid == Guid.Empty) continue;
                var partitionGuid = new Guid(entry.Slice(16, 16));
                var firstLba = BinaryPrimitives.ReadUInt64LittleEndian(entry.Slice(32, 8));
                var lastLba = BinaryPrimitives.ReadUInt64LittleEndian(entry.Slice(40, 8));
                if (lastLba < firstLba || lastLba >= totalLbas) continue;
                var partOffset = checked(firstLba * device.LogicalSectorSize);
                var length = checked((lastLba - firstLba + 1) * device.LogicalSectorSize);
                var nameLength = Math.Min(72, checked((int)entrySize - 56));
                var name = Encoding.Unicode.GetString(entry.Slice(56, nameLength)).TrimEnd('\0');
                var fileSystem = typeGuid == MicrosoftBasicData ? await DetectFileSystemAsync(device, partOffset, cancellationToken) : FileSystemKind.Unknown;
                var fallbackName = fromBackup ? $"GPT备份表分区 {result.Count + 1}" : $"GPT分区 {result.Count + 1}";
                result.Add(new PartitionDescriptor(result.Count + 1, partOffset, length, typeGuid, partitionGuid,
                    string.IsNullOrWhiteSpace(name) ? fallbackName : fromBackup ? $"{name}（GPT备份表）" : name, fileSystem, true));
            }
            return result;
        }
        catch (Exception ex) when (ex is IOException or InvalidDataException or EndOfStreamException or OverflowException or ArgumentOutOfRangeException) { return null; }
    }

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
}
