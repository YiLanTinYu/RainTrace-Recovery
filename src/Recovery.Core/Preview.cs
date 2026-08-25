namespace Recovery.Core;

public static class RecoveryPreview
{
    public const int DefaultMaximumBytes = 32 * 1024 * 1024;

    public static async Task<byte[]> ReadAsync(
        IBlockDevice source,
        RecoveryCandidate candidate,
        NtfsScanResult? ntfs = null,
        ExFatScanResult? exFat = null,
        Fat32ScanResult? fat32 = null,
        int maximumBytes = DefaultMaximumBytes,
        CancellationToken cancellationToken = default)
    {
        return await ReadRangeAsync(source, candidate, 0, maximumBytes, ntfs, exFat, fat32, cancellationToken);
    }

    public static async Task<byte[]> ReadRangeAsync(
        IBlockDevice source,
        RecoveryCandidate candidate,
        ulong logicalOffset,
        int maximumBytes,
        NtfsScanResult? ntfs = null,
        ExFatScanResult? exFat = null,
        Fat32ScanResult? fat32 = null,
        CancellationToken cancellationToken = default)
    {
        if (maximumBytes <= 0) throw new ArgumentOutOfRangeException(nameof(maximumBytes));
        if (logicalOffset > candidate.Size) throw new ArgumentOutOfRangeException(nameof(logicalOffset));
        var length = checked((int)Math.Min(candidate.Size - logicalOffset, (ulong)maximumBytes));
        if (length == 0) return [];
        var buffer = new byte[length];

        if (ntfs is not null)
        {
            if (candidate.IsResident)
            {
                var data = candidate.ResidentData ?? [];
                if (logicalOffset + (ulong)length > (ulong)data.Length) throw new EndOfStreamException("Resident data is shorter than requested preview range.");
                data.AsSpan(checked((int)logicalOffset), length).CopyTo(buffer);
                return buffer;
            }
            await NtfsExtentReader.ReadExactlyAsync(source, ntfs.PartitionOffset, ntfs.Boot.ClusterSize,
                candidate.Extents, logicalOffset, buffer, cancellationToken);
            return buffer;
        }

        if (exFat is not null)
        {
            var scanner = new ExFatScanner(source, exFat.PartitionOffset);
            scanner.InitializeForRecovery(exFat.Boot);
            await scanner.ReadExtentsExactlyAsync(candidate.Extents, logicalOffset, buffer, cancellationToken);
            return buffer;
        }

        if (fat32 is not null)
        {
            var written = 0;
            var skip = logicalOffset;
            foreach (var extent in candidate.Extents)
            {
                var extentBytes = checked((ulong)extent.ClusterCount * fat32.Boot.ClusterSize);
                if (skip >= extentBytes) { skip -= extentBytes; continue; }
                var cluster = checked((uint)extent.LogicalCluster);
                var available = extentBytes - skip;
                var count = checked((int)Math.Min((ulong)(buffer.Length - written), available));
                if (count <= 0) break;
                var offset = checked(fat32.PartitionOffset + fat32.Boot.DataOffset + (ulong)(cluster - 2) * fat32.Boot.ClusterSize + skip);
                await source.ReadExactlyAsync(offset, buffer.AsMemory(written, count), cancellationToken);
                written += count; skip = 0;
            }
            if (written != buffer.Length) throw new EndOfStreamException("FAT32 cluster chain ended before preview data.");
            return buffer;
        }

        await source.ReadExactlyAsync(checked(candidate.SourceOffset + logicalOffset), buffer, cancellationToken);
        return buffer;
    }
}
