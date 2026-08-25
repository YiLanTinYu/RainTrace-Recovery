namespace Recovery.Core;

public readonly record struct PhysicalByteRange(ulong Start, ulong End);

public static class CandidateRangeIndex
{
    public static IReadOnlyList<PhysicalByteRange> BuildNtfs(
        IEnumerable<(RecoveryCandidate Candidate, NtfsScanResult Scan)> items)
    {
        var ranges = new List<PhysicalByteRange>();
        foreach (var (candidate, scan) in items)
        {
            if (candidate.Size == 0 ||
                candidate.Quality is RecoveryQuality.Overwritten or RecoveryQuality.TrimmedOrZeroed ||
                candidate.Extents.Count == 0) continue;
            var remaining = candidate.Size;
            foreach (var extent in candidate.Extents)
            {
                if (remaining == 0) break;
                var extentBytes = checked((ulong)extent.ClusterCount * scan.Boot.ClusterSize);
                var contentBytes = Math.Min(remaining, extentBytes);
                if (!extent.Sparse && extent.LogicalCluster >= 0 && contentBytes > 0)
                {
                    var start = checked(scan.PartitionOffset + (ulong)extent.LogicalCluster * scan.Boot.ClusterSize);
                    ranges.Add(new(start, checked(start + contentBytes)));
                }
                remaining -= contentBytes;
            }
        }
        if (ranges.Count < 2) return ranges;
        ranges.Sort((left, right) => left.Start.CompareTo(right.Start));
        var merged = new List<PhysicalByteRange> { ranges[0] };
        foreach (var range in ranges.Skip(1))
        {
            var last = merged[^1];
            if (range.Start <= last.End) merged[^1] = new(last.Start, Math.Max(last.End, range.End));
            else merged.Add(range);
        }
        return merged;
    }

    public static bool Contains(IReadOnlyList<PhysicalByteRange> ranges, ulong offset)
    {
        var low = 0;
        var high = ranges.Count - 1;
        while (low <= high)
        {
            var middle = low + (high - low) / 2;
            var range = ranges[middle];
            if (offset < range.Start) high = middle - 1;
            else if (offset >= range.End) low = middle + 1;
            else return true;
        }
        return false;
    }
}
