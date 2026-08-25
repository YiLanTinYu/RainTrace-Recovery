using System.Security.Cryptography;
using System.Text;

namespace Recovery.Core;

/// <summary>
/// Computes a full-file SHA-256 for a recovery candidate. Returning <see langword="null"/>
/// means that the candidate could not be read and therefore must not be merged.
/// </summary>
public delegate ValueTask<string?> RecoveryCandidateSha256Provider(
    RecoveryCandidate candidate,
    CancellationToken cancellationToken);

/// <summary>
/// Returns an inexpensive content fingerprint (for example, hashes of the head and tail
/// samples). It is used only to reduce full-file hashing and is never sufficient by itself
/// to merge candidates.
/// </summary>
public delegate string? RecoveryCandidateQuickFingerprintProvider(RecoveryCandidate candidate);

public sealed record RecoveryCandidateIndexEntry(
    string LogicalKey,
    RecoveryCandidate PreferredCandidate,
    IReadOnlyList<RecoveryCandidate> RecoverySources,
    string? Sha256)
{
    public IReadOnlyList<RecoveryCandidate> AlternateSources =>
        RecoverySources.Count <= 1 ? [] : RecoverySources.Skip(1).ToArray();

    public bool IsMerged => RecoverySources.Count > 1;
}

public sealed record RecoveryCandidateIndexResult(
    IReadOnlyList<RecoveryCandidateIndexEntry> Entries,
    int InputCandidates,
    int PreferredCandidates,
    int MergedCandidates,
    int HashedCandidates);

/// <summary>
/// Builds a conservative, deterministic index of recovery candidates. Content candidates
/// are merged only after a full SHA-256 match. Directories are always kept as individual
/// navigation nodes.
/// </summary>
public sealed class RecoveryCandidateIndex
{
    private readonly RecoveryCandidateSha256Provider _sha256Provider;
    private readonly RecoveryCandidateQuickFingerprintProvider? _quickFingerprintProvider;

    public RecoveryCandidateIndex(
        RecoveryCandidateSha256Provider sha256Provider,
        RecoveryCandidateQuickFingerprintProvider? quickFingerprintProvider = null)
    {
        _sha256Provider = sha256Provider ?? throw new ArgumentNullException(nameof(sha256Provider));
        _quickFingerprintProvider = quickFingerprintProvider;
    }

    public async Task<RecoveryCandidateIndexResult> BuildAsync(
        IEnumerable<RecoveryCandidate> candidates,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(candidates);
        cancellationToken.ThrowIfCancellationRequested();

        var snapshot = Enumerable.Distinct<RecoveryCandidate>(candidates, ReferenceEqualityComparer.Instance)
            .Select((candidate, inputOrder) => CreateWorkItem(candidate, inputOrder))
            .ToArray();

        var pendingEntries = new List<PendingEntry>(snapshot.Length);
        var hashedCandidates = 0;

        foreach (var directory in OrderWorkItems(snapshot.Where(item => item.Candidate.IsDirectory)))
        {
            cancellationToken.ThrowIfCancellationRequested();
            pendingEntries.Add(new PendingEntry(directory.Candidate, [directory.Candidate], null));
        }

        var sizeAndExtensionBuckets = snapshot
            .Where(item => !item.Candidate.IsDirectory)
            .GroupBy(item => new InitialBucket(item.Candidate.Size, item.Extension))
            .OrderBy(group => group.Key.Size)
            .ThenBy(group => group.Key.Extension, StringComparer.Ordinal)
            .ToArray();

        foreach (var initialBucket in sizeAndExtensionBuckets)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var orderedBucket = OrderWorkItems(initialBucket).ToArray();
            if (orderedBucket.Length == 1)
            {
                AddStandalone(pendingEntries, orderedBucket[0].Candidate);
                continue;
            }

            if (_quickFingerprintProvider is not null)
            {
                for (var index = 0; index < orderedBucket.Length; index++)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    var item = orderedBucket[index];
                    orderedBucket[index] = item with
                    {
                        QuickFingerprint = NormalizeQuickFingerprint(_quickFingerprintProvider(item.Candidate))
                    };
                }
            }

            // A partially available quick fingerprint must not split the bucket: otherwise a
            // candidate could escape comparison with an identical candidate that has no sample.
            var collisionGroups = CanUseQuickFingerprints(orderedBucket)
                ? orderedBucket.GroupBy(item => item.QuickFingerprint!, StringComparer.Ordinal)
                    .OrderBy(group => group.Key, StringComparer.Ordinal)
                    .Select(group => group.ToArray())
                    .ToArray()
                : [orderedBucket];

            foreach (var collisionGroup in collisionGroups)
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (collisionGroup.Length == 1)
                {
                    AddStandalone(pendingEntries, collisionGroup[0].Candidate);
                    continue;
                }

                var hashed = new List<HashedWorkItem>(collisionGroup.Length);
                foreach (var item in collisionGroup)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    var sha256 = NormalizeSha256(await _sha256Provider(item.Candidate, cancellationToken));
                    hashedCandidates++;
                    hashed.Add(new HashedWorkItem(item, sha256));
                }

                foreach (var unreadable in hashed.Where(item => item.Sha256 is null)
                             .OrderBy(item => item.WorkItem, StableWorkItemComparer.Instance))
                {
                    AddStandalone(pendingEntries, unreadable.WorkItem.Candidate);
                }

                foreach (var exactGroup in hashed.Where(item => item.Sha256 is not null)
                             .GroupBy(item => item.Sha256!, StringComparer.Ordinal)
                             .OrderBy(group => group.Key, StringComparer.Ordinal))
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    var exactMatches = exactGroup.Select(item => item.WorkItem.Candidate).ToArray();
                    if (exactMatches.Length == 1)
                    {
                        pendingEntries.Add(new PendingEntry(
                            exactMatches[0],
                            FlattenRecoverySources(exactMatches[0]),
                            exactGroup.Key));
                        continue;
                    }

                    var preferred = exactMatches.OrderBy(candidate => candidate, PreferredCandidateComparer.Instance).First();
                    var sources = FlattenRecoverySources(exactMatches)
                        .OrderBy(candidate => candidate, PreferredCandidateComparer.Instance)
                        .ToArray();
                    sources = MovePreferredFirst(sources, preferred);
                    pendingEntries.Add(new PendingEntry(preferred, sources, exactGroup.Key));
                }
            }
        }

        cancellationToken.ThrowIfCancellationRequested();
        var orderedEntries = pendingEntries
            .OrderBy(entry => IsFileSystemMetadata(entry.Preferred) ? 0 : 1)
            .ThenBy(entry => DiscoveryRank(entry.Preferred.Discovery))
            .ThenBy(entry => QualityRank(entry.Preferred.Quality))
            .ThenBy(entry => IntegrityRank(entry.Preferred.Integrity))
            .ThenBy(entry => NormalizePath(entry.Preferred.OriginalPath), StringComparer.Ordinal)
            .ThenBy(entry => entry.Preferred.Size)
            .ThenBy(entry => entry.Preferred.SourceOffset)
            .ThenBy(entry => entry.Preferred.RecordNumber)
            .ThenBy(entry => entry.Sha256 ?? string.Empty, StringComparer.Ordinal)
            .ThenBy(entry => StableIdentity(entry.Preferred), StringComparer.Ordinal)
            .ToArray();

        var logicalKeyOccurrences = new Dictionary<string, int>(StringComparer.Ordinal);
        var entries = new List<RecoveryCandidateIndexEntry>(orderedEntries.Length);
        foreach (var entry in orderedEntries)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var baseKey = entry.Sha256 is not null
                ? $"sha256:{entry.Sha256}"
                : CreateSourceLogicalKey(entry.Preferred);
            logicalKeyOccurrences.TryGetValue(baseKey, out var occurrence);
            logicalKeyOccurrences[baseKey] = ++occurrence;
            var logicalKey = occurrence == 1 ? baseKey : $"{baseKey}#{occurrence}";

            var alternatives = entry.Sources.Where(candidate => !ReferenceEquals(candidate, entry.Preferred)).ToArray();
            entry.Preferred.AlternateCandidates = alternatives;
            entries.Add(new RecoveryCandidateIndexEntry(
                logicalKey,
                entry.Preferred,
                entry.Sources,
                entry.Sha256));
        }

        var mergedCandidates = Math.Max(0, snapshot.Length - entries.Count);
        return new RecoveryCandidateIndexResult(
            entries,
            snapshot.Length,
            entries.Count,
            mergedCandidates,
            hashedCandidates);
    }

    private WorkItem CreateWorkItem(RecoveryCandidate candidate, int inputOrder)
    {
        var extension = NormalizeExtension(candidate);
        return new WorkItem(candidate, extension, null, inputOrder);
    }

    private static bool CanUseQuickFingerprints(IReadOnlyList<WorkItem> candidates) =>
        candidates.Count > 0 && candidates.All(item => item.QuickFingerprint is not null);

    private static IOrderedEnumerable<WorkItem> OrderWorkItems(IEnumerable<WorkItem> candidates) => candidates
        .OrderBy(item => IsFileSystemMetadata(item.Candidate) ? 0 : 1)
        .ThenBy(item => DiscoveryRank(item.Candidate.Discovery))
        .ThenBy(item => QualityRank(item.Candidate.Quality))
        .ThenBy(item => IntegrityRank(item.Candidate.Integrity))
        .ThenBy(item => NormalizePath(item.Candidate.OriginalPath), StringComparer.Ordinal)
        .ThenBy(item => item.Candidate.Size)
        .ThenBy(item => item.Candidate.SourceOffset)
        .ThenBy(item => item.Candidate.RecordNumber)
        .ThenBy(item => StableIdentity(item.Candidate), StringComparer.Ordinal)
        .ThenBy(item => item.InputOrder);

    private static void AddStandalone(ICollection<PendingEntry> entries, RecoveryCandidate candidate) =>
        entries.Add(new PendingEntry(candidate, FlattenRecoverySources(candidate), null));

    private static IReadOnlyList<RecoveryCandidate> FlattenRecoverySources(params RecoveryCandidate[] candidates)
    {
        var result = new List<RecoveryCandidate>();
        var seen = new HashSet<RecoveryCandidate>(ReferenceEqualityComparer.Instance);
        var pending = new Queue<RecoveryCandidate>(candidates);
        while (pending.TryDequeue(out var candidate))
        {
            if (!seen.Add(candidate)) continue;
            result.Add(candidate);
            foreach (var alternate in candidate.AlternateCandidates)
            {
                if (alternate is not null) pending.Enqueue(alternate);
            }
        }
        return result;
    }

    private static RecoveryCandidate[] MovePreferredFirst(
        IReadOnlyList<RecoveryCandidate> orderedSources,
        RecoveryCandidate preferred)
    {
        var result = new RecoveryCandidate[orderedSources.Count];
        result[0] = preferred;
        var outputIndex = 1;
        foreach (var candidate in orderedSources)
        {
            if (!ReferenceEquals(candidate, preferred)) result[outputIndex++] = candidate;
        }
        return result;
    }

    private static string NormalizeExtension(RecoveryCandidate candidate)
    {
        var extension = Path.GetExtension(candidate.Name);
        if (string.IsNullOrWhiteSpace(extension)) extension = Path.GetExtension(candidate.OriginalPath);
        return extension.Trim().TrimStart('.').ToLowerInvariant();
    }

    private static string? NormalizeQuickFingerprint(string? fingerprint)
    {
        var normalized = fingerprint?.Trim().ToLowerInvariant();
        return string.IsNullOrWhiteSpace(normalized) ? null : normalized;
    }

    private static string? NormalizeSha256(string? sha256)
    {
        if (string.IsNullOrWhiteSpace(sha256)) return null;
        var normalized = sha256.Trim().ToLowerInvariant();
        if (normalized.Length != 64 || normalized.Any(character => !Uri.IsHexDigit(character))) return null;
        return normalized;
    }

    private static string CreateSourceLogicalKey(RecoveryCandidate candidate)
    {
        var prefix = IsFileSystemMetadata(candidate) ? "metadata" : "source";
        var identityBytes = Encoding.UTF8.GetBytes(StableIdentity(candidate));
        return $"{prefix}:{Convert.ToHexString(SHA256.HashData(identityBytes)).ToLowerInvariant()}";
    }

    private static string StableIdentity(RecoveryCandidate candidate) => string.Join('\0',
        ((int)candidate.FileSystem).ToString(System.Globalization.CultureInfo.InvariantCulture),
        ((int)candidate.Discovery).ToString(System.Globalization.CultureInfo.InvariantCulture),
        candidate.RecordNumber.ToString(System.Globalization.CultureInfo.InvariantCulture),
        candidate.SourceOffset.ToString(System.Globalization.CultureInfo.InvariantCulture),
        candidate.Size.ToString(System.Globalization.CultureInfo.InvariantCulture),
        NormalizePath(candidate.OriginalPath),
        candidate.ModifiedUtc?.Ticks.ToString(System.Globalization.CultureInfo.InvariantCulture) ?? string.Empty,
        candidate.StagedRecoveryPath is null ? string.Empty : NormalizePath(candidate.StagedRecoveryPath));

    private static string NormalizePath(string path) =>
        path.Trim().Replace('/', '\\').ToLowerInvariant();

    private static bool IsFileSystemMetadata(RecoveryCandidate candidate) =>
        candidate.Discovery is not (RecoveryDiscovery.FileSignature or RecoveryDiscovery.PhotoRecFile);

    private static int DiscoveryRank(RecoveryDiscovery discovery) => discovery switch
    {
        RecoveryDiscovery.SleuthKitMetadata => 0,
        RecoveryDiscovery.NtfsCurrentMft => 1,
        RecoveryDiscovery.ExFatMetadata => 2,
        RecoveryDiscovery.FatMetadata => 3,
        RecoveryDiscovery.NtfsDeepMft => 4,
        RecoveryDiscovery.ExFatDeepMetadata => 5,
        RecoveryDiscovery.NtfsFullDiskMft => 6,
        RecoveryDiscovery.PhotoRecFile => 20,
        RecoveryDiscovery.FileSignature => 21,
        _ => 30
    };

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

    private static int IntegrityRank(FileIntegrityState integrity) => integrity switch
    {
        FileIntegrityState.Valid => 0,
        FileIntegrityState.Salvaged => 1,
        FileIntegrityState.NotChecked => 2,
        FileIntegrityState.Damaged => 3,
        _ => 4
    };

    private sealed class PreferredCandidateComparer : IComparer<RecoveryCandidate>
    {
        public static PreferredCandidateComparer Instance { get; } = new();

        public int Compare(RecoveryCandidate? left, RecoveryCandidate? right)
        {
            if (ReferenceEquals(left, right)) return 0;
            if (left is null) return 1;
            if (right is null) return -1;

            var comparison = IsFileSystemMetadata(left).CompareTo(IsFileSystemMetadata(right));
            if (comparison != 0) return -comparison;
            comparison = DiscoveryRank(left.Discovery).CompareTo(DiscoveryRank(right.Discovery));
            if (comparison != 0) return comparison;
            comparison = QualityRank(left.Quality).CompareTo(QualityRank(right.Quality));
            if (comparison != 0) return comparison;
            comparison = IntegrityRank(left.Integrity).CompareTo(IntegrityRank(right.Integrity));
            if (comparison != 0) return comparison;
            comparison = string.Compare(NormalizePath(left.OriginalPath), NormalizePath(right.OriginalPath), StringComparison.Ordinal);
            if (comparison != 0) return comparison;
            comparison = left.Size.CompareTo(right.Size);
            if (comparison != 0) return comparison;
            comparison = left.SourceOffset.CompareTo(right.SourceOffset);
            if (comparison != 0) return comparison;
            comparison = left.RecordNumber.CompareTo(right.RecordNumber);
            if (comparison != 0) return comparison;
            return string.Compare(StableIdentity(left), StableIdentity(right), StringComparison.Ordinal);
        }
    }

    private sealed class StableWorkItemComparer : IComparer<WorkItem>
    {
        public static StableWorkItemComparer Instance { get; } = new();

        public int Compare(WorkItem? left, WorkItem? right)
        {
            if (ReferenceEquals(left, right)) return 0;
            if (left is null) return 1;
            if (right is null) return -1;
            var comparison = PreferredCandidateComparer.Instance.Compare(left.Candidate, right.Candidate);
            return comparison != 0 ? comparison : left.InputOrder.CompareTo(right.InputOrder);
        }
    }

    private sealed record WorkItem(
        RecoveryCandidate Candidate,
        string Extension,
        string? QuickFingerprint,
        int InputOrder);

    private sealed record HashedWorkItem(WorkItem WorkItem, string? Sha256);
    private sealed record PendingEntry(
        RecoveryCandidate Preferred,
        IReadOnlyList<RecoveryCandidate> Sources,
        string? Sha256);
    private readonly record struct InitialBucket(ulong Size, string Extension);
}
