using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Recovery.Core;

public enum ScanCheckpointStageState
{
    Pending,
    Running,
    Completed,
    Interrupted,
    Failed,
    Cancelled
}

/// <summary>
/// Native scanners can continue at an exact byte position. External engines can only skip an
/// already completed stage or restart an interrupted stage from its beginning.
/// </summary>
public enum ScanCheckpointResumeMode
{
    BytePosition,
    StageBoundary
}

public enum ScanCheckpointSaveReason
{
    None,
    FirstSave,
    IntervalElapsed,
    StageTransition,
    Forced
}

public enum MediaFingerprintStrength
{
    LegacySinglePoint,
    MultiPoint
}

public sealed record MediaFingerprintPoint(ulong Offset, int Length, string Sha256);

public sealed record MultiPointMediaFingerprint(
    string Algorithm,
    MediaFingerprintStrength Strength,
    IReadOnlyList<MediaFingerprintPoint> Points)
{
    public const string Sha256Algorithm = "SHA-256";
}

public sealed record SourcePartitionLayoutEntry(
    int Number,
    ulong Offset,
    ulong Length,
    FileSystemKind FileSystem,
    bool IsGpt,
    Guid TypeGuid,
    Guid PartitionGuid,
    ulong? BootSectorOffset)
{
    public static SourcePartitionLayoutEntry FromDescriptor(PartitionDescriptor partition) => new(
        partition.Number,
        partition.Offset,
        partition.Length,
        partition.FileSystem,
        partition.IsGpt,
        partition.TypeGuid,
        partition.PartitionGuid,
        partition.BootSectorOffset);
}

/// <summary>
/// Immutable identity captured when a scan starts. Id and Path are retained for diagnostics but
/// intentionally are not used as identity evidence because a device can be assigned a new number
/// or drive letter after it is reinserted.
/// </summary>
public sealed record ScanSourceIdentity(
    string Id,
    string DisplayName,
    string Path,
    ulong Length,
    uint LogicalSectorSize,
    uint PhysicalSectorSize,
    MediaKind Kind,
    MediaCategory Category,
    bool TrimSupported,
    bool WasOpenedReadOnly,
    string? Model,
    string? SerialNumber,
    IReadOnlyList<SourcePartitionLayoutEntry> PartitionLayout,
    MultiPointMediaFingerprint ContentFingerprint)
{
    public static ScanSourceIdentity Capture(
        MediaDescriptor descriptor,
        IEnumerable<PartitionDescriptor> partitionLayout,
        MultiPointMediaFingerprint contentFingerprint)
    {
        ArgumentNullException.ThrowIfNull(descriptor);
        ArgumentNullException.ThrowIfNull(partitionLayout);
        ArgumentNullException.ThrowIfNull(contentFingerprint);

        return new(
            descriptor.Id,
            descriptor.DisplayName,
            descriptor.Path,
            descriptor.Length,
            descriptor.LogicalSectorSize,
            descriptor.PhysicalSectorSize,
            descriptor.Kind,
            descriptor.Category,
            descriptor.TrimSupported,
            descriptor.IsReadOnly,
            Normalize(descriptor.Model),
            Normalize(descriptor.SerialNumber),
            partitionLayout.Select(SourcePartitionLayoutEntry.FromDescriptor).ToArray(),
            contentFingerprint);
    }

    internal static string? Normalize(string? value) => string.IsNullOrWhiteSpace(value) ? null : value.Trim();
}

public sealed record ScanCandidateIndexCheckpoint(
    long CandidateCount,
    long LastSequence,
    string? IndexPath,
    string? IndexSha256,
    IReadOnlyList<string> StableExternalArtifacts)
{
    public static ScanCandidateIndexCheckpoint Empty { get; } = new(0, 0, null, null, []);
}

public sealed record RecoveryCheckpointOptions(
    bool MetadataScan,
    bool NtfsDeepMetadataScan,
    bool ExFatDeepMetadataScan,
    bool FullDiskOldMftScan,
    bool RawContentScan,
    bool LostPartitionSearch,
    bool PhotoRecAudioVideo,
    bool PhotoRecArchives,
    IReadOnlyList<string> FileCategoryKeys);

public sealed record ScanStageCheckpoint(
    string StageId,
    RecoveryStageKind Kind,
    string DisplayName,
    ScanCheckpointResumeMode ResumeMode,
    ScanCheckpointStageState State,
    ulong BytePosition,
    ulong? TotalBytes,
    int CandidateCount,
    DateTime UpdatedUtc,
    string? WorkProductPath = null,
    string? Message = null,
    string? CurrentTargetId = null,
    IReadOnlyDictionary<string, ulong>? TargetBytePositions = null)
{
    [JsonIgnore]
    public bool IsByteResumable => ResumeMode == ScanCheckpointResumeMode.BytePosition;

    [JsonIgnore]
    public bool IsStageComplete => State == ScanCheckpointStageState.Completed;

    [JsonIgnore]
    public bool MustRestartStage => !IsStageComplete && ResumeMode == ScanCheckpointResumeMode.StageBoundary;

    [JsonIgnore]
    public ulong ResumeBytePosition => IsByteResumable && !IsStageComplete ? BytePosition : 0;

    public ulong ResumeBytePositionFor(string targetId)
    {
        if (!IsByteResumable || IsStageComplete || string.IsNullOrWhiteSpace(targetId)) return 0;
        return TargetBytePositions is not null && TargetBytePositions.TryGetValue(targetId, out var position)
            ? position
            : 0;
    }

    public static ScanStageCheckpoint FromPlanStage(string stageId, RecoveryStage stage, DateTime? utcNow = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(stageId);
        ArgumentNullException.ThrowIfNull(stage);
        return new(
            stageId,
            stage.Kind,
            stage.DisplayName,
            stage.UsesExternalEngine ? ScanCheckpointResumeMode.StageBoundary : ScanCheckpointResumeMode.BytePosition,
            ScanCheckpointStageState.Pending,
            0,
            null,
            0,
            (utcNow ?? DateTime.UtcNow).ToUniversalTime());
    }

    public ScanStageCheckpoint PrepareForResume(DateTime? utcNow = null)
    {
        if (IsStageComplete) return this;
        return this with
        {
            State = ScanCheckpointStageState.Pending,
            BytePosition = IsByteResumable ? BytePosition : 0,
            CurrentTargetId = IsByteResumable ? CurrentTargetId : null,
            TargetBytePositions = IsByteResumable ? TargetBytePositions : null,
            UpdatedUtc = (utcNow ?? DateTime.UtcNow).ToUniversalTime(),
            Message = IsByteResumable
                ? "将从已保存的字节位置继续。"
                : "外部引擎不支持字节级续扫，将重新执行本阶段。"
        };
    }
}

public sealed record ScanCheckpointV3
{
    public const int CurrentVersion = 3;

    public int Version { get; init; } = CurrentVersion;
    public DateTime SavedUtc { get; init; } = DateTime.UtcNow;
    public required ScanSourceIdentity Source { get; init; }
    public RecoveryScenario Scenario { get; init; }
    public required IReadOnlyList<ScanTarget> ScanTargets { get; init; }
    public required IReadOnlyList<ScanStageCheckpoint> Stages { get; init; }
    public string? CurrentStageId { get; init; }
    public ulong CurrentBytePosition { get; init; }
    public required ScanCandidateIndexCheckpoint CandidateIndex { get; init; }
    public required string RecoveryWorkingDirectory { get; init; }
    public RecoveryCheckpointOptions? ExecutionOptions { get; init; }
    public int? MigratedFromVersion { get; init; }

    public ScanCheckpointV3 PrepareForResume(DateTime? utcNow = null)
    {
        var now = (utcNow ?? DateTime.UtcNow).ToUniversalTime();
        var resumedStages = Stages.Select(stage => stage.PrepareForResume(now)).ToArray();
        var current = CurrentStageId is null
            ? null
            : resumedStages.FirstOrDefault(stage => string.Equals(stage.StageId, CurrentStageId, StringComparison.Ordinal));

        return this with
        {
            SavedUtc = now,
            Stages = resumedStages,
            CurrentBytePosition = current?.ResumeBytePosition ?? 0
        };
    }
}

public sealed record ScanCheckpointLoadResult(
    ScanCheckpointV3 Checkpoint,
    int LoadedVersion,
    bool WasMigrated,
    IReadOnlyList<string> Warnings);

public sealed record ScanSourceValidationOptions(bool AllowLegacySinglePointFingerprint = false);

public sealed record ScanSourceValidationResult(
    bool IsMatch,
    IReadOnlyList<string> Errors,
    IReadOnlyList<string> Warnings)
{
    public static ScanSourceValidationResult Success { get; } = new(true, [], []);
}

/// <summary>
/// Computes a small read-only fingerprint at stable positions across the source. It never opens a
/// device itself and only calls IBlockDevice.ReadExactlyAsync.
/// </summary>
public static class MultiPointMediaFingerprintService
{
    private const int DefaultSampleBytes = 4096;
    private const int MaximumSampleBytes = 1024 * 1024;

    public static async Task<MultiPointMediaFingerprint> ComputeAsync(
        IBlockDevice device,
        int requestedSampleBytes = DefaultSampleBytes,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(device);
        if (requestedSampleBytes <= 0) throw new ArgumentOutOfRangeException(nameof(requestedSampleBytes));

        var sectorSize = Math.Max(1u, device.LogicalSectorSize);
        var desired = Math.Max((ulong)requestedSampleBytes, sectorSize);
        var sampleBytes = checked((int)Math.Min((ulong)MaximumSampleBytes, desired));
        var offsets = SelectOffsets(device.Length, sectorSize, checked((ulong)sampleBytes));
        var points = new List<MediaFingerprintPoint>(offsets.Count);

        foreach (var offset in offsets)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var available = device.Length - offset;
            var length = checked((int)Math.Min((ulong)sampleBytes, available));
            if (length == 0) continue;
            var sample = new byte[length];
            await device.ReadExactlyAsync(offset, sample, cancellationToken);
            points.Add(new(offset, length, Convert.ToHexString(SHA256.HashData(sample)).ToLowerInvariant()));
        }

        return new(MultiPointMediaFingerprint.Sha256Algorithm, MediaFingerprintStrength.MultiPoint, points);
    }

    private static IReadOnlyList<ulong> SelectOffsets(ulong sourceLength, uint sectorSize, ulong sampleBytes)
    {
        if (sourceLength == 0) return [];
        if (sourceLength <= sampleBytes) return [0];

        var highestStart = sourceLength - sampleBytes;
        var raw = new[]
        {
            0UL,
            Math.Min(1024UL * 1024, highestStart),
            sourceLength / 4,
            sourceLength / 2,
            checked((sourceLength / 4) * 3),
            highestStart
        };

        return raw
            .Select(offset => Math.Min(highestStart, AlignDown(offset, sectorSize)))
            .Distinct()
            .OrderBy(offset => offset)
            .ToArray();
    }

    private static ulong AlignDown(ulong value, uint alignment) => value - value % alignment;
}

public static class ScanCheckpointSourceValidator
{
    public static ScanSourceValidationResult Validate(
        ScanCheckpointV3 checkpoint,
        MediaDescriptor actualDescriptor,
        IEnumerable<PartitionDescriptor> actualPartitionLayout,
        MultiPointMediaFingerprint actualFingerprint,
        ScanSourceValidationOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(checkpoint);
        ArgumentNullException.ThrowIfNull(actualDescriptor);
        ArgumentNullException.ThrowIfNull(actualPartitionLayout);
        ArgumentNullException.ThrowIfNull(actualFingerprint);
        options ??= new();

        var expected = checkpoint.Source;
        var errors = new List<string>();
        var warnings = new List<string>();

        Compare(expected.Length, actualDescriptor.Length, "介质容量", errors);
        Compare(expected.LogicalSectorSize, actualDescriptor.LogicalSectorSize, "逻辑扇区大小", errors);
        Compare(expected.PhysicalSectorSize, actualDescriptor.PhysicalSectorSize, "物理扇区大小", errors);
        CompareRequiredText(expected.Model, actualDescriptor.Model, "介质型号", errors);
        CompareRequiredText(expected.SerialNumber, actualDescriptor.SerialNumber, "介质序列号", errors);

        var actualLayout = actualPartitionLayout.Select(SourcePartitionLayoutEntry.FromDescriptor).ToArray();
        if (!LayoutsMatch(expected.PartitionLayout, actualLayout))
        {
            errors.Add("分区布局与保存检查点时不一致。");
        }

        if (expected.ContentFingerprint.Strength == MediaFingerprintStrength.LegacySinglePoint &&
            !options.AllowLegacySinglePointFingerprint)
        {
            errors.Add("旧版会话只保存了单点指纹，无法安全排除同型号的另一块介质。");
        }
        else if (!FingerprintsMatch(expected.ContentFingerprint, actualFingerprint, out var fingerprintReason))
        {
            errors.Add(fingerprintReason);
        }

        if (!actualDescriptor.IsReadOnly)
        {
            warnings.Add("当前介质描述未标记为只读；续扫前应确保以只读方式重新打开。");
        }

        return new(errors.Count == 0, errors, warnings);
    }

    private static void Compare<T>(T expected, T actual, string label, ICollection<string> errors) where T : IEquatable<T>
    {
        if (!expected.Equals(actual)) errors.Add($"{label}与保存检查点时不一致。");
    }

    private static void CompareRequiredText(string? expected, string? actual, string label, ICollection<string> errors)
    {
        expected = ScanSourceIdentity.Normalize(expected);
        actual = ScanSourceIdentity.Normalize(actual);
        if (expected is null) return;
        if (actual is null)
        {
            errors.Add($"无法读取{label}，不能安全确认为同一介质。");
            return;
        }
        if (!string.Equals(expected, actual, StringComparison.OrdinalIgnoreCase))
        {
            errors.Add($"{label}与保存检查点时不一致。");
        }
    }

    private static bool LayoutsMatch(
        IReadOnlyList<SourcePartitionLayoutEntry> expected,
        IReadOnlyList<SourcePartitionLayoutEntry> actual)
    {
        var expectedCanonical = expected.Select(CanonicalLayoutEntry).OrderBy(value => value, StringComparer.Ordinal).ToArray();
        var actualCanonical = actual.Select(CanonicalLayoutEntry).OrderBy(value => value, StringComparer.Ordinal).ToArray();
        return expectedCanonical.SequenceEqual(actualCanonical, StringComparer.Ordinal);
    }

    private static string CanonicalLayoutEntry(SourcePartitionLayoutEntry entry) => string.Join('|',
        entry.Offset,
        entry.Length,
        (int)entry.FileSystem,
        entry.IsGpt ? 1 : 0,
        entry.TypeGuid.ToString("N"),
        entry.PartitionGuid.ToString("N"),
        entry.BootSectorOffset?.ToString() ?? string.Empty);

    private static bool FingerprintsMatch(
        MultiPointMediaFingerprint expected,
        MultiPointMediaFingerprint actual,
        out string reason)
    {
        if (!string.Equals(expected.Algorithm, actual.Algorithm, StringComparison.OrdinalIgnoreCase))
        {
            reason = "介质指纹算法不一致。";
            return false;
        }
        if (expected.Points.Count == 0)
        {
            reason = "保存的介质指纹为空，不能安全续扫。";
            return false;
        }

        var actualByRange = actual.Points
            .GroupBy(point => (point.Offset, point.Length))
            .ToDictionary(group => group.Key, group => group.First());
        foreach (var point in expected.Points)
        {
            if (!actualByRange.TryGetValue((point.Offset, point.Length), out var actualPoint) ||
                !string.Equals(point.Sha256, actualPoint.Sha256, StringComparison.OrdinalIgnoreCase))
            {
                reason = $"介质在 {point.Offset:N0} 字节处的内容指纹不一致，当前设备不是原扫描介质。";
                return false;
            }
        }

        reason = string.Empty;
        return true;
    }
}

public static class ScanCheckpointStore
{
    public const string DefaultFileName = "raintrace-scan-checkpoint-v3.json";

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() }
    };

    public static string GetDefaultPath(ScanCheckpointV3 checkpoint)
    {
        ArgumentNullException.ThrowIfNull(checkpoint);
        if (string.IsNullOrWhiteSpace(checkpoint.RecoveryWorkingDirectory))
            throw new InvalidDataException("恢复工作目录为空。");
        return Path.Combine(checkpoint.RecoveryWorkingDirectory, DefaultFileName);
    }

    public static Task SaveToWorkingDirectoryAsync(ScanCheckpointV3 checkpoint, CancellationToken cancellationToken = default) =>
        SaveAsync(GetDefaultPath(checkpoint), checkpoint, cancellationToken);

    public static async Task SaveAsync(
        string path,
        ScanCheckpointV3 checkpoint,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        ArgumentNullException.ThrowIfNull(checkpoint);
        ValidateCheckpoint(checkpoint);

        var fullPath = Path.GetFullPath(path);
        var directory = Path.GetDirectoryName(fullPath) ?? throw new InvalidDataException("检查点路径无效。");
        Directory.CreateDirectory(directory);
        var tempPath = Path.Combine(directory, $".{Path.GetFileName(fullPath)}.{Guid.NewGuid():N}.tmp");
        try
        {
            await using (var stream = new FileStream(
                tempPath,
                FileMode.CreateNew,
                FileAccess.Write,
                FileShare.None,
                64 * 1024,
                FileOptions.Asynchronous | FileOptions.WriteThrough))
            {
                await JsonSerializer.SerializeAsync(stream, checkpoint with
                {
                    Version = ScanCheckpointV3.CurrentVersion,
                    SavedUtc = DateTime.UtcNow
                }, JsonOptions, cancellationToken);
                await stream.FlushAsync(cancellationToken);
            }

            File.Move(tempPath, fullPath, true);
        }
        finally
        {
            if (File.Exists(tempPath)) File.Delete(tempPath);
        }
    }

    public static async Task<ScanCheckpointV3> LoadAsync(string path, CancellationToken cancellationToken = default) =>
        (await LoadDetailedAsync(path, cancellationToken)).Checkpoint;

    public static async Task<ScanCheckpointLoadResult> LoadDetailedAsync(
        string path,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        var fullPath = Path.GetFullPath(path);
        var bytes = await File.ReadAllBytesAsync(fullPath, cancellationToken);
        using var document = JsonDocument.Parse(bytes);
        if (!document.RootElement.TryGetProperty("Version", out var versionElement) &&
            !document.RootElement.TryGetProperty("version", out versionElement))
        {
            throw new InvalidDataException("扫描检查点缺少版本号。");
        }

        var version = versionElement.GetInt32();
        if (version == ScanCheckpointV3.CurrentVersion)
        {
            var checkpoint = JsonSerializer.Deserialize<ScanCheckpointV3>(bytes, JsonOptions)
                ?? throw new InvalidDataException("扫描检查点内容为空。");
            ValidateCheckpoint(checkpoint);
            return new(checkpoint, version, false, []);
        }
        if (version == 2)
        {
            return MigrateV2(bytes, fullPath);
        }

        throw new InvalidDataException($"不支持的扫描检查点版本：{version}。");
    }

    private static ScanCheckpointLoadResult MigrateV2(ReadOnlySpan<byte> bytes, string checkpointPath)
    {
        var legacy = JsonSerializer.Deserialize<LegacyCheckpointV2>(bytes, JsonOptions)
            ?? throw new InvalidDataException("旧版扫描会话内容为空。");
        if (legacy.Source is null) throw new InvalidDataException("旧版扫描会话缺少源介质描述。");

        var points = legacy.SourceFingerprint is null || string.IsNullOrWhiteSpace(legacy.SourceFingerprint.FirstSectorSha256)
            ? Array.Empty<MediaFingerprintPoint>()
            : new[]
            {
                new MediaFingerprintPoint(
                    0,
                    checked((int)Math.Min(legacy.Source.Length, Math.Max(512u, legacy.Source.LogicalSectorSize))),
                    legacy.SourceFingerprint.FirstSectorSha256)
            };
        var fingerprint = new MultiPointMediaFingerprint(
            MultiPointMediaFingerprint.Sha256Algorithm,
            MediaFingerprintStrength.LegacySinglePoint,
            points);
        var source = ScanSourceIdentity.Capture(legacy.Source, [], fingerprint);
        var workDirectory = string.IsNullOrWhiteSpace(legacy.RecoveryWorkingDirectory)
            ? Path.GetDirectoryName(checkpointPath) ?? Path.GetPathRoot(checkpointPath) ?? "."
            : legacy.RecoveryWorkingDirectory;
        var candidateCount = legacy.Candidates.ValueKind == JsonValueKind.Array
            ? legacy.Candidates.GetArrayLength()
            : 0;
        var target = new ScanTarget(
            "legacy-whole-device",
            0,
            legacy.Source.Length,
            FileSystemKind.Unknown,
            "旧版会话整盘范围",
            RecoveryConfidence.Unknown,
            new(ScanTargetOrigin.WholeDevice, true, false, false, false, "v2 会话未保存分区证据。"));
        var checkpoint = new ScanCheckpointV3
        {
            SavedUtc = legacy.SavedUtc == default ? DateTime.UtcNow : legacy.SavedUtc.ToUniversalTime(),
            Source = source,
            Scenario = legacy.Scenario ?? RecoveryScenario.DeletedFiles,
            ScanTargets = [target],
            Stages = [],
            CandidateIndex = new(candidateCount, candidateCount, null, null, []),
            RecoveryWorkingDirectory = Path.GetFullPath(workDirectory),
            MigratedFromVersion = 2
        };
        ValidateCheckpoint(checkpoint);
        return new(
            checkpoint,
            2,
            true,
            ["已读取 v2 会话的源介质与候选数量；旧版未保存多点指纹和阶段位置，默认不允许直接续扫。"]);
    }

    private static void ValidateCheckpoint(ScanCheckpointV3 checkpoint)
    {
        if (checkpoint.Version != ScanCheckpointV3.CurrentVersion)
            throw new InvalidDataException($"检查点版本必须为 {ScanCheckpointV3.CurrentVersion}。");
        if (checkpoint.Source is null) throw new InvalidDataException("检查点缺少源介质身份。");
        if (checkpoint.ScanTargets is null) throw new InvalidDataException("检查点缺少扫描目标。");
        if (checkpoint.Stages is null) throw new InvalidDataException("检查点缺少阶段状态。");
        if (checkpoint.CandidateIndex is null) throw new InvalidDataException("检查点缺少候选索引。");
        if (string.IsNullOrWhiteSpace(checkpoint.RecoveryWorkingDirectory) || !Path.IsPathRooted(checkpoint.RecoveryWorkingDirectory))
            throw new InvalidDataException("恢复工作目录必须是绝对路径。");
        if (checkpoint.CandidateIndex.CandidateCount < 0 || checkpoint.CandidateIndex.LastSequence < 0)
            throw new InvalidDataException("候选索引数值不能为负数。");

        var duplicateTarget = checkpoint.ScanTargets
            .GroupBy(target => target.Id, StringComparer.Ordinal)
            .FirstOrDefault(group => group.Count() > 1);
        if (duplicateTarget is not null) throw new InvalidDataException($"扫描目标 ID 重复：{duplicateTarget.Key}。");
        foreach (var target in checkpoint.ScanTargets)
        {
            if (string.IsNullOrWhiteSpace(target.Id) || target.Length == 0)
                throw new InvalidDataException("扫描目标 ID 不能为空且长度必须大于零。");
            if (target.Offset > checkpoint.Source.Length || target.Length > checkpoint.Source.Length - target.Offset)
                throw new InvalidDataException($"扫描目标 {target.Id} 超出源介质边界。");
        }

        var duplicateStage = checkpoint.Stages
            .GroupBy(stage => stage.StageId, StringComparer.Ordinal)
            .FirstOrDefault(group => group.Count() > 1);
        if (duplicateStage is not null) throw new InvalidDataException($"扫描阶段 ID 重复：{duplicateStage.Key}。");
        foreach (var stage in checkpoint.Stages)
        {
            if (string.IsNullOrWhiteSpace(stage.StageId)) throw new InvalidDataException("扫描阶段 ID 不能为空。");
            if (stage.TotalBytes is { } total && stage.BytePosition > total)
                throw new InvalidDataException($"扫描阶段 {stage.StageId} 的字节位置超出总量。");
            if (stage.CandidateCount < 0) throw new InvalidDataException($"扫描阶段 {stage.StageId} 的候选数量不能为负数。");
            if (stage.TargetBytePositions is not null && stage.TargetBytePositions.Any(item =>
                    string.IsNullOrWhiteSpace(item.Key) || item.Value > checkpoint.Source.Length))
                throw new InvalidDataException($"扫描阶段 {stage.StageId} 含有无效的目标字节位置。");
        }
        if (checkpoint.CurrentStageId is not null &&
            checkpoint.Stages.All(stage => !string.Equals(stage.StageId, checkpoint.CurrentStageId, StringComparison.Ordinal)))
        {
            throw new InvalidDataException("当前扫描阶段不在检查点阶段列表中。");
        }

        ValidateFingerprint(checkpoint.Source.ContentFingerprint);
        foreach (var point in checkpoint.Source.ContentFingerprint.Points)
        {
            var length = checked((ulong)point.Length);
            if (point.Offset > checkpoint.Source.Length || length > checkpoint.Source.Length - point.Offset)
                throw new InvalidDataException("介质指纹取样范围超出源介质边界。");
        }
    }

    private static void ValidateFingerprint(MultiPointMediaFingerprint fingerprint)
    {
        if (fingerprint is null) throw new InvalidDataException("检查点缺少介质内容指纹。");
        if (!string.Equals(fingerprint.Algorithm, MultiPointMediaFingerprint.Sha256Algorithm, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("当前只支持 SHA-256 介质指纹。");
        if (fingerprint.Points is null) throw new InvalidDataException("介质指纹点列表缺失。");
        foreach (var point in fingerprint.Points)
        {
            if (point.Length <= 0 || point.Offset > ulong.MaxValue - checked((ulong)point.Length))
                throw new InvalidDataException("介质指纹取样范围无效。");
            if (point.Sha256.Length != 64 || point.Sha256.Any(character => !Uri.IsHexDigit(character)))
                throw new InvalidDataException("介质指纹不是有效的 SHA-256。");
        }
    }

    private sealed record LegacyCheckpointV2(
        int Version,
        DateTime SavedUtc,
        MediaDescriptor? Source,
        JsonElement Candidates,
        MediaFingerprint? SourceFingerprint,
        string? RecoveryWorkingDirectory,
        RecoveryScenario? Scenario);
}

/// <summary>
/// Testable save throttle. Call SaveIfDueAsync during progress updates; it saves immediately on a
/// stage change and otherwise at most once per configured interval (five seconds by default).
/// </summary>
public sealed class ScanCheckpointThrottle
{
    private readonly TimeSpan _interval;
    private readonly TimeProvider _timeProvider;
    private readonly SemaphoreSlim _saveGate = new(1, 1);
    private readonly object _stateGate = new();
    private DateTimeOffset? _lastSavedUtc;
    private string? _lastSavedStageId;

    public ScanCheckpointThrottle(TimeSpan? interval = null, TimeProvider? timeProvider = null)
    {
        _interval = interval ?? TimeSpan.FromSeconds(5);
        if (_interval <= TimeSpan.Zero) throw new ArgumentOutOfRangeException(nameof(interval));
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    public ScanCheckpointSaveReason GetSaveReason(string? currentStageId, bool force = false)
    {
        lock (_stateGate)
        {
            if (force) return ScanCheckpointSaveReason.Forced;
            if (_lastSavedUtc is null) return ScanCheckpointSaveReason.FirstSave;
            if (!string.Equals(_lastSavedStageId, currentStageId, StringComparison.Ordinal))
                return ScanCheckpointSaveReason.StageTransition;
            return _timeProvider.GetUtcNow() - _lastSavedUtc.Value >= _interval
                ? ScanCheckpointSaveReason.IntervalElapsed
                : ScanCheckpointSaveReason.None;
        }
    }

    public void MarkSaved(string? currentStageId)
    {
        lock (_stateGate)
        {
            _lastSavedUtc = _timeProvider.GetUtcNow();
            _lastSavedStageId = currentStageId;
        }
    }

    public async Task<ScanCheckpointSaveReason> SaveIfDueAsync(
        string path,
        ScanCheckpointV3 checkpoint,
        bool force = false,
        CancellationToken cancellationToken = default)
    {
        await _saveGate.WaitAsync(cancellationToken);
        try
        {
            var reason = GetSaveReason(checkpoint.CurrentStageId, force);
            if (reason == ScanCheckpointSaveReason.None) return reason;
            await ScanCheckpointStore.SaveAsync(path, checkpoint, cancellationToken);
            MarkSaved(checkpoint.CurrentStageId);
            return reason;
        }
        finally
        {
            _saveGate.Release();
        }
    }
}
