using System.Text.Json.Serialization;

namespace Recovery.Core;

public enum MediaKind { Unknown, HardDisk, SolidState, Removable, Image }
public enum MediaCategory { Unknown, HardDisk, SolidState, UsbStorage, MemoryCard, Raid, StorageSpace, Image }
public enum FileSystemKind { Unknown, Ntfs, Fat12, Fat16, Fat32, ExFat }
public enum RecoveryQuality { Excellent, Good, Partial, Poor, Overwritten, TrimmedOrZeroed, Unknown }
public enum RecoveryDiscovery { SleuthKitMetadata, NtfsCurrentMft, NtfsDeepMft, NtfsFullDiskMft, ExFatMetadata, ExFatDeepMetadata, FatMetadata, FileSignature, PhotoRecFile }

public sealed record MediaDescriptor(
    string Id,
    string DisplayName,
    string Path,
    ulong Length,
    uint LogicalSectorSize,
    uint PhysicalSectorSize,
    MediaKind Kind,
    bool TrimSupported,
    bool IsReadOnly,
    string? Model = null,
    string? SerialNumber = null,
    MediaCategory Category = MediaCategory.Unknown)
{
    public string CategoryLabel => Category switch
    {
        MediaCategory.HardDisk => "机械硬盘",
        MediaCategory.SolidState => "固态硬盘 / NVMe",
        MediaCategory.UsbStorage => "USB 存储设备",
        MediaCategory.MemoryCard => "SD / TF 存储卡",
        MediaCategory.Raid => "RAID 磁盘",
        MediaCategory.StorageSpace => "Windows 存储空间",
        MediaCategory.Image => "磁盘镜像",
        _ => "未识别介质"
    };

    public string MediaTraitsLabel => Category switch
    {
        MediaCategory.SolidState when TrimSupported => $"{CategoryLabel} · TRIM 已启用 · 只读扫描",
        MediaCategory.SolidState => $"{CategoryLabel} · 未报告 TRIM · 只读扫描",
        MediaCategory.Image => $"{CategoryLabel} · 文件只读打开",
        _ => $"{CategoryLabel} · 只读扫描"
    };
}

public sealed record PartitionDescriptor(
    int Number,
    ulong Offset,
    ulong Length,
    Guid TypeGuid,
    Guid PartitionGuid,
    string Name,
    FileSystemKind FileSystem,
    bool IsGpt,
    ulong? BootSectorOffset = null);

public sealed record DataExtent(long LogicalCluster, long ClusterCount, bool Sparse = false);

public sealed class RecoveryCandidate
{
    public long RecordNumber { get; init; }
    public string Name { get; init; } = string.Empty;
    public string OriginalPath { get; set; } = string.Empty;
    public long ParentRecordNumber { get; init; }
    public ulong Size { get; init; }
    public bool IsDirectory { get; init; }
    public bool IsDeleted { get; init; }
    public bool IsResident { get; init; }
    public byte[]? ResidentData { get; init; }
    public IReadOnlyList<DataExtent> Extents { get; init; } = [];
    public RecoveryQuality Quality { get; set; } = RecoveryQuality.Unknown;
    public string QualityReason { get; set; } = string.Empty;
    public FileIntegrityState Integrity { get; set; } = FileIntegrityState.NotChecked;
    public string IntegrityReason { get; set; } = "尚未执行恢复前结构预检。";
    public bool IsMarkedForRecovery { get; set; }
    public string? StagedRecoveryPath { get; set; }
    public DateTime? ModifiedUtc { get; init; }
    public FileSystemKind FileSystem { get; init; } = FileSystemKind.Unknown;
    public ulong SourceOffset { get; init; }
    public RecoveryDiscovery Discovery { get; init; } = RecoveryDiscovery.FileSignature;
    [JsonIgnore]
    public IReadOnlyList<RecoveryCandidate> AlternateCandidates { get; set; } = [];
    public int DuplicateRecordCount => 1 + AlternateCandidates.Count;
    public string DiscoveryLabel => Discovery switch
    {
        RecoveryDiscovery.SleuthKitMetadata => "TSK 文件系统元数据（原名）",
        RecoveryDiscovery.NtfsCurrentMft => "当前 MFT（原名）",
        RecoveryDiscovery.NtfsDeepMft => "深度 MFT（旧原名）",
        RecoveryDiscovery.NtfsFullDiskMft => "全盘旧 MFT（旧原名）",
        RecoveryDiscovery.ExFatMetadata => "exFAT 元数据（原名）",
        RecoveryDiscovery.ExFatDeepMetadata => "exFAT 深度元数据（原名）",
        RecoveryDiscovery.FatMetadata => "FAT 元数据（原名）",
        RecoveryDiscovery.PhotoRecFile => "PhotoRec 严格校验（临时名）",
        _ => "文件特征（临时名）"
    };
    public string Extension => Path.GetExtension(Name).TrimStart('.').ToLowerInvariant();
    public string IntegrityLabel => Integrity switch
    {
        FileIntegrityState.Valid => "预检通过",
        FileIntegrityState.Damaged => "结构损坏",
        FileIntegrityState.Salvaged => "画面已抢救",
        _ => "未预检"
    };
}

public sealed record ScanProgress(string Stage, ulong Processed, ulong Total, int Candidates, string Message)
{
    public double Percent => Total == 0 ? 0 : Math.Min(100, Processed * 100d / Total);
}

public sealed record ScanOptions(
    bool IncludeActiveFiles = false,
    bool MetadataScan = true,
    bool SignatureScan = false,
    bool ScanOnlyUnallocated = true,
    ulong StartOffset = 0,
    ulong? Length = null,
    bool DeepMetadataScan = false,
    ulong DeepMetadataBytes = 512UL * 1024 * 1024,
    bool FullDiskMetadataScan = false,
    bool EvaluateRecoverability = true,
    bool ExFatDeepMetadataScan = false);
