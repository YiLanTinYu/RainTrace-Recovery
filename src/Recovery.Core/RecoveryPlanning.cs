namespace Recovery.Core;

public enum ScanTargetOrigin
{
    PrimaryPartitionTable,
    BackupPartitionTable,
    ExtendedPartition,
    PrimaryBootSector,
    BackupBootSector,
    WholeDevice
}

public enum RecoveryStageKind
{
    PartitionDiscovery,
    FileSystemMetadata,
    DeepMetadata,
    RawContent,
    IntegrityValidation
}

public sealed record PartitionEvidence(
    ScanTargetOrigin Origin,
    bool GeometryValid,
    bool BootSectorValid,
    bool BackupStructureValid,
    bool OverlapsAnotherTarget,
    string Explanation);

public sealed record ScanTarget(
    string Id,
    ulong Offset,
    ulong Length,
    FileSystemKind FileSystem,
    string DisplayName,
    RecoveryConfidence Confidence,
    PartitionEvidence Evidence,
    int? PartitionTableNumber = null,
    ulong? BackupBootSectorOffset = null);

public sealed record RecoveryStage(
    RecoveryStageKind Kind,
    string DisplayName,
    bool ReadsWholeTarget,
    bool UsesExternalEngine);

public sealed record RecoveryPlan(
    RecoveryScenario Scenario,
    IReadOnlyList<RecoveryStage> Stages,
    IReadOnlyList<string> FileCategoryKeys,
    bool RequiresDestinationWorkspace,
    string Summary);

public static class RecoveryPlanFactory
{
    public static RecoveryPlan Create(RecoveryScenario scenario, IReadOnlyList<string>? fileCategoryKeys = null,
        bool includeOptionalRawContent = false)
    {
        var categories = fileCategoryKeys is { Count: > 0 } ? fileCategoryKeys : ["Image", "Document"];
        return scenario switch
        {
            RecoveryScenario.DeletedFiles => CreateDeletedPlan(categories, includeOptionalRawContent),
            RecoveryScenario.FormattedOrRaw => new(scenario,
            [
                new(RecoveryStageKind.PartitionDiscovery, "识别当前与备用结构", false, false),
                new(RecoveryStageKind.FileSystemMetadata, "TSK 文件系统元数据扫描", false, true),
                new(RecoveryStageKind.DeepMetadata, "原生深度元数据扫描", true, false),
                new(RecoveryStageKind.RawContent, "PhotoRec 内容扫描", true, true)
            ], categories, true, "先查找格式化后残留的元数据，再以内容特征兜底。"),
            RecoveryScenario.LostPartition => new(scenario,
            [
                new(RecoveryStageKind.PartitionDiscovery, "搜索丢失分区", true, false),
                new(RecoveryStageKind.FileSystemMetadata, "TSK 候选分区元数据扫描", false, true),
                new(RecoveryStageKind.DeepMetadata, "原生候选分区元数据补充", true, false),
                new(RecoveryStageKind.RawContent, "整盘 PhotoRec 兜底", true, true)
            ], categories, true, "只读定位丢失分区并恢复其中的文件，不写回分区表。"),
            _ => throw new ArgumentOutOfRangeException(nameof(scenario))
        };
    }

    private static RecoveryPlan CreateDeletedPlan(IReadOnlyList<string> categories, bool includeRawContent)
    {
        var stages = new List<RecoveryStage>
        {
            new(RecoveryStageKind.PartitionDiscovery, "识别当前分区", false, false),
            new(RecoveryStageKind.FileSystemMetadata, "TSK 文件系统元数据扫描", false, true),
            new(RecoveryStageKind.DeepMetadata, "原生元数据补充 / 回退", false, false)
        };
        if (includeRawContent)
            stages.Add(new(RecoveryStageKind.RawContent, "按需 PhotoRec 未分配空间扫描", true, true));
        return new(RecoveryScenario.DeletedFiles, stages, categories, includeRawContent,
            "优先查找仍保留原文件名和目录的误删除文件。");
    }
}
