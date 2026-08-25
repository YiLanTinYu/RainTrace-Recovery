using Microsoft.Win32;
using Recovery.Core;
using System.Collections.Concurrent;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;

namespace Recovery.App;

public partial class MainWindow : Window
{
    public RangeObservableCollection<RecoveryCandidate> Candidates { get; } = [];
    private readonly ObservableCollection<MediaDescriptor> _sources = [];
    private readonly Dictionary<RecoveryCandidate, NtfsScanResult> _ntfsResults = [];
    private readonly Dictionary<RecoveryCandidate, ExFatScanResult> _exFatResults = [];
    private readonly Dictionary<RecoveryCandidate, Fat32ScanResult> _fat32Results = [];
    private readonly Dictionary<RecoveryCandidate, TskRecoveryContext> _tskResults = [];
    private readonly Dictionary<(RecoveryCandidate Candidate, string Variant), string> _candidateHashes = [];
    private readonly List<RecoveryCandidate> _pendingStreamedCandidates = [];
    private readonly ObservableCollection<PartitionCandidateViewItem> _partitionCandidates = [];
    private readonly ObservableCollection<PartitionCandidateViewItem> _lowConfidencePartitionCandidates = [];
    private CancellationTokenSource? _operation;
    private IBlockDevice? _device;
    private PausableBlockDevice? _pausableDevice;
    private ScanCheckpointV3? _activeScanCheckpoint;
    private ScanCheckpointV3? _pendingResumeCheckpoint;
    private MediaDescriptor? _activeScanSource;
    private string? _activeScanCheckpointPath;
    private string? _activeCheckpointTargetId;
    private readonly ScanCheckpointThrottle _scanCheckpointThrottle = new();
    private readonly SemaphoreSlim _checkpointProgressGate = new(1, 1);
    private ScanProgress? _latestCheckpointProgress;
    private bool _checkpointProgressLoopRunning;
    private readonly ICollectionView _candidateView;
    private readonly DispatcherTimer _filterDebounce;
    private CancellationTokenSource _thumbnailOperation = new();
    private int _treeBuildGeneration;
    private int _thumbnailBuildGeneration;
    private string _resultViewMode = "List";
    private int _previewRequest;
    private string? _telemetryStage;
    private ulong _telemetryStartProcessed;
    private long _telemetryStartTimestamp;
    private TaskCompletionSource<bool>? _partitionSelectionCompletion;
    private bool _externalEngineActive;
    private string? _externalEngineName;

    private static readonly CategoryItem[] Categories =
    [
        new("All", "全部文件"), new("Image", "图片"), new("Video", "视频"), new("Document", "文档"),
        new("Audio", "音频"), new("Archive", "压缩包"), new("Other", "其他")
    ];

    public MainWindow()
    {
        InitializeComponent();
        DataContext = this;
        SourceCombo.ItemsSource = _sources;
        _candidateView = CollectionViewSource.GetDefaultView(Candidates);
        _candidateView.Filter = FilterCandidate;
        ResultsGrid.ItemsSource = _candidateView;
        _filterDebounce = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(280) };
        _filterDebounce.Tick += (_, _) => { _filterDebounce.Stop(); RefreshResults(); };
        CategoryList.ItemsSource = Categories;
        CategoryList.SelectedIndex = 0;
        PartitionCandidateList.ItemsSource = _partitionCandidates;
        LowConfidencePartitionCandidateList.ItemsSource = _lowConfidencePartitionCandidates;
        ApplyScenarioPreset(RecoveryScenario.DeletedFiles);
#if YUHEN_UI_SMOKE
        _sources.Add(new MediaDescriptor("smoke-usb", "物理磁盘 2 · Lexar RW310X · 盘符 E: · 59.48 GiB · USB", @"\\.\PhysicalDrive2", 63864569856, 512, 4096, MediaKind.Removable, false, true, "Lexar RW310X", Category: MediaCategory.UsbStorage));
        SourceCombo.SelectedIndex = 0;
        for (var index = 1; index <= 8; index++)
            Candidates.Add(new RecoveryCandidate
            {
                Name = $"交互测试文件-{index:00}.jpg",
                OriginalPath = $"测试目录\\交互测试文件-{index:00}.jpg",
                Size = checked((ulong)index * 1024),
                IsDeleted = true,
                FileSystem = FileSystemKind.ExFat,
                Discovery = RecoveryDiscovery.ExFatMetadata,
                Quality = RecoveryQuality.Good
            });
#endif
#if !YUHEN_UI_SMOKE
        Loaded += async (_, _) => await RefreshSourcesAsync();
#endif
        AppendLog($"诊断日志：{AppDiagnostics.LogPath}");
        Closed += (_, _) =>
        {
            _thumbnailOperation.Cancel();
            _thumbnailOperation.Dispose();
            _device?.DisposeAsync().AsTask().GetAwaiter().GetResult();
        };
    }

    private async Task RefreshSourcesAsync()
    {
        SetBusy(true, "正在枚举 Windows 物理磁盘…");
        try
        {
            var images = _sources.Where(s => s.Kind == MediaKind.Image).ToArray();
            var disks = await Task.Run(() => WindowsStorageEnumerator.EnumeratePhysicalDisks());
            _sources.Clear();
            foreach (var disk in disks) _sources.Add(disk);
            foreach (var image in images) _sources.Add(image);
            if (_sources.Count > 0) SourceCombo.SelectedIndex = 0;
            AppendLog($"发现 {disks.Count} 个物理磁盘。所有源设备只以读取权限打开。");
            if (disks.Count == 0)
            {
                var elevated = IsAdministrator();
                var message = elevated
                    ? "Windows 没有返回可读取的物理磁盘。请确认设备已连接，然后点击“刷新磁盘”。"
                    : "当前程序没有管理员权限，无法读取物理磁盘。请关闭此窗口，并从 dist\\win-x64-self-contained 运行正式版。";
                AppendLog(message);
                MessageBox.Show(this, message, "未发现磁盘", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        }
        catch (Exception ex) { ShowError(ex); }
        finally { SetBusy(false, "就绪"); }
    }

    private async void Refresh_Click(object sender, RoutedEventArgs e) => await RefreshSourcesAsync();

    private void OpenImage_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog
        {
            Title = "选择磁盘镜像",
            Filter = "磁盘镜像|*.img;*.dd;*.raw;*.bin|所有文件|*.*",
            CheckFileExists = true
        };
        if (dialog.ShowDialog(this) != true) return;
        var info = new FileInfo(dialog.FileName);
        var descriptor = new MediaDescriptor($"image-{Guid.NewGuid():N}", $"镜像 · {info.Name} · {FormatBytes(checked((ulong)info.Length))}", info.FullName, checked((ulong)info.Length), 512, 4096, MediaKind.Image, false, true, Category: MediaCategory.Image);
        _sources.Add(descriptor);
        SourceCombo.SelectedItem = descriptor;
        AppendLog($"已加载镜像：{info.FullName}");
    }

    private async Task<IBlockDevice> OpenSelectedSourceAsync(CancellationToken cancellationToken = default)
    {
        if (SourceCombo.SelectedItem is not MediaDescriptor source) throw new InvalidOperationException("请先选择源介质或镜像。");
        if (_device is not null)
        {
            var previous = _device;
            _device = null;
            _pausableDevice = null;
            await previous.DisposeAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(5), cancellationToken);
        }

        var openTask = Task.Run<IBlockDevice>(() => source.Kind == MediaKind.Image
            ? new ImageBlockDevice(source.Path, source.LogicalSectorSize, source.PhysicalSectorSize)
            : new WindowsPhysicalDiskDevice(source.Path, source.LogicalSectorSize, source.PhysicalSectorSize), CancellationToken.None);
        IBlockDevice inner;
        try
        {
            inner = await openTask.WaitAsync(TimeSpan.FromSeconds(15), cancellationToken);
        }
        catch (TimeoutException)
        {
            _ = openTask.ContinueWith(async completed =>
            {
                if (completed.Status == TaskStatus.RanToCompletion) await completed.Result.DisposeAsync();
            }, CancellationToken.None, TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default).Unwrap();
            throw new IOException("打开源介质超过15秒。Windows存储驱动没有及时返回，请重新插拔设备或更换USB接口后重试。");
        }
        _pausableDevice = new PausableBlockDevice(inner);
        _device = _pausableDevice;
        return _device;
    }

    private void Scenario_Checked(object sender, RoutedEventArgs e)
    {
        if (!IsInitialized || MetadataCheck is null) return;
        ApplyScenarioPreset(GetSelectedScenario());
    }

    private RecoveryScenario GetSelectedScenario() =>
        LostPartitionScenarioCheck?.IsChecked == true ? RecoveryScenario.LostPartition :
        FormattedScenarioCheck?.IsChecked == true ? RecoveryScenario.FormattedOrRaw :
        RecoveryScenario.DeletedFiles;

    private IReadOnlyList<string> GetSelectedFileCategories()
    {
        var categories = new HashSet<RecoveryFileCategory>
        {
            RecoveryFileCategory.Image,
            RecoveryFileCategory.Document
        };
        if (PhotoRecMediaCheck?.IsChecked == true)
        {
            categories.Add(RecoveryFileCategory.Audio);
            categories.Add(RecoveryFileCategory.Video);
        }
        if (PhotoRecArchiveCheck?.IsChecked == true) categories.Add(RecoveryFileCategory.Archive);
        return categories.Select(category => category.ToString()).ToArray();
    }

    private void ApplyScenarioPreset(RecoveryScenario scenario)
    {
        if (MetadataCheck is null) return;
        MetadataCheck.IsChecked = true;
        DeepMetadataCheck.IsChecked = scenario == RecoveryScenario.FormattedOrRaw;
        ExFatDeepMetadataCheck.IsChecked = scenario == RecoveryScenario.FormattedOrRaw;
        FullDiskMetadataCheck.IsChecked = false;
        CarveCheck.IsChecked = scenario != RecoveryScenario.DeletedFiles;
        LostPartitionCheck.IsChecked = scenario == RecoveryScenario.LostPartition;
        PartitionCandidatesPanel.Visibility = scenario == RecoveryScenario.LostPartition
            ? Visibility.Visible : Visibility.Collapsed;
        CategoryList.MaxHeight = scenario == RecoveryScenario.LostPartition ? 104 : 172;

        var plan = RecoveryPlanFactory.Create(scenario, GetSelectedFileCategories(), CarveCheck.IsChecked == true);
        ScenarioSummaryText.Text = scenario switch
        {
            RecoveryScenario.DeletedFiles => "优先从当前文件系统元数据恢复原文件名和目录；内容扫描可在高级设置中按需启用。",
            RecoveryScenario.FormattedOrRaw => "先识别主/备用文件系统结构和旧元数据，再用 PhotoRec 内容扫描兜底。",
            _ => "搜索主/备分区表和引导记录，按候选分区只读恢复；不会写回 GPT、MBR 或引导区。"
        };
        PlanStagesText.Text = $"扫描阶段：{string.Join(" → ", plan.Stages.Select(stage => stage.DisplayName))}";
    }

    private static string ScenarioLabel(RecoveryScenario scenario) => scenario switch
    {
        RecoveryScenario.DeletedFiles => "误删除文件",
        RecoveryScenario.FormattedOrRaw => "快速格式化 / RAW",
        _ => "分区丢失 / 分区表损坏"
    };

    private async Task InitializeScanCheckpointAsync(MediaDescriptor source, IBlockDevice device,
        IReadOnlyList<PartitionDescriptor> partitionLayout, RecoveryPlan plan, CancellationToken cancellationToken)
    {
        StatusText.Text = "正在建立只读多点介质指纹…";
        var fingerprint = await MultiPointMediaFingerprintService.ComputeAsync(device, cancellationToken: cancellationToken);
        var identity = ScanSourceIdentity.Capture(source, partitionLayout, fingerprint);
        var workDirectory = Path.Combine(Path.GetFullPath(DestinationBox.Text), "RainTrace-Work",
            $"{DateTime.Now:yyyyMMdd-HHmmss}-{SanitizePathComponent(source.Id)}");
        Directory.CreateDirectory(workDirectory);
        var stages = plan.Stages.Select((stage, index) =>
            ScanStageCheckpoint.FromPlanStage($"{index + 1:00}-{stage.Kind}", stage)).ToArray();
        _activeScanCheckpoint = new ScanCheckpointV3
        {
            Source = identity,
            Scenario = plan.Scenario,
            ScanTargets = CreateScanTargets(partitionLayout, source.Length),
            Stages = stages,
            CandidateIndex = ScanCandidateIndexCheckpoint.Empty,
            RecoveryWorkingDirectory = workDirectory,
            ExecutionOptions = CaptureCheckpointOptions()
        };
        _activeScanSource = source;
        _activeScanCheckpointPath = ScanCheckpointStore.GetDefaultPath(_activeScanCheckpoint);
        await PersistActiveScanCheckpointAsync(force: true, cancellationToken);
        AppendLog($"v3 扫描检查点已建立：{_activeScanCheckpointPath}");
    }

    private RecoveryCheckpointOptions CaptureCheckpointOptions() => new(
        MetadataCheck.IsChecked == true,
        DeepMetadataCheck.IsChecked == true,
        ExFatDeepMetadataCheck.IsChecked == true,
        FullDiskMetadataCheck.IsChecked == true,
        CarveCheck.IsChecked == true,
        LostPartitionCheck.IsChecked == true,
        PhotoRecMediaCheck.IsChecked == true,
        PhotoRecArchiveCheck.IsChecked == true,
        GetSelectedFileCategories());

    private void ApplyCheckpointOptions(RecoveryCheckpointOptions options)
    {
        MetadataCheck.IsChecked = options.MetadataScan;
        DeepMetadataCheck.IsChecked = options.NtfsDeepMetadataScan;
        ExFatDeepMetadataCheck.IsChecked = options.ExFatDeepMetadataScan;
        FullDiskMetadataCheck.IsChecked = options.FullDiskOldMftScan;
        CarveCheck.IsChecked = options.RawContentScan;
        LostPartitionCheck.IsChecked = options.LostPartitionSearch;
        PhotoRecMediaCheck.IsChecked = options.PhotoRecAudioVideo;
        PhotoRecArchiveCheck.IsChecked = options.PhotoRecArchives;
        var plan = RecoveryPlanFactory.Create(GetSelectedScenario(),
            options.FileCategoryKeys is { Count: > 0 } ? options.FileCategoryKeys : GetSelectedFileCategories(),
            options.RawContentScan);
        PlanStagesText.Text = $"扫描阶段：{string.Join(" → ", plan.Stages.Select(stage => stage.DisplayName))}";
    }

    private static IReadOnlyList<ScanTarget> CreateScanTargets(IEnumerable<PartitionDescriptor> partitions, ulong sourceLength)
    {
        var descriptors = partitions.Where(partition => partition.Length > 0 && partition.Offset <= sourceLength &&
            partition.Length <= sourceLength - partition.Offset)
            .GroupBy(partition => (partition.Offset, partition.Length))
            .Select(group => group
                .OrderByDescending(partition => partition.FileSystem != FileSystemKind.Unknown)
                .ThenByDescending(partition => partition.BootSectorOffset is not null)
                .First())
            .OrderBy(partition => partition.Offset)
            .ToArray();
        if (descriptors.Length == 0)
        {
            return [new ScanTarget("whole-device", 0, sourceLength, FileSystemKind.Unknown, "整盘",
                RecoveryConfidence.Low, new PartitionEvidence(ScanTargetOrigin.WholeDevice, true, false, false, false,
                    "分区表没有提供可用范围，保留只读整盘扫描目标。"))];
        }

        var targets = new List<ScanTarget>(descriptors.Length);
        foreach (var partition in descriptors)
        {
            var name = partition.Name ?? string.Empty;
            var wholeDevice = partition.Offset == 0 && partition.Length == sourceLength &&
                (name.Contains("whole", StringComparison.OrdinalIgnoreCase) || name.Contains("整盘", StringComparison.OrdinalIgnoreCase) ||
                 name.Contains("整块", StringComparison.OrdinalIgnoreCase));
            var origin = partition.Evidence?.Origin ?? (wholeDevice
                ? ScanTargetOrigin.WholeDevice
                : partition.BootSectorOffset is not null || name.Contains("备份引导", StringComparison.OrdinalIgnoreCase)
                ? ScanTargetOrigin.BackupBootSector
                : name.Contains("GPT备份", StringComparison.OrdinalIgnoreCase)
                    ? ScanTargetOrigin.BackupPartitionTable
                    : name.Contains("EBR", StringComparison.OrdinalIgnoreCase) || name.Contains("logical", StringComparison.OrdinalIgnoreCase)
                        ? ScanTargetOrigin.ExtendedPartition
                        : name.Contains("丢失", StringComparison.OrdinalIgnoreCase) || name.Contains("检测到", StringComparison.OrdinalIgnoreCase)
                            ? ScanTargetOrigin.PrimaryBootSector
                            : ScanTargetOrigin.PrimaryPartitionTable);
            var overlaps = descriptors.Any(other => !ReferenceEquals(other, partition) &&
                partition.Offset < other.Offset + other.Length && other.Offset < partition.Offset + partition.Length);
            var fromTable = origin is ScanTargetOrigin.PrimaryPartitionTable or ScanTargetOrigin.BackupPartitionTable or ScanTargetOrigin.ExtendedPartition;
            var confidence = overlaps
                ? RecoveryConfidence.Low
                : origin == ScanTargetOrigin.WholeDevice
                    ? partition.FileSystem == FileSystemKind.Unknown ? RecoveryConfidence.Low : RecoveryConfidence.Medium
                : fromTable && partition.FileSystem != FileSystemKind.Unknown
                    ? RecoveryConfidence.High
                    : RecoveryConfidence.Medium;
            var backupValid = origin is ScanTargetOrigin.BackupPartitionTable or ScanTargetOrigin.BackupBootSector;
            var inferredEvidence = new PartitionEvidence(
                origin,
                GeometryValid: true,
                BootSectorValid: partition.FileSystem != FileSystemKind.Unknown,
                BackupStructureValid: backupValid,
                OverlapsAnotherTarget: overlaps,
                Explanation: origin switch
                {
                    ScanTargetOrigin.BackupPartitionTable => "主 GPT 不可用，已验证磁盘末尾的备份 GPT 与分区范围。",
                    ScanTargetOrigin.ExtendedPartition => "由 MBR 扩展分区的 EBR 链定位，并通过循环、越界和重叠检查。",
                    ScanTargetOrigin.BackupBootSector => "由文件系统备用引导结构反推出原始分区范围。",
                    ScanTargetOrigin.PrimaryBootSector => "在未占用范围发现可解析的文件系统引导结构。",
                    ScanTargetOrigin.WholeDevice => partition.FileSystem == FileSystemKind.Unknown
                        ? "分区表和文件系统结构均不可用，只能保留整盘内容扫描范围。"
                        : "介质没有分区表，但整盘文件系统引导结构验证通过。",
                    _ => partition.FileSystem == FileSystemKind.Unknown
                        ? "由分区表提供范围，但文件系统结构尚未通过验证。"
                        : "由分区表提供范围，文件系统引导结构验证通过。"
                });
            var evidence = partition.Evidence is null
                ? inferredEvidence
                : partition.Evidence with
                {
                    OverlapsAnotherTarget = overlaps,
                    Explanation = overlaps
                        ? partition.Evidence.Explanation + " 与另一候选范围重叠，已降为低可信。"
                        : partition.Evidence.Explanation
                };
            int? partitionTableNumber = fromTable && partition.Number > 0 ? partition.Number : null;
            targets.Add(new ScanTarget(
                CheckpointTargetId(partition), partition.Offset, partition.Length, partition.FileSystem,
                name, confidence, evidence, partitionTableNumber, partition.BootSectorOffset));
        }
        return targets;
    }

    private void ShowPartitionCandidates(IEnumerable<PartitionDescriptor> partitions, ulong sourceLength)
    {
        var items = CreateScanTargets(partitions, sourceLength).Select(target => new PartitionCandidateViewItem(target)).ToArray();
        _partitionCandidates.Clear();
        _lowConfidencePartitionCandidates.Clear();
        foreach (var item in items)
        {
            if (item.Target.Confidence == RecoveryConfidence.Low) _lowConfidencePartitionCandidates.Add(item);
            else _partitionCandidates.Add(item);
        }
        PartitionCandidateSummary.Text = $"高/中可信 {_partitionCandidates.Count:N0} 个 · 低可信 {_lowConfidencePartitionCandidates.Count:N0} 个";
        if (_lowConfidencePartitionCandidates.Count > 0)
            AppendLog($"发现 {_lowConfidencePartitionCandidates.Count:N0} 个低可信或冲突范围，默认不纳入自动元数据扫描。");
    }

    private IReadOnlyList<PartitionDescriptor> GetSelectedPartitionCandidates(IEnumerable<PartitionDescriptor> partitions)
    {
        var descriptors = partitions.ToArray();
        var selected = _partitionCandidates.Concat(_lowConfidencePartitionCandidates)
            .Where(item => item.IsSelected).Select(item => item.Target.Id)
            .ToHashSet(StringComparer.Ordinal);
        return descriptors.Where(partition => selected.Contains(CheckpointTargetId(partition))).ToArray();
    }

    private async Task WaitForPartitionSelectionAsync(CancellationToken cancellationToken)
    {
        if (_partitionCandidates.Count == 0 && _lowConfidencePartitionCandidates.Count == 0) return;
        _partitionSelectionCompletion = new(TaskCreationOptions.RunContinuationsAsynchronously);
        ConfirmPartitionSelectionButton.Visibility = Visibility.Visible;
        ConfirmPartitionSelectionButton.IsEnabled = true;
        StatusText.Text = "分区搜索完成，请核对候选范围并选择要扫描的分区";
        AppendLog("等待确认候选分区。高/中可信范围默认勾选；低可信范围折叠且默认不选。");
        using var registration = cancellationToken.Register(() => _partitionSelectionCompletion.TrySetCanceled(cancellationToken));
        try { await _partitionSelectionCompletion.Task; }
        finally
        {
            ConfirmPartitionSelectionButton.Visibility = Visibility.Collapsed;
            _partitionSelectionCompletion = null;
        }
    }

    private void ConfirmPartitionSelection_Click(object sender, RoutedEventArgs e)
    {
        if (_partitionCandidates.Concat(_lowConfidencePartitionCandidates).All(item => !item.IsSelected))
        {
            MessageBox.Show(this, "请至少选择一个候选分区；若没有可信范围，可停止扫描并改用“快速格式化 / RAW”场景进行整盘内容扫描。",
                "候选分区", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        ConfirmPartitionSelectionButton.IsEnabled = false;
        _partitionSelectionCompletion?.TrySetResult(true);
    }

    private static string CheckpointTargetId(PartitionDescriptor partition) =>
        $"target-{partition.Offset:x16}-{partition.Length:x16}";

    private static IReadOnlyList<PartitionDescriptor> MergePartitionRanges(IEnumerable<PartitionDescriptor> partitions) =>
        partitions
            .GroupBy(partition => (partition.Offset, partition.Length))
            .Select(group => group
                .OrderByDescending(partition => partition.FileSystem != FileSystemKind.Unknown)
                .ThenByDescending(partition => partition.BootSectorOffset is not null)
                .First())
            .OrderBy(partition => partition.Offset)
            .ToArray();

    private static IReadOnlyList<PartitionDescriptor> RestorePartitionTargets(IReadOnlyList<ScanTarget> targets,
        IReadOnlyList<PartitionDescriptor> currentTable)
    {
        var restored = new List<PartitionDescriptor>();
        foreach (var target in targets.Where(target => target.Length > 0))
        {
            var current = currentTable.FirstOrDefault(partition => partition.Offset == target.Offset && partition.Length == target.Length);
            if (current is not null) { restored.Add(current); continue; }
            restored.Add(new PartitionDescriptor(target.PartitionTableNumber ?? 0, target.Offset, target.Length,
                Guid.Empty, Guid.Empty, target.DisplayName, target.FileSystem, false,
                target.BackupBootSectorOffset, target.Evidence));
        }
        return restored;
    }

    private void UpdateCheckpointTargets(IEnumerable<PartitionDescriptor> partitions)
    {
        if (_activeScanCheckpoint is null) return;
        _activeScanCheckpoint = _activeScanCheckpoint with
        {
            ScanTargets = CreateScanTargets(partitions, _activeScanCheckpoint.Source.Length)
        };
    }

    private bool IsCheckpointStageComplete(RecoveryStageKind kind) =>
        _activeScanCheckpoint?.Stages.FirstOrDefault(stage => stage.Kind == kind)?.IsStageComplete == true;

    private ulong GetCheckpointResumePosition(RecoveryStageKind kind, string? targetId = null)
    {
        var stage = _activeScanCheckpoint?.Stages.FirstOrDefault(stage => stage.Kind == kind);
        if (stage is null) return 0;
        return string.IsNullOrWhiteSpace(targetId) ? stage.ResumeBytePosition : stage.ResumeBytePositionFor(targetId);
    }

    private ulong ResumePositionForPartition(RecoveryStageKind kind, PartitionDescriptor partition)
    {
        var position = GetCheckpointResumePosition(kind, CheckpointTargetId(partition));
        return position >= partition.Offset && position - partition.Offset <= partition.Length ? position : 0;
    }

    private async Task TransitionCheckpointStageAsync(RecoveryStageKind kind, ScanCheckpointStageState state,
        string message, bool forceSave)
    {
        if (_activeScanCheckpoint is null) return;
        var index = _activeScanCheckpoint.Stages.ToList().FindIndex(stage => stage.Kind == kind);
        if (index < 0) return;
        var stages = _activeScanCheckpoint.Stages.ToArray();
        var existing = stages[index];
        stages[index] = existing with
        {
            State = state,
            CandidateCount = Candidates.Count,
            UpdatedUtc = DateTime.UtcNow,
            Message = message
        };
        _activeScanCheckpoint = _activeScanCheckpoint with
        {
            Stages = stages,
            CurrentStageId = state == ScanCheckpointStageState.Running ? existing.StageId : null,
            CurrentBytePosition = state == ScanCheckpointStageState.Running ? existing.ResumeBytePosition : 0,
            CandidateIndex = _activeScanCheckpoint.CandidateIndex
        };
        _activeCheckpointTargetId = null;
        if (state != ScanCheckpointStageState.Running && Candidates.Count > 0 && _activeScanSource is not null)
        {
            try
            {
                // A terminal transition is the durability boundary. This includes cancellation
                // and failure so the last in-memory batch is indexed before the checkpoint points
                // at that terminal state.
                await SaveAutomaticCandidateSessionAsync(_activeScanSource, CancellationToken.None);
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or InvalidDataException)
            {
                AppendLog($"候选索引未能在阶段结束时落盘：{exception.Message}");
            }
        }
        await PersistActiveScanCheckpointAsync(forceSave, CancellationToken.None);
    }

    private void UpdateActiveCheckpointProgress(ScanProgress progress)
    {
        if (_activeScanCheckpoint?.CurrentStageId is not string stageId) return;
        var stages = _activeScanCheckpoint.Stages.ToArray();
        var index = Array.FindIndex(stages, stage => string.Equals(stage.StageId, stageId, StringComparison.Ordinal));
        if (index < 0) return;
        var stage = stages[index];
        // Only scanners that expose a proven physical resume boundary may advance a byte
        // checkpoint. Ordinary counters (MFT record index, validation item count, etc.) must not
        // be mistaken for a source-device byte offset.
        var position = stage.ResumeMode == ScanCheckpointResumeMode.BytePosition && progress.CheckpointPosition is { } checkpointPosition
            ? checkpointPosition
            : stage.BytePosition;
        var targetPositions = stage.TargetBytePositions is null
            ? new Dictionary<string, ulong>(StringComparer.Ordinal)
            : new Dictionary<string, ulong>(stage.TargetBytePositions, StringComparer.Ordinal);
        if (stage.ResumeMode == ScanCheckpointResumeMode.BytePosition &&
            progress.CheckpointPosition is { } targetPosition &&
            !string.IsNullOrWhiteSpace(_activeCheckpointTargetId))
        {
            targetPositions[_activeCheckpointTargetId] = targetPosition;
        }
        stages[index] = stage with
        {
            BytePosition = position,
            TotalBytes = progress.CheckpointTotal ?? stage.TotalBytes,
            CandidateCount = Math.Max(progress.Candidates, Candidates.Count),
            UpdatedUtc = DateTime.UtcNow,
            Message = progress.Message,
            CurrentTargetId = _activeCheckpointTargetId,
            TargetBytePositions = targetPositions
        };
        _activeScanCheckpoint = _activeScanCheckpoint with
        {
            Stages = stages,
            CurrentBytePosition = position
        };
    }

    private async Task PersistProgressCheckpointAsync(ScanProgress progress)
    {
        await _checkpointProgressGate.WaitAsync();
        try
        {
            if (_activeScanCheckpoint is null) return;
            var saveReason = _scanCheckpointThrottle.GetSaveReason(_activeScanCheckpoint.CurrentStageId);
            if (saveReason != ScanCheckpointSaveReason.None && _activeScanSource is not null &&
                Candidates.Count > _activeScanCheckpoint.CandidateIndex.CandidateCount)
                await SaveAutomaticCandidateSessionAsync(_activeScanSource, CancellationToken.None);
            UpdateActiveCheckpointProgress(progress);
            if (saveReason != ScanCheckpointSaveReason.None)
                await PersistActiveScanCheckpointAsync(force: false, CancellationToken.None);
        }
        finally { _checkpointProgressGate.Release(); }
    }

    private void QueueProgressCheckpoint(ScanProgress progress)
    {
        _latestCheckpointProgress = progress;
        if (_checkpointProgressLoopRunning) return;
        _checkpointProgressLoopRunning = true;
        _ = RunProgressCheckpointLoopAsync();
    }

    private async Task RunProgressCheckpointLoopAsync()
    {
        try
        {
            while (_latestCheckpointProgress is { } progress)
            {
                _latestCheckpointProgress = null;
                await PersistProgressCheckpointAsync(progress);
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException)
        {
            AppendLog($"扫描进度检查点保存失败：{ex.Message}");
        }
        finally
        {
            _checkpointProgressLoopRunning = false;
            if (_latestCheckpointProgress is not null) QueueProgressCheckpoint(_latestCheckpointProgress);
        }
    }

    private async Task<ScanCheckpointSaveReason> PersistActiveScanCheckpointAsync(bool force, CancellationToken cancellationToken)
    {
        if (_activeScanCheckpoint is null || string.IsNullOrWhiteSpace(_activeScanCheckpointPath)) return ScanCheckpointSaveReason.None;
        try
        {
            return await _scanCheckpointThrottle.SaveIfDueAsync(_activeScanCheckpointPath, _activeScanCheckpoint, force, cancellationToken);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException)
        {
            AppendLog($"扫描检查点保存失败：{ex.Message}");
            return ScanCheckpointSaveReason.None;
        }
    }

    private async Task MarkCurrentCheckpointStageAsync(ScanCheckpointStageState state, string message,
        CancellationToken cancellationToken)
    {
        if (_activeScanCheckpoint?.CurrentStageId is not string stageId) return;
        var stage = _activeScanCheckpoint.Stages.FirstOrDefault(item => string.Equals(item.StageId, stageId, StringComparison.Ordinal));
        if (stage is null) return;
        await TransitionCheckpointStageAsync(stage.Kind, state, message, forceSave: true);
        await PersistActiveScanCheckpointAsync(force: true, cancellationToken);
    }

    private async Task SaveAutomaticCandidateSessionAsync(MediaDescriptor source, CancellationToken cancellationToken)
    {
        if (_activeScanCheckpoint is null || Candidates.Count == 0) return;
        var entries = CreateSessionCandidates();
        var session = new ScanSession(3, DateTime.UtcNow, source, entries, null);
        var path = Path.Combine(_activeScanCheckpoint.RecoveryWorkingDirectory, "raintrace-candidate-index-v3.yhs");
        await WriteTextAtomicAsync(path, JsonSerializer.Serialize(session, JsonOptions), new UTF8Encoding(false), cancellationToken);
        await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read,
            1024 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan);
        var sha256 = Convert.ToHexString(await SHA256.HashDataAsync(stream, cancellationToken)).ToLowerInvariant();
        var artifacts = Candidates.Select(candidate => candidate.StagedRecoveryPath)
            .Where(path => !string.IsNullOrWhiteSpace(path)).Select(path => path!).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        _activeScanCheckpoint = _activeScanCheckpoint with
        {
            CandidateIndex = new ScanCandidateIndexCheckpoint(Candidates.Count, Candidates.Count, path, sha256, artifacts)
        };
    }

    private SessionCandidate[] CreateSessionCandidates() => Candidates.Select(candidate =>
    {
        var primary = CreateSessionSourceContext(candidate);
        var alternates = candidate.AlternateCandidates.Select(CreateSessionSourceContext).ToArray();
        return new SessionCandidate(candidate, primary.NtfsBoot, primary.ExFatBoot, primary.Fat32Boot,
            primary.PartitionOffset, primary.TskCandidate, primary.TskOptions, candidate.AlternateCandidates,
            alternates);
    }).ToArray();

    private SessionSourceContext CreateSessionSourceContext(RecoveryCandidate candidate)
    {
        _ntfsResults.TryGetValue(candidate, out var ntfs);
        _exFatResults.TryGetValue(candidate, out var exFat);
        _fat32Results.TryGetValue(candidate, out var fat32);
        _tskResults.TryGetValue(candidate, out var tsk);
        return new(candidate, ntfs?.Boot, exFat?.Boot, fat32?.Boot,
            ntfs?.PartitionOffset ?? exFat?.PartitionOffset ?? fat32?.PartitionOffset ?? 0,
            tsk?.Candidate, tsk?.Options);
    }

    private static string SanitizePathComponent(string value)
    {
        var invalid = Path.GetInvalidFileNameChars().ToHashSet();
        var sanitized = new string(value.Select(character => invalid.Contains(character) ? '_' : character).ToArray()).Trim();
        return string.IsNullOrWhiteSpace(sanitized) ? "source" : sanitized;
    }

    private async void Scan_Click(object sender, RoutedEventArgs e)
    {
        if (MetadataCheck.IsChecked != true && DeepMetadataCheck.IsChecked != true && ExFatDeepMetadataCheck.IsChecked != true &&
            FullDiskMetadataCheck.IsChecked != true && CarveCheck.IsChecked != true && LostPartitionCheck.IsChecked != true)
        {
            MessageBox.Show(this, "请至少选择一种扫描方式。", "扫描方式", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        if (SourceCombo.SelectedItem is not MediaDescriptor selectedSource)
        {
            MessageBox.Show(this, "请先选择源介质或镜像。", "扫描", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        var resumeCheckpoint = _pendingResumeCheckpoint;
        _pendingResumeCheckpoint = null;
        var recoveryPlan = RecoveryPlanFactory.Create(resumeCheckpoint?.Scenario ?? GetSelectedScenario(),
            GetSelectedFileCategories(), CarveCheck.IsChecked == true);
        AppendLog($"恢复场景：{ScenarioLabel(recoveryPlan.Scenario)}；计划阶段：{string.Join(" → ", recoveryPlan.Stages.Select(stage => stage.DisplayName))}。源介质保持只读。");
        if (RecoveryDestinationSafety.IsDestinationOnSource(selectedSource, DestinationBox.Text, out var destinationReason))
        {
            MessageBox.Show(this, $"扫描检查点、PhotoRec 暂存文件和恢复输出必须位于另一块物理磁盘。\n\n{destinationReason}",
                "安全阻止", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }
        if (CarveCheck.IsChecked == true)
        {
            var photoRecExecutable = FindPhotoRecExecutable();
            if (!PhotoRecEngine.IsAvailable(photoRecExecutable))
            {
                MessageBox.Show(this, "发布包中缺少 PhotoRec 引擎。请重新解压完整的雨痕程序包。", "PhotoRec 不可用", MessageBoxButton.OK, MessageBoxImage.Error);
                return;
            }
        }
        _operation = new CancellationTokenSource();
        if (resumeCheckpoint is null)
        {
            Candidates.Clear();
            _pendingStreamedCandidates.Clear();
            _ntfsResults.Clear();
            _exFatResults.Clear();
            _fat32Results.Clear();
            _tskResults.Clear();
            _candidateHashes.Clear();
            CountText.Text = "0 个候选文件";
        }
        SetBusy(true, "正在打开源介质…");
        try
        {
            var device = await OpenSelectedSourceAsync(_operation.Token);
            StatusText.Text = "源介质已只读打开，正在识别分区…";
            var progress = CreateProgress();
            var initialPartitionTableRanges = await PartitionScanner.ScanAsync(device, _operation.Token);
            var partitionTableRanges = await PartitionScanner.EnrichWithBackupStructuresAsync(
                device, initialPartitionTableRanges, _operation.Token);
            var backupResolved = partitionTableRanges.Count(partition => partition.BootSectorOffset is not null) -
                initialPartitionTableRanges.Count(partition => partition.BootSectorOffset is not null);
            if (backupResolved > 0)
                AppendLog($"主引导结构不可用，已通过只读备用引导识别 {backupResolved:N0} 个分区范围。");
            IReadOnlyList<PartitionDescriptor> partitions = partitionTableRanges;
            AppendLog($"识别到 {partitions.Count} 个分区/扫描范围。");
            if (recoveryPlan.Scenario == RecoveryScenario.LostPartition)
                ShowPartitionCandidates(partitions, device.Length);
            if (resumeCheckpoint is null)
                await InitializeScanCheckpointAsync(selectedSource, device, partitionTableRanges, recoveryPlan, _operation.Token);
            else
            {
                _activeScanCheckpoint = resumeCheckpoint.PrepareForResume();
                _activeScanSource = selectedSource;
                _activeScanCheckpointPath = ScanCheckpointStore.GetDefaultPath(_activeScanCheckpoint);
                AppendLog($"继续 v3 扫描会话：{_activeScanCheckpointPath}");
            }

            var partitionStageComplete = IsCheckpointStageComplete(RecoveryStageKind.PartitionDiscovery);
            if (partitionStageComplete && resumeCheckpoint is not null)
            {
                partitions = RestorePartitionTargets(_activeScanCheckpoint!.ScanTargets, partitionTableRanges);
                ShowPartitionCandidates(partitions, device.Length);
                AppendLog("分区识别阶段已完成，继续会话时不重复搜索；已从检查点恢复扫描目标。");
            }
            else if (LostPartitionCheck.IsChecked == true)
            {
                if (resumeCheckpoint is not null && _activeScanCheckpoint is not null)
                {
                    var preserved = RestorePartitionTargets(_activeScanCheckpoint.ScanTargets, partitionTableRanges);
                    partitions = MergePartitionRanges(partitions.Concat(preserved));
                    AppendLog($"已从中断检查点保留 {partitions.Count:N0} 个既有分区范围；续扫不会丢弃先前发现的候选。");
                }
                await TransitionCheckpointStageAsync(RecoveryStageKind.PartitionDiscovery, ScanCheckpointStageState.Running, "正在搜索丢失分区。", forceSave: true);
                _activeCheckpointTargetId = "whole-device";
                AppendLog("开始逐扇区搜索丢失的 NTFS、exFAT 和 FAT32 分区引导记录。");
                var persistedLost = new List<PartitionDescriptor>();
                var lost = await PartitionScanner.FindLostPartitionsAsync(device, partitions, progress, _operation.Token,
                    GetCheckpointResumePosition(RecoveryStageKind.PartitionDiscovery), async (candidate, token) =>
                    {
                        persistedLost.Add(candidate);
                        UpdateCheckpointTargets(partitions.Concat(persistedLost));
                        await PersistActiveScanCheckpointAsync(force: true, token);
                    });
                var combined = MergePartitionRanges(partitions.Concat(lost)).ToArray();
                if (lost.Count > 0)
                    combined = combined.Where(partition => !(partition.Offset == 0 && partition.Length == device.Length &&
                        partition.FileSystem == FileSystemKind.Unknown)).ToArray();
                ShowPartitionCandidates(combined, device.Length);
                await WaitForPartitionSelectionAsync(_operation.Token);
                partitions = GetSelectedPartitionCandidates(combined);
                UpdateCheckpointTargets(partitions);
                AppendLog($"丢失分区搜索完成：新增 {lost.Count:N0} 个候选分区；用户确认扫描 {partitions.Count:N0} 个范围。");
            }
            await TransitionCheckpointStageAsync(RecoveryStageKind.PartitionDiscovery, ScanCheckpointStageState.Completed,
                "分区识别阶段完成。", forceSave: true);

            var tskHandledOffsets = _tskResults.Values.Select(context => context.Options.PartitionOffsetBytes).ToHashSet();
            var runTskStage = MetadataCheck.IsChecked == true &&
                !IsCheckpointStageComplete(RecoveryStageKind.FileSystemMetadata);
            if (runTskStage)
            {
                await TransitionCheckpointStageAsync(RecoveryStageKind.FileSystemMetadata, ScanCheckpointStageState.Running,
                    "正在运行 TSK 文件系统元数据扫描。", forceSave: true);
                var tskBinDirectory = FindSleuthKitBinDirectory();
                if (!SleuthKitEngine.IsAvailable(tskBinDirectory))
                    AppendLog("发布包中缺少 Sleuth Kit，文件系统元数据扫描将回退到雨痕原生扫描器。");
                else
                {
                    AppendLog($"启用成熟文件系统主引擎：{await SleuthKitEngine.GetVersionAsync(tskBinDirectory, _operation.Token)}。源介质保持只读。");
                    var supported = partitions.Where(partition => partition.BootSectorOffset is null &&
                        partition.FileSystem is FileSystemKind.Ntfs or FileSystemKind.ExFat or FileSystemKind.Fat12 or FileSystemKind.Fat16 or FileSystemKind.Fat32).ToArray();
                    foreach (var partition in supported)
                    {
                        var tskOptions = new SleuthKitScanOptions(selectedSource.Path, partition.Offset, selectedSource.LogicalSectorSize,
                            Recursive: partition.FileSystem != FileSystemKind.ExFat);
                        try
                        {
                            AppendLog($"TSK 元数据扫描：{partition.Name} · {partition.FileSystem} · 起始 {partition.Offset:N0} 字节。");
                            var tskLimit = partition.FileSystem switch
                            {
                                FileSystemKind.Ntfs => TimeSpan.FromMinutes(5),
                                FileSystemKind.ExFat => TimeSpan.FromSeconds(30),
                                _ => TimeSpan.FromSeconds(90)
                            };
                            SetExternalEngineActive(true, "TSK");
                            SleuthKitScanResult tskScan;
                            try
                            {
                                tskScan = await SleuthKitEngine.ScanDeletedAsync(tskBinDirectory, tskOptions, _operation.Token, progress, tskLimit);
                            }
                            finally { SetExternalEngineActive(false); }
                            if (!tskScan.CompletedNormally)
                                throw new InvalidDataException($"fls 退出代码 {tskScan.ExitCode}：{tskScan.StandardError}");
                            var tskBatch = new List<RecoveryCandidate>(tskScan.Candidates.Count);
                            foreach (var sourceCandidate in tskScan.Candidates)
                            {
                                var displayPath = supported.Length > 1 ? Path.Combine(partition.Name, sourceCandidate.OriginalPath) : sourceCandidate.OriginalPath;
                                var tskCandidate = sourceCandidate with { OriginalPath = displayPath };
                                var item = new RecoveryCandidate
                                {
                                    RecordNumber = long.TryParse(sourceCandidate.MetadataAddress.Split('-')[0], NumberStyles.Integer, CultureInfo.InvariantCulture, out var record) ? record : -1,
                                    Name = Path.GetFileName(displayPath), OriginalPath = displayPath, Size = sourceCandidate.Size,
                                    IsDeleted = true, IsDirectory = sourceCandidate.IsDirectory, ModifiedUtc = sourceCandidate.ModifiedUtc,
                                    FileSystem = partition.FileSystem, Discovery = RecoveryDiscovery.SleuthKitMetadata,
                                    Quality = RecoveryQuality.Unknown,
                                    QualityReason = $"由 The Sleuth Kit 4.15.0 解析文件系统元数据；保留原名，恢复后执行结构校验。历史重复记录 {1 + sourceCandidate.AlternateMetadataAddresses.Count:N0} 个。"
                                };
                                tskBatch.Add(item);
                                _tskResults[item] = new(tskOptions, tskCandidate);
                            }
                            Candidates.AddRange(tskBatch);
                            tskHandledOffsets.Add(partition.Offset);
                            AppendLog($"TSK 元数据完成：{tskScan.Candidates.Count:N0} 个逻辑候选；控制台编码 {tskScan.DetectedEncoding}。");
                        }
                        catch (Exception ex) when (ex is not OperationCanceledException)
                        {
                            SetExternalEngineActive(false);
                            AppendLog($"TSK 无法解析 {partition.Name}，该分区回退到雨痕原生扫描器：{ex.Message}");
                        }
                    }
                }
                await TransitionCheckpointStageAsync(RecoveryStageKind.FileSystemMetadata, ScanCheckpointStageState.Completed,
                    "TSK 文件系统元数据阶段完成。", forceSave: true);
            }
            else if (IsCheckpointStageComplete(RecoveryStageKind.FileSystemMetadata))
                AppendLog("TSK 文件系统元数据阶段已完成，继续会话时不重复执行。");

            var runNativeMetadataStage = !IsCheckpointStageComplete(RecoveryStageKind.DeepMetadata) &&
                (MetadataCheck.IsChecked == true || DeepMetadataCheck.IsChecked == true ||
                 ExFatDeepMetadataCheck.IsChecked == true || FullDiskMetadataCheck.IsChecked == true);
            if (runNativeMetadataStage)
            {
                await TransitionCheckpointStageAsync(RecoveryStageKind.DeepMetadata, ScanCheckpointStageState.Running,
                    "正在运行雨痕原生元数据补充扫描。", forceSave: true);
                var ntfsPartitions = partitions.Where(p => p.FileSystem == FileSystemKind.Ntfs).ToArray();
                if (ntfsPartitions.Length == 0) AppendLog("没有识别到 NTFS 分区，跳过 MFT 扫描。");
                foreach (var partition in ntfsPartitions)
                {
                    _activeCheckpointTargetId = CheckpointTargetId(partition);
                    var tskHandled = tskHandledOffsets.Contains(partition.Offset);
                    if (tskHandled && DeepMetadataCheck.IsChecked != true && FullDiskMetadataCheck.IsChecked != true) continue;
                    AppendLog($"扫描 NTFS：{partition.Name}，起始 {partition.Offset:N0} 字节。深度模式：{(DeepMetadataCheck.IsChecked == true ? "开启" : "关闭")}；" +
                        $"全盘旧 MFT：{(FullDiskMetadataCheck.IsChecked == true ? "开启（耗时）" : "关闭")}。");
                    var options = new ScanOptions(
                        StartOffset: ResumePositionForPartition(RecoveryStageKind.DeepMetadata, partition),
                        DeepMetadataScan: DeepMetadataCheck.IsChecked == true,
                        FullDiskMetadataScan: FullDiskMetadataCheck.IsChecked == true);
                    var streamedCandidates = new HashSet<RecoveryCandidate>();
                    NtfsScanResult? provisionalContext = null;
                    Action<RecoveryCandidate>? candidateAvailable = null;
                    if (options.DeepMetadataScan || options.FullDiskMetadataScan)
                    {
                        var bootBytes = new byte[512];
                        await device.ReadExactlyAsync(partition.BootSectorOffset ?? partition.Offset, bootBytes, _operation.Token);
                        provisionalContext = NtfsScanResult.CreateRecoveryContext(NtfsBootSector.Parse(bootBytes), partition.Offset);
                        candidateAvailable = item =>
                        {
                            if (ntfsPartitions.Length > 1) item.OriginalPath = Path.Combine(partition.Name, item.OriginalPath);
                            if (!streamedCandidates.Add(item)) return;
                            QueueStreamedCandidate(item);
                            _ntfsResults[item] = provisionalContext!;
                        };
                    }
                    var scan = await new NtfsScanner(device, partition.Offset, progress, partition.BootSectorOffset,
                        candidateAvailable).ScanAsync(options, _operation.Token);
                    FlushStreamedCandidates();
                    var ntfsBatch = new List<RecoveryCandidate>();
                    foreach (var item in scan.Candidates)
                    {
                        if (tskHandled && item.Discovery == RecoveryDiscovery.NtfsCurrentMft) continue;
                        if (streamedCandidates.Contains(item)) { _ntfsResults[item] = scan; continue; }
                        if (ntfsPartitions.Length > 1) item.OriginalPath = Path.Combine(partition.Name, item.OriginalPath);
                        ntfsBatch.Add(item);
                        _ntfsResults[item] = scan;
                    }
                    Candidates.AddRange(ntfsBatch);
                    AppendLog($"NTFS 元数据完成：当前 MFT {scan.ParsedCurrentMftRecords:N0}/{scan.CurrentMftRecords:N0} 条有效；" +
                        $"深度检查 {scan.DeepRecordsExamined:N0} 个记录槽，识别 {scan.ParsedDeepRecords:N0} 条旧记录；候选 {scan.Candidates.Count:N0} 个。");
                }

                var exFatPartitions = partitions.Where(p => p.FileSystem == FileSystemKind.ExFat).ToArray();
                foreach (var partition in exFatPartitions)
                {
                    _activeCheckpointTargetId = CheckpointTargetId(partition);
                    var tskHandled = tskHandledOffsets.Contains(partition.Offset);
                    AppendLog($"扫描 exFAT 元数据：{partition.Name}，起始 {partition.Offset:N0} 字节。");
                    var streamedCandidates = new HashSet<RecoveryCandidate>();
                    ExFatScanResult? provisionalContext = null;
                    IProgress<RecoveryCandidate>? candidateProgress = null;
                    if (ExFatDeepMetadataCheck.IsChecked == true)
                    {
                        var bootBytes = new byte[512];
                        await device.ReadExactlyAsync(partition.BootSectorOffset ?? partition.Offset, bootBytes, _operation.Token);
                        provisionalContext = ExFatScanResult.CreateRecoveryContext(ExFatBootSector.Parse(bootBytes), partition.Offset);
                        candidateProgress = new InlineProgress<RecoveryCandidate>(item =>
                        {
                            if (exFatPartitions.Length > 1) item.OriginalPath = Path.Combine(partition.Name, item.OriginalPath);
                            if (tskHandled) RemoveEquivalentTskCandidate(item);
                            if (!streamedCandidates.Add(item)) return;
                            QueueStreamedCandidate(item);
                            _exFatResults[item] = provisionalContext!;
                        });
                    }
                    var scan = await new ExFatScanner(device, partition.Offset, progress, partition.BootSectorOffset,
                        candidateProgress).ScanAsync(
                        new ScanOptions(StartOffset: ResumePositionForPartition(RecoveryStageKind.DeepMetadata, partition),
                            ExFatDeepMetadataScan: ExFatDeepMetadataCheck.IsChecked == true), _operation.Token);
                    FlushStreamedCandidates();
                    var exFatBatch = new List<RecoveryCandidate>();
                    foreach (var item in scan.Candidates)
                    {
                        if (streamedCandidates.Contains(item)) { _exFatResults[item] = scan; continue; }
                        if (exFatPartitions.Length > 1) item.OriginalPath = Path.Combine(partition.Name, item.OriginalPath);
                        if (tskHandled) RemoveEquivalentTskCandidate(item);
                        exFatBatch.Add(item);
                        _exFatResults[item] = scan;
                    }
                    Candidates.AddRange(exFatBatch);
                    AppendLog($"exFAT 元数据完成：找到 {scan.Candidates.Count:N0} 个保留原文件名的删除文件候选；深度模式：{(ExFatDeepMetadataCheck.IsChecked == true ? "开启" : "关闭")}。");
                }
                var fat32Partitions = partitions.Where(p => p.FileSystem == FileSystemKind.Fat32).ToArray();
                foreach (var partition in fat32Partitions)
                {
                    _activeCheckpointTargetId = CheckpointTargetId(partition);
                    if (tskHandledOffsets.Contains(partition.Offset)) continue;
                    AppendLog($"扫描 FAT32 元数据：{partition.Name}，起始 {partition.Offset:N0} 字节。");
                    var scan = await new Fat32Scanner(device, partition.Offset, progress).ScanAsync(_operation.Token);
                    var fatBatch = new List<RecoveryCandidate>(scan.Candidates.Count);
                    foreach (var item in scan.Candidates)
                    {
                        if (fat32Partitions.Length > 1) item.OriginalPath = Path.Combine(partition.Name, item.OriginalPath);
                        fatBatch.Add(item); _fat32Results[item] = scan;
                    }
                    Candidates.AddRange(fatBatch);
                    AppendLog($"FAT32 元数据完成：找到 {scan.Candidates.Count:N0} 个保留原文件名的删除文件候选。");
                }
                if (ntfsPartitions.Length == 0 && exFatPartitions.Length == 0 && fat32Partitions.Length == 0)
                    AppendLog("没有识别到 NTFS、exFAT 或 FAT32 分区，跳过文件系统元数据扫描。");
                await TransitionCheckpointStageAsync(RecoveryStageKind.DeepMetadata, ScanCheckpointStageState.Completed,
                    "雨痕原生元数据补充阶段完成。", forceSave: true);
            }
            else if (IsCheckpointStageComplete(RecoveryStageKind.DeepMetadata))
                AppendLog("雨痕原生元数据补充阶段已完成，继续会话时不重复执行。");

            var runRawStage = CarveCheck.IsChecked == true && !IsCheckpointStageComplete(RecoveryStageKind.RawContent);
            if (runRawStage)
            {
                await TransitionCheckpointStageAsync(RecoveryStageKind.RawContent, ScanCheckpointStageState.Running,
                    "正在运行 PhotoRec 内容扫描。", forceSave: true);
                var photoRecExecutable = FindPhotoRecExecutable();
                var sessionRoot = Path.Combine(_activeScanCheckpoint!.RecoveryWorkingDirectory, "PhotoRec-Staging");
                var workRoot = Path.Combine(sessionRoot, "work");
                AppendLog("开始 PhotoRec 严格扫描：默认只读取文件系统未分配空间；无效文件由 PhotoRec 拒绝。结果先写入目标盘暂存目录。");
                PartitionDescriptor[] ranges;
                var lostPartitionMode = LostPartitionCheck.IsChecked == true;
                if (lostPartitionMode)
                {
                    ranges = [new PartitionDescriptor(0, 0, device.Length, Guid.Empty, Guid.Empty, "整盘", FileSystemKind.Unknown, false)];
                    AppendLog("丢失分区模式的 RAW 兜底只在整个源介质上运行一次；内部候选编号不会作为 PhotoRec 分区号传递。");
                }
                else
                {
                    ranges = partitionTableRanges.Where(partition => partition.FileSystem is FileSystemKind.Ntfs or FileSystemKind.ExFat or FileSystemKind.Fat32).ToArray();
                    if (ranges.Length == 0) ranges = partitionTableRanges.ToArray();
                    if (ranges.Length == 0)
                        ranges = [new PartitionDescriptor(0, 0, device.Length, Guid.Empty, Guid.Empty, "整盘", FileSystemKind.Unknown, false)];
                }
                var totalImported = 0;
                var totalRejected = 0;
                var totalDeduplicated = 0;
                var photoRecFamilies = RecoveryCapabilityRegistry.DefaultPhotoRecFamilies.AsEnumerable();
                if (PhotoRecMediaCheck.IsChecked == true)
                    photoRecFamilies = photoRecFamilies
                        .Concat(RecoveryCapabilityRegistry.GetPhotoRecFamilies(RecoveryFileCategory.Audio))
                        .Concat(RecoveryCapabilityRegistry.GetPhotoRecFamilies(RecoveryFileCategory.Video));
                if (PhotoRecArchiveCheck.IsChecked == true)
                    photoRecFamilies = photoRecFamilies.Concat(RecoveryCapabilityRegistry.GetPhotoRecFamilies(RecoveryFileCategory.Archive));
                var selectedPhotoRecFamilies = photoRecFamilies.Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
                for (var rangeIndex = 0; rangeIndex < ranges.Length; rangeIndex++)
                {
                    var range = ranges[rangeIndex];
                    var wholeDevice = range.Offset == 0 && ranges.Length == 1 &&
                        (lostPartitionMode || selectedSource.Kind == MediaKind.Image || range.FileSystem == FileSystemKind.Unknown);
                    var rangeId = wholeDevice ? "whole-device" : $"partition-{range.Number}";
                    var options = new PhotoRecRunOptions(
                        selectedSource.Path,
                        Path.Combine(sessionRoot, rangeId),
                        Path.Combine(workRoot, rangeId),
                        selectedPhotoRecFamilies,
                        FreeSpaceOnly: range.FileSystem != FileSystemKind.Unknown,
                        TreatSourceAsWholeDevice: wholeDevice,
                        PartitionNumber: wholeDevice || range.Number <= 0 ? null : range.Number);
                    AppendLog($"PhotoRec 扫描范围 {rangeIndex + 1}/{ranges.Length}：{range.Name} · {(options.FreeSpaceOnly ? "仅未分配空间" : "未知文件系统整段扫描")}。");
                    var stableQueue = new ConcurrentQueue<PhotoRecRecoveredFile>();
                    var queuedStablePaths = new ConcurrentDictionary<string, byte>(StringComparer.OrdinalIgnoreCase);
                    var importedStablePaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                    var stableDrainGate = new SemaphoreSlim(1, 1);
                    var stableTimer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(650) };
                    var stableProgress = new InlineProgress<PhotoRecRecoveredFile>(file =>
                    {
                        if (queuedStablePaths.TryAdd(file.Path, 0)) stableQueue.Enqueue(file);
                    });

                    async Task DrainStableFilesAsync(bool drainAll, CancellationToken importToken)
                    {
                        var added = new List<RecoveryCandidate>();
                        var maximum = drainAll ? int.MaxValue : 96;
                        for (var count = 0; count < maximum && stableQueue.TryDequeue(out var file); count++)
                        {
                            try
                            {
                                var prepared = await PreparePhotoRecCandidateAsync(file, range, importToken);
                                if (prepared.Candidate is not null)
                                {
                                    added.Add(prepared.Candidate);
                                    totalImported++;
                                }
                                else if (prepared.Merged)
                                {
                                    totalDeduplicated++;
                                }
                                importedStablePaths.Add(file.Path);
                            }
                            catch (OperationCanceledException) { throw; }
                            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException or EndOfStreamException)
                            {
                                // PhotoRec may still be finalising a just-reported file. Its final
                                // output enumeration will retry anything not recorded as imported.
                                AppendLog($"暂缓导入一个 PhotoRec 候选，结束阶段将重试：{Path.GetFileName(file.Path)} · {ex.Message}");
                            }
                        }
                        if (added.Count == 0) return;
                        Candidates.AddRange(added);
                        RefreshResults();
                    }

                    async void StableTimer_Tick(object? timerSender, EventArgs timerArgs)
                    {
                        if (!await stableDrainGate.WaitAsync(0)) return;
                        try { await DrainStableFilesAsync(drainAll: false, _operation.Token); }
                        catch (OperationCanceledException) { }
                        catch (Exception ex) { AppendLog($"PhotoRec 实时结果导入失败，结束阶段将重试：{ex.Message}"); }
                        finally { stableDrainGate.Release(); }
                    }

                    stableTimer.Tick += StableTimer_Tick;
                    stableTimer.Start();
                    var priorStableFiles = await PhotoRecEngine.FindStableExistingOutputsAsync(
                        options.DestinationBase, _operation.Token);
                    foreach (var file in priorStableFiles)
                    {
                        if (queuedStablePaths.TryAdd(file.Path, 0)) stableQueue.Enqueue(file);
                    }
                    if (priorStableFiles.Count > 0)
                    {
                        await stableDrainGate.WaitAsync(_operation.Token);
                        try { await DrainStableFilesAsync(drainAll: true, _operation.Token); }
                        finally { stableDrainGate.Release(); }
                        AppendLog($"已重新导入上次中断后稳定写出的 PhotoRec 文件 {priorStableFiles.Count:N0} 个，再启动本阶段。");
                    }
                    PhotoRecRunResult result;
                    SetExternalEngineActive(true, "PhotoRec");
                    try
                    {
                        result = await PhotoRecEngine.RunAsync(photoRecExecutable, options, progress, stableProgress, _operation.Token);
                    }
                    catch (OperationCanceledException)
                    {
                        // PhotoRec has now released its handles. Probe every old/new output twice
                        // and import the final stable batch before the terminal checkpoint is saved.
                        var interruptedFiles = await PhotoRecEngine.FindStableExistingOutputsAsync(
                            options.DestinationBase, CancellationToken.None);
                        foreach (var file in interruptedFiles)
                        {
                            if (queuedStablePaths.TryAdd(file.Path, 0)) stableQueue.Enqueue(file);
                        }
                        await stableDrainGate.WaitAsync(CancellationToken.None);
                        try { await DrainStableFilesAsync(drainAll: true, CancellationToken.None); }
                        finally { stableDrainGate.Release(); }
                        throw;
                    }
                    finally
                    {
                        SetExternalEngineActive(false);
                        stableTimer.Stop();
                        stableTimer.Tick -= StableTimer_Tick;
                    }
                    await stableDrainGate.WaitAsync(_operation.Token);
                    try { await DrainStableFilesAsync(drainAll: true, _operation.Token); }
                    finally { stableDrainGate.Release(); }
                    totalRejected += result.RejectedFiles;
                    var photoRecBatch = new List<RecoveryCandidate>(result.Files.Count);
                    foreach (var file in result.Files.Where(file => !importedStablePaths.Contains(file.Path)))
                    {
                        try
                        {
                            var prepared = await PreparePhotoRecCandidateAsync(file, range, _operation.Token);
                            if (prepared.Candidate is not null)
                            {
                                photoRecBatch.Add(prepared.Candidate);
                                totalImported++;
                            }
                            else if (prepared.Merged) totalDeduplicated++;
                        }
                        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException or EndOfStreamException)
                        {
                            AppendLog($"跳过无法稳定读取的 PhotoRec 输出：{Path.GetFileName(file.Path)} · {ex.Message}");
                        }
                    }
                    Candidates.AddRange(photoRecBatch);
                    AppendLog(result.Summary);
                    RefreshResults();
                }
                AppendLog($"PhotoRec 扫描完成：导入 {totalImported:N0} 个严格校验结果，合并 {totalDeduplicated:N0} 个与原名候选内容相同的副本，拒绝 {totalRejected:N0} 个无效候选。暂存目录：{sessionRoot}");
                await TransitionCheckpointStageAsync(RecoveryStageKind.RawContent, ScanCheckpointStageState.Completed,
                    "PhotoRec 内容扫描阶段完成。", forceSave: true);
            }
            else if (CarveCheck.IsChecked == true && IsCheckpointStageComplete(RecoveryStageKind.RawContent))
                AppendLog("PhotoRec 内容扫描阶段已完成，继续会话时不重复执行。");
            await ConsolidateCandidateIndexAsync(_operation.Token);
            await SaveAutomaticCandidateSessionAsync(selectedSource, _operation.Token);
            await PersistActiveScanCheckpointAsync(force: true, _operation.Token);
            AppendLog($"扫描完成，共找到 {Candidates.Count:N0} 个逻辑候选文件。");
            RefreshResults();
            StatusText.Text = "扫描完成";
        }
        catch (OperationCanceledException)
        {
            FlushStreamedCandidates();
            await MarkCurrentCheckpointStageAsync(ScanCheckpointStageState.Cancelled, "操作已取消；可从检查点继续。", CancellationToken.None);
            AppendLog("操作已由用户取消。扫描结果和检查点已保留。");
        }
        catch (Exception ex)
        {
            FlushStreamedCandidates();
            await MarkCurrentCheckpointStageAsync(ScanCheckpointStageState.Failed, ex.Message, CancellationToken.None);
            ShowError(ex);
        }
        finally
        {
            _activeScanCheckpoint = null;
            _activeScanSource = null;
            _activeScanCheckpointPath = null;
            _activeCheckpointTargetId = null;
            SetBusy(false, StatusText.Text);
        }
    }

    private async void Recover_Click(object sender, RoutedEventArgs e)
    {
        if (_device is null || SourceCombo.SelectedItem is not MediaDescriptor source)
        {
            MessageBox.Show(this, "请先执行扫描。", "恢复", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        var selected = GetRecoverySelection();
        if (selected.Length == 0)
        {
            MessageBox.Show(this, "请在结果表中选择一个或多个文件。", "恢复", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        var destination = DestinationBox.Text;
        if (RecoveryDestinationSafety.IsDestinationOnSource(source, destination, out var reason))
        {
            MessageBox.Show(this, reason, "安全阻止", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        _operation = new CancellationTokenSource();
        var recoveryOperation = _operation;
        SetBusy(true, "正在恢复选中文件…");
        var progress = CreateProgress();
        var startedUtc = DateTime.UtcNow;
        var reportItems = new List<RecoveryItemReport>(selected.Length);
        Exception? systemicFailure = null;
        try
        {
            var execution = await RecoveryBatchExecutor.ExecuteAsync(
                selected,
                async (candidate, index, total, cancellationToken) =>
                {
                    StatusText.Text = $"正在恢复 {index + 1:N0}/{total:N0} · {candidate.Name}";
                    var result = await RecoverCandidateAsync(candidate, destination, progress, cancellationToken);
                    var wasSalvaged = result.Salvage?.State == JpegSalvageState.Salvaged;
                    candidate.Integrity = wasSalvaged ? FileIntegrityState.Salvaged : result.Integrity;
                    candidate.IntegrityReason = wasSalvaged ? result.Salvage!.Message : result.IntegrityMessage;

                    var status = !result.Complete || wasSalvaged
                        ? RecoveryItemStatus.Partial
                        : result.Integrity == FileIntegrityState.Damaged
                            ? RecoveryItemStatus.Damaged
                            : RecoveryItemStatus.Success;
                    var message = result.IntegrityMessage;
                    if (wasSalvaged)
                    {
                        candidate.Quality = RecoveryQuality.Partial;
                        candidate.QualityReason = result.Salvage!.Message;
                        message = $"{message}；自动抢救输出：{result.Salvage.OutputPath}；{result.Salvage.Message}";
                        AppendLog($"自动抢救成功：{result.Salvage.OutputPath} · {result.Salvage.Message} · 从原文件偏移 {result.Salvage.PreservedFromOffset:N0} 开始保留 · SHA-256 {result.Salvage.Sha256}");
                    }
                    else if (result.Integrity == FileIntegrityState.Damaged)
                    {
                        candidate.Quality = RecoveryQuality.Poor;
                        candidate.QualityReason = $"恢复后结构校验失败：{result.IntegrityMessage}";
                    }

                    TryPreserveModifiedTime(result.OutputPath, candidate.ModifiedUtc);
                    AppendLog($"恢复 {(result.Complete ? "字节写出完成" : "仅部分写出")} · {RecoveryReportWriter.StatusLabel(status)}：{result.OutputPath} · {result.IntegrityMessage} · SHA-256 {result.Sha256}");
                    return new RecoveryItemReport(candidate.OriginalPath, status, result.OutputPath,
                        result.BytesWritten, result.Sha256, message, DateTime.UtcNow);
                },
                candidate => candidate.OriginalPath,
                exception => IsSystemicRecoveryFailure(exception, destination),
                recoveryOperation.Token,
                onItemFailure: (candidate, exception) =>
                    AppendLog($"单个文件恢复失败，继续处理后续文件：{candidate.OriginalPath} · {exception.Message}"),
                onCancelled: () => AppendLog("恢复已取消。已写入的文件不会自动删除。"),
                onSystemicFailure: _ => AppendLog("检测到目标盘掉线、不可写或空间不足，已暂停整个恢复队列。源介质没有被写入。"));
            reportItems.AddRange(execution.Items);
            systemicFailure = execution.SystemicFailure;

            RefreshResults();
        }
        finally
        {
            var report = new RecoveryBatchReport(1, startedUtc, DateTime.UtcNow, source.Id, destination, reportItems);
            try
            {
                var reportPaths = await SaveRecoveryReportWithFallbackAsync(report);
                var summary = $"成功：{report.Successful:N0}\n部分或损坏：{report.PartialOrDamaged:N0}\n失败：{report.Failed:N0}\n取消或跳过：{report.CancelledOrSkipped:N0}\n\nJSON 报告：{reportPaths.JsonPath}\nCSV 报告：{reportPaths.CsvPath}";
                MessageBox.Show(this, summary,
                    systemicFailure is null && report.Failed == 0 ? "恢复队列完成" : "恢复队列已完成并记录异常",
                    MessageBoxButton.OK, systemicFailure is null && report.Failed == 0 ? MessageBoxImage.Information : MessageBoxImage.Warning);
            }
            catch (Exception reportException) when (reportException is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
            {
                AppendLog($"JSON/CSV 恢复报告在目标盘和本机备用目录均写入失败：{reportException.Message}");
                MessageBox.Show(this,
                    $"恢复任务已结束，但报告写入失败。\n成功 {report.Successful:N0}，部分或损坏 {report.PartialOrDamaged:N0}，失败 {report.Failed:N0}。\n\n{reportException.Message}",
                    "恢复完成，但报告未保存", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
            finally
            {
                recoveryOperation.Dispose();
                SetBusy(false, systemicFailure is null ? "就绪" : "恢复队列因目标盘故障暂停");
            }
        }
    }

    private async Task<RecoveryResult> RecoverCandidateAsync(RecoveryCandidate candidate, string destination,
        IProgress<ScanProgress> progress, CancellationToken cancellationToken)
    {
        if (_device is null) throw new InvalidOperationException("源介质没有打开。");
        if (!candidate.CanRecover) throw new InvalidOperationException("目录节点不能加入文件恢复队列。");
        Exception? firstFailure = null;
        var sources = new[] { candidate }.Concat(candidate.AlternateCandidates)
            .Where(source => source.CanRecover).Distinct().ToArray();
        foreach (var source in sources)
        {
            try
            {
                var result = await RecoverCandidateSourceAsync(source, destination, progress, cancellationToken);
                if (!ReferenceEquals(source, candidate))
                    AppendLog($"首选来源不可读，已自动改用备用恢复来源：{candidate.OriginalPath} ← {source.DiscoveryLabel} / {source.OriginalPath}");
                return result;
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex)
            {
                if (IsSystemicRecoveryFailure(ex, destination)) throw;
                firstFailure ??= ex;
            }
        }
        throw new InvalidDataException($"所有 {sources.Length:N0} 个恢复来源均失败：{firstFailure?.Message ?? "没有可用来源。"}", firstFailure);
    }

    private async Task<RecoveryResult> RecoverCandidateSourceAsync(RecoveryCandidate candidate, string destination,
        IProgress<ScanProgress> progress, CancellationToken cancellationToken)
    {
        if (_device is null) throw new InvalidOperationException("源介质没有打开。");
        if (_ntfsResults.TryGetValue(candidate, out var ntfs))
            return await RecoveryWriter.RecoverNtfsAsync(_device, ntfs, candidate, destination, progress, cancellationToken);
        if (_tskResults.TryGetValue(candidate, out var tsk))
        {
            SetExternalEngineActive(true, "TSK");
            try
            {
                return await RecoveryWriter.RecoverSleuthKitAsync(FindSleuthKitBinDirectory(), tsk.Options,
                    tsk.Candidate, destination, progress, cancellationToken);
            }
            finally { SetExternalEngineActive(false); }
        }
        if (_exFatResults.TryGetValue(candidate, out var exFat))
        {
            var physicalCandidate = await SelectExFatPhysicalCandidateAsync(candidate, exFat, cancellationToken);
            if (!ReferenceEquals(physicalCandidate, candidate))
                AppendLog($"主记录结构预检未通过，已自动改用同一文件的备用物理副本：{candidate.OriginalPath} · 偏移 {physicalCandidate.SourceOffset:N0}。");
            return await RecoveryWriter.RecoverExFatAsync(_device, exFat, physicalCandidate, destination, progress, cancellationToken);
        }
        if (_fat32Results.TryGetValue(candidate, out var fat32))
            return await RecoveryWriter.RecoverFat32Async(_device, fat32, candidate, destination, progress, cancellationToken);
        if (candidate.Discovery == RecoveryDiscovery.PhotoRecFile)
            return await RecoveryWriter.RecoverStagedAsync(candidate, destination, progress, cancellationToken);
        return await RecoveryWriter.RecoverRawAsync(_device, candidate, destination, progress, cancellationToken);
    }

    private async Task<(string JsonPath, string CsvPath)> SaveRecoveryReportWithFallbackAsync(RecoveryBatchReport report)
    {
        try
        {
            return await RecoveryReportWriter.SaveAsync(report, Path.Combine(report.Destination, "雨痕恢复报告"));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            var fallback = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "RainTrace", "Reports");
            AppendLog($"恢复目标盘无法保存报告，已改存本机应用数据目录：{ex.Message}");
            return await RecoveryReportWriter.SaveAsync(report, fallback);
        }
    }

    private static bool IsSystemicRecoveryFailure(Exception exception, string destination)
    {
        if (exception is DriveNotFoundException or UnauthorizedAccessException) return true;
        if (exception is not IOException io) return false;
        var win32Error = io.HResult & 0xFFFF;
        if (win32Error is 21 or 39 or 112) return true;
        var root = Path.GetPathRoot(Path.GetFullPath(destination));
        return !string.IsNullOrWhiteSpace(root) && !Directory.Exists(root);
    }

    private void TryPreserveModifiedTime(string outputPath, DateTime? modifiedUtc)
    {
        if (modifiedUtc is null) return;
        try { File.SetLastWriteTimeUtc(outputPath, modifiedUtc.Value); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentOutOfRangeException)
        {
            AppendLog($"文件已恢复，但无法保留修改时间：{outputPath} · {ex.Message}");
        }
    }

    private async Task<RecoveryCandidate> SelectExFatPhysicalCandidateAsync(RecoveryCandidate candidate, ExFatScanResult scan,
        CancellationToken cancellationToken)
    {
        if (_device is null || candidate.AlternateCandidates.Count == 0) return candidate;
        foreach (var option in new[] { candidate }.Concat(candidate.AlternateCandidates.Where(option =>
                     option.FileSystem == FileSystemKind.ExFat && option.Discovery is RecoveryDiscovery.ExFatMetadata or RecoveryDiscovery.ExFatDeepMetadata)))
        {
            var validation = await FileIntegrityValidator.ValidateCandidateAsync(_device, option, exFat: scan,
                cancellationToken: cancellationToken);
            if (validation.State == FileIntegrityState.Valid) return option;
            if (validation.State == FileIntegrityState.NotChecked) return candidate;
        }
        return candidate;
    }

    private async void CreateImage_Click(object sender, RoutedEventArgs e)
    {
        if (SourceCombo.SelectedItem is not MediaDescriptor source) return;
        var dialog = new SaveFileDialog { Title = "保存只读磁盘镜像", Filter = "RAW磁盘镜像|*.img", InitialDirectory = @"D:\CodexRecoveryLab\images", FileName = $"disk-{DateTime.Now:yyyyMMdd-HHmmss}.img" };
        if (dialog.ShowDialog(this) != true) return;
        if (source.Kind == MediaKind.Image && string.Equals(Path.GetFullPath(source.Path), Path.GetFullPath(dialog.FileName), StringComparison.OrdinalIgnoreCase))
        {
            MessageBox.Show(this, "镜像输出不能覆盖源镜像。", "安全阻止", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }
        if (source.Kind != MediaKind.Image && RecoveryDestinationSafety.IsDestinationOnSource(source, dialog.FileName, out var reason))
        {
            MessageBox.Show(this, reason, "安全阻止", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }
        _operation = new CancellationTokenSource();
        SetBusy(true, "正在创建镜像…");
        try
        {
            var device = await OpenSelectedSourceAsync(_operation.Token);
            var result = await new DiskImager(device, CreateProgress()).CreateImageAsync(dialog.FileName, _operation.Token);
            AppendLog($"镜像完成：{result.ImagePath} · 不可读扇区 {result.ReadErrors:N0} · 不可读字节 {result.UnreadableBytes:N0} · 重试 {result.RetryAttempts:N0} · SHA-256 {result.Sha256}");
            AppendLog($"成像检查点：{result.CheckpointPath}；坏区地图：{result.BadSectorMapPath}");
            if (result.ReadErrors > 0)
                MessageBox.Show(this, $"镜像已完成，但有 {result.ReadErrors:N0} 个逻辑扇区无法读取并被精确填零。\n坏区地图：\n{result.BadSectorMapPath}",
                    "镜像完成并存在坏区", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
        catch (OperationCanceledException) { AppendLog("镜像已暂停，可使用同一输出文件继续。"); }
        catch (Exception ex) { ShowError(ex); }
        finally { SetBusy(false, "就绪"); }
    }

    private void ChooseDestination_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFolderDialog { Title = "选择恢复输出目录", InitialDirectory = DestinationBox.Text, Multiselect = false };
        if (dialog.ShowDialog(this) == true) DestinationBox.Text = dialog.FolderName;
    }

    private void Pause_Click(object sender, RoutedEventArgs e)
    {
        if (_externalEngineActive)
        {
            AppendLog($"{_externalEngineName ?? "外部引擎"} 阶段不支持进程级暂停；可取消并从阶段检查点继续。");
            return;
        }
        if (_pausableDevice is null) return;
        if (_pausableDevice.IsPaused)
        {
            _pausableDevice.Resume(); PauseButton.Content = "暂停"; AppendLog("操作已继续。");
        }
        else
        {
            _pausableDevice.Pause(); PauseButton.Content = "继续"; AppendLog("操作已暂停；当前进度和扫描状态已保留。"); StatusText.Text = "已暂停";
        }
    }

    private void Cancel_Click(object sender, RoutedEventArgs e)
    {
        _pausableDevice?.Resume();
        _operation?.Cancel();
    }

    private void Filter_Changed(object sender, RoutedEventArgs e) => RefreshResults();

    private void FilterText_Changed(object sender, TextChangedEventArgs e)
    {
        _filterDebounce.Stop();
        _filterDebounce.Start();
    }

    private RecoveryCandidate[] GetRecoverySelection()
    {
        return Candidates.Where(candidate => candidate.CanRecover && candidate.IsMarkedForRecovery)
            .Concat(ResultsGrid.SelectedItems.Cast<RecoveryCandidate>().Where(candidate => candidate.CanRecover))
            .Concat(ThumbnailList.SelectedItems.Cast<ThumbnailViewItem>().Select(item => item.Candidate).Where(candidate => candidate.CanRecover))
            .Distinct()
            .ToArray();
    }

    private void ResultsGrid_PreviewKeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key != Key.A || !Keyboard.Modifiers.HasFlag(ModifierKeys.Control)) return;
        ResultsGrid.SelectAll();
        ResultsGrid.Focus();
        e.Handled = true;
        UpdateRecoverySelectionStatus();
    }

    private void RecoveryMark_Click(object sender, RoutedEventArgs e)
    {
        if (sender is CheckBox { DataContext: RecoveryCandidate candidate } checkBox)
            candidate.IsMarkedForRecovery = candidate.CanRecover && checkBox.IsChecked == true;
        ResultsGrid.Items.Refresh();
        ThumbnailList.Items.Refresh();
        UpdateRecoverySelectionStatus();
    }

    private void ClearRecoveryMarks_Click(object sender, RoutedEventArgs e)
    {
        foreach (var candidate in Candidates) candidate.IsMarkedForRecovery = false;
        ResultsGrid.Items.Refresh();
        ThumbnailList.Items.Refresh();
        ResultsGrid.UnselectAll();
        ThumbnailList.UnselectAll();
        UpdateRecoverySelectionStatus();
    }

    private void SelectAllRecovery_Checked(object sender, RoutedEventArgs e)
    {
        MarkVisibleRecoveryCandidates(true);
    }

    private void SelectAllRecovery_Unchecked(object sender, RoutedEventArgs e)
    {
        MarkVisibleRecoveryCandidates(false);
    }

    private void MarkVisibleRecoveryCandidates(bool marked)
    {
        if (_candidateView is null) return;
        foreach (var candidate in _candidateView.Cast<RecoveryCandidate>())
            candidate.IsMarkedForRecovery = marked && candidate.CanRecover;
        ResultsGrid.Items.Refresh();
        ThumbnailList.Items.Refresh();
        UpdateRecoverySelectionStatus();
    }

    private void UpdateRecoverySelectionStatus()
    {
        if (RecoverButton is null || ResultsGrid is null) return;
        var count = Candidates.Where(candidate => candidate.CanRecover && candidate.IsMarkedForRecovery)
            .Concat(ResultsGrid.SelectedItems.Cast<RecoveryCandidate>().Where(candidate => candidate.CanRecover))
            .Concat(ThumbnailList.SelectedItems.Cast<ThumbnailViewItem>().Select(item => item.Candidate).Where(candidate => candidate.CanRecover))
            .Distinct()
            .Count();
        RecoverButton.Content = count > 0 ? $"恢复选中文件（{count:N0}）" : "恢复选中文件";
    }

    private bool FilterCandidate(object value)
    {
        if (value is not RecoveryCandidate item) return false;
        var search = SearchBox?.Text?.Trim();
        if (!string.IsNullOrEmpty(search) &&
            !item.Name.Contains(search, StringComparison.OrdinalIgnoreCase) &&
            !item.OriginalPath.Contains(search, StringComparison.OrdinalIgnoreCase)) return false;

        var extensions = ParseExtensionFilter(ExtensionBox?.Text);
        if (extensions.Count > 0 && !extensions.Contains(item.Extension)) return false;
        if (ModifiedFromPicker?.SelectedDate is DateTime from && (item.ModifiedUtc is null || item.ModifiedUtc.Value.Date < from.Date)) return false;
        if (ModifiedToPicker?.SelectedDate is DateTime to && (item.ModifiedUtc is null || item.ModifiedUtc.Value.Date > to.Date)) return false;
        if (TryParseSizeFilter(MinimumSizeBox?.Text, out var minimumSize) && item.Size < minimumSize) return false;
        if (TryParseSizeFilter(MaximumSizeBox?.Text, out var maximumSize) && item.Size > maximumSize) return false;
        if (PreviewableOnlyCheck?.IsChecked == true &&
            !RecoveryCapabilityRegistry.SupportsImagePreview(item.Extension) && !RecoveryCapabilityRegistry.IsText(item.Extension)) return false;

        if (CategoryList?.SelectedItem is CategoryItem category && category.Key != "All" && GetCategory(item.Extension) != category.Key) return false;
        if (QualityCombo?.SelectedItem is ComboBoxItem quality && quality.Tag is string qualityTag && qualityTag != "All" &&
            !string.Equals(item.Quality.ToString(), qualityTag, StringComparison.Ordinal)) return false;
        if (DiscoveryCombo?.SelectedItem is ComboBoxItem discovery && discovery.Tag is string discoveryTag)
        {
            if (discoveryTag == "Metadata" && item.Discovery is RecoveryDiscovery.FileSignature or RecoveryDiscovery.PhotoRecFile) return false;
            if (discoveryTag == "Raw" && item.Discovery is not (RecoveryDiscovery.FileSignature or RecoveryDiscovery.PhotoRecFile)) return false;
        }
        if (IntegrityCombo?.SelectedItem is ComboBoxItem integrity && integrity.Tag is string integrityTag && integrityTag != "All" &&
            !string.Equals(item.Integrity.ToString(), integrityTag, StringComparison.Ordinal)) return false;
        if (RecoverableOnlyCheck?.IsChecked == true && (!item.CanRecover || item.Quality is RecoveryQuality.Overwritten or RecoveryQuality.TrimmedOrZeroed or RecoveryQuality.Poor)) return false;
        return true;
    }

    private void RefreshResults()
    {
        if (_candidateView is null) return;
        _candidateView.Refresh();
        CountText.Text = $"{_candidateView.Cast<object>().Count():N0} / {Candidates.Count:N0} 个候选文件";
        if (_resultViewMode == "Tree") _ = RebuildTreeAsync();
        else if (_resultViewMode == "Thumbnail") RefreshThumbnailView();
    }

    private static HashSet<string> ParseExtensionFilter(string? text) => string.IsNullOrWhiteSpace(text)
        ? new(StringComparer.OrdinalIgnoreCase)
        : text.Split([',', ';', ' ', '，', '；'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(RecoveryCapabilityRegistry.NormalizeExtension)
            .Where(value => value.Length > 0)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

    private static bool TryParseSizeFilter(string? text, out ulong bytes)
    {
        bytes = 0;
        if (string.IsNullOrWhiteSpace(text)) return false;
        var value = text.Trim().Replace(" ", string.Empty, StringComparison.Ordinal).ToUpperInvariant();
        var multiplier = 1m;
        foreach (var unit in new[] { ("TIB", 1099511627776m), ("TB", 1099511627776m), ("GIB", 1073741824m), ("GB", 1073741824m), ("MIB", 1048576m), ("MB", 1048576m), ("KIB", 1024m), ("KB", 1024m), ("B", 1m) })
        {
            if (!value.EndsWith(unit.Item1, StringComparison.Ordinal)) continue;
            value = value[..^unit.Item1.Length];
            multiplier = unit.Item2;
            break;
        }
        if (!decimal.TryParse(value, NumberStyles.AllowDecimalPoint | NumberStyles.AllowThousands,
                CultureInfo.InvariantCulture, out var numeric) || numeric < 0) return false;
        var total = numeric * multiplier;
        if (total > ulong.MaxValue) return false;
        bytes = decimal.ToUInt64(decimal.Truncate(total));
        return true;
    }

    private static string GetCategory(string extension)
        => RecoveryCapabilityRegistry.GetCategory(extension).ToString();

    private void ResultView_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not Button { Tag: string mode } || mode is not ("List" or "Tree" or "Thumbnail")) return;
        _resultViewMode = mode;
        ResultsGrid.Visibility = mode == "List" ? Visibility.Visible : Visibility.Collapsed;
        TreeResults.Visibility = mode == "Tree" ? Visibility.Visible : Visibility.Collapsed;
        ThumbnailList.Visibility = mode == "Thumbnail" ? Visibility.Visible : Visibility.Collapsed;
        foreach (var button in new[] { ListViewButton, TreeViewButton, ThumbnailViewButton })
        {
            button.ClearValue(Button.BackgroundProperty);
            button.FontWeight = FontWeights.Normal;
        }
        var selectedButton = mode switch { "Tree" => TreeViewButton, "Thumbnail" => ThumbnailViewButton, _ => ListViewButton };
        selectedButton.Background = new SolidColorBrush(Color.FromRgb(0x1B, 0x76, 0x65));
        selectedButton.FontWeight = FontWeights.SemiBold;
        if (mode == "Tree") _ = RebuildTreeAsync();
        else if (mode == "Thumbnail") RefreshThumbnailView();
    }

    private async Task RebuildTreeAsync()
    {
        var generation = ++_treeBuildGeneration;
        var snapshot = _candidateView.Cast<RecoveryCandidate>().ToArray();
        var roots = await Task.Run(() => BuildResultTree(snapshot));
        if (generation != _treeBuildGeneration || _resultViewMode != "Tree") return;
        TreeResults.ItemsSource = roots;
    }

    private static IReadOnlyList<ResultTreeNode> BuildResultTree(IReadOnlyList<RecoveryCandidate> candidates)
    {
        var roots = new List<ResultTreeNode>();
        var nodes = new Dictionary<string, ResultTreeNode>(StringComparer.OrdinalIgnoreCase);
        foreach (var candidate in candidates)
        {
            var raw = candidate.Discovery is RecoveryDiscovery.FileSignature or RecoveryDiscovery.PhotoRecFile;
            var path = candidate.OriginalPath.Replace('/', '\\');
            var segments = path.Split('\\', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            var folderSegments = candidate.IsDirectory ? segments : segments.Take(Math.Max(0, segments.Length - 1)).ToArray();
            var hierarchy = raw
                ? new[] { "内容扫描", string.IsNullOrWhiteSpace(candidate.Extension) ? "其他" : candidate.Extension.ToUpperInvariant() }
                : new[] { "文件系统元数据" }.Concat(folderSegments).ToArray();

            ResultTreeNode? parent = null;
            var key = string.Empty;
            foreach (var segment in hierarchy)
            {
                key = key.Length == 0 ? segment : key + "\\" + segment;
                if (!nodes.TryGetValue(key, out var node))
                {
                    node = new ResultTreeNode(segment);
                    nodes.Add(key, node);
                    if (parent is null) roots.Add(node); else parent.Children.Add(node);
                }
                parent = node;
            }
            if (candidate.IsDirectory) continue;
            var fileName = segments.Length == 0 ? candidate.Name : segments[^1];
            (parent?.Children ?? throw new InvalidOperationException("结果树缺少根节点。"))
                .Add(new ResultTreeNode(fileName, candidate));
        }

        foreach (var root in roots) SortTree(root);
        return roots.OrderBy(node => node.Name, StringComparer.CurrentCultureIgnoreCase).ToArray();
    }

    private static void SortTree(ResultTreeNode node)
    {
        foreach (var child in node.Children) SortTree(child);
        var ordered = node.Children.OrderBy(child => child.IsFile)
            .ThenBy(child => child.Name, StringComparer.CurrentCultureIgnoreCase).ToArray();
        node.Children.Clear();
        foreach (var child in ordered) node.Children.Add(child);
    }

    private async void RefreshThumbnailView()
    {
        var generation = ++_thumbnailBuildGeneration;
        _thumbnailOperation.Cancel();
        _thumbnailOperation.Dispose();
        _thumbnailOperation = new CancellationTokenSource();
        var token = _thumbnailOperation.Token;
        var candidates = _candidateView.Cast<RecoveryCandidate>().ToArray();
        try
        {
            var items = await Task.Run(() => candidates
                .Where(candidate => RecoveryCapabilityRegistry.SupportsImagePreview(candidate.Extension))
                .Select(candidate => new ThumbnailViewItem(candidate)).ToArray(), token);
            if (generation == _thumbnailBuildGeneration && _resultViewMode == "Thumbnail") ThumbnailList.ItemsSource = items;
        }
        catch (OperationCanceledException) { }
    }

    private async void ThumbnailCard_Loaded(object sender, RoutedEventArgs e)
    {
        if (sender is not Border { DataContext: ThumbnailViewItem item } || item.Thumbnail is not null || item.IsLoading) return;
        item.IsLoading = true;
        item.Status = "正在读取…";
        try
        {
            if (_device is null) throw new IOException("源介质当前不在线。");
            var bytes = await ReadCandidatePreviewBytesAsync(item.Candidate, _thumbnailOperation.Token);
            using var stream = new MemoryStream(bytes, writable: false);
            var bitmap = new BitmapImage();
            bitmap.BeginInit();
            bitmap.CacheOption = BitmapCacheOption.OnLoad;
            bitmap.DecodePixelWidth = 220;
            bitmap.StreamSource = stream;
            bitmap.EndInit();
            bitmap.Freeze();
            item.Thumbnail = bitmap;
            item.Status = string.Empty;
        }
        catch (OperationCanceledException) { item.Status = "等待加载"; }
        catch (Exception ex) { item.Status = $"无法预览\n{ex.Message}"; }
        finally { item.IsLoading = false; }
    }

    private async void ThumbnailList_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        UpdateRecoverySelectionStatus();
        if (ThumbnailList.SelectedItem is ThumbnailViewItem item) await ShowCandidatePreviewAsync(item.Candidate);
    }

    private async void TreeResults_SelectedItemChanged(object sender, RoutedPropertyChangedEventArgs<object> e)
    {
        if (e.NewValue is ResultTreeNode { Candidate: not null } node) await ShowCandidatePreviewAsync(node.Candidate);
    }

    private void ThumbnailList_PreviewKeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key != Key.A || !Keyboard.Modifiers.HasFlag(ModifierKeys.Control)) return;
        ThumbnailList.SelectAll();
        ThumbnailList.Focus();
        e.Handled = true;
        UpdateRecoverySelectionStatus();
    }

    private void ThumbnailRecoveryMark_Click(object sender, RoutedEventArgs e)
    {
        if (sender is CheckBox { DataContext: ThumbnailViewItem item } checkBox)
            item.Candidate.IsMarkedForRecovery = item.Candidate.CanRecover && checkBox.IsChecked == true;
        ResultsGrid.Items.Refresh();
        UpdateRecoverySelectionStatus();
    }

    private async void ResultsGrid_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        UpdateRecoverySelectionStatus();
        if (ResultsGrid.SelectedItem is not RecoveryCandidate candidate)
        {
            ++_previewRequest;
            PreviewImage.Source = null;
            PreviewTextBox.Text = string.Empty;
            PreviewTextBox.Visibility = Visibility.Collapsed;
            PreviewName.Text = string.Empty;
            PreviewDetails.Text = string.Empty;
            PreviewMessage.Text = "选择文件后查看信息";
            PreviewMessage.Visibility = Visibility.Visible;
            return;
        }
        await ShowCandidatePreviewAsync(candidate);
    }

    private async Task ShowCandidatePreviewAsync(RecoveryCandidate candidate)
    {
        var request = ++_previewRequest;
        PreviewImage.Source = null;
        PreviewTextBox.Text = string.Empty;
        PreviewTextBox.Visibility = Visibility.Collapsed;
        PreviewName.Text = candidate.OriginalPath;
        PreviewDetails.Text = $"{FormatBytes(candidate.Size)} · {candidate.QualityLabel} · {candidate.IntegrityLabel} · {candidate.DiscoveryLabel}\n{candidate.QualityReason}\n{candidate.IntegrityReason}";
        PreviewMessage.Text = "正在读取只读预览…";
        PreviewMessage.Visibility = Visibility.Visible;
        if (candidate.IsDirectory)
        {
            PreviewMessage.Text = "这是目录树节点，不是可恢复文件。";
            return;
        }
        var imagePreview = RecoveryCapabilityRegistry.SupportsImagePreview(candidate.Extension);
        var textPreview = RecoveryCapabilityRegistry.IsText(candidate.Extension);
        if (!imagePreview && !textPreview)
        {
            PreviewMessage.Text = $"{candidate.Extension.ToUpperInvariant()} 文件\n当前版本只显示经过验证的结构和基本信息，不启用不稳定的 PDF/Office 完整渲染器。";
            return;
        }
        try
        {
            var bytes = await ReadCandidatePreviewBytesAsync(candidate, CancellationToken.None);
            if (request != _previewRequest) return;
            if (textPreview)
            {
                PreviewTextBox.Text = DecodeTextPreview(bytes);
                PreviewTextBox.Visibility = Visibility.Visible;
                PreviewMessage.Visibility = Visibility.Collapsed;
                return;
            }
            using var stream = new MemoryStream(bytes, writable: false);
            var bitmap = new BitmapImage();
            bitmap.BeginInit();
            bitmap.CacheOption = BitmapCacheOption.OnLoad;
            bitmap.StreamSource = stream;
            bitmap.EndInit();
            bitmap.Freeze();
            PreviewImage.Source = bitmap;
            PreviewMessage.Visibility = Visibility.Collapsed;
        }
        catch (Exception ex)
        {
            if (request == _previewRequest) PreviewMessage.Text = $"无法预览：{ex.Message}";
        }
    }

    private async Task<byte[]> ReadCandidatePreviewBytesAsync(RecoveryCandidate candidate, CancellationToken cancellationToken)
    {
        if (candidate.Discovery == RecoveryDiscovery.PhotoRecFile && !string.IsNullOrWhiteSpace(candidate.StagedRecoveryPath))
            return await ReadStagedPreviewAsync(candidate.StagedRecoveryPath, cancellationToken);
        if (_device is null) throw new IOException("结果已载入，但源介质当前不在线。");
        if (_tskResults.TryGetValue(candidate, out var tsk))
            return await SleuthKitEngine.ReadPrefixAsync(FindSleuthKitBinDirectory(), tsk.Options, tsk.Candidate,
                RecoveryPreview.DefaultMaximumBytes, cancellationToken);
        _ntfsResults.TryGetValue(candidate, out var ntfs);
        _exFatResults.TryGetValue(candidate, out var exFat);
        _fat32Results.TryGetValue(candidate, out var fat32);
        return await RecoveryPreview.ReadAsync(_device, candidate, ntfs, exFat, fat32, cancellationToken: cancellationToken);
    }

    private static string DecodeTextPreview(ReadOnlySpan<byte> bytes)
    {
        const int maximumCharacters = 64 * 1024;
        string text;
        if (bytes.StartsWith((byte[])[0xFF, 0xFE])) text = Encoding.Unicode.GetString(bytes[2..]);
        else if (bytes.StartsWith((byte[])[0xFE, 0xFF])) text = Encoding.BigEndianUnicode.GetString(bytes[2..]);
        else if (bytes.StartsWith((byte[])[0xEF, 0xBB, 0xBF])) text = Encoding.UTF8.GetString(bytes[3..]);
        else text = Encoding.UTF8.GetString(bytes);
        text = text.Replace("\0", "", StringComparison.Ordinal);
        return text.Length <= maximumCharacters ? text : text[..maximumCharacters] + "\n\n—— 预览已截断 ——";
    }

    private async void Preflight_Click(object sender, RoutedEventArgs e)
    {
        if (_device is null)
        {
            MessageBox.Show(this, "请先扫描或打开已保存的扫描结果。", "结构预检", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        var selected = GetRecoverySelection();
        if (selected.Length == 0)
        {
            MessageBox.Show(this, "请先选择一个或多个文件。", "结构预检", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        _operation = new CancellationTokenSource(); SetBusy(true, "正在执行恢复前结构预检…");
        var valid = 0; var damaged = 0; var uncheckedFiles = 0;
        try
        {
            for (var index = 0; index < selected.Length; index++)
            {
                var candidate = selected[index];
                _ntfsResults.TryGetValue(candidate, out var ntfs); _exFatResults.TryGetValue(candidate, out var exFat); _fat32Results.TryGetValue(candidate, out var fat32);
                var result = _tskResults.TryGetValue(candidate, out var tsk)
                    ? await ValidateTskWithAlternatesAsync(tsk, progress: CreateProgress(), _operation.Token)
                    : candidate.Discovery == RecoveryDiscovery.PhotoRecFile && !string.IsNullOrWhiteSpace(candidate.StagedRecoveryPath)
                    ? await FileIntegrityValidator.ValidateAsync(candidate.StagedRecoveryPath, _operation.Token)
                    : await FileIntegrityValidator.ValidateCandidateAsync(_device, candidate, ntfs, exFat, fat32, _operation.Token);
                candidate.Integrity = result.State; candidate.IntegrityReason = result.Message;
                if (result.State == FileIntegrityState.Valid) valid++; else if (result.State == FileIntegrityState.Damaged) damaged++; else uncheckedFiles++;
                ProgressBar.Value = (index + 1) * 100d / selected.Length;
                StatusText.Text = $"结构预检 {index + 1:N0}/{selected.Length:N0} · {candidate.Name}";
            }
            RefreshResults(); ResultsGrid.Items.Refresh();
            AppendLog($"恢复前结构预检完成：通过 {valid:N0}，损坏 {damaged:N0}，未支持 {uncheckedFiles:N0}。");
            MessageBox.Show(this, $"预检通过：{valid}\n结构损坏：{damaged}\n暂不支持：{uncheckedFiles}", "结构预检完成", MessageBoxButton.OK,
                damaged > 0 ? MessageBoxImage.Warning : MessageBoxImage.Information);
        }
        catch (OperationCanceledException) { AppendLog("结构预检已取消，已完成的结果予以保留。"); }
        catch (Exception ex) { ShowError(ex); }
        finally { SetBusy(false, "就绪"); }
    }

    private static async Task<FileIntegrityResult> ValidateTskWithAlternatesAsync(
        TskRecoveryContext context,
        IProgress<ScanProgress>? progress,
        CancellationToken cancellationToken)
    {
        var addresses = new[] { context.Candidate.MetadataAddress }.Concat(context.Candidate.AlternateMetadataAddresses)
            .Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        FileIntegrityResult? primary = null;
        for (var index = 0; index < addresses.Length; index++)
        {
            var choice = context.Candidate with { MetadataAddress = addresses[index], AlternateMetadataAddresses = [] };
            var validation = await FileIntegrityValidator.ValidateSleuthKitCandidateAsync(
                FindSleuthKitBinDirectory(), context.Options, choice, progress, cancellationToken);
            primary ??= validation;
            if (validation.State == FileIntegrityState.Valid)
                return index == 0 ? validation : validation with { Message = $"{validation.Message} 主记录损坏，备用元数据地址 {addresses[index]} 可用。" };
            if (validation.State == FileIntegrityState.NotChecked) return validation;
        }
        return primary ?? new(FileIntegrityState.NotChecked, "没有可预检的TSK元数据地址。");
    }

    private async void SaveSession_Click(object sender, RoutedEventArgs e)
    {
        if (SourceCombo.SelectedItem is not MediaDescriptor source || Candidates.Count == 0)
        {
            MessageBox.Show(this, "没有可保存的扫描结果。", "保存结果", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        var dialog = new SaveFileDialog { Title = "保存雨痕扫描结果", Filter = "雨痕扫描结果|*.yhs", FileName = $"雨痕扫描-{DateTime.Now:yyyyMMdd-HHmmss}.yhs" };
        if (dialog.ShowDialog(this) != true) return;
        try
        {
            if (_device is null) throw new InvalidOperationException("源介质只读句柄已关闭，请重新扫描。");
            var entries = CreateSessionCandidates();
            var fingerprint = await MediaFingerprintService.ComputeAsync(_device, source);
            var session = new ScanSession(3, DateTime.UtcNow, source, entries, fingerprint);
            await WriteTextAtomicAsync(dialog.FileName, JsonSerializer.Serialize(session, JsonOptions), Encoding.UTF8);
            AppendLog($"扫描结果已保存：{dialog.FileName}");
        }
        catch (Exception ex) { ShowError(ex); }
    }

    private async void LoadSession_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog { Title = "打开雨痕扫描结果", Filter = "雨痕扫描结果|*.yhs", CheckFileExists = true };
        if (dialog.ShowDialog(this) != true) return;
        try
        {
            var session = JsonSerializer.Deserialize<ScanSession>(await File.ReadAllTextAsync(dialog.FileName, Encoding.UTF8), JsonOptions)
                ?? throw new InvalidDataException("扫描结果文件为空或已损坏。");
            if (session.Version is < 2 or > 3)
                throw new InvalidDataException($"不支持的扫描会话版本：v{session.Version}。当前版本可读取 v2 和 v3。");
            var source = _sources.FirstOrDefault(item => string.Equals(item.Id, session.Source.Id, StringComparison.OrdinalIgnoreCase));
            if (source is null && session.Source.Kind == MediaKind.Image && File.Exists(session.Source.Path))
            {
                source = session.Source;
                _sources.Add(source);
            }
            if (source is null) throw new IOException("原始物理磁盘当前未连接。请连接后点击“刷新磁盘”，再打开结果。");
            if (!MediaFingerprintService.IsDescriptorCompatible(session.Source, source, out var descriptorReason))
                throw new IOException($"已阻止打开扫描结果：{descriptorReason}");
            SourceCombo.SelectedItem = source;
            await OpenSelectedSourceAsync();
            if (session.SourceFingerprint is not null)
            {
                var currentFingerprint = await MediaFingerprintService.ComputeAsync(_device!, source);
                if (!MediaFingerprintService.Matches(session.SourceFingerprint, currentFingerprint, out var fingerprintReason))
                {
                    await _device!.DisposeAsync();
                    _device = null; _pausableDevice = null;
                    throw new IOException($"已阻止打开扫描结果：{fingerprintReason}");
                }
            }
            else AppendLog("这是旧版扫描结果，没有首扇区指纹；已完成容量、扇区、型号和序列号兼容检查。");
            RestoreSessionCandidates(session);
            RefreshResults();
            AppendLog($"已载入 v{session.Version} 扫描结果：{Candidates.Count:N0} 个候选；源介质已重新以只读方式打开。");
        }
        catch (Exception ex) { ShowError(ex); }
    }

    private async void ContinueCheckpoint_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog
        {
            Title = "打开雨痕 v3 扫描检查点",
            Filter = "雨痕扫描检查点|raintrace-scan-checkpoint-v3.json;*.json",
            CheckFileExists = true
        };
        if (dialog.ShowDialog(this) != true) return;
        SetBusy(true, "正在验证扫描会话和源介质…");
        try
        {
            var loaded = await ScanCheckpointStore.LoadDetailedAsync(dialog.FileName);
            var checkpoint = loaded.Checkpoint;
            foreach (var warning in loaded.Warnings) AppendLog($"会话提示：{warning}");
            var source = FindCheckpointSource(checkpoint.Source)
                ?? throw new IOException("没有找到与检查点容量和设备信息相符的已连接介质。请重新插入后点击“刷新磁盘”。");
            SourceCombo.SelectedItem = source;
            var device = await OpenSelectedSourceAsync();
            var rawLayout = await PartitionScanner.ScanAsync(device);
            var layout = await PartitionScanner.EnrichWithBackupStructuresAsync(device, rawLayout);
            var fingerprint = await MultiPointMediaFingerprintService.ComputeAsync(device);
            var validation = ScanCheckpointSourceValidator.Validate(checkpoint, source, layout, fingerprint);
            if (!validation.IsMatch)
                throw new IOException("已拒绝继续扫描：\n" + string.Join("\n", validation.Errors.Select(error => "• " + error)));
            foreach (var warning in validation.Warnings) AppendLog($"介质校验提示：{warning}");

            if (!string.IsNullOrWhiteSpace(checkpoint.CandidateIndex.IndexPath))
            {
                var indexPath = Path.GetFullPath(checkpoint.CandidateIndex.IndexPath);
                if (!IsPathInside(checkpoint.RecoveryWorkingDirectory, indexPath))
                    throw new InvalidDataException("候选索引路径不在恢复工作目录内。");
                if (!File.Exists(indexPath)) throw new FileNotFoundException("扫描会话的候选索引文件不存在。", indexPath);
                await using (var stream = new FileStream(indexPath, FileMode.Open, FileAccess.Read, FileShare.Read,
                    1024 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan))
                {
                    var actualHash = Convert.ToHexString(await SHA256.HashDataAsync(stream)).ToLowerInvariant();
                    if (!string.Equals(actualHash, checkpoint.CandidateIndex.IndexSha256, StringComparison.OrdinalIgnoreCase))
                        throw new InvalidDataException("候选索引 SHA-256 不一致，文件可能已损坏或被替换。");
                }
                var session = JsonSerializer.Deserialize<ScanSession>(await File.ReadAllTextAsync(indexPath, Encoding.UTF8), JsonOptions)
                    ?? throw new InvalidDataException("候选索引内容为空。");
                RestoreSessionCandidates(session);
            }
            else
            {
                Candidates.Clear(); _ntfsResults.Clear(); _exFatResults.Clear(); _fat32Results.Clear(); _tskResults.Clear(); _candidateHashes.Clear();
            }

            switch (checkpoint.Scenario)
            {
                case RecoveryScenario.FormattedOrRaw: FormattedScenarioCheck.IsChecked = true; break;
                case RecoveryScenario.LostPartition: LostPartitionScenarioCheck.IsChecked = true; break;
                default: DeletedScenarioCheck.IsChecked = true; break;
            }
            ApplyScenarioPreset(checkpoint.Scenario);
            if (checkpoint.ExecutionOptions is not null)
                ApplyCheckpointOptions(checkpoint.ExecutionOptions);
            else
                AppendLog("该 v3 检查点未保存高级扫描选项，已使用场景默认值；请在开始前复核高级设置。");
            var workParent = Directory.GetParent(checkpoint.RecoveryWorkingDirectory)?.Parent?.FullName;
            if (!string.IsNullOrWhiteSpace(workParent)) DestinationBox.Text = workParent;
            _pendingResumeCheckpoint = checkpoint.PrepareForResume();
            RefreshResults();
            AppendLog($"介质身份验证通过：已恢复 {Candidates.Count:N0} 个持久化候选，准备继续未完成阶段。");
        }
        catch (Exception ex)
        {
            _pendingResumeCheckpoint = null;
            ShowError(ex);
        }
        finally { SetBusy(false, "就绪"); }

        if (_pendingResumeCheckpoint is not null)
            _ = Dispatcher.BeginInvoke(() => ScanButton.RaiseEvent(new RoutedEventArgs(Button.ClickEvent)));
    }

    private MediaDescriptor? FindCheckpointSource(ScanSourceIdentity expected)
    {
        if (SourceCombo.SelectedItem is MediaDescriptor selected && selected.Length == expected.Length &&
            selected.LogicalSectorSize == expected.LogicalSectorSize) return selected;
        return _sources.FirstOrDefault(source => source.Length == expected.Length &&
            source.LogicalSectorSize == expected.LogicalSectorSize &&
            (string.IsNullOrWhiteSpace(expected.SerialNumber) || string.Equals(source.SerialNumber?.Trim(), expected.SerialNumber,
                StringComparison.OrdinalIgnoreCase)) &&
            (string.IsNullOrWhiteSpace(expected.Model) || string.Equals(source.Model?.Trim(), expected.Model,
                StringComparison.OrdinalIgnoreCase)));
    }

    private void RestoreSessionCandidates(ScanSession session)
    {
        Candidates.Clear(); _ntfsResults.Clear(); _exFatResults.Clear(); _fat32Results.Clear(); _tskResults.Clear(); _candidateHashes.Clear();
        var batch = new List<RecoveryCandidate>(session.Candidates.Count);
        foreach (var entry in session.Candidates)
        {
            var alternateSources = entry.AlternateSources ?? [];
            entry.Candidate.AlternateCandidates = alternateSources.Count > 0
                ? alternateSources.Select(source => source.Candidate).ToArray()
                : entry.AlternateCandidates ?? entry.Candidate.AlternateCandidates ?? [];
            batch.Add(entry.Candidate);
            RestoreSessionSourceContext(new(entry.Candidate, entry.NtfsBoot, entry.ExFatBoot, entry.Fat32Boot,
                entry.PartitionOffset, entry.TskCandidate, entry.TskOptions));
            foreach (var alternate in alternateSources) RestoreSessionSourceContext(alternate);
        }
        Candidates.AddRange(batch);
    }

    private void RestoreSessionSourceContext(SessionSourceContext entry)
    {
        if (entry.NtfsBoot is not null) _ntfsResults[entry.Candidate] = NtfsScanResult.CreateRecoveryContext(entry.NtfsBoot, entry.PartitionOffset);
        if (entry.ExFatBoot is not null) _exFatResults[entry.Candidate] = ExFatScanResult.CreateRecoveryContext(entry.ExFatBoot, entry.PartitionOffset);
        if (entry.Fat32Boot is not null) _fat32Results[entry.Candidate] = Fat32ScanResult.CreateRecoveryContext(entry.Fat32Boot, entry.PartitionOffset);
        if (entry.TskCandidate is not null && entry.TskOptions is not null) _tskResults[entry.Candidate] = new(entry.TskOptions, entry.TskCandidate);
    }

    private static bool IsPathInside(string root, string path)
    {
        var relative = Path.GetRelativePath(Path.GetFullPath(root), Path.GetFullPath(path));
        return !Path.IsPathRooted(relative) && relative != ".." && !relative.StartsWith(".." + Path.DirectorySeparatorChar, StringComparison.Ordinal);
    }

    private async void ExportCsv_Click(object sender, RoutedEventArgs e)
    {
        if (Candidates.Count == 0) return;
        var dialog = new SaveFileDialog { Title = "导出当前文件清单", Filter = "CSV 文件|*.csv", FileName = $"雨痕文件清单-{DateTime.Now:yyyyMMdd-HHmmss}.csv" };
        if (dialog.ShowDialog(this) != true) return;
        try
        {
            var lines = new List<string> { "原路径,扩展名,字节数,修改时间UTC,恢复质量,结构状态,发现方式,来源偏移" };
            lines.AddRange(_candidateView.Cast<RecoveryCandidate>().Select(item => string.Join(',',
                Csv(item.OriginalPath), Csv(item.Extension), item.Size.ToString(CultureInfo.InvariantCulture), Csv(item.ModifiedUtc?.ToString("O") ?? ""),
                Csv(item.QualityLabel), Csv(item.IntegrityLabel), Csv(item.DiscoveryLabel), item.SourceOffset.ToString(CultureInfo.InvariantCulture))));
            await File.WriteAllLinesAsync(dialog.FileName, lines, new UTF8Encoding(true));
            AppendLog($"已导出当前筛选清单：{dialog.FileName}");
        }
        catch (Exception ex) { ShowError(ex); }
    }

    private static string Csv(string value) => $"\"{value.Replace("\"", "\"\"")}\"";

    private static async Task WriteTextAtomicAsync(string path, string contents, Encoding encoding,
        CancellationToken cancellationToken = default)
    {
        var fullPath = Path.GetFullPath(path);
        var directory = Path.GetDirectoryName(fullPath) ?? throw new InvalidOperationException("会话文件路径没有父目录。");
        Directory.CreateDirectory(directory);
        var temporaryPath = Path.Combine(directory, $".{Path.GetFileName(fullPath)}.{Guid.NewGuid():N}.tmp");
        try
        {
            await File.WriteAllTextAsync(temporaryPath, contents, encoding, cancellationToken);
            File.Move(temporaryPath, fullPath, true);
        }
        finally
        {
            try { if (File.Exists(temporaryPath)) File.Delete(temporaryPath); }
            catch { /* 临时文件清理失败不覆盖原始异常。 */ }
        }
    }

    private static string FindPhotoRecExecutable()
    {
        var packaged = Path.Combine(AppContext.BaseDirectory, "PhotoRec", "photorec_win.exe");
        if (File.Exists(packaged)) return packaged;
        for (var directory = new DirectoryInfo(AppContext.BaseDirectory); directory is not null; directory = directory.Parent)
        {
            var development = Path.Combine(directory.FullName, "third_party", "runtime", "testdisk-7.2", "photorec_win.exe");
            if (File.Exists(development)) return development;
        }
        return packaged;
    }

    private async Task<(RecoveryCandidate? Candidate, bool Merged)> PreparePhotoRecCandidateAsync(
        PhotoRecRecoveredFile file,
        PartitionDescriptor range,
        CancellationToken cancellationToken)
    {
        var fullPath = Path.GetFullPath(file.Path);
        if (Candidates.Any(candidate =>
                string.Equals(candidate.StagedRecoveryPath, fullPath, StringComparison.OrdinalIgnoreCase) ||
                candidate.AlternateCandidates.Any(alternate =>
                    string.Equals(alternate.StagedRecoveryPath, fullPath, StringComparison.OrdinalIgnoreCase))))
            return (null, true);
        var integrity = await FileIntegrityValidator.ValidateAsync(file.Path, cancellationToken);
        var candidate = new RecoveryCandidate
        {
            RecordNumber = -1,
            Name = Path.GetFileName(file.Path),
            OriginalPath = Path.Combine("内容扫描", file.Extension.Length == 0 ? "其他" : file.Extension, Path.GetFileName(file.Path)),
            Size = file.Size,
            IsDeleted = true,
            FileSystem = range.FileSystem,
            Discovery = RecoveryDiscovery.PhotoRecFile,
            Quality = integrity.State == FileIntegrityState.Damaged ? RecoveryQuality.Poor : RecoveryQuality.Good,
            QualityReason = "PhotoRec 从未分配空间恢复并执行格式级校验；原文件名和目录不可用。",
            Integrity = integrity.State,
            IntegrityReason = integrity.Message,
            StagedRecoveryPath = file.Path
        };
        var duplicate = await FindMetadataDuplicateAsync(file, cancellationToken);
        if (duplicate is null) return (candidate, false);

        if (integrity.State == FileIntegrityState.Valid)
        {
            duplicate.Integrity = integrity.State;
            duplicate.IntegrityReason = $"PhotoRec 恢复副本与该原名候选 SHA-256 一致；{integrity.Message}";
            if (duplicate.Quality == RecoveryQuality.Unknown) duplicate.Quality = RecoveryQuality.Good;
        }
        duplicate.QualityReason += " PhotoRec 发现了内容 SHA-256 完全相同的副本，已合并显示。";
        duplicate.AlternateCandidates = duplicate.AlternateCandidates
            .Concat([candidate]).Distinct().ToArray();
        return (null, true);
    }

    private async Task<RecoveryCandidate?> FindMetadataDuplicateAsync(PhotoRecRecoveredFile file, CancellationToken cancellationToken)
    {
        const ulong maximumHashBytes = 512UL * 1024 * 1024;
        if (file.Size > maximumHashBytes) return null;
        var candidates = Candidates.Where(candidate => !candidate.IsDirectory && candidate.Size == file.Size &&
            string.Equals(candidate.Extension, file.Extension, StringComparison.OrdinalIgnoreCase) &&
            candidate.Discovery is not (RecoveryDiscovery.FileSignature or RecoveryDiscovery.PhotoRecFile)).ToArray();
        if (candidates.Length == 0) return null;
        await using var photoRecStream = new FileStream(file.Path, FileMode.Open, FileAccess.Read, FileShare.Read,
            1024 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan);
        var photoRecHash = Convert.ToHexString(await SHA256.HashDataAsync(photoRecStream, cancellationToken)).ToLowerInvariant();
        foreach (var candidate in candidates)
        {
            if (_tskResults.TryGetValue(candidate, out var tsk))
            {
                var addresses = new[] { tsk.Candidate.MetadataAddress }.Concat(tsk.Candidate.AlternateMetadataAddresses)
                    .Distinct(StringComparer.OrdinalIgnoreCase);
                foreach (var address in addresses)
                {
                    try
                    {
                        var key = (candidate, address);
                        if (!_candidateHashes.TryGetValue(key, out var hash))
                        {
                            var choice = tsk.Candidate with { MetadataAddress = address, AlternateMetadataAddresses = [] };
                            hash = (await SleuthKitEngine.ReadSamplesAsync(FindSleuthKitBinDirectory(), tsk.Options, choice,
                                maximumStreamBytes: maximumHashBytes, cancellationToken: cancellationToken)).Sha256;
                            _candidateHashes[key] = hash;
                        }
                        if (string.Equals(hash, photoRecHash, StringComparison.OrdinalIgnoreCase)) return candidate;
                    }
                    catch (Exception ex) when (ex is IOException or InvalidDataException or EndOfStreamException or InvalidOperationException or NotSupportedException)
                    {
                        AppendLog($"跳过一个无法计算内容哈希的TSK候选：{candidate.OriginalPath} · {ex.Message}");
                    }
                }
                continue;
            }
            try
            {
                var key = (candidate, string.Empty);
                if (!_candidateHashes.TryGetValue(key, out var hash))
                {
                    hash = await ComputeNativeCandidateHashAsync(candidate, cancellationToken);
                    _candidateHashes[key] = hash;
                }
                if (string.Equals(hash, photoRecHash, StringComparison.OrdinalIgnoreCase)) return candidate;
            }
            catch (Exception ex) when (ex is IOException or InvalidDataException or EndOfStreamException or OverflowException or ArgumentOutOfRangeException)
            {
                AppendLog($"跳过一个无法计算内容哈希的元数据候选：{candidate.OriginalPath} · {ex.Message}");
            }
        }
        return null;
    }

    private void RemoveEquivalentTskCandidate(RecoveryCandidate preferred)
    {
        var equivalent = Candidates.FirstOrDefault(candidate => candidate.Discovery == RecoveryDiscovery.SleuthKitMetadata &&
            candidate.FileSystem == preferred.FileSystem && candidate.Size == preferred.Size &&
            string.Equals(candidate.OriginalPath, preferred.OriginalPath, StringComparison.OrdinalIgnoreCase));
        if (equivalent is null) return;
        Candidates.Remove(equivalent);
        _tskResults.Remove(equivalent);
        foreach (var key in _candidateHashes.Keys.Where(key => ReferenceEquals(key.Candidate, equivalent)).ToArray())
            _candidateHashes.Remove(key);
    }

    private async Task<string> ComputeNativeCandidateHashAsync(RecoveryCandidate candidate, CancellationToken cancellationToken)
    {
        if (_device is null) throw new InvalidOperationException("源介质没有打开。");
        _ntfsResults.TryGetValue(candidate, out var ntfs);
        _exFatResults.TryGetValue(candidate, out var exFat);
        _fat32Results.TryGetValue(candidate, out var fat32);
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        ulong offset = 0;
        while (offset < candidate.Size)
        {
            var bytes = await RecoveryPreview.ReadRangeAsync(_device, candidate, offset, 1024 * 1024,
                ntfs, exFat, fat32, cancellationToken);
            if (bytes.Length == 0) throw new EndOfStreamException("候选文件数据链提前结束。");
            hash.AppendData(bytes);
            offset += checked((ulong)bytes.Length);
        }
        return Convert.ToHexString(hash.GetHashAndReset()).ToLowerInvariant();
    }

    private async Task ConsolidateCandidateIndexAsync(CancellationToken cancellationToken)
    {
        if (Candidates.Count < 2) return;
        StatusText.Text = "正在建立快速指纹并筛选重复候选…";
        var snapshot = Candidates.ToArray();
        var quickFingerprints = new Dictionary<RecoveryCandidate, string?>(ReferenceEqualityComparer.Instance);
        var collisionCandidates = snapshot.Where(candidate => !candidate.IsDirectory)
            .GroupBy(candidate => (candidate.Size, Extension: RecoveryCapabilityRegistry.NormalizeExtension(candidate.Extension)))
            .Where(group => group.Count() > 1)
            .SelectMany(group => group)
            .ToArray();
        for (var index = 0; index < collisionCandidates.Length; index++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var candidate = collisionCandidates[index];
            quickFingerprints[candidate] = await ComputeCandidateQuickFingerprintAsync(candidate, cancellationToken);
            if ((index & 0x3F) == 0)
                StatusText.Text = $"正在计算快速指纹 {index + 1:N0}/{collisionCandidates.Length:N0}…";
        }

        StatusText.Text = "正在对快速指纹碰撞组执行完整 SHA-256 校验…";
        var candidateIndex = new RecoveryCandidateIndex(
            ComputeCandidateSha256ForIndexAsync,
            candidate => quickFingerprints.TryGetValue(candidate, out var fingerprint) ? fingerprint : null);
        var result = await candidateIndex.BuildAsync(snapshot, cancellationToken);
        if (result.MergedCandidates == 0)
        {
            AppendLog($"候选索引完成：检查 {result.InputCandidates:N0} 项；{result.HashedCandidates:N0} 项进入完整 SHA-256 碰撞校验；没有合并证据充分的重复项。");
            return;
        }

        foreach (var entry in result.Entries)
        {
            if (entry.RecoverySources.Any(candidate => candidate.IsMarkedForRecovery))
                entry.PreferredCandidate.IsMarkedForRecovery = entry.PreferredCandidate.CanRecover;
        }
        Candidates.ReplaceAll(result.Entries.Select(entry => entry.PreferredCandidate));
        AppendLog($"候选索引完成：精确合并 {result.MergedCandidates:N0} 个 SHA-256 相同副本；保留 {result.PreferredCandidates:N0} 个首选项及全部备用恢复来源。");
    }

    private async Task<string?> ComputeCandidateQuickFingerprintAsync(
        RecoveryCandidate candidate,
        CancellationToken cancellationToken)
    {
        const int sampleBytes = 64 * 1024;
        try
        {
            byte[] sample;
            if (!string.IsNullOrWhiteSpace(candidate.StagedRecoveryPath) && File.Exists(candidate.StagedRecoveryPath))
            {
                await using var stream = new FileStream(candidate.StagedRecoveryPath, FileMode.Open, FileAccess.Read,
                    FileShare.Read, sampleBytes, FileOptions.Asynchronous | FileOptions.SequentialScan);
                sample = new byte[checked((int)Math.Min(candidate.Size, sampleBytes))];
                if (sample.Length > 0) await stream.ReadExactlyAsync(sample, cancellationToken);
            }
            else if (_tskResults.TryGetValue(candidate, out var tsk))
            {
                sample = await SleuthKitEngine.ReadPrefixAsync(FindSleuthKitBinDirectory(), tsk.Options,
                    tsk.Candidate, sampleBytes, cancellationToken);
            }
            else
            {
                if (_device is null) return null;
                _ntfsResults.TryGetValue(candidate, out var ntfs);
                _exFatResults.TryGetValue(candidate, out var exFat);
                _fat32Results.TryGetValue(candidate, out var fat32);
                sample = await RecoveryPreview.ReadRangeAsync(_device, candidate, 0, sampleBytes,
                    ntfs, exFat, fat32, cancellationToken);
            }
            return Convert.ToHexString(SHA256.HashData(sample)).ToLowerInvariant();
        }
        catch (Exception ex) when (ex is IOException or InvalidDataException or EndOfStreamException or
                                   InvalidOperationException or NotSupportedException or OverflowException or ArgumentOutOfRangeException)
        {
            return null;
        }
    }

    private async ValueTask<string?> ComputeCandidateSha256ForIndexAsync(RecoveryCandidate candidate, CancellationToken cancellationToken)
    {
        try
        {
            if (!string.IsNullOrWhiteSpace(candidate.StagedRecoveryPath) && File.Exists(candidate.StagedRecoveryPath))
            {
                await using var stream = new FileStream(candidate.StagedRecoveryPath, FileMode.Open, FileAccess.Read,
                    FileShare.Read, 1024 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan);
                return Convert.ToHexString(await SHA256.HashDataAsync(stream, cancellationToken)).ToLowerInvariant();
            }
            if (_tskResults.TryGetValue(candidate, out var tsk))
            {
                var samples = await SleuthKitEngine.ReadSamplesAsync(FindSleuthKitBinDirectory(), tsk.Options,
                    tsk.Candidate, maximumStreamBytes: ulong.MaxValue, cancellationToken: cancellationToken);
                return samples.Sha256;
            }
            return await ComputeNativeCandidateHashAsync(candidate, cancellationToken);
        }
        catch (Exception ex) when (ex is IOException or InvalidDataException or EndOfStreamException or
                                   InvalidOperationException or NotSupportedException or OverflowException or ArgumentOutOfRangeException)
        {
            return null;
        }
    }

    private static string FindSleuthKitBinDirectory()
    {
        var packaged = Path.Combine(AppContext.BaseDirectory, "SleuthKit", "bin");
        if (SleuthKitEngine.IsAvailable(packaged)) return packaged;
        for (var directory = new DirectoryInfo(AppContext.BaseDirectory); directory is not null; directory = directory.Parent)
        {
            var development = Path.Combine(directory.FullName, "third_party", "runtime", "sleuthkit-4.15.0", "sleuthkit-4.15.0-win32", "bin");
            if (SleuthKitEngine.IsAvailable(development)) return development;
        }
        return packaged;
    }

    private static async Task<byte[]> ReadStagedPreviewAsync(string path, CancellationToken cancellationToken)
    {
        await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read,
            1024 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan);
        var length = checked((int)Math.Min(stream.Length, RecoveryPreview.DefaultMaximumBytes));
        var bytes = new byte[length];
        await stream.ReadExactlyAsync(bytes, cancellationToken);
        return bytes;
    }

    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = false, PropertyNameCaseInsensitive = true };
    private sealed record CategoryItem(string Key, string DisplayName);
    private sealed record ScanSession(int Version, DateTime SavedUtc, MediaDescriptor Source, IReadOnlyList<SessionCandidate> Candidates,
        MediaFingerprint? SourceFingerprint = null);
    private sealed record SessionCandidate(RecoveryCandidate Candidate, NtfsBootSector? NtfsBoot, ExFatBootSector? ExFatBoot, Fat32BootSector? Fat32Boot,
        ulong PartitionOffset, SleuthKitCandidate? TskCandidate = null, SleuthKitScanOptions? TskOptions = null,
        IReadOnlyList<RecoveryCandidate>? AlternateCandidates = null,
        IReadOnlyList<SessionSourceContext>? AlternateSources = null);
    private sealed record SessionSourceContext(RecoveryCandidate Candidate, NtfsBootSector? NtfsBoot,
        ExFatBootSector? ExFatBoot, Fat32BootSector? Fat32Boot, ulong PartitionOffset,
        SleuthKitCandidate? TskCandidate = null, SleuthKitScanOptions? TskOptions = null);
    private sealed record TskRecoveryContext(SleuthKitScanOptions Options, SleuthKitCandidate Candidate);
    private sealed class InlineProgress<T>(Action<T> callback) : IProgress<T>
    {
        public void Report(T value) => callback(value);
    }

    private void QueueStreamedCandidate(RecoveryCandidate candidate) => _pendingStreamedCandidates.Add(candidate);

    private void FlushStreamedCandidates()
    {
        if (_pendingStreamedCandidates.Count == 0) return;
        Candidates.AddRange(_pendingStreamedCandidates);
        _pendingStreamedCandidates.Clear();
    }

    private Progress<ScanProgress> CreateProgress() => new(progress =>
    {
        FlushStreamedCandidates();
        ProgressBar.IsIndeterminate = progress.Total == 0;
        if (progress.Total != 0) ProgressBar.Value = progress.Percent;
        StatusText.Text = FormatProgressStatus(progress);
        CountText.Text = $"{Math.Max(progress.Candidates, Candidates.Count):N0} 个候选文件";
        QueueProgressCheckpoint(progress);
    });

    private string FormatProgressStatus(ScanProgress progress)
    {
        var candidateCount = Math.Max(progress.Candidates, Candidates.Count);
        if (progress.Total == 0)
            return $"{progress.Stage} · 不确定进度 · 候选 {candidateCount:N0} · {progress.Message}";

        if (progress.CheckpointPosition is null)
            return $"{progress.Stage} · {progress.Percent:0.0}% · 候选 {candidateCount:N0} · {progress.Message}";

        if (!string.Equals(_telemetryStage, progress.Stage, StringComparison.Ordinal) ||
            progress.Processed < _telemetryStartProcessed || _telemetryStartTimestamp == 0)
        {
            _telemetryStage = progress.Stage;
            _telemetryStartProcessed = progress.Processed;
            _telemetryStartTimestamp = Stopwatch.GetTimestamp();
        }

        var elapsed = Stopwatch.GetElapsedTime(_telemetryStartTimestamp);
        var completedSinceStart = progress.Processed - _telemetryStartProcessed;
        var bytesPerSecond = elapsed.TotalSeconds < 0.25 ? 0d : completedSinceStart / elapsed.TotalSeconds;
        var speed = bytesPerSecond <= 0 ? "测速中" : $"{FormatBytes((ulong)bytesPerSecond)}/秒";
        var eta = "预计时间计算中";
        if (bytesPerSecond > 0 && progress.Total > progress.Processed)
        {
            var remainingSeconds = Math.Min(TimeSpan.MaxValue.TotalSeconds,
                (progress.Total - progress.Processed) / bytesPerSecond);
            var remaining = TimeSpan.FromSeconds(remainingSeconds);
            eta = remaining.TotalHours >= 1 ? $"预计 {remaining:hh\\:mm\\:ss}" : $"预计 {remaining:mm\\:ss}";
        }
        else if (progress.Processed >= progress.Total) eta = "即将完成";

        return $"{progress.Stage} · {progress.Percent:0.0}% · 已读 {FormatBytes(progress.Processed)} / {FormatBytes(progress.Total)} · {speed} · {eta} · 候选 {candidateCount:N0}";
    }

    private void SetBusy(bool busy, string status)
    {
        ScanButton.IsEnabled = !busy;
        RecoverButton.IsEnabled = !busy;
        PreflightButton.IsEnabled = !busy;
        CancelButton.IsEnabled = busy;
        PauseButton.IsEnabled = busy && _pausableDevice is not null && !_externalEngineActive;
        if (!busy)
        {
            _externalEngineActive = false;
            _externalEngineName = null;
            _pausableDevice?.Resume();
            PauseButton.Content = "暂停";
            PauseButton.ToolTip = null;
        }
        SourceCombo.IsEnabled = !busy;
        StatusText.Text = status;
        if (!busy)
        {
            ProgressBar.IsIndeterminate = false;
            if (ProgressBar.Value >= 100) ProgressBar.Value = 0;
            _telemetryStage = null;
            _telemetryStartTimestamp = 0;
        }
    }

    private void SetExternalEngineActive(bool active, string? engineName = null)
    {
        _externalEngineActive = active;
        _externalEngineName = active ? engineName ?? "外部引擎" : null;
        if (active)
        {
            _pausableDevice?.Resume();
            PauseButton.Content = "阶段不可暂停";
            PauseButton.IsEnabled = false;
            PauseButton.ToolTip = $"{_externalEngineName} 仅支持取消和阶段级续作，不能可靠暂停子进程。";
        }
        else
        {
            PauseButton.Content = "暂停";
            PauseButton.IsEnabled = _operation is { IsCancellationRequested: false } && _pausableDevice is not null;
            PauseButton.ToolTip = null;
        }
    }

    private void AppendLog(string message)
    {
        AppDiagnostics.Write(message);
        LogBox.AppendText($"[{DateTime.Now:HH:mm:ss}] {message}{Environment.NewLine}");
        LogBox.ScrollToEnd();
    }

    private void ShowError(Exception exception)
    {
        AppendLog($"错误：{exception.Message}");
        MessageBox.Show(this, exception.Message, "操作失败", MessageBoxButton.OK, MessageBoxImage.Error);
    }

    private static string FormatBytes(ulong bytes)
    {
        string[] units = ["B", "KiB", "MiB", "GiB", "TiB"];
        var value = (double)bytes;
        var index = 0;
        while (value >= 1024 && index < units.Length - 1) { value /= 1024; index++; }
        return $"{value:0.##} {units[index]}";
    }

    private static bool IsAdministrator()
    {
        if (!OperatingSystem.IsWindows()) return false;
        using var identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }
}
