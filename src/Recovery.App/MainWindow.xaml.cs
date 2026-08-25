using Microsoft.Win32;
using Recovery.Core;
using System.Collections.ObjectModel;
using System.ComponentModel;
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
using System.Windows.Media.Imaging;

namespace Recovery.App;

public partial class MainWindow : Window
{
    public ObservableCollection<RecoveryCandidate> Candidates { get; } = [];
    private readonly ObservableCollection<MediaDescriptor> _sources = [];
    private readonly Dictionary<RecoveryCandidate, NtfsScanResult> _ntfsResults = [];
    private readonly Dictionary<RecoveryCandidate, ExFatScanResult> _exFatResults = [];
    private readonly Dictionary<RecoveryCandidate, Fat32ScanResult> _fat32Results = [];
    private readonly Dictionary<RecoveryCandidate, TskRecoveryContext> _tskResults = [];
    private readonly Dictionary<(RecoveryCandidate Candidate, string Variant), string> _candidateHashes = [];
    private CancellationTokenSource? _operation;
    private IBlockDevice? _device;
    private PausableBlockDevice? _pausableDevice;
    private readonly ICollectionView _candidateView;
    private int _previewRequest;

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
        CategoryList.ItemsSource = Categories;
        CategoryList.SelectedIndex = 0;
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
        Closed += (_, _) => _device?.DisposeAsync().AsTask().GetAwaiter().GetResult();
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

    private async void Scan_Click(object sender, RoutedEventArgs e)
    {
        if (MetadataCheck.IsChecked != true && DeepMetadataCheck.IsChecked != true && ExFatDeepMetadataCheck.IsChecked != true && FullDiskMetadataCheck.IsChecked != true && CarveCheck.IsChecked != true)
        {
            MessageBox.Show(this, "请至少选择一种扫描方式。", "扫描方式", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        if (SourceCombo.SelectedItem is not MediaDescriptor selectedSource)
        {
            MessageBox.Show(this, "请先选择源介质或镜像。", "扫描", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        if (CarveCheck.IsChecked == true)
        {
            if (RecoveryDestinationSafety.IsDestinationOnSource(selectedSource, DestinationBox.Text, out var destinationReason))
            {
                MessageBox.Show(this, $"PhotoRec 扫描会把通过校验的文件暂存到恢复目标盘。\n\n{destinationReason}", "安全阻止", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }
            var photoRecExecutable = FindPhotoRecExecutable();
            if (!PhotoRecEngine.IsAvailable(photoRecExecutable))
            {
                MessageBox.Show(this, "发布包中缺少 PhotoRec 引擎。请重新解压完整的雨痕程序包。", "PhotoRec 不可用", MessageBoxButton.OK, MessageBoxImage.Error);
                return;
            }
        }
        _operation = new CancellationTokenSource();
        Candidates.Clear();
        _ntfsResults.Clear();
        _exFatResults.Clear();
        _fat32Results.Clear();
        _tskResults.Clear();
        _candidateHashes.Clear();
        CountText.Text = "0 个候选文件";
        SetBusy(true, "正在打开源介质…");
        try
        {
            var device = await OpenSelectedSourceAsync(_operation.Token);
            StatusText.Text = "源介质已只读打开，正在识别分区…";
            var progress = CreateProgress();
            var partitions = await PartitionScanner.ScanAsync(device, _operation.Token);
            AppendLog($"识别到 {partitions.Count} 个分区/扫描范围。");
            if (LostPartitionCheck.IsChecked == true)
            {
                AppendLog("开始逐扇区搜索丢失的 NTFS、exFAT 和 FAT32 分区引导记录。");
                var lost = await PartitionScanner.FindLostPartitionsAsync(device, partitions, progress, _operation.Token);
                partitions = partitions.Concat(lost).ToArray();
                AppendLog($"丢失分区搜索完成：新增 {lost.Count:N0} 个候选分区。");
            }

            if (MetadataCheck.IsChecked == true || DeepMetadataCheck.IsChecked == true || ExFatDeepMetadataCheck.IsChecked == true || FullDiskMetadataCheck.IsChecked == true)
            {
                var tskHandledOffsets = new HashSet<ulong>();
                if (MetadataCheck.IsChecked == true)
                {
                    var tskBinDirectory = FindSleuthKitBinDirectory();
                    if (!SleuthKitEngine.IsAvailable(tskBinDirectory))
                        AppendLog("发布包中缺少 Sleuth Kit，文件系统元数据扫描将回退到雨痕旧扫描器。");
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
                                var tskScan = await SleuthKitEngine.ScanDeletedAsync(tskBinDirectory, tskOptions, _operation.Token, progress, tskLimit);
                                if (!tskScan.CompletedNormally)
                                    throw new InvalidDataException($"fls 退出代码 {tskScan.ExitCode}：{tskScan.StandardError}");
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
                                    Candidates.Add(item);
                                    _tskResults[item] = new(tskOptions, tskCandidate);
                                }
                                tskHandledOffsets.Add(partition.Offset);
                                AppendLog($"TSK 元数据完成：{tskScan.Candidates.Count:N0} 个逻辑候选；控制台编码 {tskScan.DetectedEncoding}。");
                            }
                            catch (Exception ex) when (ex is not OperationCanceledException)
                            {
                                AppendLog($"TSK 无法解析 {partition.Name}，该分区回退到雨痕旧扫描器：{ex.Message}");
                            }
                        }
                    }
                }
                var ntfsPartitions = partitions.Where(p => p.FileSystem == FileSystemKind.Ntfs).ToArray();
                if (ntfsPartitions.Length == 0) AppendLog("没有识别到 NTFS 分区，跳过 MFT 扫描。");
                foreach (var partition in ntfsPartitions)
                {
                    var tskHandled = tskHandledOffsets.Contains(partition.Offset);
                    if (tskHandled && DeepMetadataCheck.IsChecked != true && FullDiskMetadataCheck.IsChecked != true) continue;
                    AppendLog($"扫描 NTFS：{partition.Name}，起始 {partition.Offset:N0} 字节。深度模式：{(DeepMetadataCheck.IsChecked == true ? "开启" : "关闭")}；" +
                        $"全盘旧 MFT：{(FullDiskMetadataCheck.IsChecked == true ? "开启（耗时）" : "关闭")}。");
                    var options = new ScanOptions(
                        DeepMetadataScan: DeepMetadataCheck.IsChecked == true,
                        FullDiskMetadataScan: FullDiskMetadataCheck.IsChecked == true);
                    var scan = await new NtfsScanner(device, partition.Offset, progress, partition.BootSectorOffset).ScanAsync(options, _operation.Token);
                    foreach (var item in scan.Candidates)
                    {
                        if (tskHandled && item.Discovery == RecoveryDiscovery.NtfsCurrentMft) continue;
                        if (ntfsPartitions.Length > 1) item.OriginalPath = Path.Combine(partition.Name, item.OriginalPath);
                        Candidates.Add(item);
                        _ntfsResults[item] = scan;
                    }
                    AppendLog($"NTFS 元数据完成：当前 MFT {scan.ParsedCurrentMftRecords:N0}/{scan.CurrentMftRecords:N0} 条有效；" +
                        $"深度检查 {scan.DeepRecordsExamined:N0} 个记录槽，识别 {scan.ParsedDeepRecords:N0} 条旧记录；候选 {scan.Candidates.Count:N0} 个。");
                }

                var exFatPartitions = partitions.Where(p => p.FileSystem == FileSystemKind.ExFat).ToArray();
                foreach (var partition in exFatPartitions)
                {
                    var tskHandled = tskHandledOffsets.Contains(partition.Offset);
                    AppendLog($"扫描 exFAT 元数据：{partition.Name}，起始 {partition.Offset:N0} 字节。");
                    var scan = await new ExFatScanner(device, partition.Offset, progress, partition.BootSectorOffset).ScanAsync(
                        new ScanOptions(ExFatDeepMetadataScan: ExFatDeepMetadataCheck.IsChecked == true), _operation.Token);
                    foreach (var item in scan.Candidates)
                    {
                        if (exFatPartitions.Length > 1) item.OriginalPath = Path.Combine(partition.Name, item.OriginalPath);
                        if (tskHandled) RemoveEquivalentTskCandidate(item);
                        Candidates.Add(item);
                        _exFatResults[item] = scan;
                    }
                    AppendLog($"exFAT 元数据完成：找到 {scan.Candidates.Count:N0} 个保留原文件名的删除文件候选；深度模式：{(ExFatDeepMetadataCheck.IsChecked == true ? "开启" : "关闭")}。");
                }
                var fat32Partitions = partitions.Where(p => p.FileSystem == FileSystemKind.Fat32).ToArray();
                foreach (var partition in fat32Partitions)
                {
                    if (tskHandledOffsets.Contains(partition.Offset)) continue;
                    AppendLog($"扫描 FAT32 元数据：{partition.Name}，起始 {partition.Offset:N0} 字节。");
                    var scan = await new Fat32Scanner(device, partition.Offset, progress).ScanAsync(_operation.Token);
                    foreach (var item in scan.Candidates)
                    {
                        if (fat32Partitions.Length > 1) item.OriginalPath = Path.Combine(partition.Name, item.OriginalPath);
                        Candidates.Add(item); _fat32Results[item] = scan;
                    }
                    AppendLog($"FAT32 元数据完成：找到 {scan.Candidates.Count:N0} 个保留原文件名的删除文件候选。");
                }
                if (ntfsPartitions.Length == 0 && exFatPartitions.Length == 0 && fat32Partitions.Length == 0)
                    AppendLog("没有识别到 NTFS、exFAT 或 FAT32 分区，跳过文件系统元数据扫描。");
            }

            if (CarveCheck.IsChecked == true)
            {
                var photoRecExecutable = FindPhotoRecExecutable();
                var sessionRoot = Path.Combine(Path.GetFullPath(DestinationBox.Text), "PhotoRec-Staging", DateTime.Now.ToString("yyyyMMdd-HHmmss"));
                var workRoot = Path.Combine(sessionRoot, "work");
                AppendLog("开始 PhotoRec 严格扫描：默认只读取文件系统未分配空间；无效文件由 PhotoRec 拒绝。结果先写入目标盘暂存目录。");
                var ranges = partitions.Where(partition => partition.FileSystem is FileSystemKind.Ntfs or FileSystemKind.ExFat or FileSystemKind.Fat32).ToArray();
                if (ranges.Length == 0) ranges = partitions.ToArray();
                if (ranges.Length == 0)
                {
                    ranges = [new PartitionDescriptor(0, 0, device.Length, Guid.Empty, Guid.Empty, "整盘", FileSystemKind.Unknown, false)];
                }
                var totalImported = 0;
                var totalRejected = 0;
                var totalDeduplicated = 0;
                for (var rangeIndex = 0; rangeIndex < ranges.Length; rangeIndex++)
                {
                    var range = ranges[rangeIndex];
                    var wholeDevice = selectedSource.Kind == MediaKind.Image && range.Offset == 0 && ranges.Length == 1;
                    var options = new PhotoRecRunOptions(
                        selectedSource.Path,
                        Path.Combine(sessionRoot, $"partition-{range.Number}"),
                        Path.Combine(workRoot, $"partition-{range.Number}"),
                        ["jpg", "png", "bmp", "pdf", "zip", "doc", "mov", "riff", "tif", "gif"],
                        FreeSpaceOnly: range.FileSystem != FileSystemKind.Unknown,
                        TreatSourceAsWholeDevice: wholeDevice,
                        PartitionNumber: wholeDevice || range.Number <= 0 ? null : range.Number);
                    AppendLog($"PhotoRec 扫描范围 {rangeIndex + 1}/{ranges.Length}：{range.Name} · {(options.FreeSpaceOnly ? "仅未分配空间" : "未知文件系统整段扫描")}。");
                    var result = await PhotoRecEngine.RunAsync(photoRecExecutable, options, progress, _operation.Token);
                    totalRejected += result.RejectedFiles;
                    foreach (var file in result.Files)
                    {
                        var integrity = await FileIntegrityValidator.ValidateAsync(file.Path, _operation.Token);
                        var duplicate = await FindMetadataDuplicateAsync(file, _operation.Token);
                        if (duplicate is not null)
                        {
                            if (integrity.State == FileIntegrityState.Valid)
                            {
                                duplicate.Integrity = integrity.State;
                                duplicate.IntegrityReason = $"PhotoRec恢复副本与该原名候选SHA-256一致；{integrity.Message}";
                                if (duplicate.Quality == RecoveryQuality.Unknown) duplicate.Quality = RecoveryQuality.Good;
                            }
                            duplicate.QualityReason += " PhotoRec发现了内容SHA-256完全相同的副本，已合并显示。";
                            totalDeduplicated++;
                            continue;
                        }
                        var candidate = new RecoveryCandidate
                        {
                            RecordNumber = -1,
                            Name = Path.GetFileName(file.Path),
                            OriginalPath = Path.Combine("PhotoRec Recovery", file.Extension.Length == 0 ? "other" : file.Extension, Path.GetFileName(file.Path)),
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
                        Candidates.Add(candidate);
                        totalImported++;
                    }
                    AppendLog(result.Summary);
                    RefreshResults();
                }
                AppendLog($"PhotoRec 扫描完成：导入 {totalImported:N0} 个严格校验结果，合并 {totalDeduplicated:N0} 个与原名候选内容相同的副本，拒绝 {totalRejected:N0} 个无效候选。暂存目录：{sessionRoot}");
            }
            AppendLog($"扫描完成，共找到 {Candidates.Count:N0} 个候选文件。");
            RefreshResults();
            StatusText.Text = "扫描完成";
        }
        catch (OperationCanceledException) { AppendLog("操作已由用户取消。扫描结果已保留。"); }
        catch (Exception ex) { ShowError(ex); }
        finally { SetBusy(false, StatusText.Text); }
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

        var concurrentWithScan = !ScanButton.IsEnabled;
        var recoveryOperation = concurrentWithScan ? new CancellationTokenSource() : (_operation = new CancellationTokenSource());
        if (concurrentWithScan) { RecoverButton.IsEnabled = false; AppendLog("扫描仍在进行；开始恢复当前已发现的文件。"); }
        else SetBusy(true, "正在恢复选中文件…");
        var progress = CreateProgress();
        var succeeded = 0;
        var salvaged = 0;
        var damaged = 0;
        var uncheckedFiles = 0;
        try
        {
            foreach (var candidate in selected)
            {
                RecoveryResult result;
                if (_ntfsResults.TryGetValue(candidate, out var ntfs))
                    result = await RecoveryWriter.RecoverNtfsAsync(_device, ntfs, candidate, destination, progress, recoveryOperation.Token);
                else if (_tskResults.TryGetValue(candidate, out var tsk))
                    result = await RecoveryWriter.RecoverSleuthKitAsync(FindSleuthKitBinDirectory(), tsk.Options, tsk.Candidate, destination, progress, recoveryOperation.Token);
                else if (_exFatResults.TryGetValue(candidate, out var exFat))
                {
                    var physicalCandidate = await SelectExFatPhysicalCandidateAsync(candidate, exFat, recoveryOperation.Token);
                    if (!ReferenceEquals(physicalCandidate, candidate))
                        AppendLog($"主记录结构预检未通过，已自动改用同一文件的备用物理副本：{candidate.OriginalPath} · 偏移 {physicalCandidate.SourceOffset:N0}。 ");
                    result = await RecoveryWriter.RecoverExFatAsync(_device, exFat, physicalCandidate, destination, progress, recoveryOperation.Token);
                }
                else if (_fat32Results.TryGetValue(candidate, out var fat32))
                    result = await RecoveryWriter.RecoverFat32Async(_device, fat32, candidate, destination, progress, recoveryOperation.Token);
                else if (candidate.Discovery == RecoveryDiscovery.PhotoRecFile)
                    result = await RecoveryWriter.RecoverStagedAsync(candidate, destination, progress, recoveryOperation.Token);
                else
                    result = await RecoveryWriter.RecoverRawAsync(_device, candidate, destination, progress, recoveryOperation.Token);
                var validationLabel = result.Integrity switch
                {
                    FileIntegrityState.Valid => "结构校验通过",
                    FileIntegrityState.Damaged => "结构损坏，不可保证打开",
                    _ => "该类型未校验"
                };
                var wasSalvaged = result.Salvage?.State == JpegSalvageState.Salvaged;
                candidate.Integrity = wasSalvaged ? FileIntegrityState.Salvaged : result.Integrity;
                candidate.IntegrityReason = wasSalvaged ? result.Salvage!.Message : result.IntegrityMessage;
                AppendLog($"恢复 {(result.Complete ? "字节写出完成" : "仅部分写出")} · {validationLabel}：{result.OutputPath} · {result.IntegrityMessage} · SHA-256 {result.Sha256}");
                if (wasSalvaged)
                {
                    salvaged++;
                    candidate.Quality = RecoveryQuality.Partial;
                    candidate.QualityReason = result.Salvage!.Message;
                    AppendLog($"自动抢救成功：{result.Salvage.OutputPath} · {result.Salvage.Message} · 从原文件偏移 {result.Salvage.PreservedFromOffset:N0} 开始保留 · SHA-256 {result.Salvage.Sha256}");
                }
                else if (result.Integrity == FileIntegrityState.Damaged)
                {
                    damaged++;
                    candidate.Quality = RecoveryQuality.Poor;
                    candidate.QualityReason = $"恢复后结构校验失败：{result.IntegrityMessage}";
                }
                else if (result.Integrity == FileIntegrityState.NotChecked) uncheckedFiles++;
                succeeded++;
            }
            RefreshResults();
            var summary = $"已写出 {succeeded} 个原恢复文件到：\n{destination}\n\n自动抢救出可打开的JPEG画面：{salvaged} 个\n仍然结构损坏：{damaged} 个\n暂不支持结构校验：{uncheckedFiles} 个";
            MessageBox.Show(this, summary, damaged > 0 ? "恢复完成，但存在损坏文件" : "恢复完成",
                MessageBoxButton.OK, damaged > 0 ? MessageBoxImage.Warning : MessageBoxImage.Information);
        }
        catch (OperationCanceledException) { AppendLog("恢复已取消。已写入的文件不会自动删除。"); }
        catch (Exception ex) { ShowError(ex); }
        finally
        {
            recoveryOperation.Dispose();
            if (concurrentWithScan) RecoverButton.IsEnabled = true;
            else SetBusy(false, "就绪");
        }
    }

    private async Task<RecoveryCandidate> SelectExFatPhysicalCandidateAsync(RecoveryCandidate candidate, ExFatScanResult scan,
        CancellationToken cancellationToken)
    {
        if (_device is null || candidate.AlternateCandidates.Count == 0) return candidate;
        foreach (var option in new[] { candidate }.Concat(candidate.AlternateCandidates))
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
            AppendLog($"镜像完成：{result.ImagePath} · 读取错误 {result.ReadErrors} · SHA-256 {result.Sha256}");
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

    private RecoveryCandidate[] GetRecoverySelection()
    {
        return Candidates.Where(candidate => candidate.IsMarkedForRecovery)
            .Concat(ResultsGrid.SelectedItems.Cast<RecoveryCandidate>())
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
            candidate.IsMarkedForRecovery = checkBox.IsChecked == true;
        UpdateRecoverySelectionStatus();
    }

    private void ClearRecoveryMarks_Click(object sender, RoutedEventArgs e)
    {
        foreach (var candidate in Candidates) candidate.IsMarkedForRecovery = false;
        ResultsGrid.Items.Refresh();
        ResultsGrid.UnselectAll();
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
        foreach (var candidate in _candidateView.Cast<RecoveryCandidate>()) candidate.IsMarkedForRecovery = marked;
        ResultsGrid.Items.Refresh();
        UpdateRecoverySelectionStatus();
    }

    private void UpdateRecoverySelectionStatus()
    {
        if (RecoverButton is null || ResultsGrid is null) return;
        var count = Candidates.Where(candidate => candidate.IsMarkedForRecovery)
            .Concat(ResultsGrid.SelectedItems.Cast<RecoveryCandidate>())
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
        if (RecoverableOnlyCheck?.IsChecked == true && item.Quality is RecoveryQuality.Overwritten or RecoveryQuality.TrimmedOrZeroed or RecoveryQuality.Poor) return false;
        return true;
    }

    private void RefreshResults()
    {
        if (_candidateView is null) return;
        _candidateView.Refresh();
        CountText.Text = $"{_candidateView.Cast<object>().Count():N0} / {Candidates.Count:N0} 个候选文件";
    }

    private static string GetCategory(string extension)
    {
        if (new[] { "jpg", "jpeg", "png", "gif", "bmp", "tif", "tiff", "webp", "heic", "dng", "raw" }.Contains(extension)) return "Image";
        if (new[] { "mp4", "mov", "avi", "mkv", "mts", "m2ts", "wmv", "flv" }.Contains(extension)) return "Video";
        if (new[] { "doc", "docx", "xls", "xlsx", "ppt", "pptx", "pdf", "txt", "rtf", "csv", "log", "ini", "md", "markdown", "json", "xml", "yaml", "yml" }.Contains(extension)) return "Document";
        if (new[] { "mp3", "wav", "flac", "aac", "m4a", "ogg" }.Contains(extension)) return "Audio";
        if (new[] { "zip", "rar", "7z", "gz", "tar" }.Contains(extension)) return "Archive";
        return "Other";
    }

    private async void ResultsGrid_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        UpdateRecoverySelectionStatus();
        var request = ++_previewRequest;
        PreviewImage.Source = null;
        if (ResultsGrid.SelectedItem is not RecoveryCandidate candidate)
        {
            PreviewName.Text = string.Empty;
            PreviewDetails.Text = string.Empty;
            PreviewMessage.Text = "选择文件后查看信息";
            PreviewMessage.Visibility = Visibility.Visible;
            return;
        }

        PreviewName.Text = candidate.OriginalPath;
        PreviewDetails.Text = $"{FormatBytes(candidate.Size)} · {candidate.Quality} · {candidate.IntegrityLabel} · {candidate.DiscoveryLabel}\n{candidate.QualityReason}\n{candidate.IntegrityReason}";
        PreviewMessage.Text = "正在读取只读预览…";
        PreviewMessage.Visibility = Visibility.Visible;
        if (GetCategory(candidate.Extension) != "Image")
        {
            PreviewMessage.Text = $"{candidate.Extension.ToUpperInvariant()} 文件\n当前版本显示文件信息；图片支持内容预览。";
            return;
        }
        if (_device is null)
        {
            PreviewMessage.Text = "结果已载入，请确认源介质仍在线后再预览。";
            return;
        }
        try
        {
            _ntfsResults.TryGetValue(candidate, out var ntfs);
            _exFatResults.TryGetValue(candidate, out var exFat);
            _fat32Results.TryGetValue(candidate, out var fat32);
            var bytes = _tskResults.TryGetValue(candidate, out var tsk)
                ? await SleuthKitEngine.ReadPrefixAsync(FindSleuthKitBinDirectory(), tsk.Options, tsk.Candidate,
                    RecoveryPreview.DefaultMaximumBytes, _operation?.Token ?? CancellationToken.None)
                : candidate.Discovery == RecoveryDiscovery.PhotoRecFile && !string.IsNullOrWhiteSpace(candidate.StagedRecoveryPath)
                ? await ReadStagedPreviewAsync(candidate.StagedRecoveryPath, _operation?.Token ?? CancellationToken.None)
                : await RecoveryPreview.ReadAsync(_device, candidate, ntfs, exFat, fat32);
            if (request != _previewRequest) return;
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
            var entries = Candidates.Select(candidate =>
            {
                _ntfsResults.TryGetValue(candidate, out var ntfs);
                _exFatResults.TryGetValue(candidate, out var exFat);
                _fat32Results.TryGetValue(candidate, out var fat32);
                _tskResults.TryGetValue(candidate, out var tsk);
                return new SessionCandidate(candidate, ntfs?.Boot, exFat?.Boot, fat32?.Boot, ntfs?.PartitionOffset ?? exFat?.PartitionOffset ?? fat32?.PartitionOffset ?? 0,
                    tsk?.Candidate, tsk?.Options);
            }).ToArray();
            var fingerprint = await MediaFingerprintService.ComputeAsync(_device, source);
            var session = new ScanSession(2, DateTime.UtcNow, source, entries, fingerprint);
            await File.WriteAllTextAsync(dialog.FileName, JsonSerializer.Serialize(session, JsonOptions), Encoding.UTF8);
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
            Candidates.Clear(); _ntfsResults.Clear(); _exFatResults.Clear(); _fat32Results.Clear(); _tskResults.Clear(); _candidateHashes.Clear();
            foreach (var entry in session.Candidates)
            {
                Candidates.Add(entry.Candidate);
                if (entry.NtfsBoot is not null) _ntfsResults[entry.Candidate] = NtfsScanResult.CreateRecoveryContext(entry.NtfsBoot, entry.PartitionOffset);
                if (entry.ExFatBoot is not null) _exFatResults[entry.Candidate] = ExFatScanResult.CreateRecoveryContext(entry.ExFatBoot, entry.PartitionOffset);
                if (entry.Fat32Boot is not null) _fat32Results[entry.Candidate] = Fat32ScanResult.CreateRecoveryContext(entry.Fat32Boot, entry.PartitionOffset);
                if (entry.TskCandidate is not null && entry.TskOptions is not null) _tskResults[entry.Candidate] = new(entry.TskOptions, entry.TskCandidate);
            }
            RefreshResults();
            AppendLog($"已载入扫描结果：{Candidates.Count:N0} 个候选；源介质已重新以只读方式打开。");
        }
        catch (Exception ex) { ShowError(ex); }
    }

    private async void ExportCsv_Click(object sender, RoutedEventArgs e)
    {
        if (Candidates.Count == 0) return;
        var dialog = new SaveFileDialog { Title = "导出当前文件清单", Filter = "CSV 文件|*.csv", FileName = $"雨痕文件清单-{DateTime.Now:yyyyMMdd-HHmmss}.csv" };
        if (dialog.ShowDialog(this) != true) return;
        try
        {
            var lines = new List<string> { "原路径,扩展名,字节数,修改时间UTC,恢复质量,发现方式,来源偏移" };
            lines.AddRange(_candidateView.Cast<RecoveryCandidate>().Select(item => string.Join(',',
                Csv(item.OriginalPath), Csv(item.Extension), item.Size.ToString(CultureInfo.InvariantCulture), Csv(item.ModifiedUtc?.ToString("O") ?? ""),
                Csv(item.Quality.ToString()), Csv(item.DiscoveryLabel), item.SourceOffset.ToString(CultureInfo.InvariantCulture))));
            await File.WriteAllLinesAsync(dialog.FileName, lines, new UTF8Encoding(true));
            AppendLog($"已导出当前筛选清单：{dialog.FileName}");
        }
        catch (Exception ex) { ShowError(ex); }
    }

    private static string Csv(string value) => $"\"{value.Replace("\"", "\"\"")}\"";

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
        ulong PartitionOffset, SleuthKitCandidate? TskCandidate = null, SleuthKitScanOptions? TskOptions = null);
    private sealed record TskRecoveryContext(SleuthKitScanOptions Options, SleuthKitCandidate Candidate);

    private Progress<ScanProgress> CreateProgress() => new(progress =>
    {
        ProgressBar.Value = progress.Percent;
        StatusText.Text = $"{progress.Stage} · {progress.Percent:0.0}% · {progress.Message}";
        CountText.Text = $"{Math.Max(progress.Candidates, Candidates.Count):N0} 个候选文件";
    });

    private void SetBusy(bool busy, string status)
    {
        ScanButton.IsEnabled = !busy;
        RecoverButton.IsEnabled = !busy;
        PreflightButton.IsEnabled = !busy;
        CancelButton.IsEnabled = busy;
        PauseButton.IsEnabled = busy && _pausableDevice is not null;
        if (!busy) { _pausableDevice?.Resume(); PauseButton.Content = "暂停"; }
        SourceCombo.IsEnabled = !busy;
        StatusText.Text = status;
        if (!busy && ProgressBar.Value >= 100) ProgressBar.Value = 0;
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
