using Recovery.App;
using Recovery.Core;
using System.ComponentModel;
using System.Diagnostics;
using System.Reflection;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Media;
using System.Windows.Threading;

namespace Recovery.UiTests;

internal static class Program
{
    private static MethodInfo? _refreshResults;
    private static DispatcherTimer? _filterDebounce;

    [STAThread]
    private static int Main()
    {
        MainWindow? window = null;
        try
        {
            SynchronizationContext.SetSynchronizationContext(
                new DispatcherSynchronizationContext(Dispatcher.CurrentDispatcher));
            var application = new Recovery.App.App();
            application.InitializeComponent();
            window = new MainWindow { Width = 1440, Height = 900 };
            window.Show();
            window.UpdateLayout();

            _refreshResults = typeof(MainWindow).GetMethod("RefreshResults", BindingFlags.Instance | BindingFlags.NonPublic)
                ?? throw new InvalidOperationException("RefreshResults was not found.");
            _filterDebounce = (DispatcherTimer?)(typeof(MainWindow).GetField("_filterDebounce", BindingFlags.Instance | BindingFlags.NonPublic)
                ?.GetValue(window)) ?? throw new InvalidOperationException("Filter debounce timer was not found.");

            Assert(window.Title.Contains("雨痕数据恢复", StringComparison.Ordinal) &&
                   window.Title.Contains("只读安全模式", StringComparison.Ordinal),
                "main window identifies RainTrace and read-only safe mode without pinning tests to one release number");

            TestSourceSelector(window);
            TestLightSectionTheme(window);
            TestScenarioLayout(window);
            TestResultViews(window);
            TestFiltersAndDirectorySafety(window);
            TestVirtualizationAndSelection(window);
            TestProgressLayout(window);
            TestHundredThousandCandidateWorkload(window);

            window.Close();
            window = null;
            Console.WriteLine("RESULT: ALL V1.12/V1.13 WPF UI CONTRACT TESTS PASSED");
            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine(ex);
            return 1;
        }
        finally
        {
            _filterDebounce?.Stop();
            window?.Close();
        }
    }

    private static void TestSourceSelector(MainWindow window)
    {
        var sourceCombo = FindRequired<ComboBox>(window, "SourceCombo");
        Assert(string.IsNullOrEmpty(sourceCombo.DisplayMemberPath) && sourceCombo.ItemTemplate is not null,
            "source selector uses the icon-and-details item template");
        Assert(sourceCombo.ActualHeight >= 56, "source selector is tall enough for icon and two-line media information");
        Assert(sourceCombo.SelectedItem is MediaDescriptor selectedSource &&
               selectedSource.Category == MediaCategory.UsbStorage &&
               selectedSource.MediaTraitsLabel.Contains("只读扫描", StringComparison.Ordinal),
            "smoke fixture exposes a classified read-only USB source without opening a physical disk");
    }

    private static void TestScenarioLayout(MainWindow window)
    {
        var deleted = FindRequired<RadioButton>(window, "DeletedScenarioCheck");
        var formatted = FindRequired<RadioButton>(window, "FormattedScenarioCheck");
        var lost = FindRequired<RadioButton>(window, "LostPartitionScenarioCheck");
        var summary = FindRequired<TextBlock>(window, "ScenarioSummaryText");
        var stages = FindRequired<TextBlock>(window, "PlanStagesText");
        var metadata = FindRequired<CheckBox>(window, "MetadataCheck");
        var ntfsDeep = FindRequired<CheckBox>(window, "DeepMetadataCheck");
        var exFatDeep = FindRequired<CheckBox>(window, "ExFatDeepMetadataCheck");
        var photoRec = FindRequired<CheckBox>(window, "CarveCheck");
        var lostPartition = FindRequired<CheckBox>(window, "LostPartitionCheck");
        var modifiedFrom = FindRequired<DatePicker>(window, "ModifiedFromPicker");
        var modifiedTo = FindRequired<DatePicker>(window, "ModifiedToPicker");
        var scanOptions = FindRequired<FrameworkElement>(window, "ScanOptionsPanel");
        var advanced = FindVisualChildren<Expander>(window)
            .SingleOrDefault(item => item.Header?.ToString()?.Contains("高级设置", StringComparison.Ordinal) == true)
            ?? throw new InvalidOperationException("Advanced scan options expander was not found.");

        var readableText = Color.FromRgb(0x17, 0x20, 0x33);
        Assert(window.Foreground is SolidColorBrush windowForeground && windowForeground.Color == readableText &&
               deleted.Foreground is SolidColorBrush deletedForeground && deletedForeground.Color == readableText &&
               formatted.Foreground is SolidColorBrush formattedForeground && formattedForeground.Color == readableText &&
               lost.Foreground is SolidColorBrush lostForeground && lostForeground.Color == readableText &&
               summary.Foreground is SolidColorBrush summaryForeground && summaryForeground.Color == readableText &&
               advanced.Foreground is SolidColorBrush advancedForeground && advancedForeground.Color == readableText,
            "scenario labels, summary and advanced header use an explicit high-contrast foreground");
        Assert(FindVisualChildren<TextBlock>(window).All(item =>
                   !item.Text.Contains("源介质永久只读", StringComparison.Ordinal)),
            "the removed read-only marketing badge is not rendered in the header");
        Assert(Math.Abs(modifiedFrom.ActualHeight - 42) < 0.5 && Math.Abs(modifiedTo.ActualHeight - 42) < 0.5 &&
               modifiedFrom.VerticalAlignment == VerticalAlignment.Bottom && modifiedTo.VerticalAlignment == VerticalAlignment.Bottom,
            "date range controls use the compact input height and align to the filter-row baseline");

        Assert(deleted.IsChecked == true && formatted.IsChecked != true && lost.IsChecked != true,
            "the default layout exposes exactly three scenarios and selects deleted-file recovery");
        Assert(!advanced.IsExpanded && !scanOptions.IsVisible,
            "professional scan checkboxes are collapsed by default");
        Assert(metadata.IsChecked == true && ntfsDeep.IsChecked != true && exFatDeep.IsChecked != true &&
               photoRec.IsChecked != true && lostPartition.IsChecked != true,
            "deleted-file preset starts with metadata-first scanning only");
        Assert(summary.Text.Contains("原文件名", StringComparison.Ordinal) &&
               stages.Text.Contains("文件系统元数据", StringComparison.Ordinal),
            "deleted-file scenario explains its metadata-first plan");

        formatted.IsChecked = true;
        window.UpdateLayout();
        Assert(formatted.IsChecked == true && deleted.IsChecked != true && lost.IsChecked != true,
            "formatted-or-RAW scenario is mutually exclusive");
        Assert(metadata.IsChecked == true && ntfsDeep.IsChecked == true && exFatDeep.IsChecked == true &&
               photoRec.IsChecked == true && lostPartition.IsChecked != true,
            "formatted-or-RAW scenario enables deep metadata and content fallback");
        Assert(summary.Text.Contains("备用", StringComparison.Ordinal) &&
               stages.Text.Contains("深度元数据", StringComparison.Ordinal) &&
               stages.Text.Contains("内容扫描", StringComparison.Ordinal),
            "formatted-or-RAW scenario exposes its complete automatic stage plan");

        lost.IsChecked = true;
        window.UpdateLayout();
        Assert(lost.IsChecked == true && deleted.IsChecked != true && formatted.IsChecked != true,
            "lost-partition scenario is mutually exclusive");
        Assert(metadata.IsChecked == true && ntfsDeep.IsChecked != true && exFatDeep.IsChecked != true &&
               photoRec.IsChecked == true && lostPartition.IsChecked == true,
            "lost-partition scenario enables partition discovery plus one content fallback");
        Assert(summary.Text.Contains("不会写回", StringComparison.Ordinal) &&
               stages.Text.Contains("丢失分区", StringComparison.Ordinal),
            "lost-partition scenario explicitly promises read-only candidate recovery");

        deleted.IsChecked = true;
        advanced.IsExpanded = true;
        window.UpdateLayout();
        Assert(scanOptions.IsVisible, "advanced options can be intentionally expanded");
        advanced.IsExpanded = false;
        window.UpdateLayout();
    }

    private static void TestLightSectionTheme(MainWindow window)
    {
        var sourceCard = FindRequired<Border>(window, "SourceScenarioCard");
        var filterCard = FindRequired<Border>(window, "FilterCard");
        var categoryCard = FindRequired<Border>(window, "CategoryCard");
        var resultsCard = FindRequired<Border>(window, "ResultsCard");
        var previewCard = FindRequired<Border>(window, "PreviewCard");

        Assert(window.Background is SolidColorBrush canvas && canvas.Color == Color.FromRgb(0xEA, 0xF0, 0xF6),
            "the main work area uses a light gray-blue canvas instead of a black board");
        Assert(sourceCard.Background is SolidColorBrush source && source.Color == Colors.White &&
               resultsCard.Background is SolidColorBrush results && results.Color == Colors.White &&
               filterCard.Background is SolidColorBrush filter && filter.Color == Color.FromRgb(0xF5, 0xF8, 0xFC) &&
               categoryCard.Background is SolidColorBrush category && category.Color == Color.FromRgb(0xF4, 0xF8, 0xFC) &&
               previewCard.Background is SolidColorBrush preview && preview.Color == Color.FromRgb(0xF1, 0xFA, 0xF7),
            "scan, filter, result and preview sections use distinct light card surfaces");
        Assert(sourceCard.Effect is not null && filterCard.Effect is not null && categoryCard.Effect is not null &&
               resultsCard.Effect is not null && previewCard.Effect is not null,
            "primary functional sections have a restrained card shadow for visual separation");
        var filterControls = FindVisualChildren<Control>(filterCard)
            .Where(item => item.TemplatedParent is null &&
                           (item is TextBox || item is ComboBox || item is DatePicker || item is Button))
            .ToArray();
        var filterHeightSummary = string.Join(", ", filterControls.Select(item => $"{item.Name}:{item.GetType().Name}={item.ActualHeight:0.0}"));
        Assert(filterControls.Length == 17 && filterControls.All(item => Math.Abs(item.ActualHeight - 42) < 0.5),
            $"both filter rows use one 42-pixel height for inputs, selectors and buttons ({filterHeightSummary})");
    }

    private static void TestResultViews(MainWindow window)
    {
        var grid = FindRequired<DataGrid>(window, "ResultsGrid");
        var tree = FindRequired<TreeView>(window, "TreeResults");
        var thumbnails = FindRequired<ListBox>(window, "ThumbnailList");
        var listButton = FindRequired<Button>(window, "ListViewButton");
        var treeButton = FindRequired<Button>(window, "TreeViewButton");
        var thumbnailButton = FindRequired<Button>(window, "ThumbnailViewButton");

        Assert(grid.Visibility == Visibility.Visible && tree.Visibility == Visibility.Collapsed &&
               thumbnails.Visibility == Visibility.Collapsed,
            "flat list is the default result view");
        Assert(window.Candidates.Count == 8 && grid.Items.Count == 8 &&
               window.Candidates.All(candidate => RecoveryCapabilityRegistry.SupportsImagePreview(candidate.Extension)),
            "smoke fixture begins with eight registry-previewable image candidates");

        SelectResultView(window, treeButton);
        var rebuildTree = typeof(MainWindow).GetMethod("RebuildTreeAsync", BindingFlags.Instance | BindingFlags.NonPublic)
            ?? throw new InvalidOperationException("RebuildTreeAsync was not found.");
        var treeTask = (Task)(rebuildTree.Invoke(window, null)
            ?? throw new InvalidOperationException("RebuildTreeAsync returned null."));
        Assert(PumpUntil(() => treeTask.IsCompleted, TimeSpan.FromSeconds(3)),
            "directory tree completes its background grouping pass");
        treeTask.GetAwaiter().GetResult();
        Assert(tree.Items.Count > 0,
            "directory tree is built asynchronously from stable candidates");
        Assert(grid.Visibility == Visibility.Collapsed && tree.Visibility == Visibility.Visible &&
               thumbnails.Visibility == Visibility.Collapsed,
            "directory-tree switch shows only the tree view");
        Assert(VirtualizingPanel.GetIsVirtualizing(tree) &&
               VirtualizingPanel.GetVirtualizationMode(tree) == VirtualizationMode.Recycling,
            "directory tree enables recycling virtualization");

        SelectResultView(window, thumbnailButton);
        var refreshThumbnails = typeof(MainWindow).GetMethod("RefreshThumbnailView", BindingFlags.Instance | BindingFlags.NonPublic)
            ?? throw new InvalidOperationException("RefreshThumbnailView was not found.");
        refreshThumbnails.Invoke(window, null);
        window.UpdateLayout();
        var candidateView = (ICollectionView?)(typeof(MainWindow).GetField("_candidateView", BindingFlags.Instance | BindingFlags.NonPublic)
            ?.GetValue(window)) ?? throw new InvalidOperationException("Candidate view was not found.");
        Assert(candidateView.Cast<RecoveryCandidate>().Count() == 8,
            "candidate view remains populated after tree grouping");
        Assert(PumpUntil(() => thumbnails.Items.Count > 0, TimeSpan.FromSeconds(3)),
            "thumbnail grouping completes without blocking the UI dispatcher");
        var thumbnailSourceCount = thumbnails.ItemsSource?.Cast<object>().Count() ?? 0;
        Assert(thumbnailSourceCount == 8,
            $"thumbnail ItemsSource contains all previewable fixture images ({thumbnailSourceCount:N0} source items)");
        Assert(grid.Visibility == Visibility.Collapsed && tree.Visibility == Visibility.Collapsed &&
               thumbnails.Visibility == Visibility.Visible,
            "thumbnail switch shows only the thumbnail surface");
        Assert(thumbnails.Items.Count > 0,
            $"thumbnail view receives registered image candidates ({thumbnails.Items.Count:N0} items)");
        Assert(thumbnails.SelectionMode == SelectionMode.Extended &&
               VirtualizingPanel.GetIsVirtualizing(thumbnails) &&
               VirtualizingPanel.GetVirtualizationMode(thumbnails) == VirtualizationMode.Recycling &&
               ScrollViewer.GetCanContentScroll(thumbnails),
            "thumbnail view preserves extended selection and recycling virtualization");

        SelectResultView(window, listButton);
        window.UpdateLayout();
        Assert(grid.Visibility == Visibility.Visible && tree.Visibility == Visibility.Collapsed &&
               thumbnails.Visibility == Visibility.Collapsed,
            "list switch restores the virtualized DataGrid");
    }

    private static void TestFiltersAndDirectorySafety(MainWindow window)
    {
        var grid = FindRequired<DataGrid>(window, "ResultsGrid");
        var search = FindRequired<TextBox>(window, "SearchBox");
        var extension = FindRequired<TextBox>(window, "ExtensionBox");
        var from = FindRequired<DatePicker>(window, "ModifiedFromPicker");
        var to = FindRequired<DatePicker>(window, "ModifiedToPicker");
        var minimum = FindRequired<TextBox>(window, "MinimumSizeBox");
        var maximum = FindRequired<TextBox>(window, "MaximumSizeBox");
        var quality = FindRequired<ComboBox>(window, "QualityCombo");
        var discovery = FindRequired<ComboBox>(window, "DiscoveryCombo");
        var integrity = FindRequired<ComboBox>(window, "IntegrityCombo");
        var previewable = FindRequired<CheckBox>(window, "PreviewableOnlyCheck");
        var recoverable = FindRequired<CheckBox>(window, "RecoverableOnlyCheck");

        var directory = new RecoveryCandidate
        {
            Name = "资料目录", OriginalPath = "测试目录\\资料目录", IsDirectory = true, IsDeleted = true,
            FileSystem = FileSystemKind.Ntfs, Discovery = RecoveryDiscovery.NtfsCurrentMft, Quality = RecoveryQuality.Good
        };
        var text = new RecoveryCandidate
        {
            Name = "恢复说明.txt", OriginalPath = "测试目录\\文档\\恢复说明.txt", Size = 600 * 1024,
            IsDeleted = true, ModifiedUtc = new DateTime(2025, 4, 16, 8, 30, 0, DateTimeKind.Utc),
            FileSystem = FileSystemKind.Ntfs, Discovery = RecoveryDiscovery.NtfsCurrentMft,
            Quality = RecoveryQuality.Excellent, Integrity = FileIntegrityState.Valid
        };
        var raw = new RecoveryCandidate
        {
            Name = "carved_00000042.png", OriginalPath = "内容扫描\\png\\carved_00000042.png",
            Size = 3 * 1024 * 1024, IsDeleted = true,
            ModifiedUtc = new DateTime(2024, 8, 20, 0, 0, 0, DateTimeKind.Utc),
            FileSystem = FileSystemKind.Unknown, Discovery = RecoveryDiscovery.PhotoRecFile,
            Quality = RecoveryQuality.Partial, Integrity = FileIntegrityState.Damaged
        };
        window.Candidates.Add(directory);
        window.Candidates.Add(text);
        window.Candidates.Add(raw);
        Refresh(window);

        Assert(_filterDebounce!.Interval >= TimeSpan.FromMilliseconds(200),
            "search input uses a debounce interval suitable for large result sets");

        extension.Text = "txt";
        Refresh(window);
        Assert(grid.Items.Count == 1 && ReferenceEquals(grid.Items[0], text),
            "extension filter accepts a normalized extension");

        extension.Clear();
        minimum.Text = "550KB";
        maximum.Text = "650KB";
        Refresh(window);
        Assert(grid.Items.Count == 1 && ReferenceEquals(grid.Items[0], text),
            "minimum and maximum size filters use human-readable units");

        minimum.Clear();
        maximum.Clear();
        from.SelectedDate = new DateTime(2025, 1, 1);
        to.SelectedDate = new DateTime(2025, 12, 31);
        Refresh(window);
        Assert(grid.Items.Count == 1 && ReferenceEquals(grid.Items[0], text),
            "modified-date range filter excludes candidates without or outside the requested date");

        from.SelectedDate = null;
        to.SelectedDate = null;
        SelectComboTag(quality, "Partial");
        Refresh(window);
        Assert(grid.Items.Count == 1 && ReferenceEquals(grid.Items[0], raw),
            "recovery-quality filter selects the expected candidate");

        quality.SelectedIndex = 0;
        SelectComboTag(discovery, "Raw");
        Refresh(window);
        Assert(grid.Items.Count == 1 && ReferenceEquals(grid.Items[0], raw),
            "discovery-method filter distinguishes content scan from metadata");

        discovery.SelectedIndex = 0;
        SelectComboTag(integrity, "Valid");
        Refresh(window);
        Assert(grid.Items.Count == 1 && ReferenceEquals(grid.Items[0], text),
            "structure-state filter uses preflight integrity state");

        integrity.SelectedIndex = 0;
        previewable.IsChecked = true;
        Refresh(window);
        Assert(grid.Items.Cast<RecoveryCandidate>().All(item =>
                RecoveryCapabilityRegistry.SupportsImagePreview(item.Extension) || RecoveryCapabilityRegistry.IsText(item.Extension)),
            "previewable filter includes only registered image or readable text formats");

        previewable.IsChecked = false;
        recoverable.IsChecked = true;
        Refresh(window);
        Assert(!grid.Items.Cast<RecoveryCandidate>().Contains(directory),
            "recoverable-only filter excludes directory nodes");

        ResetFilters(window);
        search.Text = "恢复说明";
        Assert(_filterDebounce.IsEnabled, "typing starts the search debounce timer");
        _filterDebounce.Stop();
        Refresh(window);
        Assert(grid.Items.Count == 1 && ReferenceEquals(grid.Items[0], text),
            "debounced search matches file name or original path");

        ResetFilters(window);
        grid.ScrollIntoView(directory);
        window.UpdateLayout();
        var directoryRow = (DataGridRow?)(grid.ItemContainerGenerator.ContainerFromItem(directory))
            ?? throw new InvalidOperationException("Directory row was not realized.");
        var directoryCheckBox = FindVisualChild<CheckBox>(directoryRow)
            ?? throw new InvalidOperationException("Directory recovery checkbox was not realized.");
        Assert(!directory.CanRecover && !directoryCheckBox.IsEnabled,
            "directory candidates remain visible as tree nodes but cannot enter the recovery queue");

        var qualityColumn = grid.Columns.OfType<DataGridBoundColumn>()
            .Single(column => string.Equals(column.Header?.ToString(), "质量", StringComparison.Ordinal));
        Assert(qualityColumn.Binding is Binding qualityBinding &&
               string.Equals(qualityBinding.Path?.Path, nameof(RecoveryCandidate.QualityLabel), StringComparison.Ordinal) &&
               text.QualityLabel == "优秀" && raw.QualityLabel == "部分可恢复",
            "quality column binds to Chinese labels rather than enum names");
    }

    private static void TestVirtualizationAndSelection(MainWindow window)
    {
        var grid = FindRequired<DataGrid>(window, "ResultsGrid");
        Assert(grid.SelectionMode == DataGridSelectionMode.Extended && grid.SelectionUnit == DataGridSelectionUnit.FullRow,
            "DataGrid uses Windows extended full-row selection for Ctrl and Shift gestures");
        Assert(grid.EnableRowVirtualization && grid.EnableColumnVirtualization &&
               VirtualizingPanel.GetIsVirtualizing(grid) &&
               VirtualizingPanel.GetVirtualizationMode(grid) == VirtualizationMode.Recycling &&
               ScrollViewer.GetCanContentScroll(grid),
            "DataGrid enables row/column virtualization with recycling");
        Assert(Math.Abs(grid.Columns[0].ActualWidth - 96) < 1 &&
               grid.Columns[0].MinWidth == 96 && grid.Columns[0].MaxWidth == 96,
            "selection column keeps enough fixed width for the complete select-all label");
        var selectAllHeader = (CheckBox)(grid.Columns[0].HeaderTemplate?.LoadContent()
            ?? throw new InvalidOperationException("Select-all header template was not created."));
        Assert(string.Equals(selectAllHeader.Content?.ToString(), "全选", StringComparison.Ordinal) &&
               selectAllHeader.Margin == new Thickness(0),
            "select-all header keeps its complete label and retained checkbox");

        ResetFilters(window);
        grid.UnselectAll();
        grid.SelectAll();
        var selectionMethod = typeof(MainWindow).GetMethod("GetRecoverySelection", BindingFlags.Instance | BindingFlags.NonPublic)
            ?? throw new InvalidOperationException("GetRecoverySelection was not found.");
        var recoverySelection = (RecoveryCandidate[])(selectionMethod.Invoke(window, null)
            ?? throw new InvalidOperationException("GetRecoverySelection returned null."));
        Assert(recoverySelection.Length == window.Candidates.Count(candidate => candidate.CanRecover) &&
               recoverySelection.All(candidate => candidate.CanRecover),
            "Ctrl+A target selects all visible files while the recovery queue excludes directories");

        grid.UnselectAll();
        var contiguous = grid.Items.Cast<RecoveryCandidate>().Where(item => item.CanRecover).Take(4).ToArray();
        foreach (var candidate in contiguous.Take(3)) grid.SelectedItems.Add(candidate);
        Assert(grid.SelectedItems.Count == 3 && contiguous.Take(3).All(grid.SelectedItems.Contains),
            "extended-selection state supports a contiguous Shift-style range");

        grid.SelectedItems.Remove(contiguous[1]);
        grid.SelectedItems.Add(contiguous[3]);
        Assert(grid.SelectedItems.Count == 3 && !grid.SelectedItems.Contains(contiguous[1]) &&
               grid.SelectedItems.Contains(contiguous[0]) && grid.SelectedItems.Contains(contiguous[2]) &&
               grid.SelectedItems.Contains(contiguous[3]),
            "extended-selection state supports Ctrl-style single-item toggle without clearing other rows");

        var marked = contiguous[1];
        marked.IsMarkedForRecovery = true;
        recoverySelection = (RecoveryCandidate[])selectionMethod.Invoke(window, null)!;
        Assert(recoverySelection.Contains(marked) && recoverySelection.Contains(contiguous[0]) &&
               recoverySelection.Contains(contiguous[2]) && recoverySelection.Contains(contiguous[3]),
            "retained checkboxes and selected rows form one deduplicated recovery selection");

        grid.ScrollIntoView(contiguous[0]);
        window.UpdateLayout();
        var selectedRow = (DataGridRow?)(grid.ItemContainerGenerator.ContainerFromItem(contiguous[0]))
            ?? throw new InvalidOperationException("Selected row was not realized.");
        Assert(selectedRow.IsSelected && selectedRow.Background is SolidColorBrush background &&
               background.Color == Color.FromRgb(0x1D, 0x4E, 0xD8) && selectedRow.BorderThickness.Left == 4,
            "selected rows use a high-contrast blue background and a visible left indicator");
        Assert(FindVisualChild<CheckBox>(selectedRow) is not null,
            "row recovery checkbox remains visible during multi-selection");
    }

    private static void TestProgressLayout(MainWindow window)
    {
        var progressBar = FindRequired<ProgressBar>(window, "ProgressBar");
        var countText = FindRequired<TextBlock>(window, "CountText");
        Assert(progressBar.ActualHeight >= 12, "scan progress bar has a clearly visible thickness");
        var initialWidth = progressBar.ActualWidth;
        countText.Text = "1,234,567 / 12,345,678 个候选文件";
        window.UpdateLayout();
        Assert(initialWidth > 0 && Math.Abs(initialWidth - progressBar.ActualWidth) < 1,
            "changing candidate-count text cannot resize the progress track");
    }

    private static void TestHundredThousandCandidateWorkload(MainWindow window)
    {
        var grid = FindRequired<DataGrid>(window, "ResultsGrid");
        var search = FindRequired<TextBox>(window, "SearchBox");
        ResetFilters(window);
        grid.UnselectAll();
        window.Candidates.Clear();

        const int candidateCount = 100_000;
        var syntheticCandidates = new RecoveryCandidate[candidateCount];
        for (var index = 0; index < candidateCount; index++)
        {
            var extension = index % 5 == 0 ? "pdf" : "jpg";
            syntheticCandidates[index] = new RecoveryCandidate
            {
                Name = $"批量-{index:000000}.{extension}",
                OriginalPath = $"十万候选\\组-{index % 100:00}\\批量-{index:000000}.{extension}",
                Size = checked((ulong)(index + 1) * 128), IsDeleted = true,
                FileSystem = FileSystemKind.ExFat, Discovery = RecoveryDiscovery.ExFatMetadata,
                Quality = RecoveryQuality.Good
            };
        }
        var populateTimer = Stopwatch.StartNew();
        window.Candidates.AddRange(syntheticCandidates);
        Refresh(window);
        window.UpdateLayout();
        populateTimer.Stop();

        Assert(grid.Items.Count == candidateCount,
            "virtualized result view accepts 100,000 synthetic candidates");
        Assert(populateTimer.Elapsed < TimeSpan.FromSeconds(5),
            $"100,000-candidate batch notification and first layout avoid a long UI hang ({populateTimer.Elapsed.TotalSeconds:F2}s)");
        var realizedRows = FindVisualChildren<DataGridRow>(grid).Count;
        Assert(realizedRows > 0 && realizedRows < 200,
            $"recycling realizes only the visible rows for 100,000 candidates ({realizedRows:N0} rows)");

        var filterTimer = Stopwatch.StartNew();
        search.Text = "批量-099999";
        _filterDebounce!.Stop();
        Refresh(window);
        window.UpdateLayout();
        filterTimer.Stop();
        Assert(grid.Items.Count == 1 && ((RecoveryCandidate)grid.Items[0]).Name == "批量-099999.jpg",
            "search correctly filters the 100,000-candidate result set");
        Assert(filterTimer.Elapsed < TimeSpan.FromSeconds(10),
            $"100,000-candidate search refresh stays responsive ({filterTimer.Elapsed.TotalSeconds:F2}s)");
    }

    private static void ResetFilters(MainWindow window)
    {
        _filterDebounce?.Stop();
        FindRequired<TextBox>(window, "SearchBox").Clear();
        FindRequired<TextBox>(window, "ExtensionBox").Clear();
        FindRequired<DatePicker>(window, "ModifiedFromPicker").SelectedDate = null;
        FindRequired<DatePicker>(window, "ModifiedToPicker").SelectedDate = null;
        FindRequired<TextBox>(window, "MinimumSizeBox").Clear();
        FindRequired<TextBox>(window, "MaximumSizeBox").Clear();
        FindRequired<ComboBox>(window, "QualityCombo").SelectedIndex = 0;
        FindRequired<ComboBox>(window, "DiscoveryCombo").SelectedIndex = 0;
        FindRequired<ComboBox>(window, "IntegrityCombo").SelectedIndex = 0;
        FindRequired<ListBox>(window, "CategoryList").SelectedIndex = 0;
        FindRequired<CheckBox>(window, "PreviewableOnlyCheck").IsChecked = false;
        FindRequired<CheckBox>(window, "RecoverableOnlyCheck").IsChecked = false;
        _filterDebounce?.Stop();
        Refresh(window);
    }

    private static void Refresh(MainWindow window)
    {
        _filterDebounce?.Stop();
        _refreshResults!.Invoke(window, null);
        window.UpdateLayout();
    }

    private static void SelectComboTag(ComboBox comboBox, string tag)
    {
        comboBox.SelectedItem = comboBox.Items.Cast<ComboBoxItem>()
            .Single(item => string.Equals(item.Tag?.ToString(), tag, StringComparison.Ordinal));
    }

    private static void SelectResultView(MainWindow window, Button button)
    {
        var handler = typeof(MainWindow).GetMethod("ResultView_Click", BindingFlags.Instance | BindingFlags.NonPublic)
            ?? throw new InvalidOperationException("ResultView_Click was not found.");
        handler.Invoke(window, [button, new RoutedEventArgs(Button.ClickEvent, button)]);
        window.UpdateLayout();
    }

    private static bool PumpUntil(Func<bool> condition, TimeSpan timeout)
    {
        var timer = Stopwatch.StartNew();
        while (!condition() && timer.Elapsed < timeout)
        {
            var frame = new DispatcherFrame();
            var dispatcherTimer = new DispatcherTimer(DispatcherPriority.Background)
            {
                Interval = TimeSpan.FromMilliseconds(15)
            };
            dispatcherTimer.Tick += (_, _) =>
            {
                dispatcherTimer.Stop();
                frame.Continue = false;
            };
            dispatcherTimer.Start();
            Dispatcher.PushFrame(frame);
        }
        return condition();
    }

    private static T FindRequired<T>(FrameworkElement root, string name) where T : FrameworkElement
        => (T)(root.FindName(name) ?? throw new InvalidOperationException($"{name} was not created."));

    private static T? FindVisualChild<T>(DependencyObject parent) where T : DependencyObject
        => FindVisualChildren<T>(parent).FirstOrDefault();

    private static List<T> FindVisualChildren<T>(DependencyObject parent) where T : DependencyObject
    {
        var matches = new List<T>();
        FindVisualChildren(parent, matches);
        return matches;
    }

    private static void FindVisualChildren<T>(DependencyObject parent, ICollection<T> matches) where T : DependencyObject
    {
        for (var index = 0; index < VisualTreeHelper.GetChildrenCount(parent); index++)
        {
            var child = VisualTreeHelper.GetChild(parent, index);
            if (child is T match) matches.Add(match);
            FindVisualChildren(child, matches);
        }
    }

    private static void Assert(bool condition, string name)
    {
        if (!condition) throw new InvalidOperationException($"FAILED: {name}");
        Console.WriteLine($"PASS {name}");
    }
}
