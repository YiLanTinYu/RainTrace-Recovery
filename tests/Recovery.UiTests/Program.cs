using Recovery.App;
using Recovery.Core;
using System.Reflection;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace Recovery.UiTests;

internal static class Program
{
    [STAThread]
    private static int Main()
    {
        try
        {
            var application = new Recovery.App.App();
            application.InitializeComponent();
            var window = new MainWindow();
            window.Width = window.MinWidth;
            window.Show();
            window.UpdateLayout();
            Assert(window.Title == "雨痕数据恢复 1.10.1 · TSK/PhotoRec 只读安全模式", "1.10.1 main window starts with the expected title");
            var sourceCombo = (ComboBox)(window.FindName("SourceCombo") ?? throw new InvalidOperationException("SourceCombo was not created."));
            var grid = (DataGrid)(window.FindName("ResultsGrid") ?? throw new InvalidOperationException("ResultsGrid was not created."));
            var photoRec = (CheckBox)(window.FindName("CarveCheck") ?? throw new InvalidOperationException("CarveCheck was not created."));
            var scanOptions = (FrameworkElement)(window.FindName("ScanOptionsPanel") ?? throw new InvalidOperationException("ScanOptionsPanel was not created."));
            var scanControls = (FrameworkElement)(window.FindName("ScanControlsPanel") ?? throw new InvalidOperationException("ScanControlsPanel was not created."));
            var scanButton = (Button)(window.FindName("ScanButton") ?? throw new InvalidOperationException("ScanButton was not created."));
            var pauseButton = (Button)(window.FindName("PauseButton") ?? throw new InvalidOperationException("PauseButton was not created."));
            var cancelButton = (Button)(window.FindName("CancelButton") ?? throw new InvalidOperationException("CancelButton was not created."));
            var progressBar = (ProgressBar)(window.FindName("ProgressBar") ?? throw new InvalidOperationException("ProgressBar was not created."));
            var countText = (TextBlock)(window.FindName("CountText") ?? throw new InvalidOperationException("CountText was not created."));
            var preflightButton = (Button)(window.FindName("PreflightButton") ?? throw new InvalidOperationException("PreflightButton was not created."));
            var lostPartition = (CheckBox)(window.FindName("LostPartitionCheck") ?? throw new InvalidOperationException("LostPartitionCheck was not created."));

            Assert(grid.SelectionMode == DataGridSelectionMode.Extended, "DataGrid uses Windows extended multi-selection");
            Assert(Math.Abs(grid.Columns[0].ActualWidth - 96) < 1 && grid.Columns[0].MinWidth == 96 && grid.Columns[0].MaxWidth == 96,
                "selection column keeps enough fixed width for the complete select-all label");
            var selectAllHeader = (CheckBox)(grid.Columns[0].HeaderTemplate?.LoadContent()
                ?? throw new InvalidOperationException("Select-all header template was not created."));
            Assert(string.Equals(selectAllHeader.Content?.ToString(), "全选", StringComparison.Ordinal) && selectAllHeader.Margin == new Thickness(0),
                "select-all header keeps its full label without inherited checkbox margins");
            Assert(string.IsNullOrEmpty(sourceCombo.DisplayMemberPath) && sourceCombo.ItemTemplate is not null,
                "source selector uses the icon-and-details item template");
            Assert(sourceCombo.ActualHeight >= 56, "source selector is tall enough for icon and two-line media information");
            Assert(sourceCombo.SelectedItem is MediaDescriptor selectedSource && selectedSource.Category == MediaCategory.UsbStorage &&
                   selectedSource.MediaTraitsLabel.Contains("只读扫描", StringComparison.Ordinal),
                "source selector exposes a classified read-only USB fixture");
            Assert(grid.SelectionUnit == DataGridSelectionUnit.FullRow, "DataGrid selects complete rows");
            Assert(photoRec.IsChecked != true, "PhotoRec deep fallback is not selected by default");
            Assert(preflightButton.ToolTip?.ToString()?.Contains("TXT", StringComparison.Ordinal) == true &&
                   preflightButton.ToolTip?.ToString()?.Contains("YAML/YML", StringComparison.Ordinal) == true,
                "preflight tooltip lists the expanded format support");
            Assert(lostPartition.ToolTip?.ToString()?.Contains("GPT 备份表", StringComparison.Ordinal) == true &&
                   lostPartition.ToolTip?.ToString()?.Contains("不写回", StringComparison.Ordinal) == true,
                "lost-partition tooltip explains backup discovery and read-only behavior");
            Assert(scanControls.TranslatePoint(new Point(0, 0), window).X > scanOptions.TranslatePoint(new Point(0, 0), window).X,
                "scan controls stay in a dedicated right-side group");
            var scanButtonTop = scanButton.TranslatePoint(new Point(0, 0), window).Y;
            Assert(Math.Abs(scanButtonTop - pauseButton.TranslatePoint(new Point(0, 0), window).Y) < 1 &&
                   Math.Abs(scanButtonTop - cancelButton.TranslatePoint(new Point(0, 0), window).Y) < 1,
                "start, pause and stop remain on one row");
            Assert(progressBar.ActualHeight >= 12, "scan progress bar has a clearly visible height");
            var initialProgressWidth = progressBar.ActualWidth;
            countText.Text = "1,234,567 / 12,345,678 个候选文件";
            window.UpdateLayout();
            Assert(Math.Abs(initialProgressWidth - progressBar.ActualWidth) < 1, "candidate count changes do not resize the progress bar");
            Assert(grid.Items.Count == 8, "smoke fixture exposes eight candidates");

            grid.Focus();
            grid.SelectAll();
            Assert(grid.SelectedItems.Count == 8, "Ctrl+A handler target selects all visible files");

            grid.UnselectAll();
            var first = (RecoveryCandidate)grid.Items[0];
            var second = (RecoveryCandidate)grid.Items[1];
            var third = (RecoveryCandidate)grid.Items[2];
            grid.SelectedItems.Add(first);
            grid.SelectedItems.Add(second);
            third.IsMarkedForRecovery = true;
            var selectionMethod = typeof(MainWindow).GetMethod("GetRecoverySelection", BindingFlags.Instance | BindingFlags.NonPublic)
                ?? throw new InvalidOperationException("GetRecoverySelection was not found.");
            var recoverySelection = (RecoveryCandidate[])(selectionMethod.Invoke(window, null)
                ?? throw new InvalidOperationException("GetRecoverySelection returned null."));
            Assert(recoverySelection.Length == 3 && recoverySelection.Contains(first) && recoverySelection.Contains(second) && recoverySelection.Contains(third),
                "row selection and retained checkboxes form one recovery selection");

            grid.ScrollIntoView(first);
            window.UpdateLayout();
            var firstRow = (DataGridRow)(grid.ItemContainerGenerator.ContainerFromItem(first)
                ?? throw new InvalidOperationException("Selected row was not realized."));
            Assert(firstRow.IsSelected, "selected row remains selected");
            Assert(firstRow.Background is SolidColorBrush background && background.Color == Color.FromRgb(0x1D, 0x4E, 0xD8),
                "selected row resolves to the high-contrast blue background");
            Assert(firstRow.BorderThickness.Left == 4, "selected row has an additional visible left indicator");
            Assert(FindVisualChild<CheckBox>(firstRow) is not null, "row recovery checkbox remains available");

            window.Close();
            Console.WriteLine("RESULT: ALL WPF MULTI-SELECTION TESTS PASSED");
            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine(ex);
            return 1;
        }
    }

    private static T? FindVisualChild<T>(DependencyObject parent) where T : DependencyObject
    {
        for (var index = 0; index < VisualTreeHelper.GetChildrenCount(parent); index++)
        {
            var child = VisualTreeHelper.GetChild(parent, index);
            if (child is T match) return match;
            if (FindVisualChild<T>(child) is { } nested) return nested;
        }
        return null;
    }

    private static void Assert(bool condition, string name)
    {
        if (!condition) throw new InvalidOperationException($"FAILED: {name}");
        Console.WriteLine($"PASS {name}");
    }
}
