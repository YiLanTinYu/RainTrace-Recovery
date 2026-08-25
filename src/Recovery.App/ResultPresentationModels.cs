using Recovery.Core;
using System.Collections.ObjectModel;
using System.Collections.Specialized;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Windows.Media.Imaging;

namespace Recovery.App;

public sealed class RangeObservableCollection<T> : ObservableCollection<T>
{
    public void AddRange(IEnumerable<T> items)
    {
        var added = false;
        foreach (var item in items) { Items.Add(item); added = true; }
        if (!added) return;
        OnPropertyChanged(new PropertyChangedEventArgs(nameof(Count)));
        OnPropertyChanged(new PropertyChangedEventArgs("Item[]"));
        OnCollectionChanged(new NotifyCollectionChangedEventArgs(NotifyCollectionChangedAction.Reset));
    }

    public void ReplaceAll(IEnumerable<T> items)
    {
        Items.Clear();
        foreach (var item in items) Items.Add(item);
        OnPropertyChanged(new PropertyChangedEventArgs(nameof(Count)));
        OnPropertyChanged(new PropertyChangedEventArgs("Item[]"));
        OnCollectionChanged(new NotifyCollectionChangedEventArgs(NotifyCollectionChangedAction.Reset));
    }
}

internal sealed class ResultTreeNode
{
    public ResultTreeNode(string name, RecoveryCandidate? candidate = null)
    {
        Name = name;
        Candidate = candidate;
    }

    public string Name { get; }
    public RecoveryCandidate? Candidate { get; }
    public bool IsFile => Candidate is not null;
    public string Details => Candidate is null
        ? string.Empty
        : $"{Candidate.Extension.ToUpperInvariant()} · {Candidate.Size:N0} 字节 · {Candidate.QualityLabel}";
    public ObservableCollection<ResultTreeNode> Children { get; } = [];
}

internal sealed class ThumbnailViewItem : INotifyPropertyChanged
{
    private BitmapSource? _thumbnail;
    private string _status = "等待加载";
    private bool _isLoading;

    public ThumbnailViewItem(RecoveryCandidate candidate) => Candidate = candidate;

    public RecoveryCandidate Candidate { get; }
    public BitmapSource? Thumbnail
    {
        get => _thumbnail;
        set { if (ReferenceEquals(_thumbnail, value)) return; _thumbnail = value; OnPropertyChanged(); }
    }
    public string Status
    {
        get => _status;
        set { if (_status == value) return; _status = value; OnPropertyChanged(); }
    }
    public bool IsLoading
    {
        get => _isLoading;
        set { if (_isLoading == value) return; _isLoading = value; OnPropertyChanged(); }
    }

    public event PropertyChangedEventHandler? PropertyChanged;
    private void OnPropertyChanged([CallerMemberName] string? propertyName = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
}

internal sealed class PartitionCandidateViewItem : INotifyPropertyChanged
{
    private bool _isSelected;

    public PartitionCandidateViewItem(ScanTarget target)
    {
        Target = target;
        _isSelected = target.Confidence is RecoveryConfidence.High or RecoveryConfidence.Medium &&
            !target.Evidence.OverlapsAnotherTarget;
    }

    public ScanTarget Target { get; }
    public bool IsSelected
    {
        get => _isSelected;
        set { if (_isSelected == value) return; _isSelected = value; OnPropertyChanged(); }
    }
    public string Name => Target.DisplayName;
    public string FileSystemLabel => Target.FileSystem switch
    {
        FileSystemKind.Ntfs => "NTFS",
        FileSystemKind.ExFat => "exFAT",
        FileSystemKind.Fat32 => "FAT32",
        FileSystemKind.Fat16 => "FAT16",
        FileSystemKind.Fat12 => "FAT12",
        _ => "未知文件系统"
    };
    public string ConfidenceLabel => Target.Confidence switch
    {
        RecoveryConfidence.High => "高可信",
        RecoveryConfidence.Medium => "中可信",
        RecoveryConfidence.Low => "低可信",
        _ => "待判断"
    };
    public string RangeLabel
    {
        get
        {
            var end = Target.Length == 0 ? Target.Offset : checked(Target.Offset + Target.Length - 1);
            return $"{FormatBytes(Target.Offset)} – {FormatBytes(end)} · 容量 {FormatBytes(Target.Length)}";
        }
    }
    public string StructureLabel
    {
        get
        {
            var checks = new List<string>();
            if (Target.Evidence.GeometryValid) checks.Add("范围有效");
            if (Target.Evidence.BootSectorValid) checks.Add("引导结构有效");
            if (Target.Evidence.BackupStructureValid) checks.Add("备用结构有效");
            if (Target.Evidence.OverlapsAnotherTarget) checks.Add("存在重叠冲突");
            return checks.Count == 0 ? "结构证据不足" : string.Join(" · ", checks);
        }
    }
    public string EvidenceLabel => Target.Evidence.Explanation;

    private static string FormatBytes(ulong bytes)
    {
        string[] units = ["B", "KiB", "MiB", "GiB", "TiB"];
        var value = (double)bytes;
        var unit = 0;
        while (value >= 1024 && unit < units.Length - 1) { value /= 1024; unit++; }
        return $"{value:0.##} {units[unit]}";
    }

    public event PropertyChangedEventHandler? PropertyChanged;
    private void OnPropertyChanged([CallerMemberName] string? propertyName = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
}
