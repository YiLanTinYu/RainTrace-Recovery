using System.Text;
using System.Text.Json;

namespace Recovery.Core;

public enum RecoveryItemStatus { Success, Partial, Damaged, Failed, Cancelled, Skipped }

public sealed record RecoveryItemReport(
    string OriginalPath,
    RecoveryItemStatus Status,
    string? OutputPath,
    ulong BytesWritten,
    string? Sha256,
    string Message,
    DateTime CompletedUtc);

public sealed record RecoveryBatchReport(
    int Version,
    DateTime StartedUtc,
    DateTime CompletedUtc,
    string SourceId,
    string Destination,
    IReadOnlyList<RecoveryItemReport> Items)
{
    public int Successful => Items.Count(item => item.Status == RecoveryItemStatus.Success);
    public int PartialOrDamaged => Items.Count(item => item.Status is RecoveryItemStatus.Partial or RecoveryItemStatus.Damaged);
    public int Failed => Items.Count(item => item.Status == RecoveryItemStatus.Failed);
    public int CancelledOrSkipped => Items.Count(item => item.Status is RecoveryItemStatus.Cancelled or RecoveryItemStatus.Skipped);
}

public sealed record RecoveryQueueExecutionResult(
    IReadOnlyList<RecoveryItemReport> Items,
    Exception? SystemicFailure);

public static class RecoveryBatchExecutor
{
    public static async Task<RecoveryQueueExecutionResult> ExecuteAsync<T>(
        IReadOnlyList<T> items,
        Func<T, int, int, CancellationToken, Task<RecoveryItemReport>> recoverOne,
        Func<T, string> originalPath,
        Func<Exception, bool> isSystemicFailure,
        CancellationToken cancellationToken = default,
        Action<T, Exception>? onItemFailure = null,
        Action? onCancelled = null,
        Action<Exception>? onSystemicFailure = null)
    {
        ArgumentNullException.ThrowIfNull(items);
        ArgumentNullException.ThrowIfNull(recoverOne);
        ArgumentNullException.ThrowIfNull(originalPath);
        ArgumentNullException.ThrowIfNull(isSystemicFailure);
        var reports = new List<RecoveryItemReport>(items.Count);
        Exception? systemicFailure = null;

        for (var index = 0; index < items.Count; index++)
        {
            var item = items[index];
            try
            {
                cancellationToken.ThrowIfCancellationRequested();
                reports.Add(await recoverOne(item, index, items.Count, cancellationToken));
            }
            catch (OperationCanceledException)
            {
                reports.Add(new(originalPath(item), RecoveryItemStatus.Cancelled, null, 0, null,
                    "用户取消了恢复。", DateTime.UtcNow));
                AddSkippedReports(items, index + 1, reports, originalPath, "队列已取消，未开始恢复。");
                onCancelled?.Invoke();
                break;
            }
            catch (Exception exception)
            {
                reports.Add(new(originalPath(item), RecoveryItemStatus.Failed, null, 0, null,
                    exception.Message, DateTime.UtcNow));
                onItemFailure?.Invoke(item, exception);
                if (!isSystemicFailure(exception)) continue;
                systemicFailure = exception;
                AddSkippedReports(items, index + 1, reports, originalPath,
                    "恢复目标盘不可用或空间不足，队列已暂停。");
                onSystemicFailure?.Invoke(exception);
                break;
            }
        }

        return new(reports, systemicFailure);
    }

    private static void AddSkippedReports<T>(IReadOnlyList<T> items, int start,
        ICollection<RecoveryItemReport> reports, Func<T, string> originalPath, string reason)
    {
        for (var index = start; index < items.Count; index++)
            reports.Add(new(originalPath(items[index]), RecoveryItemStatus.Skipped, null, 0, null,
                reason, DateTime.UtcNow));
    }
}

public static class RecoveryReportWriter
{
    public static async Task<(string JsonPath, string CsvPath)> SaveAsync(
        RecoveryBatchReport report,
        string reportDirectory,
        CancellationToken cancellationToken = default)
    {
        var root = Path.GetFullPath(reportDirectory);
        Directory.CreateDirectory(root);
        var stem = $"雨痕恢复报告-{report.StartedUtc.ToLocalTime():yyyyMMdd-HHmmss}";
        var jsonPath = AllocateUniquePath(Path.Combine(root, stem + ".json"));
        var csvPath = Path.ChangeExtension(jsonPath, ".csv");
        var json = JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true });
        await File.WriteAllTextAsync(jsonPath, json, new UTF8Encoding(false), cancellationToken);

        var lines = new List<string> { "原路径,状态,输出路径,写出字节,SHA-256,说明,完成时间UTC" };
        lines.AddRange(report.Items.Select(item => string.Join(',',
            Csv(item.OriginalPath), Csv(StatusLabel(item.Status)), Csv(item.OutputPath ?? string.Empty),
            item.BytesWritten.ToString(System.Globalization.CultureInfo.InvariantCulture), Csv(item.Sha256 ?? string.Empty),
            Csv(item.Message), Csv(item.CompletedUtc.ToString("O")))));
        await File.WriteAllLinesAsync(csvPath, lines, new UTF8Encoding(true), cancellationToken);
        return (jsonPath, csvPath);
    }

    public static string StatusLabel(RecoveryItemStatus status) => status switch
    {
        RecoveryItemStatus.Success => "成功",
        RecoveryItemStatus.Partial => "部分写出",
        RecoveryItemStatus.Damaged => "结构损坏",
        RecoveryItemStatus.Failed => "失败",
        RecoveryItemStatus.Cancelled => "已取消",
        _ => "已跳过"
    };

    private static string Csv(string value) => $"\"{value.Replace("\"", "\"\"", StringComparison.Ordinal)}\"";

    private static string AllocateUniquePath(string path)
    {
        if (!File.Exists(path)) return path;
        var directory = Path.GetDirectoryName(path) ?? string.Empty;
        var stem = Path.GetFileNameWithoutExtension(path);
        var extension = Path.GetExtension(path);
        for (var index = 1; index < 10000; index++)
        {
            var candidate = Path.Combine(directory, $"{stem}-{index}{extension}");
            if (!File.Exists(candidate)) return candidate;
        }
        throw new IOException("无法分配唯一的恢复报告文件名。");
    }
}
