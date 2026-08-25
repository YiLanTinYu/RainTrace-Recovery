using System.IO;
using System.Text;

namespace Recovery.App;

internal static class AppDiagnostics
{
    private static readonly object Sync = new();
    public static string LogPath { get; } = CreateLogPath();

    public static void Write(string message)
    {
        try
        {
            lock (Sync)
                File.AppendAllText(LogPath, $"[{DateTimeOffset.Now:O}] {message}{Environment.NewLine}", new UTF8Encoding(false));
        }
        catch { }
    }

    public static void WriteException(string source, Exception exception) =>
        Write($"UNHANDLED {source}: {exception}");

    private static string CreateLogPath()
    {
        var name = $"raintrace-{DateTime.Now:yyyyMMdd-HHmmss}-{Environment.ProcessId}.log";
        try
        {
            var root = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "RainTrace", "Logs");
            Directory.CreateDirectory(root);
            var path = Path.Combine(root, name);
            File.WriteAllText(path, $"RainTrace diagnostics · {Environment.OSVersion} · {Environment.Version}{Environment.NewLine}", new UTF8Encoding(false));
            return path;
        }
        catch { return Path.Combine(Path.GetTempPath(), name); }
    }
}
