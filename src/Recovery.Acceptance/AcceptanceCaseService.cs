using System.Buffers.Binary;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Recovery.Acceptance;

public enum AcceptanceItemStatus
{
    CompleteOriginalPath,
    CompleteOriginalName,
    CompleteRenamed,
    Damaged,
    Missing
}

public sealed record AcceptanceExpectedFile(
    string RelativePath,
    string Category,
    long Length,
    string Sha256,
    DateTime ModifiedUtc);

public sealed record AcceptanceManifest(
    int Version,
    string DatasetId,
    DateTime CreatedUtc,
    string ContentFolder,
    IReadOnlyList<AcceptanceExpectedFile> Files);

public sealed record AcceptanceItemResult(
    string ExpectedPath,
    string Category,
    long ExpectedLength,
    string ExpectedSha256,
    AcceptanceItemStatus Status,
    string StatusLabel,
    string? RecoveredPath,
    long? RecoveredLength,
    string? RecoveredSha256,
    string Message);

public sealed record AcceptanceSummary(
    int Expected,
    int ContentRecovered,
    int OriginalPathRecovered,
    int OriginalNameRecovered,
    int RenamedRecovered,
    int Damaged,
    int Missing,
    int Extra,
    double ContentRecoveryRate,
    double OriginalNameRate,
    double OriginalPathRate);

public sealed record AcceptanceReport(
    int Version,
    string DatasetId,
    DateTime VerifiedUtc,
    string RecoveredDirectory,
    AcceptanceSummary Summary,
    IReadOnlyList<AcceptanceItemResult> Items,
    IReadOnlyList<string> ExtraFiles);

public sealed record AcceptanceGenerationResult(
    AcceptanceManifest Manifest,
    string ContentDirectory,
    string ManifestPath,
    string InstructionsPath);

public sealed record AcceptanceVerificationResult(
    AcceptanceReport Report,
    string JsonPath,
    string CsvPath,
    string MarkdownPath);

public static class AcceptanceCaseService
{
    public const string ManifestFileName = "raintrace-acceptance-manifest.json";
    public const string ContentFolderName = "待复制文件";
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };
    private static readonly DateTime FixtureModifiedUtc = new(2025, 1, 15, 8, 30, 0, DateTimeKind.Utc);

    public static async Task<AcceptanceGenerationResult> GenerateAsync(string targetDirectory,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(targetDirectory)) throw new ArgumentException("测试文件集目录不能为空。", nameof(targetDirectory));
        var root = Path.GetFullPath(targetDirectory);
        if (File.Exists(root)) throw new IOException("目标路径是文件，不是目录。");
        if (Directory.Exists(root) && Directory.EnumerateFileSystemEntries(root).Any())
            throw new IOException("测试文件集目录必须为空或不存在，避免覆盖现有文件。");

        Directory.CreateDirectory(root);
        var contentDirectory = Path.Combine(root, ContentFolderName);
        Directory.CreateDirectory(contentDirectory);

        var fixtures = new (string RelativePath, string Category, Func<byte[]> Build)[]
        {
            (Path.Combine("图片", "雨痕测试图片.png"), "图片", BuildPng),
            (Path.Combine("图片", "动画样本.gif"), "图片", BuildGif),
            (Path.Combine("图片", "像素图样本.bmp"), "图片", BuildBmp),
            (Path.Combine("文档", "中文说明.txt"), "文档", () => Encoding.UTF8.GetBytes("雨痕恢复验收文件\r\n用于验证中文文件名、原路径、文件大小和 SHA-256。\r\n")),
            (Path.Combine("文档", "设备清单.csv"), "文档", () => Encoding.UTF8.GetBytes("name,type,readonly\r\n雨痕,U盘,true\r\nRainTrace,SD卡,true\r\n")),
            (Path.Combine("文档", "恢复参数.json"), "文档", () => Encoding.UTF8.GetBytes("{\"name\":\"雨痕恢复验收\",\"readonly\":true,\"filesystems\":[\"NTFS\",\"exFAT\",\"FAT32\"]}")),
            (Path.Combine("文档", "简要报告.pdf"), "文档", BuildPdf),
            (Path.Combine("文档", "带 空格 的报告.docx"), "文档", BuildDocx),
            (Path.Combine("表格", "验收统计.xlsx"), "文档", BuildXlsx),
            (Path.Combine("压缩包", "资料归档.zip"), "压缩包", BuildZip),
            (Path.Combine("音频", "提示音.wav"), "音频", BuildWav),
            (Path.Combine("深层目录", "一级", "二级", "中文长文件名-用于验证目录结构保留.txt"), "文档", () => Encoding.UTF8.GetBytes("深层目录与长文件名验收。\r\n")),
            (Path.Combine("大文件", "连续数据-4MB.dat"), "其他", () => BuildDeterministicBytes(4 * 1024 * 1024))
        };

        var expected = new List<AcceptanceExpectedFile>(fixtures.Length);
        foreach (var fixture in fixtures)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var path = Path.Combine(contentDirectory, fixture.RelativePath);
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            await File.WriteAllBytesAsync(path, fixture.Build(), cancellationToken);
            File.SetLastWriteTimeUtc(path, FixtureModifiedUtc);
            var info = new FileInfo(path);
            expected.Add(new AcceptanceExpectedFile(
                NormalizeRelativePath(fixture.RelativePath), fixture.Category, info.Length,
                await ComputeSha256Async(path, cancellationToken), FixtureModifiedUtc));
        }

        var manifest = new AcceptanceManifest(1, Guid.NewGuid().ToString("N"), DateTime.UtcNow,
            ContentFolderName, expected.OrderBy(file => file.RelativePath, StringComparer.OrdinalIgnoreCase).ToArray());
        var manifestPath = Path.Combine(root, ManifestFileName);
        await WriteTextAtomicAsync(manifestPath, JsonSerializer.Serialize(manifest, JsonOptions), cancellationToken);
        var instructionsPath = Path.Combine(root, "下一步操作.txt");
        var instructions = "1. 将“待复制文件”目录内的全部内容复制到待测试介质。\r\n" +
                           "2. 正常弹出并重新连接介质，确认文件可以打开。\r\n" +
                           "3. 删除测试文件，或按计划执行快速格式化。\r\n" +
                           "4. 使用雨痕扫描并把结果恢复到另一块物理磁盘。\r\n" +
                           "5. 使用本工具的 verify 命令，将恢复目录与本清单进行比较。\r\n";
        await File.WriteAllTextAsync(instructionsPath, instructions, new UTF8Encoding(true), cancellationToken);
        return new AcceptanceGenerationResult(manifest, contentDirectory, manifestPath, instructionsPath);
    }

    public static async Task<AcceptanceVerificationResult> VerifyAsync(string manifestPath, string recoveredDirectory,
        string? reportDirectory = null, CancellationToken cancellationToken = default)
    {
        var fullManifestPath = Path.GetFullPath(manifestPath);
        if (!File.Exists(fullManifestPath)) throw new FileNotFoundException("找不到验收清单。", fullManifestPath);
        var recoveredRoot = Path.GetFullPath(recoveredDirectory);
        if (!Directory.Exists(recoveredRoot)) throw new DirectoryNotFoundException($"找不到恢复输出目录：{recoveredRoot}");

        var manifest = JsonSerializer.Deserialize<AcceptanceManifest>(
            await File.ReadAllTextAsync(fullManifestPath, Encoding.UTF8, cancellationToken), JsonOptions)
            ?? throw new InvalidDataException("验收清单为空或已损坏。");
        if (manifest.Version != 1) throw new InvalidDataException($"不支持的验收清单版本：{manifest.Version}。");
        if (manifest.Files.Count == 0) throw new InvalidDataException("验收清单没有文件记录。");
        if (manifest.Files.Any(file => !IsSafeRelativePath(file.RelativePath)))
            throw new InvalidDataException("验收清单包含不安全的相对路径。");

        var recovered = new List<RecoveredFile>();
        foreach (var path in Directory.EnumerateFiles(recoveredRoot, "*", SearchOption.AllDirectories))
        {
            cancellationToken.ThrowIfCancellationRequested();
            var info = new FileInfo(path);
            recovered.Add(new RecoveredFile(path, NormalizeRelativePath(Path.GetRelativePath(recoveredRoot, path)),
                info.Name, info.Length, await ComputeSha256Async(path, cancellationToken)));
        }

        var usedPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var items = new List<AcceptanceItemResult>(manifest.Files.Count);
        foreach (var expected in manifest.Files)
        {
            var expectedPath = NormalizeRelativePath(expected.RelativePath);
            var expectedName = Path.GetFileName(expectedPath);
            var sameHash = recovered.Where(file => !usedPaths.Contains(file.FullPath) &&
                string.Equals(file.Sha256, expected.Sha256, StringComparison.OrdinalIgnoreCase)).ToArray();
            var match = sameHash.FirstOrDefault(file => PathMatches(file.RelativePath, expectedPath))
                ?? sameHash.FirstOrDefault(file => string.Equals(file.Name, expectedName, StringComparison.OrdinalIgnoreCase))
                ?? sameHash.FirstOrDefault();

            if (match is not null)
            {
                usedPaths.Add(match.FullPath);
                var status = PathMatches(match.RelativePath, expectedPath)
                    ? AcceptanceItemStatus.CompleteOriginalPath
                    : string.Equals(match.Name, expectedName, StringComparison.OrdinalIgnoreCase)
                        ? AcceptanceItemStatus.CompleteOriginalName
                        : AcceptanceItemStatus.CompleteRenamed;
                items.Add(CreateItem(expected, status, match, status switch
                {
                    AcceptanceItemStatus.CompleteOriginalPath => "内容完整，原文件名和目录结构已保留。",
                    AcceptanceItemStatus.CompleteOriginalName => "内容完整并保留原文件名，但目录结构未完整保留。",
                    _ => "内容完整，但恢复结果使用了不同文件名。"
                }));
                continue;
            }

            var damaged = recovered.FirstOrDefault(file => !usedPaths.Contains(file.FullPath) &&
                string.Equals(file.Name, expectedName, StringComparison.OrdinalIgnoreCase));
            if (damaged is not null)
            {
                usedPaths.Add(damaged.FullPath);
                items.Add(CreateItem(expected, AcceptanceItemStatus.Damaged, damaged,
                    "找到同名文件，但大小或 SHA-256 与原文件不一致。"));
            }
            else
            {
                items.Add(CreateItem(expected, AcceptanceItemStatus.Missing, null, "没有找到内容相同或同名的恢复文件。"));
            }
        }

        var extras = recovered.Where(file => !usedPaths.Contains(file.FullPath))
            .Select(file => file.RelativePath).OrderBy(path => path, StringComparer.OrdinalIgnoreCase).ToArray();
        var contentRecovered = items.Count(item => item.Status is AcceptanceItemStatus.CompleteOriginalPath or
            AcceptanceItemStatus.CompleteOriginalName or AcceptanceItemStatus.CompleteRenamed);
        var originalPathRecovered = items.Count(item => item.Status == AcceptanceItemStatus.CompleteOriginalPath);
        var originalNameRecovered = items.Count(item => item.Status is AcceptanceItemStatus.CompleteOriginalPath or AcceptanceItemStatus.CompleteOriginalName);
        var summary = new AcceptanceSummary(manifest.Files.Count, contentRecovered, originalPathRecovered,
            originalNameRecovered, items.Count(item => item.Status == AcceptanceItemStatus.CompleteRenamed),
            items.Count(item => item.Status == AcceptanceItemStatus.Damaged),
            items.Count(item => item.Status == AcceptanceItemStatus.Missing), extras.Length,
            Percentage(contentRecovered, manifest.Files.Count), Percentage(originalNameRecovered, manifest.Files.Count),
            Percentage(originalPathRecovered, manifest.Files.Count));
        var report = new AcceptanceReport(1, manifest.DatasetId, DateTime.UtcNow, recoveredRoot, summary, items, extras);

        var reportRoot = string.IsNullOrWhiteSpace(reportDirectory)
            ? Path.Combine(Directory.GetParent(recoveredRoot)?.FullName ?? recoveredRoot, $"雨痕验收报告-{DateTime.Now:yyyyMMdd-HHmmss}")
            : Path.GetFullPath(reportDirectory);
        Directory.CreateDirectory(reportRoot);
        var jsonPath = Path.Combine(reportRoot, "雨痕恢复验收报告.json");
        var csvPath = Path.Combine(reportRoot, "雨痕恢复验收明细.csv");
        var markdownPath = Path.Combine(reportRoot, "雨痕恢复验收报告.md");
        await WriteTextAtomicAsync(jsonPath, JsonSerializer.Serialize(report, JsonOptions), cancellationToken);
        await WriteTextAtomicAsync(csvPath, BuildCsv(report), cancellationToken, new UTF8Encoding(true));
        await WriteTextAtomicAsync(markdownPath, BuildMarkdown(report), cancellationToken, new UTF8Encoding(true));
        return new AcceptanceVerificationResult(report, jsonPath, csvPath, markdownPath);
    }

    private static AcceptanceItemResult CreateItem(AcceptanceExpectedFile expected, AcceptanceItemStatus status,
        RecoveredFile? recovered, string message) => new(expected.RelativePath, expected.Category, expected.Length,
        expected.Sha256, status, StatusLabel(status), recovered?.RelativePath, recovered?.Length, recovered?.Sha256, message);

    private static string StatusLabel(AcceptanceItemStatus status) => status switch
    {
        AcceptanceItemStatus.CompleteOriginalPath => "完整（原路径）",
        AcceptanceItemStatus.CompleteOriginalName => "完整（原名）",
        AcceptanceItemStatus.CompleteRenamed => "完整（已改名）",
        AcceptanceItemStatus.Damaged => "损坏",
        _ => "缺失"
    };

    private static double Percentage(int value, int total) => total == 0 ? 0 : Math.Round(value * 100d / total, 2);

    private static bool PathMatches(string recoveredPath, string expectedPath)
    {
        var recovered = NormalizeRelativePath(recoveredPath);
        var expected = NormalizeRelativePath(expectedPath);
        return string.Equals(recovered, expected, StringComparison.OrdinalIgnoreCase) ||
               recovered.EndsWith('/' + expected, StringComparison.OrdinalIgnoreCase);
    }

    private static string NormalizeRelativePath(string path) => path.Replace('\\', '/').TrimStart('/');

    private static bool IsSafeRelativePath(string path)
    {
        if (string.IsNullOrWhiteSpace(path) || Path.IsPathRooted(path)) return false;
        var normalized = NormalizeRelativePath(path);
        return normalized.Split('/').All(segment => segment is not "" and not "." and not "..");
    }

    private static async Task<string> ComputeSha256Async(string path, CancellationToken cancellationToken)
    {
        await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read,
            1024 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan);
        return Convert.ToHexString(await SHA256.HashDataAsync(stream, cancellationToken)).ToLowerInvariant();
    }

    private static async Task WriteTextAtomicAsync(string path, string content, CancellationToken cancellationToken,
        Encoding? encoding = null)
    {
        encoding ??= new UTF8Encoding(false);
        var fullPath = Path.GetFullPath(path);
        var directory = Path.GetDirectoryName(fullPath)!;
        Directory.CreateDirectory(directory);
        var temporary = Path.Combine(directory, $".{Path.GetFileName(fullPath)}.{Guid.NewGuid():N}.tmp");
        try
        {
            await File.WriteAllTextAsync(temporary, content, encoding, cancellationToken);
            File.Move(temporary, fullPath, true);
        }
        finally
        {
            if (File.Exists(temporary)) File.Delete(temporary);
        }
    }

    private static string BuildCsv(AcceptanceReport report)
    {
        var lines = new List<string>
        {
            "预期路径,类别,预期字节数,状态,恢复路径,恢复字节数,预期SHA-256,恢复SHA-256,说明"
        };
        lines.AddRange(report.Items.Select(item => string.Join(',', Csv(item.ExpectedPath), Csv(item.Category),
            item.ExpectedLength, Csv(item.StatusLabel), Csv(item.RecoveredPath ?? string.Empty),
            item.RecoveredLength?.ToString() ?? string.Empty, Csv(item.ExpectedSha256), Csv(item.RecoveredSha256 ?? string.Empty), Csv(item.Message))));
        return string.Join(Environment.NewLine, lines) + Environment.NewLine;
    }

    private static string BuildMarkdown(AcceptanceReport report)
    {
        var summary = report.Summary;
        var builder = new StringBuilder();
        builder.AppendLine("# 雨痕恢复验收报告").AppendLine();
        builder.AppendLine($"验收时间：{report.VerifiedUtc.ToLocalTime():yyyy-MM-dd HH:mm:ss}");
        builder.AppendLine($"恢复目录：`{report.RecoveredDirectory}`");
        builder.AppendLine($"数据集编号：`{report.DatasetId}`").AppendLine();
        builder.AppendLine("## 汇总").AppendLine();
        builder.AppendLine("| 指标 | 数量 / 比例 |").AppendLine("|---|---:|");
        builder.AppendLine($"| 预期文件 | {summary.Expected:N0} |");
        builder.AppendLine($"| 内容完整恢复 | {summary.ContentRecovered:N0} / {summary.ContentRecoveryRate:0.00}% |");
        builder.AppendLine($"| 保留原文件名 | {summary.OriginalNameRecovered:N0} / {summary.OriginalNameRate:0.00}% |");
        builder.AppendLine($"| 保留原路径 | {summary.OriginalPathRecovered:N0} / {summary.OriginalPathRate:0.00}% |");
        builder.AppendLine($"| 内容完整但改名 | {summary.RenamedRecovered:N0} |");
        builder.AppendLine($"| 损坏 | {summary.Damaged:N0} |");
        builder.AppendLine($"| 缺失 | {summary.Missing:N0} |");
        builder.AppendLine($"| 额外文件 | {summary.Extra:N0} |").AppendLine();
        builder.AppendLine("## 文件明细").AppendLine();
        builder.AppendLine("| 预期文件 | 类别 | 状态 | 恢复文件 | 说明 |").AppendLine("|---|---|---|---|---|");
        foreach (var item in report.Items)
            builder.AppendLine($"| {Md(item.ExpectedPath)} | {Md(item.Category)} | {Md(item.StatusLabel)} | {Md(item.RecoveredPath ?? "-")} | {Md(item.Message)} |");
        if (report.ExtraFiles.Count > 0)
        {
            builder.AppendLine().AppendLine("## 额外文件").AppendLine();
            foreach (var path in report.ExtraFiles) builder.AppendLine($"- `{path.Replace("`", "'", StringComparison.Ordinal)}`");
        }
        return builder.ToString();
    }

    private static string Csv(string value) => $"\"{value.Replace("\"", "\"\"", StringComparison.Ordinal)}\"";
    private static string Md(string value) => value.Replace("|", "\\|", StringComparison.Ordinal).Replace("\r", " ", StringComparison.Ordinal).Replace("\n", " ", StringComparison.Ordinal);

    private static byte[] BuildPng() => Convert.FromBase64String(
        "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAusB9Y9Zl9sAAAAASUVORK5CYII=");

    private static byte[] BuildGif()
    {
        var data = new List<byte>(Encoding.ASCII.GetBytes("GIF89a"));
        data.AddRange([1, 0, 1, 0, 0, 0, 0, 0x2C, 0, 0, 0, 0, 1, 0, 1, 0, 0, 2, 2, 0x44, 0x01, 0, 0x3B]);
        return [.. data];
    }

    private static byte[] BuildBmp()
    {
        var data = new byte[70];
        data[0] = (byte)'B'; data[1] = (byte)'M';
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(2, 4), (uint)data.Length);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(10, 4), 54);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(14, 4), 40);
        BinaryPrimitives.WriteInt32LittleEndian(data.AsSpan(18, 4), 2);
        BinaryPrimitives.WriteInt32LittleEndian(data.AsSpan(22, 4), 2);
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(26, 2), 1);
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(28, 2), 24);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(34, 4), 16);
        data[54] = 0x20; data[55] = 0x80; data[56] = 0xE0;
        data[57] = 0xE0; data[58] = 0x80; data[59] = 0x20;
        data[62] = 0x40; data[63] = 0xC0; data[64] = 0x80;
        data[65] = 0x80; data[66] = 0x40; data[67] = 0xC0;
        return data;
    }

    private static byte[] BuildPdf()
    {
        var objects = new[]
        {
            "<< /Type /Catalog /Pages 2 0 R >>",
            "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>",
            "<< /Length 54 >>\nstream\nBT /F1 14 Tf 72 720 Td (RainTrace Acceptance PDF) Tj ET\nendstream",
            "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"
        };
        using var stream = new MemoryStream();
        using var writer = new StreamWriter(stream, Encoding.ASCII, 1024, true) { NewLine = "\n" };
        writer.WriteLine("%PDF-1.4"); writer.Flush();
        var offsets = new List<long> { 0 };
        for (var index = 0; index < objects.Length; index++)
        {
            offsets.Add(stream.Position);
            writer.WriteLine($"{index + 1} 0 obj"); writer.WriteLine(objects[index]); writer.WriteLine("endobj"); writer.Flush();
        }
        var xref = stream.Position;
        writer.WriteLine("xref"); writer.WriteLine($"0 {objects.Length + 1}"); writer.WriteLine("0000000000 65535 f ");
        foreach (var offset in offsets.Skip(1)) writer.WriteLine($"{offset:0000000000} 00000 n ");
        writer.WriteLine($"trailer\n<< /Size {objects.Length + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF"); writer.Flush();
        return stream.ToArray();
    }

    private static byte[] BuildDocx() => BuildZipArchive(new Dictionary<string, string>
    {
        ["[Content_Types].xml"] = "<?xml version=\"1.0\"?><Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\"><Default Extension=\"rels\" ContentType=\"application/vnd.openxmlformats-package.relationships+xml\"/><Default Extension=\"xml\" ContentType=\"application/xml\"/><Override PartName=\"/word/document.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml\"/></Types>",
        ["_rels/.rels"] = "<?xml version=\"1.0\"?><Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\"><Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument\" Target=\"word/document.xml\"/></Relationships>",
        ["word/document.xml"] = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><w:document xmlns:w=\"http://schemas.openxmlformats.org/wordprocessingml/2006/main\"><w:body><w:p><w:r><w:t>雨痕恢复验收 DOCX</w:t></w:r></w:p><w:sectPr/></w:body></w:document>"
    });

    private static byte[] BuildXlsx() => BuildZipArchive(new Dictionary<string, string>
    {
        ["[Content_Types].xml"] = "<?xml version=\"1.0\"?><Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\"><Default Extension=\"rels\" ContentType=\"application/vnd.openxmlformats-package.relationships+xml\"/><Default Extension=\"xml\" ContentType=\"application/xml\"/><Override PartName=\"/xl/workbook.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml\"/><Override PartName=\"/xl/worksheets/sheet1.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml\"/></Types>",
        ["_rels/.rels"] = "<?xml version=\"1.0\"?><Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\"><Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument\" Target=\"xl/workbook.xml\"/></Relationships>",
        ["xl/workbook.xml"] = "<?xml version=\"1.0\"?><workbook xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\" xmlns:r=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships\"><sheets><sheet name=\"验收\" sheetId=\"1\" r:id=\"rId1\"/></sheets></workbook>",
        ["xl/_rels/workbook.xml.rels"] = "<?xml version=\"1.0\"?><Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\"><Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet\" Target=\"worksheets/sheet1.xml\"/></Relationships>",
        ["xl/worksheets/sheet1.xml"] = "<?xml version=\"1.0\"?><worksheet xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\"><sheetData><row r=\"1\"><c r=\"A1\" t=\"inlineStr\"><is><t>雨痕恢复验收</t></is></c></row></sheetData></worksheet>"
    });

    private static byte[] BuildZip() => BuildZipArchive(new Dictionary<string, string>
    {
        ["说明.txt"] = "雨痕恢复验收 ZIP 文件。",
        ["资料/数据.csv"] = "id,name\r\n1,RainTrace\r\n"
    });

    private static byte[] BuildZipArchive(IReadOnlyDictionary<string, string> entries)
    {
        using var stream = new MemoryStream();
        using (var archive = new ZipArchive(stream, ZipArchiveMode.Create, true, Encoding.UTF8))
        {
            foreach (var item in entries)
            {
                var entry = archive.CreateEntry(item.Key, CompressionLevel.Optimal);
                entry.LastWriteTime = new DateTimeOffset(FixtureModifiedUtc);
                using var writer = new StreamWriter(entry.Open(), new UTF8Encoding(false));
                writer.Write(item.Value);
            }
        }
        return stream.ToArray();
    }

    private static byte[] BuildWav()
    {
        const int sampleRate = 8000;
        const int sampleCount = 2000;
        var data = new byte[44 + sampleCount * 2];
        "RIFF"u8.CopyTo(data); BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(4, 4), (uint)data.Length - 8);
        "WAVEfmt "u8.CopyTo(data.AsSpan(8)); BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(16, 4), 16);
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(20, 2), 1); BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(22, 2), 1);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(24, 4), sampleRate); BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(28, 4), sampleRate * 2);
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(32, 2), 2); BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(34, 2), 16);
        "data"u8.CopyTo(data.AsSpan(36)); BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(40, 4), sampleCount * 2);
        for (var index = 0; index < sampleCount; index++)
        {
            var sample = (short)(Math.Sin(2 * Math.PI * 440 * index / sampleRate) * short.MaxValue * 0.2);
            BinaryPrimitives.WriteInt16LittleEndian(data.AsSpan(44 + index * 2, 2), sample);
        }
        return data;
    }

    private static byte[] BuildDeterministicBytes(int length)
    {
        var data = new byte[length];
        uint state = 0x5241494E;
        for (var index = 0; index < data.Length; index++)
        {
            state = state * 1664525 + 1013904223;
            data[index] = (byte)(state >> 24);
        }
        return data;
    }

    private sealed record RecoveredFile(string FullPath, string RelativePath, string Name, long Length, string Sha256);
}
