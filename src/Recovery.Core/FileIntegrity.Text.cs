using System.Text;
using System.Text.Json;
using System.Xml;

namespace Recovery.Core;

public static partial class FileIntegrityValidator
{
    private const int TextSampleSize = 256 * 1024;
    private const long MaximumInMemoryStructuredText = 64L * 1024 * 1024;
    private static readonly Encoding Gb18030 = CreateGb18030();

    private static FileIntegrityResult ValidateTextSamples(string extension, ulong size, ReadOnlySpan<byte> head)
    {
        if (size == 0 || head.Length == 0) return Damaged("恢复前预检失败：文本文件为空。");
        if (!TryDecodeText(head, allowTruncatedTail: (ulong)head.Length < size, out var decoded, out var error))
            return Damaged($"恢复前预检失败：{error}");
        if ((ulong)head.Length >= size && extension is "json" or "xml" or "csv")
        {
            var structured = ValidateStructuredText(extension, decoded.Text);
            if (structured.State == FileIntegrityState.Damaged) return structured;
        }
        return Valid($"恢复前预检通过：{decoded.EncodingName}文本可读，可读字符比例 {decoded.ReadableRatio:P0}；文本格式无法保证内容未被截断。");
    }

    private static async Task<FileIntegrityResult> ValidateTextFileAsync(string path, string extension, CancellationToken token)
    {
        var info = new FileInfo(path);
        if (info.Length == 0) return Damaged("文本文件为空。");
        var sampleLength = checked((int)Math.Min(TextSampleSize, info.Length));
        var sample = new byte[sampleLength];
        await using (var stream = Open(path)) await stream.ReadExactlyAsync(sample, token);
        if (!TryDecodeText(sample, allowTruncatedTail: sampleLength < info.Length, out var decoded, out var error)) return Damaged(error);

        if (extension == "xml") return await ValidateXmlFileAsync(path, decoded.EncodingName, token);
        if (extension is "json" or "csv")
        {
            if (info.Length > MaximumInMemoryStructuredText)
                return Valid($"{decoded.EncodingName}文本可读，可读字符比例 {decoded.ReadableRatio:P0}；文件超过64 MiB，已跳过完整{extension.ToUpperInvariant()}语法解析。");
            var bytes = await File.ReadAllBytesAsync(path, token);
            if (!TryDecodeText(bytes, allowTruncatedTail: false, out var complete, out error)) return Damaged(error);
            return ValidateStructuredText(extension, complete.Text);
        }
        return Valid($"{decoded.EncodingName}文本可读，可读字符比例 {decoded.ReadableRatio:P0}；纯文本没有可靠结束标记，无法判断语义内容是否被截断。");
    }

    private static FileIntegrityResult ValidateStructuredText(string extension, string text)
    {
        try
        {
            if (extension == "json")
            {
                using var document = JsonDocument.Parse(text, new JsonDocumentOptions { AllowTrailingCommas = false, CommentHandling = JsonCommentHandling.Disallow });
                return Valid("JSON编码可读且完整语法解析通过。");
            }
            if (extension == "xml")
            {
                using var input = new StringReader(text);
                using var reader = XmlReader.Create(input, SecureXmlSettings(async: false));
                while (reader.Read()) { }
                return Valid("XML编码可读且完整语法解析通过。");
            }
            if (extension == "csv") return ValidateCsv(text);
        }
        catch (JsonException ex) { return Damaged($"JSON语法损坏：第 {ex.LineNumber + 1} 行附近无法解析。"); }
        catch (XmlException ex) { return Damaged($"XML语法损坏：第 {ex.LineNumber} 行、第 {ex.LinePosition} 列附近无法解析。"); }
        return Valid("文本编码和可读性检查通过。");
    }

    private static async Task<FileIntegrityResult> ValidateXmlFileAsync(string path, string encodingName, CancellationToken token)
    {
        try
        {
            await using var stream = Open(path);
            using var reader = XmlReader.Create(stream, SecureXmlSettings(async: true));
            while (await reader.ReadAsync()) token.ThrowIfCancellationRequested();
            return Valid($"XML为{encodingName}兼容文本，完整流式语法解析通过。");
        }
        catch (XmlException ex) { return Damaged($"XML语法损坏：第 {ex.LineNumber} 行、第 {ex.LinePosition} 列附近无法解析。"); }
    }

    private static XmlReaderSettings SecureXmlSettings(bool async) => new()
    {
        Async = async,
        DtdProcessing = DtdProcessing.Prohibit,
        XmlResolver = null,
        MaxCharactersFromEntities = 0,
        IgnoreComments = false,
        IgnoreWhitespace = false
    };

    private static FileIntegrityResult ValidateCsv(string text)
    {
        var rows = new List<int>(); var columns = 1; var inQuotes = false; var atFieldStart = true;
        for (var index = 0; index < text.Length; index++)
        {
            var current = text[index];
            if (current == '"')
            {
                if (inQuotes && index + 1 < text.Length && text[index + 1] == '"') { index++; atFieldStart = false; continue; }
                if (!inQuotes && !atFieldStart) return Damaged("CSV结构损坏：字段中间出现未转义引号。");
                inQuotes = !inQuotes; atFieldStart = false; continue;
            }
            if (!inQuotes && current == ',') { columns++; atFieldStart = true; continue; }
            if (!inQuotes && current is '\r' or '\n')
            {
                if (current == '\r' && index + 1 < text.Length && text[index + 1] == '\n') index++;
                if (rows.Count < 1000 && (columns > 1 || !atFieldStart)) rows.Add(columns);
                columns = 1; atFieldStart = true; continue;
            }
            atFieldStart = false;
        }
        if (inQuotes) return Damaged("CSV结构损坏：引号字段没有闭合。");
        if (columns > 1 || !atFieldStart) rows.Add(columns);
        if (rows.Count == 0) return Damaged("CSV没有可读取的数据行。");
        var expected = rows.GroupBy(value => value).OrderByDescending(group => group.Count()).First().Key;
        var inconsistent = rows.Count(value => value != expected);
        return inconsistent == 0 ? Valid($"CSV编码可读，引号闭合，前 {rows.Count:N0} 行均为 {expected:N0} 列。")
            : Damaged($"CSV列结构不一致：{inconsistent:N0}/{rows.Count:N0} 行与主要的 {expected:N0} 列结构不同。");
    }

    private static bool TryDecodeText(ReadOnlySpan<byte> bytes, bool allowTruncatedTail, out DecodedText decoded, out string error)
    {
        decoded = default; error = string.Empty;
        if (bytes.Length == 0) { error = "文本内容为空。"; return false; }
        var encodings = new List<(Encoding Encoding, int BomLength, string Name)>();
        if (bytes.StartsWith((byte[])[0xEF, 0xBB, 0xBF])) encodings.Add((new UTF8Encoding(false, true), 3, "UTF-8 BOM"));
        else if (bytes.StartsWith((byte[])[0xFF, 0xFE, 0x00, 0x00])) encodings.Add((new UTF32Encoding(false, true, true), 4, "UTF-32 LE"));
        else if (bytes.StartsWith((byte[])[0x00, 0x00, 0xFE, 0xFF])) encodings.Add((new UTF32Encoding(true, true, true), 4, "UTF-32 BE"));
        else if (bytes.StartsWith((byte[])[0xFF, 0xFE])) encodings.Add((new UnicodeEncoding(false, true, true), 2, "UTF-16 LE"));
        else if (bytes.StartsWith((byte[])[0xFE, 0xFF])) encodings.Add((new UnicodeEncoding(true, true, true), 2, "UTF-16 BE"));
        else
        {
            if (LooksLikeUtf16(bytes, littleEndian: true)) encodings.Add((new UnicodeEncoding(false, false, true), 0, "UTF-16 LE（无BOM）"));
            if (LooksLikeUtf16(bytes, littleEndian: false)) encodings.Add((new UnicodeEncoding(true, false, true), 0, "UTF-16 BE（无BOM）"));
            encodings.Add((new UTF8Encoding(false, true), 0, "UTF-8")); encodings.Add((Gb18030, 0, "GB18030/GBK"));
        }
        foreach (var choice in encodings)
        {
            var payload = bytes[choice.BomLength..];
            var maximumTrim = allowTruncatedTail ? Math.Min(4, payload.Length - 1) : 0;
            for (var trim = 0; trim <= maximumTrim; trim++)
            {
                try
                {
                    var text = choice.Encoding.GetString(payload[..(payload.Length - trim)]);
                    var ratio = ReadableRatio(text);
                    if (ratio < 0.90 || text.IndexOf('\0') >= 0) continue;
                    decoded = new(text, choice.Name, ratio); return true;
                }
                catch (DecoderFallbackException) { }
            }
        }
        error = "无法按UTF-8、UTF-16、UTF-32或GB18030可靠解码，或可读字符比例低于90%。"; return false;
    }

    private static bool LooksLikeUtf16(ReadOnlySpan<byte> bytes, bool littleEndian)
    {
        var pairs = Math.Min(bytes.Length / 2, 2048); if (pairs < 4) return false;
        var expectedZeros = 0; var oppositeZeros = 0;
        for (var index = 0; index < pairs; index++)
        {
            if (bytes[index * 2 + (littleEndian ? 1 : 0)] == 0) expectedZeros++;
            if (bytes[index * 2 + (littleEndian ? 0 : 1)] == 0) oppositeZeros++;
        }
        return expectedZeros >= pairs * 3 / 5 && oppositeZeros <= pairs / 5;
    }

    private static double ReadableRatio(string text)
    {
        if (text.Length == 0) return 0;
        var readable = 0;
        foreach (var character in text)
            if (character is '\r' or '\n' or '\t' || (!char.IsControl(character) && character != '\uFFFD')) readable++;
        return (double)readable / text.Length;
    }

    private static Encoding CreateGb18030()
    {
        Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
        return Encoding.GetEncoding(54936, EncoderFallback.ExceptionFallback, DecoderFallback.ExceptionFallback);
    }

    private readonly record struct DecodedText(string Text, string EncodingName, double ReadableRatio);
}
