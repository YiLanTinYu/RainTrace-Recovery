using System.Buffers.Binary;
using System.IO.Compression;
using System.Text;

namespace Recovery.Core;

public enum FileIntegrityState { NotChecked, Valid, Damaged, Salvaged }
public sealed record FileIntegrityResult(FileIntegrityState State, string Message);

public static partial class FileIntegrityValidator
{
    public static async Task<FileIntegrityResult> ValidateCandidateAsync(IBlockDevice source, RecoveryCandidate candidate,
        NtfsScanResult? ntfs = null, ExFatScanResult? exFat = null, Fat32ScanResult? fat32 = null,
        CancellationToken cancellationToken = default)
    {
        if (candidate.Size == 0) return new(FileIntegrityState.NotChecked, "空文件不需要结构预检。");
        if (candidate.Discovery != RecoveryDiscovery.FileSignature && !candidate.IsResident && candidate.Extents.Count == 0)
            return Damaged("元数据仍在，但原数据簇链不可用。");
        var extension = candidate.Extension;
        if (extension is not ("png" or "jpg" or "jpeg" or "pdf" or "zip" or "docx" or "xlsx" or "pptx" or "bmp" or "webp" or "wav" or "mp4" or "mov" or
            "gif" or "tif" or "tiff" or "mp3" or "avi" or "rar" or "7z" or "doc" or "xls" or "ppt" or
            "txt" or "csv" or "log" or "ini" or "md" or "markdown" or "json" or "xml" or "yaml" or "yml"))
            return new(FileIntegrityState.NotChecked, "此文件类型暂未提供恢复前结构预检。");
        try
        {
            const int sampleSize = 64 * 1024;
            var head = await RecoveryPreview.ReadRangeAsync(source, candidate, 0, sampleSize, ntfs, exFat, fat32, cancellationToken);
            var tailOffset = candidate.Size > sampleSize ? candidate.Size - sampleSize : 0;
            var tail = tailOffset == 0 ? head : await RecoveryPreview.ReadRangeAsync(source, candidate, tailOffset, sampleSize, ntfs, exFat, fat32, cancellationToken);
            return ValidateSamples(extension, candidate.Size, head, tail);
        }
        catch (Exception ex) when (ex is IOException or InvalidDataException or EndOfStreamException or OverflowException or ArgumentOutOfRangeException)
        {
            return Damaged($"无法读取预检数据：{ex.Message}");
        }
    }

    public static FileIntegrityResult ValidateSamples(string extension, ulong size, ReadOnlySpan<byte> head, ReadOnlySpan<byte> tail)
    {
        if (extension == "png")
            return head.StartsWith((byte[])[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]) && head.Length >= 24 && head.Slice(12, 4).SequenceEqual("IHDR"u8) && tail.IndexOf("IEND"u8) >= 0
                ? Valid("恢复前预检通过：PNG签名、IHDR和IEND存在。") : Damaged("恢复前预检失败：PNG签名、IHDR或IEND缺失。");
        if (extension is "jpg" or "jpeg")
            return head.StartsWith((byte[])[0xFF, 0xD8]) && tail.IndexOf((byte[])[0xFF, 0xD9]) >= 0 ? Valid("恢复前预检通过：JPEG首尾标记存在。") : Damaged("恢复前预检失败：JPEG首尾标记缺失。");
        if (extension == "pdf")
            return head.StartsWith("%PDF-"u8) && tail.IndexOf("%%EOF"u8) >= 0 ? Valid("恢复前预检通过：PDF文件头和EOF存在。") : Damaged("恢复前预检失败：PDF文件头或EOF缺失。");
        if (extension is "zip" or "docx" or "xlsx" or "pptx")
            return head.StartsWith((byte[])[0x50, 0x4B, 0x03, 0x04]) && tail.IndexOf((byte[])[0x50, 0x4B, 0x05, 0x06]) >= 0 ? Valid("恢复前预检通过：ZIP/Office首部和中央目录结尾存在。") : Damaged("恢复前预检失败：ZIP/Office容器边界缺失。");
        if (extension == "bmp")
        {
            var declared = head.Length >= 6 ? BinaryPrimitives.ReadUInt32LittleEndian(head.Slice(2, 4)) : 0;
            return head.StartsWith("BM"u8) && declared >= 54 && declared <= size ? Valid("恢复前预检通过：BMP签名和声明长度有效。") : Damaged("恢复前预检失败：BMP签名或声明长度无效。");
        }
        if (extension is "webp" or "wav")
        {
            var family = extension == "webp" ? "WEBP"u8 : "WAVE"u8;
            var declared = head.Length >= 12 ? (ulong)BinaryPrimitives.ReadUInt32LittleEndian(head.Slice(4, 4)) + 8 : 0;
            return head.StartsWith("RIFF"u8) && head.Length >= 12 && head.Slice(8, 4).SequenceEqual(family) && declared <= size
                ? Valid("恢复前预检通过：RIFF签名和声明长度有效。") : Damaged("恢复前预检失败：RIFF签名、类型或长度无效。");
        }
        if (extension is "mp4" or "mov")
            return head.Length >= 12 && head.Slice(4, 4).SequenceEqual("ftyp"u8) && (head.IndexOf("mdat"u8) >= 0 || head.IndexOf("moov"u8) >= 0 || tail.IndexOf("moov"u8) >= 0)
                ? Valid("恢复前预检通过：ISO-BMFF文件头和媒体容器标记存在。") : Damaged("恢复前预检失败：MP4/MOV容器头或媒体盒缺失。");
        if (extension is "gif" or "tif" or "tiff" or "mp3" or "avi" or "rar" or "7z" or "doc" or "xls" or "ppt")
            return ValidateAdditionalSamples(extension, size, head, tail);
        if (extension is "txt" or "csv" or "log" or "ini" or "md" or "markdown" or "json" or "xml" or "yaml" or "yml")
            return ValidateTextSamples(extension, size, head);
        return new(FileIntegrityState.NotChecked, "此文件类型暂未提供恢复前结构预检。");
    }

    public static async Task<FileIntegrityResult> ValidateAsync(string path, CancellationToken cancellationToken = default)
    {
        var extension = Path.GetExtension(path).TrimStart('.').ToLowerInvariant();
        try
        {
            return extension switch
            {
                "png" => await ValidatePngAsync(path, cancellationToken),
                "jpg" or "jpeg" => await ValidateJpegAsync(path, cancellationToken),
                "pdf" => await ValidatePdfAsync(path, cancellationToken),
                "zip" or "docx" or "xlsx" or "pptx" => ValidateZip(path, extension),
                "bmp" => await ValidateBmpAsync(path, cancellationToken),
                "webp" => await ValidateRiffAsync(path, "WEBP", cancellationToken),
                "wav" => await ValidateRiffAsync(path, "WAVE", cancellationToken),
                "mp4" or "mov" => await ValidateIsoBmffAsync(path, cancellationToken),
                "gif" => await ValidateGifAsync(path, cancellationToken),
                "tif" or "tiff" => await ValidateTiffAsync(path, cancellationToken),
                "mp3" => await ValidateMp3Async(path, cancellationToken),
                "avi" => await ValidateAviAsync(path, cancellationToken),
                "rar" => await ValidateRarAsync(path, cancellationToken),
                "7z" => await Validate7ZipAsync(path, cancellationToken),
                "doc" or "xls" or "ppt" => await ValidateCompoundDocumentAsync(path, extension, cancellationToken),
                "txt" or "csv" or "log" or "ini" or "md" or "markdown" or "json" or "xml" or "yaml" or "yml" => await ValidateTextFileAsync(path, extension, cancellationToken),
                _ => new(FileIntegrityState.NotChecked, "此文件类型暂未提供结构完整性校验。")
            };
        }
        catch (Exception ex) when (ex is IOException or InvalidDataException or EndOfStreamException or ArgumentException or OverflowException)
        {
            return new(FileIntegrityState.Damaged, $"文件结构检查失败：{ex.Message}");
        }
    }

    private static async Task<FileIntegrityResult> ValidatePngAsync(string path, CancellationToken token)
    {
        await using var stream = Open(path);
        var signature = new byte[8];
        if (!await ReadExactlyOrFalseAsync(stream, signature, token) || !signature.AsSpan().SequenceEqual((byte[])[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]))
            return Damaged("缺少PNG文件签名；文件起始数据已丢失或被覆盖。");
        var header = new byte[8]; var first = true; var sawIdat = false; var sawIend = false;
        while (stream.Position + 12 <= stream.Length)
        {
            if (!await ReadExactlyOrFalseAsync(stream, header, token)) break;
            var length = BinaryPrimitives.ReadUInt32BigEndian(header.AsSpan(0, 4));
            var type = Encoding.ASCII.GetString(header, 4, 4);
            if ((ulong)length + 4 > (ulong)(stream.Length - stream.Position)) return Damaged($"PNG块 {type} 的长度超出文件边界。");
            if (first)
            {
                if (type != "IHDR" || length != 13) return Damaged("PNG签名后没有有效的IHDR图像头。");
                var ihdr = new byte[13]; await stream.ReadExactlyAsync(ihdr, token);
                if (BinaryPrimitives.ReadUInt32BigEndian(ihdr.AsSpan(0, 4)) == 0 || BinaryPrimitives.ReadUInt32BigEndian(ihdr.AsSpan(4, 4)) == 0)
                    return Damaged("PNG图像宽度或高度为零。");
            }
            else stream.Seek(length, SeekOrigin.Current);
            stream.Seek(4, SeekOrigin.Current); // CRC
            sawIdat |= type == "IDAT";
            if (type == "IEND") { if (length != 0) return Damaged("PNG的IEND结束块长度无效。"); sawIend = true; break; }
            first = false;
        }
        if (!sawIdat) return Damaged("PNG缺少IDAT图像数据块。");
        if (!sawIend) return Damaged("PNG缺少IEND结束块。");
        if (stream.Position != stream.Length) return Damaged("PNG结束块之后存在无法解释的尾随数据。");
        return Valid("PNG签名、IHDR、IDAT和IEND结构完整。");
    }

    private static async Task<FileIntegrityResult> ValidateJpegAsync(string path, CancellationToken token)
    {
        await using var stream = Open(path); if (stream.Length < 4) return Damaged("JPEG文件过短。");
        var first = new byte[2]; await stream.ReadExactlyAsync(first, token);
        if (first[0] != 0xFF || first[1] != 0xD8) return Damaged("缺少JPEG SOI起始标记。");
        var buffer = new byte[1024 * 1024]; var previous = first[1]; var sawScan = false; var sawEnd = false;
        int read;
        while ((read = await stream.ReadAsync(buffer, token)) > 0)
        {
            for (var i = 0; i < read; i++)
            {
                var current = buffer[i]; sawScan |= previous == 0xFF && current == 0xDA; sawEnd |= previous == 0xFF && current == 0xD9; previous = current;
            }
        }
        return !sawScan ? Damaged("JPEG缺少SOS扫描数据标记。") : !sawEnd ? Damaged("JPEG缺少EOI结束标记。") : Valid("JPEG起始、扫描数据和结束标记完整。");
    }

    private static async Task<FileIntegrityResult> ValidatePdfAsync(string path, CancellationToken token)
    {
        await using var stream = Open(path); if (stream.Length < 10) return Damaged("PDF文件过短。");
        var head = new byte[checked((int)Math.Min(16L, stream.Length))]; await stream.ReadExactlyAsync(head, token);
        if (!Encoding.ASCII.GetString(head).StartsWith("%PDF-", StringComparison.Ordinal)) return Damaged("缺少PDF文件头。");
        var tailLength = checked((int)Math.Min(65536, stream.Length)); var tail = new byte[tailLength]; stream.Seek(-tailLength, SeekOrigin.End); await stream.ReadExactlyAsync(tail, token);
        return Encoding.ASCII.GetString(tail).Contains("%%EOF", StringComparison.Ordinal) ? Valid("PDF文件头和EOF结构存在。") : Damaged("PDF缺少EOF结束标记。");
    }

    private static FileIntegrityResult ValidateZip(string path, string extension)
    {
        using var archive = ZipFile.OpenRead(path);
        if (archive.Entries.Count == 0) return Damaged("ZIP中央目录为空。");
        var required = extension switch { "docx" => "word/document.xml", "xlsx" => "xl/workbook.xml", "pptx" => "ppt/presentation.xml", _ => null };
        if (required is not null && archive.GetEntry(required) is null) return Damaged($"Office压缩包缺少 {required}。");
        foreach (var entry in archive.Entries)
        {
            using var input = entry.Open(); var buffer = new byte[65536]; while (input.Read(buffer, 0, buffer.Length) > 0) { }
        }
        return Valid(required is null ? "ZIP中央目录和条目数据可读取。" : "Office容器及主要文档条目可读取。");
    }

    private static async Task<FileIntegrityResult> ValidateBmpAsync(string path, CancellationToken token)
    {
        await using var stream = Open(path); if (stream.Length < 54) return Damaged("BMP文件过短。");
        var header = new byte[54]; await stream.ReadExactlyAsync(header, token);
        if (!header.AsSpan(0, 2).SequenceEqual("BM"u8)) return Damaged("缺少BMP文件签名。");
        var declared = BinaryPrimitives.ReadUInt32LittleEndian(header.AsSpan(2, 4));
        return declared <= stream.Length && declared >= 54 ? Valid("BMP文件头和声明长度有效。") : Damaged("BMP声明长度与恢复文件不一致。");
    }

    private static async Task<FileIntegrityResult> ValidateRiffAsync(string path, string family, CancellationToken token)
    {
        await using var stream = Open(path); if (stream.Length < 12) return Damaged("RIFF文件过短。");
        var header = new byte[12]; await stream.ReadExactlyAsync(header, token);
        if (!header.AsSpan(0, 4).SequenceEqual("RIFF"u8) || Encoding.ASCII.GetString(header, 8, 4) != family) return Damaged($"缺少有效的{family} RIFF文件头。");
        var declared = (ulong)BinaryPrimitives.ReadUInt32LittleEndian(header.AsSpan(4, 4)) + 8;
        return declared <= (ulong)stream.Length ? Valid($"{family} RIFF头和声明长度有效。") : Damaged($"{family}声明长度超出恢复文件。");
    }

    private static async Task<FileIntegrityResult> ValidateIsoBmffAsync(string path, CancellationToken token)
    {
        await using var stream = Open(path); var header = new byte[16]; var first = true; var media = false;
        while (stream.Position + 8 <= stream.Length)
        {
            await stream.ReadExactlyAsync(header.AsMemory(0, 8), token); var size32 = BinaryPrimitives.ReadUInt32BigEndian(header.AsSpan(0, 4)); var type = Encoding.ASCII.GetString(header, 4, 4); ulong size = size32; var headerSize = 8;
            if (size32 == 1) { await stream.ReadExactlyAsync(header.AsMemory(8, 8), token); size = BinaryPrimitives.ReadUInt64BigEndian(header.AsSpan(8, 8)); headerSize = 16; }
            if (first && type != "ftyp") return Damaged("MP4/MOV缺少ftyp容器头。");
            if (size < (ulong)headerSize || size - (ulong)headerSize > (ulong)(stream.Length - stream.Position)) return Damaged($"MP4/MOV的{type}盒长度超出文件边界。");
            media |= type is "mdat" or "moov" or "moof"; stream.Seek(checked((long)(size - (ulong)headerSize)), SeekOrigin.Current); first = false;
        }
        return media && stream.Position == stream.Length ? Valid("MP4/MOV顶层容器盒边界完整。") : Damaged("MP4/MOV缺少媒体盒或尾部结构不完整。");
    }

    private static FileStream Open(string path) => new(path, FileMode.Open, FileAccess.Read, FileShare.Read, 1024 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan);
    private static FileIntegrityResult Valid(string message) => new(FileIntegrityState.Valid, message);
    private static FileIntegrityResult Damaged(string message) => new(FileIntegrityState.Damaged, message);
    private static async Task<bool> ReadExactlyOrFalseAsync(Stream stream, Memory<byte> buffer, CancellationToken token)
    {
        try { await stream.ReadExactlyAsync(buffer, token); return true; } catch (EndOfStreamException) { return false; }
    }
}

public static partial class RecoveryWriter
{
    internal static async Task<RecoveryResult> FinalizeResultAsync(string output, ulong written, string sha256, bool byteComplete, CancellationToken token)
    {
        var integrity = await FileIntegrityValidator.ValidateAsync(output, token);
        var salvage = integrity.State == FileIntegrityState.Damaged
            ? await JpegSalvager.TrySalvageAsync(output, token)
            : JpegSalvageResult.NotApplicable("原恢复文件不需要自动抢救。");
        return new(output, written, sha256, byteComplete, integrity.State, integrity.Message, salvage);
    }
}
