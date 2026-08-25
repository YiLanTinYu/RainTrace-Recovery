using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Recovery.Core;

public enum JpegSalvageState { NotApplicable, Unrepairable, Salvaged }

public sealed record JpegSalvageResult(
    JpegSalvageState State,
    string Message,
    string? OutputPath = null,
    string? Sha256 = null,
    int Width = 0,
    int Height = 0,
    long PreservedFromOffset = 0)
{
    public static JpegSalvageResult NotApplicable(string message) => new(JpegSalvageState.NotApplicable, message);
}

/// <summary>
/// Conservatively rescues JPEG pixel data when the beginning of a recovered file was overwritten but
/// the DQT/SOF/DHT/SOS marker chain and entropy stream are still intact. The damaged source is never modified.
/// </summary>
public static class JpegSalvager
{
    private const int HeaderSearchLimit = 4 * 1024 * 1024;

    public static async Task<JpegSalvageResult> TrySalvageAsync(string damagedPath, CancellationToken cancellationToken = default)
    {
        var extension = Path.GetExtension(damagedPath).ToLowerInvariant();
        if (extension is not (".jpg" or ".jpeg"))
            return JpegSalvageResult.NotApplicable("自动抢救当前只处理JPEG文件。");

        await using var input = new FileStream(damagedPath, FileMode.Open, FileAccess.Read, FileShare.Read,
            1024 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan);
        if (input.Length < 32)
            return new(JpegSalvageState.Unrepairable, "JPEG过短，没有可重建的图像标记链。");

        var headLength = checked((int)Math.Min(input.Length, HeaderSearchLimit));
        var head = new byte[headLength];
        await input.ReadExactlyAsync(head, cancellationToken);

        MarkerChain? chain = null;
        for (var offset = 0; offset + 4 <= head.Length; offset++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (head[offset] != 0xFF || head[offset + 1] != 0xDB) continue;
            if (TryParseMarkerChain(head, offset, out var parsed))
            {
                chain = parsed;
                break;
            }
        }

        if (chain is null)
            return new(JpegSalvageState.Unrepairable, "未找到连续有效的DQT、SOF、DHT和SOS标记链，未生成可能误导的文件。");

        var eoiOffset = await FindEoiAsync(input, chain.EntropyOffset, cancellationToken);
        if (eoiOffset < 0)
            return new(JpegSalvageState.Unrepairable, "图像标记链存在，但扫描数据后没有找到JPEG结束标记EOI。");

        var outputPath = CreateUniquePath(damagedPath);
        try
        {
            await using (var output = new FileStream(outputPath, FileMode.CreateNew, FileAccess.Write, FileShare.None,
                1024 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan))
            {
                await output.WriteAsync(new byte[] { 0xFF, 0xD8 }, cancellationToken);
                input.Position = chain.StartOffset;
                var remaining = eoiOffset + 2 - chain.StartOffset;
                var buffer = new byte[1024 * 1024];
                while (remaining > 0)
                {
                    var wanted = checked((int)Math.Min(remaining, buffer.Length));
                    var read = await input.ReadAsync(buffer.AsMemory(0, wanted), cancellationToken);
                    if (read == 0) throw new EndOfStreamException("JPEG扫描数据在EOI之前意外结束。");
                    await output.WriteAsync(buffer.AsMemory(0, read), cancellationToken);
                    remaining -= read;
                }
                await output.FlushAsync(cancellationToken);
            }

            var integrity = await FileIntegrityValidator.ValidateAsync(outputPath, cancellationToken);
            if (integrity.State != FileIntegrityState.Valid)
            {
                File.Delete(outputPath);
                return new(JpegSalvageState.Unrepairable, $"重建结果未通过结构校验：{integrity.Message}");
            }

            await using var hashInput = new FileStream(outputPath, FileMode.Open, FileAccess.Read, FileShare.Read,
                1024 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan);
            var sha256 = Convert.ToHexString(await SHA256.HashDataAsync(hashInput, cancellationToken));
            return new(JpegSalvageState.Salvaged,
                $"已保住JPEG画面（{chain.Width}×{chain.Height}）；文件头、EXIF、拍摄时间和缩略图等前置元数据无法恢复。",
                outputPath, sha256, chain.Width, chain.Height, chain.StartOffset);
        }
        catch
        {
            if (File.Exists(outputPath)) File.Delete(outputPath);
            throw;
        }
    }

    private static bool TryParseMarkerChain(ReadOnlySpan<byte> bytes, int start, out MarkerChain chain)
    {
        chain = default!;
        var offset = start;
        var sawDqt = false;
        var sawSof = false;
        var sawDht = false;
        var width = 0;
        var height = 0;

        while (offset + 4 <= bytes.Length)
        {
            if (bytes[offset] != 0xFF) return false;
            var codeOffset = offset + 1;
            while (codeOffset < bytes.Length && bytes[codeOffset] == 0xFF) codeOffset++;
            if (codeOffset >= bytes.Length) return false;
            var marker = bytes[codeOffset];
            if (marker is 0x00 or 0xD8 or 0xD9 || marker is >= 0xD0 and <= 0xD7) return false;
            if (codeOffset + 2 >= bytes.Length) return false;
            var length = BinaryPrimitives.ReadUInt16BigEndian(bytes.Slice(codeOffset + 1, 2));
            if (length < 2) return false;
            var segmentEnd = codeOffset + 1 + length;
            if (segmentEnd > bytes.Length) return false;

            if (marker == 0xDB)
            {
                if (length < 67) return false;
                sawDqt = true;
            }
            else if (IsStartOfFrame(marker))
            {
                if (length < 8) return false;
                height = BinaryPrimitives.ReadUInt16BigEndian(bytes.Slice(codeOffset + 4, 2));
                width = BinaryPrimitives.ReadUInt16BigEndian(bytes.Slice(codeOffset + 6, 2));
                var components = bytes[codeOffset + 8];
                if (width is <= 0 or > 100_000 || height is <= 0 or > 100_000 || components is < 1 or > 4) return false;
                sawSof = true;
            }
            else if (marker == 0xC4)
            {
                if (length < 19) return false;
                sawDht = true;
            }
            else if (marker == 0xDA)
            {
                if (length < 6 || !sawDqt || !sawSof || !sawDht) return false;
                chain = new MarkerChain(start, segmentEnd, width, height);
                return true;
            }

            offset = segmentEnd;
        }
        return false;
    }

    private static bool IsStartOfFrame(byte marker) => marker is >= 0xC0 and <= 0xCF && marker is not (0xC4 or 0xC8 or 0xCC);

    private static async Task<long> FindEoiAsync(FileStream input, long startOffset, CancellationToken token)
    {
        input.Position = startOffset;
        var buffer = new byte[1024 * 1024];
        var previous = -1;
        while (true)
        {
            var blockStart = input.Position;
            var read = await input.ReadAsync(buffer, token);
            if (read == 0) return -1;
            for (var index = 0; index < read; index++)
            {
                var current = buffer[index];
                if (previous == 0xFF && current == 0xD9) return blockStart + index - 1;
                previous = current;
            }
        }
    }

    private static string CreateUniquePath(string damagedPath)
    {
        var directory = Path.GetDirectoryName(damagedPath) ?? ".";
        var stem = Path.GetFileNameWithoutExtension(damagedPath);
        var candidate = Path.Combine(directory, $"{stem}.salvaged.jpg");
        for (var suffix = 1; File.Exists(candidate); suffix++)
            candidate = Path.Combine(directory, $"{stem}.salvaged ({suffix}).jpg");
        return candidate;
    }

    private sealed record MarkerChain(long StartOffset, long EntropyOffset, int Width, int Height);
}
