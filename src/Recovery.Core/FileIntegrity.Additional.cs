using System.Buffers.Binary;
using System.Text;

namespace Recovery.Core;

public static partial class FileIntegrityValidator
{
    private static readonly byte[] Rar4Signature = [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00];
    private static readonly byte[] Rar5Signature = [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00];
    private static readonly byte[] SevenZipSignature = [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C];
    private static readonly byte[] CompoundSignature = [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];

    private static FileIntegrityResult ValidateAdditionalSamples(string extension, ulong size, ReadOnlySpan<byte> head, ReadOnlySpan<byte> tail)
    {
        if (extension == "gif")
        {
            var signature = head.StartsWith("GIF87a"u8) || head.StartsWith("GIF89a"u8);
            var dimensions = head.Length >= 10 && BinaryPrimitives.ReadUInt16LittleEndian(head.Slice(6, 2)) > 0 &&
                BinaryPrimitives.ReadUInt16LittleEndian(head.Slice(8, 2)) > 0;
            return signature && dimensions && tail.LastIndexOf((byte)0x3B) >= 0
                ? Valid("恢复前预检通过：GIF签名、画布尺寸和结束标记存在。")
                : Damaged("恢复前预检失败：GIF签名、画布尺寸或结束标记无效。");
        }
        if (extension is "tif" or "tiff") return ValidateTiffHeader(head, size, "恢复前预检");
        if (extension == "mp3")
        {
            var id3 = TryGetId3PayloadOffset(head, size, out _);
            var frame = FindMp3Frame(head) >= 0;
            return id3 || frame ? Valid("恢复前预检通过：MP3的ID3头或MPEG音频帧有效。") : Damaged("恢复前预检失败：未找到有效的ID3头或MPEG音频帧。");
        }
        if (extension == "avi")
        {
            var declared = head.Length >= 12 ? (ulong)BinaryPrimitives.ReadUInt32LittleEndian(head.Slice(4, 4)) + 8 : 0;
            var markers = head.IndexOf("hdrl"u8) >= 0 && (head.IndexOf("movi"u8) >= 0 || tail.IndexOf("movi"u8) >= 0);
            return head.StartsWith("RIFF"u8) && head.Length >= 12 && head.Slice(8, 4).SequenceEqual("AVI "u8) && declared <= size && markers
                ? Valid("恢复前预检通过：AVI的RIFF边界、头列表和媒体列表存在。")
                : Damaged("恢复前预检失败：AVI的RIFF头、长度或媒体列表无效。");
        }
        if (extension == "rar")
            return IsRarHeader(head) ? Valid("恢复前预检通过：RAR 4/5归档签名和基础头存在；分卷、密码及文件数据需恢复后再验证。")
                : Damaged("恢复前预检失败：RAR归档签名或基础头无效。");
        if (extension == "7z") return ValidateSevenZipHeader(head, size, verifyStartHeaderCrc: true, "恢复前预检");
        if (extension is "doc" or "xls" or "ppt") return ValidateCompoundHeader(head, size, extension, "恢复前预检");
        return new(FileIntegrityState.NotChecked, "此文件类型暂未提供恢复前结构预检。");
    }

    private static async Task<FileIntegrityResult> ValidateGifAsync(string path, CancellationToken token)
    {
        await using var stream = Open(path);
        var header = new byte[13];
        if (!await ReadExactlyOrFalseAsync(stream, header, token)) return Damaged("GIF文件过短。");
        if (!header.AsSpan(0, 6).SequenceEqual("GIF87a"u8) && !header.AsSpan(0, 6).SequenceEqual("GIF89a"u8)) return Damaged("缺少GIF87a/GIF89a签名。");
        if (BinaryPrimitives.ReadUInt16LittleEndian(header.AsSpan(6, 2)) == 0 || BinaryPrimitives.ReadUInt16LittleEndian(header.AsSpan(8, 2)) == 0)
            return Damaged("GIF画布尺寸无效。");
        if ((header[10] & 0x80) != 0 && !TrySkip(stream, 3L << ((header[10] & 0x07) + 1))) return Damaged("GIF全局颜色表超出文件边界。");

        var sawImage = false;
        while (stream.Position < stream.Length)
        {
            var introducer = await ReadByteAsync(stream, token);
            if (introducer < 0) break;
            if (introducer == 0x3B) return sawImage ? Valid("GIF数据块、图像帧和结束标记完整。") : Damaged("GIF没有图像帧。");
            if (introducer == 0x21)
            {
                if (await ReadByteAsync(stream, token) < 0 || !await SkipGifSubBlocksAsync(stream, token)) return Damaged("GIF扩展数据块被截断。");
                continue;
            }
            if (introducer != 0x2C) return Damaged($"GIF包含未知或损坏的数据块 0x{introducer:X2}。");
            var descriptor = new byte[9];
            if (!await ReadExactlyOrFalseAsync(stream, descriptor, token)) return Damaged("GIF图像描述符被截断。");
            if (BinaryPrimitives.ReadUInt16LittleEndian(descriptor.AsSpan(4, 2)) == 0 || BinaryPrimitives.ReadUInt16LittleEndian(descriptor.AsSpan(6, 2)) == 0)
                return Damaged("GIF图像帧尺寸无效。");
            if ((descriptor[8] & 0x80) != 0 && !TrySkip(stream, 3L << ((descriptor[8] & 0x07) + 1))) return Damaged("GIF局部颜色表超出文件边界。");
            if (await ReadByteAsync(stream, token) < 0 || !await SkipGifSubBlocksAsync(stream, token)) return Damaged("GIF图像数据被截断。");
            sawImage = true;
        }
        return Damaged("GIF缺少结束标记。");
    }

    private static async Task<FileIntegrityResult> ValidateTiffAsync(string path, CancellationToken token)
    {
        await using var stream = Open(path);
        var header = new byte[8];
        if (!await ReadExactlyOrFalseAsync(stream, header, token)) return Damaged("TIFF文件过短。");
        var initial = ValidateTiffHeader(header, (ulong)stream.Length, "TIFF");
        if (initial.State != FileIntegrityState.Valid) return initial;
        var little = header.AsSpan(0, 2).SequenceEqual("II"u8);
        uint ReadU32(ReadOnlySpan<byte> value) => little ? BinaryPrimitives.ReadUInt32LittleEndian(value) : BinaryPrimitives.ReadUInt32BigEndian(value);
        ushort ReadU16(ReadOnlySpan<byte> value) => little ? BinaryPrimitives.ReadUInt16LittleEndian(value) : BinaryPrimitives.ReadUInt16BigEndian(value);
        var offset = ReadU32(header.AsSpan(4, 4));
        var visited = new HashSet<uint>();
        var directories = 0;
        while (offset != 0 && directories < 64)
        {
            if (!visited.Add(offset) || offset > stream.Length - 2) return Damaged("TIFF的IFD目录链循环或越界。");
            stream.Position = offset;
            var countBytes = new byte[2]; await stream.ReadExactlyAsync(countBytes, token);
            var count = ReadU16(countBytes);
            var tableBytes = checked((ulong)count * 12UL + 4UL);
            if (tableBytes > (ulong)(stream.Length - stream.Position)) return Damaged("TIFF的IFD条目表被截断。");
            var entry = new byte[12];
            for (var index = 0; index < count; index++)
            {
                await stream.ReadExactlyAsync(entry, token);
                var typeSize = TiffTypeSize(ReadU16(entry.AsSpan(2, 2)));
                var elementCount = ReadU32(entry.AsSpan(4, 4));
                if (typeSize == 0) continue;
                var dataLength = checked((ulong)typeSize * elementCount);
                if (dataLength > 4)
                {
                    var dataOffset = ReadU32(entry.AsSpan(8, 4));
                    if ((ulong)dataOffset + dataLength > (ulong)stream.Length) return Damaged("TIFF标签数据指向文件边界之外。");
                }
            }
            var nextBytes = new byte[4]; await stream.ReadExactlyAsync(nextBytes, token);
            offset = ReadU32(nextBytes); directories++;
        }
        return directories > 0 ? Valid("TIFF字节序、IFD目录链和标签数据边界有效。") : Damaged("TIFF没有有效的IFD目录。");
    }

    private static async Task<FileIntegrityResult> ValidateMp3Async(string path, CancellationToken token)
    {
        await using var stream = Open(path);
        if (stream.Length < 4) return Damaged("MP3文件过短。");
        var first = new byte[Math.Min(10, checked((int)stream.Length))]; await stream.ReadExactlyAsync(first, token);
        long audioOffset = 0;
        if (first.Length >= 10 && first.AsSpan(0, 3).SequenceEqual("ID3"u8))
        {
            if (!TryGetId3PayloadOffset(first, (ulong)stream.Length, out var parsedOffset)) return Damaged("MP3的ID3标签长度无效。");
            audioOffset = checked((long)parsedOffset);
        }
        stream.Position = audioOffset;
        var searchLength = checked((int)Math.Min(2L * 1024 * 1024, stream.Length - audioOffset));
        var buffer = new byte[searchLength]; await stream.ReadExactlyAsync(buffer, token);
        var frameOffset = FindMp3Frame(buffer);
        if (frameOffset < 0) return Damaged("MP3中未找到有效的MPEG音频帧。");
        if (!TryGetMp3FrameLength(buffer.AsSpan(frameOffset), out var frameLength)) return Damaged("MP3音频帧头无效。");
        var next = frameOffset + frameLength;
        var secondFrame = next + 4 <= buffer.Length && TryGetMp3FrameLength(buffer.AsSpan(next), out _);
        return Valid(secondFrame ? "MP3的ID3边界及连续MPEG音频帧有效。" : "MP3至少包含一个有效MPEG音频帧；短文件或可变结构无法验证连续帧。");
    }

    private static async Task<FileIntegrityResult> ValidateAviAsync(string path, CancellationToken token)
    {
        await using var stream = Open(path);
        var prefixLength = checked((int)Math.Min(16L * 1024 * 1024, stream.Length));
        var prefix = new byte[prefixLength]; await stream.ReadExactlyAsync(prefix, token);
        if (prefix.Length < 12 || !prefix.AsSpan(0, 4).SequenceEqual("RIFF"u8) || !prefix.AsSpan(8, 4).SequenceEqual("AVI "u8)) return Damaged("缺少AVI RIFF容器头。");
        var declared = (ulong)BinaryPrimitives.ReadUInt32LittleEndian(prefix.AsSpan(4, 4)) + 8;
        if (declared > (ulong)stream.Length) return Damaged("AVI的RIFF声明长度超出恢复文件。");
        if (prefix.AsSpan().IndexOf("hdrl"u8) < 0 || prefix.AsSpan().IndexOf("movi"u8) < 0) return Damaged("AVI缺少hdrl头列表或movi媒体列表。");
        return Valid("AVI的RIFF边界、hdrl头列表和movi媒体列表存在。");
    }

    private static async Task<FileIntegrityResult> ValidateRarAsync(string path, CancellationToken token)
    {
        await using var stream = Open(path);
        var header = new byte[checked((int)Math.Min(32L, stream.Length))]; await stream.ReadExactlyAsync(header, token);
        if (!IsRarHeader(header)) return Damaged("缺少有效的RAR 4/5归档签名或基础头。");
        return Valid("RAR 4/5归档签名和基础头有效；加密内容、分卷连续性及内部文件CRC需由解压器最终确认。");
    }

    private static async Task<FileIntegrityResult> Validate7ZipAsync(string path, CancellationToken token)
    {
        await using var stream = Open(path);
        var header = new byte[checked((int)Math.Min(32L, stream.Length))]; await stream.ReadExactlyAsync(header, token);
        var initial = ValidateSevenZipHeader(header, (ulong)stream.Length, verifyStartHeaderCrc: true, "7Z");
        if (initial.State != FileIntegrityState.Valid) return initial;
        var nextOffset = BinaryPrimitives.ReadUInt64LittleEndian(header.AsSpan(12, 8));
        var nextSize = BinaryPrimitives.ReadUInt64LittleEndian(header.AsSpan(20, 8));
        var expectedCrc = BinaryPrimitives.ReadUInt32LittleEndian(header.AsSpan(28, 4));
        stream.Position = checked((long)(32UL + nextOffset));
        var actualCrc = await ComputeCrc32Async(stream, nextSize, token);
        return actualCrc == expectedCrc ? Valid("7Z签名、起始头CRC、下一头边界和下一头CRC有效。") : Damaged("7Z下一头CRC校验失败，目录结构可能损坏。");
    }

    private static async Task<FileIntegrityResult> ValidateCompoundDocumentAsync(string path, string extension, CancellationToken token)
    {
        await using var stream = Open(path);
        var header = new byte[checked((int)Math.Min(512L, stream.Length))]; await stream.ReadExactlyAsync(header, token);
        var initial = ValidateCompoundHeader(header, (ulong)stream.Length, extension, "复合文档");
        if (initial.State != FileIntegrityState.Valid) return initial;
        var requiredNames = extension switch
        {
            "doc" => new[] { "WordDocument" },
            "xls" => new[] { "Workbook", "Book" },
            "ppt" => new[] { "PowerPoint Document" },
            _ => []
        };
        foreach (var name in requiredNames)
            if (await ContainsSequenceAsync(stream, Encoding.Unicode.GetBytes(name), token))
                return Valid($"{extension.ToUpperInvariant()}的CFB容器头、扇区边界和主数据流 {name} 有效。");
        return Damaged($"{extension.ToUpperInvariant()}的CFB容器中未找到必要的主数据流。");
    }

    private static FileIntegrityResult ValidateTiffHeader(ReadOnlySpan<byte> head, ulong size, string prefix)
    {
        if (head.Length < 8) return Damaged($"{prefix}失败：TIFF文件头被截断。");
        var little = head.Slice(0, 2).SequenceEqual("II"u8); var big = head.Slice(0, 2).SequenceEqual("MM"u8);
        if (!little && !big) return Damaged($"{prefix}失败：TIFF字节序标记无效。");
        var magic = little ? BinaryPrimitives.ReadUInt16LittleEndian(head.Slice(2, 2)) : BinaryPrimitives.ReadUInt16BigEndian(head.Slice(2, 2));
        if (magic != 42) return Damaged($"{prefix}失败：仅支持标准TIFF，版本标记无效或属于BigTIFF。");
        var offset = little ? BinaryPrimitives.ReadUInt32LittleEndian(head.Slice(4, 4)) : BinaryPrimitives.ReadUInt32BigEndian(head.Slice(4, 4));
        return offset >= 8 && offset + 2UL <= size ? Valid($"{prefix}通过：TIFF字节序、版本和首个IFD偏移有效。") : Damaged($"{prefix}失败：TIFF首个IFD偏移越界。");
    }

    private static FileIntegrityResult ValidateSevenZipHeader(ReadOnlySpan<byte> head, ulong size, bool verifyStartHeaderCrc, string prefix)
    {
        if (head.Length < 32 || !head.StartsWith(SevenZipSignature)) return Damaged($"{prefix}失败：7Z签名或起始头被截断。");
        if (verifyStartHeaderCrc && ComputeCrc32(head.Slice(12, 20)) != BinaryPrimitives.ReadUInt32LittleEndian(head.Slice(8, 4)))
            return Damaged($"{prefix}失败：7Z起始头CRC错误。");
        var nextOffset = BinaryPrimitives.ReadUInt64LittleEndian(head.Slice(12, 8));
        var nextSize = BinaryPrimitives.ReadUInt64LittleEndian(head.Slice(20, 8));
        if (nextOffset > ulong.MaxValue - 32 || 32UL + nextOffset > size || nextSize > size - (32UL + nextOffset))
            return Damaged($"{prefix}失败：7Z下一头指针超出文件边界。");
        return Valid($"{prefix}通过：7Z签名、起始头CRC和下一头边界有效。");
    }

    private static FileIntegrityResult ValidateCompoundHeader(ReadOnlySpan<byte> head, ulong size, string extension, string prefix)
    {
        if (head.Length < 512 || !head.StartsWith(CompoundSignature)) return Damaged($"{prefix}失败：{extension.ToUpperInvariant()}缺少完整CFB复合文档头。");
        if (head[28] != 0xFE || head[29] != 0xFF) return Damaged($"{prefix}失败：CFB字节序标记无效。");
        var major = BinaryPrimitives.ReadUInt16LittleEndian(head.Slice(26, 2));
        var sectorShift = BinaryPrimitives.ReadUInt16LittleEndian(head.Slice(30, 2));
        var miniShift = BinaryPrimitives.ReadUInt16LittleEndian(head.Slice(32, 2));
        if ((major == 3 && sectorShift != 9) || (major == 4 && sectorShift != 12) || major is not (3 or 4) || miniShift != 6)
            return Damaged($"{prefix}失败：CFB版本或扇区尺寸无效。");
        var sectorSize = 1UL << sectorShift;
        if (size < 512UL + sectorSize || (size - 512UL) % sectorSize != 0) return Damaged($"{prefix}失败：CFB文件长度未按扇区对齐。");
        var directorySector = BinaryPrimitives.ReadUInt32LittleEndian(head.Slice(48, 4));
        var sectorCount = (size - 512UL) / sectorSize;
        return directorySector < sectorCount ? Valid($"{prefix}通过：{extension.ToUpperInvariant()}的CFB头、扇区尺寸和目录指针有效。")
            : Damaged($"{prefix}失败：CFB目录扇区指针越界。");
    }

    private static bool IsRarHeader(ReadOnlySpan<byte> data)
    {
        if (data.StartsWith(Rar4Signature)) return data.Length >= 14 && data[9] == 0x73 && BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(12, 2)) >= 7;
        if (!data.StartsWith(Rar5Signature) || data.Length < 14) return false;
        var index = 12;
        return TryReadRar5VInt(data, ref index, out var headerSize) && headerSize > 0 && TryReadRar5VInt(data, ref index, out var headerType) && headerType == 1;
    }

    private static bool TryReadRar5VInt(ReadOnlySpan<byte> data, ref int index, out ulong value)
    {
        value = 0;
        for (var shift = 0; shift < 64 && index < data.Length; shift += 7)
        {
            var current = data[index++]; value |= (ulong)(current & 0x7F) << shift;
            if ((current & 0x80) == 0) return true;
        }
        return false;
    }

    private static bool TryGetId3PayloadOffset(ReadOnlySpan<byte> data, ulong size, out ulong offset)
    {
        offset = 0;
        if (data.Length < 10 || !data.Slice(0, 3).SequenceEqual("ID3"u8) || data[3] == 0xFF || data[4] == 0xFF ||
            (data[6] | data[7] | data[8] | data[9]) >= 0x80) return false;
        var tagSize = ((ulong)data[6] << 21) | ((ulong)data[7] << 14) | ((ulong)data[8] << 7) | data[9];
        offset = 10UL + tagSize + ((data[5] & 0x10) != 0 ? 10UL : 0UL);
        return offset <= size;
    }

    private static int FindMp3Frame(ReadOnlySpan<byte> data)
    {
        for (var index = 0; index + 4 <= data.Length; index++) if (TryGetMp3FrameLength(data.Slice(index), out _)) return index;
        return -1;
    }

    private static bool TryGetMp3FrameLength(ReadOnlySpan<byte> data, out int length)
    {
        length = 0;
        if (data.Length < 4 || data[0] != 0xFF || (data[1] & 0xE0) != 0xE0) return false;
        var version = (data[1] >> 3) & 0x03; var layer = (data[1] >> 1) & 0x03;
        var bitrateIndex = (data[2] >> 4) & 0x0F; var sampleIndex = (data[2] >> 2) & 0x03; var padding = (data[2] >> 1) & 1;
        if (version == 1 || layer == 0 || bitrateIndex is 0 or 15 || sampleIndex == 3) return false;
        int[] mpeg1Layer1 = [32, 64, 96, 128, 160, 192, 224, 256, 288, 320, 352, 384, 416, 448];
        int[] mpeg1Layer2 = [32, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 384];
        int[] mpeg1Layer3 = [32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320];
        int[] mpeg2Layer1 = [32, 48, 56, 64, 80, 96, 112, 128, 144, 160, 176, 192, 224, 256];
        int[] mpeg2Layer23 = [8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160];
        var table = version == 3 ? layer == 3 ? mpeg1Layer1 : layer == 2 ? mpeg1Layer2 : mpeg1Layer3 : layer == 3 ? mpeg2Layer1 : mpeg2Layer23;
        var bitrate = table[bitrateIndex - 1] * 1000;
        var sampleRate = new[] { 44100, 48000, 32000 }[sampleIndex] / (version == 3 ? 1 : version == 2 ? 2 : 4);
        length = layer == 3 ? (12 * bitrate / sampleRate + padding) * 4 : (version == 3 || layer == 2 ? 144 : 72) * bitrate / sampleRate + padding;
        return length >= 24;
    }

    private static int TiffTypeSize(ushort type) => type switch { 1 or 2 or 6 or 7 => 1, 3 or 8 => 2, 4 or 9 or 11 or 13 => 4, 5 or 10 or 12 or 16 or 17 or 18 => 8, _ => 0 };

    private static bool TrySkip(Stream stream, long count)
    {
        if (count < 0 || count > stream.Length - stream.Position) return false;
        stream.Position += count; return true;
    }

    private static async Task<int> ReadByteAsync(Stream stream, CancellationToken token)
    {
        var one = new byte[1]; return await stream.ReadAsync(one, token) == 1 ? one[0] : -1;
    }

    private static async Task<bool> SkipGifSubBlocksAsync(Stream stream, CancellationToken token)
    {
        while (true)
        {
            var length = await ReadByteAsync(stream, token);
            if (length < 0) return false;
            if (length == 0) return true;
            if (!TrySkip(stream, length)) return false;
        }
    }

    private static async Task<bool> ContainsSequenceAsync(Stream stream, byte[] pattern, CancellationToken token)
    {
        stream.Position = 0;
        var buffer = new byte[1024 * 1024 + pattern.Length]; var retained = 0;
        while (true)
        {
            var read = await stream.ReadAsync(buffer.AsMemory(retained, buffer.Length - retained), token);
            if (read == 0) return false;
            var total = retained + read;
            if (buffer.AsSpan(0, total).IndexOf(pattern) >= 0) return true;
            retained = Math.Min(pattern.Length - 1, total);
            buffer.AsSpan(total - retained, retained).CopyTo(buffer);
        }
    }

    private static uint ComputeCrc32(ReadOnlySpan<byte> data)
    {
        var crc = 0xFFFFFFFFu;
        foreach (var value in data) crc = UpdateCrc32(crc, value);
        return ~crc;
    }

    private static async Task<uint> ComputeCrc32Async(Stream stream, ulong length, CancellationToken token)
    {
        var crc = 0xFFFFFFFFu; var remaining = length; var buffer = new byte[1024 * 1024];
        while (remaining > 0)
        {
            var wanted = checked((int)Math.Min((ulong)buffer.Length, remaining));
            var read = await stream.ReadAsync(buffer.AsMemory(0, wanted), token);
            if (read == 0) throw new EndOfStreamException("7Z下一头被截断。");
            for (var index = 0; index < read; index++) crc = UpdateCrc32(crc, buffer[index]);
            remaining -= (ulong)read;
        }
        return ~crc;
    }

    private static uint UpdateCrc32(uint crc, byte value)
    {
        crc ^= value;
        for (var bit = 0; bit < 8; bit++) crc = (crc & 1) != 0 ? (crc >> 1) ^ 0xEDB88320u : crc >> 1;
        return crc;
    }
}
