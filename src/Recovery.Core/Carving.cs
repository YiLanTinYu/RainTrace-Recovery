using System.Buffers;
using System.Buffers.Binary;
using System.Text;

namespace Recovery.Core;

public sealed record FileSignature(string Extension, byte[] Header, byte[] Footer, ulong MaxSize, int HeaderOffset = 0, int FooterExtraBytes = 0);

public sealed class SignatureCarver
{
    private const int ScanChunkSize = 8 * 1024 * 1024;
    private const int SearchChunkSize = 1024 * 1024;
    private static readonly FileSignature[] Signatures =
    [
        new("jpg", [0xFF, 0xD8, 0xFF], [0xFF, 0xD9], 512UL * 1024 * 1024, FooterExtraBytes: 0),
        new("png", [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A], [0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82], 512UL * 1024 * 1024),
        new("pdf", Encoding.ASCII.GetBytes("%PDF-"), Encoding.ASCII.GetBytes("%%EOF"), 2UL * 1024 * 1024 * 1024),
        new("zip", [0x50, 0x4B, 0x03, 0x04], [0x50, 0x4B, 0x05, 0x06], 4UL * 1024 * 1024 * 1024, FooterExtraBytes: 18),
        new("bmp", [0x42, 0x4D], [], 512UL * 1024 * 1024),
        new("webp", Encoding.ASCII.GetBytes("WEBP"), [], 512UL * 1024 * 1024, HeaderOffset: 8),
        new("wav", Encoding.ASCII.GetBytes("WAVE"), [], 4UL * 1024 * 1024 * 1024, HeaderOffset: 8),
        new("mp4", Encoding.ASCII.GetBytes("ftyp"), [], 32UL * 1024 * 1024 * 1024, HeaderOffset: 4)
    ];

    private readonly IBlockDevice _device;
    private readonly IProgress<ScanProgress>? _progress;
    private readonly Action<RecoveryCandidate>? _candidateFound;

    public SignatureCarver(IBlockDevice device, IProgress<ScanProgress>? progress = null, Action<RecoveryCandidate>? candidateFound = null)
    {
        _device = device;
        _progress = progress;
        _candidateFound = candidateFound;
    }

    public async Task<IReadOnlyList<RecoveryCandidate>> ScanAsync(ulong startOffset = 0, ulong? length = null, CancellationToken cancellationToken = default)
    {
        if (startOffset > _device.Length) throw new ArgumentOutOfRangeException(nameof(startOffset));
        var scanLength = Math.Min(length ?? (_device.Length - startOffset), _device.Length - startOffset);
        var end = checked(startOffset + scanLength);
        var overlap = Signatures.Max(s => s.Header.Length + s.HeaderOffset) - 1;
        var rented = ArrayPool<byte>.Shared.Rent(ScanChunkSize + overlap);
        var foundOffsets = new HashSet<ulong>();
        var results = new List<RecoveryCandidate>();
        var carry = 0;
        try
        {
            for (var position = startOffset; position < end;)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var requested = checked((int)Math.Min((ulong)ScanChunkSize, end - position));
                var read = await _device.ReadAsync(position, rented.AsMemory(carry, requested), cancellationToken);
                if (read <= 0) break;
                var valid = carry + read;
                var baseOffset = position - checked((ulong)carry);
                var matches = new List<(FileSignature Signature, ulong Offset)>();
                foreach (var signature in Signatures)
                {
                    var search = 0;
                    while (search + signature.HeaderOffset + signature.Header.Length <= valid)
                    {
                        var relative = rented.AsSpan(search, valid - search).IndexOf(signature.Header);
                        if (relative < 0) break;
                        var headerPosition = search + relative - signature.HeaderOffset;
                        search += relative + 1;
                        if (headerPosition < 0) continue;
                        var absolute = checked(baseOffset + (ulong)headerPosition);
                        if (absolute < startOffset || absolute >= end || !foundOffsets.Add(absolute)) continue;
                        matches.Add((signature, absolute));
                    }
                }
                foreach (var match in matches)
                {
                        var signature = match.Signature;
                        var absolute = match.Offset;
                        var size = await DetermineSizeAsync(signature, absolute, end, cancellationToken);
                        if (size == 0) continue;
                        var extension = signature.Extension switch
                        {
                            "zip" => await DetectZipFamilyAsync(absolute, size, cancellationToken),
                            "mp4" => await DetectIsoBmffFamilyAsync(absolute, cancellationToken),
                            _ => signature.Extension
                        };
                        var candidate = new RecoveryCandidate
                        {
                            RecordNumber = -checked((long)absolute),
                            Name = $"carved_{absolute:x16}.{extension}",
                            OriginalPath = Path.Combine("Raw Recovery", extension, $"carved_{absolute:x16}.{extension}"),
                            ParentRecordNumber = -1,
                            Size = size,
                            IsDeleted = true,
                            IsResident = false,
                            FileSystem = FileSystemKind.Unknown,
                            SourceOffset = absolute,
                            Discovery = RecoveryDiscovery.FileSignature,
                            Quality = RecoveryQuality.Partial,
                            QualityReason = "Recovered by file signature; the original name and directory are unavailable."
                        };
                        results.Add(candidate);
                        _candidateFound?.Invoke(candidate);
                }
                position += checked((ulong)read);
                carry = Math.Min(overlap, valid);
                Buffer.BlockCopy(rented, valid - carry, rented, 0, carry);
                _progress?.Report(new("Signature scan", position - startOffset, scanLength, results.Count, $"Offset {position:N0}"));
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(rented);
        }
        return results.OrderBy(r => r.SourceOffset).ToArray();
    }

    private async ValueTask<ulong> DetermineSizeAsync(FileSignature signature, ulong start, ulong scanEnd, CancellationToken cancellationToken)
    {
        if (signature.Extension == "bmp")
        {
            var header = new byte[6]; await _device.ReadExactlyAsync(start, header, cancellationToken);
            var length = BinaryPrimitives.ReadUInt32LittleEndian(header.AsSpan(2, 4));
            return length >= 14 && length <= signature.MaxSize && length <= scanEnd - start ? length : 0;
        }
        if (signature.Extension is "webp" or "wav")
        {
            var header = new byte[12]; await _device.ReadExactlyAsync(start, header, cancellationToken);
            if (!header.AsSpan(0, 4).SequenceEqual("RIFF"u8)) return 0;
            var length = checked((ulong)BinaryPrimitives.ReadUInt32LittleEndian(header.AsSpan(4, 4)) + 8);
            return length >= 12 && length <= signature.MaxSize && length <= scanEnd - start ? length : 0;
        }
        if (signature.Extension == "mp4") return await DetermineIsoBmffSizeAsync(start, scanEnd, signature.MaxSize, cancellationToken);
        var limit = Math.Min(scanEnd, checked(start + Math.Min(signature.MaxSize, scanEnd - start)));
        var searchStart = start + checked((ulong)signature.Header.Length);
        if (signature.Extension == "jpg")
            searchStart = await TryFindJpegScanDataAsync(start, limit, cancellationToken) ?? searchStart;
        var buffer = new byte[SearchChunkSize + signature.Footer.Length - 1];
        var carry = 0;
        for (var position = searchStart; position < limit;)
        {
            var count = checked((int)Math.Min((ulong)SearchChunkSize, limit - position));
            var read = await _device.ReadAsync(position, buffer.AsMemory(carry, count), cancellationToken);
            if (read <= 0) return 0;
            var valid = carry + read;
            var index = buffer.AsSpan(0, valid).IndexOf(signature.Footer);
            if (index >= 0)
            {
                ulong end = checked(position - (ulong)carry + (ulong)index + (ulong)signature.Footer.Length + (ulong)signature.FooterExtraBytes);
                if (signature.Extension == "zip")
                {
                    var eocd = new byte[22];
                    var eocdStart = checked(position - (ulong)carry + (ulong)index);
                    if (eocdStart + 22 <= scanEnd)
                    {
                        await _device.ReadExactlyAsync(eocdStart, eocd, cancellationToken);
                        var commentLength = BinaryPrimitives.ReadUInt16LittleEndian(eocd.AsSpan(20, 2));
                        end = checked(eocdStart + 22UL + commentLength);
                    }
                }
                return end > start ? end - start : 0;
            }
            carry = Math.Min(signature.Footer.Length - 1, valid);
            buffer.AsSpan(valid - carry, carry).CopyTo(buffer);
            position += checked((ulong)read);
        }
        return 0;
    }

    private async ValueTask<ulong> DetermineIsoBmffSizeAsync(ulong start, ulong scanEnd, ulong maximum, CancellationToken cancellationToken)
    {
        var limit = Math.Min(scanEnd, checked(start + Math.Min(maximum, scanEnd - start)));
        var position = start; var boxes = 0; var sawFtyp = false; var sawMedia = false;
        var header = new byte[16];
        while (position + 8 <= limit && boxes++ < 1_000_000)
        {
            await _device.ReadExactlyAsync(position, header.AsMemory(0, 8), cancellationToken);
            var size = BinaryPrimitives.ReadUInt32BigEndian(header.AsSpan(0, 4));
            var type = Encoding.ASCII.GetString(header, 4, 4);
            if (type.Any(character => character is < ' ' or > '~')) break;
            ulong boxSize = size;
            if (size == 1)
            {
                if (position + 16 > limit) break;
                await _device.ReadExactlyAsync(position + 8, header.AsMemory(8, 8), cancellationToken);
                boxSize = BinaryPrimitives.ReadUInt64BigEndian(header.AsSpan(8, 8));
                if (boxSize < 16) break;
            }
            else if (size < 8) break;
            if (boxSize > limit - position) break;
            if (position == start && type != "ftyp") return 0;
            sawFtyp |= type == "ftyp"; sawMedia |= type is "mdat" or "moov" or "moof";
            position += boxSize;
        }
        var length = position - start;
        return sawFtyp && sawMedia && length >= 16 ? length : 0;
    }

    private async ValueTask<string> DetectIsoBmffFamilyAsync(ulong start, CancellationToken cancellationToken)
    {
        var header = new byte[16]; await _device.ReadExactlyAsync(start, header, cancellationToken);
        return header.AsSpan(8, 4).SequenceEqual("qt  "u8) ? "mov" : "mp4";
    }

    private async ValueTask<ulong?> TryFindJpegScanDataAsync(ulong start, ulong limit, CancellationToken cancellationToken)
    {
        var cursor = checked(start + 2);
        var twoBytes = new byte[2];
        for (var markerCount = 0; markerCount < 1024 && cursor + 2 <= limit; markerCount++)
        {
            await _device.ReadExactlyAsync(cursor, twoBytes, cancellationToken);
            if (twoBytes[0] != 0xFF) return null;
            cursor++;
            byte marker;
            do
            {
                await _device.ReadExactlyAsync(cursor, twoBytes.AsMemory(0, 1), cancellationToken);
                marker = twoBytes[0];
                cursor++;
            } while (marker == 0xFF && cursor < limit);

            if (marker == 0xD9) return cursor;
            if (marker is 0x01 or >= 0xD0 and <= 0xD8) continue;
            if (cursor + 2 > limit) return null;
            await _device.ReadExactlyAsync(cursor, twoBytes, cancellationToken);
            var segmentLength = BinaryPrimitives.ReadUInt16BigEndian(twoBytes);
            if (segmentLength < 2 || cursor + segmentLength > limit) return null;
            cursor += segmentLength;
            if (marker == 0xDA) return cursor;
        }
        return null;
    }

    private async ValueTask<string> DetectZipFamilyAsync(ulong start, ulong size, CancellationToken cancellationToken)
    {
        var count = checked((int)Math.Min(size, 4UL * 1024 * 1024));
        var buffer = new byte[count];
        await _device.ReadExactlyAsync(start, buffer, cancellationToken);
        var text = Encoding.ASCII.GetString(buffer);
        if (text.Contains("word/", StringComparison.Ordinal) && text.Contains("[Content_Types].xml", StringComparison.Ordinal)) return "docx";
        if (text.Contains("xl/", StringComparison.Ordinal) && text.Contains("[Content_Types].xml", StringComparison.Ordinal)) return "xlsx";
        if (text.Contains("ppt/", StringComparison.Ordinal) && text.Contains("[Content_Types].xml", StringComparison.Ordinal)) return "pptx";
        return "zip";
    }
}

public static partial class RecoveryWriter
{
    public static async Task<RecoveryResult> RecoverRawAsync(IBlockDevice source, RecoveryCandidate candidate, string destinationRoot, IProgress<ScanProgress>? progress = null, CancellationToken cancellationToken = default)
    {
        if (candidate.Size == 0) throw new InvalidOperationException("The carved file size is unknown.");
        var root = Path.GetFullPath(destinationRoot);
        Directory.CreateDirectory(root);
        var relative = string.IsNullOrWhiteSpace(candidate.OriginalPath) ? candidate.Name : candidate.OriginalPath;
        var components = relative
            .Split([Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar], StringSplitOptions.RemoveEmptyEntries)
            .Where(component => component is not "." and not "..")
            .Select(NtfsScanner.SanitizePathComponent)
            .ToArray();
        if (components.Length == 0) components = [NtfsScanner.SanitizePathComponent(candidate.Name)];
        relative = Path.Combine(components);
        var output = EnsureUniqueRawPath(Path.Combine(root, relative));
        Directory.CreateDirectory(Path.GetDirectoryName(output)!);
        await using var file = new FileStream(output, FileMode.CreateNew, FileAccess.Write, FileShare.None, 1024 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan);
        using var hash = System.Security.Cryptography.IncrementalHash.CreateHash(System.Security.Cryptography.HashAlgorithmName.SHA256);
        var buffer = new byte[1024 * 1024];
        ulong written = 0;
        while (written < candidate.Size)
        {
            var count = checked((int)Math.Min((ulong)buffer.Length, candidate.Size - written));
            await source.ReadExactlyAsync(candidate.SourceOffset + written, buffer.AsMemory(0, count), cancellationToken);
            await file.WriteAsync(buffer.AsMemory(0, count), cancellationToken);
            hash.AppendData(buffer.AsSpan(0, count));
            written += checked((ulong)count);
            progress?.Report(new("Recovering carved file", written, candidate.Size, 1, candidate.Name));
        }
        await file.FlushAsync(cancellationToken);
        var digest = Convert.ToHexString(hash.GetHashAndReset()).ToLowerInvariant();
        await file.DisposeAsync();
        return await FinalizeResultAsync(output, written, digest, true, cancellationToken);
    }

    private static string EnsureUniqueRawPath(string path)
    {
        if (!File.Exists(path)) return path;
        var directory = Path.GetDirectoryName(path) ?? string.Empty;
        var stem = Path.GetFileNameWithoutExtension(path);
        var extension = Path.GetExtension(path);
        for (var i = 1; i < 100_000; i++)
        {
            var candidate = Path.Combine(directory, $"{stem} ({i}){extension}");
            if (!File.Exists(candidate)) return candidate;
        }
        throw new IOException("Unable to allocate a unique output filename.");
    }
}
