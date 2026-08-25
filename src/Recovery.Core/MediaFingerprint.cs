using System.Security.Cryptography;

namespace Recovery.Core;

public sealed record MediaFingerprint(
    ulong Length,
    uint LogicalSectorSize,
    string FirstSectorSha256,
    string? Model,
    string? SerialNumber);

public static class MediaFingerprintService
{
    public static async Task<MediaFingerprint> ComputeAsync(
        IBlockDevice device,
        MediaDescriptor descriptor,
        CancellationToken cancellationToken = default)
    {
        var sampleLength = checked((int)Math.Min(device.Length, Math.Max(512u, device.LogicalSectorSize)));
        var firstSector = new byte[sampleLength];
        if (sampleLength > 0) await device.ReadExactlyAsync(0, firstSector, cancellationToken);
        var hash = Convert.ToHexString(SHA256.HashData(firstSector)).ToLowerInvariant();
        return new(device.Length, device.LogicalSectorSize, hash, Normalize(descriptor.Model), Normalize(descriptor.SerialNumber));
    }

    public static bool IsDescriptorCompatible(MediaDescriptor expected, MediaDescriptor actual, out string reason)
    {
        if (expected.Length != actual.Length)
        {
            reason = $"磁盘容量不一致：保存时 {expected.Length:N0} 字节，当前 {actual.Length:N0} 字节。";
            return false;
        }
        if (expected.LogicalSectorSize != actual.LogicalSectorSize)
        {
            reason = $"逻辑扇区大小不一致：保存时 {expected.LogicalSectorSize:N0}，当前 {actual.LogicalSectorSize:N0}。";
            return false;
        }
        var expectedSerial = Normalize(expected.SerialNumber);
        var actualSerial = Normalize(actual.SerialNumber);
        if (expectedSerial is not null && actualSerial is not null && !string.Equals(expectedSerial, actualSerial, StringComparison.OrdinalIgnoreCase))
        {
            reason = "磁盘序列号与保存扫描结果时不一致。";
            return false;
        }
        var expectedModel = Normalize(expected.Model);
        var actualModel = Normalize(actual.Model);
        if (expectedModel is not null && actualModel is not null && !string.Equals(expectedModel, actualModel, StringComparison.OrdinalIgnoreCase))
        {
            reason = "磁盘型号与保存扫描结果时不一致。";
            return false;
        }
        reason = string.Empty;
        return true;
    }

    public static bool Matches(MediaFingerprint expected, MediaFingerprint actual, out string reason)
    {
        if (expected.Length != actual.Length || expected.LogicalSectorSize != actual.LogicalSectorSize)
        {
            reason = "介质容量或逻辑扇区大小发生变化。";
            return false;
        }
        if (!string.Equals(expected.FirstSectorSha256, actual.FirstSectorSha256, StringComparison.OrdinalIgnoreCase))
        {
            reason = "介质首扇区指纹不一致，当前设备不是保存扫描结果时的源介质。";
            return false;
        }
        if (expected.SerialNumber is not null && actual.SerialNumber is not null &&
            !string.Equals(expected.SerialNumber, actual.SerialNumber, StringComparison.OrdinalIgnoreCase))
        {
            reason = "介质序列号不一致。";
            return false;
        }
        reason = string.Empty;
        return true;
    }

    private static string? Normalize(string? value) => string.IsNullOrWhiteSpace(value) ? null : value.Trim();
}
