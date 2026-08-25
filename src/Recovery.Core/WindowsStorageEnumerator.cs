using Microsoft.Win32.SafeHandles;
using System.Runtime.InteropServices;

namespace Recovery.Core;

public static partial class WindowsStorageEnumerator
{
    private const uint GenericRead = 0x80000000;
    private const uint ShareRead = 0x00000001;
    private const uint ShareWrite = 0x00000002;
    private const uint OpenExisting = 3;
    private const uint IoctlDiskGetLengthInfo = 0x0007405C;
    private const uint IoctlDiskGetDriveGeometryEx = 0x000700A0;
    private const uint IoctlStorageQueryProperty = 0x002D1400;

    public static IReadOnlyList<MediaDescriptor> EnumeratePhysicalDisks(int maximum = 64)
    {
        if (!OperatingSystem.IsWindows()) return [];
        var result = new List<MediaDescriptor>();
        var driveLetters = BuildDriveLetterMap();
        for (var index = 0; index < maximum; index++)
        {
            var path = $@"\\.\PhysicalDrive{index}";
            using var handle = Native.CreateFileW(path, GenericRead, ShareRead | ShareWrite, IntPtr.Zero, OpenExisting, 0, IntPtr.Zero);
            if (handle.IsInvalid) continue;
            if (!TryQueryLength(handle, out var length) || length == 0) continue;
            var sectorSize = TryQueryLogicalSectorSize(handle, out var logical) ? logical : 512u;
            var storage = TryQueryStorageDescriptor(handle, out var details) ? details : StorageDetails.Unknown;
            var trimSupported = TryQueryTrim(handle, out var trim) && trim;
            var kind = DetermineKind(storage, trimSupported);
            var category = DetermineCategory(storage, trimSupported);
            var identity = string.IsNullOrWhiteSpace(storage.Model) ? $"物理磁盘 {index}" : $"物理磁盘 {index} · {storage.Model}";
            var bus = string.IsNullOrWhiteSpace(storage.BusName) ? string.Empty : $" · {storage.BusName}";
            var volumes = driveLetters.TryGetValue(index, out var letters) && letters.Count > 0
                ? $" · 盘符 {string.Join(", ", letters)}"
                : " · 无盘符";
            result.Add(new(
                $"disk-{index}",
                $"{identity}{volumes} · {FormatBytes(length)}{bus}",
                path,
                length,
                sectorSize,
                Math.Max(4096u, sectorSize),
                kind,
                trimSupported,
                true,
                Model: string.IsNullOrWhiteSpace(storage.Model) ? null : storage.Model,
                SerialNumber: string.IsNullOrWhiteSpace(storage.Serial) ? null : storage.Serial,
                Category: category));
        }
        return result;
    }

    private static IReadOnlyDictionary<int, IReadOnlyList<string>> BuildDriveLetterMap()
    {
        var map = new Dictionary<int, List<string>>();
        foreach (var drive in DriveInfo.GetDrives())
        {
            if (drive.DriveType is not (DriveType.Fixed or DriveType.Removable) || !drive.IsReady) continue;
            int physicalNumber;
            try
            {
                if (!RecoveryDestinationSafety.TryGetPrimaryPhysicalDiskNumber(drive.RootDirectory.FullName, out physicalNumber)) continue;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException) { continue; }
            var letter = drive.RootDirectory.FullName.TrimEnd('\\');
            if (!map.TryGetValue(physicalNumber, out var letters)) map[physicalNumber] = letters = [];
            if (!letters.Contains(letter, StringComparer.OrdinalIgnoreCase)) letters.Add(letter);
        }
        return map.ToDictionary(
            pair => pair.Key,
            pair => (IReadOnlyList<string>)pair.Value.OrderBy(letter => letter, StringComparer.OrdinalIgnoreCase).ToArray());
    }

    private static bool TryQueryLength(SafeFileHandle handle, out ulong length)
    {
        long value = 0;
        var ok = Native.DeviceIoControlLong(handle, IoctlDiskGetLengthInfo, IntPtr.Zero, 0, ref value, sizeof(long), out _, IntPtr.Zero);
        length = ok && value > 0 ? checked((ulong)value) : 0;
        return ok;
    }

    private static bool TryQueryLogicalSectorSize(SafeFileHandle handle, out uint sectorSize)
    {
        var buffer = Marshal.AllocHGlobal(64);
        try
        {
            if (!Native.DeviceIoControlBuffer(handle, IoctlDiskGetDriveGeometryEx, IntPtr.Zero, 0, buffer, 64, out var returned, IntPtr.Zero) || returned < 24)
            {
                sectorSize = 512;
                return false;
            }
            sectorSize = unchecked((uint)Marshal.ReadInt32(buffer, 20));
            return sectorSize is >= 512 and <= 65536 && (sectorSize & (sectorSize - 1)) == 0;
        }
        finally { Marshal.FreeHGlobal(buffer); }
    }

    private static string FormatBytes(ulong bytes)
    {
        string[] units = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
        var value = (double)bytes;
        var unit = 0;
        while (value >= 1024 && unit < units.Length - 1) { value /= 1024; unit++; }
        return $"{value:0.##} {units[unit]}";
    }

    private static bool TryQueryStorageDescriptor(SafeFileHandle handle, out StorageDetails details)
    {
        var query = Marshal.AllocHGlobal(12);
        var output = Marshal.AllocHGlobal(4096);
        try
        {
            for (var i = 0; i < 12; i++) Marshal.WriteByte(query, i, 0); // StorageDeviceProperty + standard query.
            if (!Native.DeviceIoControlBuffer(handle, IoctlStorageQueryProperty, query, 12, output, 4096, out var returned, IntPtr.Zero) || returned < 36)
            {
                details = StorageDetails.Unknown;
                return false;
            }
            var removable = Marshal.ReadByte(output, 10) != 0;
            var vendor = ReadDescriptorString(output, returned, Marshal.ReadInt32(output, 12));
            var product = ReadDescriptorString(output, returned, Marshal.ReadInt32(output, 16));
            var serial = ReadDescriptorString(output, returned, Marshal.ReadInt32(output, 24));
            var busType = Marshal.ReadInt32(output, 28);
            var model = string.Join(' ', new[] { vendor, product }.Where(s => !string.IsNullOrWhiteSpace(s))).Trim();
            details = new(model, serial, BusTypeName(busType), busType, removable);
            return true;
        }
        finally
        {
            Marshal.FreeHGlobal(query);
            Marshal.FreeHGlobal(output);
        }
    }

    private static bool TryQueryTrim(SafeFileHandle handle, out bool enabled)
    {
        var query = Marshal.AllocHGlobal(12);
        var output = Marshal.AllocHGlobal(16);
        try
        {
            for (var i = 0; i < 12; i++) Marshal.WriteByte(query, i, 0);
            Marshal.WriteInt32(query, 0, 8); // StorageDeviceTrimProperty.
            var ok = Native.DeviceIoControlBuffer(handle, IoctlStorageQueryProperty, query, 12, output, 16, out var returned, IntPtr.Zero);
            enabled = ok && returned >= 9 && Marshal.ReadByte(output, 8) != 0;
            return ok;
        }
        finally
        {
            Marshal.FreeHGlobal(query);
            Marshal.FreeHGlobal(output);
        }
    }

    private static string ReadDescriptorString(IntPtr buffer, uint returned, int offset)
    {
        if (offset <= 0 || (uint)offset >= returned) return string.Empty;
        var bytes = new List<byte>();
        for (var i = offset; (uint)i < returned && bytes.Count < 512; i++)
        {
            var value = Marshal.ReadByte(buffer, i);
            if (value == 0) break;
            bytes.Add(value);
        }
        return System.Text.Encoding.ASCII.GetString([.. bytes]).Trim();
    }

    private static MediaKind DetermineKind(StorageDetails storage, bool trimSupported)
    {
        if (storage.Removable || storage.BusType is 12 or 13) return MediaKind.Removable;
        if (trimSupported || storage.BusType == 17 || storage.Model.Contains("NVME", StringComparison.OrdinalIgnoreCase) || storage.Model.Contains("SSD", StringComparison.OrdinalIgnoreCase))
            return MediaKind.SolidState;
        return MediaKind.HardDisk;
    }

    private static MediaCategory DetermineCategory(StorageDetails storage, bool trimSupported)
    {
        if (storage.BusType is 12 or 13) return MediaCategory.MemoryCard;
        if (storage.BusType == 8) return MediaCategory.Raid;
        if (storage.BusType == 16) return MediaCategory.StorageSpace;
        if (trimSupported || storage.BusType == 17 ||
            storage.Model.Contains("NVME", StringComparison.OrdinalIgnoreCase) ||
            storage.Model.Contains("SSD", StringComparison.OrdinalIgnoreCase))
            return MediaCategory.SolidState;
        if (storage.BusType == 7 || storage.Removable) return MediaCategory.UsbStorage;
        if (storage.BusType is 3 or 10 or 11) return MediaCategory.HardDisk;
        return MediaCategory.Unknown;
    }

    private static string BusTypeName(int busType) => busType switch
    {
        3 => "ATA", 7 => "USB", 8 => "RAID", 10 => "SAS", 11 => "SATA",
        12 => "SD", 13 => "MMC/TF", 14 => "虚拟磁盘", 16 => "存储空间", 17 => "NVMe", 18 => "SCM", 19 => "UFS",
        _ => busType > 0 ? $"总线 {busType}" : string.Empty
    };

    private sealed record StorageDetails(string Model, string Serial, string BusName, int BusType, bool Removable)
    {
        public static StorageDetails Unknown { get; } = new(string.Empty, string.Empty, string.Empty, 0, false);
    }

    private static partial class Native
    {
        [LibraryImport("kernel32.dll", EntryPoint = "CreateFileW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
        internal static partial SafeFileHandle CreateFileW(string fileName, uint desiredAccess, uint shareMode, IntPtr securityAttributes, uint creationDisposition, uint flagsAndAttributes, IntPtr templateFile);

        [LibraryImport("kernel32.dll", EntryPoint = "DeviceIoControl", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static partial bool DeviceIoControlLong(SafeFileHandle device, uint controlCode, IntPtr input, uint inputSize, ref long output, int outputSize, out uint bytesReturned, IntPtr overlapped);

        [LibraryImport("kernel32.dll", EntryPoint = "DeviceIoControl", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static partial bool DeviceIoControlBuffer(SafeFileHandle device, uint controlCode, IntPtr input, uint inputSize, IntPtr output, int outputSize, out uint bytesReturned, IntPtr overlapped);
    }
}

public static partial class RecoveryDestinationSafety
{
    private const uint ShareRead = 0x00000001;
    private const uint ShareWrite = 0x00000002;
    private const uint OpenExisting = 3;
    private const uint IoctlVolumeGetVolumeDiskExtents = 0x00560000;
    private const uint IoctlStorageGetDeviceNumber = 0x002D1080;

    public static bool TryGetPrimaryPhysicalDiskNumber(string rootPath, out int diskNumber)
    {
        diskNumber = -1;
        if (!OperatingSystem.IsWindows()) return false;
        var root = Path.GetPathRoot(Path.GetFullPath(rootPath));
        if (string.IsNullOrEmpty(root) || root.StartsWith("\\\\", StringComparison.Ordinal)) return false;
        var volumePath = $@"\\.\{root.TrimEnd('\\')}";
        using var handle = Native.CreateFileW(volumePath, 0, ShareRead | ShareWrite, IntPtr.Zero, OpenExisting, 0, IntPtr.Zero);
        if (handle.IsInvalid) return false;
        var buffer = Marshal.AllocHGlobal(12);
        try
        {
            if (!Native.DeviceIoControlBuffer(handle, IoctlStorageGetDeviceNumber, IntPtr.Zero, 0, buffer, 12, out var returned, IntPtr.Zero) || returned < 12)
                return false;
            diskNumber = Marshal.ReadInt32(buffer, 4);
            return diskNumber >= 0;
        }
        finally { Marshal.FreeHGlobal(buffer); }
    }

    public static bool IsDestinationOnSource(MediaDescriptor source, string destinationPath, out string reason)
    {
        var destinationRoot = Path.GetPathRoot(Path.GetFullPath(destinationPath));
        if (string.IsNullOrEmpty(destinationRoot))
        {
            reason = "无法识别恢复目录所在磁盘。";
            return true;
        }
        if (source.Kind == MediaKind.Image)
        {
            var sourceRoot = Path.GetPathRoot(Path.GetFullPath(source.Path));
            var same = string.Equals(sourceRoot, destinationRoot, StringComparison.OrdinalIgnoreCase);
            reason = same ? "镜像文件和恢复输出位于同一磁盘；为避免空间与覆盖风险，请选择另一磁盘。" : string.Empty;
            return same;
        }
        if (TryParsePhysicalDiskNumber(source.Path, out var sourceNumber))
        {
            var targetNumbers = GetPhysicalDiskNumbers(destinationRoot);
            if (targetNumbers.Count == 0)
            {
                reason = "无法验证目标目录所在物理磁盘，已阻止恢复。";
                return true;
            }
            if (targetNumbers.Contains(sourceNumber))
            {
                reason = "恢复目录位于源物理磁盘上，操作已阻止。";
                return true;
            }
        }
        reason = string.Empty;
        return false;
    }

    public static IReadOnlyList<int> GetPhysicalDiskNumbers(string rootPath)
    {
        if (!OperatingSystem.IsWindows()) return [];
        var root = Path.GetPathRoot(Path.GetFullPath(rootPath));
        if (string.IsNullOrEmpty(root) || root.StartsWith("\\\\", StringComparison.Ordinal)) return [];
        var volumePath = $@"\\.\{root.TrimEnd('\\')}";
        using var handle = Native.CreateFileW(volumePath, 0, ShareRead | ShareWrite, IntPtr.Zero, OpenExisting, 0, IntPtr.Zero);
        if (handle.IsInvalid) return [];
        const int capacity = 4096;
        var buffer = Marshal.AllocHGlobal(capacity);
        try
        {
            if (!Native.DeviceIoControlBuffer(handle, IoctlVolumeGetVolumeDiskExtents, IntPtr.Zero, 0, buffer, capacity, out var returned, IntPtr.Zero) || returned < 32)
                return [];
            var count = Marshal.ReadInt32(buffer, 0);
            if (count is <= 0 or > 128) return [];
            var result = new List<int>(count);
            for (var i = 0; i < count; i++) result.Add(Marshal.ReadInt32(buffer, 8 + i * 24));
            return result;
        }
        finally { Marshal.FreeHGlobal(buffer); }
    }

    private static bool TryParsePhysicalDiskNumber(string path, out int number)
    {
        const string prefix = @"\\.\PhysicalDrive";
        number = -1;
        return path.StartsWith(prefix, StringComparison.OrdinalIgnoreCase) && int.TryParse(path[prefix.Length..], out number);
    }

    private static partial class Native
    {
        [LibraryImport("kernel32.dll", EntryPoint = "CreateFileW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
        internal static partial SafeFileHandle CreateFileW(string fileName, uint desiredAccess, uint shareMode, IntPtr securityAttributes, uint creationDisposition, uint flagsAndAttributes, IntPtr templateFile);

        [LibraryImport("kernel32.dll", EntryPoint = "DeviceIoControl", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static partial bool DeviceIoControlBuffer(SafeFileHandle device, uint controlCode, IntPtr input, uint inputSize, IntPtr output, int outputSize, out uint bytesReturned, IntPtr overlapped);
    }
}
