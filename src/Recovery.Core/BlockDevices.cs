using Microsoft.Win32.SafeHandles;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace Recovery.Core;

public interface IBlockDevice : IAsyncDisposable
{
    string Id { get; }
    ulong Length { get; }
    uint LogicalSectorSize { get; }
    uint PhysicalSectorSize { get; }
    bool IsReadOnly { get; }
    ValueTask<int> ReadAsync(ulong offset, Memory<byte> buffer, CancellationToken cancellationToken = default);
}

public sealed class PausableBlockDevice : IBlockDevice
{
    private readonly IBlockDevice _inner;
    private readonly object _sync = new();
    private TaskCompletionSource _resume = CompletedSource();
    public PausableBlockDevice(IBlockDevice inner) => _inner = inner;
    public string Id => _inner.Id;
    public ulong Length => _inner.Length;
    public uint LogicalSectorSize => _inner.LogicalSectorSize;
    public uint PhysicalSectorSize => _inner.PhysicalSectorSize;
    public bool IsReadOnly => _inner.IsReadOnly;
    public bool IsPaused { get; private set; }

    public void Pause()
    {
        lock (_sync)
        {
            if (IsPaused) return;
            _resume = new(TaskCreationOptions.RunContinuationsAsynchronously);
            IsPaused = true;
        }
    }

    public void Resume()
    {
        TaskCompletionSource source;
        lock (_sync) { if (!IsPaused) return; IsPaused = false; source = _resume; }
        source.TrySetResult();
    }

    public async ValueTask<int> ReadAsync(ulong offset, Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        Task wait;
        lock (_sync) wait = _resume.Task;
        await wait.WaitAsync(cancellationToken);
        return await _inner.ReadAsync(offset, buffer, cancellationToken);
    }

    public async ValueTask DisposeAsync()
    {
        Resume();
        await _inner.DisposeAsync();
    }

    private static TaskCompletionSource CompletedSource()
    {
        var source = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        source.SetResult(); return source;
    }
}

public sealed class ImageBlockDevice : IBlockDevice
{
    private readonly SafeFileHandle _handle;
    public string Id { get; }
    public ulong Length { get; }
    public uint LogicalSectorSize { get; }
    public uint PhysicalSectorSize { get; }
    public bool IsReadOnly => true;

    public ImageBlockDevice(string path, uint logicalSectorSize = 512, uint physicalSectorSize = 4096)
    {
        Id = Path.GetFullPath(path);
        _handle = File.OpenHandle(Id, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, FileOptions.Asynchronous | FileOptions.RandomAccess);
        Length = checked((ulong)RandomAccess.GetLength(_handle));
        LogicalSectorSize = logicalSectorSize;
        PhysicalSectorSize = physicalSectorSize;
    }

    public ValueTask<int> ReadAsync(ulong offset, Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        if (offset > long.MaxValue) throw new ArgumentOutOfRangeException(nameof(offset));
        return RandomAccess.ReadAsync(_handle, buffer, checked((long)offset), cancellationToken);
    }

    public ValueTask DisposeAsync()
    {
        _handle.Dispose();
        return ValueTask.CompletedTask;
    }
}

public sealed partial class WindowsPhysicalDiskDevice : IBlockDevice
{
    private const uint GenericRead = 0x80000000;
    private const uint ShareRead = 0x00000001;
    private const uint ShareWrite = 0x00000002;
    private const uint OpenExisting = 3;
    private const uint IoctlDiskGetLengthInfo = 0x0007405C;
    private const uint FileBegin = 0;
    private const int CacheCapacity = 8 * 1024 * 1024 + 64 * 1024;
    private const int MinimumCacheRead = 64 * 1024;
    private readonly SafeFileHandle _handle;
    private readonly SemaphoreSlim _ioGate = new(1, 1);
    private readonly byte[] _cache = new byte[CacheCapacity];
    private ulong _cacheOffset;
    private int _cacheLength;

    public string Id { get; }
    public ulong Length { get; }
    public uint LogicalSectorSize { get; }
    public uint PhysicalSectorSize { get; }
    public bool IsReadOnly => true;

    public WindowsPhysicalDiskDevice(string path, uint logicalSectorSize = 512, uint physicalSectorSize = 4096)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
        if (!path.StartsWith(@"\\.\PhysicalDrive", StringComparison.OrdinalIgnoreCase) &&
            !(path.StartsWith(@"\\.\", StringComparison.OrdinalIgnoreCase) && path.EndsWith(':')))
            throw new ArgumentException("Only a Windows physical disk or volume path is accepted.", nameof(path));

        Id = path;
        _handle = Native.CreateFileW(path, GenericRead, ShareRead | ShareWrite, IntPtr.Zero, OpenExisting, 0, IntPtr.Zero);
        if (_handle.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error(), $"Unable to open {path} for read-only access");
        try { Length = QueryLength(_handle); }
        catch { _handle.Dispose(); throw; }
        LogicalSectorSize = logicalSectorSize;
        PhysicalSectorSize = physicalSectorSize;
    }

    private static ulong QueryLength(SafeFileHandle handle)
    {
        long length = 0;
        if (!Native.DeviceIoControl(handle, IoctlDiskGetLengthInfo, IntPtr.Zero, 0, ref length, sizeof(long), out _, IntPtr.Zero))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to query device length");
        return checked((ulong)length);
    }

    public async ValueTask<int> ReadAsync(ulong offset, Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        if (offset > long.MaxValue) throw new ArgumentOutOfRangeException(nameof(offset));
        if (offset >= Length || buffer.IsEmpty) return 0;
        await _ioGate.WaitAsync(cancellationToken);
        try
        {
            if (offset >= _cacheOffset && offset + (ulong)buffer.Length <= _cacheOffset + (ulong)_cacheLength)
            {
                var cacheIndex = checked((int)(offset - _cacheOffset));
                _cache.AsMemory(cacheIndex, buffer.Length).CopyTo(buffer);
                return buffer.Length;
            }

            var alignedOffset = offset / LogicalSectorSize * LogicalSectorSize;
            var delta = checked((int)(offset - alignedOffset));
            var available = Math.Min((ulong)_cache.Length, Length - alignedOffset);
            var desired = Math.Max((ulong)MinimumCacheRead, checked((ulong)delta + (ulong)buffer.Length));
            var roundedDesired = checked((desired + LogicalSectorSize - 1) / LogicalSectorSize * LogicalSectorSize);
            var readLength = checked((int)Math.Min(available, roundedDesired));
            if ((ulong)readLength < (ulong)delta + (ulong)buffer.Length)
                readLength = checked((int)Math.Min(available, checked((ulong)delta + (ulong)buffer.Length)));

            var read = await Task.Run(() => ReadNative(alignedOffset, _cache, readLength), cancellationToken);
            _cacheOffset = alignedOffset;
            _cacheLength = read;
            if (delta >= read) return 0;
            var take = Math.Min(buffer.Length, read - delta);
            _cache.AsMemory(delta, take).CopyTo(buffer);
            return take;
        }
        finally
        {
            _ioGate.Release();
        }
    }

    private int ReadNative(ulong offset, byte[] target, int count)
    {
        if (!Native.SetFilePointerEx(_handle, checked((long)offset), out _, FileBegin))
            throw new IOException($"Unable to seek the physical disk to byte {offset:N0}.", new Win32Exception(Marshal.GetLastWin32Error()));
        if (!Native.ReadFile(_handle, target, count, out var read, IntPtr.Zero))
            throw new IOException($"Unable to read the physical disk at byte {offset:N0}.", new Win32Exception(Marshal.GetLastWin32Error()));
        return read;
    }

    public ValueTask DisposeAsync()
    {
        _handle.Dispose();
        _ioGate.Dispose();
        return ValueTask.CompletedTask;
    }

    private static partial class Native
    {
        [LibraryImport("kernel32.dll", EntryPoint = "CreateFileW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
        internal static partial SafeFileHandle CreateFileW(string fileName, uint desiredAccess, uint shareMode, IntPtr securityAttributes, uint creationDisposition, uint flagsAndAttributes, IntPtr templateFile);

        [LibraryImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static partial bool DeviceIoControl(SafeFileHandle device, uint controlCode, IntPtr input, uint inputSize, ref long output, int outputSize, out uint bytesReturned, IntPtr overlapped);

        [LibraryImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static partial bool SetFilePointerEx(SafeFileHandle file, long distance, out long newPosition, uint moveMethod);

        [LibraryImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static partial bool ReadFile(SafeFileHandle file, [Out] byte[] buffer, int bytesToRead, out int bytesRead, IntPtr overlapped);
    }
}

public static class BlockDeviceExtensions
{
    public static async ValueTask ReadExactlyAsync(this IBlockDevice device, ulong offset, Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        var total = 0;
        while (total < buffer.Length)
        {
            var read = await device.ReadAsync(offset + checked((ulong)total), buffer[total..], cancellationToken);
            if (read == 0) throw new EndOfStreamException($"Unexpected end of device at byte {offset + checked((ulong)total):N0}");
            total += read;
        }
    }
}
