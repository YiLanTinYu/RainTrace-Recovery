using Recovery.Core;
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace Recovery.Tests;

internal static class Program
{
    private const int SectorSize = 512;
    private const int ClusterSize = 4096;
    private const int RecordSize = 1024;
    private static readonly byte[] ResidentPayload = Encoding.UTF8.GetBytes("雨痕数据恢复：resident deleted file\r\n");
    private static readonly byte[] JpegPayload = [0xff, 0xd8, 0xff, 0xe0, .. Encoding.ASCII.GetBytes("synthetic-jpeg-payload"), 0xff, 0xd9];
    private static readonly byte[] DeepPayload = BuildSyntheticDocxSignature();
    private static readonly byte[] FullDiskPayload = BuildSyntheticXlsxSignature();
    private static readonly byte[] ValidPngPayload = Convert.FromBase64String("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAusB9Y9Zl9sAAAAASUVORK5CYII=");

    private static async Task<int> Main(string[] args)
    {
        if (args.Length > 2 && args[0] == "--scantsk")
        {
            var binDirectory = Path.GetFullPath(args[1]);
            var sourcePath = Path.GetFullPath(args[2]);
            var offset = args.Length > 3 ? ulong.Parse(args[3], System.Globalization.CultureInfo.InvariantCulture) : 0UL;
            var timeout = args.Length > 4 ? TimeSpan.FromSeconds(double.Parse(args[4], System.Globalization.CultureInfo.InvariantCulture)) : (TimeSpan?)null;
            var tskProgress = new Progress<ScanProgress>(item => Console.WriteLine($"TSK_PROGRESS PERCENT={item.Percent:0.0} MESSAGE={item.Message}"));
            SleuthKitScanResult result;
            try { result = await SleuthKitEngine.ScanDeletedAsync(binDirectory, new SleuthKitScanOptions(sourcePath, offset), progress: tskProgress, maximumRuntime: timeout); }
            catch (TimeoutException ex) when (timeout is not null)
            {
                Console.WriteLine($"TSK_TIMEOUT_OK MESSAGE={ex.Message}");
                return 0;
            }
            Console.WriteLine($"TSK_SCAN_OK EXIT={result.ExitCode} CANDIDATES={result.Candidates.Count} ENCODING={result.DetectedEncoding} ERROR={result.StandardError}");
            foreach (var candidate in result.Candidates.Take(100))
                Console.WriteLine($"TSK_CANDIDATE META={candidate.MetadataAddress}|PATH={candidate.OriginalPath}|SIZE={candidate.Size}|DIRECTORY={candidate.IsDirectory}|MODIFIED={candidate.ModifiedUtc:O}");
            return result.CompletedNormally ? 0 : 3;
        }
        if (args.Length > 5 && args[0] == "--recovertsk")
        {
            var binDirectory = Path.GetFullPath(args[1]);
            var sourcePath = Path.GetFullPath(args[2]);
            var metadataAddress = args[3];
            var expectedSize = ulong.Parse(args[4], System.Globalization.CultureInfo.InvariantCulture);
            var outputPath = Path.GetFullPath(args[5]);
            var candidate = new SleuthKitCandidate(metadataAddress, Path.GetFileName(outputPath), expectedSize, false, null);
            var result = await SleuthKitEngine.RecoverAsync(binDirectory, new SleuthKitScanOptions(sourcePath), candidate, outputPath);
            Console.WriteLine($"TSK_RECOVERY_OK EXIT={result.ExitCode} BYTES={result.BytesWritten} EXPECTED={expectedSize} MATCH={result.BytesWritten == expectedSize} PATH={result.OutputPath}");
            return result.CompletedNormally && result.BytesWritten == expectedSize ? 0 : 3;
        }
        if (args.Length > 1 && args[0] == "--validate")
        {
            var validation = await FileIntegrityValidator.ValidateAsync(Path.GetFullPath(args[1]));
            Console.WriteLine($"INTEGRITY={validation.State} MESSAGE={validation.Message}");
            return validation.State == FileIntegrityState.Damaged ? 3 : 0;
        }
        if (args.Length > 1 && args[0] == "--salvagejpeg")
        {
            var result = await JpegSalvager.TrySalvageAsync(Path.GetFullPath(args[1]));
            Console.WriteLine($"SALVAGE={result.State} PATH={result.OutputPath} WIDTH={result.Width} HEIGHT={result.Height} " +
                $"SOURCE_OFFSET={result.PreservedFromOffset} SHA256={result.Sha256} MESSAGE={result.Message}");
            return result.State == JpegSalvageState.Salvaged ? 0 : 3;
        }
        if (args.Length > 4 && args[0] == "--scanexfat")
        {
            var logical = uint.Parse(args[2], System.Globalization.CultureInfo.InvariantCulture);
            var physicalSector = uint.Parse(args[3], System.Globalization.CultureInfo.InvariantCulture);
            var partitionOffset = ulong.Parse(args[4], System.Globalization.CultureInfo.InvariantCulture);
            await using var physical = new WindowsPhysicalDiskDevice(args[1], logical, physicalSector);
            long lastReport = 0;
            var progress = new Progress<ScanProgress>(item =>
            {
                var now = Environment.TickCount64;
                if (now - Interlocked.Read(ref lastReport) < 5000) return;
                Interlocked.Exchange(ref lastReport, now);
                Console.WriteLine($"PROGRESS STAGE={item.Stage} PERCENT={item.Percent:0.0} CANDIDATES={item.Candidates} MESSAGE={item.Message}");
            });
            var deepMode = args.Length > 5 && string.Equals(args[5], "deep", StringComparison.OrdinalIgnoreCase);
            var scan = await new ExFatScanner(physical, partitionOffset, progress).ScanAsync(
                new ScanOptions(EvaluateRecoverability: false, ExFatDeepMetadataScan: deepMode));
            var deep = scan.Candidates.Count(candidate => candidate.Discovery == RecoveryDiscovery.ExFatDeepMetadata);
            Console.WriteLine($"EXFAT_DEEP_SCAN_OK CANDIDATES={scan.Candidates.Count} DEEP={deep}");
            foreach (var candidate in scan.Candidates.Take(100))
                Console.WriteLine($"CANDIDATE NAME={candidate.Name}|PATH={candidate.OriginalPath}|SIZE={candidate.Size}|SOURCE={candidate.SourceOffset}|MODIFIED={candidate.ModifiedUtc:O}");
            return 0;
        }
        if (args.Length > 4 && args[0] == "--runphotorec")
        {
            var result = await PhotoRecEngine.RunAsync(Path.GetFullPath(args[1]), new PhotoRecRunOptions(
                Path.GetFullPath(args[2]), Path.GetFullPath(args[3]), Path.GetFullPath(args[4]),
                ["jpg", "png", "bmp", "pdf", "zip", "doc", "mov", "riff", "tif", "gif"],
                FreeSpaceOnly: true, TreatSourceAsWholeDevice: true));
            Console.WriteLine($"PHOTOREC_OK EXIT={result.ExitCode} FILES={result.Files.Count} REJECTED={result.RejectedFiles} LOG={result.LogPath}");
            foreach (var file in result.Files.Take(20)) Console.WriteLine($"RECOVERED={file.Path}|{file.Size}|{file.Extension}");
            return result.CompletedNormally && result.Files.Count > 0 ? 0 : 3;
        }
        if (args.Length > 0 && args[0] == "--enumerate")
        {
            var disks = WindowsStorageEnumerator.EnumeratePhysicalDisks();
            foreach (var disk in disks)
                Console.WriteLine($"{disk.Path}|{disk.Length}|{disk.LogicalSectorSize}|{disk.DisplayName}");
            Console.WriteLine($"COUNT={disks.Count}");
            return disks.Count > 0 ? 0 : 2;
        }
        if (args.Length > 1 && args[0] == "--readphysical")
        {
            await using var physical = new WindowsPhysicalDiskDevice(args[1]);
            var sector = new byte[512];
            await physical.ReadExactlyAsync(0, sector);
            Console.WriteLine($"PATH={args[1]} LENGTH={physical.Length} READ={sector.Length} SIGNATURE={sector[510]:X2}{sector[511]:X2} READONLY={physical.IsReadOnly}");
            var partitions = await PartitionScanner.ScanAsync(physical);
            foreach (var partition in partitions)
                Console.WriteLine($"PARTITION={partition.Number}|OFFSET={partition.Offset}|LENGTH={partition.Length}|FS={partition.FileSystem}|GPT={partition.IsGpt}|NAME={partition.Name}");
            Console.WriteLine($"PARTITION_COUNT={partitions.Count}");
            return 0;
        }
        if (args.Length > 7 && args[0] == "--recoverexfat")
        {
            var logicalSectorSize = uint.Parse(args[2], System.Globalization.CultureInfo.InvariantCulture);
            var physicalSectorSize = uint.Parse(args[3], System.Globalization.CultureInfo.InvariantCulture);
            var partitionOffset = ulong.Parse(args[4], System.Globalization.CultureInfo.InvariantCulture);
            var exactName = args[5];
            var destination = Path.GetFullPath(args[6]);
            var expectedHash = args[7];
            await using var physical = new WindowsPhysicalDiskDevice(args[1], logicalSectorSize, physicalSectorSize);
            long lastProgress = 0;
            var progress = new Progress<ScanProgress>(item =>
            {
                var now = Environment.TickCount64;
                if (now - Interlocked.Read(ref lastProgress) < 1000) return;
                Interlocked.Exchange(ref lastProgress, now);
                Console.WriteLine($"PROGRESS STAGE={item.Stage} CANDIDATES={item.Candidates} MESSAGE={item.Message}");
            });
            var scan = await new ExFatScanner(physical, partitionOffset, progress).ScanAsync(new ScanOptions(EvaluateRecoverability: false));
            var matches = scan.Candidates.Where(candidate =>
                string.Equals(candidate.Name, exactName, StringComparison.OrdinalIgnoreCase)).ToArray();
            Console.WriteLine($"EXFAT_SCAN_OK PATH={args[1]} OFFSET={partitionOffset} CANDIDATES={scan.Candidates.Count} MATCHES={matches.Length}");
            foreach (var candidate in matches)
            {
                Console.WriteLine($"CANDIDATE NAME={candidate.Name} PATH={candidate.OriginalPath} SIZE={candidate.Size} " +
                    $"QUALITY={candidate.Quality} SOURCE={candidate.SourceOffset}");
                var result = await RecoveryWriter.RecoverExFatAsync(physical, scan, candidate, destination);
                var hashMatches = string.Equals(result.Sha256, expectedHash, StringComparison.OrdinalIgnoreCase);
                Console.WriteLine($"RECOVERED PATH={result.OutputPath} BYTES={result.BytesWritten} COMPLETE={result.Complete} " +
                    $"SHA256={result.Sha256.ToUpperInvariant()} HASH_MATCH={hashMatches}");
            }
            return matches.Length > 0 ? 0 : 3;
        }
        if (args.Length > 9 && args[0] == "--recoverraw")
        {
            var logicalSectorSize = uint.Parse(args[2], System.Globalization.CultureInfo.InvariantCulture);
            var physicalSectorSize = uint.Parse(args[3], System.Globalization.CultureInfo.InvariantCulture);
            var start = ulong.Parse(args[4], System.Globalization.CultureInfo.InvariantCulture);
            var length = ulong.Parse(args[5], System.Globalization.CultureInfo.InvariantCulture);
            var extension = args[6].TrimStart('.');
            var expectedSize = ulong.Parse(args[7], System.Globalization.CultureInfo.InvariantCulture);
            var destination = Path.GetFullPath(args[8]);
            var expectedHash = args[9];
            await using var physical = new WindowsPhysicalDiskDevice(args[1], logicalSectorSize, physicalSectorSize);
            var candidates = await new SignatureCarver(physical).ScanAsync(start, length);
            var matches = candidates.Where(candidate =>
                string.Equals(candidate.Extension, extension, StringComparison.OrdinalIgnoreCase) &&
                candidate.Size == expectedSize).ToList();
            Console.WriteLine($"RAW_SCAN_OK PATH={args[1]} START={start} LENGTH={length} CANDIDATES={candidates.Count} MATCHES={matches.Count}");
            if (matches.Count == 0)
            {
                var nearest = candidates
                    .Where(candidate => string.Equals(candidate.Extension, extension, StringComparison.OrdinalIgnoreCase))
                    .OrderBy(candidate => candidate.Size >= expectedSize ? candidate.Size - expectedSize : expectedSize - candidate.Size)
                    .Take(10)
                    .ToArray();
                foreach (var candidate in nearest)
                    Console.WriteLine($"NEAREST NAME={candidate.Name} SIZE={candidate.Size} SOURCE={candidate.SourceOffset}");
                foreach (var candidate in nearest.Where(candidate =>
                    candidate.Size <= expectedSize && expectedSize - candidate.Size <= 4096))
                {
                    var rawHash = await HashDeviceRangeAsync(physical, candidate.SourceOffset, expectedSize);
                    if (!string.Equals(rawHash, expectedHash, StringComparison.OrdinalIgnoreCase)) continue;
                    Console.WriteLine($"BASELINE_ASSISTED_MATCH SOURCE={candidate.SourceOffset} SIGNATURE_SIZE={candidate.Size} " +
                        $"EXACT_SIZE={expectedSize} TRAILING_BYTES={expectedSize - candidate.Size}");
                    matches.Add(new RecoveryCandidate
                    {
                        RecordNumber = candidate.RecordNumber,
                        Name = candidate.Name,
                        OriginalPath = candidate.OriginalPath,
                        Size = expectedSize,
                        IsDeleted = true,
                        FileSystem = candidate.FileSystem,
                        SourceOffset = candidate.SourceOffset,
                        Discovery = candidate.Discovery,
                        Quality = candidate.Quality,
                        QualityReason = candidate.QualityReason
                    });
                    break;
                }
            }
            foreach (var candidate in matches)
            {
                Console.WriteLine($"CANDIDATE NAME={candidate.Name} SIZE={candidate.Size} SOURCE={candidate.SourceOffset}");
                var result = await RecoveryWriter.RecoverRawAsync(physical, candidate, destination);
                var hashMatches = string.Equals(result.Sha256, expectedHash, StringComparison.OrdinalIgnoreCase);
                Console.WriteLine($"RECOVERED PATH={result.OutputPath} BYTES={result.BytesWritten} COMPLETE={result.Complete} " +
                    $"SHA256={result.Sha256.ToUpperInvariant()} HASH_MATCH={hashMatches}");
            }
            return matches.Count > 0 ? 0 : 3;
        }
        if (args.Length > 5 && args[0] == "--recoverntfs")
        {
            await using var physical = new WindowsPhysicalDiskDevice(args[1]);
            var offset = ulong.Parse(args[2], System.Globalization.CultureInfo.InvariantCulture);
            var mode = args[3];
            var exactName = args[4];
            var destination = Path.GetFullPath(args[5]);
            var expectedHash = args.Length > 6 ? args[6] : string.Empty;
            var scan = await new NtfsScanner(physical, offset).ScanAsync(new ScanOptions(
                DeepMetadataScan: string.Equals(mode, "deep", StringComparison.OrdinalIgnoreCase),
                FullDiskMetadataScan: string.Equals(mode, "full", StringComparison.OrdinalIgnoreCase)));
            var matches = scan.Candidates
                .Where(candidate => string.Equals(candidate.Name, exactName, StringComparison.OrdinalIgnoreCase))
                .ToArray();
            Console.WriteLine($"MATCHES={matches.Length} NAME={exactName} MODE={mode}");
            foreach (var candidate in matches)
            {
                Console.WriteLine($"CANDIDATE RECORD={candidate.RecordNumber} PATH={candidate.OriginalPath} SIZE={candidate.Size} " +
                    $"QUALITY={candidate.Quality} DISCOVERY={candidate.Discovery} SOURCE={candidate.SourceOffset}");
                var result = await RecoveryWriter.RecoverNtfsAsync(physical, scan, candidate, destination);
                var hashMatches = string.IsNullOrEmpty(expectedHash) ||
                    string.Equals(result.Sha256, expectedHash, StringComparison.OrdinalIgnoreCase);
                Console.WriteLine($"RECOVERED PATH={result.OutputPath} BYTES={result.BytesWritten} COMPLETE={result.Complete} " +
                    $"SHA256={result.Sha256.ToUpperInvariant()} HASH_MATCH={hashMatches}");
            }
            return matches.Length > 0 ? 0 : 3;
        }
        if (args.Length > 2 && args[0] == "--scanntfs")
        {
            var logicalSectorSize = args.Length > 4
                ? uint.Parse(args[4], System.Globalization.CultureInfo.InvariantCulture)
                : 512u;
            var physicalSectorSize = args.Length > 5
                ? uint.Parse(args[5], System.Globalization.CultureInfo.InvariantCulture)
                : 4096u;
            await using var physical = new WindowsPhysicalDiskDevice(args[1], logicalSectorSize, physicalSectorSize);
            var offset = ulong.Parse(args[2], System.Globalization.CultureInfo.InvariantCulture);
            var mode = args.Length > 3 ? args[3] : "current";
            var deep = string.Equals(mode, "deep", StringComparison.OrdinalIgnoreCase);
            var full = string.Equals(mode, "full", StringComparison.OrdinalIgnoreCase);
            var scan = await new NtfsScanner(physical, offset).ScanAsync(new ScanOptions(
                DeepMetadataScan: deep,
                FullDiskMetadataScan: full));
            var quality = scan.Candidates.GroupBy(candidate => candidate.Quality).OrderBy(group => group.Key)
                .Select(group => $"{group.Key}={group.Count()}");
            var discovery = scan.Candidates.GroupBy(candidate => candidate.Discovery).OrderBy(group => group.Key)
                .Select(group => $"{group.Key}={group.Count()}");
            Console.WriteLine($"NTFS_SCAN_OK PATH={args[1]} OFFSET={offset} MODE={mode} CURRENT={scan.ParsedCurrentMftRecords}/{scan.CurrentMftRecords} " +
                $"DEEP_RECORDS={scan.ParsedDeepRecords}/{scan.DeepRecordsExamined} CANDIDATES={scan.Candidates.Count} " +
                $"DISCOVERY={string.Join(',', discovery)} QUALITY={string.Join(',', quality)}");
            return 0;
        }
        if (args.Length > 5 && args[0] == "--scancombined")
        {
            var logicalSectorSize = uint.Parse(args[2], System.Globalization.CultureInfo.InvariantCulture);
            var physicalSectorSize = uint.Parse(args[3], System.Globalization.CultureInfo.InvariantCulture);
            var partitionOffset = ulong.Parse(args[4], System.Globalization.CultureInfo.InvariantCulture);
            var length = ulong.Parse(args[5], System.Globalization.CultureInfo.InvariantCulture);
            await using var physical = new WindowsPhysicalDiskDevice(args[1], logicalSectorSize, physicalSectorSize);
            var scan = await new NtfsScanner(physical, partitionOffset).ScanAsync(new ScanOptions());
            var ranges = CandidateRangeIndex.BuildNtfs(scan.Candidates.Select(candidate => (candidate, scan)));
            var carved = await new SignatureCarver(physical).ScanAsync(partitionOffset, length);
            var filtered = carved.Where(candidate => !CandidateRangeIndex.Contains(ranges, candidate.SourceOffset)).ToArray();
            Console.WriteLine($"COMBINED_SCAN_OK METADATA={scan.Candidates.Count} RAW={carved.Count} FILTERED={filtered.Length} RANGES={ranges.Count}");
            foreach (var candidate in filtered.Take(50))
                Console.WriteLine($"RAW_CANDIDATE NAME={candidate.Name} SIZE={candidate.Size} SOURCE={candidate.SourceOffset}");
            return 0;
        }
        var root = args.Length > 0 ? Path.GetFullPath(args[0]) : @"D:\CodexRecoveryLab";
        var testDrive = Path.GetPathRoot(root);
        if (testDrive is null || !new[] { @"D:\", @"F:\", @"G:\" }.Contains(testDrive, StringComparer.OrdinalIgnoreCase))
            throw new InvalidOperationException("Safety rule: the integration test root must be on D:, F: or G:. C: is never accepted.");

        Directory.CreateDirectory(root);
        var imageDir = Path.Combine(root, "images");
        var outputDir = Path.Combine(root, "output", "automated-tests");
        var logDir = Path.Combine(root, "logs");
        Directory.CreateDirectory(imageDir);
        Directory.CreateDirectory(outputDir);
        Directory.CreateDirectory(logDir);
        var logPath = Path.Combine(logDir, "test-results.txt");
        var lines = new List<string> { $"Started UTC: {DateTime.UtcNow:O}" };

        try
        {
            var photoRecArguments = PhotoRecEngine.BuildArguments(new PhotoRecRunOptions(
                Path.Combine(imageDir, "source image.img"), Path.Combine(outputDir, "photorec-stage"),
                Path.Combine(root, "photorec-work"), ["jpg", "png", "pdf", "zip", "bmp"],
                FreeSpaceOnly: true, TreatSourceAsWholeDevice: true));
            Assert(photoRecArguments.Contains("/cmd") && photoRecArguments[^1].Contains("partition_none", StringComparison.Ordinal) &&
                photoRecArguments[^1].Contains("paranoid", StringComparison.Ordinal) &&
                photoRecArguments[^1].Contains("keep_corrupted_file_no", StringComparison.Ordinal) &&
                photoRecArguments[^1].Contains("freespace", StringComparison.Ordinal), "PhotoRec safe scripted arguments");
            lines.Add("PASS PhotoRec adapter builds strict free-space-only command arguments without shell interpolation");

            var imagePath = Path.Combine(imageDir, "synthetic-ntfs.img");
            await BuildNtfsImageAsync(imagePath);
            lines.Add($"PASS fixture: {imagePath}");

            var fingerprintDescriptor = new MediaDescriptor("fingerprint-image", "fingerprint image", imagePath,
                checked((ulong)new FileInfo(imagePath).Length), 512, 4096, MediaKind.Image, false, true, Model: "Synthetic", SerialNumber: "RAINTRACE-001");
            MediaFingerprint fingerprint;
            await using (var fingerprintImage = new ImageBlockDevice(imagePath))
                fingerprint = await MediaFingerprintService.ComputeAsync(fingerprintImage, fingerprintDescriptor);
            await using (var sameFingerprintImage = new ImageBlockDevice(imagePath))
            {
                var same = await MediaFingerprintService.ComputeAsync(sameFingerprintImage, fingerprintDescriptor);
                Assert(MediaFingerprintService.Matches(fingerprint, same, out _), "same media fingerprint matches");
            }
            var changedFingerprintPath = Path.Combine(imageDir, "synthetic-ntfs-changed-fingerprint.img");
            File.Copy(imagePath, changedFingerprintPath, overwrite: true);
            await using (var changedStream = new FileStream(changedFingerprintPath, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
            {
                var first = changedStream.ReadByte(); changedStream.Position = 0; changedStream.WriteByte(checked((byte)(first ^ 0x5a)));
            }
            await using (var changedFingerprintImage = new ImageBlockDevice(changedFingerprintPath))
            {
                var changed = await MediaFingerprintService.ComputeAsync(changedFingerprintImage, fingerprintDescriptor);
                Assert(!MediaFingerprintService.Matches(fingerprint, changed, out var reason) && reason.Contains("指纹", StringComparison.Ordinal),
                    "different first-sector fingerprint is rejected");
            }
            var wrongSerial = fingerprintDescriptor with { SerialNumber = "OTHER-DEVICE" };
            Assert(!MediaFingerprintService.IsDescriptorCompatible(fingerprintDescriptor, wrongSerial, out _), "different device serial is rejected");
            lines.Add("PASS saved-session media fingerprint accepts the same source and rejects changed sectors or serial numbers");

            var photoRecExecutable = Path.Combine(Directory.GetCurrentDirectory(), "third_party", "runtime", "testdisk-7.2", "photorec_win.exe");
            Assert(PhotoRecEngine.IsAvailable(photoRecExecutable), "bundled PhotoRec executable is available");
            var photoRecDestination = Path.Combine(outputDir, "photorec-engine-" + DateTime.UtcNow.ToString("yyyyMMdd-HHmmssfff"));
            var photoRecResult = await PhotoRecEngine.RunAsync(photoRecExecutable, new PhotoRecRunOptions(
                imagePath, photoRecDestination, Path.Combine(root, "photorec-work", Guid.NewGuid().ToString("N")),
                ["jpg", "png", "pdf", "bmp"], FreeSpaceOnly: true, TreatSourceAsWholeDevice: true));
            Assert(photoRecResult.CompletedNormally && photoRecResult.Files.Count > 0 && photoRecResult.RejectedFiles > 0,
                "PhotoRec engine strictly recovers valid files and rejects invalid candidates");
            lines.Add($"PASS PhotoRec 7.2 process integration recovered {photoRecResult.Files.Count} validated files and rejected {photoRecResult.RejectedFiles} invalid candidates from read-only image");

            var stagedPngPath = Path.Combine(outputDir, "photorec-staged-source.png");
            await File.WriteAllBytesAsync(stagedPngPath, ValidPngPayload);
            var stagedCandidate = new RecoveryCandidate
            {
                Name = "f0000001.png", OriginalPath = Path.Combine("PhotoRec Recovery", "png", "f0000001.png"),
                Size = (ulong)ValidPngPayload.Length, IsDeleted = true, Discovery = RecoveryDiscovery.PhotoRecFile,
                StagedRecoveryPath = stagedPngPath
            };
            var stagedResult = await RecoveryWriter.RecoverStagedAsync(stagedCandidate, Path.Combine(outputDir, "photorec-selected"));
            Assert(stagedResult.Usable && (await File.ReadAllBytesAsync(stagedResult.OutputPath)).SequenceEqual(ValidPngPayload),
                "selected PhotoRec staged file recovery");
            lines.Add("PASS selected PhotoRec result copies to final recovery folder and passes post-recovery integrity validation");

            var validPngPath = Path.Combine(imageDir, "valid-1x1.png");
            var damagedPngPath = Path.Combine(imageDir, "damaged-missing-header.png");
            var validPng = ValidPngPayload;
            await File.WriteAllBytesAsync(validPngPath, validPng);
            var damagedPng = validPng.ToArray(); Array.Clear(damagedPng, 0, 33); await File.WriteAllBytesAsync(damagedPngPath, damagedPng);
            var validPngResult = await FileIntegrityValidator.ValidateAsync(validPngPath);
            var damagedPngResult = await FileIntegrityValidator.ValidateAsync(damagedPngPath);
            Assert(validPngResult.State == FileIntegrityState.Valid, "valid PNG integrity");
            Assert(damagedPngResult.State == FileIntegrityState.Damaged && damagedPngResult.Message.Contains("PNG文件签名"), "damaged PNG missing header");
            await using (var damagedSource = new ImageBlockDevice(damagedPngPath))
            {
                var damagedCandidate = new RecoveryCandidate { Name = "damaged.png", OriginalPath = "damaged.png", Size = (ulong)damagedPng.Length, IsDeleted = true, SourceOffset = 0 };
                var damagedPreflight = await FileIntegrityValidator.ValidateCandidateAsync(damagedSource, damagedCandidate);
                Assert(damagedPreflight.State == FileIntegrityState.Damaged, "preflight rejects damaged PNG before recovery");
                var damagedRecovery = await RecoveryWriter.RecoverRawAsync(damagedSource, damagedCandidate, Path.Combine(outputDir, "integrity"));
                Assert(damagedRecovery.Integrity == FileIntegrityState.Damaged && !damagedRecovery.Usable, "recovery result propagates damaged integrity");
            }
            lines.Add("PASS preflight/post-recovery PNG integrity accepts a complete image, rejects missing signature/IHDR and marks recovery unusable");

            var additionalIntegrityFixtures = new Dictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase)
            {
                ["gif"] = BuildSyntheticGif(), ["tiff"] = BuildSyntheticTiff(), ["mp3"] = BuildSyntheticMp3(),
                ["avi"] = BuildSyntheticAvi(), ["rar"] = BuildSyntheticRar(), ["7z"] = BuildSynthetic7Zip(),
                ["doc"] = BuildSyntheticCompoundDocument("WordDocument"), ["xls"] = BuildSyntheticCompoundDocument("Workbook"),
                ["ppt"] = BuildSyntheticCompoundDocument("PowerPoint Document")
            };
            foreach (var fixture in additionalIntegrityFixtures)
            {
                var validPath = Path.Combine(imageDir, $"valid-structure.{fixture.Key}");
                var damagedPath = Path.Combine(imageDir, $"damaged-structure.{fixture.Key}");
                await File.WriteAllBytesAsync(validPath, fixture.Value);
                var damaged = fixture.Value.ToArray(); Array.Clear(damaged); await File.WriteAllBytesAsync(damagedPath, damaged);
                Assert((await FileIntegrityValidator.ValidateAsync(validPath)).State == FileIntegrityState.Valid, $"valid {fixture.Key} integrity");
                Assert((await FileIntegrityValidator.ValidateAsync(damagedPath)).State == FileIntegrityState.Damaged, $"damaged {fixture.Key} integrity");
                await using var fixtureSource = new ImageBlockDevice(validPath);
                var fixtureCandidate = new RecoveryCandidate
                {
                    Name = Path.GetFileName(validPath), OriginalPath = Path.GetFileName(validPath),
                    Size = (ulong)fixture.Value.Length, IsDeleted = true, SourceOffset = 0
                };
                Assert((await FileIntegrityValidator.ValidateCandidateAsync(fixtureSource, fixtureCandidate)).State == FileIntegrityState.Valid,
                    $"valid {fixture.Key} preflight");
            }
            lines.Add("PASS GIF/TIFF/MP3/AVI/RAR/7Z/DOC/XLS/PPT preflight and post-recovery validators accept valid structures and reject damaged signatures");

            Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
            var textIntegrityFixtures = new Dictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase)
            {
                ["txt"] = Encoding.UTF8.GetBytes("雨痕数据恢复\r\n普通文本内容完整可读。\r\n"),
                ["csv"] = Encoding.UTF8.GetBytes("name,age\r\nAlice,30\r\n张三,20\r\n"),
                ["log"] = Encoding.GetEncoding(54936).GetBytes("2026-08-25 启动扫描\r\n读取介质完成\r\n"),
                ["ini"] = [.. Encoding.Unicode.GetPreamble(), .. Encoding.Unicode.GetBytes("[RainTrace]\r\nReadOnly=true\r\n")],
                ["md"] = Encoding.UTF8.GetBytes("# 雨痕\r\n\r\n- 只读扫描\r\n- 数据恢复\r\n"),
                ["json"] = Encoding.UTF8.GetBytes("{\"name\":\"雨痕\",\"readonly\":true}"),
                ["xml"] = Encoding.UTF8.GetBytes("<?xml version=\"1.0\" encoding=\"utf-8\"?><root><name>雨痕</name></root>"),
                ["yaml"] = Encoding.UTF8.GetBytes("name: 雨痕\nreadonly: true\n"),
                ["yml"] = Encoding.UTF8.GetBytes("formats:\n  - ntfs\n  - exfat\n")
            };
            foreach (var fixture in textIntegrityFixtures)
            {
                var validPath = Path.Combine(imageDir, $"valid-text.{fixture.Key}");
                var damagedPath = Path.Combine(imageDir, $"damaged-text.{fixture.Key}");
                await File.WriteAllBytesAsync(validPath, fixture.Value);
                var damaged = fixture.Key switch
                {
                    "json" => Encoding.UTF8.GetBytes("{\"name\": [}"),
                    "xml" => Encoding.UTF8.GetBytes("<root><item></root>"),
                    "csv" => Encoding.UTF8.GetBytes("name,value\r\n\"unclosed,1\r\n"),
                    _ => Enumerable.Repeat((byte)0, 128).ToArray()
                };
                await File.WriteAllBytesAsync(damagedPath, damaged);
                Assert((await FileIntegrityValidator.ValidateAsync(validPath)).State == FileIntegrityState.Valid, $"valid {fixture.Key} text integrity");
                Assert((await FileIntegrityValidator.ValidateAsync(damagedPath)).State == FileIntegrityState.Damaged, $"damaged {fixture.Key} text integrity");
                await using var fixtureSource = new ImageBlockDevice(validPath);
                var fixtureCandidate = new RecoveryCandidate
                {
                    Name = Path.GetFileName(validPath), OriginalPath = Path.GetFileName(validPath),
                    Size = (ulong)fixture.Value.Length, IsDeleted = true, SourceOffset = 0
                };
                Assert((await FileIntegrityValidator.ValidateCandidateAsync(fixtureSource, fixtureCandidate)).State == FileIntegrityState.Valid,
                    $"valid {fixture.Key} text preflight");
            }
            lines.Add("PASS TXT/CSV/LOG/INI/MD/JSON/XML/YAML text preflight handles UTF-8, UTF-16 and GB18030 and rejects binary or malformed structured text");

            var damagedJpegPath = Path.Combine(imageDir, "damaged-jpeg-overwritten-header.jpg");
            var damagedJpeg = BuildSalvageableJpeg(512, 555, 985);
            await File.WriteAllBytesAsync(damagedJpegPath, damagedJpeg);
            var originalDamagedHash = await FileSha256Async(damagedJpegPath);
            var salvage = await JpegSalvager.TrySalvageAsync(damagedJpegPath);
            Assert(salvage.State == JpegSalvageState.Salvaged && salvage.OutputPath is not null, "JPEG marker-chain salvage succeeds");
            Assert(salvage.Width == 555 && salvage.Height == 985 && salvage.PreservedFromOffset == 512, "JPEG salvage dimensions and preserved offset");
            Assert(await FileSha256Async(damagedJpegPath) == originalDamagedHash, "JPEG salvage never modifies damaged original");
            Assert((await FileIntegrityValidator.ValidateAsync(salvage.OutputPath!)).State == FileIntegrityState.Valid, "salvaged JPEG validates");
            var secondSalvage = await JpegSalvager.TrySalvageAsync(damagedJpegPath);
            Assert(secondSalvage.State == JpegSalvageState.Salvaged && secondSalvage.OutputPath != salvage.OutputPath,
                "JPEG salvage uses non-overwriting unique sidecar names");
            await using (var damagedJpegSource = new ImageBlockDevice(damagedJpegPath))
            {
                var candidate = new RecoveryCandidate { Name = "damaged.jpg", OriginalPath = "damaged.jpg", Size = (ulong)damagedJpeg.Length, IsDeleted = true, SourceOffset = 0 };
                var recovery = await RecoveryWriter.RecoverRawAsync(damagedJpegSource, candidate, Path.Combine(outputDir, "jpeg-salvage"));
                Assert(recovery.Integrity == FileIntegrityState.Damaged && recovery.Salvage?.State == JpegSalvageState.Salvaged && recovery.Usable,
                    "recovery pipeline automatically creates usable JPEG salvage sidecar");
            }
            lines.Add("PASS conservative JPEG marker-chain auto-salvage preserves original, emits unique valid sidecar and reports dimensions");

            await using var image = new ImageBlockDevice(imagePath);
            Assert(image.IsReadOnly, "image device must be read-only");
            var partitions = await PartitionScanner.ScanAsync(image);
            Assert(partitions.Count == 1 && partitions[0].FileSystem == FileSystemKind.Ntfs, "whole-device NTFS detection");
            lines.Add("PASS partition and NTFS detection");

            var backupGptPath = Path.Combine(imageDir, "synthetic-backup-gpt.img");
            await BuildBackupGptImageAsync(backupGptPath, await File.ReadAllBytesAsync(imagePath));
            await using (var backupGptImage = new ImageBlockDevice(backupGptPath))
            {
                var backupGptPartitions = await PartitionScanner.ScanAsync(backupGptImage);
                Assert(backupGptPartitions.Count == 1 && backupGptPartitions[0].IsGpt &&
                       backupGptPartitions[0].Offset == 2048UL * SectorSize &&
                       backupGptPartitions[0].Name.Contains("GPT备份表", StringComparison.Ordinal),
                    "invalid primary GPT falls back to the CRC-valid backup GPT");
            }
            lines.Add("PASS damaged primary GPT automatically falls back to the backup header and entry table");

            await using (var pausable = new PausableBlockDevice(new ImageBlockDevice(imagePath)))
            {
                pausable.Pause();
                var pausedBuffer = new byte[512];
                var pendingRead = pausable.ReadAsync(0, pausedBuffer).AsTask();
                await Task.Delay(50);
                Assert(!pendingRead.IsCompleted, "paused block read must wait");
                pausable.Resume();
                Assert(await pendingRead == 512, "resumed block read");
            }
            lines.Add("PASS pause/resume preserves a pending read without restarting");

            var bootBytes = new byte[512];
            await image.ReadExactlyAsync(0, bootBytes);
            var boot = NtfsBootSector.Parse(bootBytes);
            Assert(boot.ClusterSize == ClusterSize && boot.FileRecordSize == RecordSize, "NTFS geometry");
            var native4KnBootBytes = bootBytes.ToArray();
            BinaryPrimitives.WriteUInt16LittleEndian(native4KnBootBytes.AsSpan(11, 2), 4096);
            native4KnBootBytes[13] = 1;
            native4KnBootBytes[64] = unchecked((byte)-10);
            var native4KnBoot = NtfsBootSector.Parse(native4KnBootBytes);
            Assert(native4KnBoot.BytesPerSector == 4096 && native4KnBoot.ClusterSize == 4096 &&
                   native4KnBoot.FileRecordSize == 1024, "4Kn NTFS permits 1 KiB FILE records");

            var scan = await new NtfsScanner(image, 0).ScanAsync(new ScanOptions());
            var contentRanges = CandidateRangeIndex.BuildNtfs(scan.Candidates.Select(candidate => (candidate, scan)));
            Assert(scan.Candidates.Where(candidate => candidate.Extents.Count > 0 &&
                    candidate.Quality is not (RecoveryQuality.Overwritten or RecoveryQuality.TrimmedOrZeroed))
                .All(candidate => CandidateRangeIndex.Contains(contentRanges,
                    checked(scan.PartitionOffset + (ulong)candidate.Extents[0].LogicalCluster * scan.Boot.ClusterSize))),
                "NTFS content range index covers recoverable metadata candidates");
            var resident = scan.Candidates.Single(c => c.Name == "deleted-note.txt");
            var jpeg = scan.Candidates.Single(c => c.Name == "deleted-photo.jpg");
            var zeroed = scan.Candidates.Single(c => c.Name == "trimmed.bin");
            var overwritten = scan.Candidates.Single(c => c.Name == "reused.bin");
            Assert(resident.Quality == RecoveryQuality.Excellent, "resident quality");
            Assert(jpeg.Quality == RecoveryQuality.Good, "unallocated extent quality");
            Assert(zeroed.Quality == RecoveryQuality.TrimmedOrZeroed, "TRIM/zero quality");
            Assert(overwritten.Quality == RecoveryQuality.Overwritten, "allocated extent quality");
            lines.Add("PASS NTFS MFT scan and four quality branches");

            var ntfsBackupBootPath = Path.Combine(imageDir, "synthetic-ntfs-backup-boot.img");
            var ntfsBackupBytes = await File.ReadAllBytesAsync(imagePath);
            ntfsBackupBytes.AsSpan(0, SectorSize).CopyTo(ntfsBackupBytes.AsSpan(ntfsBackupBytes.Length - SectorSize));
            ntfsBackupBytes.AsSpan(3, 8).Clear();
            await File.WriteAllBytesAsync(ntfsBackupBootPath, ntfsBackupBytes);
            await using (var ntfsBackupImage = new ImageBlockDevice(ntfsBackupBootPath))
            {
                var known = await PartitionScanner.ScanAsync(ntfsBackupImage);
                var recovered = await PartitionScanner.FindLostPartitionsAsync(ntfsBackupImage, known);
                var recoveredPartition = recovered.Single(item => item.FileSystem == FileSystemKind.Ntfs);
                Assert(recoveredPartition.Offset == 0 && recoveredPartition.BootSectorOffset == (ulong)(ntfsBackupBytes.Length - SectorSize),
                    "NTFS backup boot sector reconstructs the original partition start");
                var recoveredScan = await new NtfsScanner(ntfsBackupImage, recoveredPartition.Offset,
                    bootSectorOffset: recoveredPartition.BootSectorOffset).ScanAsync(new ScanOptions());
                Assert(recoveredScan.Candidates.Any(item => item.Name == "deleted-note.txt"), "NTFS metadata scan works through the backup boot sector");
            }
            lines.Add("PASS damaged NTFS primary boot sector is located and scanned through the end-of-volume backup boot sector");

            Assert(scan.Candidates.All(c => c.Name != "原始报告.docx"), "ordinary MFT scan must not see stale records beyond valid length");
            var deepScan = await new NtfsScanner(image, 0).ScanAsync(new ScanOptions(DeepMetadataScan: true, DeepMetadataBytes: 512 * 1024));
            var deepFile = deepScan.Candidates.Single(c => c.Name == "原始报告.docx");
            Assert(deepFile.Discovery == RecoveryDiscovery.NtfsDeepMft, "deep discovery source");
            Assert(deepFile.OriginalPath == Path.Combine("旧项目", "原始报告.docx"), "deep original path reconstruction");
            Assert(deepFile.Quality == RecoveryQuality.Good, "deep candidate quality");
            Assert(deepScan.DeepRecordsExamined > 0 && deepScan.ParsedDeepRecords >= 2, "deep scan statistics");
            var deepRecovery = await RecoveryWriter.RecoverNtfsAsync(image, deepScan, deepFile,
                Path.Combine(outputDir, "deep-" + DateTime.UtcNow.ToString("yyyyMMdd-HHmmssfff")));
            Assert((await File.ReadAllBytesAsync(deepRecovery.OutputPath)).SequenceEqual(DeepPayload), "deep MFT recovery bytes");
            lines.Add("PASS deep MFT stale record scan, original Unicode path and recovery");

            Assert(deepScan.Candidates.All(c => c.Name != "年度数据.xlsx"), "near-MFT deep scan must not see remote stale records");
            var fullScan = await new NtfsScanner(image, 0).ScanAsync(new ScanOptions(FullDiskMetadataScan: true));
            var fullDiskFile = fullScan.Candidates.Single(c => c.Name == "年度数据.xlsx");
            Assert(fullDiskFile.Discovery == RecoveryDiscovery.NtfsFullDiskMft, "full disk discovery source");
            Assert(fullDiskFile.OriginalPath == Path.Combine("归档资料", "年度数据.xlsx"), "full disk original path reconstruction");
            Assert(fullScan.Candidates.Count(c => c.Name == "deleted-note.txt") == 1, "current MFT exclusion and deduplication");
            var fullDiskRecovery = await RecoveryWriter.RecoverNtfsAsync(image, fullScan, fullDiskFile,
                Path.Combine(outputDir, "full-mft-" + DateTime.UtcNow.ToString("yyyyMMdd-HHmmssfff")));
            Assert((await File.ReadAllBytesAsync(fullDiskRecovery.OutputPath)).SequenceEqual(FullDiskPayload), "full disk MFT recovery bytes");
            lines.Add("PASS full-volume remote MFT search, current-MFT exclusion and original path recovery");

            var recoveryRoot = Path.Combine(outputDir, "ntfs-" + DateTime.UtcNow.ToString("yyyyMMdd-HHmmssfff"));
            var recoveredResident = await RecoveryWriter.RecoverNtfsAsync(image, scan, resident, recoveryRoot);
            var recoveredJpeg = await RecoveryWriter.RecoverNtfsAsync(image, scan, jpeg, recoveryRoot);
            Assert(await File.ReadAllBytesAsync(recoveredResident.OutputPath) is var residentBytes && residentBytes.SequenceEqual(ResidentPayload), "resident recovery bytes");
            Assert(await File.ReadAllBytesAsync(recoveredJpeg.OutputPath) is var jpegBytes && jpegBytes.SequenceEqual(JpegPayload), "nonresident recovery bytes");
            Assert(recoveredResident.Sha256 == Sha256(ResidentPayload) && recoveredJpeg.Sha256 == Sha256(JpegPayload), "recovery hashes");
            lines.Add("PASS NTFS resident/nonresident recovery and SHA-256");

            Assert((await RecoveryPreview.ReadAsync(image, resident, scan)).SequenceEqual(ResidentPayload), "resident preview bytes");
            Assert((await RecoveryPreview.ReadAsync(image, jpeg, scan)).SequenceEqual(JpegPayload), "nonresident preview bytes");
            lines.Add("PASS read-only NTFS preview bytes");

            var streamedCandidates = new List<RecoveryCandidate>();
            var carved = await new SignatureCarver(image, candidateFound: streamedCandidates.Add).ScanAsync();
            Assert(streamedCandidates.Count == carved.Count && streamedCandidates.Count > 0, "signature candidates streamed during scan");
            var carvedJpeg = carved.FirstOrDefault(c => c.SourceOffset == 30UL * ClusterSize && c.Extension == "jpg");
            var carvedPng = carved.FirstOrDefault(c => c.Extension == "png");
            var carvedPdf = carved.FirstOrDefault(c => c.Extension == "pdf");
            var carvedDocx = carved.FirstOrDefault(c => c.Extension == "docx");
            var carvedBmp = carved.FirstOrDefault(c => c.Extension == "bmp");
            var carvedWebp = carved.FirstOrDefault(c => c.Extension == "webp");
            var carvedWav = carved.FirstOrDefault(c => c.Extension == "wav");
            var carvedMp4 = carved.FirstOrDefault(c => c.Extension == "mp4");
            Assert(carvedJpeg is not null && carvedPng is not null && carvedPdf is not null && carvedDocx is not null &&
                carvedBmp is not null && carvedWebp is not null && carvedWav is not null && carvedMp4 is not null, "signature families");
            var rawResult = await RecoveryWriter.RecoverRawAsync(image, carvedJpeg!, Path.Combine(outputDir, "raw-" + DateTime.UtcNow.ToString("yyyyMMdd-HHmmssfff")));
            Assert((await File.ReadAllBytesAsync(rawResult.OutputPath)).SequenceEqual(JpegPayload), "raw carving output");
            lines.Add("PASS JPG/PNG/PDF/DOCX/BMP/WEBP/WAV/MP4 carving, scan-time candidate streaming and raw recovery");

            var exFatImagePath = Path.Combine(imageDir, "synthetic-exfat.img");
            var exFatPayload = BuildSyntheticJpegWithTrailingData();
            await BuildExFatImageAsync(exFatImagePath, exFatPayload);
            await using var exFatImage = new ImageBlockDevice(exFatImagePath);
            var exFatPartitions = await PartitionScanner.ScanAsync(exFatImage);
            Assert(exFatPartitions.Count == 1 && exFatPartitions[0].FileSystem == FileSystemKind.ExFat, "whole-device exFAT detection");
            var tskBinDirectory = Path.Combine(Directory.GetCurrentDirectory(), "third_party", "runtime", "sleuthkit-4.15.0", "sleuthkit-4.15.0-win32", "bin");
            Assert(SleuthKitEngine.IsAvailable(tskBinDirectory), "bundled TSK engine is available");
            Assert((await SleuthKitEngine.GetVersionAsync(tskBinDirectory)).Contains("4.15.0", StringComparison.Ordinal), "bundled TSK version");
            var tskScan = await SleuthKitEngine.ScanDeletedAsync(tskBinDirectory, new SleuthKitScanOptions(exFatImagePath));
            var tskExFatFile = tskScan.Candidates.Single(candidate => candidate.OriginalPath == Path.Combine("相册", "假期照片.jpg"));
            Assert(tskScan.CompletedNormally && tskScan.DetectedEncoding == "GBK/CP936" && tskScan.Candidates.Count == 5,
                "TSK exFAT deleted metadata scan and Windows Unicode decoding");
            Assert(tskExFatFile.AlternateMetadataAddresses.Count == 1, "TSK duplicate metadata is collapsed but retained as alternate address");
            var tskPreview = await SleuthKitEngine.ReadPrefixAsync(tskBinDirectory, new SleuthKitScanOptions(exFatImagePath), tskExFatFile);
            Assert(tskPreview.SequenceEqual(exFatPayload), "TSK read-only preview bytes");
            var tskSamples = await SleuthKitEngine.ReadSamplesAsync(tskBinDirectory, new SleuthKitScanOptions(exFatImagePath), tskExFatFile);
            Assert(tskSamples.Sha256 == Sha256(exFatPayload) && tskSamples.BytesRead == (ulong)exFatPayload.Length,
                "TSK streamed content hash");
            var tskPreflight = await FileIntegrityValidator.ValidateSleuthKitCandidateAsync(
                tskBinDirectory, new SleuthKitScanOptions(exFatImagePath), tskExFatFile);
            Assert(tskPreflight.State == FileIntegrityState.Valid, "TSK preflight streams head/tail samples through icat");
            var tskRecovery = await RecoveryWriter.RecoverSleuthKitAsync(tskBinDirectory, new SleuthKitScanOptions(exFatImagePath), tskExFatFile,
                Path.Combine(outputDir, "tsk-exfat-" + DateTime.UtcNow.ToString("yyyyMMdd-HHmmssfff")));
            Assert(tskRecovery.Usable && tskRecovery.Sha256 == Sha256(exFatPayload) &&
                (await File.ReadAllBytesAsync(tskRecovery.OutputPath)).SequenceEqual(exFatPayload), "TSK icat exact recovery bytes and validation");
            var tskFallbackCandidate = new SleuthKitCandidate("268", "备用恢复.jpg", (ulong)exFatPayload.Length, false, null)
            {
                AlternateMetadataAddresses = [tskExFatFile.MetadataAddress]
            };
            var tskFallbackRecovery = await RecoveryWriter.RecoverSleuthKitAsync(tskBinDirectory, new SleuthKitScanOptions(exFatImagePath),
                tskFallbackCandidate, Path.Combine(outputDir, "tsk-fallback-" + DateTime.UtcNow.ToString("yyyyMMdd-HHmmssfff")));
            Assert(tskFallbackRecovery.Usable && tskFallbackRecovery.Sha256 == Sha256(exFatPayload) &&
                tskFallbackRecovery.IntegrityMessage.Contains("备用元数据地址", StringComparison.Ordinal), "TSK damaged primary automatically switches to valid alternate metadata");
            lines.Add("PASS Sleuth Kit 4.15.0 streaming scan, Unicode paths, preview/preflight, duplicate collapse, alternate fallback and exact recovery");
            var exFatScan = await new ExFatScanner(exFatImage, 0).ScanAsync();
            Assert(exFatScan.Candidates.All(candidate => candidate.Name != "孤立照片.png"), "ordinary exFAT directory traversal must not see orphan entry set");
            Assert(exFatScan.Candidates.Count(candidate => candidate.Name == "假期照片.jpg") == 1,
                "ordinary exFAT metadata deduplicates repeated directory entry sets that point to the same payload");
            var exFatFile = exFatScan.Candidates.Single(candidate => candidate.Name == "假期照片.jpg");
            Assert(exFatFile.DuplicateRecordCount == 2 && exFatFile.AlternateCandidates.Count == 1,
                "exFAT logical deduplication retains an alternate physical copy for recovery fallback");
            var exFatOverwritten = exFatScan.Candidates.Single(candidate => candidate.Name == "已覆盖.jpg");
            var exFatFragmented = exFatScan.Candidates.Single(candidate => candidate.Name == "碎片数据.bin");
            var exFatMissingChain = exFatScan.Candidates.Single(candidate => candidate.Name == "仅剩文件名.bin");
            Assert(exFatFile.OriginalPath == Path.Combine("相册", "假期照片.jpg"), "exFAT original Unicode path");
            Assert(exFatFile.Size == (ulong)exFatPayload.Length && exFatFile.Discovery == RecoveryDiscovery.ExFatMetadata, "exFAT exact metadata length and source");
            Assert(exFatFile.Quality == RecoveryQuality.Good && exFatOverwritten.Quality == RecoveryQuality.Overwritten, "exFAT allocation bitmap quality");
            Assert(exFatFragmented.Extents.Count == 2 && exFatFragmented.Quality == RecoveryQuality.Good, "exFAT fragmented FAT chain");
            Assert(exFatMissingChain.Quality == RecoveryQuality.Poor && exFatMissingChain.Extents.Count == 0, "exFAT missing deleted FAT chain still preserves name");
            var exFatRecovery = await RecoveryWriter.RecoverExFatAsync(exFatImage, exFatScan, exFatFile,
                Path.Combine(outputDir, "exfat-" + DateTime.UtcNow.ToString("yyyyMMdd-HHmmssfff")));
            Assert((await File.ReadAllBytesAsync(exFatRecovery.OutputPath)).SequenceEqual(exFatPayload), "exFAT exact recovery bytes including JPEG trailer");
            Assert(exFatRecovery.Sha256 == Sha256(exFatPayload), "exFAT recovery SHA-256");
            Assert(exFatRecovery.Integrity == FileIntegrityState.Valid && exFatRecovery.Usable, "exFAT recovered JPEG integrity");
            Assert((await RecoveryPreview.ReadAsync(exFatImage, exFatFile, exFat: exFatScan)).SequenceEqual(exFatPayload), "exFAT preview bytes");
            var fragmentedPayload = BuildFragmentedExFatPayload();
            var fragmentedRecovery = await RecoveryWriter.RecoverExFatAsync(exFatImage, exFatScan, exFatFragmented,
                Path.Combine(outputDir, "exfat-fragmented-" + DateTime.UtcNow.ToString("yyyyMMdd-HHmmssfff")));
            Assert((await File.ReadAllBytesAsync(fragmentedRecovery.OutputPath)).SequenceEqual(fragmentedPayload), "exFAT fragmented recovery bytes");
            lines.Add("PASS exFAT deleted Unicode name/path, exact length, contiguous/FAT-chain recovery and bitmap quality");

            var exFatBackupBootPath = Path.Combine(imageDir, "synthetic-exfat-backup-boot.img");
            var exFatBackupBytes = await File.ReadAllBytesAsync(exFatImagePath);
            exFatBackupBytes.AsSpan(0, SectorSize).CopyTo(exFatBackupBytes.AsSpan(12 * SectorSize, SectorSize));
            exFatBackupBytes.AsSpan(3, 8).Clear();
            await File.WriteAllBytesAsync(exFatBackupBootPath, exFatBackupBytes);
            await using (var exFatBackupImage = new ImageBlockDevice(exFatBackupBootPath))
            {
                var known = await PartitionScanner.ScanAsync(exFatBackupImage);
                var recovered = await PartitionScanner.FindLostPartitionsAsync(exFatBackupImage, known);
                var recoveredPartition = recovered.Single(item => item.FileSystem == FileSystemKind.ExFat);
                Assert(recoveredPartition.Offset == 0 && recoveredPartition.BootSectorOffset == 12UL * SectorSize,
                    "exFAT backup boot region reconstructs the original partition start");
                var recoveredScan = await new ExFatScanner(exFatBackupImage, recoveredPartition.Offset,
                    bootSectorOffset: recoveredPartition.BootSectorOffset).ScanAsync();
                Assert(recoveredScan.Candidates.Any(item => item.Name == "假期照片.jpg"), "exFAT metadata scan works through the backup boot region");
            }
            lines.Add("PASS damaged exFAT primary boot sector is located and scanned through the backup boot region");

            var exFatDeepScan = await new ExFatScanner(exFatImage, 0).ScanAsync(new ScanOptions(ExFatDeepMetadataScan: true));
            var orphanExFat = exFatDeepScan.Candidates.Single(candidate => candidate.Name == "孤立照片.png");
            Assert(orphanExFat.Discovery == RecoveryDiscovery.ExFatDeepMetadata && orphanExFat.OriginalPath == Path.Combine("exFAT 深度扫描", "孤立照片.png"),
                "deep exFAT orphan metadata discovery");
            Assert(exFatDeepScan.Candidates.Count(candidate => candidate.Name == "假期照片.jpg") == 1, "deep exFAT deduplication");
            var orphanPreflight = await FileIntegrityValidator.ValidateCandidateAsync(exFatImage, orphanExFat, exFat: exFatDeepScan);
            Assert(orphanPreflight.State == FileIntegrityState.Valid, "deep exFAT candidate preflight integrity");
            var orphanRecovery = await RecoveryWriter.RecoverExFatAsync(exFatImage, exFatDeepScan, orphanExFat,
                Path.Combine(outputDir, "exfat-deep-" + DateTime.UtcNow.ToString("yyyyMMdd-HHmmssfff")));
            Assert(orphanRecovery.Usable && (await File.ReadAllBytesAsync(orphanRecovery.OutputPath)).SequenceEqual(ValidPngPayload), "deep exFAT orphan recovery");
            lines.Add("PASS exFAT whole-volume deep metadata finds an orphan Unicode record, deduplicates and recovers a preflight-valid PNG");

            var fat32ImagePath = Path.Combine(imageDir, "synthetic-fat32.img");
            var fat32Payload = Enumerable.Range(0, 900).Select(index => checked((byte)(index * 17 % 251))).ToArray();
            await BuildFat32ImageAsync(fat32ImagePath, fat32Payload);
            await using var fat32Image = new ImageBlockDevice(fat32ImagePath);
            var fat32Partitions = await PartitionScanner.ScanAsync(fat32Image);
            Assert(fat32Partitions.Count == 1 && fat32Partitions[0].FileSystem == FileSystemKind.Fat32, "whole-device FAT32 detection");
            var fat32Scan = await new Fat32Scanner(fat32Image, 0).ScanAsync();
            var fat32File = fat32Scan.Candidates.Single(candidate => candidate.Name == "假期照片.jpg");
            Assert(fat32File.OriginalPath == Path.Combine("相册", "假期照片.jpg"), "FAT32 deleted LFN and parent path");
            Assert(fat32File.Quality == RecoveryQuality.Partial && fat32File.Extents.Count == 2, "FAT32 cleared-chain contiguous inference");
            Assert((await RecoveryPreview.ReadAsync(fat32Image, fat32File, fat32: fat32Scan)).SequenceEqual(fat32Payload), "FAT32 preview bytes");
            var fat32Recovery = await RecoveryWriter.RecoverFat32Async(fat32Image, fat32Scan, fat32File,
                Path.Combine(outputDir, "fat32-" + DateTime.UtcNow.ToString("yyyyMMdd-HHmmssfff")));
            Assert((await File.ReadAllBytesAsync(fat32Recovery.OutputPath)).SequenceEqual(fat32Payload), "FAT32 recovery bytes");
            lines.Add("PASS FAT32 deleted Unicode LFN/path, cleared-chain inference, preview and recovery");

            var lostPartitionImagePath = Path.Combine(imageDir, "synthetic-lost-partition.img");
            var lostDisk = new byte[10 * 1024 * 1024];
            (await File.ReadAllBytesAsync(fat32ImagePath)).CopyTo(lostDisk, 1024 * 1024);
            await File.WriteAllBytesAsync(lostPartitionImagePath, lostDisk);
            await using var lostImage = new ImageBlockDevice(lostPartitionImagePath);
            var knownLostImageRanges = await PartitionScanner.ScanAsync(lostImage);
            var lostPartitions = await PartitionScanner.FindLostPartitionsAsync(lostImage, knownLostImageRanges);
            Assert(lostPartitions.Count == 1 && lostPartitions[0].Offset == 1024UL * 1024 && lostPartitions[0].FileSystem == FileSystemKind.Fat32,
                "lost FAT32 boot-sector discovery");
            lines.Add("PASS lost partition discovery by validated FAT32 boot sector");

            var clonePath = Path.Combine(imageDir, "synthetic-ntfs-clone.img");
            var imaging = await new DiskImager(image).CreateImageAsync(clonePath);
            Assert(imaging.Complete && imaging.ReadErrors == 0, "disk imaging completion");
            Assert(imaging.Sha256 == await FileSha256Async(imagePath), "disk image checksum");
            var resumedImaging = await new DiskImager(image).CreateImageAsync(clonePath);
            Assert(resumedImaging.Complete && resumedImaging.Sha256 == imaging.Sha256, "disk imaging checkpoint resume");
            lines.Add("PASS read-only disk imaging, checkpoint resume and SHA-256");

            await TestLargeDiskMathAsync();
            lines.Add("PASS 16 TiB-class GPT and 64-bit offset arithmetic");
            lines.Add($"Finished UTC: {DateTime.UtcNow:O}");
            lines.Add("RESULT: ALL TESTS PASSED");
            await File.WriteAllLinesAsync(logPath, lines, Encoding.UTF8);
            Console.WriteLine(string.Join(Environment.NewLine, lines));
            return 0;
        }
        catch (Exception ex)
        {
            lines.Add("RESULT: FAILED");
            lines.Add(ex.ToString());
            await File.WriteAllLinesAsync(logPath, lines, Encoding.UTF8);
            Console.Error.WriteLine(string.Join(Environment.NewLine, lines));
            return 1;
        }
    }

    private static async Task<string> HashDeviceRangeAsync(IBlockDevice device, ulong offset, ulong length)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var buffer = new byte[1024 * 1024];
        ulong processed = 0;
        while (processed < length)
        {
            var count = checked((int)Math.Min((ulong)buffer.Length, length - processed));
            await device.ReadExactlyAsync(offset + processed, buffer.AsMemory(0, count));
            hash.AppendData(buffer.AsSpan(0, count));
            processed += checked((ulong)count);
        }
        return Convert.ToHexString(hash.GetHashAndReset());
    }

    private static async Task BuildExFatImageAsync(string path, byte[] payload)
    {
        const int imageSize = 8 * 1024 * 1024;
        const int fatOffsetSectors = 24;
        const int fatLengthSectors = 8;
        const int heapOffsetSectors = 128;
        const int clusterCount = 1000;
        var bytes = new byte[imageSize];
        var boot = bytes.AsSpan(0, 512);
        boot[0] = 0xEB; boot[1] = 0x76; boot[2] = 0x90;
        "EXFAT   "u8.CopyTo(boot[3..]);
        BinaryPrimitives.WriteUInt64LittleEndian(boot[72..80], imageSize / 512);
        BinaryPrimitives.WriteUInt32LittleEndian(boot[80..84], fatOffsetSectors);
        BinaryPrimitives.WriteUInt32LittleEndian(boot[84..88], fatLengthSectors);
        BinaryPrimitives.WriteUInt32LittleEndian(boot[88..92], heapOffsetSectors);
        BinaryPrimitives.WriteUInt32LittleEndian(boot[92..96], clusterCount);
        BinaryPrimitives.WriteUInt32LittleEndian(boot[96..100], 2);
        BinaryPrimitives.WriteUInt16LittleEndian(boot[104..106], 0x0100);
        boot[108] = 9;
        boot[109] = 3;
        boot[110] = 1;
        boot[510] = 0x55; boot[511] = 0xAA;

        var fat = bytes.AsSpan(fatOffsetSectors * 512, fatLengthSectors * 512);
        BinaryPrimitives.WriteUInt32LittleEndian(fat[0..4], 0xFFFFFFF8);
        BinaryPrimitives.WriteUInt32LittleEndian(fat[4..8], uint.MaxValue);
        BinaryPrimitives.WriteUInt32LittleEndian(fat[8..12], uint.MaxValue);  // root cluster 2
        BinaryPrimitives.WriteUInt32LittleEndian(fat[12..16], uint.MaxValue); // bitmap cluster 3
        BinaryPrimitives.WriteUInt32LittleEndian(fat.Slice(12 * 4, 4), 14);   // fragmented file: 12 -> 14
        BinaryPrimitives.WriteUInt32LittleEndian(fat.Slice(14 * 4, 4), uint.MaxValue);

        var heapOffset = heapOffsetSectors * 512;
        var root = bytes.AsSpan(heapOffset, ClusterSize);
        root[0] = 0x81;
        BinaryPrimitives.WriteUInt32LittleEndian(root[20..24], 3);
        BinaryPrimitives.WriteUInt64LittleEndian(root[24..32], (clusterCount + 7) / 8);
        var directorySet = BuildExFatEntrySet("相册", true, true, 4, ClusterSize, true);
        directorySet.CopyTo(root[32..]);

        var bitmap = bytes.AsSpan(heapOffset + ClusterSize, ClusterSize);
        bitmap[0] = 0b0000_0111; // root 2, bitmap 3, directory 4 allocated
        bitmap[1] |= 1 << 1;     // cluster 11 is allocated/reused

        var directory = bytes.AsSpan(heapOffset + 2 * ClusterSize, ClusterSize); // cluster 4
        var deletedSet = BuildExFatEntrySet("假期照片.jpg", false, false, 10, (ulong)payload.Length, true);
        deletedSet.CopyTo(directory);
        var overwrittenSet = BuildExFatEntrySet("已覆盖.jpg", false, false, 11, (ulong)payload.Length, true);
        overwrittenSet.CopyTo(directory[deletedSet.Length..]);
        var fragmentedPayload = BuildFragmentedExFatPayload();
        var fragmentedSet = BuildExFatEntrySet("碎片数据.bin", false, false, 12, (ulong)fragmentedPayload.Length, false);
        fragmentedSet.CopyTo(directory[(deletedSet.Length + overwrittenSet.Length)..]);
        var missingChainSet = BuildExFatEntrySet("仅剩文件名.bin", false, false, 16, 5000, false);
        missingChainSet.CopyTo(directory[(deletedSet.Length + overwrittenSet.Length + fragmentedSet.Length)..]);
        // Simulate stale records left by repeated copy/delete cycles. This second record has the
        // same logical identity but points at a different physical copy, which must be grouped in
        // the UI while remaining available as a recovery fallback.
        var duplicateDeletedSet = BuildExFatEntrySet("假期照片.jpg", false, false, 18, (ulong)payload.Length, true);
        duplicateDeletedSet.CopyTo(directory[(deletedSet.Length + overwrittenSet.Length + fragmentedSet.Length + missingChainSet.Length)..]);
        payload.CopyTo(bytes.AsSpan(heapOffset + 8 * ClusterSize)); // cluster 10
        payload.CopyTo(bytes.AsSpan(heapOffset + 9 * ClusterSize)); // cluster 11
        payload.CopyTo(bytes.AsSpan(heapOffset + 16 * ClusterSize)); // alternate copy: cluster 18
        fragmentedPayload.AsSpan(0, ClusterSize).CopyTo(bytes.AsSpan(heapOffset + 10 * ClusterSize)); // cluster 12
        fragmentedPayload.AsSpan(ClusterSize).CopyTo(bytes.AsSpan(heapOffset + 12 * ClusterSize));    // cluster 14
        var orphanSet = BuildExFatEntrySet("孤立照片.png", false, false, 22, (ulong)ValidPngPayload.Length, true);
        orphanSet.CopyTo(bytes.AsSpan(heapOffset + 18 * ClusterSize)); // orphan directory data in cluster 20
        ValidPngPayload.CopyTo(bytes.AsSpan(heapOffset + 20 * ClusterSize)); // cluster 22
        await File.WriteAllBytesAsync(path, bytes);
    }

    private static async Task BuildFat32ImageAsync(string path, byte[] payload)
    {
        const int bytesPerSector = 512, reservedSectors = 32, fatSectors = 128, totalSectors = 16384;
        var bytes = new byte[totalSectors * bytesPerSector];
        var boot = bytes.AsSpan(0, 512);
        boot[0] = 0xEB; boot[1] = 0x58; boot[2] = 0x90; "MSWIN4.1"u8.CopyTo(boot[3..]);
        BinaryPrimitives.WriteUInt16LittleEndian(boot[11..13], bytesPerSector); boot[13] = 1;
        BinaryPrimitives.WriteUInt16LittleEndian(boot[14..16], reservedSectors); boot[16] = 1;
        BinaryPrimitives.WriteUInt32LittleEndian(boot[32..36], totalSectors);
        BinaryPrimitives.WriteUInt32LittleEndian(boot[36..40], fatSectors);
        BinaryPrimitives.WriteUInt32LittleEndian(boot[44..48], 2); "FAT32   "u8.CopyTo(boot[82..]); boot[510] = 0x55; boot[511] = 0xAA;
        var fat = bytes.AsSpan(reservedSectors * bytesPerSector, fatSectors * bytesPerSector);
        BinaryPrimitives.WriteUInt32LittleEndian(fat[0..4], 0x0FFFFFF8); BinaryPrimitives.WriteUInt32LittleEndian(fat[4..8], 0x0FFFFFFF);
        BinaryPrimitives.WriteUInt32LittleEndian(fat[8..12], 0x0FFFFFFF); BinaryPrimitives.WriteUInt32LittleEndian(fat[12..16], 0x0FFFFFFF);
        var dataOffset = (reservedSectors + fatSectors) * bytesPerSector;
        WriteFatDirectorySet(bytes.AsSpan(dataOffset, 512), 0, "相册", "ALBUM      ", false, true, 3, 0);
        WriteFatDirectorySet(bytes.AsSpan(dataOffset + 512, 512), 0, "假期照片.jpg", "HOLIDAY JPG", true, false, 5, (uint)payload.Length);
        payload.CopyTo(bytes.AsSpan(dataOffset + 3 * 512));
        await File.WriteAllBytesAsync(path, bytes);
    }

    private static void WriteFatDirectorySet(Span<byte> directory, int offset, string longName, string shortName11,
        bool deleted, bool isDirectory, uint firstCluster, uint size)
    {
        var chunks = Enumerable.Range(0, (longName.Length + 12) / 13).Select(index => longName.Skip(index * 13).Take(13).ToArray()).ToArray();
        var cursor = offset;
        for (var sequence = chunks.Length; sequence >= 1; sequence--)
        {
            var entry = directory.Slice(cursor, 32); entry.Clear();
            entry[0] = deleted ? (byte)0xE5 : checked((byte)(sequence | (sequence == chunks.Length ? 0x40 : 0)));
            entry[11] = 0x0F;
            var chars = chunks[sequence - 1].Concat(new[] { '\0' }).Concat(Enumerable.Repeat('\uffff', 13)).Take(13).ToArray();
            var encoded = Encoding.Unicode.GetBytes(chars);
            encoded.AsSpan(0, 10).CopyTo(entry[1..11]); encoded.AsSpan(10, 12).CopyTo(entry[14..26]); encoded.AsSpan(22, 4).CopyTo(entry[28..32]);
            cursor += 32;
        }
        var shortEntry = directory.Slice(cursor, 32); shortEntry.Clear();
        Encoding.ASCII.GetBytes(shortName11.PadRight(11)[..11]).CopyTo(shortEntry);
        if (deleted) shortEntry[0] = 0xE5;
        shortEntry[11] = isDirectory ? (byte)0x10 : (byte)0x20;
        BinaryPrimitives.WriteUInt16LittleEndian(shortEntry[20..22], checked((ushort)(firstCluster >> 16)));
        BinaryPrimitives.WriteUInt16LittleEndian(shortEntry[26..28], checked((ushort)firstCluster));
        BinaryPrimitives.WriteUInt32LittleEndian(shortEntry[28..32], size);
    }

    private static byte[] BuildExFatEntrySet(string name, bool inUse, bool directory, uint firstCluster, ulong dataLength, bool noFatChain)
    {
        var nameBytes = Encoding.Unicode.GetBytes(name);
        var nameEntries = (name.Length + 14) / 15;
        var set = new byte[(2 + nameEntries) * 32];
        set[0] = 0x85;
        set[1] = checked((byte)(1 + nameEntries));
        BinaryPrimitives.WriteUInt16LittleEndian(set.AsSpan(4, 2), directory ? (ushort)0x10 : (ushort)0x20);
        BinaryPrimitives.WriteUInt32LittleEndian(set.AsSpan(12, 4), EncodeExFatTimestamp(new DateTime(2026, 8, 19, 9, 0, 0)));
        set[32] = 0xC0;
        set[33] = checked((byte)(0x01 | (noFatChain ? 0x02 : 0)));
        set[35] = checked((byte)name.Length);
        BinaryPrimitives.WriteUInt64LittleEndian(set.AsSpan(40, 8), dataLength);
        BinaryPrimitives.WriteUInt32LittleEndian(set.AsSpan(52, 4), firstCluster);
        BinaryPrimitives.WriteUInt64LittleEndian(set.AsSpan(56, 8), dataLength);
        for (var index = 0; index < nameEntries; index++)
        {
            var entryOffset = 64 + index * 32;
            set[entryOffset] = 0xC1;
            var sourceOffset = index * 30;
            var count = Math.Min(30, nameBytes.Length - sourceOffset);
            nameBytes.AsSpan(sourceOffset, count).CopyTo(set.AsSpan(entryOffset + 2, count));
        }
        BinaryPrimitives.WriteUInt16LittleEndian(set.AsSpan(2, 2), ComputeExFatSetChecksum(set));
        if (!inUse)
            for (var offset = 0; offset < set.Length; offset += 32) set[offset] &= 0x7F;
        return set;
    }

    private static ushort ComputeExFatSetChecksum(ReadOnlySpan<byte> set)
    {
        ushort checksum = 0;
        for (var index = 0; index < set.Length; index++)
        {
            if (index is 2 or 3) continue;
            checksum = (ushort)(((checksum & 1) != 0 ? 0x8000 : 0) + (checksum >> 1) + set[index]);
        }
        return checksum;
    }

    private static uint EncodeExFatTimestamp(DateTime value) =>
        checked((uint)((value.Year - 1980) << 25 | value.Month << 21 | value.Day << 16 | value.Hour << 11 | value.Minute << 5 | value.Second / 2));

    private static byte[] BuildSyntheticJpegWithTrailingData()
    {
        var bytes = new List<byte>([0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10]);
        bytes.AddRange(Encoding.ASCII.GetBytes("JFIF-SYNTHETIC"));
        bytes.AddRange([0xFF, 0xDA, 0x00, 0x08, 1, 2, 3, 4, 5, 6, 10, 20, 30, 0xFF, 0x00, 40, 0xFF, 0xD9]);
        bytes.AddRange(Encoding.ASCII.GetBytes("24-byte-trailer-padding!"));
        return [.. bytes];
    }

    private static byte[] BuildSalvageableJpeg(int overwrittenPrefix, ushort width, ushort height)
    {
        var bytes = new List<byte>(new byte[overwrittenPrefix]);
        bytes.AddRange([0xFF, 0xDB, 0x00, 0x43, 0x00]);
        bytes.AddRange(Enumerable.Repeat((byte)1, 64));
        bytes.AddRange([0xFF, 0xC0, 0x00, 0x11, 0x08, (byte)(height >> 8), (byte)height,
            (byte)(width >> 8), (byte)width, 0x03, 0x01, 0x11, 0x00, 0x02, 0x11, 0x00, 0x03, 0x11, 0x00]);
        bytes.AddRange([0xFF, 0xC4, 0x00, 0x14]);
        bytes.AddRange(Enumerable.Repeat((byte)0, 18));
        bytes.AddRange([0xFF, 0xDA, 0x00, 0x0C, 0x03, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x00, 0x3F, 0x00]);
        bytes.AddRange([0x11, 0x22, 0xFF, 0x00, 0x33, 0x44, 0xFF, 0xD9]);
        return [.. bytes];
    }

    private static byte[] BuildFragmentedExFatPayload() =>
        Enumerable.Range(0, 5000).Select(index => checked((byte)(index * 31 % 251 + 1))).ToArray();

    private static async Task BuildNtfsImageAsync(string path)
    {
        const int imageSize = 2 * 1024 * 1024;
        var bytes = new byte[imageSize];
        var boot = bytes.AsSpan(0, SectorSize);
        boot[0] = 0xeb; boot[1] = 0x52; boot[2] = 0x90;
        "NTFS    "u8.CopyTo(boot[3..]);
        BinaryPrimitives.WriteUInt16LittleEndian(boot[11..13], SectorSize);
        boot[13] = ClusterSize / SectorSize;
        BinaryPrimitives.WriteUInt64LittleEndian(boot[40..48], imageSize / SectorSize);
        BinaryPrimitives.WriteInt64LittleEndian(boot[48..56], 4);
        BinaryPrimitives.WriteInt64LittleEndian(boot[56..64], 2);
        boot[64] = unchecked((byte)-10);
        boot[68] = 1;

        WriteRecord(bytes, 0, CreateRecord(0, true, false, "$MFT", 5, null, 4, 4, 16UL * RecordSize));
        WriteRecord(bytes, 5, CreateRecord(5, true, true, ".", 5, null, 0, 0, 0));
        WriteRecord(bytes, 6, CreateRecord(6, true, false, "$Bitmap", 5, null, 20, 1, 64));
        WriteRecord(bytes, 10, CreateRecord(10, false, false, "deleted-note.txt", 5, ResidentPayload, 0, 0, (ulong)ResidentPayload.Length));
        WriteRecord(bytes, 11, CreateRecord(11, false, false, "deleted-photo.jpg", 5, null, 30, 1, (ulong)JpegPayload.Length));
        WriteRecord(bytes, 12, CreateRecord(12, false, false, "trimmed.bin", 5, null, 31, 1, 128));
        WriteRecord(bytes, 13, CreateRecord(13, false, false, "reused.bin", 5, null, 32, 1, 128));
        WriteRecord(bytes, 40, CreateRecord(40, false, true, "旧项目", 5, null, 0, 0, 0));
        WriteRecord(bytes, 41, CreateRecord(41, false, false, "原始报告.docx", 40, null, 35, 1, (ulong)DeepPayload.Length));

        JpegPayload.CopyTo(bytes.AsSpan(30 * ClusterSize));
        DeepPayload.CopyTo(bytes.AsSpan(35 * ClusterSize));
        bytes[20 * ClusterSize + 4] |= 0x01; // cluster 32 is allocated

        byte[] png = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 1, 2, 3, 4, 0x49, 0x45, 0x4e, 0x44, 0xae, 0x42, 0x60, 0x82];
        png.CopyTo(bytes.AsSpan(40 * ClusterSize));
        Encoding.ASCII.GetBytes("%PDF-1.7\nsynthetic pdf\n%%EOF").CopyTo(bytes.AsSpan(41 * ClusterSize));
        var docx = BuildSyntheticDocxSignature();
        docx.CopyTo(bytes.AsSpan(42 * ClusterSize));
        BuildSyntheticBmp().CopyTo(bytes.AsSpan(60 * ClusterSize));
        BuildSyntheticRiff("WEBP").CopyTo(bytes.AsSpan(61 * ClusterSize));
        BuildSyntheticRiff("WAVE").CopyTo(bytes.AsSpan(62 * ClusterSize));
        BuildSyntheticMp4().CopyTo(bytes.AsSpan(63 * ClusterSize));
        const int remoteDirectoryOffset = 512 * 2501;
        CreateRecord(70, false, true, "归档资料", 5, null, 0, 0, 0).CopyTo(bytes.AsSpan(remoteDirectoryOffset));
        CreateRecord(71, false, false, "年度数据.xlsx", 70, null, 50, 1, (ulong)FullDiskPayload.Length)
            .CopyTo(bytes.AsSpan(remoteDirectoryOffset + RecordSize));
        FullDiskPayload.CopyTo(bytes.AsSpan(50 * ClusterSize));
        await File.WriteAllBytesAsync(path, bytes);
    }

    private static byte[] BuildSyntheticDocxSignature()
    {
        var content = new List<byte>([0x50, 0x4b, 0x03, 0x04]);
        content.AddRange(Encoding.ASCII.GetBytes("[Content_Types].xml........word/document.xml"));
        content.AddRange([0x50, 0x4b, 0x05, 0x06]);
        content.AddRange(new byte[18]);
        return [.. content];
    }

    private static byte[] BuildSyntheticXlsxSignature()
    {
        var content = new List<byte>([0x50, 0x4b, 0x03, 0x04]);
        content.AddRange(Encoding.ASCII.GetBytes("[Content_Types].xml........xl/workbook.xml"));
        content.AddRange([0x50, 0x4b, 0x05, 0x06]);
        content.AddRange(new byte[18]);
        return [.. content];
    }

    private static byte[] BuildSyntheticBmp()
    {
        var data = new byte[70]; data[0] = 0x42; data[1] = 0x4D;
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(2, 4), (uint)data.Length);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(10, 4), 54); BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(14, 4), 40);
        return data;
    }

    private static byte[] BuildSyntheticRiff(string family)
    {
        var data = new byte[32]; "RIFF"u8.CopyTo(data); BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(4, 4), 24);
        Encoding.ASCII.GetBytes(family).CopyTo(data, 8); return data;
    }

    private static byte[] BuildSyntheticMp4()
    {
        var data = new byte[44];
        BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(0, 4), 24); "ftyp"u8.CopyTo(data.AsSpan(4)); "isom"u8.CopyTo(data.AsSpan(8)); "isom"u8.CopyTo(data.AsSpan(16));
        BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(24, 4), 12); "mdat"u8.CopyTo(data.AsSpan(28));
        BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(36, 4), 8); "moov"u8.CopyTo(data.AsSpan(40));
        return data;
    }

    private static byte[] BuildSyntheticGif()
    {
        var data = new List<byte>(Encoding.ASCII.GetBytes("GIF89a"));
        data.AddRange([1, 0, 1, 0, 0, 0, 0]);
        data.Add(0x2C); data.AddRange([0, 0, 0, 0, 1, 0, 1, 0, 0]);
        data.AddRange([2, 2, 0x44, 0x01, 0, 0x3B]);
        return [.. data];
    }

    private static byte[] BuildSyntheticTiff()
    {
        var data = new byte[26]; "II"u8.CopyTo(data); BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(2, 2), 42);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(4, 4), 8); BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(8, 2), 1);
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(10, 2), 256); BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(12, 2), 4);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(14, 4), 1); BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(18, 4), 1);
        return data;
    }

    private static byte[] BuildSyntheticMp3()
    {
        const int frameLength = 417; var data = new byte[frameLength * 2];
        byte[] header = [0xFF, 0xFB, 0x90, 0x64]; header.CopyTo(data, 0); header.CopyTo(data, frameLength); return data;
    }

    private static byte[] BuildSyntheticAvi()
    {
        var data = new byte[32]; "RIFF"u8.CopyTo(data); BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(4, 4), 24); "AVI "u8.CopyTo(data.AsSpan(8));
        "LIST"u8.CopyTo(data.AsSpan(12)); BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(16, 4), 4); "hdrl"u8.CopyTo(data.AsSpan(20));
        "LIST"u8.CopyTo(data.AsSpan(24)); "movi"u8.CopyTo(data.AsSpan(28)); return data;
    }

    private static byte[] BuildSyntheticRar()
    {
        byte[] data = [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00, 0, 0, 0x73, 0, 0, 7, 0]; return data;
    }

    private static byte[] BuildSynthetic7Zip()
    {
        byte[] nextHeader = [0x01, 0x00]; var data = new byte[32 + nextHeader.Length];
        byte[] signature = [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C]; signature.CopyTo(data, 0); data[7] = 4;
        BinaryPrimitives.WriteUInt64LittleEndian(data.AsSpan(12, 8), 0); BinaryPrimitives.WriteUInt64LittleEndian(data.AsSpan(20, 8), (ulong)nextHeader.Length);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(28, 4), TestCrc32(nextHeader));
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(8, 4), TestCrc32(data.AsSpan(12, 20))); nextHeader.CopyTo(data, 32); return data;
    }

    private static byte[] BuildSyntheticCompoundDocument(string streamName)
    {
        var data = new byte[1024]; byte[] signature = [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]; signature.CopyTo(data, 0);
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(24, 2), 0x003E); BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(26, 2), 3);
        data[28] = 0xFE; data[29] = 0xFF; BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(30, 2), 9); BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(32, 2), 6);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(48, 4), 0); Encoding.Unicode.GetBytes(streamName).CopyTo(data, 512); return data;
    }

    private static async Task BuildBackupGptImageAsync(string path, byte[] partitionImage)
    {
        const int diskBytes = 16 * 1024 * 1024; const uint entryCount = 128; const uint entrySize = 128;
        var disk = new byte[diskBytes]; var totalLbas = (ulong)disk.Length / SectorSize; var lastLba = totalLbas - 1;
        disk[510] = 0x55; disk[511] = 0xAA; disk[446 + 4] = 0xEE;
        BinaryPrimitives.WriteUInt32LittleEndian(disk.AsSpan(446 + 8, 4), 1);
        BinaryPrimitives.WriteUInt32LittleEndian(disk.AsSpan(446 + 12, 4), checked((uint)Math.Min(totalLbas - 1, uint.MaxValue)));

        const ulong firstPartitionLba = 2048;
        var partitionSectors = checked((ulong)partitionImage.Length / SectorSize);
        var lastPartitionLba = firstPartitionLba + partitionSectors - 1;
        partitionImage.CopyTo(disk, checked((int)(firstPartitionLba * SectorSize)));

        var entries = new byte[entryCount * entrySize];
        new Guid("EBD0A0A2-B9E5-4433-87C0-68B6B72699C7").TryWriteBytes(entries.AsSpan(0, 16));
        Guid.NewGuid().TryWriteBytes(entries.AsSpan(16, 16));
        BinaryPrimitives.WriteUInt64LittleEndian(entries.AsSpan(32, 8), firstPartitionLba);
        BinaryPrimitives.WriteUInt64LittleEndian(entries.AsSpan(40, 8), lastPartitionLba);
        Encoding.Unicode.GetBytes("恢复测试分区").CopyTo(entries, 56);
        var entriesCrc = TestCrc32(entries);
        const ulong primaryEntriesLba = 2;
        var backupEntriesLba = lastLba - (ulong)entries.Length / SectorSize;
        entries.CopyTo(disk, checked((int)(primaryEntriesLba * SectorSize)));
        entries.CopyTo(disk, checked((int)(backupEntriesLba * SectorSize)));

        var diskGuid = Guid.NewGuid();
        var primary = BuildGptHeader(1, lastLba, primaryEntriesLba, entryCount, entrySize, entriesCrc, diskGuid, lastLba);
        var backup = BuildGptHeader(lastLba, 1, backupEntriesLba, entryCount, entrySize, entriesCrc, diskGuid, lastLba);
        primary[16] ^= 0x5A; // 保留签名和尺寸，但破坏主GPT头CRC，必须回退到备份表。
        primary.CopyTo(disk, SectorSize); backup.CopyTo(disk, checked((int)(lastLba * SectorSize)));
        await File.WriteAllBytesAsync(path, disk);
    }

    private static byte[] BuildGptHeader(ulong currentLba, ulong alternateLba, ulong entriesLba, uint entryCount,
        uint entrySize, uint entriesCrc, Guid diskGuid, ulong lastLba)
    {
        var header = new byte[SectorSize]; "EFI PART"u8.CopyTo(header);
        BinaryPrimitives.WriteUInt32LittleEndian(header.AsSpan(8, 4), 0x00010000);
        BinaryPrimitives.WriteUInt32LittleEndian(header.AsSpan(12, 4), 92);
        BinaryPrimitives.WriteUInt64LittleEndian(header.AsSpan(24, 8), currentLba);
        BinaryPrimitives.WriteUInt64LittleEndian(header.AsSpan(32, 8), alternateLba);
        BinaryPrimitives.WriteUInt64LittleEndian(header.AsSpan(40, 8), 34);
        BinaryPrimitives.WriteUInt64LittleEndian(header.AsSpan(48, 8), lastLba - 34);
        diskGuid.TryWriteBytes(header.AsSpan(56, 16));
        BinaryPrimitives.WriteUInt64LittleEndian(header.AsSpan(72, 8), entriesLba);
        BinaryPrimitives.WriteUInt32LittleEndian(header.AsSpan(80, 4), entryCount);
        BinaryPrimitives.WriteUInt32LittleEndian(header.AsSpan(84, 4), entrySize);
        BinaryPrimitives.WriteUInt32LittleEndian(header.AsSpan(88, 4), entriesCrc);
        BinaryPrimitives.WriteUInt32LittleEndian(header.AsSpan(16, 4), TestCrc32(header.AsSpan(0, 92)));
        return header;
    }

    private static uint TestCrc32(ReadOnlySpan<byte> bytes)
    {
        var crc = 0xFFFFFFFFu;
        foreach (var value in bytes)
        {
            crc ^= value;
            for (var bit = 0; bit < 8; bit++) crc = (crc & 1) != 0 ? (crc >> 1) ^ 0xEDB88320u : crc >> 1;
        }
        return ~crc;
    }

    private static byte[] CreateRecord(uint number, bool inUse, bool directory, string name, long parent, byte[]? resident, int lcn, int clusters, ulong realSize)
    {
        var record = new byte[RecordSize];
        "FILE"u8.CopyTo(record);
        BinaryPrimitives.WriteUInt16LittleEndian(record.AsSpan(4, 2), 0x30);
        BinaryPrimitives.WriteUInt16LittleEndian(record.AsSpan(6, 2), 3);
        BinaryPrimitives.WriteUInt16LittleEndian(record.AsSpan(16, 2), 1);
        BinaryPrimitives.WriteUInt16LittleEndian(record.AsSpan(20, 2), 0x38);
        BinaryPrimitives.WriteUInt16LittleEndian(record.AsSpan(22, 2), (ushort)((inUse ? 1 : 0) | (directory ? 2 : 0)));
        BinaryPrimitives.WriteUInt32LittleEndian(record.AsSpan(28, 4), RecordSize);
        BinaryPrimitives.WriteUInt32LittleEndian(record.AsSpan(44, 4), number);
        var offset = 0x38;
        offset += WriteFileNameAttribute(record.AsSpan(offset), name, parent, 1);
        if (!directory)
            offset += resident is not null
                ? WriteResidentDataAttribute(record.AsSpan(offset), resident, 2)
                : WriteNonResidentDataAttribute(record.AsSpan(offset), lcn, clusters, realSize, 2);
        BinaryPrimitives.WriteUInt32LittleEndian(record.AsSpan(offset, 4), uint.MaxValue);
        offset += 4;
        BinaryPrimitives.WriteUInt32LittleEndian(record.AsSpan(24, 4), (uint)offset);
        ApplyFixup(record);
        return record;
    }

    private static int WriteFileNameAttribute(Span<byte> attr, string name, long parent, ushort id)
    {
        var nameBytes = Encoding.Unicode.GetBytes(name);
        var valueLength = 66 + nameBytes.Length;
        var length = Align8(24 + valueLength);
        BinaryPrimitives.WriteUInt32LittleEndian(attr[0..4], 0x30);
        BinaryPrimitives.WriteUInt32LittleEndian(attr[4..8], (uint)length);
        BinaryPrimitives.WriteUInt16LittleEndian(attr[14..16], id);
        BinaryPrimitives.WriteUInt32LittleEndian(attr[16..20], (uint)valueLength);
        BinaryPrimitives.WriteUInt16LittleEndian(attr[20..22], 24);
        var value = attr.Slice(24, valueLength);
        BinaryPrimitives.WriteInt64LittleEndian(value[0..8], parent);
        BinaryPrimitives.WriteInt64LittleEndian(value[16..24], DateTime.UtcNow.ToFileTimeUtc());
        BinaryPrimitives.WriteUInt64LittleEndian(value[48..56], 0);
        value[64] = (byte)(nameBytes.Length / 2);
        value[65] = 1;
        nameBytes.CopyTo(value[66..]);
        return length;
    }

    private static int WriteResidentDataAttribute(Span<byte> attr, byte[] data, ushort id)
    {
        var length = Align8(24 + data.Length);
        BinaryPrimitives.WriteUInt32LittleEndian(attr[0..4], 0x80);
        BinaryPrimitives.WriteUInt32LittleEndian(attr[4..8], (uint)length);
        BinaryPrimitives.WriteUInt16LittleEndian(attr[14..16], id);
        BinaryPrimitives.WriteUInt32LittleEndian(attr[16..20], (uint)data.Length);
        BinaryPrimitives.WriteUInt16LittleEndian(attr[20..22], 24);
        data.CopyTo(attr[24..]);
        return length;
    }

    private static int WriteNonResidentDataAttribute(Span<byte> attr, int lcn, int clusters, ulong realSize, ushort id)
    {
        const int length = 72;
        BinaryPrimitives.WriteUInt32LittleEndian(attr[0..4], 0x80);
        BinaryPrimitives.WriteUInt32LittleEndian(attr[4..8], length);
        attr[8] = 1;
        BinaryPrimitives.WriteUInt16LittleEndian(attr[14..16], id);
        BinaryPrimitives.WriteInt64LittleEndian(attr[24..32], clusters - 1);
        BinaryPrimitives.WriteUInt16LittleEndian(attr[32..34], 64);
        BinaryPrimitives.WriteUInt64LittleEndian(attr[40..48], (ulong)clusters * ClusterSize);
        BinaryPrimitives.WriteUInt64LittleEndian(attr[48..56], realSize);
        BinaryPrimitives.WriteUInt64LittleEndian(attr[56..64], realSize);
        attr[64] = 0x11;
        attr[65] = (byte)clusters;
        attr[66] = (byte)lcn;
        attr[67] = 0;
        return length;
    }

    private static void ApplyFixup(Span<byte> record)
    {
        const ushort usn = 0xa55a;
        BinaryPrimitives.WriteUInt16LittleEndian(record[0x30..0x32], usn);
        BinaryPrimitives.WriteUInt16LittleEndian(record[0x32..0x34], BinaryPrimitives.ReadUInt16LittleEndian(record[510..512]));
        BinaryPrimitives.WriteUInt16LittleEndian(record[0x34..0x36], BinaryPrimitives.ReadUInt16LittleEndian(record[1022..1024]));
        BinaryPrimitives.WriteUInt16LittleEndian(record[510..512], usn);
        BinaryPrimitives.WriteUInt16LittleEndian(record[1022..1024], usn);
    }

    private static void WriteRecord(byte[] image, int number, byte[] record) => record.CopyTo(image.AsSpan(4 * ClusterSize + number * RecordSize));
    private static int Align8(int value) => (value + 7) & ~7;
    private static string Sha256(byte[] bytes) => Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
    private static async Task<string> FileSha256Async(string path) => Convert.ToHexString(await SHA256.HashDataAsync(File.OpenRead(path))).ToLowerInvariant();
    private static void Assert(bool condition, string message) { if (!condition) throw new InvalidOperationException("Assertion failed: " + message); }

    private static async Task TestLargeDiskMathAsync()
    {
        const ulong length = 16UL * 1024 * 1024 * 1024 * 1024;
        var data = new Dictionary<ulong, byte[]>();
        var mbr = new byte[512];
        mbr[510] = 0x55; mbr[511] = 0xaa; mbr[446 + 4] = 0xee;
        BinaryPrimitives.WriteUInt32LittleEndian(mbr.AsSpan(446 + 8, 4), 1);
        BinaryPrimitives.WriteUInt32LittleEndian(mbr.AsSpan(446 + 12, 4), uint.MaxValue);
        data[0] = mbr;
        var gpt = new byte[512];
        "EFI PART"u8.CopyTo(gpt);
        BinaryPrimitives.WriteUInt64LittleEndian(gpt.AsSpan(72, 8), 2);
        BinaryPrimitives.WriteUInt32LittleEndian(gpt.AsSpan(80, 4), 1);
        BinaryPrimitives.WriteUInt32LittleEndian(gpt.AsSpan(84, 4), 128);
        data[512] = gpt;
        var entrySector = new byte[512];
        new Guid("EBD0A0A2-B9E5-4433-87C0-68B6B72699C7").TryWriteBytes(entrySector.AsSpan(0, 16));
        Guid.NewGuid().TryWriteBytes(entrySector.AsSpan(16, 16));
        const ulong firstLba = 2048;
        var lastLba = length / 512 - 2049;
        BinaryPrimitives.WriteUInt64LittleEndian(entrySector.AsSpan(32, 8), firstLba);
        BinaryPrimitives.WriteUInt64LittleEndian(entrySector.AsSpan(40, 8), lastLba);
        data[1024] = entrySector;
        await using var fake = new SparseBlockDevice(length, data);
        var parts = await PartitionScanner.ScanAsync(fake);
        Assert(parts.Count == 1 && parts[0].Offset == firstLba * 512 && parts[0].Length > 15UL * 1024 * 1024 * 1024 * 1024, "large GPT partition");
    }

    private sealed class SparseBlockDevice(ulong length, Dictionary<ulong, byte[]> blocks) : IBlockDevice
    {
        public string Id => "synthetic-16tib";
        public ulong Length { get; } = length;
        public uint LogicalSectorSize => 512;
        public uint PhysicalSectorSize => 4096;
        public bool IsReadOnly => true;
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
        public ValueTask<int> ReadAsync(ulong offset, Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            buffer.Span.Clear();
            foreach (var pair in blocks)
            {
                var end = pair.Key + (ulong)pair.Value.Length;
                var readEnd = offset + (ulong)buffer.Length;
                if (offset >= end || readEnd <= pair.Key) continue;
                var sourceOffset = checked((int)(Math.Max(offset, pair.Key) - pair.Key));
                var targetOffset = checked((int)(Math.Max(offset, pair.Key) - offset));
                var count = Math.Min(pair.Value.Length - sourceOffset, buffer.Length - targetOffset);
                pair.Value.AsSpan(sourceOffset, count).CopyTo(buffer.Span[targetOffset..]);
            }
            return ValueTask.FromResult(buffer.Length);
        }
    }
}
