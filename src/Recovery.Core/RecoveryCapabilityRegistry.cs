using System;
using System.Collections.Frozen;
using System.Collections.Generic;
using System.Linq;

namespace Recovery.Core;

/// <summary>
/// Stable, user-facing file groups used by filtering and recovery presets.
/// Text formats remain documents so existing category behavior does not change.
/// </summary>
public enum RecoveryFileCategory
{
    Image,
    Video,
    Document,
    Audio,
    Archive,
    Other
}

/// <summary>
/// Describes only capabilities that RainTrace can currently provide and validate.
/// A missing PhotoRec family means that the extension must not be selected for raw carving.
/// </summary>
public sealed record RecoveryFileCapability(
    string Extension,
    RecoveryFileCategory Category,
    bool IsText,
    bool SupportsImagePreview,
    bool SupportsPreflight,
    string? PhotoRecFamily = null)
{
    public bool SupportsPhotoRec => !IsText && PhotoRecFamily is not null;
}

/// <summary>
/// Single source of truth for common file classification and the recovery features that are
/// actually implemented. Keep entries conservative: unsupported formats may still be shown as
/// metadata results, but they are not advertised as previewable, preflightable, or raw-recoverable.
/// </summary>
public static class RecoveryCapabilityRegistry
{
    private static readonly RecoveryFileCapability[] CapabilityEntries =
    [
        // Images. WPF can preview the common bitmap formats below; WebP is validated but is not
        // advertised as previewable because a codec is not guaranteed to be installed.
        Capability("jpg", RecoveryFileCategory.Image, preview: true, preflight: true, photoRecFamily: "jpg"),
        Capability("jpeg", RecoveryFileCategory.Image, preview: true, preflight: true, photoRecFamily: "jpg"),
        Capability("png", RecoveryFileCategory.Image, preview: true, preflight: true, photoRecFamily: "png"),
        Capability("bmp", RecoveryFileCategory.Image, preview: true, preflight: true, photoRecFamily: "bmp"),
        Capability("gif", RecoveryFileCategory.Image, preview: true, preflight: true, photoRecFamily: "gif"),
        Capability("tif", RecoveryFileCategory.Image, preview: true, preflight: true, photoRecFamily: "tif"),
        Capability("tiff", RecoveryFileCategory.Image, preview: true, preflight: true, photoRecFamily: "tif"),
        Capability("webp", RecoveryFileCategory.Image, preview: false, preflight: true, photoRecFamily: "riff"),
        Capability("heic", RecoveryFileCategory.Image),
        Capability("dng", RecoveryFileCategory.Image),
        Capability("raw", RecoveryFileCategory.Image),

        // Video. PhotoRec uses the MOV family for ISO-BMFF and RIFF for AVI.
        Capability("mp4", RecoveryFileCategory.Video, preflight: true, photoRecFamily: "mov"),
        Capability("mov", RecoveryFileCategory.Video, preflight: true, photoRecFamily: "mov"),
        Capability("avi", RecoveryFileCategory.Video, preflight: true, photoRecFamily: "riff"),
        Capability("mkv", RecoveryFileCategory.Video),
        Capability("mts", RecoveryFileCategory.Video),
        Capability("m2ts", RecoveryFileCategory.Video),
        Capability("wmv", RecoveryFileCategory.Video),
        Capability("flv", RecoveryFileCategory.Video),

        // Documents. OOXML containers are recovered by PhotoRec's ZIP family; legacy Office
        // compound documents share its DOC family.
        Capability("pdf", RecoveryFileCategory.Document, preflight: true, photoRecFamily: "pdf"),
        Capability("doc", RecoveryFileCategory.Document, preflight: true, photoRecFamily: "doc"),
        Capability("xls", RecoveryFileCategory.Document, preflight: true, photoRecFamily: "doc"),
        Capability("ppt", RecoveryFileCategory.Document, preflight: true, photoRecFamily: "doc"),
        Capability("docx", RecoveryFileCategory.Document, preflight: true, photoRecFamily: "zip"),
        Capability("xlsx", RecoveryFileCategory.Document, preflight: true, photoRecFamily: "zip"),
        Capability("pptx", RecoveryFileCategory.Document, preflight: true, photoRecFamily: "zip"),
        Capability("rtf", RecoveryFileCategory.Document),

        // Text is deliberately metadata-only. It supports readability/structure preflight, but it
        // never contributes a PhotoRec family because unbounded text carving creates false results.
        TextCapability("txt"),
        TextCapability("csv"),
        TextCapability("log"),
        TextCapability("ini"),
        TextCapability("json"),
        TextCapability("xml"),
        TextCapability("yaml"),
        TextCapability("yml"),

        // Audio.
        Capability("mp3", RecoveryFileCategory.Audio, preflight: true, photoRecFamily: "mp3"),
        Capability("wav", RecoveryFileCategory.Audio, preflight: true, photoRecFamily: "riff"),
        Capability("flac", RecoveryFileCategory.Audio),
        Capability("aac", RecoveryFileCategory.Audio),
        Capability("m4a", RecoveryFileCategory.Audio),
        Capability("ogg", RecoveryFileCategory.Audio),

        // Archives.
        Capability("zip", RecoveryFileCategory.Archive, preflight: true, photoRecFamily: "zip"),
        Capability("rar", RecoveryFileCategory.Archive, preflight: true, photoRecFamily: "rar"),
        Capability("7z", RecoveryFileCategory.Archive, preflight: true, photoRecFamily: "7z"),
        Capability("gz", RecoveryFileCategory.Archive),
        Capability("tar", RecoveryFileCategory.Archive)
    ];

    private static readonly FrozenDictionary<string, RecoveryFileCapability> ByExtension =
        CapabilityEntries.ToFrozenDictionary(entry => entry.Extension, StringComparer.OrdinalIgnoreCase);

    private static readonly FrozenSet<string> PhotoRecFamilySet = CapabilityEntries
        .Where(entry => entry.SupportsPhotoRec)
        .Select(entry => entry.PhotoRecFamily!)
        .ToFrozenSet(StringComparer.OrdinalIgnoreCase);

    private static readonly FrozenDictionary<string, string> PhotoRecFamilyAliases =
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["jpeg"] = "jpg",
            ["tiff"] = "tif",
            ["mp4"] = "mov",
            ["avi"] = "riff",
            ["wav"] = "riff",
            ["webp"] = "riff",
            ["xls"] = "doc",
            ["ppt"] = "doc",
            ["docx"] = "zip",
            ["xlsx"] = "zip",
            ["pptx"] = "zip"
        }.ToFrozenDictionary(StringComparer.OrdinalIgnoreCase);

    private static readonly string[] DefaultPhotoRecFamilyEntries =
    [
        "jpg", "png", "bmp", "gif", "tif", "pdf", "doc", "zip"
    ];

    private static readonly IReadOnlyList<RecoveryFileCapability> ReadOnlyCapabilityEntries =
        Array.AsReadOnly(CapabilityEntries);

    private static readonly IReadOnlyList<string> ReadOnlyDefaultPhotoRecFamilyEntries =
        Array.AsReadOnly(DefaultPhotoRecFamilyEntries);

    public static IReadOnlyList<RecoveryFileCapability> All => ReadOnlyCapabilityEntries;

    /// <summary>Canonical PhotoRec fileopt names permitted by this build.</summary>
    public static IReadOnlySet<string> AllowedPhotoRecFamilies => PhotoRecFamilySet;

    /// <summary>
    /// Conservative default: common pictures and documents. RIFF and MOV are intentionally not
    /// enabled here because those families also carve audio/video and are opt-in categories.
    /// </summary>
    public static IReadOnlyList<string> DefaultPhotoRecFamilies => ReadOnlyDefaultPhotoRecFamilyEntries;

    public static string NormalizeExtension(string? extension) =>
        (extension ?? string.Empty).Trim().TrimStart('.').ToLowerInvariant();

    public static bool TryGet(string? extension, out RecoveryFileCapability capability) =>
        ByExtension.TryGetValue(NormalizeExtension(extension), out capability!);

    public static RecoveryFileCapability? Find(string? extension) =>
        TryGet(extension, out var capability) ? capability : null;

    public static RecoveryFileCategory GetCategory(string? extension) =>
        Find(extension)?.Category ?? RecoveryFileCategory.Other;

    public static bool IsText(string? extension) => Find(extension)?.IsText == true;

    public static bool SupportsImagePreview(string? extension) =>
        Find(extension)?.SupportsImagePreview == true;

    public static bool SupportsPreflight(string? extension) =>
        Find(extension)?.SupportsPreflight == true;

    public static bool SupportsPhotoRec(string? extension) =>
        Find(extension)?.SupportsPhotoRec == true;

    /// <summary>
    /// Accepts both canonical PhotoRec family names and historically accepted extension aliases.
    /// This preserves the existing PhotoRecRunOptions API while emitting valid canonical fileopts.
    /// </summary>
    public static string NormalizePhotoRecFamily(string? family)
    {
        var normalized = NormalizeExtension(family);
        return PhotoRecFamilyAliases.TryGetValue(normalized, out var canonical) ? canonical : normalized;
    }

    public static bool IsPhotoRecFamilyAllowed(string? family) =>
        PhotoRecFamilySet.Contains(NormalizePhotoRecFamily(family));

    public static IReadOnlyList<string> GetPhotoRecFamilies(IEnumerable<string> extensions)
    {
        ArgumentNullException.ThrowIfNull(extensions);
        return extensions
            .Select(Find)
            .Where(capability => capability?.SupportsPhotoRec == true)
            .Select(capability => capability!.PhotoRecFamily!)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    public static IReadOnlyList<string> GetPhotoRecFamilies(RecoveryFileCategory category) =>
        CapabilityEntries
            .Where(capability => capability.Category == category && capability.SupportsPhotoRec)
            .Select(capability => capability.PhotoRecFamily!)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

    private static RecoveryFileCapability Capability(
        string extension,
        RecoveryFileCategory category,
        bool preview = false,
        bool preflight = false,
        string? photoRecFamily = null) =>
        new(extension, category, IsText: false, preview, preflight, photoRecFamily);

    private static RecoveryFileCapability TextCapability(string extension) =>
        new(extension, RecoveryFileCategory.Document, IsText: true, SupportsImagePreview: false,
            SupportsPreflight: true, PhotoRecFamily: null);
}
