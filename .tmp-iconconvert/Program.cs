using System;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Drawing.Imaging;
using System.IO;
using System.IO.Compression;

var root = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", ".."));
var assets = Path.Combine(root, "Assets");
var src = Path.Combine(assets, "PerseusIconsource.jpg");

using var source = Image.FromFile(src);

byte[] RenderPng(int size)
{
    using var resized = new Bitmap(size, size);
    using (var g = Graphics.FromImage(resized))
    {
        g.Clear(Color.Transparent);
        g.InterpolationMode = InterpolationMode.HighQualityBicubic;
        g.SmoothingMode = SmoothingMode.HighQuality;
        g.PixelOffsetMode = PixelOffsetMode.HighQuality;
        g.DrawImage(source, 0, 0, size, size);
    }

    using var ms = new MemoryStream();
    resized.Save(ms, ImageFormat.Png);
    return ms.ToArray();
}

// --- Build Perseus.icns (macOS icon container: 'icns' magic + length-prefixed,
// type-coded chunks, each holding plain PNG data - supported since Mac OS X 10.7). ---
var icnsEntries = new (string Type, int Size)[]
{
    ("icp4", 16), ("icp5", 32), ("icp6", 64),
    ("ic11", 32), ("ic12", 64),
    ("ic07", 128), ("ic08", 256), ("ic13", 256),
};

var pngCache = new Dictionary<int, byte[]>();
byte[] GetPng(int size) => pngCache.TryGetValue(size, out var cached) ? cached : (pngCache[size] = RenderPng(size));

using var icnsStream = new MemoryStream();
using (var w = new BinaryWriter(icnsStream))
{
    var chunks = new List<(string Type, byte[] Data)>();
    foreach (var (type, size) in icnsEntries)
    {
        chunks.Add((type, GetPng(size)));
    }

    var totalLength = 8 + chunks.Count * 8;
    foreach (var (_, data) in chunks) totalLength += data.Length;

    w.Write(System.Text.Encoding.ASCII.GetBytes("icns"));
    WriteBigEndian(w, (uint)totalLength);

    foreach (var (type, data) in chunks)
    {
        w.Write(System.Text.Encoding.ASCII.GetBytes(type));
        WriteBigEndian(w, (uint)(8 + data.Length));
        w.Write(data);
    }
}

var icnsPath = Path.Combine(assets, "Perseus.icns");
File.WriteAllBytes(icnsPath, icnsStream.ToArray());
Console.WriteLine($"Wrote {icnsPath} ({icnsEntries.Length} sizes)");

// --- Assemble Perseus.app and zip it with the executable bit set on the binary,
// once per macOS architecture. ---
const string Plist = """
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleName</key>
    <string>Perseus</string>
    <key>CFBundleDisplayName</key>
    <string>Perseus</string>
    <key>CFBundleIdentifier</key>
    <string>com.omarpresley.perseus</string>
    <key>CFBundleVersion</key>
    <string>1.0.0</string>
    <key>CFBundleShortVersionString</key>
    <string>1.0.0</string>
    <key>CFBundleExecutable</key>
    <string>Perseus</string>
    <key>CFBundleIconFile</key>
    <string>Perseus.icns</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleInfoDictionaryVersion</key>
    <string>6.0</string>
    <key>LSMinimumSystemVersion</key>
    <string>11.0</string>
    <key>NSHighResolutionCapable</key>
    <true/>
    <key>NSHumanReadableCopyright</key>
    <string>Copyright (c) 2026 Omar-Presley</string>
</dict>
</plist>
""";

var outputDir = Path.Combine(root, "installer", "Output");
Directory.CreateDirectory(outputDir);

foreach (var rid in new[] { "osx-arm64", "osx-x64" })
{
    BuildAppBundleZip(rid);
}

void BuildAppBundleZip(string rid)
{
    var publishDir = Path.Combine(root, "bin", "Release", "net10.0", rid, "publish");
    var binaryPath = Path.Combine(publishDir, "Perseus");
    if (!File.Exists(binaryPath))
    {
        Console.WriteLine($"Skipping {rid} app bundle - publish output not found at {binaryPath}");
        return;
    }

    var archSuffix = rid == "osx-arm64" ? "arm64" : "x64";
    var zipPath = Path.Combine(outputDir, $"Perseus-macOS-{archSuffix}.zip");
    if (File.Exists(zipPath)) File.Delete(zipPath);

    using (var zip = ZipFile.Open(zipPath, ZipArchiveMode.Create))
    {
        void AddFile(string entryName, byte[] data, bool executable)
        {
            var entry = zip.CreateEntry(entryName, CompressionLevel.Optimal);
            var unixMode = executable ? 0b1_000_000_111_101_101 : 0b1_000_000_110_100_100;
            entry.ExternalAttributes = unixMode << 16;
            using var s = entry.Open();
            s.Write(data, 0, data.Length);
        }

        AddFile("Perseus.app/Contents/Info.plist", System.Text.Encoding.UTF8.GetBytes(Plist), executable: false);
        AddFile("Perseus.app/Contents/Resources/Perseus.icns", File.ReadAllBytes(icnsPath), executable: false);
        AddFile("Perseus.app/Contents/MacOS/Perseus", File.ReadAllBytes(binaryPath), executable: true);
    }

    Console.WriteLine($"Wrote {zipPath}");
}

static void WriteBigEndian(BinaryWriter w, uint value)
{
    var bytes = BitConverter.GetBytes(value);
    if (BitConverter.IsLittleEndian) Array.Reverse(bytes);
    w.Write(bytes);
}
