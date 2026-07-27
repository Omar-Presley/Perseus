using System;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Drawing.Imaging;
using System.IO;

var assets = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "Assets"));
var src = Path.Combine(assets, "PerseusIconsource.jpg");
var png = Path.Combine(assets, "PerseusIcon.png");
var ico = Path.Combine(assets, "PerseusIcon.ico");

int[] sizes = [16, 32, 48, 256];

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

// Standalone PerseusIcon.png used by the app's in-window Image controls.
File.WriteAllBytes(png, RenderPng(256));

// Real multi-resolution .ico: ICONDIR + one ICONDIRENTRY per size, each entry's
// image data PNG-compressed (supported by the ICO format since Windows Vista).
var images = new List<(int Size, byte[] Data)>();
foreach (var size in sizes)
{
    images.Add((size, RenderPng(size)));
}

using var stream = new FileStream(ico, FileMode.Create, FileAccess.Write);
using var writer = new BinaryWriter(stream);

writer.Write((short)0);              // reserved
writer.Write((short)1);              // type: 1 = icon
writer.Write((short)images.Count);   // image count

var dataOffset = 6 + (16 * images.Count);
foreach (var (size, data) in images)
{
    writer.Write((byte)(size >= 256 ? 0 : size));  // width (0 = 256)
    writer.Write((byte)(size >= 256 ? 0 : size));  // height (0 = 256)
    writer.Write((byte)0);           // color palette
    writer.Write((byte)0);           // reserved
    writer.Write((short)1);          // color planes
    writer.Write((short)32);         // bits per pixel
    writer.Write(data.Length);       // size of image data
    writer.Write(dataOffset);        // offset of image data
    dataOffset += data.Length;
}

foreach (var (_, data) in images)
{
    writer.Write(data);
}

Console.WriteLine($"Wrote {png}");
Console.WriteLine($"Wrote {ico} ({images.Count} sizes: {string.Join(", ", sizes)})");
