using Perseus.Reporting;

namespace Perseus.Audit;

/// <summary>One menu entry: a label and the async action it runs.</summary>
public sealed record MenuCheck(string Label, Func<FindingStore, Task> Run);

/// <summary>
/// Everything Program.cs needs from a platform's check set. Windows/macOS/
/// Linux each implement this once; Program.cs picks the right one via
/// PlatformHelper.Current and never branches on OS itself - that branching
/// lives here, once, per platform.
/// </summary>
public interface ICheckProvider
{
    string PlatformLabel { get; }
    IReadOnlyList<MenuCheck> Checks { get; }
    Task<List<SoftwareItem>> GetSoftwareInventoryAsync(FindingStore store);
}
