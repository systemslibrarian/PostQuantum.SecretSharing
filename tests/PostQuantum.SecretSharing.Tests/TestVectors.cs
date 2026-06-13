using System.Text.Json;
using System.Text.Json.Serialization;

namespace PostQuantum.SecretSharing.Tests;

/// <summary>Strongly-typed view over docs/test-vectors.json (copied to the test output dir).</summary>
public sealed class VectorFile
{
    [JsonPropertyName("gf_mul_table_sha256")] public string GfMulTableSha256 { get; set; } = "";
    [JsonPropertyName("gf_inverses_1_to_255")] public int[] GfInverses { get; set; } = Array.Empty<int>();
    [JsonPropertyName("split")] public SplitVector[] Split { get; set; } = Array.Empty<SplitVector>();
    [JsonPropertyName("reconstruct")] public ReconstructVector[] Reconstruct { get; set; } = Array.Empty<ReconstructVector>();
    [JsonPropertyName("checkValue")] public CheckValueVector[] CheckValue { get; set; } = Array.Empty<CheckValueVector>();
}

public sealed class SplitVector
{
    public string Label { get; set; } = "";
    public int K { get; set; }
    public int N { get; set; }
    public int SecretLength { get; set; }
    public string Secret { get; set; } = "";
    public string[] CoeffRows { get; set; } = Array.Empty<string>();
    public ShareVector[] Shares { get; set; } = Array.Empty<ShareVector>();
}

public sealed class ShareVector { public int X { get; set; } public string Y { get; set; } = ""; }

public sealed class ReconstructVector
{
    public string Label { get; set; } = "";
    public int K { get; set; }
    public int[] Xs { get; set; } = Array.Empty<int>();
    public ShareVector[] Shares { get; set; } = Array.Empty<ShareVector>();
    public string ExpectedSecret { get; set; } = "";
}

public sealed class CheckValueVector
{
    public string Label { get; set; } = "";
    public string Secret { get; set; } = "";
    public string SplitId { get; set; } = "";
    public string CheckValue { get; set; } = "";
}

public static class Vectors
{
    private static readonly Lazy<VectorFile> _file = new(Load);

    public static VectorFile File => _file.Value;

    private static VectorFile Load()
    {
        string path = Path.Combine(AppContext.BaseDirectory, "test-vectors.json");
        string json = System.IO.File.ReadAllText(path);
        var opts = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };
        return JsonSerializer.Deserialize<VectorFile>(json, opts)
            ?? throw new InvalidOperationException("Failed to load test-vectors.json");
    }

    public static byte[] Hex(string s) => Convert.FromHexString(s);
}
