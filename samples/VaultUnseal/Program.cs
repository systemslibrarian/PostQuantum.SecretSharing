using System.Security.Cryptography;
using System.Text;
using PostQuantum.SecretSharing;

// VaultUnseal — a Vault-style "sealed service" break-glass pattern.
//
// A service holds sensitive configuration (here, a production DB connection
// string) encrypted under a master key it does NOT keep. On startup the service
// is *sealed*: it can prove it has ciphertext but cannot read it. It becomes
// *unsealed* only when a quorum of operators presents their shares, at which
// point the master key is reconstructed in memory, the config is decrypted and
// used, and the key is wiped.
//
// This mirrors how HashiCorp Vault unseals with Shamir shares — but here the
// secrecy of the master key below the quorum is information-theoretic, and the
// whole thing runs on net8.0 with no ML-DSA dependency (the portable core).

Console.WriteLine("PostQuantum.SecretSharing — VaultUnseal sample\n");

string dir = Path.Combine(AppContext.BaseDirectory, "sealed-store");
Directory.CreateDirectory(dir);

// ── Provisioning (run once, by an operator) ───────────────────────────────────
// The service's sensitive config. Wrapped so it can be any size / entropy.
const string sensitiveConfig =
    "Server=prod-sql-01;Database=ledger;User Id=svc_ledger;Password=Zq7!9xPm…;Encrypt=true";
Console.WriteLine("Provisioning: sealing the service configuration under a 3-of-5 master key.");

WrappedSplit provisioned = WrappedSecret.Split(
    Encoding.UTF8.GetBytes(sensitiveConfig), new SharePolicy(Threshold: 3, TotalShares: 5));

// The sealed store (the envelope) ships with the service; it is not secret.
File.WriteAllBytes(Path.Combine(dir, "config.sealed"), provisioned.Envelope);
// Each operator receives exactly one share, out-of-band.
string[] operators = { "Alice (SRE)", "Bob (Security)", "Carol (DBA)", "Dave (offsite)", "Erin (Mgr)" };
var operatorShares = new Dictionary<string, byte[]>();
foreach (SecretShare s in provisioned.Shares)
    operatorShares[operators[s.ShareIndex - 1]] = s.Export();
Console.WriteLine($"  sealed store written; {provisioned.Shares.Length} shares distributed to operators.\n");

// ── A fresh service process starts up: SEALED ─────────────────────────────────
var service = new SealedService(File.ReadAllBytes(Path.Combine(dir, "config.sealed")));
Console.WriteLine($"Service starting… state = {service.State}");
try
{
    _ = service.GetConnectionString();
}
catch (InvalidOperationException ex)
{
    Console.WriteLine($"  Request for config while sealed → refused: {ex.Message}\n");
}

// ── An incomplete quorum cannot unseal ────────────────────────────────────────
Console.WriteLine("Two operators try to unseal (below threshold):");
try
{
    service.Unseal(new[] { operatorShares["Alice (SRE)"], operatorShares["Bob (Security)"] });
}
catch (SharePolicyException ex)
{
    Console.WriteLine($"  Refused: {ex.Message}\n");
}

// ── A quorum unseals the service ──────────────────────────────────────────────
Console.WriteLine("Three operators convene to unseal:");
service.Unseal(new[]
{
    operatorShares["Alice (SRE)"],
    operatorShares["Carol (DBA)"],
    operatorShares["Dave (offsite)"],
});
Console.WriteLine($"  state = {service.State}");
Console.WriteLine($"  service can now read its config: \"{Mask(service.GetConnectionString())}\"\n");

// ── Re-seal when done (forget the key) ────────────────────────────────────────
service.Seal();
Console.WriteLine($"Service re-sealed; state = {service.State}. Master key wiped from memory.");
Console.WriteLine("\nDone. Secrecy below the quorum is information-theoretic. Soli Deo Gloria.");

static string Mask(string connectionString)
{
    // Don't print the password even in a demo.
    int pw = connectionString.IndexOf("Password=", StringComparison.OrdinalIgnoreCase);
    return pw < 0 ? connectionString : connectionString[..(pw + 9)] + "********…";
}

/// <summary>A service whose configuration is sealed until a quorum unseals it.</summary>
internal sealed class SealedService
{
    private readonly byte[] _sealedConfig;     // the envelope; not secret
    private ZeroizingBuffer? _configPlaintext; // populated only while unsealed

    public SealedService(byte[] sealedConfig) => _sealedConfig = sealedConfig;

    public string State => _configPlaintext is null ? "SEALED" : "UNSEALED";

    /// <summary>Reconstructs the master key from a quorum and decrypts the config in memory.</summary>
    public void Unseal(IReadOnlyCollection<byte[]> shareBytes)
    {
        var shares = shareBytes.Select(b => SecretShare.Import(b)).ToList();
        // WrappedSecret reconstructs the KEK from the quorum and decrypts the envelope.
        _configPlaintext = WrappedSecret.Reconstruct(shares, _sealedConfig);
    }

    /// <summary>Wipes the decrypted config; the service returns to SEALED.</summary>
    public void Seal()
    {
        _configPlaintext?.Dispose();
        _configPlaintext = null;
    }

    public string GetConnectionString()
    {
        if (_configPlaintext is null)
            throw new InvalidOperationException("service is sealed; present a quorum of shares to unseal.");
        return Encoding.UTF8.GetString(_configPlaintext.Span);
    }
}
