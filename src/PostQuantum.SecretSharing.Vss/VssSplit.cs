namespace PostQuantum.SecretSharing.Vss;

/// <summary>
/// The result of a verifiable split: the per-trustee <see cref="Shares"/> and the
/// dealer's public <see cref="Commitments"/> broadcast that every trustee verifies
/// against.
/// </summary>
public sealed record VssSplit(VssShare[] Shares, VssCommitments Commitments);
