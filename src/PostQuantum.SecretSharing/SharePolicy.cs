namespace PostQuantum.SecretSharing;

/// <summary>
/// A threshold policy: split a secret into <paramref name="TotalShares"/> shares
/// such that any <paramref name="Threshold"/> of them reconstruct it and any
/// fewer reveal nothing.
/// </summary>
/// <param name="Threshold">
/// The quorum size <c>k</c> required to reconstruct. Must satisfy
/// <c>2 ≤ k ≤ TotalShares</c>. <c>k = 1</c> is forbidden: every share would equal
/// the secret, which is security theater rather than secret sharing.
/// </param>
/// <param name="TotalShares">
/// The number of shares <c>n</c> to issue. Must satisfy <c>k ≤ n ≤ 255</c>
/// (x-coordinates live in GF(2^8) and x=0 is reserved for the secret).
/// </param>
public sealed record SharePolicy(int Threshold, int TotalShares);
