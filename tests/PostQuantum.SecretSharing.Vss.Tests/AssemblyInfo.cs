// The VSS package exposes a single assembly-internal RNG seam (Secp256r1Group.FillRandom,
// see docs/KNOWN-GAPS.md §7) used only to drive the published reference vectors. Because it
// is process-global, the test assembly runs serially so a deterministic-vector test can
// never observe — or be observed by — another test's split. The suite is small (~5s).
[assembly: Xunit.CollectionBehavior(DisableTestParallelization = true)]
