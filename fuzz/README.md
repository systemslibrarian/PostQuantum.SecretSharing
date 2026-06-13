# Fuzzing

Coverage-guided fuzzing of the strict `.pqss` parser — the library's primary
untrusted-input surface — using [SharpFuzz](https://github.com/Metalnem/sharpfuzz)
+ libFuzzer. This complements the property/structural tests
(`tests/.../CborPropertyTests.cs`, `FsCheckCborTests.cs`): those generate
*structured* inputs; libFuzzer drives raw-byte mutation guided by code coverage.

## The property under test

For **any** byte sequence, `SecretShare.Import` must either succeed or throw a
`SecretSharingException` (the declared fail-closed hierarchy). Any other exception
type escaping is a bug; the harness lets it propagate so libFuzzer records a crash
and a minimal reproducer.

## Run it locally (Linux, or WSL/macOS)

```bash
# 1. tools
dotnet tool install --global SharpFuzz.CommandLine
sudo apt-get install -y clang          # provides the libFuzzer driver compiler

# 2. build + seed (seed against a clean, un-instrumented build)
dotnet build fuzz/PostQuantum.SecretSharing.Fuzz/PostQuantum.SecretSharing.Fuzz.csproj -c Release -o fuzzbin
dotnet fuzzbin/PostQuantum.SecretSharing.Fuzz.dll --seed corpus

# 3. instrument the library assembly
sharpfuzz fuzzbin/PostQuantum.SecretSharing.dll

# 4. build the libfuzzer-dotnet driver
curl -sSL https://raw.githubusercontent.com/Metalnem/libfuzzer-dotnet/master/libfuzzer-dotnet.cc -o libfuzzer-dotnet.cc
clang -g -O2 -fsanitize=fuzzer libfuzzer-dotnet.cc -o libfuzzer-dotnet

# 5. fuzz (Ctrl-C to stop; drop -max_total_time to run unbounded)
./libfuzzer-dotnet \
  --target_path="$(command -v dotnet)" \
  --target_arg="$PWD/fuzzbin/PostQuantum.SecretSharing.Fuzz.dll" \
  -timeout=25 -print_final_stats=1 corpus
```

A crash drops a `crash-<sha1>` file; reproduce it with:

```bash
./libfuzzer-dotnet --target_path="$(command -v dotnet)" \
  --target_arg="$PWD/fuzzbin/PostQuantum.SecretSharing.Fuzz.dll" crash-<sha1>
```

CI runs a timeboxed session weekly and on parser changes
([`.github/workflows/fuzz.yml`](../.github/workflows/fuzz.yml)). This project is
intentionally outside the main solution — it is a specialized tool, built only by
that workflow.
