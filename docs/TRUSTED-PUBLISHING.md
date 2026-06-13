# Trusted Publishing on nuget.org

`release.yml` publishes `PostQuantum.SecretSharing` to nuget.org using
**Trusted Publishing** — short-lived API keys minted on demand from a GitHub
OIDC token. There is **no long-lived `NUGET_API_KEY` secret** in this repo.

- A leaked CI secret can't be used to publish: the minted key is issued for
  one push and expires in an hour.
- A fork cannot publish to our package ID: nuget.org checks the OIDC token
  against an owner + repo + workflow file + environment policy.
- There is nothing to rotate. The OIDC trust *is* the credential.

Microsoft docs: <https://learn.microsoft.com/en-us/nuget/nuget-org/trusted-publishing>.

> **Note:** the OIDC trust is pinned to this exact repo + workflow file +
> environment, so the policy you set up for any sibling package (e.g.
> PostQuantum.Hybrid) does **not** cover this one. The steps below must be
> done once for `PostQuantum.SecretSharing`.

## One-time setup

Two sides — nuget.org and GitHub. Do them in this order.

### 1. nuget.org — create the trusted-publishing policy

1. Sign in to <https://www.nuget.org>.
2. Username (top right) → **Trusted Publishing**.
   (If the menu item is missing, the feature has not rolled out to your
   account yet — Microsoft is gating rollout.)
3. **Add a new GitHub Actions policy** with these values:

   | Field         | Value                                                       |
   | ------------- | ----------------------------------------------------------- |
   | Owner         | `systemslibrarian`                                          |
   | Repository    | `PostQuantum.SecretSharing`                                 |
   | Workflow File | `release.yml`  *(file name only — no `.github/workflows/`)* |
   | Environment   | `nuget`                                                     |

4. Choose the owner that matches the package owner on nuget.org.
5. Save. For a public repo the policy is permanently active immediately; if
   the package ID does not exist yet, the first push from this workflow both
   creates the package and confirms the policy.

### 2. GitHub — `NUGET_USER` secret + `nuget` environment

#### `NUGET_USER` repo secret

`NuGet/login` requires your nuget.org **profile name** (not your email).
Stored as a secret so the public workflow source doesn't leak the account
name to scrapers.

1. <https://github.com/systemslibrarian/PostQuantum.SecretSharing/settings/secrets/actions>
2. **New repository secret**
3. Name: `NUGET_USER`
4. Value: your nuget.org profile name (e.g. `systemslibrarian`)

#### `nuget` environment

The workflow's `environment: nuget` line. Creating the environment also gives
you a place to add protection rules (required reviewers, allowed tags).

1. <https://github.com/systemslibrarian/PostQuantum.SecretSharing/settings/environments>
2. **New environment** → name it `nuget`
3. (Recommended) under **Deployment branches and tags**, restrict to tags
   matching `v*.*.*` so a stray push can never run the release job.

### 3. Release

The csproj `<Version>` is the single source of truth. To cut a release, set
`<Version>` in `src/PostQuantum.SecretSharing/PostQuantum.SecretSharing.csproj`,
commit, then tag with a matching `v` prefix:

```bash
git tag v1.0.0-rc.1
git push origin v1.0.0-rc.1
```

On push the workflow:

1. **Verifies the tag matches `<Version>`** — fails the release otherwise.
2. Builds, tests, packs, generates the SBOM, attests provenance.
3. Creates a GitHub Release with the `.nupkg`/`.snupkg`/SBOM/checksums
   (marked *prerelease* automatically when the tag contains `-`, e.g. `-rc.1`).
4. **NuGet login (OIDC → short-lived key)** → **Publish to NuGet**.

A version with a prerelease suffix (`1.0.0-rc.1`) only surfaces to consumers
who opt into prereleases — correct for a release candidate.

### 4. Troubleshooting

If **NuGet login** fails with `401 Unauthorized`, in descending likelihood:

- The nuget.org policy's `Workflow File` isn't exactly `release.yml`
  (people put `.github/workflows/release.yml` — don't).
- The policy's `Environment` doesn't match the workflow's `environment: nuget`.
- `NUGET_USER` is set to your email instead of your profile name.
- The policy was created under a different owner than the package owner.

## Why the workflow looks the way it does

- **`environment: nuget` is at job scope** — the GitHub-supported location,
  and what the nuget.org policy matches against.
- **`id-token: write` is on the job**, not the workflow — least-privilege,
  and the only scope `NuGet/login` and the attestation step require.
- **`contents: write`** is needed at job scope for `action-gh-release` to
  attach the artifacts. Trusted publishing only handles the NuGet leg.
- **`--skip-duplicate`** stays on `dotnet nuget push` so a partial re-run of a
  tagged release doesn't fail on a package that already uploaded.
- **Every action is pinned to a full commit SHA** with a version comment,
  matching the rest of this repo's workflows.
