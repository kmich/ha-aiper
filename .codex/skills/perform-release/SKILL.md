---
name: perform-release
description: Perform a release for this repository. Use when the user asks to create, prepare, cut, tag, publish, bump or run a patch/minor/major release for the HACS Home Assistant Aiper integration by bumping repo versions and letting the CI/CD workflow tag and publish after validation passes.
---

# Perform Release

Release this HACS integration by committing a version bump to `main`. The
`CI/CD` workflow validates that the stored versions match, runs quality checks,
and only then tags the current commit and creates the GitHub release archive.

Do not create tags locally. Do not run a separate release workflow.

## Release Type

- Default to `patch`.
- Use `minor` or `major` when the user asks for that release type.
- Use an explicit SemVer version when the user gives a target such as `0.9.0`
  or `v0.9.0`.

## Preconditions

1. Work from the repository root.
2. Check local state:
   ```bash
   git status --short --branch
   git fetch origin --prune --tags
   ```
3. Require local `main` to track `origin/main`.
4. If local `main` is behind `origin/main`, pull or ask before continuing.
5. If local `main` is ahead of `origin/main`, confirm those commits are intended
   to be released before pushing.
6. If there are unrelated uncommitted changes, stop and ask unless the user
   explicitly wants them included in the release commit.
7. Read current versions:
   ```bash
   rg -n '"version"|^version =|name = "ha-aiper"' custom_components/aiper/manifest.json pyproject.toml uv.lock
   ```
8. Require the existing versions in `custom_components/aiper/manifest.json`,
   `pyproject.toml`, and the `ha-aiper` stanza in `uv.lock` to match before
   bumping. If they differ, stop and fix that mismatch first.

## Bump Version

1. Determine the target version from the current version:
   - patch: increment `PATCH`
   - minor: increment `MINOR` and reset `PATCH` to `0`
   - major: increment `MAJOR` and reset `MINOR` and `PATCH` to `0`
2. Update all stored package versions:
   - `custom_components/aiper/manifest.json`: top-level `"version"`
   - `pyproject.toml`: `[project]` `version`
   - `uv.lock`: only the `version` in the `[[package]]` stanza where
     `name = "ha-aiper"`
3. Prefer `uv lock` after editing `pyproject.toml` so `uv.lock` stays
   mechanically consistent.
4. Confirm the new version is greater than the latest SemVer tag:
   ```bash
   git tag --list 'v[0-9]*.[0-9]*.[0-9]*' --sort=v:refname | tail -1
   ```

## Validate Locally

Run the local checks before committing:

```bash
uv sync --locked --group dev
uv run --frozen ruff check custom_components/
uv run --frozen mypy custom_components/
uv run --frozen pytest
```

If a check fails, fix it or report the blocker. Do not commit a release version
that has not passed local validation unless the user explicitly instructs that.

## Commit And Push

Commit only the intended release files and push `main`:

```bash
git diff -- custom_components/aiper/manifest.json pyproject.toml uv.lock
git add custom_components/aiper/manifest.json pyproject.toml uv.lock
git commit -m "Release X.Y.Z"
git push origin main
```

The push triggers `.github/workflows/ci-cd.yaml`. The release job will only run
when the quality job succeeds and the version does not already have a matching
tag. The GitHub release uses generated release notes so merged pull requests
and contributor credit are visible on the release page.

The release asset must contain the contents of `custom_components/aiper` at the
zip root. Do not package the parent `custom_components/aiper` path inside
`aiper.zip`, or HACS will install it as
`/config/custom_components/aiper/custom_components/aiper`.

## Follow CI/CD

Find the new run and watch it:

```bash
gh run list -R kmich/ha-aiper --workflow "CI/CD" --branch main --limit 10 --json databaseId,displayTitle,headSha,status,conclusion,createdAt,url
gh run watch -R kmich/ha-aiper RUN_ID --exit-status
```

If it fails, inspect logs:

```bash
gh run view -R kmich/ha-aiper RUN_ID --log-failed
```

## Verify Release

After success:

1. Fetch refs:
   ```bash
   git fetch origin --prune --tags
   git status --short --branch
   git log --oneline --decorate -5
   ```
2. Verify the tag points at the release commit.
3. Verify GitHub release notes and `aiper.zip`:
   ```bash
   gh release view -R kmich/ha-aiper vX.Y.Z --json tagName,name,url,body,assets
   ```

## Final Response

Report:

- released version and tag
- release commit SHA
- CI/CD workflow result and URL
- GitHub release URL
- asset name/size
- warnings or follow-up issues
