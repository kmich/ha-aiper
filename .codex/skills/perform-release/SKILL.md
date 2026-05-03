---
name: perform-release
description: Perform a release for this ha-aiper repository. Use when the user asks to create, prepare, cut, tag, publish, or run a patch/minor/major release for the HACS Home Assistant Aiper integration, including version bumping, committing, pushing, creating the v* tag, and following the GitHub release action.
---

# Perform Release

Release this HACS integration by bumping the repo versions, committing the bump,
pushing `main`, pushing a `v*` tag, and following the tag-triggered release action.

## Release Type

- Default to a patch release.
- If the user asks for `minor` or `major`, bump that SemVer component instead.
- If the user gives an explicit version such as `0.8.0` or `v0.8.0`, use it after stripping a leading `v`.
- Reject non-SemVer versions. Use `MAJOR.MINOR.PATCH`.

## Preconditions

1. Work from the repository root.
2. Check branch and cleanliness:
   ```bash
   git status --short --branch
   ```
3. Require the active branch to be `main` tracking `origin/main`.
4. If there are uncommitted changes unrelated to the release bump, stop and ask.
5. Fetch tags and refs:
   ```bash
   git fetch origin --prune --tags
   ```
6. Confirm the target tag does not already exist locally or remotely:
   ```bash
   git tag --list vX.Y.Z
   git ls-remote --tags origin vX.Y.Z
   ```

## Determine Version

Read both version sources:

- `custom_components/aiper/manifest.json` field: `version`
- `pyproject.toml` field: `[project].version`

Use the manifest version as the authoritative current release version unless the
user explicitly instructs otherwise. `pyproject.toml` is development metadata in
this repo, but keep it synchronized with the release version because the user has
requested both files be updated during release.

Compute the new version:

- patch: `X.Y.Z -> X.Y.(Z+1)`
- minor: `X.Y.Z -> X.(Y+1).0`
- major: `X.Y.Z -> (X+1).0.0`

The Git tag must be `vX.Y.Z`; the files must contain `X.Y.Z` without `v`.

## Edit Versions

Update only:

- `custom_components/aiper/manifest.json`
- `pyproject.toml`

Prefer `apply_patch` for simple edits. Preserve existing formatting.

After editing, verify:

```bash
rg -n '"version"|^version =' custom_components/aiper/manifest.json pyproject.toml
```

## Validate Before Tagging

Run the normal local validation before creating the tag:

```bash
uv run ruff check custom_components/aiper tools tests
uv run pyright
uv run pytest
python -m compileall custom_components/aiper tools tests
```

If any validation fails, fix it before committing.

## Commit And Push

Commit only the version bump:

```bash
git add custom_components/aiper/manifest.json pyproject.toml
git commit -m "Release X.Y.Z"
git push origin main
```

Wait for the `main` push Validation workflow to complete before creating or
pushing the release tag. This prevents the tag-triggered Release workflow from
publishing an artifact before the commit has passed validation.

Find and watch the validation run for the release commit:

```bash
git rev-parse HEAD
gh run list -R filmackay/ha-aiper --workflow Validation --branch main --limit 10 --json databaseId,headSha,status,conclusion,url
gh run watch -R filmackay/ha-aiper RUN_ID --exit-status
```

If Validation fails, do not tag. Inspect logs, fix the issue, amend or create a
new release commit as appropriate, push `main`, and wait for Validation again.

Create and push an annotated tag:

```bash
git tag -a vX.Y.Z -m "vX.Y.Z"
git push origin vX.Y.Z
```

Do not force-push a release tag. If a tag was created incorrectly but not pushed,
delete it locally and recreate it. If it was pushed, stop and ask.

## Follow Release Action

The release workflow is `.github/workflows/release.yaml` and triggers on tags
matching `v*`. After pushing the tag:

1. Find the Release workflow run:
   ```bash
   gh run list --workflow Release --limit 10 --json databaseId,displayTitle,headBranch,headSha,status,conclusion,createdAt,url
   ```
2. Watch it:
   ```bash
   gh run watch RUN_ID --exit-status
   ```
3. If it fails, inspect logs:
   ```bash
   gh run view RUN_ID --log-failed
   ```
4. If it succeeds, verify the GitHub release and `aiper.zip` asset:
   ```bash
   gh release view vX.Y.Z --json tagName,name,url,assets
   ```

## Final Response

Report:

- released version and tag
- commit SHA
- release workflow result
- GitHub release URL
- any warnings or follow-up issues
