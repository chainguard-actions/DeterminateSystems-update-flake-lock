<!-- markdownlint-disable -->

# Hardening Report: DeterminateSystems--update-flake-lock/v27

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `2`

Action **DeterminateSystems--update-flake-lock/v27** was hardened automatically. 7 finding(s) were identified and resolved across 1 iteration(s).

## Findings Fixed

### unpinned-uses (severity: high)

Two `uses:` references in action.yml use mutable tags instead of full 40-character SHA commit digests, making the action vulnerable to supply-chain attacks if those tags are moved:
- `DamianReeves/write-file-action@v1.3` (tag, not a SHA)
- `juliangruber/read-file-action@v1` (tag, not a SHA)
These should be pinned to full SHA digests, e.g. `uses: juliangruber/read-file-action@b549046febe0fe86f8cb4f93c24e284433f9ab58 # v1`.

Locations:

- `action.yml:148`
- `action.yml:162`

### script-injection (severity: high)

Sub-rule (a): The 'Set environment variables (unsigned commits)' run: block directly interpolates attacker-controllable `inputs.*` expressions inside shell command strings, enabling script injection. Offending lines:
  echo "GIT_AUTHOR_NAME=${{ inputs.git-author-name }}" >> $GITHUB_ENV
  echo "GIT_AUTHOR_EMAIL=<${{ inputs.git-author-email }}>" >> $GITHUB_ENV
  echo "GIT_COMMITTER_NAME=${{ inputs.git-committer-name }}" >> $GITHUB_ENV
  echo "GIT_COMMITTER_EMAIL=<${{ inputs.git-committer-email }}>" >> $GITHUB_ENV
An attacker can supply a crafted input value containing shell metacharacters or newlines to inject arbitrary commands or environment variable entries. Fix: route inputs through env: variables and double-quote all expansions.

Locations:

- `action.yml:119`

### github-env-injection (severity: high)

Two run: steps write untrusted values to $GITHUB_ENV without the required sanitization step (`printf '%s' ... | tr -d '\n\r'`):

(1) 'Set environment variables (signed commits)': writes env vars sourced from `steps.import-gpg.outputs.name` and `steps.import-gpg.outputs.email` (untrusted step outputs, workflow-controllable) directly to $GITHUB_ENV:
  echo "GIT_AUTHOR_NAME=$GIT_AUTHOR_NAME" >> $GITHUB_ENV
  echo "GIT_AUTHOR_EMAIL=<$GIT_AUTHOR_EMAIL>" >> $GITHUB_ENV
  echo "GIT_COMMITTER_NAME=$GIT_COMMITTER_NAME" >> $GITHUB_ENV
  echo "GIT_COMMITTER_EMAIL=<$GIT_COMMITTER_EMAIL>" >> $GITHUB_ENV

(2) 'Set environment variables (unsigned commits)': writes `inputs.*` values directly to $GITHUB_ENV via inline ${{ }} interpolation without sanitization:
  echo "GIT_AUTHOR_NAME=${{ inputs.git-author-name }}" >> $GITHUB_ENV
  echo "GIT_AUTHOR_EMAIL=<${{ inputs.git-author-email }}>" >> $GITHUB_ENV
  echo "GIT_COMMITTER_NAME=${{ inputs.git-committer-name }}" >> $GITHUB_ENV
  echo "GIT_COMMITTER_EMAIL=<${{ inputs.git-committer-email }}>" >> $GITHUB_ENV

A newline embedded in any of these values can inject arbitrary environment variable definitions into $GITHUB_ENV, potentially overwriting security-sensitive variables for subsequent steps.

Locations:

- `action.yml:111`
- `action.yml:119`

### static-inline-injection (severity: high)

shell injection: expression "${{ inputs.git-author-name }}" appears directly in run: block of step "Set environment variables (unsigned commits)"; move to env: map

Locations:

- `action.yml:139`

### static-inline-injection (severity: high)

shell injection: expression "${{ inputs.git-author-email }}" appears directly in run: block of step "Set environment variables (unsigned commits)"; move to env: map

Locations:

- `action.yml:140`

### static-inline-injection (severity: high)

shell injection: expression "${{ inputs.git-committer-name }}" appears directly in run: block of step "Set environment variables (unsigned commits)"; move to env: map

Locations:

- `action.yml:141`

### static-inline-injection (severity: high)

shell injection: expression "${{ inputs.git-committer-email }}" appears directly in run: block of step "Set environment variables (unsigned commits)"; move to env: map

Locations:

- `action.yml:142`

## Iteration Notes

### Iteration 1

**Fixes applied:** unpinned-uses, script-injection, github-env-injection, static-inline-injection

**Notes:**

Fixed all 7 findings in hardened/action/action.yml:

1. **unpinned-uses**: Pinned `DamianReeves/write-file-action@v1.3` to `@6929a9a6d1807689191dcc8bbe62b54d70a32b42 # v1.3` and `juliangruber/read-file-action@v1` to `@271ff311a4947af354c6abcd696a306553b9ec18 # v1`.

2. **script-injection / static-inline-injection**: In the 'Set environment variables (unsigned commits)' step, moved all four `${{ inputs.* }}` expressions out of the `run:` block and into a new `env:` block (`GIT_AUTHOR_NAME`, `GIT_AUTHOR_EMAIL`, `GIT_COMMITTER_NAME`, `GIT_COMMITTER_EMAIL`).

3. **github-env-injection**: In both 'Set environment variables (signed commits)' and 'Set environment variables (unsigned commits)' steps, added sanitization using `printf '%s' "$VAR" | tr -d '\n\r'` before writing each value to `$GITHUB_ENV`, preventing newline injection that could overwrite security-sensitive environment variables in subsequent steps.

