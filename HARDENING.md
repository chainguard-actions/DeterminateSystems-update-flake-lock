<!-- markdownlint-disable -->

# Hardening Report: DeterminateSystems--update-flake-lock/v26

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `2`

Action **DeterminateSystems--update-flake-lock/v26** was hardened automatically. 9 finding(s) were identified and resolved across 2 iteration(s).

## Findings Fixed

### script-injection (severity: high)

Sub-rule (a): The 'Set environment variables (unsigned commits)' step directly interpolates `${{ inputs.git-author-name }}`, `${{ inputs.git-author-email }}`, `${{ inputs.git-committer-name }}`, and `${{ inputs.git-committer-email }}` inside `run:` shell command strings. These expressions are expanded by the Actions template engine before the shell sees them, allowing an attacker-controlled value to inject arbitrary shell commands. Example offending line: `echo "GIT_AUTHOR_NAME=${{ inputs.git-author-name }}" >> $GITHUB_ENV`

Locations:

- `action.yml:116`

### github-env-injection (severity: high)

The 'Set environment variables (unsigned commits)' step writes `${{ inputs.git-author-name }}`, `${{ inputs.git-author-email }}`, `${{ inputs.git-committer-name }}`, and `${{ inputs.git-committer-email }}` directly into `$GITHUB_ENV` without the required sanitization step (`printf '%s' ... | tr -d '\n\r'`). An attacker-controlled newline in any of these values can inject arbitrary environment variables into subsequent steps.

Locations:

- `action.yml:116`

### github-env-injection (severity: high)

The 'Set environment variables (signed commits)' step routes `steps.import-gpg.outputs.name` and `steps.import-gpg.outputs.email` through env vars (`GIT_AUTHOR_NAME`, `GIT_AUTHOR_EMAIL`, `GIT_COMMITTER_NAME`, `GIT_COMMITTER_EMAIL`) and writes them to `$GITHUB_ENV` without sanitization. `steps.*.outputs.*` is an untrusted source; routing through an `env:` block does not sanitize the value. Example: `echo "GIT_AUTHOR_NAME=$GIT_AUTHOR_NAME" >> $GITHUB_ENV`

Locations:

- `action.yml:108`

### github-env-injection (severity: high)

The 'Set additional env variables (GIT_COMMIT_MESSAGE)' step writes `$COMMIT_MESSAGE` (sourced from `git log --format=%b -n 1`, which can contain attacker-controlled commit message content) to `$GITHUB_ENV` without sanitization. Although a random heredoc delimiter is used to prevent header injection in the key line, the raw value is written unsanitized: `echo "$COMMIT_MESSAGE" >> $GITHUB_ENV`. An attacker who controls commit message content (e.g. via a PR) can inject environment variables into subsequent steps.

Locations:

- `action.yml:142`

### unpinned-uses (severity: high)

Two `uses:` references in action.yml are pinned to mutable version tags rather than immutable 40-character commit SHAs, making the action vulnerable to supply-chain attacks if those tags are moved:
- `uses: DamianReeves/write-file-action@v1.3` (line 134)
- `uses: juliangruber/read-file-action@v1` (line 148)
These should be pinned to full SHA digests, e.g. `uses: DamianReeves/write-file-action@<40-char-sha> # v1.3`.

Locations:

- `action.yml:134`
- `action.yml:148`

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

**Fixes applied:** script-injection, github-env-injection, static-inline-injection, unpinned-uses

**Notes:**

Fixed all 9 findings in action.yml:

1. script-injection + static-inline-injection: Moved ${{ inputs.git-author-name }}, ${{ inputs.git-author-email }}, ${{ inputs.git-committer-name }}, ${{ inputs.git-committer-email }} from the run: block of 'Set environment variables (unsigned commits)' into an env: block, eliminating direct template interpolation in shell.

2. github-env-injection (unsigned commits): Added sanitization via `printf '%s' "$VAR" | tr -d '\n\r'` for all four git identity variables before writing to $GITHUB_ENV.

3. github-env-injection (signed commits): Added the same sanitization for the GPG-derived name/email values before writing to $GITHUB_ENV.

4. github-env-injection (GIT_COMMIT_MESSAGE): Added `printf '%s' "$COMMIT_MESSAGE" | tr -d '\r'` to strip carriage returns from the commit message before writing to $GITHUB_ENV (newlines are preserved as the heredoc delimiter mechanism already prevents key injection).

5. unpinned-uses: Pinned DamianReeves/write-file-action@v1.3 to SHA 6929a9a6d1807689191dcc8bbe62b54d70a32b42 and juliangruber/read-file-action@v1 to SHA 271ff311a4947af354c6abcd696a306553b9ec18.

### Iteration 2

**Fixes applied:** unpinned-uses, missing-permissions

**Notes:**

Fixed all 9 unpinned action references across three workflow files by resolving each tag/branch to its full 40-character SHA digest (preserving the original ref as a comment). Specifically: actions/checkout@v4 → 11d5960a..., DeterminateSystems/flake-checker-action@main → de924abd..., DeterminateSystems/determinate-nix-action@v3 → d96678350..., DeterminateSystems/flakehub-cache-action@main → 77c6bddd..., DeterminateSystems/update-flake-lock@main → ec13d37c..., nwisbeta/validate-yaml-schema@v2.0.0 → c3734e64.... Also added `permissions: {}` at the top level of validate.yml and `permissions: contents: read` at the job level to fix the missing-permissions finding.

