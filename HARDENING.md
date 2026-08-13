<!-- markdownlint-disable -->

# Hardening Report: DeterminateSystems--update-flake-lock/v25

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `2`

Action **DeterminateSystems--update-flake-lock/v25** was hardened automatically. 7 finding(s) were identified and resolved across 3 iteration(s).

## Findings Fixed

### script-injection (severity: high)

Sub-rule (a): The 'Set environment variables (unsigned commits)' run: block directly interpolates ${{ inputs.git-author-name }}, ${{ inputs.git-author-email }}, ${{ inputs.git-committer-name }}, and ${{ inputs.git-committer-email }} inside shell echo commands. These are attacker-controlled values that flow through YAML template substitution before the shell sees them, enabling command injection. Example offending line: echo "GIT_AUTHOR_NAME=${{ inputs.git-author-name }}" >> $GITHUB_ENV

Locations:

- `action.yml:122`

### github-env-injection (severity: high)

Two steps write untrusted values to $GITHUB_ENV without the required sanitization step (printf '%s' ... | tr -d '\n\r'). (1) 'Set environment variables (signed commits)': writes $GIT_AUTHOR_NAME, $GIT_AUTHOR_EMAIL, $GIT_COMMITTER_NAME, $GIT_COMMITTER_EMAIL — sourced from steps.import-gpg.outputs.* (which are derived from caller-supplied GPG inputs) — directly to $GITHUB_ENV with plain echo. (2) 'Set environment variables (unsigned commits)': directly interpolates ${{ inputs.git-author-name }}, ${{ inputs.git-author-email }}, ${{ inputs.git-committer-name }}, ${{ inputs.git-committer-email }} into echo commands writing to $GITHUB_ENV, with no newline sanitization. An attacker-controlled input containing a newline can inject arbitrary environment variables.

Locations:

- `action.yml:114`
- `action.yml:122`

### unpinned-uses (severity: high)

Two uses: references are pinned to mutable version tags rather than immutable full 40-character SHA commit hashes, making them vulnerable to supply-chain attacks if the tag is moved: (1) 'uses: DamianReeves/write-file-action@v1.3' — should be pinned to a full SHA. (2) 'uses: juliangruber/read-file-action@v1' — should be pinned to a full SHA.

Locations:

- `action.yml:155`
- `action.yml:163`

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

**Fixes applied:** script-injection, static-inline-injection, github-env-injection, unpinned-uses

**Notes:**

Fixed all 7 findings in action.yml:

1. **unpinned-uses**: Pinned `DamianReeves/write-file-action@v1.3` → `@6929a9a6d1807689191dcc8bbe62b54d70a32b42 # v1.3` and `juliangruber/read-file-action@v1` → `@271ff311a4947af354c6abcd696a306553b9ec18 # v1`.

2. **script-injection / static-inline-injection** (4 findings): Moved all `${{ inputs.git-author-name }}`, `${{ inputs.git-author-email }}`, `${{ inputs.git-committer-name }}`, `${{ inputs.git-committer-email }}` expressions from the `run:` block of the 'Set environment variables (unsigned commits)' step into the step's `env:` block. They are now referenced as plain shell variables.

3. **github-env-injection** (2 findings): Both the 'signed commits' and 'unsigned commits' steps now sanitize all values before writing to `$GITHUB_ENV` using `safe_var=$(printf '%s' "$VAR" | tr -d '\n\r')`, preventing newline injection attacks.

### Iteration 1

**Fixes applied:** unpinned-uses, missing-permissions

**Notes:**

Fixed all unpinned `uses:` references across three workflow files by resolving each tag/branch to its full 40-character commit SHA (preserving the original tag/branch as a comment). Specifically: ci.yml — pinned actions/checkout@v4, DeterminateSystems/flake-checker-action@main, DeterminateSystems/determinate-nix-action@v3, DeterminateSystems/flakehub-cache-action@main; update.yml — pinned actions/checkout@v4, DeterminateSystems/determinate-nix-action@v3, DeterminateSystems/flakehub-cache-action@main; validate.yml — pinned actions/checkout@v4, nwisbeta/validate-yaml-schema@v2.0.0. Also added a top-level `permissions: contents: read` block to validate.yml to address the missing-permissions finding (the validate job only needs to read repository contents).

### Iteration 2

**Fixes applied:** github-env-injection

**Notes:**

Fixed the 'Set additional env variables (GIT_COMMIT_MESSAGE)' step in hardened/action/action.yml. The original code used a random heredoc delimiter to write the git commit message body to $GITHUB_ENV, but the message itself could contain newlines that inject additional environment variables. The fix captures the commit message, sanitizes it with `printf '%s' "$COMMIT_MESSAGE" | tr -d '\n\r'` to strip all newlines and carriage returns, then writes the safe single-line value using the simple `KEY=value` format to $GITHUB_ENV.

