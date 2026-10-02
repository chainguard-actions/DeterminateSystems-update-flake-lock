<!-- markdownlint-disable -->

# Hardening Report: DeterminateSystems--update-flake-lock/v26

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `2`

Action **DeterminateSystems--update-flake-lock/v26** was hardened automatically. 7 finding(s) were identified and resolved across 1 iteration(s).

## Findings Fixed

### unpinned-uses (severity: high)

Two `uses:` references in action.yml are pinned to mutable version tags instead of full 40-character commit SHAs, making them vulnerable to supply-chain attacks if the tag is moved:
- `DamianReeves/write-file-action@v1.3` (mutable tag)
- `juliangruber/read-file-action@v1` (mutable tag)
These should be pinned to their full SHA digests.

Locations:

- `action.yml:148`
- `action.yml:160`

### script-injection (severity: high)

Sub-rule (a): The 'Set environment variables (unsigned commits)' step directly interpolates `${{ inputs.* }}` expressions inside `run:` shell command strings. These values are substituted by the YAML template engine before the shell processes them, allowing an attacker-controlled input to inject arbitrary shell commands. Offending lines:
  `echo "GIT_AUTHOR_NAME=${{ inputs.git-author-name }}" >> $GITHUB_ENV`
  `echo "GIT_AUTHOR_EMAIL=<${{ inputs.git-author-email }}>" >> $GITHUB_ENV`
  `echo "GIT_COMMITTER_NAME=${{ inputs.git-committer-name }}" >> $GITHUB_ENV`
  `echo "GIT_COMMITTER_EMAIL=<${{ inputs.git-committer-email }}>" >> $GITHUB_ENV`

Locations:

- `action.yml:141`

### github-env-injection (severity: high)

Two `run:` steps write untrusted values to `$GITHUB_ENV` without the required sanitization (`printf '%s' ... | tr -d '\n\r'`):

1. 'Set environment variables (signed commits)': writes `$GIT_AUTHOR_NAME`, `$GIT_AUTHOR_EMAIL`, `$GIT_COMMITTER_NAME`, `$GIT_COMMITTER_EMAIL` — all sourced from `steps.import-gpg.outputs.*` (workflow-controllable step outputs) — directly to `$GITHUB_ENV` with no newline stripping. A value containing a newline could inject arbitrary environment variables.

2. 'Set environment variables (unsigned commits)': writes `${{ inputs.git-author-name }}`, `${{ inputs.git-author-email }}`, `${{ inputs.git-committer-name }}`, `${{ inputs.git-committer-email }}` (caller-supplied inputs) directly to `$GITHUB_ENV` with no sanitization. An attacker can supply a value containing `\nARBITRARY_VAR=malicious` to inject additional environment variables.

Locations:

- `action.yml:132`
- `action.yml:141`

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

Fixed all findings in hardened/action/action.yml:
1. Pinned DamianReeves/write-file-action@v1.3 → @6929a9a6d1807689191dcc8bbe62b54d70a32b42 # v1.3
2. Pinned juliangruber/read-file-action@v1 → @271ff311a4947af354c6abcd696a306553b9ec18 # v1
3. Moved all ${{ inputs.git-author-name/email/committer-name/email }} expressions in the 'unsigned commits' step into an env: block, eliminating shell injection risk.
4. Added newline sanitization (printf '%s' ... | tr -d '\n\r') before writing all git identity values to $GITHUB_ENV in both the signed and unsigned commit steps, preventing GITHUB_ENV injection attacks.

