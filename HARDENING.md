<!-- markdownlint-disable -->

# Hardening Report: DeterminateSystems--update-flake-lock/v28

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `1`

Action **DeterminateSystems--update-flake-lock/v28** was hardened automatically. 7 finding(s) were identified and resolved across 1 iteration(s).

## Findings Fixed

### script-injection (severity: high)

Sub-rule (a): The 'Set environment variables (unsigned commits)' step directly interpolates `${{ inputs.git-author-name }}`, `${{ inputs.git-author-email }}`, `${{ inputs.git-committer-name }}`, and `${{ inputs.git-committer-email }}` inside `run:` shell command strings. These `inputs.*` expressions are expanded by the Actions template engine before the shell ever sees them, allowing an attacker-controlled value containing shell metacharacters (`;`, `|`, `$(...)`, etc.) to be executed as shell code. Example offending lines: `echo "GIT_AUTHOR_NAME=${{ inputs.git-author-name }}" >> $GITHUB_ENV` and `echo "GIT_COMMITTER_EMAIL=<${{ inputs.git-committer-email }}>" >> $GITHUB_ENV`.

Locations:

- `action.yml:143`

### github-env-injection (severity: high)

The 'Set environment variables (unsigned commits)' step writes `inputs.*` values directly to `$GITHUB_ENV` without the required sanitization step (`printf '%s' ... | tr -d '\n\r'`). An attacker can supply a newline in any of these inputs to inject arbitrary environment variable assignments into the runner environment. Offending lines: `echo "GIT_AUTHOR_NAME=${{ inputs.git-author-name }}" >> $GITHUB_ENV`, `echo "GIT_AUTHOR_EMAIL=<${{ inputs.git-author-email }}>" >> $GITHUB_ENV`, `echo "GIT_COMMITTER_NAME=${{ inputs.git-committer-name }}" >> $GITHUB_ENV`, `echo "GIT_COMMITTER_EMAIL=<${{ inputs.git-committer-email }}>" >> $GITHUB_ENV`.

Locations:

- `action.yml:143`

### github-env-injection (severity: high)

The 'Set environment variables (signed commits)' step places `steps.import-gpg.outputs.name` and `steps.import-gpg.outputs.email` (both are `steps.*.outputs.*` — untrusted per the check scope) into env vars `GIT_AUTHOR_NAME`, `GIT_AUTHOR_EMAIL`, `GIT_COMMITTER_NAME`, `GIT_COMMITTER_EMAIL`, then writes them to `$GITHUB_ENV` without the required sanitization (`printf '%s' ... | tr -d '\n\r'`). A malicious GPG key whose name or email contains a newline could inject arbitrary environment variables. Offending lines: `echo "GIT_AUTHOR_NAME=$GIT_AUTHOR_NAME" >> $GITHUB_ENV`, `echo "GIT_AUTHOR_EMAIL=<$GIT_AUTHOR_EMAIL>" >> $GITHUB_ENV`, `echo "GIT_COMMITTER_NAME=$GIT_COMMITTER_NAME" >> $GITHUB_ENV`, `echo "GIT_COMMITTER_EMAIL=<$GIT_COMMITTER_EMAIL>" >> $GITHUB_ENV`.

Locations:

- `action.yml:135`

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

**Fixes applied:** script-injection, github-env-injection, static-inline-injection

**Notes:**

Fixed two steps in action.yml:

1. 'Set environment variables (unsigned commits)': Moved all four ${{ inputs.* }} expressions (git-author-name, git-author-email, git-committer-name, git-committer-email) from the run: shell block into the step's env: map, eliminating script-injection and static-inline-injection. Added printf + tr -d '\n\r' sanitization before writing each value to $GITHUB_ENV, eliminating github-env-injection.

2. 'Set environment variables (signed commits)': Added printf + tr -d '\n\r' sanitization for all four values (steps.import-gpg.outputs.name/email) before writing to $GITHUB_ENV, eliminating github-env-injection. The values were already in the env: map so no script-injection fix was needed here.

Both steps now also quote $GITHUB_ENV properly as "$GITHUB_ENV".

