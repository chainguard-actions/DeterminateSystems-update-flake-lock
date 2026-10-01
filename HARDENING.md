<!-- markdownlint-disable -->

# Hardening Report: DeterminateSystems--update-flake-lock/v28

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `2`

Action **DeterminateSystems--update-flake-lock/v28** was hardened automatically. 7 finding(s) were identified and resolved across 1 iteration(s).

## Findings Fixed

### script-injection (severity: high)

Sub-rule (a): The 'Set environment variables (unsigned commits)' run: block directly interpolates GitHub Actions expressions inside shell commands. The values `${{ inputs.git-author-name }}`, `${{ inputs.git-author-email }}`, `${{ inputs.git-committer-name }}`, and `${{ inputs.git-committer-email }}` are template-substituted directly into the shell script before execution, allowing an attacker to inject arbitrary shell commands via these inputs. Example offending line: `echo "GIT_AUTHOR_NAME=${{ inputs.git-author-name }}" >> $GITHUB_ENV`

Locations:

- `action.yml:137`
- `action.yml:138`
- `action.yml:139`
- `action.yml:140`

### github-env-injection (severity: high)

The 'Set environment variables (signed commits)' step writes values sourced from `steps.import-gpg.outputs.name` and `steps.import-gpg.outputs.email` (untrusted `steps.*.outputs.*` values) into `$GITHUB_ENV` via env vars `$GIT_AUTHOR_NAME`, `$GIT_AUTHOR_EMAIL`, `$GIT_COMMITTER_NAME`, `$GIT_COMMITTER_EMAIL` without the required sanitization step (`printf '%s' ... | tr -d '\n\r'`). A newline embedded in these values could inject arbitrary environment variables into subsequent steps.

Locations:

- `action.yml:128`
- `action.yml:129`
- `action.yml:130`
- `action.yml:131`

### github-env-injection (severity: high)

The 'Set environment variables (unsigned commits)' step directly interpolates `${{ inputs.git-author-name }}`, `${{ inputs.git-author-email }}`, `${{ inputs.git-committer-name }}`, and `${{ inputs.git-committer-email }}` into shell echo commands that write to `$GITHUB_ENV`, without the required sanitization step (`printf '%s' ... | tr -d '\n\r'`). A newline in any of these user-controlled inputs could inject arbitrary environment variables into subsequent steps.

Locations:

- `action.yml:137`
- `action.yml:138`
- `action.yml:139`
- `action.yml:140`

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

1. 'Set environment variables (unsigned commits)': Moved all four ${{ inputs.* }} expressions (git-author-name, git-author-email, git-committer-name, git-committer-email) from the run: block into the step's env: block to prevent script injection. Added sanitization using `printf '%s' "$VAR" | tr -d '\n\r'` before writing each value to $GITHUB_ENV to prevent newline injection.

2. 'Set environment variables (signed commits)': Added the same sanitization pattern (`printf '%s' "$VAR" | tr -d '\n\r'`) before writing the GPG-derived name and email values to $GITHUB_ENV to prevent newline injection. The values were already in env: vars, so no script-injection fix was needed here.

Both steps now quote $GITHUB_ENV properly as "$GITHUB_ENV".

