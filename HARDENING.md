<!-- markdownlint-disable -->

# Hardening Report: DeterminateSystems--update-flake-lock/v28

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `2`

Action **DeterminateSystems--update-flake-lock/v28** was hardened automatically. 6 finding(s) were identified and resolved across 1 iteration(s).

## Findings Fixed

### script-injection (severity: high)

Sub-rule (a): The 'Set environment variables (unsigned commits)' run: block directly interpolates GitHub Actions expressions inside shell commands. The values `${{ inputs.git-author-name }}`, `${{ inputs.git-author-email }}`, `${{ inputs.git-committer-name }}`, and `${{ inputs.git-committer-email }}` are embedded directly in shell strings written to $GITHUB_ENV. An attacker-controlled input value containing shell metacharacters or newlines can break out of the echo command context. These inputs should be placed in env: variables and the shell expansions double-quoted.

Locations:

- `action.yml:132`
- `action.yml:133`
- `action.yml:134`
- `action.yml:135`

### github-env-injection (severity: high)

Two run: steps write untrusted values to $GITHUB_ENV without the required sanitization step (`printf '%s' ... | tr -d '\n\r'`).

(1) 'Set environment variables (signed commits)' (lines ~124-127): env vars GIT_AUTHOR_NAME, GIT_AUTHOR_EMAIL, GIT_COMMITTER_NAME, GIT_COMMITTER_EMAIL are sourced from `steps.import-gpg.outputs.*` (workflow-controlled) and written directly via `echo "VAR=$VAR" >> $GITHUB_ENV` without newline sanitization. A value containing a newline could inject arbitrary environment variables.

(2) 'Set environment variables (unsigned commits)' (lines ~132-135): `${{ inputs.git-author-name }}`, `${{ inputs.git-author-email }}`, `${{ inputs.git-committer-name }}`, `${{ inputs.git-committer-email }}` are interpolated directly into echo commands that write to $GITHUB_ENV, with no sanitization applied before the write.

Locations:

- `action.yml:124`
- `action.yml:125`
- `action.yml:126`
- `action.yml:127`
- `action.yml:132`
- `action.yml:133`
- `action.yml:134`
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

Fixed both 'Set environment variables' steps in action.yml:

1. 'Set environment variables (signed commits)': Added newline sanitization using `printf '%s' "$VAR" | tr -d '\n\r'` before writing each value to $GITHUB_ENV. The values were already in the env: block, so only the sanitization step was missing.

2. 'Set environment variables (unsigned commits)': Moved all four `${{ inputs.* }}` expressions out of the run: block into an env: block (GIT_AUTHOR_NAME, GIT_AUTHOR_EMAIL, GIT_COMMITTER_NAME, GIT_COMMITTER_EMAIL). Added the same newline sanitization using `printf '%s' "$VAR" | tr -d '\n\r'` before writing to $GITHUB_ENV. This fixes both the script-injection/static-inline-injection findings (expressions no longer directly interpolated in shell) and the github-env-injection finding (values sanitized before writing to GITHUB_ENV).

