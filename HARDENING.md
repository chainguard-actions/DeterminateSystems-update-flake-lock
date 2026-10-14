<!-- markdownlint-disable -->

# Hardening Report: DeterminateSystems--update-flake-lock/v28

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `2`

Action **DeterminateSystems--update-flake-lock/v28** was hardened automatically. 6 finding(s) were identified and resolved across 1 iteration(s).

## Findings Fixed

### script-injection (severity: high)

Rule (a) violation: The 'Set environment variables (unsigned commits)' run: block directly interpolates ${{ inputs.* }} expressions inside shell command strings. Specifically, `${{ inputs.git-author-name }}`, `${{ inputs.git-author-email }}`, `${{ inputs.git-committer-name }}`, and `${{ inputs.git-committer-email }}` are expanded by the Actions template engine before the shell ever sees them, allowing an attacker-controlled value to inject arbitrary shell commands. Offending lines:
  echo "GIT_AUTHOR_NAME=${{ inputs.git-author-name }}" >> $GITHUB_ENV
  echo "GIT_AUTHOR_EMAIL=<${{ inputs.git-author-email }}>" >> $GITHUB_ENV
  echo "GIT_COMMITTER_NAME=${{ inputs.git-committer-name }}" >> $GITHUB_ENV
  echo "GIT_COMMITTER_EMAIL=<${{ inputs.git-committer-email }}>" >> $GITHUB_ENV

Locations:

- `action.yml:145`
- `action.yml:146`
- `action.yml:147`
- `action.yml:148`

### github-env-injection (severity: high)

Two run: blocks write untrusted values to $GITHUB_ENV without the required sanitization step (printf '%s' ... | tr -d '\n\r').

(1) 'Set environment variables (signed commits)' step (lines ~137-140): Writes $GIT_AUTHOR_NAME, $GIT_AUTHOR_EMAIL, $GIT_COMMITTER_NAME, $GIT_COMMITTER_EMAIL to $GITHUB_ENV. These variables are sourced from steps.import-gpg.outputs.* (untrusted step outputs set via the env: block) and are forwarded without sanitization, e.g.:
  echo "GIT_AUTHOR_NAME=$GIT_AUTHOR_NAME" >> $GITHUB_ENV
  echo "GIT_AUTHOR_EMAIL=<$GIT_AUTHOR_EMAIL>" >> $GITHUB_ENV

(2) 'Set environment variables (unsigned commits)' step (lines ~145-148): Directly writes ${{ inputs.* }} values to $GITHUB_ENV without sanitization, e.g.:
  echo "GIT_AUTHOR_NAME=${{ inputs.git-author-name }}" >> $GITHUB_ENV
  echo "GIT_AUTHOR_EMAIL=<${{ inputs.git-author-email }}>" >> $GITHUB_ENV

A newline injected into any of these values would allow an attacker to define arbitrary environment variables or override existing ones in subsequent steps.

Locations:

- `action.yml:137`
- `action.yml:138`
- `action.yml:139`
- `action.yml:140`
- `action.yml:145`
- `action.yml:146`
- `action.yml:147`
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

**Fixes applied:** script-injection, github-env-injection, static-inline-injection

**Notes:**

Fixed two steps in action.yml:

1. 'Set environment variables (unsigned commits)' step: Moved all four ${{ inputs.* }} expressions (git-author-name, git-author-email, git-committer-name, git-committer-email) out of the run: block and into the step's env: block. They are now referenced as plain shell variables ($GIT_AUTHOR_NAME, etc.) in the run: script, eliminating the script-injection risk.

2. Both 'Set environment variables (signed commits)' and 'Set environment variables (unsigned commits)' steps: Added newline sanitization before writing to $GITHUB_ENV. Each value is now sanitized with `printf '%s' "$VAR" | tr -d '\n\r'` into a `safe_*` variable before being echoed to $GITHUB_ENV, preventing github-env-injection attacks where a newline in a value could define arbitrary environment variables in subsequent steps.

