<!-- markdownlint-disable -->

# Hardening Report: DeterminateSystems--update-flake-lock/v29

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `2`

Action **DeterminateSystems--update-flake-lock/v29** was hardened automatically. 7 finding(s) were identified and resolved across 1 iteration(s).

## Findings Fixed

### script-injection (severity: high)

Sub-rule (a): The 'Set environment variables (unsigned commits)' run: block directly interpolates GitHub Actions expressions inside shell command strings. The lines `echo "GIT_AUTHOR_NAME=${{ inputs.git-author-name }}" >> $GITHUB_ENV`, `echo "GIT_AUTHOR_EMAIL=<${{ inputs.git-author-email }}>" >> $GITHUB_ENV`, `echo "GIT_COMMITTER_NAME=${{ inputs.git-committer-name }}" >> $GITHUB_ENV`, and `echo "GIT_COMMITTER_EMAIL=<${{ inputs.git-committer-email }}>" >> $GITHUB_ENV` all embed `${{ inputs.* }}` expressions directly in the shell script. These are expanded by the Actions template engine before the shell ever sees them, allowing an attacker-controlled value to inject arbitrary shell commands.

Locations:

- `action.yml:133`
- `action.yml:134`
- `action.yml:135`
- `action.yml:136`

### github-env-injection (severity: high)

The 'Set environment variables (signed commits)' run: block writes values sourced from `steps.import-gpg.outputs.*` (untrusted step outputs) to $GITHUB_ENV without the required sanitization step (`printf '%s' ... | tr -d '\n\r'`). Specifically: `echo "GIT_AUTHOR_NAME=$GIT_AUTHOR_NAME" >> $GITHUB_ENV`, `echo "GIT_AUTHOR_EMAIL=<$GIT_AUTHOR_EMAIL>" >> $GITHUB_ENV`, `echo "GIT_COMMITTER_NAME=$GIT_COMMITTER_NAME" >> $GITHUB_ENV`, and `echo "GIT_COMMITTER_EMAIL=<$GIT_COMMITTER_EMAIL>" >> $GITHUB_ENV`. A newline embedded in any of these values would allow injection of arbitrary environment variables into subsequent steps.

Locations:

- `action.yml:126`
- `action.yml:127`
- `action.yml:128`
- `action.yml:129`

### github-env-injection (severity: high)

The 'Set environment variables (unsigned commits)' run: block writes user-controlled `inputs.*` values directly to $GITHUB_ENV without the required sanitization step (`printf '%s' ... | tr -d '\n\r'`). The lines `echo "GIT_AUTHOR_NAME=${{ inputs.git-author-name }}" >> $GITHUB_ENV`, `echo "GIT_AUTHOR_EMAIL=<${{ inputs.git-author-email }}>" >> $GITHUB_ENV`, `echo "GIT_COMMITTER_NAME=${{ inputs.git-committer-name }}" >> $GITHUB_ENV`, and `echo "GIT_COMMITTER_EMAIL=<${{ inputs.git-committer-email }}>" >> $GITHUB_ENV` all write attacker-controllable input values to the special environment file. A newline in any input value would allow injection of arbitrary environment variables.

Locations:

- `action.yml:133`
- `action.yml:134`
- `action.yml:135`
- `action.yml:136`

### static-inline-injection (severity: high)

shell injection: expression "${{ inputs.git-author-name }}" appears directly in run: block of step "Set environment variables (unsigned commits)"; move to env: map

Locations:

- `action.yml:145`

### static-inline-injection (severity: high)

shell injection: expression "${{ inputs.git-author-email }}" appears directly in run: block of step "Set environment variables (unsigned commits)"; move to env: map

Locations:

- `action.yml:146`

### static-inline-injection (severity: high)

shell injection: expression "${{ inputs.git-committer-name }}" appears directly in run: block of step "Set environment variables (unsigned commits)"; move to env: map

Locations:

- `action.yml:147`

### static-inline-injection (severity: high)

shell injection: expression "${{ inputs.git-committer-email }}" appears directly in run: block of step "Set environment variables (unsigned commits)"; move to env: map

Locations:

- `action.yml:148`

## Iteration Notes

### Iteration 1

**Fixes applied:** script-injection, github-env-injection, static-inline-injection

**Notes:**

Fixed all findings in the 'Set environment variables (signed commits)' and 'Set environment variables (unsigned commits)' steps in action.yml:

1. For 'unsigned commits' step: Moved all ${{ inputs.* }} expressions (git-author-name, git-author-email, git-committer-name, git-committer-email) from the run: block into the step's env: block, eliminating script-injection and static-inline-injection findings.

2. For both steps: Added sanitization using `printf '%s' "$VAR" | tr -d '\n\r'` before writing each value to $GITHUB_ENV. Each value is captured into a `safe_*` variable first, then written to $GITHUB_ENV, preventing newline-based environment variable injection attacks.

