<!-- markdownlint-disable -->

# Hardening Report: DeterminateSystems--update-flake-lock/v29

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `2`

Action **DeterminateSystems--update-flake-lock/v29** was hardened automatically. 6 finding(s) were identified and resolved across 1 iteration(s).

## Findings Fixed

### script-injection (severity: high)

Sub-rule (a): The 'Set environment variables (unsigned commits)' run: block directly interpolates ${{ inputs.git-author-name }}, ${{ inputs.git-author-email }}, ${{ inputs.git-committer-name }}, and ${{ inputs.git-committer-email }} inside shell command strings. These are user-controlled inputs that flow through YAML template substitution before the shell sees them, enabling script injection. Offending lines:
  echo "GIT_AUTHOR_NAME=${{ inputs.git-author-name }}" >> $GITHUB_ENV
  echo "GIT_AUTHOR_EMAIL=<${{ inputs.git-author-email }}>" >> $GITHUB_ENV
  echo "GIT_COMMITTER_NAME=${{ inputs.git-committer-name }}" >> $GITHUB_ENV
  echo "GIT_COMMITTER_EMAIL=<${{ inputs.git-committer-email }}>" >> $GITHUB_ENV

Locations:

- `action.yml:130`
- `action.yml:131`
- `action.yml:132`
- `action.yml:133`

### github-env-injection (severity: high)

Two steps write untrusted values to $GITHUB_ENV without the required sanitization step (printf '%s' ... | tr -d '\n\r').

(1) 'Set environment variables (unsigned commits)': directly writes ${{ inputs.git-author-name }}, ${{ inputs.git-author-email }}, ${{ inputs.git-committer-name }}, and ${{ inputs.git-committer-email }} to $GITHUB_ENV. These are caller-controlled inputs and can contain newlines to inject arbitrary environment variables.

(2) 'Set environment variables (signed commits)': writes $GIT_AUTHOR_NAME, $GIT_AUTHOR_EMAIL, $GIT_COMMITTER_NAME, $GIT_COMMITTER_EMAIL (sourced from steps.import-gpg.outputs.*, a steps.*.outputs.* source which is untrusted per the check scope) to $GITHUB_ENV via env: vars without sanitization:
  echo "GIT_AUTHOR_NAME=$GIT_AUTHOR_NAME" >> $GITHUB_ENV
  echo "GIT_AUTHOR_EMAIL=<$GIT_AUTHOR_EMAIL>" >> $GITHUB_ENV
  echo "GIT_COMMITTER_NAME=$GIT_COMMITTER_NAME" >> $GITHUB_ENV
  echo "GIT_COMMITTER_EMAIL=<$GIT_COMMITTER_EMAIL>" >> $GITHUB_ENV

Locations:

- `action.yml:122`
- `action.yml:123`
- `action.yml:124`
- `action.yml:125`
- `action.yml:130`
- `action.yml:131`
- `action.yml:132`
- `action.yml:133`

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

Fixed two steps in action.yml:

1. 'Set environment variables (unsigned commits)': Moved all four ${{ inputs.* }} expressions (git-author-name, git-author-email, git-committer-name, git-committer-email) from the run: block into an env: block, eliminating script injection. Added newline sanitization using `printf '%s' "$VAR" | tr -d '\n\r'` before writing each value to $GITHUB_ENV.

2. 'Set environment variables (signed commits)': Added the same newline sanitization pattern for the four GPG-derived values (already in env: block) before writing them to $GITHUB_ENV.

Both steps now write only sanitized values to $GITHUB_ENV, preventing newline-based environment variable injection attacks.

