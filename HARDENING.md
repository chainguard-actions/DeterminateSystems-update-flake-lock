<!-- markdownlint-disable -->

# Hardening Report: DeterminateSystems--update-flake-lock/v29

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `2`

Action **DeterminateSystems--update-flake-lock/v29** was hardened automatically. 6 finding(s) were identified and resolved across 1 iteration(s).

## Findings Fixed

### script-injection (severity: high)

Sub-rule (a): The 'Set environment variables (unsigned commits)' run: block directly interpolates ${{ inputs.git-author-name }}, ${{ inputs.git-author-email }}, ${{ inputs.git-committer-name }}, and ${{ inputs.git-committer-email }} inside the shell script string. These user-controlled inputs flow through YAML template substitution before the shell processes them, enabling command injection. For example: `echo "GIT_AUTHOR_NAME=${{ inputs.git-author-name }}" >> $GITHUB_ENV`

Locations:

- `action.yml:144`

### github-env-injection (severity: high)

Two steps write untrusted values to $GITHUB_ENV without the required sanitization (printf '%s' ... | tr -d '\n\r'). (1) 'Set environment variables (signed commits)': writes $GIT_AUTHOR_NAME, $GIT_AUTHOR_EMAIL, $GIT_COMMITTER_NAME, $GIT_COMMITTER_EMAIL — sourced from steps.import-gpg.outputs.* (an untrusted steps.*.outputs.* context) — directly to $GITHUB_ENV via unquoted env-var expansion with no newline stripping. A newline in any GPG output field would allow injecting arbitrary environment variables. (2) 'Set environment variables (unsigned commits)': writes ${{ inputs.git-author-name }}, ${{ inputs.git-author-email }}, ${{ inputs.git-committer-name }}, ${{ inputs.git-committer-email }} directly to $GITHUB_ENV with no sanitization, allowing a caller to inject arbitrary environment variables via embedded newlines.

Locations:

- `action.yml:133`
- `action.yml:144`

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

Fixed both 'Set environment variables' steps in action.yml:

1. 'Set environment variables (unsigned commits)': Moved all four ${{ inputs.* }} expressions (git-author-name, git-author-email, git-committer-name, git-committer-email) from the run: block into the step's env: block. The shell script now references them as plain environment variables, eliminating script-injection and static-inline-injection risks.

2. Both steps now sanitize values before writing to $GITHUB_ENV using `printf '%s' "$VAR" | tr -d '\n\r'` to strip embedded newlines/carriage returns, preventing github-env-injection attacks. This applies to both the signed commits step (which sources values from steps.import-gpg.outputs.*) and the unsigned commits step (which sources values from inputs.*). Also quoted $GITHUB_ENV properly in both steps.

