<!-- markdownlint-disable -->

# Hardening Report: DeterminateSystems--update-flake-lock/v29

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `2`

Action **DeterminateSystems--update-flake-lock/v29** was hardened automatically. 7 finding(s) were identified and resolved across 2 iteration(s).

## Findings Fixed

### script-injection (severity: high)

Sub-rule (a): The 'Set environment variables (unsigned commits)' run: block directly interpolates ${{ inputs.git-author-name }}, ${{ inputs.git-author-email }}, ${{ inputs.git-committer-name }}, and ${{ inputs.git-committer-email }} inside shell command strings. Any of these inputs can contain shell metacharacters (e.g. newlines, command substitution) that are evaluated by the shell before the value reaches $GITHUB_ENV. Example offending lines: `echo "GIT_AUTHOR_NAME=${{ inputs.git-author-name }}" >> $GITHUB_ENV`

Locations:

- `action.yml:128`

### github-env-injection (severity: high)

The 'Set environment variables (unsigned commits)' run: block writes ${{ inputs.git-author-name }}, ${{ inputs.git-author-email }}, ${{ inputs.git-committer-name }}, and ${{ inputs.git-committer-email }} directly to $GITHUB_ENV without the required sanitization step (printf '%s' ... | tr -d '\n\r'). An attacker-controlled input containing a newline can inject arbitrary environment variable assignments into subsequent steps.

Locations:

- `action.yml:128`

### github-env-injection (severity: high)

The 'Set environment variables (signed commits)' run: block writes GIT_AUTHOR_NAME, GIT_AUTHOR_EMAIL, GIT_COMMITTER_NAME, and GIT_COMMITTER_EMAIL to $GITHUB_ENV. These env vars are sourced from steps.import-gpg.outputs.name and steps.import-gpg.outputs.email (steps.*.outputs.* is an untrusted source per the check rules). The values are routed through env: variables but written to $GITHUB_ENV without the required sanitization step (printf '%s' ... | tr -d '\n\r'). A newline in the GPG output could inject arbitrary environment variable assignments.

Locations:

- `action.yml:119`

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

1. 'Set environment variables (unsigned commits)': Moved all four ${{ inputs.* }} expressions (${{ inputs.git-author-name }}, ${{ inputs.git-author-email }}, ${{ inputs.git-committer-name }}, ${{ inputs.git-committer-email }}) from the run: block into a new env: block. Added sanitization using `printf '%s' "$VAR" | tr -d '\n\r'` for each value before writing to $GITHUB_ENV.

2. 'Set environment variables (signed commits)': Added sanitization using `printf '%s' "$VAR" | tr -d '\n\r'` for each value (GIT_AUTHOR_NAME, GIT_AUTHOR_EMAIL, GIT_COMMITTER_NAME, GIT_COMMITTER_EMAIL) before writing to $GITHUB_ENV. These values come from steps.import-gpg.outputs.* which were already in env vars.

Both steps also now properly quote "$GITHUB_ENV" in the redirection.

### Iteration 1

**Fixes applied:** github-env-injection

**Notes:**

Fixed the 'Set additional env variables (GIT_COMMIT_MESSAGE)' step in action.yml. The commit message body from `git log --format=%b -n 1` is now sanitized with `printf '%s' "$COMMIT_MESSAGE" | tr -d '\n\r'` before being written to $GITHUB_ENV. The sanitized value is stored in SAFE_COMMIT_MESSAGE and used in place of the raw COMMIT_MESSAGE throughout the step. Also added proper quoting around $GITHUB_ENV references.

