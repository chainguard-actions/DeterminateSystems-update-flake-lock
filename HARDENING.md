<!-- markdownlint-disable -->

# Hardening Report: DeterminateSystems--update-flake-lock/v29

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `2`

Action **DeterminateSystems--update-flake-lock/v29** was hardened automatically. 8 finding(s) were identified and resolved across 1 iteration(s).

## Findings Fixed

### script-injection (severity: high)

Sub-rule (a): The 'Set environment variables (unsigned commits)' run: block directly interpolates ${{ inputs.git-author-name }}, ${{ inputs.git-author-email }}, ${{ inputs.git-committer-name }}, and ${{ inputs.git-committer-email }} inside shell command strings. These expressions are expanded by the GitHub Actions template engine before the shell sees them, allowing an attacker-controlled input value containing shell metacharacters to execute arbitrary commands. Example offending line: `echo "GIT_AUTHOR_NAME=${{ inputs.git-author-name }}" >> $GITHUB_ENV`

Locations:

- `action.yml:133`

### github-env-injection (severity: high)

The 'Set environment variables (unsigned commits)' run: block writes inputs.git-author-name, inputs.git-author-email, inputs.git-committer-name, and inputs.git-committer-email directly to $GITHUB_ENV via ${{ inputs.* }} interpolation without the required sanitization step (printf '%s' ... | tr -d '\n\r'). An attacker can inject newlines into these values to poison GITHUB_ENV with arbitrary key=value pairs, leading to environment variable injection in subsequent steps.

Locations:

- `action.yml:133`

### github-env-injection (severity: high)

The 'Set environment variables (signed commits)' run: block writes the env vars GIT_AUTHOR_NAME, GIT_AUTHOR_EMAIL, GIT_COMMITTER_NAME, and GIT_COMMITTER_EMAIL (sourced from steps.import-gpg.outputs.name and steps.import-gpg.outputs.email, which are untrusted step outputs per the check spec) to $GITHUB_ENV without the required sanitization step (printf '%s' ... | tr -d '\n\r'). Example: `echo "GIT_AUTHOR_NAME=$GIT_AUTHOR_NAME" >> $GITHUB_ENV`. Routing through an env: variable does not sanitize the value.

Locations:

- `action.yml:124`

### github-env-injection (severity: high)

The 'Set additional env variables (GIT_COMMIT_MESSAGE)' run: block writes $COMMIT_MESSAGE (derived from `git log --format=%b -n 1`, which is the commit message body and is attacker-controlled in a PR context) to $GITHUB_ENV via `echo "$COMMIT_MESSAGE" >> $GITHUB_ENV` without the required sanitization step. Although a random heredoc delimiter is used for the outer GIT_COMMIT_MESSAGE assignment, the raw commit message content is still written unsanitized to the environment file.

Locations:

- `action.yml:175`

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

Fixed three categories of findings in hardened/action/action.yml:

1. **Unsigned commits step (lines ~133-148)**: Moved all four ${{ inputs.git-* }} expressions from the run: block into an env: map. Added printf '%s' ... | tr -d '\n\r' sanitization for each value before writing to $GITHUB_ENV, preventing both shell injection and newline-based GITHUB_ENV injection.

2. **Signed commits step (lines ~124-131)**: Added printf '%s' ... | tr -d '\n\r' sanitization for the GPG-derived name/email values (already in env vars) before writing to $GITHUB_ENV.

3. **GIT_COMMIT_MESSAGE step (lines ~175-180)**: Added sanitization of the git log commit message body using printf '%s' ... | tr -d '\n\r' before writing to $GITHUB_ENV, preventing newline injection from attacker-controlled commit messages. Also quoted $GITHUB_ENV references throughout.

