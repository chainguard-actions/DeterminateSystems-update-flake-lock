<!-- markdownlint-disable -->

# Hardening Report: DeterminateSystems--update-flake-lock/v25

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `2`

Action **DeterminateSystems--update-flake-lock/v25** was hardened automatically. 8 finding(s) were identified and resolved across 2 iteration(s).

## Findings Fixed

### script-injection (severity: high)

Rule (a) violation: The 'Set environment variables (unsigned commits)' run: block directly interpolates ${{ inputs.git-author-name }}, ${{ inputs.git-author-email }}, ${{ inputs.git-committer-name }}, and ${{ inputs.git-committer-email }} inside shell command strings. These are caller-controlled inputs that flow through YAML template substitution before the shell sees them, enabling script injection. Offending lines: `echo "GIT_AUTHOR_NAME=${{ inputs.git-author-name }}" >> $GITHUB_ENV`, `echo "GIT_AUTHOR_EMAIL=<${{ inputs.git-author-email }}>" >> $GITHUB_ENV`, `echo "GIT_COMMITTER_NAME=${{ inputs.git-committer-name }}" >> $GITHUB_ENV`, `echo "GIT_COMMITTER_EMAIL=<${{ inputs.git-committer-email }}>" >> $GITHUB_ENV`.

Locations:

- `action.yml:117`

### github-env-injection (severity: high)

The 'Set environment variables (unsigned commits)' run: block writes caller-controlled inputs (${{ inputs.git-author-name }}, ${{ inputs.git-author-email }}, ${{ inputs.git-committer-name }}, ${{ inputs.git-committer-email }}) directly to $GITHUB_ENV without the required sanitization step (printf '%s' ... | tr -d '\n\r'). An attacker can inject newlines to set arbitrary environment variables for subsequent steps.

Locations:

- `action.yml:117`

### github-env-injection (severity: high)

The 'Set environment variables (signed commits)' run: block writes env vars $GIT_AUTHOR_NAME, $GIT_AUTHOR_EMAIL, $GIT_COMMITTER_NAME, $GIT_COMMITTER_EMAIL (sourced from steps.import-gpg.outputs.name and steps.import-gpg.outputs.email, which are workflow-controllable step outputs) to $GITHUB_ENV without the required sanitization step (printf '%s' ... | tr -d '\n\r'). Routing through env: does not sanitize the values. An attacker controlling the GPG key input could inject newlines to set arbitrary environment variables.

Locations:

- `action.yml:110`

### unpinned-uses (severity: high)

Two uses: references are pinned to mutable tags rather than full 40-character commit SHAs, making the action vulnerable to supply-chain attacks if those tags are moved: (1) `DamianReeves/write-file-action@v1.3` — uses a version tag; (2) `juliangruber/read-file-action@v1` — uses a version tag. Both should be pinned to a full SHA digest (e.g. `@<40-hex-char-sha> # v1.3`).

Locations:

- `action.yml:143`
- `action.yml:152`

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

**Fixes applied:** script-injection, static-inline-injection, github-env-injection, unpinned-uses

**Notes:**

Fixed all 8 findings in action.yml:
1. 'Set environment variables (unsigned commits)': Moved all ${{ inputs.git-author-name }}, ${{ inputs.git-author-email }}, ${{ inputs.git-committer-name }}, ${{ inputs.git-committer-email }} expressions from inline run: shell strings into an env: block (fixes script-injection and static-inline-injection). Added printf/tr sanitization before writing to $GITHUB_ENV (fixes github-env-injection).
2. 'Set environment variables (signed commits)': Added printf/tr sanitization for GIT_AUTHOR_NAME, GIT_AUTHOR_EMAIL, GIT_COMMITTER_NAME, GIT_COMMITTER_EMAIL before writing to $GITHUB_ENV (fixes github-env-injection).
3. Pinned DamianReeves/write-file-action@v1.3 to full SHA @6929a9a6d1807689191dcc8bbe62b54d70a32b42 # v1.3.
4. Pinned juliangruber/read-file-action@v1 to full SHA @271ff311a4947af354c6abcd696a306553b9ec18 # v1.

### Iteration 2

**Fixes applied:** github-env-injection

**Notes:**

Fixed the 'Set additional env variables (GIT_COMMIT_MESSAGE)' step in action.yml. Replaced the heredoc delimiter pattern (which prevented delimiter collision but not injection of other variable assignments within the body) with proper sanitization: the commit message body is now passed through `tr -d '\n\r'` to strip all newlines and carriage returns before being written to $GITHUB_ENV as a simple KEY=value assignment. Also properly quoted $GITHUB_ENV.

