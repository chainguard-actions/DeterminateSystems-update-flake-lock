<!-- markdownlint-disable -->

# Hardening Report: DeterminateSystems--update-flake-lock/v26

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `2`

Action **DeterminateSystems--update-flake-lock/v26** was hardened automatically. 8 finding(s) were identified and resolved across 1 iteration(s).

## Findings Fixed

### script-injection (severity: high)

Sub-rule (a): The 'Set environment variables (unsigned commits)' run: block directly interpolates ${{ inputs.git-author-name }}, ${{ inputs.git-author-email }}, ${{ inputs.git-committer-name }}, and ${{ inputs.git-committer-email }} inside shell command strings. These expressions are expanded by the Actions template engine before the shell ever sees them, allowing an attacker-controlled value to inject arbitrary shell commands. Example offending line: `echo "GIT_AUTHOR_NAME=${{ inputs.git-author-name }}" >> $GITHUB_ENV`

Locations:

- `action.yml:132`

### github-env-injection (severity: high)

The 'Set environment variables (unsigned commits)' run: block writes ${{ inputs.git-author-name }}, ${{ inputs.git-author-email }}, ${{ inputs.git-committer-name }}, and ${{ inputs.git-committer-email }} directly to $GITHUB_ENV without the required sanitization step (printf '%s' ... | tr -d '\n\r'). An attacker can inject newlines into these input values to poison the GITHUB_ENV file and set arbitrary environment variables for subsequent steps.

Locations:

- `action.yml:132`

### github-env-injection (severity: high)

The 'Set environment variables (signed commits)' run: block writes GIT_AUTHOR_NAME, GIT_AUTHOR_EMAIL, GIT_COMMITTER_NAME, and GIT_COMMITTER_EMAIL to $GITHUB_ENV via unsanitized echo. These env vars are sourced from ${{ steps.import-gpg.outputs.name }} and ${{ steps.import-gpg.outputs.email }} — step outputs that are workflow-controllable — without applying the required sanitization (printf '%s' ... | tr -d '\n\r') before the write. Example: `echo "GIT_AUTHOR_NAME=$GIT_AUTHOR_NAME" >> $GITHUB_ENV`

Locations:

- `action.yml:124`

### unpinned-uses (severity: high)

Two composite action steps reference external actions using mutable tag refs instead of full 40-character commit SHAs, making them vulnerable to supply-chain attacks if the tag is moved: (1) `uses: DamianReeves/write-file-action@v1.3` — tag ref `v1.3`; (2) `uses: juliangruber/read-file-action@v1` — tag ref `v1`. These should be pinned to their full SHA digests (e.g. `uses: DamianReeves/write-file-action@a83778b2d5c5d4b5c5e5f5a5b5c5d5e5f5a5b5c5 # v1.3`).

Locations:

- `action.yml:148`
- `action.yml:158`

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

**Fixes applied:** script-injection, github-env-injection, static-inline-injection, unpinned-uses

**Notes:**

Fixed all findings in action.yml:
1. 'Set environment variables (unsigned commits)': Moved ${{ inputs.git-author-name }}, ${{ inputs.git-author-email }}, ${{ inputs.git-committer-name }}, ${{ inputs.git-committer-email }} from inline run: shell strings into an env: block, eliminating script-injection. Added printf/tr sanitization before writing to $GITHUB_ENV to prevent newline injection.
2. 'Set environment variables (signed commits)': Added printf/tr sanitization for GIT_AUTHOR_NAME, GIT_AUTHOR_EMAIL, GIT_COMMITTER_NAME, GIT_COMMITTER_EMAIL before writing to $GITHUB_ENV.
3. Pinned DamianReeves/write-file-action@v1.3 → @6929a9a6d1807689191dcc8bbe62b54d70a32b42 # v1.3
4. Pinned juliangruber/read-file-action@v1 → @271ff311a4947af354c6abcd696a306553b9ec18 # v1

