<!-- markdownlint-disable -->

# Hardening Report: DeterminateSystems--update-flake-lock/v27

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `2`

Action **DeterminateSystems--update-flake-lock/v27** was hardened automatically. 8 finding(s) were identified and resolved across 1 iteration(s).

## Findings Fixed

### script-injection (severity: high)

Sub-rule (a): The 'Set environment variables (unsigned commits)' run: block directly interpolates ${{ inputs.git-author-name }}, ${{ inputs.git-author-email }}, ${{ inputs.git-committer-name }}, and ${{ inputs.git-committer-email }} inside shell command strings. These user-controlled inputs are template-substituted before the shell parses them, enabling command injection. Example offending line: `echo "GIT_AUTHOR_NAME=${{ inputs.git-author-name }}" >> $GITHUB_ENV`

Locations:

- `action.yml:133`

### github-env-injection (severity: high)

The 'Set environment variables (unsigned commits)' step writes user-controlled inputs (${{ inputs.git-author-name }}, ${{ inputs.git-author-email }}, ${{ inputs.git-committer-name }}, ${{ inputs.git-committer-email }}) directly to $GITHUB_ENV without the required sanitization step (printf '%s' ... | tr -d '\n\r'). An attacker can inject newlines into these input values to poison the GitHub Actions environment.

Locations:

- `action.yml:133`

### github-env-injection (severity: high)

The 'Set environment variables (signed commits)' step writes $GIT_AUTHOR_NAME, $GIT_AUTHOR_EMAIL, $GIT_COMMITTER_NAME, and $GIT_COMMITTER_EMAIL (sourced from steps.import-gpg.outputs.name and steps.import-gpg.outputs.email, which are steps.*.outputs.* values and therefore untrusted) to $GITHUB_ENV without the required sanitization step (printf '%s' ... | tr -d '\n\r'). Example offending line: `echo "GIT_AUTHOR_NAME=$GIT_AUTHOR_NAME" >> $GITHUB_ENV`

Locations:

- `action.yml:125`

### unpinned-uses (severity: high)

Two 'uses:' references are pinned to mutable version tags rather than full 40-character SHA commit hashes, making them vulnerable to supply-chain attacks: (1) `uses: DamianReeves/write-file-action@v1.3` — pinned to tag v1.3; (2) `uses: juliangruber/read-file-action@v1` — pinned to branch/tag v1. These should be pinned to their full SHA digests.

Locations:

- `action.yml:163`
- `action.yml:174`

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

Fixed all findings in action.yml:
1. script-injection/static-inline-injection: Moved ${{ inputs.git-author-name/email }} and ${{ inputs.git-committer-name/email }} expressions from the 'run:' block into the step's 'env:' block as INPUT_GIT_AUTHOR_NAME, INPUT_GIT_AUTHOR_EMAIL, INPUT_GIT_COMMITTER_NAME, INPUT_GIT_COMMITTER_EMAIL.
2. github-env-injection (unsigned commits step): Added sanitization via `printf '%s' "$VAR" | tr -d '\n\r'` before writing each value to $GITHUB_ENV.
3. github-env-injection (signed commits step): Added sanitization via `printf '%s' "$VAR" | tr -d '\n\r'` before writing GPG-sourced name/email values to $GITHUB_ENV.
4. unpinned-uses: Pinned DamianReeves/write-file-action@v1.3 to SHA 6929a9a6d1807689191dcc8bbe62b54d70a32b42 and juliangruber/read-file-action@v1 to SHA 271ff311a4947af354c6abcd696a306553b9ec18.

