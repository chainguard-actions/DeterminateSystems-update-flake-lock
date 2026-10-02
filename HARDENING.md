<!-- markdownlint-disable -->

# Hardening Report: DeterminateSystems--update-flake-lock/v26

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `2`

Action **DeterminateSystems--update-flake-lock/v26** was hardened automatically. 7 finding(s) were identified and resolved across 1 iteration(s).

## Findings Fixed

### script-injection (severity: high)

Sub-rule (a): The 'Set environment variables (unsigned commits)' run block directly interpolates GitHub Actions expressions inside the shell script string. The lines `echo "GIT_AUTHOR_NAME=${{ inputs.git-author-name }}" >> $GITHUB_ENV`, `echo "GIT_AUTHOR_EMAIL=<${{ inputs.git-author-email }}>" >> $GITHUB_ENV`, `echo "GIT_COMMITTER_NAME=${{ inputs.git-committer-name }}" >> $GITHUB_ENV`, and `echo "GIT_COMMITTER_EMAIL=<${{ inputs.git-committer-email }}>" >> $GITHUB_ENV` all embed `${{ inputs.* }}` expressions directly in the shell command string. An attacker-controlled input value containing shell metacharacters (`;`, `|`, `$(...)`, etc.) would be interpreted by the shell before execution.

Locations:

- `action.yml:137`

### github-env-injection (severity: high)

Two run blocks write untrusted input values to $GITHUB_ENV without the required sanitization step (`printf '%s' ... | tr -d '\n\r'`).

(1) 'Set environment variables (signed commits)': The env vars GIT_AUTHOR_NAME, GIT_AUTHOR_EMAIL, GIT_COMMITTER_NAME, GIT_COMMITTER_EMAIL are sourced from `steps.import-gpg.outputs.*` (untrusted step outputs) via the `env:` block, then written directly to $GITHUB_ENV with `echo "GIT_AUTHOR_NAME=$GIT_AUTHOR_NAME" >> $GITHUB_ENV` etc. — no newline sanitization is applied.

(2) 'Set environment variables (unsigned commits)': The lines `echo "GIT_AUTHOR_NAME=${{ inputs.git-author-name }}" >> $GITHUB_ENV` etc. write user-controlled `inputs.*` values directly to $GITHUB_ENV without sanitization, allowing newline injection to set arbitrary environment variables.

Locations:

- `action.yml:127`
- `action.yml:137`

### unpinned-uses (severity: high)

Two `uses:` references in action.yml are pinned to mutable version tags rather than immutable 40-character commit SHAs, making them vulnerable to supply-chain attacks if the tag is moved:
- `DamianReeves/write-file-action@v1.3` (tag reference)
- `juliangruber/read-file-action@v1` (tag reference)

The other three actions in the file are correctly pinned to full SHA digests.

Locations:

- `action.yml:152`
- `action.yml:162`

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

Fixed all 7 findings in action.yml:

1. script-injection + static-inline-injection (4 findings): Moved all ${{ inputs.git-author-name }}, ${{ inputs.git-author-email }}, ${{ inputs.git-committer-name }}, ${{ inputs.git-committer-email }} expressions from the 'Set environment variables (unsigned commits)' run: block into the step's env: block, referencing them as plain shell variables.

2. github-env-injection (2 findings): Added newline sanitization in both 'Set environment variables (signed commits)' and 'Set environment variables (unsigned commits)' steps using `printf '%s' "$VAR" | tr -d '\n\r'` before writing to $GITHUB_ENV.

3. unpinned-uses (2 findings): Pinned DamianReeves/write-file-action@v1.3 to SHA 6929a9a6d1807689191dcc8bbe62b54d70a32b42 and juliangruber/read-file-action@v1 to SHA 271ff311a4947af354c6abcd696a306553b9ec18.

