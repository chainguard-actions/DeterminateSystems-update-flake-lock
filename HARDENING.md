<!-- markdownlint-disable -->

# Hardening Report: DeterminateSystems--update-flake-lock/v25

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `2`

Action **DeterminateSystems--update-flake-lock/v25** was hardened automatically. 7 finding(s) were identified and resolved across 1 iteration(s).

## Findings Fixed

### script-injection (severity: high)

Sub-rule (a): The 'Set environment variables (unsigned commits)' run: block directly interpolates ${{ inputs.git-author-name }}, ${{ inputs.git-author-email }}, ${{ inputs.git-committer-name }}, and ${{ inputs.git-committer-email }} inside shell command strings. These expressions are expanded by the YAML template engine before the shell processes them, allowing an attacker who controls these inputs to inject arbitrary shell commands. Example offending lines:
  echo "GIT_AUTHOR_NAME=${{ inputs.git-author-name }}" >> $GITHUB_ENV
  echo "GIT_AUTHOR_EMAIL=<${{ inputs.git-author-email }}>" >> $GITHUB_ENV
  echo "GIT_COMMITTER_NAME=${{ inputs.git-committer-name }}" >> $GITHUB_ENV
  echo "GIT_COMMITTER_EMAIL=<${{ inputs.git-committer-email }}>" >> $GITHUB_ENV

Locations:

- `action.yml:122`
- `action.yml:123`
- `action.yml:124`
- `action.yml:125`

### github-env-injection (severity: high)

Two steps write untrusted values to $GITHUB_ENV without the required sanitization step (printf '%s' ... | tr -d '\n\r').

(1) 'Set environment variables (signed commits)': env vars $GIT_AUTHOR_NAME, $GIT_AUTHOR_EMAIL, $GIT_COMMITTER_NAME, $GIT_COMMITTER_EMAIL are sourced from steps.import-gpg.outputs.* (workflow-controlled step outputs) and written directly to $GITHUB_ENV. An attacker-controlled GPG key name/email containing newlines could inject arbitrary environment variables.
  echo "GIT_AUTHOR_NAME=$GIT_AUTHOR_NAME" >> $GITHUB_ENV
  echo "GIT_AUTHOR_EMAIL=<$GIT_AUTHOR_EMAIL>" >> $GITHUB_ENV
  echo "GIT_COMMITTER_NAME=$GIT_COMMITTER_NAME" >> $GITHUB_ENV
  echo "GIT_COMMITTER_EMAIL=<$GIT_COMMITTER_EMAIL>" >> $GITHUB_ENV

(2) 'Set environment variables (unsigned commits)': ${{ inputs.* }} values are interpolated directly into $GITHUB_ENV writes without sanitization, allowing newline injection into the environment file.
  echo "GIT_AUTHOR_NAME=${{ inputs.git-author-name }}" >> $GITHUB_ENV
  echo "GIT_AUTHOR_EMAIL=<${{ inputs.git-author-email }}>" >> $GITHUB_ENV
  echo "GIT_COMMITTER_NAME=${{ inputs.git-committer-name }}" >> $GITHUB_ENV
  echo "GIT_COMMITTER_EMAIL=<${{ inputs.git-committer-email }}>" >> $GITHUB_ENV

Locations:

- `action.yml:113`
- `action.yml:114`
- `action.yml:115`
- `action.yml:116`
- `action.yml:122`
- `action.yml:123`
- `action.yml:124`
- `action.yml:125`

### unpinned-uses (severity: high)

Two uses: references in action.yml are pinned to mutable version tags rather than immutable 40-character SHA commit hashes, making the action vulnerable to supply-chain attacks if those tags are moved or the repositories are compromised:
  - uses: DamianReeves/write-file-action@v1.3  (tag ref, not a SHA)
  - uses: juliangruber/read-file-action@v1     (tag ref, not a SHA)
The other three uses: references are correctly pinned to full SHAs.

Locations:

- `action.yml:155`
- `action.yml:163`

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

**Fixes applied:** unpinned-uses, script-injection, github-env-injection, static-inline-injection

**Notes:**

Fixed all findings in hardened/action/action.yml:
1. Pinned DamianReeves/write-file-action@v1.3 → @6929a9a6d1807689191dcc8bbe62b54d70a32b42 # v1.3
2. Pinned juliangruber/read-file-action@v1 → @271ff311a4947af354c6abcd696a306553b9ec18 # v1
3. Moved ${{ inputs.git-author-name }}, ${{ inputs.git-author-email }}, ${{ inputs.git-committer-name }}, ${{ inputs.git-committer-email }} from run: block to env: block in 'Set environment variables (unsigned commits)' step, eliminating script injection.
4. Added printf '%s' ... | tr -d '\n\r' sanitization before writing all git identity values to $GITHUB_ENV in both the signed and unsigned commit steps, preventing newline injection into the environment file.

