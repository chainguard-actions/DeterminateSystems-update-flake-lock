<!-- markdownlint-disable -->

# Hardening Report: DeterminateSystems--update-flake-lock/v25

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `2`

Action **DeterminateSystems--update-flake-lock/v25** was hardened automatically. 7 finding(s) were identified and resolved across 1 iteration(s).

## Findings Fixed

### script-injection (severity: high)

Sub-rule (a): The 'Set environment variables (unsigned commits)' run: block directly interpolates GitHub Actions expressions inside shell command strings. The values ${{ inputs.git-author-name }}, ${{ inputs.git-author-email }}, ${{ inputs.git-committer-name }}, and ${{ inputs.git-committer-email }} are caller-controlled inputs that are substituted into the shell script before the shell parses it, enabling command injection via newlines or shell metacharacters. Offending lines:
  echo "GIT_AUTHOR_NAME=${{ inputs.git-author-name }}" >> $GITHUB_ENV
  echo "GIT_AUTHOR_EMAIL=<${{ inputs.git-author-email }}>" >> $GITHUB_ENV
  echo "GIT_COMMITTER_NAME=${{ inputs.git-committer-name }}" >> $GITHUB_ENV
  echo "GIT_COMMITTER_EMAIL=<${{ inputs.git-committer-email }}>" >> $GITHUB_ENV

Locations:

- `action.yml:128`

### github-env-injection (severity: high)

Two run: steps write untrusted values to $GITHUB_ENV without the required sanitization (printf '%s' ... | tr -d '\n\r'):

(1) 'Set environment variables (signed commits)': The env vars GIT_AUTHOR_NAME, GIT_AUTHOR_EMAIL, GIT_COMMITTER_NAME, and GIT_COMMITTER_EMAIL are sourced from steps.import-gpg.outputs.* (workflow-controlled, untrusted) and echoed directly to $GITHUB_ENV with no newline stripping. A value containing a newline could inject arbitrary environment variables.
  echo "GIT_AUTHOR_NAME=$GIT_AUTHOR_NAME" >> $GITHUB_ENV
  echo "GIT_AUTHOR_EMAIL=<$GIT_AUTHOR_EMAIL>" >> $GITHUB_ENV
  echo "GIT_COMMITTER_NAME=$GIT_COMMITTER_NAME" >> $GITHUB_ENV
  echo "GIT_COMMITTER_EMAIL=<$GIT_COMMITTER_EMAIL>" >> $GITHUB_ENV

(2) 'Set environment variables (unsigned commits)': ${{ inputs.* }} values are interpolated directly into echo commands that write to $GITHUB_ENV, also without sanitization.

Locations:

- `action.yml:120`
- `action.yml:128`

### unpinned-uses (severity: high)

Two uses: references in action.yml are pinned to mutable version tags rather than immutable 40-character SHA digests, making the action vulnerable to supply-chain attacks if those tags are moved:
  - uses: DamianReeves/write-file-action@v1.3  (tag, not a SHA)
  - uses: juliangruber/read-file-action@v1     (tag, not a SHA)
The other three uses: references (crazy-max/ghaction-import-gpg, pedrolamas/handlebars-action, peter-evans/create-pull-request) are correctly SHA-pinned.

Locations:

- `action.yml:155`
- `action.yml:167`

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

**Fixes applied:** unpinned-uses, script-injection, static-inline-injection, github-env-injection

**Notes:**

Fixed all findings in action.yml:
1. Pinned DamianReeves/write-file-action@v1.3 → @6929a9a6d1807689191dcc8bbe62b54d70a32b42 # v1.3
2. Pinned juliangruber/read-file-action@v1 → @271ff311a4947af354c6abcd696a306553b9ec18 # v1
3. Moved ${{ inputs.git-author-name/email }}, ${{ inputs.git-committer-name/email }} from run: block to env: block in 'Set environment variables (unsigned commits)' step, eliminating script injection.
4. Added newline sanitization (printf '%s' ... | tr -d '\n\r') for all values written to $GITHUB_ENV in both 'Set environment variables (signed commits)' and 'Set environment variables (unsigned commits)' steps to prevent GITHUB_ENV injection.

