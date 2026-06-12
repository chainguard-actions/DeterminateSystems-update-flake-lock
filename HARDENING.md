<!-- markdownlint-disable -->

# Hardening Report: DeterminateSystems--update-flake-lock/v25

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `1`

Action **DeterminateSystems--update-flake-lock/v25** was hardened automatically. 7 finding(s) were identified and resolved across 1 iteration(s).

## Findings Fixed

### script-injection (severity: high)

Rule (a) violation: The 'Set environment variables (unsigned commits)' step directly interpolates ${{ inputs.git-author-name }}, ${{ inputs.git-author-email }}, ${{ inputs.git-committer-name }}, and ${{ inputs.git-committer-email }} inside run: shell commands. These expressions are substituted by the Actions runner before the shell sees them, allowing an attacker-controlled value containing shell metacharacters to execute arbitrary commands. Example offending lines:
  echo "GIT_AUTHOR_NAME=${{ inputs.git-author-name }}" >> $GITHUB_ENV
  echo "GIT_AUTHOR_EMAIL=<${{ inputs.git-author-email }}>" >> $GITHUB_ENV
  echo "GIT_COMMITTER_NAME=${{ inputs.git-committer-name }}" >> $GITHUB_ENV
  echo "GIT_COMMITTER_EMAIL=<${{ inputs.git-committer-email }}>" >> $GITHUB_ENV

Locations:

- `action.yml:113`

### github-env-injection (severity: high)

Two run: steps write untrusted values to $GITHUB_ENV without the required sanitization (printf '%s' ... | tr -d '\n\r'):

(1) 'Set environment variables (signed commits)': env vars GIT_AUTHOR_NAME, GIT_AUTHOR_EMAIL, GIT_COMMITTER_NAME, GIT_COMMITTER_EMAIL are sourced from steps.import-gpg.outputs.* (untrusted step outputs) and written directly to $GITHUB_ENV without newline stripping. A newline in the GPG output could inject arbitrary environment variables.
  echo "GIT_AUTHOR_NAME=$GIT_AUTHOR_NAME" >> $GITHUB_ENV
  echo "GIT_AUTHOR_EMAIL=<$GIT_AUTHOR_EMAIL>" >> $GITHUB_ENV

(2) 'Set environment variables (unsigned commits)': ${{ inputs.* }} expressions are interpolated directly into the run: block and written to $GITHUB_ENV without sanitization, allowing newline injection via attacker-controlled input values.
  echo "GIT_AUTHOR_NAME=${{ inputs.git-author-name }}" >> $GITHUB_ENV
  echo "GIT_AUTHOR_EMAIL=<${{ inputs.git-author-email }}>" >> $GITHUB_ENV

Locations:

- `action.yml:103`
- `action.yml:113`

### unpinned-uses (severity: high)

Two uses: references are pinned to mutable tags rather than full 40-character commit SHAs, making them vulnerable to supply-chain attacks if the tag is moved:
  - uses: DamianReeves/write-file-action@v1.3  (tag, not SHA)
  - uses: juliangruber/read-file-action@v1     (tag, not SHA)
The other three uses: references (crazy-max/ghaction-import-gpg, pedrolamas/handlebars-action, peter-evans/create-pull-request) are correctly pinned to full SHAs.

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

**Fixes applied:** script-injection, github-env-injection, unpinned-uses, static-inline-injection

**Notes:**

Fixed all findings in action.yml:
1. Moved ${{ inputs.git-author-name/email }}, ${{ inputs.git-committer-name/email }} from run: block to env: block in 'Set environment variables (unsigned commits)' step to prevent script injection.
2. Added newline sanitization (printf '%s' ... | tr -d '\n\r') before writing to $GITHUB_ENV in both 'Set environment variables (signed commits)' and 'Set environment variables (unsigned commits)' steps to prevent GITHUB_ENV injection.
3. Pinned DamianReeves/write-file-action@v1.3 to full SHA @6929a9a6d1807689191dcc8bbe62b54d70a32b42.
4. Pinned juliangruber/read-file-action@v1 to full SHA @271ff311a4947af354c6abcd696a306553b9ec18.

