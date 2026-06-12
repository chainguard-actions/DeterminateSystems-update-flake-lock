<!-- markdownlint-disable -->

# Hardening Report: DeterminateSystems--update-flake-lock/v27

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `1`

Action **DeterminateSystems--update-flake-lock/v27** was hardened automatically. 7 finding(s) were identified and resolved across 1 iteration(s).

## Findings Fixed

### script-injection (severity: high)

Sub-rule (a): The 'Set environment variables (unsigned commits)' run: block directly interpolates ${{ inputs.* }} expressions inside shell command strings, enabling script injection. Offending lines:
  echo "GIT_AUTHOR_NAME=${{ inputs.git-author-name }}" >> $GITHUB_ENV
  echo "GIT_AUTHOR_EMAIL=<${{ inputs.git-author-email }}>" >> $GITHUB_ENV
  echo "GIT_COMMITTER_NAME=${{ inputs.git-committer-name }}" >> $GITHUB_ENV
  echo "GIT_COMMITTER_EMAIL=<${{ inputs.git-committer-email }}>" >> $GITHUB_ENV
An attacker-controlled input value containing shell metacharacters (e.g. newlines, backticks, semicolons) is substituted directly into the shell command before the shell parses it.

Locations:

- `action.yml:120`

### github-env-injection (severity: high)

Two steps write unsanitized untrusted values to $GITHUB_ENV without the required `printf '%s' ... | tr -d '\n\r'` sanitization step:

(1) 'Set environment variables (signed commits)': writes steps.import-gpg.outputs.name and steps.import-gpg.outputs.email (workflow-controllable step outputs) via env: vars directly to $GITHUB_ENV — sub-rule (c) violation:
  echo "GIT_AUTHOR_NAME=$GIT_AUTHOR_NAME" >> $GITHUB_ENV
  echo "GIT_AUTHOR_EMAIL=<$GIT_AUTHOR_EMAIL>" >> $GITHUB_ENV
  echo "GIT_COMMITTER_NAME=$GIT_COMMITTER_NAME" >> $GITHUB_ENV
  echo "GIT_COMMITTER_EMAIL=<$GIT_COMMITTER_EMAIL>" >> $GITHUB_ENV

(2) 'Set environment variables (unsigned commits)': directly writes ${{ inputs.* }} expressions to $GITHUB_ENV — sub-rule (a)/(b) violation:
  echo "GIT_AUTHOR_NAME=${{ inputs.git-author-name }}" >> $GITHUB_ENV
  echo "GIT_AUTHOR_EMAIL=<${{ inputs.git-author-email }}>" >> $GITHUB_ENV
  echo "GIT_COMMITTER_NAME=${{ inputs.git-committer-name }}" >> $GITHUB_ENV
  echo "GIT_COMMITTER_EMAIL=<${{ inputs.git-committer-email }}>" >> $GITHUB_ENV

A newline injected into any of these values would allow an attacker to write arbitrary variables into the runner's environment.

Locations:

- `action.yml:109`
- `action.yml:120`

### unpinned-uses (severity: high)

Two `uses:` references in action.yml are pinned to mutable tags rather than immutable 40-character commit SHAs, making the action vulnerable to supply-chain attacks if the referenced tag is moved or overwritten:
  - uses: DamianReeves/write-file-action@v1.3  (tag: v1.3)
  - uses: juliangruber/read-file-action@v1     (tag: v1)
The other three uses: references (crazy-max/ghaction-import-gpg, pedrolamas/handlebars-action, peter-evans/create-pull-request) are correctly SHA-pinned.

Locations:

- `action.yml:143`
- `action.yml:155`

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

Fixed all four finding types in action.yml:
1. script-injection/static-inline-injection: Moved all ${{ inputs.* }} expressions in 'Set environment variables (unsigned commits)' from the run: block into an env: map (GIT_AUTHOR_NAME, GIT_AUTHOR_EMAIL, GIT_COMMITTER_NAME, GIT_COMMITTER_EMAIL).
2. github-env-injection: Both 'Set environment variables (signed commits)' and 'Set environment variables (unsigned commits)' steps now sanitize values with `printf '%s' "$VAR" | tr -d '\n\r'` before writing to $GITHUB_ENV, preventing newline injection.
3. unpinned-uses: Pinned DamianReeves/write-file-action@v1.3 to SHA 6929a9a6d1807689191dcc8bbe62b54d70a32b42 and juliangruber/read-file-action@v1 to SHA 271ff311a4947af354c6abcd696a306553b9ec18, both with tag comments for readability.

