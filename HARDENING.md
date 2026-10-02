<!-- markdownlint-disable -->

# Hardening Report: DeterminateSystems--update-flake-lock/v27

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `2`

Action **DeterminateSystems--update-flake-lock/v27** was hardened automatically. 7 finding(s) were identified and resolved across 1 iteration(s).

## Findings Fixed

### script-injection (severity: high)

Sub-rule (a): The 'Set environment variables (unsigned commits)' run: block directly interpolates GitHub Actions expressions inside shell commands. The lines `echo "GIT_AUTHOR_NAME=${{ inputs.git-author-name }}" >> $GITHUB_ENV`, `echo "GIT_AUTHOR_EMAIL=<${{ inputs.git-author-email }}>" >> $GITHUB_ENV`, `echo "GIT_COMMITTER_NAME=${{ inputs.git-committer-name }}" >> $GITHUB_ENV`, and `echo "GIT_COMMITTER_EMAIL=<${{ inputs.git-committer-email }}>" >> $GITHUB_ENV` embed ${{ inputs.* }} expressions directly in the shell script. An attacker-controlled input value containing shell metacharacters (e.g. newlines, backticks, semicolons) will be interpreted by the shell before the echo command executes.

Locations:

- `action.yml:132`
- `action.yml:133`
- `action.yml:134`
- `action.yml:135`

### github-env-injection (severity: high)

Two run: steps write untrusted input values to $GITHUB_ENV without the required sanitization step (`printf '%s' ... | tr -d '\n\r'`).

(1) 'Set environment variables (signed commits)': The env: block maps `steps.import-gpg.outputs.name` and `steps.import-gpg.outputs.email` (workflow-controlled step outputs) into GIT_AUTHOR_NAME, GIT_AUTHOR_EMAIL, GIT_COMMITTER_NAME, GIT_COMMITTER_EMAIL, which are then written directly to $GITHUB_ENV via `echo "GIT_AUTHOR_NAME=$GIT_AUTHOR_NAME" >> $GITHUB_ENV` etc. without newline sanitization. A value containing a newline can inject arbitrary key=value pairs into the environment.

(2) 'Set environment variables (unsigned commits)': ${{ inputs.git-author-name }}, ${{ inputs.git-author-email }}, ${{ inputs.git-committer-name }}, and ${{ inputs.git-committer-email }} are written directly to $GITHUB_ENV via echo without sanitization. Attacker-controlled newlines in these inputs can inject arbitrary environment variables.

Locations:

- `action.yml:123`
- `action.yml:124`
- `action.yml:125`
- `action.yml:126`
- `action.yml:132`
- `action.yml:133`
- `action.yml:134`
- `action.yml:135`

### unpinned-uses (severity: high)

Two `uses:` references in action.yml are pinned to mutable version tags rather than immutable full 40-character SHA commit hashes, making the action vulnerable to supply-chain attacks if the referenced tag is moved or the repository is compromised:

1. `uses: DamianReeves/write-file-action@v1.3` — mutable tag `v1.3`
2. `uses: juliangruber/read-file-action@v1` — mutable tag `v1`

The other two external actions are correctly pinned to full SHAs:
- `crazy-max/ghaction-import-gpg@e89d40939c28e39f97cf32126055eeae86ba74ec` ✓
- `pedrolamas/handlebars-action@2995d7eadacbc8f2f6ab8431a01d84a5fa3b8bb4` ✓
- `peter-evans/create-pull-request@6d6857d36972b65feb161a90e484f2984215f83e` ✓

Locations:

- `action.yml:164`
- `action.yml:189`

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

Fixed all four finding categories in hardened/action/action.yml:

1. script-injection + static-inline-injection: Moved all ${{ inputs.git-author-name/email/committer-name/email }} expressions from the 'run:' block of 'Set environment variables (unsigned commits)' into the step's 'env:' block. They are now referenced as plain shell variables ($GIT_AUTHOR_NAME, etc.).

2. github-env-injection: Both 'Set environment variables (signed commits)' and 'Set environment variables (unsigned commits)' steps now sanitize each value with `printf '%s' "$VAR" | tr -d '\n\r'` before writing to $GITHUB_ENV, preventing newline-based injection of arbitrary environment variables.

3. unpinned-uses: Pinned DamianReeves/write-file-action@v1.3 to full SHA 6929a9a6d1807689191dcc8bbe62b54d70a32b42 and juliangruber/read-file-action@v1 to full SHA 271ff311a4947af354c6abcd696a306553b9ec18, with the original tags preserved as inline comments.

