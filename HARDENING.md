<!-- markdownlint-disable -->

# Hardening Report: DeterminateSystems--update-flake-lock/v27

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `2`

Action **DeterminateSystems--update-flake-lock/v27** was hardened automatically. 7 finding(s) were identified and resolved across 1 iteration(s).

## Findings Fixed

### script-injection (severity: high)

Sub-rule (a): The 'Set environment variables (unsigned commits)' run: block directly interpolates GitHub Actions expressions inside shell commands without routing through env: variables first. The offending lines are:
  echo "GIT_AUTHOR_NAME=${{ inputs.git-author-name }}" >> $GITHUB_ENV
  echo "GIT_AUTHOR_EMAIL=<${{ inputs.git-author-email }}>" >> $GITHUB_ENV
  echo "GIT_COMMITTER_NAME=${{ inputs.git-committer-name }}" >> $GITHUB_ENV
  echo "GIT_COMMITTER_EMAIL=<${{ inputs.git-committer-email }}>" >> $GITHUB_ENV
These inputs are caller-controlled and are interpolated directly into the shell command string before the shell ever sees them, enabling shell metacharacter injection.

Locations:

- `action.yml:128`

### github-env-injection (severity: high)

Multiple run: blocks write untrusted values to $GITHUB_ENV without the required sanitization step (printf '%s' ... | tr -d '\n\r'):

1. 'Set environment variables (signed commits)' step: writes $GIT_AUTHOR_NAME, $GIT_AUTHOR_EMAIL, $GIT_COMMITTER_NAME, $GIT_COMMITTER_EMAIL (sourced from steps.import-gpg.outputs.*, which are workflow-controllable) directly to $GITHUB_ENV with no newline stripping.

2. 'Set environment variables (unsigned commits)' step: directly interpolates ${{ inputs.git-author-name }}, ${{ inputs.git-author-email }}, ${{ inputs.git-committer-name }}, ${{ inputs.git-committer-email }} into echo commands writing to $GITHUB_ENV — attacker-supplied newlines can inject arbitrary environment variables.

3. 'Set additional env variables (GIT_COMMIT_MESSAGE)' step: writes $COMMIT_MESSAGE (from 'git log --format=%b -n 1', which contains the PR commit message body — attacker-controlled in a pull_request context) to $GITHUB_ENV using a heredoc delimiter. Although a random delimiter is used, the commit message itself is written unsanitized to $GITHUB_ENV on the following line.

Locations:

- `action.yml:116`
- `action.yml:128`
- `action.yml:161`

### unpinned-uses (severity: high)

Two uses: references in action.yml are pinned to mutable version tags rather than immutable 40-character commit SHAs, making them vulnerable to supply-chain attacks if the tag is moved:
  - uses: DamianReeves/write-file-action@v1.3  (tag, not a SHA)
  - uses: juliangruber/read-file-action@v1     (tag, not a SHA)
The other three referenced actions (crazy-max/ghaction-import-gpg, pedrolamas/handlebars-action, peter-evans/create-pull-request) are correctly pinned to full SHA digests.

Locations:

- `action.yml:155`
- `action.yml:168`

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

1. **unpinned-uses**: Pinned `DamianReeves/write-file-action@v1.3` → `@6929a9a6d1807689191dcc8bbe62b54d70a32b42 # v1.3` and `juliangruber/read-file-action@v1` → `@271ff311a4947af354c6abcd696a306553b9ec18 # v1`.

2. **script-injection / static-inline-injection**: Moved all four `${{ inputs.git-*-name/email }}` expressions from the `run:` block of 'Set environment variables (unsigned commits)' into an `env:` block, then referenced them as plain shell variables (`$GIT_AUTHOR_NAME`, etc.).

3. **github-env-injection** (3 locations):
   - 'Set environment variables (signed commits)': Added `printf '%s' "$VAR" | tr -d '\n\r'` sanitization for all four GPG-sourced values before writing to `$GITHUB_ENV`.
   - 'Set environment variables (unsigned commits)': Same sanitization applied to the four input values (now safely in env: block).
   - 'Set additional env variables (GIT_COMMIT_MESSAGE)': Added `printf '%s' "$COMMIT_MESSAGE" | tr -d '\r' | grep -v "^${DELIMITER}$"` to strip carriage returns and prevent delimiter injection from attacker-controlled git commit message bodies. Also quoted `$GITHUB_ENV` references throughout.

