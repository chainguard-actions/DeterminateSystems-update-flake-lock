<!-- markdownlint-disable -->

# Hardening Report: DeterminateSystems--update-flake-lock/v25

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `2`

Action **DeterminateSystems--update-flake-lock/v25** was hardened automatically. 7 finding(s) were identified and resolved across 1 iteration(s).

## Findings Fixed

### script-injection (severity: high)

Sub-rule (a): The 'Set environment variables (unsigned commits)' run: block directly interpolates ${{ inputs.git-author-name }}, ${{ inputs.git-author-email }}, ${{ inputs.git-committer-name }}, and ${{ inputs.git-committer-email }} inside shell command strings. These expressions are substituted by the YAML template engine before the shell executes them, allowing an attacker-controlled input value containing shell metacharacters (e.g. semicolons, backticks, $(...)) to achieve command injection. Offending lines:
  echo "GIT_AUTHOR_NAME=${{ inputs.git-author-name }}" >> $GITHUB_ENV
  echo "GIT_AUTHOR_EMAIL=<${{ inputs.git-author-email }}>" >> $GITHUB_ENV
  echo "GIT_COMMITTER_NAME=${{ inputs.git-committer-name }}" >> $GITHUB_ENV
  echo "GIT_COMMITTER_EMAIL=<${{ inputs.git-committer-email }}>" >> $GITHUB_ENV

Locations:

- `action.yml:122`

### github-env-injection (severity: high)

Two run: blocks write untrusted values to $GITHUB_ENV without the required sanitization step (printf '%s' ... | tr -d '\n\r'):

1. 'Set environment variables (signed commits)' step: env vars GIT_AUTHOR_NAME, GIT_AUTHOR_EMAIL, GIT_COMMITTER_NAME, GIT_COMMITTER_EMAIL are sourced from steps.import-gpg.outputs.name and steps.import-gpg.outputs.email (untrusted steps.*.outputs.* values) and written directly to $GITHUB_ENV with plain echo. A newline in the output value would allow injecting arbitrary environment variable assignments.

2. 'Set environment variables (unsigned commits)' step: ${{ inputs.* }} values are interpolated directly into the run: shell and written to $GITHUB_ENV without sanitization, compounding the script-injection risk with environment injection.

Locations:

- `action.yml:113`
- `action.yml:122`

### unpinned-uses (severity: high)

Two uses: references in action.yml are pinned to mutable version tags rather than immutable 40-character commit SHAs, making them vulnerable to supply-chain attacks if the tag is moved:
  - uses: DamianReeves/write-file-action@v1.3  (tag, not a SHA)
  - uses: juliangruber/read-file-action@v1     (tag, not a SHA)
The other three references (crazy-max/ghaction-import-gpg, pedrolamas/handlebars-action, peter-evans/create-pull-request) are correctly SHA-pinned.

Locations:

- `action.yml:143`
- `action.yml:153`

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

Fixed all findings in hardened/action/action.yml:
1. Pinned DamianReeves/write-file-action@v1.3 → @6929a9a6d1807689191dcc8bbe62b54d70a32b42 # v1.3
2. Pinned juliangruber/read-file-action@v1 → @271ff311a4947af354c6abcd696a306553b9ec18 # v1
3. Moved ${{ inputs.git-author-name }}, ${{ inputs.git-author-email }}, ${{ inputs.git-committer-name }}, ${{ inputs.git-committer-email }} from the 'unsigned commits' run: block into an env: map, eliminating script injection.
4. Added printf '%s' ... | tr -d '\n\r' sanitization in both 'signed commits' and 'unsigned commits' steps before writing values to $GITHUB_ENV, preventing newline injection attacks.

