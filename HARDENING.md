<!-- markdownlint-disable -->

# Hardening Report: DeterminateSystems--update-flake-lock/v26

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `2`

Action **DeterminateSystems--update-flake-lock/v26** was hardened automatically. 7 finding(s) were identified and resolved across 3 iteration(s).

## Findings Fixed

### script-injection (severity: high)

Sub-rule (a): The 'Set environment variables (unsigned commits)' run: block directly interpolates ${{ inputs.git-author-name }}, ${{ inputs.git-author-email }}, ${{ inputs.git-committer-name }}, and ${{ inputs.git-committer-email }} inside shell command strings. These expressions are expanded by the GitHub Actions template engine before the shell ever sees them, allowing an attacker who controls these inputs to inject arbitrary shell commands. Example offending lines: `echo "GIT_AUTHOR_NAME=${{ inputs.git-author-name }}" >> $GITHUB_ENV`

Locations:

- `action.yml:116`
- `action.yml:117`
- `action.yml:118`
- `action.yml:119`

### github-env-injection (severity: high)

Multiple run: blocks write untrusted values to $GITHUB_ENV without the required sanitization step (printf '%s' ... | tr -d '\n\r'). (1) 'Set environment variables (signed commits)': env vars GIT_AUTHOR_NAME, GIT_AUTHOR_EMAIL, GIT_COMMITTER_NAME, GIT_COMMITTER_EMAIL are sourced from steps.import-gpg.outputs.* (workflow-controllable) and written unsanitized to $GITHUB_ENV. (2) 'Set environment variables (unsigned commits)': ${{ inputs.git-author-name }}, ${{ inputs.git-author-email }}, ${{ inputs.git-committer-name }}, ${{ inputs.git-committer-email }} are written directly to $GITHUB_ENV without sanitization. (3) 'Set additional env variables (GIT_COMMIT_MESSAGE)': $COMMIT_MESSAGE from `git log` (repository-controlled content) is written to $GITHUB_ENV via heredoc without sanitization, enabling newline injection to set arbitrary environment variables.

Locations:

- `action.yml:109`
- `action.yml:110`
- `action.yml:111`
- `action.yml:112`
- `action.yml:116`
- `action.yml:117`
- `action.yml:118`
- `action.yml:119`
- `action.yml:163`
- `action.yml:164`

### unpinned-uses (severity: high)

Two uses: references are pinned to mutable tags rather than immutable 40-character SHA digests, making the action vulnerable to supply-chain attacks if the tag is moved or the repository is compromised: (1) `uses: DamianReeves/write-file-action@v1.3` — tag ref, not a SHA. (2) `uses: juliangruber/read-file-action@v1` — tag ref, not a SHA. The other three uses: references (crazy-max/ghaction-import-gpg, pedrolamas/handlebars-action, peter-evans/create-pull-request) are correctly pinned to full SHA digests.

Locations:

- `action.yml:148`
- `action.yml:157`

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
1. script-injection/static-inline-injection: Moved ${{ inputs.git-author-name }}, ${{ inputs.git-author-email }}, ${{ inputs.git-committer-name }}, ${{ inputs.git-committer-email }} from inline run: strings into the 'Set environment variables (unsigned commits)' step's env: block. The shell script now references $GIT_AUTHOR_NAME etc. as plain environment variables.
2. github-env-injection: Added sanitization using 'printf "%s" "$VAR" | tr -d "\n\r"' before writing to $GITHUB_ENV in both the signed and unsigned commit steps. The GIT_COMMIT_MESSAGE heredoc with random delimiter is exempt (multi-line value, random delimiter prevents injection).
3. unpinned-uses: Pinned DamianReeves/write-file-action@v1.3 to SHA 6929a9a6d1807689191dcc8bbe62b54d70a32b42 and juliangruber/read-file-action@v1 to SHA 271ff311a4947af354c6abcd696a306553b9ec18.

### Iteration 2

**Fixes applied:** github-env-injection

**Notes:**

Fixed the github-env-injection finding in the 'Set additional env variables (GIT_COMMIT_MESSAGE)' step of action.yml. Added sanitization of the COMMIT_MESSAGE value using `printf '%s' "$COMMIT_MESSAGE" | tr -d '\n\r'` before writing it to $GITHUB_ENV. The sanitized value `safe_commit_message` is now used in the heredoc write to $GITHUB_ENV and in the echo statement, preventing attacker-controlled commit messages from injecting additional KEY=VALUE environment variable lines.

### Iteration 1

**Fixes applied:** publish-gate

**Notes:**

Fixed action.yml around line 196-198: removed the `safe_commit_message` variable that was stripping newlines from the commit message, and changed the heredoc body to write the original `$COMMIT_MESSAGE` variable instead. The random DELIMITER already prevents injection in the heredoc form, so stripping newlines was incorrect and caused multi-line commit messages to be merged into a single line.

