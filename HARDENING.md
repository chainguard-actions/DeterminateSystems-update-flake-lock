<!-- markdownlint-disable -->

# Hardening Report: DeterminateSystems--update-flake-lock/v26

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `1`

Action **DeterminateSystems--update-flake-lock/v26** was hardened automatically. 7 finding(s) were identified and resolved across 1 iteration(s).

## Findings Fixed

### script-injection (severity: high)

Sub-rule (a): The 'Set environment variables (unsigned commits)' run: block directly interpolates ${{ inputs.git-author-name }}, ${{ inputs.git-author-email }}, ${{ inputs.git-committer-name }}, and ${{ inputs.git-committer-email }} inside shell command strings. These expressions are expanded by the GitHub Actions template engine before the shell ever sees them, allowing an attacker-controlled value containing shell metacharacters to be injected. Example offending line: `echo "GIT_AUTHOR_NAME=${{ inputs.git-author-name }}" >> $GITHUB_ENV`

Locations:

- `action.yml:122`

### github-env-injection (severity: high)

Multiple run: blocks write untrusted values to $GITHUB_ENV without the required sanitization step (printf '%s' ... | tr -d '\n\r'):

(1) 'Set environment variables (signed commits)' step: writes $GIT_AUTHOR_NAME, $GIT_AUTHOR_EMAIL, $GIT_COMMITTER_NAME, $GIT_COMMITTER_EMAIL (sourced from steps.import-gpg.outputs.name/email, which are workflow-controlled step outputs) directly to $GITHUB_ENV via `echo "GIT_AUTHOR_NAME=$GIT_AUTHOR_NAME" >> $GITHUB_ENV` without sanitization.

(2) 'Set environment variables (unsigned commits)' step: directly writes ${{ inputs.git-author-name }}, ${{ inputs.git-author-email }}, ${{ inputs.git-committer-name }}, ${{ inputs.git-committer-email }} to $GITHUB_ENV — e.g. `echo "GIT_AUTHOR_NAME=${{ inputs.git-author-name }}" >> $GITHUB_ENV` — with no sanitization.

(3) 'Set additional env variables (GIT_COMMIT_MESSAGE)' step: writes the output of `git log --format=%b -n 1` (user-controlled commit message content) to $GITHUB_ENV via `echo "$COMMIT_MESSAGE" >> $GITHUB_ENV` without sanitization. Although a random heredoc delimiter is used to prevent delimiter injection, the commit message body itself is not stripped of newlines before being written.

Locations:

- `action.yml:116`
- `action.yml:122`
- `action.yml:163`

### unpinned-uses (severity: high)

Two action references use mutable version tags instead of full 40-character SHA commit digests, making them vulnerable to supply-chain attacks if the tag is moved:

1. `uses: DamianReeves/write-file-action@v1.3` — uses tag @v1.3 instead of a pinned SHA.
2. `uses: juliangruber/read-file-action@v1` — uses tag @v1 instead of a pinned SHA.

The other three uses references in the file are correctly pinned to full SHA digests: crazy-max/ghaction-import-gpg@e89d40939c28e39f97cf32126055eeae86ba74ec, pedrolamas/handlebars-action@2995d7eadacbc8f2f6ab8431a01d84a5fa3b8bb4, and peter-evans/create-pull-request@6d6857d36972b65feb161a90e484f2984215f83e.

Locations:

- `action.yml:152`
- `action.yml:172`

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
1. Pinned DamianReeves/write-file-action@v1.3 to full SHA @6929a9a6d1807689191dcc8bbe62b54d70a32b42 and juliangruber/read-file-action@v1 to full SHA @271ff311a4947af354c6abcd696a306553b9ec18.
2. Moved ${{ inputs.git-author-name/email }} and ${{ inputs.git-committer-name/email }} expressions from the 'Set environment variables (unsigned commits)' run: block into an env: block, eliminating script injection risk.
3. Added printf '%s' ... | tr -d '\n\r' sanitization in all three steps that write to $GITHUB_ENV: 'Set environment variables (signed commits)', 'Set environment variables (unsigned commits)', and 'Set additional env variables (GIT_COMMIT_MESSAGE)'. Also quoted $GITHUB_ENV references consistently.

