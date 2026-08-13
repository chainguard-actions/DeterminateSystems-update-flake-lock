<!-- markdownlint-disable -->

# Hardening Report: DeterminateSystems--update-flake-lock/v27

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `2`

Action **DeterminateSystems--update-flake-lock/v27** was hardened automatically. 7 finding(s) were identified and resolved across 3 iteration(s).

## Findings Fixed

### unpinned-uses (severity: high)

Two `uses:` references in action.yml are pinned to mutable version tags instead of immutable 40-character SHA digests, making the action vulnerable to supply-chain attacks if those tags are moved:
- `DamianReeves/write-file-action@v1.3` (tag, not a SHA)
- `juliangruber/read-file-action@v1` (tag, not a SHA)

The other three references (`crazy-max/ghaction-import-gpg`, `pedrolamas/handlebars-action`, `peter-evans/create-pull-request`) are correctly SHA-pinned.

Locations:

- `action.yml:155`
- `action.yml:168`

### script-injection (severity: high)

Sub-rule (a): The 'Set environment variables (unsigned commits)' run: block directly interpolates caller-controlled `${{ inputs.* }}` expressions inside shell command strings. These values flow through YAML template substitution before the shell processes them, allowing an attacker to inject arbitrary shell metacharacters:

  echo "GIT_AUTHOR_NAME=${{ inputs.git-author-name }}" >> $GITHUB_ENV
  echo "GIT_AUTHOR_EMAIL=<${{ inputs.git-author-email }}>" >> $GITHUB_ENV
  echo "GIT_COMMITTER_NAME=${{ inputs.git-committer-name }}" >> $GITHUB_ENV
  echo "GIT_COMMITTER_EMAIL=<${{ inputs.git-committer-email }}>" >> $GITHUB_ENV

These inputs should be passed via an `env:` block and the shell variables double-quoted.

Locations:

- `action.yml:120`

### github-env-injection (severity: high)

Two run: steps write untrusted values to $GITHUB_ENV without the required sanitization (`printf '%s' ... | tr -d '\n\r'`), enabling newline injection that can set arbitrary environment variables for subsequent steps.

(1) 'Set environment variables (signed commits)': writes step outputs (`steps.import-gpg.outputs.name`, `steps.import-gpg.outputs.email`) via env vars to $GITHUB_ENV without sanitization:
  echo "GIT_AUTHOR_NAME=$GIT_AUTHOR_NAME" >> $GITHUB_ENV
  echo "GIT_AUTHOR_EMAIL=<$GIT_AUTHOR_EMAIL>" >> $GITHUB_ENV
  echo "GIT_COMMITTER_NAME=$GIT_COMMITTER_NAME" >> $GITHUB_ENV
  echo "GIT_COMMITTER_EMAIL=<$GIT_COMMITTER_EMAIL>" >> $GITHUB_ENV

(2) 'Set environment variables (unsigned commits)': directly interpolates `${{ inputs.* }}` values and writes them to $GITHUB_ENV without sanitization:
  echo "GIT_AUTHOR_NAME=${{ inputs.git-author-name }}" >> $GITHUB_ENV
  echo "GIT_AUTHOR_EMAIL=<${{ inputs.git-author-email }}>" >> $GITHUB_ENV
  echo "GIT_COMMITTER_NAME=${{ inputs.git-committer-name }}" >> $GITHUB_ENV
  echo "GIT_COMMITTER_EMAIL=<${{ inputs.git-committer-email }}>" >> $GITHUB_ENV

A value containing a newline (e.g. `name\nSECRET_KEY=injected`) would inject an additional environment variable into $GITHUB_ENV.

Locations:

- `action.yml:110`
- `action.yml:120`

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

Fixed all 7 findings in hardened/action/action.yml:
1. Pinned DamianReeves/write-file-action@v1.3 → @6929a9a6d1807689191dcc8bbe62b54d70a32b42 # v1.3
2. Pinned juliangruber/read-file-action@v1 → @271ff311a4947af354c6abcd696a306553b9ec18 # v1
3. Moved all ${{ inputs.git-author-name/email }}, ${{ inputs.git-committer-name/email }} expressions from the 'Set environment variables (unsigned commits)' run: block into an env: block, eliminating shell injection risk.
4. Added printf '%s' ... | tr -d '\n\r' sanitization in both 'Set environment variables (signed commits)' and 'Set environment variables (unsigned commits)' steps before writing to $GITHUB_ENV, preventing newline injection attacks.

### Iteration 2

**Fixes applied:** github-env-injection

**Notes:**

Fixed the 'Set additional env variables (GIT_COMMIT_MESSAGE)' step in hardened/action/action.yml. Replaced the heredoc-based write (which wrote the raw, multi-line git commit body to $GITHUB_ENV) with a sanitized approach: the commit message is now passed through `printf '%s' "$COMMIT_MESSAGE" | tr -d '\n\r'` to strip all embedded newlines and carriage returns before being written as a simple `GIT_COMMIT_MESSAGE=$safe_msg` key=value pair to $GITHUB_ENV. This prevents an attacker from injecting arbitrary environment variable assignments via crafted commit messages.

### Iteration 3

**Fixes applied:** unpinned-uses, missing-permissions

**Notes:**

Pinned all 9 unpinned action references to full 40-character SHA hashes with original tag/branch as comments: actions/checkout@v4 → 34e114876b0b11c390a56381ad16ebd13914f8d5, DeterminateSystems/flake-checker-action@main → de924abd783455e8429c858962b9e43062d19da1, DeterminateSystems/determinate-nix-action@v3 → 2a0be2498974c2b6327e19780488744384637d88, DeterminateSystems/flakehub-cache-action@main → 3be0931021788e3bb4df65f59a555039c2fa2d46, DeterminateSystems/update-flake-lock@main → ec13d37c32ca75bc750ecc133e944e5a18164688, nwisbeta/validate-yaml-schema@v2.0.0 → c3734e647d2a3beb98b9132330067e900fdbd1a2. Added top-level `permissions: contents: read` to validate.yml to fix the missing-permissions finding.

