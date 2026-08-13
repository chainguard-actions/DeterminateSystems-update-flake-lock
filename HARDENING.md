<!-- markdownlint-disable -->

# Hardening Report: DeterminateSystems--update-flake-lock/v28

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `2`

Action **DeterminateSystems--update-flake-lock/v28** was hardened automatically. 6 finding(s) were identified and resolved across 2 iteration(s).

## Findings Fixed

### script-injection (severity: high)

Sub-rule (a): The 'Set environment variables (unsigned commits)' run: block directly interpolates ${{ inputs.git-author-name }}, ${{ inputs.git-author-email }}, ${{ inputs.git-committer-name }}, and ${{ inputs.git-committer-email }} inside shell command strings. These inputs are caller-controlled and flow through YAML template substitution before the shell sees them, enabling command injection. Offending lines:
  echo "GIT_AUTHOR_NAME=${{ inputs.git-author-name }}" >> $GITHUB_ENV
  echo "GIT_AUTHOR_EMAIL=<${{ inputs.git-author-email }}>" >> $GITHUB_ENV
  echo "GIT_COMMITTER_NAME=${{ inputs.git-committer-name }}" >> $GITHUB_ENV
  echo "GIT_COMMITTER_EMAIL=<${{ inputs.git-committer-email }}>" >> $GITHUB_ENV

Locations:

- `action.yml:117`

### github-env-injection (severity: high)

Multiple run: blocks write unsanitized untrusted values to $GITHUB_ENV without the required `printf '%s' ... | tr -d '\n\r'` sanitization step:

(1) 'Set environment variables (signed commits)': writes $GIT_AUTHOR_NAME, $GIT_AUTHOR_EMAIL, $GIT_COMMITTER_NAME, $GIT_COMMITTER_EMAIL (sourced from steps.import-gpg.outputs.* — workflow-controlled) directly to $GITHUB_ENV with no newline stripping. An attacker-controlled GPG identity containing newlines could inject arbitrary environment variables.

(2) 'Set environment variables (unsigned commits)': directly writes ${{ inputs.git-author-name }}, ${{ inputs.git-author-email }}, ${{ inputs.git-committer-name }}, ${{ inputs.git-committer-email }} to $GITHUB_ENV. These are caller-supplied inputs with no sanitization.

(3) 'Set additional env variables (GIT_COMMIT_MESSAGE)': writes $COMMIT_MESSAGE (from `git log --format=%b -n 1`) to $GITHUB_ENV. Git commit message bodies can contain attacker-controlled content (e.g. from a PR), and the value is written without newline sanitization. Although a heredoc delimiter is used for the outer write, the $COMMIT_MESSAGE itself is echoed as a raw second line with no sanitization.

Locations:

- `action.yml:109`
- `action.yml:117`
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

**Fixes applied:** script-injection, github-env-injection, static-inline-injection

**Notes:**

Fixed all three affected steps in action.yml:

1. 'Set environment variables (signed commits)': Added `printf '%s' ... | tr -d '\n\r'` sanitization for all four GPG-sourced values (name, email for author and committer) before writing to $GITHUB_ENV. Also quoted $GITHUB_ENV variable references.

2. 'Set environment variables (unsigned commits)': Moved all four ${{ inputs.git-author-name }}, ${{ inputs.git-author-email }}, ${{ inputs.git-committer-name }}, ${{ inputs.git-committer-email }} expressions from the run: block into a new env: block (fixing script-injection/static-inline-injection). Added `printf '%s' ... | tr -d '\n\r'` sanitization before writing to $GITHUB_ENV (fixing github-env-injection). Also quoted $GITHUB_ENV variable references.

3. 'Set additional env variables (GIT_COMMIT_MESSAGE)': Added SAFE_COMMIT_MESSAGE variable using `printf '%s' "$COMMIT_MESSAGE" | tr -d '\r'` to strip carriage returns from the git commit message before writing to $GITHUB_ENV via heredoc. Also quoted $GITHUB_ENV variable references.

### Iteration 2

**Fixes applied:** unpinned-uses, missing-permissions

**Notes:**

Fixed all 3 workflow files:

1. .github/workflows/ci.yml: Pinned 4 actions to full SHAs:
   - actions/checkout@v5 → @fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09
   - DeterminateSystems/flake-checker-action@main → @de924abd783455e8429c858962b9e43062d19da1
   - DeterminateSystems/determinate-nix-action@v3 → @d96678350ffd6a456235832eb11e1c491589b7bb
   - DeterminateSystems/flakehub-cache-action@main → @77c6bddd7d747943530aaa578c57f233ee5d920e

2. .github/workflows/update.yml: Pinned 3 actions to full SHAs:
   - actions/checkout@v5 → @fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09
   - DeterminateSystems/determinate-nix-action@v3 → @d96678350ffd6a456235832eb11e1c491589b7bb
   - DeterminateSystems/update-flake-lock@main → @ec13d37c32ca75bc750ecc133e944e5a18164688

3. .github/workflows/validate.yml: Pinned 2 actions to full SHAs and added missing permissions:
   - actions/checkout@v5 → @fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09
   - nwisbeta/validate-yaml-schema@v2.0.0 → @c3734e647d2a3beb98b9132330067e900fdbd1a2
   - Added top-level `permissions: {}` and job-level `permissions: contents: read`

All original tags/branches are preserved as inline comments for readability.

