<!-- markdownlint-disable -->

# Hardening Report: DeterminateSystems--update-flake-lock/v29

> This file was generated automatically by the hardening agent.

**Policy SHA:** `374911c4be584df24e6da57af2d990570ef0f859`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `2`

Action **DeterminateSystems--update-flake-lock/v29** was hardened automatically. 8 finding(s) were identified and resolved across 1 iteration(s).

## Findings Fixed

### github-env-injection (severity: high)

Step 'Set environment variables (signed commits)' writes values from steps.import-gpg.outputs.name and steps.import-gpg.outputs.email to $GITHUB_ENV without stripping newlines first (no printf '%s' ... | tr -d '\n\r'). The values come in through env vars, e.g. `echo "GIT_AUTHOR_NAME=$GIT_AUTHOR_NAME" >> $GITHUB_ENV`, and the same applies to GIT_AUTHOR_EMAIL, GIT_COMMITTER_NAME and GIT_COMMITTER_EMAIL.

Locations:

- `action.yml:137`

### github-env-injection (severity: high)

Step 'Set environment variables (unsigned commits)' writes inputs.git-author-name, inputs.git-author-email, inputs.git-committer-name and inputs.git-committer-email directly to $GITHUB_ENV without stripping newlines, e.g. `echo "GIT_AUTHOR_NAME=${{ inputs.git-author-name }}" >> $GITHUB_ENV`. A newline in any of these inputs lets the caller set arbitrary environment variables.

Locations:

- `action.yml:145`

### script-injection (severity: high)

Sub-rule (a): step 'Set environment variables (unsigned commits)' puts ${{ inputs.git-author-name }}, ${{ inputs.git-author-email }}, ${{ inputs.git-committer-name }} and ${{ inputs.git-committer-email }} directly into the run: script. Offending line: `echo "GIT_AUTHOR_NAME=${{ inputs.git-author-name }}" >> $GITHUB_ENV`.

Locations:

- `action.yml:145`

### static-inline-injection (severity: high)

shell injection: expression "${{ inputs.git-author-name }}" appears directly in run: block of step "Set environment variables (unsigned commits)"; move to env: map

Locations:

- `action.yml:145`

### static-inline-injection (severity: high)

shell injection: expression "${{ inputs.git-author-email }}" appears directly in run: block of step "Set environment variables (unsigned commits)"; move to env: map

Locations:

- `action.yml:146`

### static-inline-injection (severity: high)

shell injection: expression "${{ inputs.git-committer-name }}" appears directly in run: block of step "Set environment variables (unsigned commits)"; move to env: map

Locations:

- `action.yml:147`

### static-inline-injection (severity: high)

shell injection: expression "${{ inputs.git-committer-email }}" appears directly in run: block of step "Set environment variables (unsigned commits)"; move to env: map

Locations:

- `action.yml:148`

### prior-fix (severity: high)

Carried forward from this version's previous harden, which fixed it; fix it again unless the code no longer has the problem. The previous harden changed action.yml without recording a finding for it, and this analysis reported nothing there. Re-apply its security changes unless the code no longer needs them. The previous patch:
```diff
diff --git a/action.yml b/action.yml
index 80c8751..ddb4c2b 100644
--- a/action.yml
+++ b/action.yml
@@ -21,10 +21,7 @@ inputs:
     required: false
     default: "update_flake_lock_action"
   push-to-fork:
-    description:
-      "A fork of the checked out parent repository to which the pull request branch will be pushed.
-      e.g. `owner/repo-fork`.
-      The pull request will be created to merge the fork's branch into the parent's base."
+    description: "A fork of the checked out parent repository to which the pull request branch will be pushed. e.g. `owner/repo-fork`. The pull request will be created to merge the fork's branch into the parent's base."
     required: false
   path-to-flake-dir:
     description: "The path of the directory containing `flake.nix` file within your repository. Useful when `flake.nix` cannot reside at the root of your repository."
@@ -48,7 +45,6 @@ inputs:
       GitHub Actions will not run workflows on pull requests which are opened by a GitHub Action.
 
       **To run GitHub Actions workflows on this PR, close and re-open this pull request.**
-
   pr-labels:
     description: "A comma or newline separated list of labels to set on the Pull Request to be created"
     required: false
@@ -113,10 +109,27 @@ outputs:
 runs:
   using: "composite"
   steps:
     - name: Import bot's GPG key for signing commits
       if: ${{ inputs.sign-commits == 'true' }}
       id: import-gpg
       uses: crazy-max/ghaction-import-gpg@2dc316deee8e90f13e1a351ab510b4d5bc0c82cd # v7.0.0
       with:
         gpg_private_key: ${{ inputs.gpg-private-key }}
         fingerprint: ${{ inputs.gpg-fingerprint }}
@@ -134,18 +147,31 @@ runs:
         GIT_COMMITTER_EMAIL: ${{ steps.import-gpg.outputs.email }}
         TARGETS: ${{ inputs.inputs }}
       run: |
-        echo "GIT_AUTHOR_NAME=$GIT_AUTHOR_NAME" >> $GITHUB_ENV
-        echo "GIT_AUTHOR_EMAIL=<$GIT_AUTHOR_EMAIL>" >> $GITHUB_ENV
-        echo "GIT_COMMITTER_NAME=$GIT_COMMITTER_NAME" >> $GITHUB_ENV
-        echo "GIT_COMMITTER_EMAIL=<$GIT_COMMITTER_EMAIL>" >> $GITHUB_ENV
+        safe_author_name="$(printf '%s' "$GIT_AUTHOR_NAME" | tr -d '\n\r')"
+        safe_author_email="$(printf '%s' "$GIT_AUTHOR_EMAIL" | tr -d '\n\r')"
+        safe_committer_name="$(printf '%s' "$GIT_COMMITTER_NAME" | tr -d '\n\r')"
+        safe_committer_email="$(printf '%s' "$GIT_COMMITTER_EMAIL" | tr -d '\n\r')"
+        echo "GIT_AUTHOR_NAME=$safe_author_name" >> "$GITHUB_ENV"
+        echo "GIT_AUTHOR_EMAIL=<$safe_author_email>" >> "$GITHUB_ENV"
+        echo "GIT_COMMITTER_NAME=$safe_committer_name" >> "$GITHUB_ENV"
+        echo "GIT_COMMITTER_EMAIL=<$safe_committer_email>" >> "$GITHUB_ENV"
     - name: Set environment variables (unsigned commits)
       if: ${{ inputs.sign-commits != 'true' }}
       shell: bash
+      env:
+        GIT_AUTHOR_NAME: ${{ inputs.git-author-name }}
+        GIT_AUTHOR_EMAIL: ${{ inputs.git-author-email }}
+        GIT_COMMITTER_NAME: ${{ inputs.git-committer-name }}
+        GIT_COMMITTER_EMAIL: ${{ inputs.git-committer-email }}
       run: |
-        echo "GIT_AUTHOR_NAME=${{ inputs.git-author-name }}" >> $GITHUB_ENV
-        echo "GIT_AUTHOR_EMAIL=<${{ inputs.git-author-email }}>" >> $GITHUB_ENV
-        echo "GIT_COMMITTER_NAME=${{ inputs.git-committer-name }}" >> $GITHUB_ENV
-        echo "GIT_COMMITTER_EMAIL=<${{ inputs.git-committer-email }}>" >> $GITHUB_ENV
+        safe_author_name="$(printf '%s' "$GIT_AUTHOR_NAME" | tr -d '\n\r')"
+        safe_author_email="$(printf '%s' "$GIT_AUTHOR_EMAIL" | tr -d '\n\r')"
+        safe_committer_name="$(printf '%s' "$GIT_COMMITTER_NAME" | tr -d '\n\r')"
+        safe_committer_email="$(printf '%s' "$GIT_COMMITTER_EMAIL" | tr -d '\n\r')"
+        echo "GIT_AUTHOR_NAME=$safe_author_name" >> "$GITHUB_ENV"
+        echo "GIT_AUTHOR_EMAIL=<$safe_author_email>" >> "$GITHUB_ENV"
+        echo "GIT_COMMITTER_NAME=$safe_committer_name" >> "$GITHUB_ENV"
+        echo "GIT_COMMITTER_EMAIL=<$safe_committer_email>" >> "$GITHUB_ENV"
     - name: Run update-flake-lock
       shell: bash
       run: node "$GITHU
... (truncated)
```

Locations:

- `action.yml`

## Iteration Notes

### Iteration 1

**Fixes applied:** github-env-injection, script-injection, static-inline-injection, prior-fix

**Notes:**

Changed action.yml. In the 'Set environment variables (unsigned commits)' step, moved inputs.git-author-name, git-author-email, git-committer-name and git-committer-email into the step's env: block. In that step and in the signed-commits step, each value now goes through printf '%s' | tr -d '\n\r' before it is written to "$GITHUB_ENV" (now quoted). The <...> wrapping on the email values is kept as upstream had it. The prior-fix finding asked to re-apply the previous harden's security changes, which were these same two steps. That patch also reformatted some input descriptions, which is cosmetic, so I didn't redo it. Its diff was cut off partway, so I can't confirm it had no other security changes; nothing visible in the current file needed one. The GIT_COMMIT_MESSAGE step already uses a random delimiter read from /dev/urandom, so I left it alone. Nothing has been run yet; the next analysis pass will confirm whether the findings are cleared.

