<!-- markdownlint-disable -->

# Hardening Report: DeterminateSystems--update-flake-lock/v28

> This file was generated automatically by the hardening agent.

**Policy SHA:** `374911c4be584df24e6da57af2d990570ef0f859`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `2`

Action **DeterminateSystems--update-flake-lock/v28** was hardened automatically. 8 finding(s) were identified and resolved across 1 iteration(s).

## Findings Fixed

### github-env-injection (severity: high)

The step 'Set environment variables (signed commits)' writes GIT_AUTHOR_NAME, GIT_AUTHOR_EMAIL, GIT_COMMITTER_NAME and GIT_COMMITTER_EMAIL to $GITHUB_ENV. These values come from steps.import-gpg.outputs.name/email through env vars. Newlines are not stripped first (no printf '%s' ... | tr -d '\n\r'), e.g. `echo "GIT_AUTHOR_NAME=$GIT_AUTHOR_NAME" >> $GITHUB_ENV`.

Locations:

- `action.yml:130`

### github-env-injection (severity: high)

The step 'Set environment variables (unsigned commits)' writes inputs.git-author-name, git-author-email, git-committer-name and git-committer-email directly to $GITHUB_ENV with no sanitization, e.g. `echo "GIT_AUTHOR_NAME=${{ inputs.git-author-name }}" >> $GITHUB_ENV`. A newline in an input can inject arbitrary environment variables.

Locations:

- `action.yml:138`

### script-injection (severity: high)

Rule (a): the run: block of the step 'Set environment variables (unsigned commits)' puts ${{ inputs.* }} expressions straight into the shell script, e.g. `echo "GIT_AUTHOR_NAME=${{ inputs.git-author-name }}" >> $GITHUB_ENV` (also inputs.git-author-email, git-committer-name, git-committer-email). Move them into env: and quote the expansions.

Locations:

- `action.yml:138`

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

### prior-fix (severity: high)

Carried forward from this version's previous harden, which fixed it; fix it again unless the code no longer has the problem. The previous harden changed action.yml without recording a finding for it, and this analysis reported nothing there. Re-apply its security changes unless the code no longer needs them. The previous patch:
```diff
diff --git a/action.yml b/action.yml
index 4182c25..3dae3d3 100644
--- a/action.yml
+++ b/action.yml
@@ -42,7 +42,6 @@ inputs:
       GitHub Actions will not run workflows on pull requests which are opened by a GitHub Action.
 
       **To run GitHub Actions workflows on this PR, close and re-open this pull request.**
-
   pr-labels:
     description: "A comma or newline separated list of labels to set on the Pull Request to be created"
     required: false
@@ -107,10 +106,27 @@ outputs:
 runs:
   using: "composite"
   steps:
     - name: Import bot's GPG key for signing commits
       if: ${{ inputs.sign-commits == 'true' }}
       id: import-gpg
       uses: crazy-max/ghaction-import-gpg@e89d40939c28e39f97cf32126055eeae86ba74ec # v6.3.0
       with:
         gpg_private_key: ${{ inputs.gpg-private-key }}
         fingerprint: ${{ inputs.gpg-fingerprint }}
@@ -128,18 +144,31 @@ runs:
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
       run: node "$GITHUB_ACTION_PATH/dist/index.js"
@@ -170,7 +199,7 @@ runs:
         INPUT_TOKEN: ${{ inputs.token }}
         INPUT__INTERNAL-STRICT-MODE: ${{ inputs._internal-strict-mode }}
     - name: Save PR Body as file
       uses: DamianReeves/write-file-action@6929a9a6d1807689191dcc8bbe62b54d70a32b42 # v1.3
       with:
         path: pr_body.template
         contents: ${{ inputs.pr-body }}
@@ -185,7 +214,7 @@ runs:
         echo "$DELIMITER" >> $GITHUB_ENV
         echo "GIT_COMMIT_MESSAGE is: ${COMMIT_MESSAGE}"
     - name: Interpolate PR Body
       uses: pedrolamas/handlebars-action@2995d7eadacbc8f2f6ab8431a01d84a5fa3b8bb4 # v2.4.0
       with:
         files: "pr_body.template"
         output-filename: "pr_body.txt"
@@ -202,7 +231,7 @@ runs:
       run: rm -f pr_body.txt pr_
... (truncated)
```

Locations:

- `action.yml`

## Iteration Notes

### Iteration 1

**Fixes applied:** github-env-injection, script-injection, static-inline-injection, prior-fix

**Notes:**

Fixed the two steps in action.yml that set the git author and committer variables. In the unsigned-commits step, the git-author/committer inputs now go through an env: block instead of being written straight into the script. In both the signed and unsigned steps, each value has newlines and carriage returns removed before it is written to $GITHUB_ENV, and $GITHUB_ENV is now quoted. The other changes from the previous harden (actions pinned to full commit SHAs) were already there, so I didn't change them.

