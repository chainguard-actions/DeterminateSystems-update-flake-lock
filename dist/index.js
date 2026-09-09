// src/nix.ts
function makeNixCommandArgs(nixOptions, flakeInputs, commitMessage) {
  const flakeInputFlags = flakeInputs.flatMap((input) => [
    "--update-input",
    input
  ]);
  const lockfileSummaryFlags = [
    "--option",
    "commit-lockfile-summary",
    commitMessage
  ];
  const updateLockMechanism = flakeInputFlags.length === 0 ? "update" : "lock";
  return nixOptions.concat(["flake", updateLockMechanism]).concat(flakeInputFlags).concat(["--commit-lock-file"]).concat(lockfileSummaryFlags);
}

// src/index.ts
import * as actionsExec from "@actions/exec";
import {
  DetSysAction,
  inputs,
  log,
  recordSpanError,
  withSpan
} from "@determinate-systems/detsys-ts";
var ATTR_EXIT_CODE = "detsys.exit_code";
var UpdateFlakeLockAction = class extends DetSysAction {
  constructor() {
    super({
      name: "update-flake-lock",
      fetchStyle: "universal",
      requireNix: "fail"
    });
    this.commitMessage = inputs.getString("commit-msg");
    this.flakeInputs = inputs.getArrayOfStrings("inputs", "space");
    this.nixOptions = inputs.getArrayOfStrings("nix-options", "space");
    this.pathToFlakeDir = inputs.getStringOrNull("path-to-flake-dir");
  }
  async main() {
    await this.update();
  }
  // No post phase
  async post() {
  }
  async update() {
    return await withSpan("update_flake_lock", async (span) => {
      const nixCommandArgs = makeNixCommandArgs(
        this.nixOptions,
        this.flakeInputs,
        this.commitMessage
      );
      log.debug(
        JSON.stringify({
          options: this.nixOptions,
          inputs: this.flakeInputs,
          message: this.commitMessage,
          args: nixCommandArgs
        })
      );
      const execOptions = {
        cwd: this.pathToFlakeDir !== null ? this.pathToFlakeDir : void 0,
        ignoreReturnCode: true
      };
      const exitCode = await actionsExec.exec(
        "nix",
        nixCommandArgs,
        execOptions
      );
      span.setAttribute(ATTR_EXIT_CODE, exitCode);
      if (exitCode !== 0) {
        const failure = new Error(`non-zero exit code of ${exitCode} detected`);
        recordSpanError(span, failure);
        log.setFailed(failure);
      } else {
        log.info(`flake.lock file was successfully updated`);
      }
    });
  }
};
function main() {
  new UpdateFlakeLockAction().execute();
}
main();
//# sourceMappingURL=index.js.map