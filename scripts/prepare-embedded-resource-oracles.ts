import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

// On Windows the upstream Linux toolchain runs in the default WSL distribution.
const result = spawnSync(process.platform === "win32" ? "wsl.exe" : "sh",
  process.platform === "win32"
    ? ["--", "sh", "scripts/build-embedded-resource-oracles.sh"]
    : ["scripts/build-embedded-resource-oracles.sh"],
  { cwd: fileURLToPath(new URL("../", import.meta.url)), stdio: "inherit", windowsHide: true });

if (result.error || result.status !== 0) {
  console.error(result.error?.message ?? "Embedded resource fixture generation failed.");
  console.error("Install the toolchain listed in tests/fixtures/embedded-resource-oracles/README.md.");
  process.exitCode = 1;
}
