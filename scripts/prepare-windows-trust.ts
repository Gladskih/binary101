import { spawnSync } from "node:child_process";
import { ensureWindowsTrustSnapshot } from "./windows-trust-snapshot.js";

const snapshotPath = "generated/windows-trust-store.generated.json";

const generateSnapshot = async (): Promise<void> => {
  const result = spawnSync("powershell.exe", [
    "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File",
    "scripts/dump-windows-authenticode-trust.ps1", "-OutputPath", snapshotPath
  ], { stdio: "inherit", windowsHide: true });
  if (result.error) throw result.error;
  if (result.status !== 0) throw new Error("Windows certificate store export failed.");
};

void ensureWindowsTrustSnapshot(snapshotPath, process.platform, generateSnapshot).catch(error => {
  console.error(String(error));
  process.exitCode = 1;
});
