import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";

const child = spawn(process.env["QT_LAB_PYTHON"] ??
  (process.platform === "win32" && existsSync("C:/msys64/ucrt64/bin/python.exe")
    ? "C:/msys64/ucrt64/bin/python.exe" : "python3"),
  [fileURLToPath(new URL("./qt-resource-lab/lab.py", import.meta.url)), ...process.argv.slice(2)],
  { stdio: "inherit", windowsHide: true });
child.on("error", error => { console.error(error.message); process.exitCode = 1; });
child.on("exit", code => { process.exitCode = code ?? 1; });
