import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { test } from "node:test";
import { parseElf } from "../../analyzers/elf/index.js";
import { probeWslReadelf } from "./elf-wsl-readelf-fixtures.js";

void test("decodes a Linux kernel core from a dedicated WSL test process", async context => {
  const probe = probeWslReadelf();
  if (!probe.available) return context.skip(probe.reason);
  const pattern = execFileSync("wsl", ["--exec", "cat", "/proc/sys/kernel/core_pattern"],
    { encoding: "utf8" }).trim();
  if (pattern !== "core") return context.skip("Requires the local core filename pattern 'core'.");
  const directory = execFileSync("wsl", ["--exec", "mktemp", "-d", "/tmp/binary101-core-XXXXXXXX"],
    { encoding: "utf8" }).trim();
  assert.match(directory, /^\/tmp\/binary101-core-[a-zA-Z0-9]+$/);
  let corePath = `${directory}/core`;
  try {
    execFileSync("wsl", ["--exec", "clang", "-x", "c", "-o", `${directory}/fixture`, "-"], {
      input: "#include <stdio.h>\n#include <stdlib.h>\n#include <unistd.h>\n" +
        "int main(void) { FILE *fp = fopen(\"pid.txt\", \"w\"); " +
        "if (!fp) return 1; fprintf(fp, \"%d\", getpid()); fclose(fp); abort(); }\n"
    });
    const run = spawnSync("wsl", ["--exec", "sh", "-c",
      "ulimit -c unlimited; cd \"$1\" && ./fixture", "core-test", directory]);
    assert.equal(run.status, 134, String(run.stderr));
    const pid = BigInt(execFileSync("wsl", ["--exec", "cat", `${directory}/pid.txt`], { encoding: "utf8" }));
    const usesPid = execFileSync("wsl", ["--exec", "cat", "/proc/sys/kernel/core_uses_pid"],
      { encoding: "utf8" }).trim();
    corePath = `${directory}/core${usesPid === "1" ? `.${pid}` : ""}`;
    const bytes = execFileSync("wsl", ["--exec", "cat", corePath], { maxBuffer: 32 * 1024 * 1024 });
    const dump = execFileSync("wsl", ["--exec", "readelf", "-nW", corePath],
      { encoding: "utf8", maxBuffer: 16 * 1024 * 1024 });
    const parsed = await parseElf(new File([bytes], "core"));
    assert.equal(parsed?.header.type, 4);
    const entries = parsed.notes?.entries ?? [];
    const status = entries.find(note => note.typeName === "NT_PRSTATUS")?.core;
    assert.ok(status);
    assert.deepEqual(status.issues, []);
    assert.equal(status.fields.find(field => field.name === "PID")?.value, pid);
    assert.equal(status.fields.find(field => field.name === "Current signal")?.value, 6n);
    assert.equal(status.registers?.length, 27);
    assert.ok(status.registers?.find(field => field.name === "rip")?.value);
    assert.ok(entries.find(note => note.typeName === "NT_FILE")?.core?.mappings
      ?.some(mapping => mapping.path === `${directory}/fixture`));
    assert.ok(entries.find(note => note.typeName === "NT_AUXV")?.core?.auxv
      ?.some(pair => pair.tag === 6n && pair.value === 4096n));
    assert.match(dump, /NT_PRSTATUS/);
    assert.match(dump, /NT_FILE/);
    assert.equal(entries.length, [...dump.matchAll(/^\s+(?:CORE|LINUX)\s+0x/gm)].length);
  } finally {
    execFileSync("wsl", ["--exec", "rm", "-f", "--", `${directory}/fixture`,
      corePath, `${directory}/pid.txt`]);
    execFileSync("wsl", ["--exec", "rmdir", "--", directory]);
  }
});
