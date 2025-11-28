import fs from "node:fs/promises";
import { existsSync } from "node:fs";
import { join } from "node:path";
import { peProbe } from "./analyzers/pe/signature.ts";
import { parsePe } from "./analyzers/pe/index.ts";
import { MockFile } from "./tests/helpers/mock-file.ts";

(async () => {
  const manifest = JSON.parse(await fs.readFile("./external-pe-fixtures/manifest.json", "utf8"));
  const root = "./external-pe-fixtures";
  const reasons = new Map<string, string>();
  for (const entry of manifest.entries) {
    const disk = join(root, entry.source, ...entry.relativePath.split("/"));
    if (!existsSync(disk)) continue;
    const bytes = await fs.readFile(disk);
    const label = `${entry.source}/${entry.relativePath}`;
    const head = new DataView(bytes.buffer, bytes.byteOffset, Math.min(bytes.byteLength, 0x400));
    const probe = peProbe(head);
    if (!probe) {
      reasons.set(label, "no MZ signature");
      continue;
    }
    if (probe.e_lfanew + 4 > bytes.byteLength) {
      reasons.set(label, `e_lfanew ${probe.e_lfanew} beyond file ${bytes.byteLength}`);
      continue;
    }
    try {
      const res = await parsePe(new MockFile(new Uint8Array(bytes), entry.relativePath));
      if (!res) reasons.set(label, "parsePe returned null");
    } catch (error) {
      reasons.set(label, "parsePe threw");
    }
  }
  console.log("nullish", reasons.size);
  console.log(Object.fromEntries(reasons));
})();
