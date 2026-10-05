import assert from "node:assert/strict";
import { createReadStream } from "node:fs";
import { stat } from "node:fs/promises";
import { createInterface } from "node:readline";
import { openDiskFileRangeReader } from "../../scripts/disk-file-range-reader.js";
import { parsePeHeaders, isPeWindowsCore } from "../../analyzers/pe/core/index.js";
import { parseReadyToRun } from "../../analyzers/pe/clr/ready-to-run.js";
import type { PeClrHeader } from "../../analyzers/pe/clr/types.js";
import type { PeWindowsParseResult } from "../../analyzers/pe/core/parse-result.js";
import { collectReadyToRunMethodRvas } from "../../analyzers/pe/clr/ready-to-run-seeds.js";

interface ReferenceSection {
  type: number;
  text?: string;
  methods?: unknown[];
  imports?: { entries: unknown[] }[];
}

const compareMethodRvas = async (
  reader: Parameters<typeof collectReadyToRunMethodRvas>[0],
  pe: PeWindowsParseResult, expected: number[], path: string
): Promise<void> => {
  const issues: string[] = [];
  assert.deepEqual(await collectReadyToRunMethodRvas(reader, pe, issues), expected,
    `${path} native method roots`);
  assert.deepEqual(issues, [], path);
};

const compareFile = async (
  path: string, sections: ReferenceSection[], methodRvas: number[]
): Promise<void> => {
  const disk = await openDiskFileRangeReader(path, (await stat(path)).size);
  try {
    const core = await parsePeHeaders(disk.reader);
    assert.ok(core && isPeWindowsCore(core));
    const directory = core.dataDirs.find(directory => directory.name === "CLR_RUNTIME");
    assert.ok(directory);
    const offset = core.rvaToOff(directory.rva);
    assert.ok(offset !== null);
    const header = await disk.reader.read(offset, 72);
    const parsed = await parseReadyToRun(disk.reader, core.rvaToOff, {
      ManagedNativeHeaderRVA: header.getUint32(64, true),
      ManagedNativeHeaderSize: header.getUint32(68, true)
    } as PeClrHeader, core.coff.Machine);
    assert.deepEqual(parsed.issues, [], path);
    for (const { type, ...expected } of sections) {
      const actual = parsed.sections.find(section => section.type === type)?.decoded;
      assert.ok(actual);
      const { kind: _, ...normalized } = JSON.parse(JSON.stringify(actual, (_key, value: unknown) =>
        value instanceof Uint8Array ? [...value] : value)) as Record<string, unknown>;
      assert.deepEqual(normalized, expected, `${path} section ${type}`);
    }
    await compareMethodRvas(disk.reader, {
      ...core, clr: { readyToRun: parsed }
    } as unknown as PeWindowsParseResult, methodRvas, path);
  } finally { await disk.close(); }
};

export const compareReadyToRunReference = async (referencePath: string) => {
  const lines = createInterface({ input: createReadStream(referencePath), crlfDelay: Infinity });
  const counts = { files: 0, methods: 0, imports: 0, cells: 0, seeds: 0 };
  for await (const line of lines) {
    const reference = JSON.parse(line) as {
      path: string; sections: ReferenceSection[]; methodRvas: number[]
    };
    await compareFile(reference.path, reference.sections, reference.methodRvas);
    counts.files += 1;
    counts.seeds += reference.methodRvas.length;
    for (const section of reference.sections) {
      counts.methods += section.methods?.length ?? 0;
      counts.imports += section.imports?.length ?? 0;
      counts.cells += section.imports?.reduce((count, table) => count + table.entries.length, 0) ?? 0;
    }
  }
  return counts;
};
