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
import { parseExportDirectory } from "../../analyzers/pe/directories/exports.js";
import { parseExportedReadyToRun } from "../../analyzers/pe/clr/ready-to-run-export.js";
import type { PeClrReadyToRun, PeClrReadyToRunSection } from "../../analyzers/pe/clr/ready-to-run-types.js";
import type { PeWindowsCore } from "../../analyzers/pe/types.js";
import type { FileRangeReader } from "../../analyzers/file-range-reader.js";

interface ReferenceSection {
  type: number;
  text?: string;
  methods?: unknown[];
  imports?: { entries: unknown[] }[];
}

interface ReferenceComponent {
  flags: number;
  sectionCount: number;
  sections: ReferenceSection[];
}

const compareSections = (actualSections: PeClrReadyToRunSection[],
  sections: ReferenceSection[], path: string): void => {
  for (const { type, ...expected } of sections) {
    const actual = actualSections.find(section => section.type === type)?.decoded;
    assert.ok(actual);
    const { kind: _, ...normalized } = JSON.parse(JSON.stringify(actual, (_key, value: unknown) =>
      value instanceof Uint8Array ? [...value] : value)) as Record<string, unknown>;
    assert.deepEqual(normalized, expected, `${path} section ${type}`);
  }
};

const compareComponents = (data: PeClrReadyToRun, components: ReferenceComponent[], path: string): void => {
  if (!components.length) return;
  const table = data.sections.find(section => section.type === 115)?.decoded;
  assert.ok(table?.kind === "components");
  assert.equal(table.entries.length, components.length);
  components.forEach((expected, index) => {
    const core = table.entries[index]?.coreHeader;
    assert.ok(core);
    assert.equal(core.flags, expected.flags);
    assert.equal(core.sectionCount, expected.sectionCount);
    compareSections(core.sections, expected.sections, `${path} component ${index + 1}`);
  });
};

const compareMethodRvas = async (
  reader: Parameters<typeof collectReadyToRunMethodRvas>[0],
  pe: PeWindowsParseResult, expected: number[], path: string
): Promise<void> => {
  const issues: string[] = [];
  assert.deepEqual(await collectReadyToRunMethodRvas(reader, pe, issues), expected,
    `${path} native method roots`);
  assert.deepEqual(issues, [], path);
};

const readManagedReadyToRun = async (reader: FileRangeReader, core: PeWindowsCore) => {
  const directory = core.dataDirs.find(directory => directory.name === "CLR_RUNTIME");
  const offset = directory?.rva ? core.rvaToOff(directory.rva) : null;
  const header = offset === null ? null : await reader.read(offset, 72);
  return parseReadyToRun(reader, core.rvaToOff, {
    ManagedNativeHeaderRVA: header?.getUint32(64, true) ?? 0,
    ManagedNativeHeaderSize: header?.getUint32(68, true) ?? 0
  } as PeClrHeader, core.coff.Machine);
};

const compareFile = async (
  path: string, sections: ReferenceSection[], methodRvas: number[], components: ReferenceComponent[]
): Promise<void> => {
  const disk = await openDiskFileRangeReader(path, (await stat(path)).size);
  try {
    const core = await parsePeHeaders(disk.reader);
    assert.ok(core && isPeWindowsCore(core));
    let parsed = await readManagedReadyToRun(disk.reader, core);
    if (parsed.status !== "ready-to-run") {
      const exports = await parseExportDirectory(disk.reader, core.dataDirs, core.rvaToOff);
      parsed = await parseExportedReadyToRun(disk.reader, core.rvaToOff,
        exports?.entries ?? [], core.coff.Machine) ?? parsed;
    }
    assert.deepEqual(parsed.issues, [], path);
    compareSections(parsed.sections, sections, path);
    compareComponents(parsed, components, path);
    await compareMethodRvas(disk.reader, {
      ...core, clr: { readyToRun: parsed }
    } as unknown as PeWindowsParseResult, methodRvas, path);
  } finally { await disk.close(); }
};

const countSections = (sections: ReferenceSection[]) => {
  const counts = { methods: 0, debugMethods: 0, imports: 0, cells: 0 };
  for (const section of sections) {
    if (section.type === 105) counts.debugMethods += section.methods?.length ?? 0;
    else counts.methods += section.methods?.length ?? 0;
    for (const table of section.imports ?? []) { counts.imports++; counts.cells += table.entries.length; }
  }
  return counts;
};

export const compareReadyToRunReference = async (referencePath: string) => {
  const lines = createInterface({ input: createReadStream(referencePath), crlfDelay: Infinity });
  const counts = { files: 0, methods: 0, debugMethods: 0, imports: 0, cells: 0, seeds: 0, components: 0 };
  for await (const line of lines) {
    const reference = JSON.parse(line) as {
      path: string; sections: ReferenceSection[]; methodRvas: number[]; components?: ReferenceComponent[]
    };
    await compareFile(reference.path, reference.sections, reference.methodRvas, reference.components ?? []);
    counts.files += 1;
    counts.seeds += reference.methodRvas.length;
    counts.components += reference.components?.length ?? 0;
    const sections = countSections([...reference.sections,
      ...(reference.components ?? []).flatMap(component => component.sections)]);
    counts.methods += sections.methods;
    counts.debugMethods += sections.debugMethods;
    counts.imports += sections.imports;
    counts.cells += sections.cells;
  }
  return counts;
};
