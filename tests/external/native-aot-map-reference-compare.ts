import assert from "node:assert/strict";
import { openAsBlob } from "node:fs";
import { readFile } from "node:fs/promises";
import { parsePe, isPeWindowsParseResult } from "../../analyzers/pe/index.js";
import { parseElf } from "../../analyzers/elf/index.js";
import type { NativeAotMetadata } from "../../analyzers/native-aot/format.js";
import { collectNativeAotMapSeeds } from "../../analyzers/native-aot/disassembly-seeds.js";

const parseNativeFile = async (path: string): Promise<NativeAotMetadata> => {
  const file = new File([await openAsBlob(path)], "native-image");
  const signature = new Uint8Array(await file.slice(0, 2).arrayBuffer());
  if (signature[0] === 0x4d && signature[1] === 0x5a) {
    const pe = await parsePe(file);
    assert.ok(pe && isPeWindowsParseResult(pe) && pe.nativeAotCandidate?.status === "confirmed");
    return pe.nativeAotCandidate;
  }
  const elf = await parseElf(file);
  assert.ok(elf?.nativeAot);
  return elf.nativeAot;
};

export const compareNativeAotMapReference = async (referencePath: string) => {
  const references = JSON.parse(await readFile(referencePath, "utf8")) as
    (Pick<NativeAotMetadata, "invokeMap" | "stackTraceMap"> & { path: string })[];
  const counts = { files: 0, invokes: 0, stackTraceMethods: 0, seeds: 0 };
  for (const reference of references) {
    const actual = await parseNativeFile(reference.path);
    assert.deepEqual(actual.invokeMap, reference.invokeMap, `${reference.path} invoke map`);
    assert.deepEqual(actual.stackTraceMap, reference.stackTraceMap, `${reference.path} stack trace map`);
    counts.files += 1;
    counts.invokes += actual.invokeMap?.entries.length ?? 0;
    counts.stackTraceMethods += actual.stackTraceMap?.entries.length ?? 0;
    counts.seeds += new Set(collectNativeAotMapSeeds(actual).flatMap(group => group.rvas)).size;
  }
  return counts;
};
