import assert from "node:assert/strict";
import { test } from "node:test";
import { readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { parsePeHeaders, isPeWindowsCore } from "../../analyzers/pe/core/index.js";
import type { PeWindowsCore } from "../../analyzers/pe/types.js";
import { peSectionNameValue } from "../../analyzers/pe/sections/name.js";
import { parseExceptionDirectory, type PeExceptionDirectory } from "../../analyzers/pe/exception/index.js";
import { createExceptionDebugParser } from "../../analyzers/pe/debug/exception.js";
import { MockFile } from "../helpers/mock-file.js";

const linuxPath = (path: string): string => resolve(path).replace(/^([a-z]):[\\/]/i,
  (_, drive: string) => `/mnt/${drive.toLowerCase()}/`).replaceAll("\\", "/");

// Binutils 2.44's unchanged COFF WinCE frontend selects the compressed decoder;
// its PEI frontend incorrectly selects the generic 20-byte decoder. Only this
// oracle envelope changes: remove the DOS stub/signature, rebase section file
// offsets/VMAs, select ARM magic instead of THUMB, and register only .text
// and .pdata to keep unrelated PE-only formatters out of this COFF envelope. All section bytes,
// including the complete .pdata and PDATA_EH records, stay unchanged.
const coffEnvelope = (file: MockFile, core: PeWindowsCore): Uint8Array => {
  const peOffset = new DataView(file.data.buffer).getUint32(0x3c, true);
  const bytes = Uint8Array.from(file.data.subarray(peOffset + 4));
  const view = new DataView(bytes.buffer);
  view.setUint16(0, 0x1c0, true);
  const indices = core.sections.flatMap((section, index) =>
    [".text", ".pdata"].includes(peSectionNameValue(section.name)) ? [index] : []);
  view.setUint16(2, indices.length, true);
  indices.forEach((sourceIndex, index) => {
    const section = core.sections[sourceIndex]!;
    const header = 20 + core.coff.SizeOfOptionalHeader + index * 40;
    const sourceHeader = peOffset + 24 + core.coff.SizeOfOptionalHeader + sourceIndex * 40;
    bytes.set(file.data.subarray(sourceHeader, sourceHeader + 40), header);
    if (section.pointerToRawData) view.setUint32(header + 20, section.pointerToRawData - peOffset - 4, true);
    view.setUint32(header + 12, section.virtualAddress + Number(core.opt.ImageBase), true);
  });
  return bytes;
};

const oracleWidth = (entry: RegExpMatchArray): number => entry[4] === "1" ? 4 : 2;
const verifyStatistics = (parsed: PeExceptionDirectory, entries: RegExpMatchArray[], imageBase: bigint): void => {
  const prologs = entries.map(entry => parseInt(entry[2]!, 16) * oracleWidth(entry));
  const handlers = entries.filter(entry => entry[5] === "1");
  assert.equal(parsed.functionCount, entries.length);
  assert.deepEqual(parsed.beginRvas, entries.map(entry => Number(BigInt(`0x${entry[1]}`) - imageBase)));
  assert.deepEqual(parsed.rangeLengths, entries.map(entry => parseInt(entry[3]!, 16) * oracleWidth(entry)));
  assert.equal(parsed.handlerUnwindInfoCount, handlers.length);
  assert.deepEqual(parsed.handlerRvas.toSorted((left, right) => left - right),
    [...new Set(handlers.map(entry => parseInt(entry[6]!, 16)).filter(value => value !== 0)
      .map(value => Number(BigInt(value - (value & 1)) - imageBase)))].toSorted((left, right) => left - right));
  assert.deepEqual(parsed.ceCompressed, {
    instruction16Count: entries.filter(entry => entry[4] === "0").length,
    instruction32Count: entries.filter(entry => entry[4] === "1").length, extendedEntryCount: 0,
    handlerDataCount: handlers.filter(entry => parseInt(entry[7]!, 16) !== 0).length,
    prologs: { count: prologs.length, empty: prologs.filter(value => value === 0).length,
      minimumBytes: Math.min(...prologs), maximumBytes: Math.max(...prologs) }
  });
};

// Genuine WinCE executables from https://www.7-zip.org/a/7z920-arm.exe.
// Extract the CAB with 7-Zip, then CAB members with tar. Never run the targets.
for (const [name, hash] of [
  ["7z920-arm.exe", "781e3e1e3ca653250ef2144b79dfd640fe3a068c4d05ac6f71fc292a2a207649"],
  ["7z920-arm-files/00007zFM.001", "9f3092f0b275ee9080ee6c39b630a0039fdd9eab82ab857c8db864b34490a688"],
  ["7z920-arm-files/0000007z.002", "fa95d3e884e4e747817b8c99a4019f7521884884a12ad66180a885f8268b83e4"]
] as const) {
  void test(`real WinCE .pdata and its raw debug copy match unchanged GNU Binutils: ${name}`, async () => {
    const file = new MockFile(await readFile(`scan-results/pe-debug-native/${name}`));
    assert.equal(createHash("sha256").update(file.data).digest("hex"), hash);
    const core = await parsePeHeaders(file);
    assert.ok(core && isPeWindowsCore(core));
    const directory = core.dataDirs.find(entry => entry.name === "EXCEPTION")!;
    const payload = file.data.subarray(core.rvaToOff(directory.rva)!, core.rvaToOff(directory.rva)! + directory.size);
    const wrapper = coffEnvelope(file, core);
    assert.deepEqual(wrapper.subarray(core.rvaToOff(directory.rva)! - core.dos.e_lfanew - 4,
      core.rvaToOff(directory.rva)! - core.dos.e_lfanew - 4 + directory.size), payload);
    const oracleFile = `scan-results/pe-debug-native/ce-oracle-${name.replaceAll("/", "-")}.coff`;
    await writeFile(oracleFile, wrapper);
    const oracle = execFileSync("wsl.exe", ["-d", "Ubuntu-26.04", "--", linuxPath("scan-results/binutils-ce/objdump"),
      "-b", "pe-arm-wince-little", "-p", linuxPath(oracleFile)], { encoding: "utf8", maxBuffer: 16 * 1024 * 1024 });
    const entries = [...oracle.matchAll(/^[ \t]+[0-9a-f]{8}[ \t]+([0-9a-f]{8}) ([0-9a-f]{8}) ([0-9a-f]{8})[ \t]+([01])[ \t]+([01])(?:[ \t]+([0-9a-f]{8})[ \t]+([0-9a-f]{8}))?/gmi)];
    const parsed = await parseExceptionDirectory(file, core.dataDirs, core.rvaToOff, core.coff.Machine,
      undefined, undefined, core.opt);
    assert.ok(parsed);
    assert.equal(entries.length, directory.size / 8);
    verifyStatistics(parsed, entries, core.opt.ImageBase);
    const copy = new Uint8Array(file.size + payload.length);
    copy.set(file.data); copy.set(payload, file.size);
    const warnings: string[] = [];
    const debug = await createExceptionDebugParser(new MockFile(copy), core.rvaToOff, core.coff.Machine, core.opt)(
      0, file.size, directory.size, warning => warnings.push(warning), directory);
    assert.deepEqual(debug, parsed);
    assert.equal(parsed.invalidEntryCount, 0);
    assert.deepEqual(parsed.issues, []);
    assert.deepEqual(warnings, []);
    assert.equal(createHash("sha256").update(await readFile(`scan-results/pe-debug-native/${name}`)).digest("hex"), hash);
  });
}
