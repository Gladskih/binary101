"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  parseDelayImports32,
  parseDelayImports64
} from "../../analyzers/pe/delay-imports.js";
import { MockFile } from "../helpers/mock-file.js";
import { expectDefined } from "../helpers/expect-defined.js";

const encoder = new TextEncoder();
const IMAGE_DELAYLOAD_DESCRIPTOR_SIZE = 32; // IMAGE_DELAYLOAD_DESCRIPTOR
const IMAGE_THUNK_DATA32_SIZE = 4; // IMAGE_THUNK_DATA32
const IMAGE_THUNK_DATA64_SIZE = 8; // IMAGE_THUNK_DATA64
const IMAGE_IMPORT_BY_NAME_HINT_SIZE = 2; // Hint field before the import name string.
const IMAGE_ORDINAL_FLAG64 = 0x8000000000000000n; // IMAGE_ORDINAL_FLAG64

const createRvaLayout = (start = IMAGE_DELAYLOAD_DESCRIPTOR_SIZE): ((size: number) => number) => {
  let next = start;
  return (size: number): number => {
    const offset = next;
    next += size;
    return offset;
  };
};

const cStringSize = (text: string): number => encoder.encode(`${text}\0`).length;
const imageImportByNameSize = (name: string): number =>
  IMAGE_IMPORT_BY_NAME_HINT_SIZE + cStringSize(name);

void test("parseDelayImports warns when Delay Import Name Table RVA cannot be mapped", async () => {
  const dllName = "delay.dll";
  const reserve = createRvaLayout();
  const descriptorOffset = reserve(IMAGE_DELAYLOAD_DESCRIPTOR_SIZE);
  const dllNameRva = reserve(cStringSize(dllName));
  const intRva = reserve(IMAGE_THUNK_DATA32_SIZE);
  const bytes = new Uint8Array(reserve(0)).fill(0);
  const dv = new DataView(bytes.buffer);
  dv.setUint32(descriptorOffset + 0, 0, true);
  dv.setUint32(descriptorOffset + 4, dllNameRva, true);
  dv.setUint32(descriptorOffset + 16, intRva, true);
  encoder.encodeInto(`${dllName}\0`, new Uint8Array(bytes.buffer, dllNameRva));

  const result = expectDefined(await parseDelayImports32(
    new MockFile(bytes),
    [{ name: "DELAY_IMPORT", rva: descriptorOffset, size: IMAGE_DELAYLOAD_DESCRIPTOR_SIZE }],
    value => (value === intRva ? null : value),
    () => {}
  ));

  assert.ok(result.warning?.toLowerCase().includes("name"));
});

void test("parseDelayImports warns when PE32+ name thunks set reserved bits", async () => {
  const dllName = "delay64.dll";
  const importName = "DelayFunc";
  const hint = 0x21;
  const reserve = createRvaLayout();
  const descriptorOffset = reserve(IMAGE_DELAYLOAD_DESCRIPTOR_SIZE);
  const dllNameRva = reserve(cStringSize(dllName));
  const intRva = reserve(IMAGE_THUNK_DATA64_SIZE * 2);
  const hintNameRva = reserve(imageImportByNameSize(importName));
  const bytes = new Uint8Array(reserve(0)).fill(0);
  const dv = new DataView(bytes.buffer);
  dv.setUint32(descriptorOffset + 0, 0, true);
  dv.setUint32(descriptorOffset + 4, dllNameRva, true);
  dv.setUint32(descriptorOffset + 16, intRva, true);
  encoder.encodeInto(`${dllName}\0`, new Uint8Array(bytes.buffer, dllNameRva));
  // Delay import INT entries use IMAGE_THUNK_DATA, so PE32+ name imports reserve bits 62-31.
  dv.setBigUint64(intRva, 0x0000000100000000n | BigInt(hintNameRva), true); // Set reserved bit 32 and keep the name RVA.
  dv.setBigUint64(intRva + IMAGE_THUNK_DATA64_SIZE, 0n, true);
  dv.setUint16(hintNameRva, hint, true);
  encoder.encodeInto(
    `${importName}\0`,
    new Uint8Array(bytes.buffer, hintNameRva + IMAGE_IMPORT_BY_NAME_HINT_SIZE)
  );

  const result = expectDefined(await parseDelayImports64(
    new MockFile(bytes),
    [{ name: "DELAY_IMPORT", rva: descriptorOffset, size: IMAGE_DELAYLOAD_DESCRIPTOR_SIZE }],
    value => value,
    () => {}
  ));

  assert.ok(result.warning?.toLowerCase().includes("reserved"));
});

void test("parseDelayImports walks the full null-terminated PE32+ thunk array without a fixed cap", async () => {
  // Delay-load thunk tables mirror IMAGE_THUNK_DATA and are terminated by a null entry.
  const importCount = 16385; // Deliberately 16384 + 1 to prove the parser must follow the terminator instead of a loop cap.
  const dllName = "kernel32.dll";
  const reserve = createRvaLayout();
  const base = reserve(IMAGE_DELAYLOAD_DESCRIPTOR_SIZE);
  const dllNameRva = reserve(cStringSize(dllName));
  const intRva = reserve((importCount + 1) * IMAGE_THUNK_DATA64_SIZE);
  const bytes = new Uint8Array(reserve(0)).fill(0);
  const dv = new DataView(bytes.buffer);

  dv.setUint32(base + 0, 0, true);
  dv.setUint32(base + 4, dllNameRva, true);
  dv.setUint32(base + 16, intRva, true);
  encoder.encodeInto(`${dllName}\0`, new Uint8Array(bytes.buffer, dllNameRva));
  for (let index = 0; index < importCount; index += 1) {
    dv.setBigUint64(intRva + index * IMAGE_THUNK_DATA64_SIZE, IMAGE_ORDINAL_FLAG64 | BigInt(index + 1), true);
  }
  dv.setBigUint64(intRva + importCount * IMAGE_THUNK_DATA64_SIZE, 0n, true);

  const result = await parseDelayImports64(
    new MockFile(bytes),
    [{ name: "DELAY_IMPORT", rva: base, size: IMAGE_DELAYLOAD_DESCRIPTOR_SIZE }],
    value => value,
    () => {}
  );

  const definedResult = expectDefined(result);
  const entry = expectDefined(definedResult.entries[0]);
  assert.equal(entry.functions.length, importCount);
  assert.deepEqual(entry.functions.at(-1), { ordinal: importCount });
});

void test("parseDelayImports stops when later thunk slots no longer map through rvaToOff", async () => {
  const dllName = "delay.dll";
  const mappedHint = 0x11;
  const mappedName = "OnlyMapped";
  const unmappedHint = 0x22;
  const unmappedName = "UnmappedThunk";
  const reserve = createRvaLayout();
  const descriptorOffset = reserve(IMAGE_DELAYLOAD_DESCRIPTOR_SIZE);
  const dllNameRva = reserve(cStringSize(dllName));
  const thunkTableRva = reserve(IMAGE_THUNK_DATA32_SIZE * 3);
  const mappedHintNameRva = reserve(imageImportByNameSize(mappedName));
  const unmappedHintNameRva = reserve(imageImportByNameSize(unmappedName));
  const mappedEnd = mappedHintNameRva + imageImportByNameSize(mappedName);
  const unmappedEnd = unmappedHintNameRva + imageImportByNameSize(unmappedName);
  const bytes = new Uint8Array(reserve(0)).fill(0);
  const dv = new DataView(bytes.buffer);
  dv.setUint32(descriptorOffset + 0, 0, true);
  dv.setUint32(descriptorOffset + 4, dllNameRva, true);
  dv.setUint32(descriptorOffset + 16, thunkTableRva, true);
  encoder.encodeInto(`${dllName}\0`, new Uint8Array(bytes.buffer, dllNameRva));
  dv.setUint32(thunkTableRva, mappedHintNameRva, true);
  dv.setUint32(thunkTableRva + IMAGE_THUNK_DATA32_SIZE, unmappedHintNameRva, true);
  dv.setUint32(thunkTableRva + IMAGE_THUNK_DATA32_SIZE * 2, 0, true);
  dv.setUint16(mappedHintNameRva, mappedHint, true);
  encoder.encodeInto(
    `${mappedName}\0`,
    new Uint8Array(bytes.buffer, mappedHintNameRva + IMAGE_IMPORT_BY_NAME_HINT_SIZE)
  );
  dv.setUint16(unmappedHintNameRva, unmappedHint, true);
  encoder.encodeInto(
    `${unmappedName}\0`,
    new Uint8Array(bytes.buffer, unmappedHintNameRva + IMAGE_IMPORT_BY_NAME_HINT_SIZE)
  );

  const sparseRvaToOff = (rva: number): number | null => {
    // Only the first thunk slot maps. A parser that assumes the table stays contiguous in file offsets will
    // incorrectly read the second thunk from raw bytes instead of respecting the RVA mapper for each entry.
    if (rva === descriptorOffset || rva === dllNameRva || rva === thunkTableRva) return rva;
    if (rva >= mappedHintNameRva && rva < mappedEnd) return rva;
    if (rva >= unmappedHintNameRva && rva < unmappedEnd) return rva;
    return null;
  };

  const result = expectDefined(await parseDelayImports32(
    new MockFile(bytes),
    [{ name: "DELAY_IMPORT", rva: descriptorOffset, size: IMAGE_DELAYLOAD_DESCRIPTOR_SIZE }],
    sparseRvaToOff,
    () => {}
  ));

  const entry = expectDefined(result.entries[0]);
  assert.deepEqual(entry.functions, [{ hint: mappedHint, name: mappedName }]);
});
