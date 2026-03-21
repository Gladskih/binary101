"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  parseDelayImports32,
  parseDelayImports64
} from "../../analyzers/pe/delay-imports.js";
import { MockFile } from "../helpers/mock-file.js";
import { expectDefined } from "../helpers/expect-defined.js";
import {
  IMAGE_DELAYLOAD_DESCRIPTOR_SIZE,
  IMAGE_ORDINAL_FLAG64,
  IMAGE_THUNK_DATA32_SIZE,
  IMAGE_THUNK_DATA64_SIZE,
  cStringSize,
  createDelayImportLayout,
  imageImportByNameSize,
  writeDelayImportDescriptor,
  writeDelayImportName,
  writeImportByName,
  writeThunkTable32,
  writeThunkTable64
} from "./pe.delay-import-layout.js";

void test("parseDelayImports warns when the Delay Import Name Table cannot be mapped", async () => {
  const dllName = "delay.dll";
  const layout = createDelayImportLayout();
  const descriptorOffset = layout.reserve(IMAGE_DELAYLOAD_DESCRIPTOR_SIZE);
  const dllNameRva = layout.reserve(cStringSize(dllName));
  const intRva = layout.reserve(IMAGE_THUNK_DATA32_SIZE);
  const bytes = new Uint8Array(layout.size()).fill(0);
  const dv = new DataView(bytes.buffer);
  writeDelayImportDescriptor(dv, descriptorOffset, {
    dllNameRva,
    importNameTableRva: intRva
  });
  writeDelayImportName(bytes, dllNameRva, dllName);

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
  const layout = createDelayImportLayout();
  const descriptorOffset = layout.reserve(IMAGE_DELAYLOAD_DESCRIPTOR_SIZE);
  const dllNameRva = layout.reserve(cStringSize(dllName));
  const intRva = layout.reserve(IMAGE_THUNK_DATA64_SIZE * 2);
  const hintNameRva = layout.reserve(imageImportByNameSize(importName));
  const bytes = new Uint8Array(layout.size()).fill(0);
  const dv = new DataView(bytes.buffer);
  writeDelayImportDescriptor(dv, descriptorOffset, {
    dllNameRva,
    importNameTableRva: intRva
  });
  writeDelayImportName(bytes, dllNameRva, dllName);
  // Delay import INT entries use IMAGE_THUNK_DATA, so PE32+ name imports reserve bits 62-31.
  writeThunkTable64(dv, intRva, [0x0000000100000000n | BigInt(hintNameRva), 0n]);
  writeImportByName(bytes, dv, hintNameRva, hint, importName);

  const result = expectDefined(await parseDelayImports64(
    new MockFile(bytes),
    [{ name: "DELAY_IMPORT", rva: descriptorOffset, size: IMAGE_DELAYLOAD_DESCRIPTOR_SIZE }],
    value => value,
    () => {}
  ));

  assert.ok(result.warning?.toLowerCase().includes("reserved"));
});

void test("parseDelayImports walks the full PE32+ thunk array to its terminator", async () => {
  // Delay-load thunk tables mirror IMAGE_THUNK_DATA and are terminated by a null entry.
  const importCount = 16385;
  // Deliberately 16384 + 1 to prove the parser must follow the terminator instead of a loop cap.
  const dllName = "kernel32.dll";
  const layout = createDelayImportLayout();
  const descriptorOffset = layout.reserve(IMAGE_DELAYLOAD_DESCRIPTOR_SIZE);
  const dllNameRva = layout.reserve(cStringSize(dllName));
  const intRva = layout.reserve((importCount + 1) * IMAGE_THUNK_DATA64_SIZE);
  const bytes = new Uint8Array(layout.size()).fill(0);
  const dv = new DataView(bytes.buffer);
  writeDelayImportDescriptor(dv, descriptorOffset, {
    dllNameRva,
    importNameTableRva: intRva
  });
  writeDelayImportName(bytes, dllNameRva, dllName);
  const thunks = Array.from(
    { length: importCount },
    (_, index) => IMAGE_ORDINAL_FLAG64 | BigInt(index + 1)
  );
  thunks.push(0n);
  writeThunkTable64(dv, intRva, thunks);

  const result = await parseDelayImports64(
    new MockFile(bytes),
    [{ name: "DELAY_IMPORT", rva: descriptorOffset, size: IMAGE_DELAYLOAD_DESCRIPTOR_SIZE }],
    value => value,
    () => {}
  );

  const definedResult = expectDefined(result);
  const entry = expectDefined(definedResult.entries[0]);
  assert.equal(entry.functions.length, importCount);
  assert.deepEqual(entry.functions.at(-1), { ordinal: importCount });
});

void test("parseDelayImports stops when later thunk slots stop mapping", async () => {
  const dllName = "delay.dll";
  const mappedHint = 0x11;
  const mappedName = "OnlyMapped";
  const unmappedHint = 0x22;
  const unmappedName = "UnmappedThunk";
  const layout = createDelayImportLayout();
  const descriptorOffset = layout.reserve(IMAGE_DELAYLOAD_DESCRIPTOR_SIZE);
  const dllNameRva = layout.reserve(cStringSize(dllName));
  const thunkTableRva = layout.reserve(IMAGE_THUNK_DATA32_SIZE * 3);
  const mappedHintNameRva = layout.reserve(imageImportByNameSize(mappedName));
  const unmappedHintNameRva = layout.reserve(imageImportByNameSize(unmappedName));
  const mappedEnd = mappedHintNameRva + imageImportByNameSize(mappedName);
  const unmappedEnd = unmappedHintNameRva + imageImportByNameSize(unmappedName);
  const bytes = new Uint8Array(layout.size()).fill(0);
  const dv = new DataView(bytes.buffer);
  writeDelayImportDescriptor(dv, descriptorOffset, {
    dllNameRva,
    importNameTableRva: thunkTableRva
  });
  writeDelayImportName(bytes, dllNameRva, dllName);
  writeThunkTable32(dv, thunkTableRva, [mappedHintNameRva, unmappedHintNameRva, 0]);
  writeImportByName(bytes, dv, mappedHintNameRva, mappedHint, mappedName);
  writeImportByName(bytes, dv, unmappedHintNameRva, unmappedHint, unmappedName);

  const sparseRvaToOff = (rva: number): number | null => {
    // Only the first thunk slot maps. A parser that assumes contiguous file
    // offsets will read the second thunk from raw bytes instead of the mapper.
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
  assert.ok(result.warning?.toLowerCase().match(/truncated|unmapped|thunk/));
});

void test("parseDelayImports resolves later descriptors through rvaToOff", async () => {
  const firstDescriptorRva = 0x1000;
  const secondDescriptorRva = firstDescriptorRva + IMAGE_DELAYLOAD_DESCRIPTOR_SIZE;
  const firstNameRva = 0x1100;
  const secondNameRva = 0x1120;
  const firstName = "first.dll";
  const secondName = "second.dll";
  const firstNameSize = cStringSize(firstName);
  const secondNameSize = cStringSize(secondName);
  const bytes = new Uint8Array(0xb0).fill(0);
  const dv = new DataView(bytes.buffer);
  writeDelayImportDescriptor(dv, 0x00, {
    dllNameRva: firstNameRva,
    importNameTableRva: 0
  });
  writeDelayImportDescriptor(dv, 0x80, {
    dllNameRva: secondNameRva,
    importNameTableRva: 0
  });
  writeDelayImportName(bytes, 0x20, firstName);
  writeDelayImportName(bytes, 0xa0, secondName);

  const sparseRvaToOff = (rva: number): number | null => {
    if (rva >= firstDescriptorRva && rva < firstDescriptorRva + IMAGE_DELAYLOAD_DESCRIPTOR_SIZE) {
      return rva - firstDescriptorRva;
    }
    if (rva >= secondDescriptorRva && rva < secondDescriptorRva + IMAGE_DELAYLOAD_DESCRIPTOR_SIZE) {
      return 0x80 + (rva - secondDescriptorRva);
    }
    if (rva >= firstNameRva && rva < firstNameRva + firstNameSize) {
      return 0x20 + (rva - firstNameRva);
    }
    if (rva >= secondNameRva && rva < secondNameRva + secondNameSize) {
      return 0xa0 + (rva - secondNameRva);
    }
    return null;
  };

  const result = expectDefined(await parseDelayImports32(
    new MockFile(bytes, "delay-descriptor-gap.bin"),
    [{ name: "DELAY_IMPORT", rva: firstDescriptorRva, size: IMAGE_DELAYLOAD_DESCRIPTOR_SIZE * 2 }],
    sparseRvaToOff,
    () => {}
  ));

  assert.deepEqual(result.entries.map(entry => entry.name), [firstName, secondName]);
});

void test("parseDelayImports warns when a later delay descriptor stops mapping before the null terminator", async () => {
  const firstDescriptorRva = 0x1000;
  const secondDescriptorRva = firstDescriptorRva + IMAGE_DELAYLOAD_DESCRIPTOR_SIZE;
  const firstNameRva = 0x1100;
  const firstName = "first.dll";
  const firstNameSize = cStringSize(firstName);
  const bytes = new Uint8Array(0x60).fill(0);
  const dv = new DataView(bytes.buffer);
  writeDelayImportDescriptor(dv, 0x00, {
    dllNameRva: firstNameRva,
    importNameTableRva: 0
  });
  writeDelayImportDescriptor(dv, 0x20, {
    dllNameRva: 0x1200,
    importNameTableRva: 0
  });
  writeDelayImportName(bytes, 0x40, firstName);

  const sparseRvaToOff = (rva: number): number | null => {
    if (rva >= firstDescriptorRva && rva < firstDescriptorRva + IMAGE_DELAYLOAD_DESCRIPTOR_SIZE) {
      return rva - firstDescriptorRva;
    }
    if (rva >= firstNameRva && rva < firstNameRva + firstNameSize) {
      return 0x40 + (rva - firstNameRva);
    }
    if (rva === secondDescriptorRva) return null;
    return null;
  };

  const result = expectDefined(await parseDelayImports32(
    new MockFile(bytes, "delay-descriptor-unmapped.bin"),
    [{ name: "DELAY_IMPORT", rva: firstDescriptorRva, size: IMAGE_DELAYLOAD_DESCRIPTOR_SIZE * 2 }],
    sparseRvaToOff,
    () => {}
  ));

  assert.deepEqual(result.entries.map(entry => entry.name), [firstName]);
  assert.ok(result.warning?.toLowerCase().match(/descriptor|truncated|unmapped/));
});

void test("parseDelayImports ignores partially non-zero descriptors as terminators", async () => {
  const dllName = "delay.dll";
  const layout = createDelayImportLayout();
  const descriptorOffset = layout.reserve(IMAGE_DELAYLOAD_DESCRIPTOR_SIZE * 2);
  const dllNameRva = layout.reserve(cStringSize(dllName));
  const thunkTableRva = layout.reserve(IMAGE_THUNK_DATA32_SIZE * 2);
  const bytes = new Uint8Array(layout.size()).fill(0);
  const dv = new DataView(bytes.buffer);
  // Microsoft PE format, Delay-Load Directory Table:
  // the descriptor is fixed-size and only a fully zero-filled record is the terminator.
  dv.setUint32(descriptorOffset + 16, 0x12345678, true);
  // Non-zero INT RVA makes the first descriptor malformed, not null.
  writeDelayImportDescriptor(dv, descriptorOffset + IMAGE_DELAYLOAD_DESCRIPTOR_SIZE, {
    dllNameRva,
    importNameTableRva: thunkTableRva
  });
  writeDelayImportName(bytes, dllNameRva, dllName);
  writeThunkTable32(dv, thunkTableRva, [0x80000002, 0]);

  const result = expectDefined(await parseDelayImports32(
    new MockFile(bytes),
    [{ name: "DELAY_IMPORT", rva: descriptorOffset, size: IMAGE_DELAYLOAD_DESCRIPTOR_SIZE * 2 }],
    value => value,
    () => {}
  ));

  const entry = expectDefined(result.entries[0]);
  assert.equal(result.entries.length, 1);
  assert.equal(entry.name, dllName);
  assert.deepEqual(entry.functions, [{ ordinal: 2 }]);
});

void test("parseDelayImports warns when 32-bit ordinal thunks set reserved bits", async () => {
  const dllName = "delay32.dll";
  const layout = createDelayImportLayout();
  const descriptorOffset = layout.reserve(IMAGE_DELAYLOAD_DESCRIPTOR_SIZE);
  const dllNameRva = layout.reserve(cStringSize(dllName));
  const thunkTableRva = layout.reserve(IMAGE_THUNK_DATA32_SIZE * 2);
  const bytes = new Uint8Array(layout.size()).fill(0);
  const dv = new DataView(bytes.buffer);
  writeDelayImportDescriptor(dv, descriptorOffset, {
    dllNameRva,
    importNameTableRva: thunkTableRva
  });
  writeDelayImportName(bytes, dllNameRva, dllName);
  // Microsoft PE format, Import Lookup Table:
  // for ordinal imports, bits 30-15 must be zero in PE32.
  writeThunkTable32(dv, thunkTableRva, [0xffff0002, 0]);

  const result = expectDefined(await parseDelayImports32(
    new MockFile(bytes),
    [{ name: "DELAY_IMPORT", rva: descriptorOffset, size: IMAGE_DELAYLOAD_DESCRIPTOR_SIZE }],
    value => value,
    () => {}
  ));

  assert.ok(result.warning?.toLowerCase().includes("reserved"));
});

void test("parseDelayImports warns when PE32+ ordinal thunks set reserved bits", async () => {
  const dllName = "delay64.dll";
  const layout = createDelayImportLayout();
  const descriptorOffset = layout.reserve(IMAGE_DELAYLOAD_DESCRIPTOR_SIZE);
  const dllNameRva = layout.reserve(cStringSize(dllName));
  const thunkTableRva = layout.reserve(IMAGE_THUNK_DATA64_SIZE * 2);
  const bytes = new Uint8Array(layout.size()).fill(0);
  const dv = new DataView(bytes.buffer);
  writeDelayImportDescriptor(dv, descriptorOffset, {
    dllNameRva,
    importNameTableRva: thunkTableRva
  });
  writeDelayImportName(bytes, dllNameRva, dllName);
  // Microsoft PE format, Import Lookup Table:
  // for ordinal imports, bits 62-15 must be zero in PE32+.
  writeThunkTable64(dv, thunkTableRva, [0xffff000000000002n, 0n]);

  const result = expectDefined(await parseDelayImports64(
    new MockFile(bytes),
    [{ name: "DELAY_IMPORT", rva: descriptorOffset, size: IMAGE_DELAYLOAD_DESCRIPTOR_SIZE }],
    value => value,
    () => {}
  ));

  assert.ok(result.warning?.toLowerCase().includes("reserved"));
});
