import assert from "node:assert/strict";
import test from "node:test";
import { collectReadyToRunMethodRvas } from "../../../../../analyzers/pe/clr/ready-to-run-seeds.js";
import { createReadyToRunSeedFixture, createLargeRuntimeTableFixture } from
  "../../../../helpers/ready-to-run-seed-fixture.js";

const resolveFixture = (fixture: ReturnType<typeof createReadyToRunSeedFixture>) =>
  collectReadyToRunMethodRvas(fixture.reader, fixture.pe, fixture.issues);

const runtimeTable = (fixture: ReturnType<typeof createReadyToRunSeedFixture>) =>
  fixture.pe.clr!.readyToRun!.sections[0]!;

void test("runtime functions beyond the I/O buffer remain seeds without a record cap", async () => {
  const fixture = createLargeRuntimeTableFixture();

  assert.deepEqual(await resolveFixture(fixture), fixture.codeRvas);
  // Floor(64KiB / 12) rows in each read, then the complete remaining suffix.
  assert.deepEqual(fixture.calls, [[fixture.tableRva, 65532],
    [fixture.tableRva + 65532, fixture.count * fixture.width - 65532]]);
  assert.deepEqual(fixture.issues, []);
});

for (const index of [-1, 0.5, 2, Number.MAX_SAFE_INTEGER + 1]) {
  void test(`invalid method index ${index} warns even though all runtime rows are still parsed`, async () => {
    const fixture = createReadyToRunSeedFixture(0x8664, [index]);

    assert.deepEqual(await resolveFixture(fixture), fixture.codeRvas);
    assert.deepEqual(fixture.issues,
      ["ReadyToRun disassembly seeds: method map references a missing runtime-function index."]);
  });
}

void test("invalid instance method indices warn independently of MethodDef records", async () => {
  const fixture = createReadyToRunSeedFixture(0x8664, []);
  fixture.pe.clr!.readyToRun!.sections.push({ type: 109, name: "InstanceMethodEntryPoints", rva: 0, size: 0,
    decoded: { kind: "instance-methods", methods: [
      { signatureOffset: 9, runtimeFunctionIndex: 2, fixupOffset: null }
    ] } });

  assert.deepEqual(await resolveFixture(fixture), fixture.codeRvas);
  assert.deepEqual(fixture.issues,
    ["ReadyToRun disassembly seeds: method map references a missing runtime-function index."]);
});

void test("unrelated method-like sections never contribute index warnings", async () => {
  const fixture = createReadyToRunSeedFixture(0x8664, []);
  fixture.pe.clr!.readyToRun!.sections.push({ type: 999, name: "Other", rva: 0, size: 0,
    decoded: { kind: "methods", methods: [{ methodRid: 1, runtimeFunctionIndex: -1, fixupOffset: null }] } });

  assert.deepEqual(await resolveFixture(fixture), fixture.codeRvas);
  assert.deepEqual(fixture.issues, []);
});

void test("runtime code validation reports untyped failures", () => {
  const fixture = createReadyToRunSeedFixture();
  fixture.pe.rvaToOff = rva => {
    if (rva >= fixture.codeRvas[0]!) throw "untyped code mapping error";
    return rva;
  };

  return resolveFixture(fixture).then(rvas => {
    assert.deepEqual(rvas, []);
    assert.deepEqual(fixture.issues, ["ReadyToRun disassembly seeds: runtime-function read failed."]);
  });
});

void test("row recovery preserves readable data before a short recovered row", async () => {
  const fixture = createReadyToRunSeedFixture();
  const read = fixture.reader.read;
  fixture.reader.read = async (offset, size) => {
    if (size > fixture.width) throw new Error("bulk read failed");
    return offset === fixture.tableRva + fixture.width ? new DataView(new ArrayBuffer(3)) : read(offset, size);
  };

  assert.deepEqual(await resolveFixture(fixture), [fixture.codeRvas[0]]);
  assert.deepEqual(fixture.issues, ["ReadyToRun disassembly seeds: bulk read failed.",
    "ReadyToRun disassembly seeds: runtime-function entry is truncated or unmapped."]);
});

void test("row recovery reports row-specific failures and stops before an unmapped suffix", async () => {
  const fixture = createReadyToRunSeedFixture();
  fixture.reader.read = async (_offset, size) => {
    if (size > fixture.width) {
      fixture.pe.rvaToOff = rva => rva < fixture.tableRva + fixture.width ? rva : null;
      throw new Error("bulk read failed");
    }
    throw "untyped row read failed";
  };

  assert.deepEqual(await resolveFixture(fixture), []);
  assert.deepEqual(fixture.issues, ["ReadyToRun disassembly seeds: bulk read failed.",
    "ReadyToRun disassembly seeds: runtime-function read failed.",
    "ReadyToRun disassembly seeds: runtime-function entry is truncated or unmapped."]);
});

void test("R2R includes unreferenced cold blocks and funclets and reads the runtime table once", async () => {
  const fixture = createReadyToRunSeedFixture(0x8664, [1, 1]);
  const calls: number[][] = [], read = fixture.reader.read;
  fixture.reader.read = async (offset, size) => { calls.push([offset, size]); return read(offset, size); };

  assert.deepEqual(await resolveFixture(fixture), fixture.codeRvas);
  assert.deepEqual(calls, [[fixture.tableRva, fixture.width * fixture.codeRvas.length]]);
});

for (const [name, machine] of [["x86", 0x14c], ["ARM64", 0xaa64]] as const) {
  void test(`R2R uses eight-byte ${name} runtime rows`, async () => {
    const fixture = createReadyToRunSeedFixture(machine);

    assert.deepEqual(await resolveFixture(fixture), fixture.codeRvas);
    assert.deepEqual(fixture.issues, []);
  });
}

void test("R2R deduplicates identical starts stored in distinct runtime records", async () => {
  const fixture = createReadyToRunSeedFixture();
  fixture.view.setUint32(fixture.tableRva + fixture.width, fixture.codeRvas[0]!, true);

  assert.deepEqual(await resolveFixture(fixture), [fixture.codeRvas[0]]);
});

void test("R2R normalizes Linux AMD64 OS-encoded machine values", async () => {
  const fixture = createReadyToRunSeedFixture();
  // readytorun.h: IMAGE_FILE_MACHINE_NATIVE_OS_OVERRIDE for Linux = 0x7b79.
  fixture.pe.coff.Machine ^= 0x7b79;

  assert.deepEqual(await resolveFixture(fixture), fixture.codeRvas);
});

void test("R2R clears the ARMNT Thumb bit before resolving the code RVA", async () => {
  const fixture = createReadyToRunSeedFixture(0x1c4);
  fixture.view.setUint32(fixture.tableRva, fixture.codeRvas[0]! + 1, true);

  assert.deepEqual(await resolveFixture(fixture), fixture.codeRvas);
});

void test("R2R preserves odd byte addresses on x86-64", async () => {
  const fixture = createReadyToRunSeedFixture();
  fixture.view.setUint32(fixture.tableRva, fixture.codeRvas[0]! + 1, true);

  assert.deepEqual(await resolveFixture(fixture), [fixture.codeRvas[0]! + 1, fixture.codeRvas[1]]);
});

void test("R2R retains complete records preceding a truncated final record", async () => {
  const fixture = createReadyToRunSeedFixture();
  fixture.reader.size = fixture.tableRva + fixture.width * 2 - 1;
  // Keep code bytes mapped while cutting only the runtime table's final byte.
  fixture.pe.rvaToOff = rva => rva >= fixture.codeRvas[0]! ? 1 : rva;

  assert.deepEqual(await resolveFixture(fixture), [fixture.codeRvas[0]]);
  assert.match(fixture.issues.join(" "), /truncated or unmapped/);
});

void test("R2R warns about a table tail without discarding its complete rows", async () => {
  const fixture = createReadyToRunSeedFixture();
  runtimeTable(fixture).size += 1;

  assert.deepEqual(await resolveFixture(fixture), fixture.codeRvas);
  assert.match(fixture.issues.join(" "), /incomplete entry/);
});

void test("R2R rejects runtime tables whose RVA range overflows", async () => {
  const fixture = createReadyToRunSeedFixture();
  // ECMA-335/PE RVAs occupy unsigned 32-bit fields.
  runtimeTable(fixture).rva = 0xfffffff0;

  assert.deepEqual(await resolveFixture(fixture), []);
  assert.match(fixture.issues.join(" "), /invalid RVA range/);
});

void test("R2R rejects a missing runtime table", async () => {
  const fixture = createReadyToRunSeedFixture();
  fixture.pe.clr!.readyToRun!.sections.shift();

  assert.deepEqual(await resolveFixture(fixture), []);
  assert.match(fixture.issues.join(" "), /missing or ambiguous/);
});

void test("R2R rejects ambiguous duplicate runtime tables", async () => {
  const fixture = createReadyToRunSeedFixture();
  fixture.pe.clr!.readyToRun!.sections.push({ ...runtimeTable(fixture) });

  assert.deepEqual(await resolveFixture(fixture), []);
  assert.match(fixture.issues.join(" "), /missing or ambiguous/);
});

void test("R2R warns when the target runtime-function layout is unknown", async () => {
  const fixture = createReadyToRunSeedFixture();
  fixture.pe.coff.Machine = 0;

  assert.deepEqual(await resolveFixture(fixture), []);
  assert.match(fixture.issues.join(" "), /layout is unknown/);
});

void test("R2R ignores non-R2R managed native headers", async () => {
  const fixture = createReadyToRunSeedFixture();
  fixture.pe.clr!.readyToRun!.status = "ngen";

  assert.deepEqual(await resolveFixture(fixture), []);
  assert.deepEqual(fixture.issues, []);
});

void test("R2R ignores absent CLR metadata", async () => {
  const fixture = createReadyToRunSeedFixture();
  fixture.pe.clr = null;

  assert.deepEqual(await resolveFixture(fixture), []);
  assert.deepEqual(fixture.issues, []);
});

void test("R2R does not require a runtime table when there are no compiled MethodDefs", async () => {
  const fixture = createReadyToRunSeedFixture(0x8664, []);
  fixture.pe.clr!.readyToRun!.sections.shift();

  assert.deepEqual(await resolveFixture(fixture), []);
  assert.deepEqual(fixture.issues, []);
});

void test("R2R generic instance indices contribute native roots even without MethodDef entrypoints", async () => {
  const fixture = createReadyToRunSeedFixture(0x8664, []);
  fixture.pe.clr!.readyToRun!.sections.push({ type: 109, name: "InstanceMethodEntryPoints", rva: 0, size: 0,
    decoded: { kind: "instance-methods", methods: [
      { signatureOffset: 9, runtimeFunctionIndex: 1, fixupOffset: null }
    ] } });

  assert.deepEqual(await resolveFixture(fixture), fixture.codeRvas);
  assert.deepEqual(fixture.issues, []);
});

void test("R2R preserves valid starts when a runtime read throws", async () => {
  const fixture = createReadyToRunSeedFixture();
  const read = fixture.reader.read;
  fixture.reader.read = (offset, size) => offset === fixture.tableRva ?
    Promise.reject(new Error("disk error")) : read(offset, size);

  assert.deepEqual(await resolveFixture(fixture), [fixture.codeRvas[1]]);
  assert.deepEqual(fixture.issues, ["ReadyToRun disassembly seeds: disk error.",
    "ReadyToRun disassembly seeds: runtime-function start does not map to file-backed executable code."]);
});

void test("R2R reports untyped read failures visibly", async () => {
  const fixture = createReadyToRunSeedFixture(), read = fixture.reader.read;
  fixture.reader.read = (offset, size) =>
    size > fixture.width ? Promise.reject("untyped failure") : read(offset, size);

  assert.deepEqual(await resolveFixture(fixture), fixture.codeRvas);
  assert.deepEqual(fixture.issues, ["ReadyToRun disassembly seeds: runtime-function read failed."]);
});

void test("R2R rejects null code addresses while retaining other starts", async () => {
  const fixture = createReadyToRunSeedFixture();
  fixture.view.setUint32(fixture.tableRva, 0, true);

  assert.deepEqual(await resolveFixture(fixture), [fixture.codeRvas[1]]);
  assert.match(fixture.issues.join(" "), /file-backed executable code/);
});

void test("R2R rejects code addresses at SizeOfImage", async () => {
  const fixture = createReadyToRunSeedFixture();
  fixture.pe.opt.SizeOfImage = fixture.codeRvas[1]!;

  assert.deepEqual(await resolveFixture(fixture), [fixture.codeRvas[0]]);
});

void test("R2R rejects code addresses outside all sections", async () => {
  const fixture = createReadyToRunSeedFixture();
  fixture.view.setUint32(fixture.tableRva, fixture.bytes.length - 1, true);

  assert.deepEqual(await resolveFixture(fixture), [fixture.codeRvas[1]]);
});

void test("R2R rejects code in non-executable sections", async () => {
  const fixture = createReadyToRunSeedFixture();
  fixture.pe.sections[0]!.characteristics = 0;

  assert.deepEqual(await resolveFixture(fixture), []);
  assert.match(fixture.issues.join(" "), /file-backed executable code/);
});

void test("R2R rejects zero-filled code past raw section bytes", async () => {
  const fixture = createReadyToRunSeedFixture();
  fixture.pe.sections[0]!.sizeOfRawData = fixture.codeRvas[1]! - fixture.codeRvas[0]!;

  assert.deepEqual(await resolveFixture(fixture), [fixture.codeRvas[0]]);
});

void test("R2R rejects code mapping beyond the file", async () => {
  const fixture = createReadyToRunSeedFixture();
  fixture.pe.rvaToOff = rva => rva === fixture.codeRvas[1] ? fixture.reader.size : rva;

  assert.deepEqual(await resolveFixture(fixture), [fixture.codeRvas[0]]);
});

void test("R2R rejects unmapped code without dropping other starts", async () => {
  const fixture = createReadyToRunSeedFixture();
  fixture.pe.rvaToOff = rva => rva === fixture.codeRvas[1] ? null : rva;

  assert.deepEqual(await resolveFixture(fixture), [fixture.codeRvas[0]]);
});
