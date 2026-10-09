import assert from "node:assert/strict";
import test from "node:test";
import { NativeAotRuntimeTails } from "../../../../analyzers/native-aot/runtime-type-tail.js";
import { createNativeAotRuntimeTailFixture } from "../../../helpers/native-aot-runtime-tail-fixture.js";

for (const width of [4, 8] as const) {
  void test(`resolves finalizer and only dispatch-referenced sealed slots for pointer size ${width}`, async () => {
    const fixture = createNativeAotRuntimeTailFixture(width);

    const tail = await new NativeAotRuntimeTails(fixture.references,
      { majorVersion: 16, minorVersion: 0 }).read(fixture.type);

    assert.deepEqual(tail, { finalizerRva: fixture.codeRvas[1], dispatchMap: {
      rva: fixture.dispatchRva, counts: [2, 1, 1, 1], entries: [
        { kind: "standard", interfaceIndex: 0, interfaceMethodSlot: 0, implementationSlot: 0 },
        { kind: "standard", interfaceIndex: 0, interfaceMethodSlot: 0, implementationSlot: 3 },
        { kind: "default", interfaceIndex: 0, interfaceMethodSlot: 0, implementationSlot: 65534 },
        { kind: "static", interfaceIndex: 0, interfaceMethodSlot: 0, implementationSlot: 3, contextSource: 1 },
        { kind: "default static", interfaceIndex: 0, interfaceMethodSlot: 0, implementationSlot: 65535, contextSource: 2 }
      ] }, sealedSlots: [{ slot: 0, targetRva: fixture.codeRvas[0], requiresInstantiatingThunk: false }] });
    assert.deepEqual([...fixture.issues], []);
  });
}

void test(".NET 9 uses the same static relative layout and unflagged types have no tail", async () => {
  const fixture = createNativeAotRuntimeTailFixture();
  const reader = new NativeAotRuntimeTails(fixture.references, { majorVersion: 10, minorVersion: 1 });

  assert.equal((await reader.read(fixture.type))?.finalizerRva, fixture.codeRvas[1]);
  assert.equal(await reader.read({ ...fixture.type, flags: 0 }), null);
  assert.deepEqual([...fixture.issues], []);
});

void test("unknown, incompatible minor versions and dynamic layouts cannot supply guessed tail seeds", async () => {
  const fixture = createNativeAotRuntimeTailFixture();

  assert.equal(await new NativeAotRuntimeTails(fixture.references).read(fixture.type), null);
  assert.equal(await new NativeAotRuntimeTails(fixture.references,
    { majorVersion: 10, minorVersion: 0 }).read(fixture.type), null);
  assert.equal(await new NativeAotRuntimeTails(fixture.references,
    { majorVersion: 16, minorVersion: 1 }).read(fixture.type), null);
  assert.equal(await new NativeAotRuntimeTails(fixture.references,
    { majorVersion: 16, minorVersion: 0 }).read({ ...fixture.type, flags: fixture.flags | 0x80000 }), null);
  assert.match([...fixture.issues].join(), /header version/);
  assert.match([...fixture.issues].join(), /Dynamic MethodTable/);
});

void test("finalizer-only and dispatch-only layouts do not read absent optional fields", async () => {
  const fixture = createNativeAotRuntimeTailFixture();
  fixture.view.setInt32(fixture.tailRva + 8, fixture.codeRvas[1]! - fixture.tailRva - 8, true);
  const reader = new NativeAotRuntimeTails(fixture.references, { majorVersion: 16, minorVersion: 0 });

  assert.deepEqual(await reader.read({ ...fixture.type, flags: 0x00100000 }), {
    finalizerRva: fixture.codeRvas[1], dispatchMap: null, sealedSlots: [] });
  assert.deepEqual([...fixture.issues], []);
  const other = createNativeAotRuntimeTailFixture();
  const dispatch = await new NativeAotRuntimeTails(other.references, { majorVersion: 16, minorVersion: 0 })
    .read({ ...other.type, flags: 0x00040000 });
  assert.equal(dispatch?.finalizerRva, null);
  assert.equal(dispatch?.dispatchMap?.entries.length, 5);
  assert.deepEqual(dispatch?.sealedSlots, []);
  assert.match([...other.issues].join(), /without a sealed vtable/);
});

void test("sealed slot indices address their own relative fields instead of the start of the table", async () => {
  const fixture = createNativeAotRuntimeTailFixture();
  fixture.view.setUint16(fixture.dispatchRva + 18, 4, true);
  fixture.view.setUint16(fixture.dispatchRva + 30, 4, true);
  fixture.view.setInt32(fixture.sealedRva + 4, fixture.codeRvas[1]! - fixture.sealedRva - 4, true);

  const tail = await new NativeAotRuntimeTails(fixture.references, { majorVersion: 16, minorVersion: 0 })
    .read(fixture.type);

  assert.deepEqual(tail?.sealedSlots, [{ slot: 1, targetRva: fixture.codeRvas[1], requiresInstantiatingThunk: false }]);
  assert.deepEqual([...fixture.issues], []);
});

void test("an untagged interface implementation remains an ordinary method", async () => {
  const fixture = createNativeAotRuntimeTailFixture();

  const tail = await new NativeAotRuntimeTails(fixture.references, { majorVersion: 16, minorVersion: 0 })
    .read({ ...fixture.type, flags: 0x54540000 });

  assert.deepEqual(tail?.sealedSlots, [{ slot: 0, targetRva: fixture.codeRvas[0], requiresInstantiatingThunk: false }]);
});

void test("missing dispatch maps never trigger speculative sealed-table scanning", async () => {
  const fixture = createNativeAotRuntimeTailFixture();
  fixture.view.setInt32(fixture.tailRva + 8, fixture.sealedRva - fixture.tailRva - 8, true);

  const tail = await new NativeAotRuntimeTails(fixture.references, { majorVersion: 16, minorVersion: 0 })
    .read({ ...fixture.type, flags: 0x00400000 });

  assert.deepEqual(tail, { finalizerRva: null, dispatchMap: null, sealedSlots: [] });
  assert.deepEqual([...fixture.issues], []);
});

void test("interface sealed code strips its instantiating-thunk flag without altering class method addresses", async () => {
  const fixture = createNativeAotRuntimeTailFixture();
  // RuntimeConstants.DispatchMapCodePointerFlags.RequiresInstantiatingThunkFlag = 2.
  fixture.view.setInt32(fixture.sealedRva, fixture.codeRvas[0]! + 2 - fixture.sealedRva, true);

  const tail = await new NativeAotRuntimeTails(fixture.references, { majorVersion: 16, minorVersion: 0 })
    .read({ ...fixture.type, flags: 0x54540000 });

  assert.deepEqual(tail?.sealedSlots, [{ slot: 0, targetRva: fixture.codeRvas[0], requiresInstantiatingThunk: true }]);
  const other = createNativeAotRuntimeTailFixture();
  other.codeRvas[0] = 0x42;
  other.view.setInt32(other.sealedRva, 0x42 - other.sealedRva, true);
  assert.deepEqual((await new NativeAotRuntimeTails(other.references, { majorVersion: 16, minorVersion: 0 })
    .read(other.type))?.sealedSlots, [{ slot: 0, targetRva: 0x42, requiresInstantiatingThunk: false }]);
});

void test("invalid interface and static context indices preserve raw dispatch records but produce no sealed seeds", async () => {
  const fixture = createNativeAotRuntimeTailFixture();
  fixture.view.setUint16(fixture.dispatchRva + 14, 1, true);
  fixture.view.setUint16(fixture.dispatchRva + 32, 3, true);

  const tail = await new NativeAotRuntimeTails(fixture.references, { majorVersion: 16, minorVersion: 0 })
    .read(fixture.type);

  assert.equal(tail?.dispatchMap?.entries.length, 5);
  assert.deepEqual(tail?.sealedSlots, []);
  assert.match([...fixture.issues].join(), /interface or context index/);
});

void test("data targets and malformed sealed table addresses cannot become instruction seeds", async () => {
  const fixture = createNativeAotRuntimeTailFixture();
  fixture.view.setInt32(fixture.tailRva + 12, 0x220 - fixture.tailRva - 12, true);
  fixture.view.setInt32(fixture.sealedRva, 0x220 - fixture.sealedRva, true);

  const tail = await new NativeAotRuntimeTails(fixture.references, { majorVersion: 16, minorVersion: 0 })
    .read(fixture.type);

  assert.equal(tail?.finalizerRva, null);
  assert.deepEqual(tail?.sealedSlots, [{ slot: 0, targetRva: null, requiresInstantiatingThunk: false }]);
  assert.match([...fixture.issues].join(), /finalizer target/);
  assert.match([...fixture.issues].join(), /sealed slot target/);
});

for (const target of [0x2a1, 0x300, 0x400]) {
  void test(`rejects the invalid sealed-table address ${target}`, async () => {
    const fixture = createNativeAotRuntimeTailFixture();
    fixture.view.setInt32(fixture.tailRva + 16, target - fixture.tailRva - 16, true);

    const tail = await new NativeAotRuntimeTails(fixture.references, { majorVersion: 16, minorVersion: 0 })
    .read(fixture.type);

    assert.deepEqual(tail?.sealedSlots, []);
    assert.match([...fixture.issues].join(), /sealed vtable has an invalid/);
  });
}

void test("unreadable tail pointers stay unavailable", async context => {
  const fixture = createNativeAotRuntimeTailFixture();
  context.mock.method(fixture.references.data, "relative", async () => null);

  const tail = await new NativeAotRuntimeTails(fixture.references, { majorVersion: 16, minorVersion: 0 })
    .read(fixture.type);

  assert.deepEqual(tail, { finalizerRva: null, dispatchMap: null, sealedSlots: [] });
});

void test("an unreadable referenced slot is retained as unavailable", async context => {
  const fixture = createNativeAotRuntimeTailFixture();
  context.mock.method(fixture.image, "readData", async (address: number, size: number) =>
    address === fixture.sealedRva ? null : new DataView(fixture.bytes.buffer, address, size));

  const tail = await new NativeAotRuntimeTails(fixture.references, { majorVersion: 16, minorVersion: 0 })
    .read(fixture.type);

  assert.deepEqual(tail?.sealedSlots, [{ slot: 0, targetRva: null, requiresInstantiatingThunk: false }]);
  assert.match([...fixture.issues].join(), /unreadable/);
});
