import assert from "node:assert/strict";
import { mock, test } from "node:test";
import { createEhPersonalityResolver } from "../../../../../analyzers/pe/msvc-eh/personality.js";
import { createEhImage } from "../../../../../analyzers/pe/msvc-eh/image.js";
import { createEhFixture } from "../../../../fixtures/pe-msvc-eh.js";

void test("EH personality resolves named imports by the correct IAT slot through a direct thunk chain", async () => {
  const subject = createEhFixture();
  subject.builder.patchByte(subject.beginRva, 0xe9);
  subject.builder.patchInt32(subject.beginRva, 1, subject.handlerRva - subject.beginRva - 5);
  const fixture = subject.builder.build();
  const image = createEhImage(fixture.file, fixture.core);
  const reads = mock.method(image, "read");
  const resolve = createEhPersonalityResolver(image, subject.imports, []);
  assert.equal((await resolve(subject.beginRva))?.name, "__CxxFrameHandler3");
  const firstReads = reads.mock.callCount();
  assert.equal((await resolve(subject.beginRva))?.name, "__CxxFrameHandler3");
  assert.equal(reads.mock.callCount(), firstReads);
  assert.equal(await resolve(subject.iatRva), null);
});

for (const name of ["__CxxFrameHandler4", "__C_specific_handler", "__GSHandlerCheck_EH", "__GSHandlerCheck_EH4"]) {
  void test(`EH personality accepts proven ${name} exports`, async () => {
    const subject = createEhFixture();
    const fixture = subject.builder.build();
    const resolve = createEhPersonalityResolver(createEhImage(fixture.file, fixture.core), null,
      [{ ordinal: 1, names: [name], rva: subject.beginRva }]);
    assert.ok(await resolve(subject.beginRva));
  });
}

void test("EH resolver rejects cycles, forwarded exports, ordinal-only imports and IAT fallback", async () => {
  const subject = createEhFixture();
  subject.builder.patchByte(subject.beginRva, 0xe9);
  subject.builder.patchInt32(subject.beginRva, 1, -5);
  subject.imports.entries[0]!.lookupSource = "iat-fallback";
  const fixture = subject.builder.build();
  const resolve = createEhPersonalityResolver(createEhImage(fixture.file, fixture.core), subject.imports,
    [{ ordinal: 1, names: ["__CxxFrameHandler3"], rva: subject.catchRva, forwarder: "other.func" }]);
  assert.equal(await resolve(subject.beginRva), null);
  assert.equal(await resolve(subject.handlerRva), null);
  assert.equal(await resolve(subject.catchRva), null);
});

void test("EH resolver does not use unterminated import tables or unrelated names", async () => {
  const subject = createEhFixture();
  subject.imports.entries[0]!.thunkTableTerminated = false;
  subject.imports.entries[0]!.functions = [{ ordinal: 1 }, { name: "unrelated" }];
  const fixture = subject.builder.build();
  assert.equal(await createEhPersonalityResolver(createEhImage(fixture.file, fixture.core), subject.imports,
    [{ ordinal: 1, names: ["unrelated"], rva: subject.beginRva }])(subject.handlerRva), null);
});

void test("conflicting handler identities at one address remain unresolved", async () => {
  const subject = createEhFixture();
  const fixture = subject.builder.build();
  const resolve = createEhPersonalityResolver(createEhImage(fixture.file, fixture.core), null,
    [{ ordinal: 1, names: ["__CxxFrameHandler3"], rva: subject.beginRva }],
    [{ rva: subject.beginRva, name: "__CxxFrameHandler4", source: "COFF" }]);
  assert.equal(await resolve(subject.beginRva), null);
});

void test("COFF or CodeView function symbols can identify an unexported GS wrapper", async () => {
  const subject = createEhFixture();
  const fixture = subject.builder.build();
  const resolve = createEhPersonalityResolver(createEhImage(fixture.file, fixture.core), null, [],
    [{ rva: subject.beginRva, name: "__GSHandlerCheck_EH4", source: "CodeView" },
      { rva: subject.iatRva, name: "__CxxFrameHandler3", source: "COFF" },
      { rva: subject.catchRva, name: "unrelated", source: "COFF" }]);
  assert.equal((await resolve(subject.beginRva))?.name, "__CxxFrameHandler4");
  assert.equal(await resolve(subject.iatRva), null);
});

void test("an ordinal import never supplies a personality name", async () => {
  const subject = createEhFixture();
  subject.imports.entries[0]!.functions = [{ ordinal: 1 }];
  const fixture = subject.builder.build();
  assert.equal(await createEhPersonalityResolver(createEhImage(fixture.file, fixture.core), subject.imports, [])(
    subject.handlerRva), null);
});

void test("EH import identity requires a readable mapped IAT slot", async () => {
  const subject = createEhFixture();
  subject.imports.entries[0]!.firstThunkRva = 0x300000; // Outside this fixture's SizeOfImage.
  subject.builder.patchInt32(subject.handlerRva, 2, 0x300000 - subject.handlerRva - 6);
  const fixture = subject.builder.build();
  assert.equal(await createEhPersonalityResolver(createEhImage(fixture.file, fixture.core),
    subject.imports, [])(subject.handlerRva), null);
});

void test("EH import identity refuses warnings that can include masked invalid name thunks", async () => {
  const subject = createEhFixture();
  subject.imports.warning = "Import name thunk has reserved bits set.";
  const fixture = subject.builder.build();
  assert.equal(await createEhPersonalityResolver(createEhImage(fixture.file, fixture.core),
    subject.imports, [])(subject.handlerRva), null);
});

void test("EH import stride must agree with the optional header", async () => {
  const subject = createEhFixture();
  subject.imports.thunkEntrySize = 4;
  const fixture = subject.builder.build();
  assert.equal(await createEhPersonalityResolver(createEhImage(fixture.file, fixture.core),
    subject.imports, [])(subject.handlerRva), null);
});

void test("a nameless import descriptor cannot identify an EH runtime", async () => {
  const subject = createEhFixture();
  subject.imports.entries[0]!.dll = "";
  const fixture = subject.builder.build();
  assert.equal(await createEhPersonalityResolver(createEhImage(fixture.file, fixture.core),
    subject.imports, [])(subject.handlerRva), null);
});

void test("the GS SEH wrapper retains the C-specific scope-table layout", async () => {
  const subject = createEhFixture();
  const fixture = subject.builder.build();
  const resolve = createEhPersonalityResolver(createEhImage(fixture.file, fixture.core), null,
    [{ ordinal: 1, names: ["__GSHandlerCheck_SEH"], rva: subject.beginRva }]);
  assert.equal((await resolve(subject.beginRva))?.name, "__C_specific_handler");
});

void test("EH import identities retain ordinal slots before a named handler", async () => {
  const subject = createEhFixture();
  subject.imports.entries[0]!.functions.unshift({ ordinal: 1 });
  subject.builder.patchInt32(subject.handlerRva, 2, subject.iatRva + 8 - subject.handlerRva - 6);
  const fixture = subject.builder.build();
  const identity = await createEhPersonalityResolver(createEhImage(fixture.file, fixture.core),
    subject.imports, [])(subject.handlerRva);
  assert.equal(identity?.name, "__CxxFrameHandler3");
  assert.match(identity?.evidence ?? "", /vcruntime140\.dll!__CxxFrameHandler3/);
});

void test("unrelated export aliases and identical corroborating symbols are consistent", async () => {
  const subject = createEhFixture();
  const fixture = subject.builder.build();
  const identity = await createEhPersonalityResolver(createEhImage(fixture.file, fixture.core), null,
    [{ ordinal: 1, names: ["unrelated", "__CxxFrameHandler3"], rva: subject.beginRva }],
    [{ rva: subject.beginRva, name: "__CxxFrameHandler3", source: "COFF" }])(subject.beginRva);
  assert.equal(identity?.name, "__CxxFrameHandler3");
  assert.match(identity?.evidence ?? "", /COFF function symbol __CxxFrameHandler3/);
});
