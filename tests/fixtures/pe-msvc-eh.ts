import { MsvcRttiPeFixtureBuilder } from "./pe-msvc-rtti-fixture.js";
import { createEmptyExceptionDirectory } from "../../analyzers/pe/exception/types.js";
import type { PeLanguageHandler } from "../../analyzers/pe/exception/types.js";
import type { PeImportParseResult } from "../../analyzers/pe/imports/index.js";
import { MockFile } from "../helpers/mock-file.js";

export const createEhFixture = () => {
  const builder = new MsvcRttiPeFixtureBuilder();
  const beginRva = builder.allocateFunctionTarget();
  const catchRva = builder.allocateFunctionTarget();
  const handlerRva = builder.allocateFunctionTarget();
  const unwindInfoRva = builder.allocateData(12);
  const dataRva = unwindInfoRva + 8;
  // Zero-code v1 UNWIND_INFO with EHANDLER; tail points at a real import thunk.
  builder.patchByte(unwindInfoRva, 9);
  builder.patchUint32(unwindInfoRva, 4, handlerRva);
  const iatRva = builder.allocateData(16, 8);
  builder.patchByte(handlerRva, 0xff);
  builder.patchByte(handlerRva + 1, 0x25);
  builder.patchInt32(handlerRva, 2, iatRva - handlerRva - 6);
  const imports: PeImportParseResult = {
    thunkEntrySize: 8, entries: [{ dll: "vcruntime140.dll", originalFirstThunkRva: iatRva + 8,
      firstThunkRva: iatRva, timeDateStamp: 0, forwarderChain: 0,
      lookupSource: "import-lookup-table", thunkTableTerminated: true,
      functions: [{ name: "__CxxFrameHandler3" }] }]
  };
  const exception = { ...createEmptyExceptionDirectory([], "amd64"), functionCount: 1, beginRvas: [beginRva],
    rangeLengths: [16],
    languageHandlers: [{ unwindInfoRva, handlerRva, dataRva,
      functionRanges: [{ begin: beginRva, end: beginRva + 16 }] as
        NonNullable<PeLanguageHandler["functionRanges"]> }] };
  return { builder, beginRva, catchRva, handlerRva, iatRva, dataRva, unwindInfoRva, imports, exception };
};

/** Complete PE image for the parseForUi and browser paths, with a real ILT/IAT and .pdata. */
export const buildEhPeImage = (subject: ReturnType<typeof createEhFixture>): MockFile => {
  const { builder, beginRva, unwindInfoRva, iatRva, imports } = subject;
  const descriptor = builder.allocateData(40);
  const ilt = builder.allocateData(16, 8);
  const functionName = new TextEncoder().encode(`${imports.entries[0]!.functions[0]!.name}\0`);
  const nameRva = builder.allocateData(2 + functionName.length, 2);
  builder.bytes.set(functionName, builder.offsetOf(nameRva + 2));
  const dllName = new TextEncoder().encode("vcruntime140.dll\0");
  const dllRva = builder.allocateData(dllName.length, 1);
  builder.bytes.set(dllName, builder.offsetOf(dllRva));
  builder.patchBigUint64(ilt, BigInt(nameRva));
  builder.patchBigUint64(iatRva, BigInt(nameRva));
  builder.patchUint32(descriptor, 0, ilt);
  builder.patchUint32(descriptor, 12, dllRva);
  builder.patchUint32(descriptor, 16, iatRva);
  const pdata = builder.allocateData(12);
  builder.patchUint32(pdata, 0, beginRva);
  builder.patchUint32(pdata, 4, beginRva + 16);
  builder.patchUint32(pdata, 8, unwindInfoRva);
  const fixture = builder.build();
  const view = new DataView(fixture.bytes.buffer);
  // PE32+ optional header offset 0x98; DataDirectory starts at offset 112.
  view.setUint32(0x98 + 112 + 8, descriptor, true);
  view.setUint32(0x98 + 112 + 12, 40, true);
  view.setUint32(0x98 + 112 + 24, pdata, true);
  view.setUint32(0x98 + 112 + 28, 12, true);
  return new MockFile(fixture.bytes, "msvc-eh.exe", "application/vnd.microsoft.portable-executable");
};

export const addFh3 = (subject: ReturnType<typeof createEhFixture>) => {
  const { builder, beginRva, catchRva } = subject;
  const unwindRva = builder.allocateData(16);
  builder.patchInt32(unwindRva, 0, -1);
  builder.patchInt32(unwindRva, 8, -1);
  const handlerMapRva = builder.allocateData(20);
  builder.patchUint32(handlerMapRva, 12, catchRva);
  const tryMapRva = builder.allocateData(20);
  builder.patchInt32(tryMapRva, 8, 1);
  builder.patchUint32(tryMapRva, 12, 1);
  builder.patchUint32(tryMapRva, 16, handlerMapRva);
  const ipMapRva = builder.allocateData(8);
  builder.patchUint32(ipMapRva, 0, beginRva);
  builder.patchInt32(ipMapRva, 4, -1);
  const infoRva = builder.allocateData(40);
  // MSVC ehdata.h EH_MAGIC_NUMBER3, relative FuncInfo layout.
  builder.patchUint32(infoRva, 0, 0x19930522);
  builder.patchUint32(infoRva, 4, 2);
  builder.patchUint32(infoRva, 8, unwindRva);
  builder.patchUint32(infoRva, 12, 1);
  builder.patchUint32(infoRva, 16, tryMapRva);
  builder.patchUint32(infoRva, 20, 1);
  builder.patchUint32(infoRva, 24, ipMapRva);
  builder.patchUint32(subject.dataRva, 0, infoRva);
  return { infoRva, unwindRva, handlerMapRva, tryMapRva, ipMapRva };
};

export const addFh4 = (subject: ReturnType<typeof createEhFixture>) => {
  const { builder, catchRva } = subject;
  subject.imports.entries[0]!.functions[0]!.name = "__CxxFrameHandler4";
  // MSVC ehdata4_export.h: count=2; NoUW entries point back to before entries.
  const unwindRva = builder.allocateData(3, 1);
  builder.bytes.set([4, 8, 16], builder.offsetOf(unwindRva));
  const handlerMapRva = builder.allocateData(7, 1);
  // count=1; one relative continuation (header 0x10), continuation offset=8.
  builder.bytes.set([2, 0x10], builder.offsetOf(handlerMapRva));
  builder.patchUint32(handlerMapRva, 2, catchRva);
  builder.patchByte(handlerMapRva + 6, 16);
  const tryMapRva = builder.allocateData(8, 1);
  builder.bytes.set([2, 0, 0, 2], builder.offsetOf(tryMapRva));
  builder.patchUint32(tryMapRva, 4, handlerMapRva);
  const ipMapRva = builder.allocateData(3, 1);
  builder.bytes.set([2, 0, 0], builder.offsetOf(ipMapRva)); // one {delta=0,state=-1}
  const infoRva = builder.allocateData(13, 1);
  builder.patchByte(infoRva, 0x38); // UnwindMap|TryBlockMap|EHs.
  builder.patchUint32(infoRva, 1, unwindRva);
  builder.patchUint32(infoRva, 5, tryMapRva);
  builder.patchUint32(infoRva, 9, ipMapRva);
  builder.patchUint32(subject.dataRva, 0, infoRva);
  return { infoRva, unwindRva, handlerMapRva, tryMapRva, ipMapRva };
};
