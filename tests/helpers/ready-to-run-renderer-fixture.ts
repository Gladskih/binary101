import type { PeClrReadyToRun } from "../../analyzers/pe/clr/ready-to-run-types.js";
export const createReadyToRunRendererFixture = (): PeClrReadyToRun => ({
  status: "ready-to-run", signature: 0x00525452, majorVersion: 16, minorVersion: 0,
  flags: 0, sectionCount: 7, issues: [], sections: [
    { type: 100, name: "CompilerIdentifier", rva: 16, size: 4,
      decoded: { kind: "text", text: "<compiler>" } },
    { type: 101, name: "ImportSections", rva: 32, size: 20, decoded: {
      kind: "imports", imports: [{ rva: 128, size: 8, flags: 1, type: 2, entrySize: 4,
        signaturesRva: 144, auxiliaryDataRva: 160, entries: [
          { value: Uint8Array.of(0x12, 0x34, 0x56, 0x78), signatureRva: 176 },
          { value: Uint8Array.of(0, 0, 0, 0), signatureRva: null }]
      }] } },
    { type: 103, name: "MethodDefEntryPoints", rva: 64, size: 8, decoded: {
      kind: "methods", methods: [
        { methodRid: 1, runtimeFunctionIndex: 2, fixupOffset: 4 },
        { methodRid: 3, runtimeFunctionIndex: 5, fixupOffset: null }]
    } },
    { type: 115, name: "ComponentAssemblies", rva: 80, size: 16, decoded: {
      kind: "components", entries: [{ clrRva: 256, clrSize: 72,
        coreHeaderRva: 512, coreHeaderSize: 32 }]
    } },
    { type: 120, name: "HotColdMap", rva: 96, size: 8, decoded: {
      kind: "hot-cold", entries: [{ coldRuntimeFunction: 3, hotRuntimeFunction: 1 }]
    } },
    { type: 999, name: "<unknown>", rva: 112, size: 0 },
    { type: 101, name: "EmptyImports", rva: 112, size: 0, decoded: {kind:"imports",imports:[]} }
  ]
});

