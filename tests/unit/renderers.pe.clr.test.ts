"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { renderClr } from "../../renderers/pe/directories.js";

type RenderClrInput = Parameters<typeof renderClr>[0];

// Format values below are copied from ECMA-335 and dotnet/runtime CoreCLR headers.
const CLR_HEADER_SIZE = 0x48; // ECMA-335 II.25.3.3 IMAGE_COR20_HEADER byte size.
const CLR_NATIVE_ENTRYPOINT_FLAG = 0x00000010; // COMIMAGE_FLAGS_NATIVE_ENTRYPOINT.
const CLR_ILONLY_FLAG = 0x00000001; // COMIMAGE_FLAGS_ILONLY.
const CLR_32BIT_REQUIRED_FLAG = 0x00000002; // COMIMAGE_FLAGS_32BITREQUIRED.
const CLR_STRONG_NAME_SIGNED_FLAG = 0x00000008; // COMIMAGE_FLAGS_STRONGNAMESIGNED.
const CLR_RESERVED_40_FLAG = 0x00000040; // Not defined by ECMA-335 II.25.3.3.1.
const VTABLE_32BIT_CALL_MOST_DERIVED = 0x0011; // ECMA-335 II.25.3.3 VTableFixups Type flags.
const METADATA_ROOT_SIGNATURE = 0x424a5342; // ECMA-335 II.24.2.1 metadata signature "BSJB".
const HEAP_EXTRA_DATA = 0x40; // CoreCLR CMiniMdSchemaBase::EXTRA_DATA schema flag.
const READY_TO_RUN_LARGEST_RID_LOG2 = 0x0a; // Observed in CoreCLR ReadyToRun table streams.
const ASSEMBLY_TABLE_ID = 0x20; // ECMA-335 II.22 Assembly table.
const MEMBER_REF_TABLE_ID = 0x0a; // ECMA-335 II.22 MemberRef table.
const SHA1_HASH_ALGORITHM_ID = 0x00008004; // ECMA-335 Assembly.HashAlgId SHA-1 / CALG_SHA1.
// ReadyToRun values from dotnet/runtime src/coreclr/inc/readytorun.h:
// https://github.com/dotnet/runtime/blob/main/src/coreclr/inc/readytorun.h
const READY_TO_RUN_SIGNATURE = 0x00525452;
const READY_TO_RUN_MAJOR_VERSION = 18;
const READY_TO_RUN_STRIPPED_IL_BODIES = 0x00000200;
const COMPILER_IDENTIFIER_SECTION = 100;

const generatedLabel = (prefix: string, index: number): string => `${prefix}-${index.toString(36)}`;

const generatedHex = (bytes: number): string =>
  Array.from({ length: bytes }, (_, index) => index.toString(16).padStart(2, "0")).join("");

const makeIncidentalNumbers = (): { nextRva: () => number; nextSize: () => number } => {
  let current = Uint8Array.BYTES_PER_ELEMENT << 8;
  return {
    nextRva: () => {
      current += Uint32Array.BYTES_PER_ELEMENT << 4;
      return current;
    },
    nextSize: () => Uint32Array.BYTES_PER_ELEMENT << 4
  };
};

const makeClrBase = (): RenderClrInput => ({
  cb: CLR_HEADER_SIZE,
  MajorRuntimeVersion: 4,
  MinorRuntimeVersion: 0,
  MetaDataRVA: 0,
  MetaDataSize: 0,
  Flags: 0,
  EntryPointToken: 0,
  ResourcesRVA: 0,
  ResourcesSize: 0,
  StrongNameSignatureRVA: 0,
  StrongNameSignatureSize: 0,
  CodeManagerTableRVA: 0,
  CodeManagerTableSize: 0,
  VTableFixupsRVA: 0,
  VTableFixupsSize: 0,
  ExportAddressTableJumpsRVA: 0,
  ExportAddressTableJumpsSize: 0,
  ManagedNativeHeaderRVA: 0,
  ManagedNativeHeaderSize: 0
});

void test("renderClr includes extended COR20 fields and native entrypoint interpretation", () => {
  const values = makeIncidentalNumbers();
  const clr: RenderClrInput = {
    ...makeClrBase(),
    Flags: CLR_NATIVE_ENTRYPOINT_FLAG,
    EntryPointToken: values.nextRva(),
    ResourcesRVA: values.nextRva(),
    ResourcesSize: values.nextSize(),
    StrongNameSignatureRVA: values.nextRva(),
    StrongNameSignatureSize: values.nextSize(),
    CodeManagerTableRVA: values.nextRva(),
    CodeManagerTableSize: values.nextSize(),
    VTableFixupsRVA: values.nextRva(),
    VTableFixupsSize: values.nextSize(),
    ExportAddressTableJumpsRVA: values.nextRva(),
    ExportAddressTableJumpsSize: values.nextSize(),
    ManagedNativeHeaderRVA: values.nextRva(),
    ManagedNativeHeaderSize: values.nextSize()
  };
  const out: string[] = [];
  renderClr(clr, out);
  const html = out.join("");

  assert.ok(html.includes("CLR (.NET) header"));
  assert.ok(html.includes("EntryPointRVA"));
  assert.ok(html.includes("Resources"));
  assert.ok(html.includes("StrongNameSignature"));
  assert.ok(html.includes("CodeManagerTable"));
  assert.ok(html.includes("VTableFixups"));
  assert.ok(html.includes("ExportAddressTableJumps"));
  assert.ok(html.includes("ManagedNativeHeader"));
});

void test("renderClr decodes managed entrypoint tokens, metadata stream types, and vtable flags", () => {
  const values = makeIncidentalNumbers();
  const assemblyName = generatedLabel("assembly", 0);
  const targetFramework = ".NETCoreApp,Version=v8.0";
  const parentIndexRaw = values.nextSize();
  const constructorIndexRaw = values.nextSize();
  const clr: RenderClrInput = {
    ...makeClrBase(),
    Flags: CLR_ILONLY_FLAG,
    EntryPointToken: 0x06000001, // ECMA-335 MethodDef token for RID 1.
    VTableFixupsRVA: values.nextRva(),
    VTableFixupsSize: values.nextSize(),
    vtableFixups: [{ RVA: values.nextRva(), Count: 2, Type: VTABLE_32BIT_CALL_MOST_DERIVED }],
    meta: {
      version: "v4.0.30319",
      verMajor: 1,
      verMinor: 1,
      signature: METADATA_ROOT_SIGNATURE,
      flags: 0,
      reserved: 0,
      streamCount: 2,
      streams: [
        { name: "#~", offset: values.nextSize(), size: values.nextSize() },
        { name: "#Strings", offset: values.nextSize(), size: values.nextSize() }
      ],
      tables: {
        streamName: "#~",
        majorVersion: 2,
        minorVersion: 0,
        heapSizes: HEAP_EXTRA_DATA,
        largestRidLog2: READY_TO_RUN_LARGEST_RID_LOG2,
        extraData: HEAP_EXTRA_DATA + READY_TO_RUN_LARGEST_RID_LOG2,
        validMask: "0x0000000100001003",
        sortedMask: "0x0000000000000000",
        heapIndexSizes: { string: 2, guid: 2, blob: 2 },
        rowCounts: [
          { tableId: 0, name: "Module", rows: 1, known: true, sorted: false },
          { tableId: ASSEMBLY_TABLE_ID, name: "Assembly", rows: 1, known: true, sorted: false }
        ],
        modules: [{ row: 1, name: generatedLabel("module", 0), mvid: null }],
        assembly: {
          row: 1,
          name: assemblyName,
          culture: "",
          version: generatedLabel("version", 0),
          hashAlgorithm: SHA1_HASH_ALGORITHM_ID,
          flags: 0,
          publicKey: []
        },
        assemblyRefs: [],
        typeRefs: [],
        typeDefs: [],
        methodDefs: [],
        memberRefs: [],
        moduleRefs: [],
        implMaps: [],
        files: [],
        exportedTypes: [],
        manifestResources: [],
        customAttributes: [{
          row: 1,
          parent: { table: "Assembly", tableId: ASSEMBLY_TABLE_ID, row: 1, raw: parentIndexRaw, valid: true },
          parentName: assemblyName,
          constructor: {
            table: "MemberRef",
            tableId: MEMBER_REF_TABLE_ID,
            row: 1,
            raw: constructorIndexRaw,
            tag: Uint32Array.BYTES_PER_ELEMENT - Uint8Array.BYTES_PER_ELEMENT,
            valid: true
          },
          constructorName: ".ctor",
          attributeType: "System.Runtime.Versioning.TargetFrameworkAttribute",
          valueBlobIndex: 1,
          fixedArguments: [{ type: "string", value: targetFramework }],
          namedArguments: [{ kind: "property", name: "FrameworkDisplayName", type: "string", value: ".NET 8.0" }]
        }]
      }
    }
  };
  const out: string[] = [];
  renderClr(clr, out);
  const html = out.join("");

  assert.ok(html.includes("EntryPointToken"));
  assert.ok(html.includes("MethodDef, RID 1"));
  assert.ok(html.includes("Metadata root"));
  assert.ok(html.includes("424a5342"));
  assert.ok(html.includes("Compressed metadata tables"));
  assert.ok(html.includes("String heap"));
  assert.ok(html.includes("32BIT | CALL_MOST_DERIVED"));
  assert.ok(html.includes("Target framework"));
  assert.ok(html.includes(targetFramework));
  assert.ok(html.includes("Assembly identity"));
  assert.ok(html.includes("LargestRidLog2"));
  assert.ok(html.includes("EXTRA_DATA"));
});

void test("renderClr includes explanatory strong-name resources and ReadyToRun sections", () => {
  const values = makeIncidentalNumbers();
  const publicKeyToken = generatedHex(8);
  const resourceName = generatedLabel("logo", 0);
  const clr: RenderClrInput = {
    ...makeClrBase(),
    Flags: CLR_STRONG_NAME_SIGNED_FLAG,
    ResourcesRVA: values.nextRva(),
    ResourcesSize: values.nextSize(),
    StrongNameSignatureRVA: values.nextRva(),
    StrongNameSignatureSize: values.nextSize(),
    ManagedNativeHeaderRVA: values.nextRva(),
    ManagedNativeHeaderSize: values.nextSize(),
    strongName: {
      status: "delay-signed",
      publicKeyToken,
      verification: "unknown",
      verificationNote: "Signature bytes are all zero, which is typical for delay-signed assemblies.",
      issues: []
    },
    managedResources: {
      issues: [],
      entries: [{
        row: 1,
        name: resourceName,
        flags: 1,
        offset: 0,
        implementation: { table: "null", tableId: -1, row: 0, raw: 0, valid: false },
        storage: "embedded",
        size: values.nextSize(),
        previewKind: "summary",
        previewFields: [{ label: "Detected", value: "PNG (heuristic)" }]
      }]
    },
    readyToRun: {
      status: "ready-to-run",
      signature: READY_TO_RUN_SIGNATURE,
      majorVersion: READY_TO_RUN_MAJOR_VERSION,
      minorVersion: 5,
      flags: READY_TO_RUN_STRIPPED_IL_BODIES,
      sectionCount: 1,
      sections: [{
        type: COMPILER_IDENTIFIER_SECTION,
        name: "CompilerIdentifier",
        rva: values.nextRva(),
        size: values.nextSize()
      }],
      issues: []
    }
  };
  const out: string[] = [];
  renderClr(clr, out);
  const html = out.join("");

  assert.ok(html.includes("Strong names identify assemblies"));
  assert.ok(html.includes(publicKeyToken));
  assert.ok(html.includes("Managed resources"));
  assert.ok(html.includes(resourceName));
  assert.ok(html.includes("<dt>Flags</dt>"));
  assert.ok(html.includes("<dt>Implementation</dt>"));
  assert.ok(!html.includes("Manifest resources"));
  assert.ok(html.includes("ReadyToRun"));
  assert.ok(html.includes("STRIPPED_IL_BODIES"));
  assert.ok(html.includes("CompilerIdentifier"));
});

void test("renderClr decodes known CorFlags and leaves only reserved bits unknown", () => {
  const clr: RenderClrInput = {
    ...makeClrBase(),
    Flags: CLR_ILONLY_FLAG |
      CLR_32BIT_REQUIRED_FLAG |
      CLR_STRONG_NAME_SIGNED_FLAG |
      CLR_RESERVED_40_FLAG
  };
  const out: string[] = [];
  renderClr(clr, out);
  const html = out.join("");

  assert.match(html, /<span class="opt sel"[^>]*>ILONLY<\/span>/);
  assert.match(html, /<span class="opt sel"[^>]*>32BITREQUIRED<\/span>/);
  assert.match(html, /<span class="opt sel"[^>]*>STRONGNAMESIGNED<\/span>/);
  assert.match(html, /UNKNOWN_BITS_0x0040/);
  assert.doesNotMatch(html, /UNKNOWN_BITS_0x004a/);
});
