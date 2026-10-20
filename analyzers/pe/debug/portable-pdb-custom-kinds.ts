import type { PortablePdbCustomData } from "./portable-pdb-custom-types.js";

// Authoritative GUIDs: compiler source, not inferred from record payload sizes.
// https://github.com/dotnet/roslyn/blob/main/src/Dependencies/CodeAnalysis.Debugging/PortableCustomDebugInfoKinds.cs
export const PORTABLE_PDB_CUSTOM_KINDS: Readonly<Record<string, {
  name: string; type: PortablePdbCustomData["type"];
  family: "text" | "state" | "source"; parents: readonly number[];
}>> = {
  "54fd2ac5-e925-401a-9c2a-f94f171072f8": {
    name: "Async method stepping", type: "asyncStepping", family: "state", parents: [6]
  },
  "6da9a61e-f8c7-4874-be62-68bc5630df71": {
    name: "Hoisted local scopes", type: "hoistedScopes", family: "state", parents: [6]
  },
  "83c563c4-b4f3-47d5-b824-ba5441477ea8": {
    name: "Dynamic local variables", type: "dynamicFlags", family: "state", parents: [0x33, 0x34]
  },
  "ed9fdf71-8879-4747-8ed3-fe5ede3ce710": {
    name: "Tuple element names", type: "tupleNames", family: "text", parents: [0x33, 0x34]
  },
  "58b2eab6-209f-4e4e-a22c-b2d0f910c782": {
    name: "Default namespace", type: "defaultNamespace", family: "text", parents: [0]
  },
  "755f52a8-91c5-45be-b4b8-209571e552bd": {
    name: "Edit and Continue local slots", type: "encSlots", family: "state", parents: [6]
  },
  "a643004c-0240-496f-a783-30d64f4979de": {
    name: "Edit and Continue lambdas and closures", type: "encLambdas", family: "state", parents: [6]
  },
  "8b78cd68-2ede-420b-980b-e15884b8aaa3": {
    name: "Edit and Continue state machine states", type: "encStates", family: "state", parents: [6]
  },
  "cc110556-a091-4d38-9fec-25ab9a351a6a": {
    name: "Source Link", type: "sourceLink", family: "text", parents: [0]
  },
  "0e8a571b-6926-466e-b4ad-8ab04611f5fe": {
    name: "Embedded source", type: "embeddedSource", family: "source", parents: [0x30]
  },
  "7e4d4708-096e-4c5c-aeda-cb10ba6a740d": {
    name: "Compilation references", type: "references", family: "text", parents: [0]
  },
  "b5feec05-8cd0-4a83-96da-466284bb4bd8": {
    name: "Compilation options", type: "options", family: "text", parents: [0]
  },
  "932e74bc-dba9-4478-8d46-0f32a7bab3d3": {
    name: "Type definition documents", type: "typeDocuments", family: "state", parents: [2]
  },
  "9d40ace1-c703-4d0e-bf41-7243060a8fb5": {
    name: "Primary constructor", type: "primaryConstructor", family: "state", parents: [6]
  }
};
