import { PortablePdbBlobReader } from "./portable-pdb-blob.js";
import type { PortablePdbCustomData } from "./portable-pdb-custom-types.js";

// Portable PDB custom records and the compiler's public serialization source:
// https://github.com/dotnet/runtime/blob/main/docs/design/specs/PortablePdb-Metadata.md
// https://github.com/dotnet/roslyn/blob/main/src/Compilers/Core/Portable/Emit/EditAndContinueMethodDebugInformation.cs
const hoistedScopes = (reader: PortablePdbBlobReader): PortablePdbCustomData => {
  const result = { type: "hoistedScopes" as const, scopes: 0, inactiveScopes: 0, totalIlBytes: 0 };
  while (reader.remaining) {
    const start = reader.uint32();
    const length = reader.uint32();
    if (!start && !length) result.inactiveScopes++;
    else if (!length || start + length >= 0x80000000) throw new Error("hoisted scope IL range is invalid");
    result.scopes++;
    result.totalIlBytes += length;
  }
  return result;
};

const dynamicFlags = (reader: PortablePdbBlobReader): PortablePdbCustomData => {
  const storedBits = reader.remaining * 8;
  let setBits = 0;
  while (reader.remaining) {
    for (let bits = reader.byte(); bits; bits &= bits - 1) setBits++;
  }
  return { type: "dynamicFlags", storedBits, setBits };
};

const encSlots = (reader: PortablePdbBlobReader): PortablePdbCustomData => {
  const result = { type: "encSlots" as const, slots: 0, temporaries: 0, ordinalSlots: 0 };
  while (reader.remaining) {
    const flags = reader.byte();
    if (flags === 255) { reader.compressed(); continue; } // Syntax-offset baseline marker.
    result.slots++;
    if (flags === 0) { result.temporaries++; continue; }
    reader.compressed(); // Syntax offset relative to the current baseline.
    if (flags & 128) { reader.compressed(); result.ordinalSlots++; }
  }
  return result;
};

const encLambdas = (reader: PortablePdbBlobReader): PortablePdbCustomData => {
  if (!reader.remaining) return { type: "encLambdas", closures: 0, lambdas: 0 };
  reader.compressed(); // Method ordinal + 1.
  reader.compressed(); // Negated syntax offset baseline.
  const closures = reader.count();
  for (let index = 0; index < closures; index++) reader.compressed();
  let lambdas = 0;
  while (reader.remaining) {
    reader.compressed();
    // Roslyn LambdaDebugInfo.MinClosureOrdinal is -2 (this-only), -1 is static.
    // https://github.com/dotnet/roslyn/blob/main/src/Compilers/Core/Portable/CodeGen/LambdaDebugInfo.cs
    if (reader.compressed() >= closures + 2) throw new Error("lambda closure ordinal is out of range");
    lambdas++;
  }
  return { type: "encLambdas", closures, lambdas };
};

const encStates = (reader: PortablePdbBlobReader): PortablePdbCustomData => {
  if (!reader.remaining) return { type: "encStates", states: 0 };
  const states = reader.count();
  if (!states) return { type: "encStates", states };
  const baseline = -reader.compressed();
  let previousOffset = -Infinity;
  let ordinal = 0;
  for (let index = 0; index < states; index++) {
    reader.signed(); // State number; syntax offsets determine relative await ordinals.
    const offset = baseline + reader.compressed();
    if (offset < previousOffset) throw new Error("state syntax offsets are not ordered");
    ordinal = offset === previousOffset ? ordinal + 1 : 0;
    if (ordinal > 255) throw new Error("relative await ordinal exceeds one byte");
    previousOffset = offset;
  }
  return { type: "encStates", states };
};

const requireRow = (row: number, table: number, name: string, counts: ReadonlyMap<number, number>): void => {
  if (!row || row > (counts.get(table) ?? 0)) throw new Error(`${name} row is out of range`);
};

const asyncStepping = (
  reader: PortablePdbBlobReader, counts: ReadonlyMap<number, number>
): PortablePdbCustomData => {
  // Roslyn MetadataWriter.PortablePdb.cs: catch offset + 1; yield/resume offsets and MethodDef row.
  // https://github.com/dotnet/roslyn/blob/main/src/Compilers/Core/Portable/PEWriter/MetadataWriter.PortablePdb.cs
  const catchOffset = reader.uint32();
  if (catchOffset > 0x80000000) throw new Error("async catch-handler offset is out of range");
  let awaits = 0;
  while (reader.remaining) {
    const yieldOffset = reader.uint32();
    const resumeOffset = reader.uint32();
    if (yieldOffset >= 0x80000000 || resumeOffset >= 0x80000000) {
      throw new Error("async yield/resume offset is out of range");
    }
    requireRow(reader.compressed(), 0x06, "MethodDef", counts);
    awaits++;
  }
  return { type: "asyncStepping", hasCatchHandler: catchOffset !== 0, awaits };
};

const typeDocuments = (
  reader: PortablePdbBlobReader, counts: ReadonlyMap<number, number>
): PortablePdbCustomData => {
  const documents: number[] = [];
  while (reader.remaining) {
    const row = reader.compressed();
    requireRow(row, 0x30, "Document", counts);
    documents.push(row);
  }
  return { type: "typeDocuments", documents };
};

const DECODERS: Readonly<Record<string, (
  reader: PortablePdbBlobReader, counts: ReadonlyMap<number, number>
) => PortablePdbCustomData>> = {
  hoistedScopes, dynamicFlags, encSlots, encLambdas, encStates, asyncStepping, typeDocuments,
  primaryConstructor: () => ({ type: "primaryConstructor" })
};

export const decodeCustomState = (
  type: string, bytes: Uint8Array, counts: ReadonlyMap<number, number>
): PortablePdbCustomData => {
  if (!Object.hasOwn(DECODERS, type)) throw new Error(`unsupported custom state record ${type}`);
  const reader = new PortablePdbBlobReader(bytes);
  const result = DECODERS[type]!(reader, counts);
  reader.finish();
  return result;
};
