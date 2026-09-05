"use strict";

import {
  NATIVE_AOT_METADATA_SIGNATURE,
  type NativeAotReflectionMetadata,
  type NativeAotReflectionScope,
  type NativeAotReflectionType
} from "./format.js";
import { NativeFormatReader, type NativeFormatHandle } from "./native-format-reader.js";
import {
  NATIVE_FORMAT_SCOPE_HANDLE,
  parseNativeFormatFieldName,
  parseNativeFormatMethodName,
  parseNativeFormatNamespaceRecord,
  parseNativeFormatScopeRecord,
  parseNativeFormatTypeRecord
} from "./native-format-records.js";

// Existing supported blob extent; independent of the number of records in the graph.
export const MAX_NATIVE_AOT_REFLECTION_METADATA_BYTES = 0x0200_0000;

type MemberKind = "method" | "field";

interface TraversalEntry {
  kind: "namespace" | "type";
  handle: NativeFormatHandle;
  namespaceName: string;
  enclosingName: string;
}

interface ParseState {
  reader: NativeFormatReader;
  warnings: Set<string>;
  visited: Record<"scope" | "namespace" | "type", Set<number>>;
  memberNames: Record<MemberKind, Map<number, string | null>>;
}

const recordWarning = (kind: string, offset: number, error: unknown): string =>
  `Could not decode NativeFormat ${kind} at 0x${offset.toString(16)}: ${errorMessage(error)}`;

const errorMessage = (error: unknown): string =>
  error instanceof Error ? error.message : "unknown decoding error";

const parseMemberName = (
  state: ParseState, handle: NativeFormatHandle, kind: MemberKind
): string | null => {
  const cache = state.memberNames[kind];
  const cached = cache.get(handle.offset);
  if (cached !== undefined) return cached;
  try {
    const name = kind === "method"
      ? parseNativeFormatMethodName(state.reader, handle)
      : parseNativeFormatFieldName(state.reader, handle);
    cache.set(handle.offset, name);
    return name;
  } catch (error) {
    cache.set(handle.offset, null);
    state.warnings.add(recordWarning(kind, handle.offset, error));
    return null;
  }
};

const readFieldList = (state: ParseState, offset: number, count: number): string[] => {
  const names: string[] = [];
  let nextOffset = offset;
  for (let index = 0; index < count; index += 1) {
    // HandleType.Field = 0x23; typed collections store offsets, not polymorphic tokens.
    // https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/tools/Common/Internal/Metadata/NativeFormat/NativeFormatReaderCommonGen.cs
    const handle = state.reader.handle(nextOffset, [0x23]);
    nextOffset = handle.nextOffset;
    if (!handle.value.offset) continue;
    const name = parseMemberName(state, handle.value, "field");
    if (name !== null) names.push(name);
  }
  return names;
};

const parseFields = (state: ParseState, offset: number): string[] => {
  try {
    const count = state.reader.collectionCount(offset);
    return readFieldList(state, count.nextOffset, count.value);
  } catch (error) {
    state.warnings.add(recordWarning("field list", offset, error));
    return [];
  }
};

const readType = (
  state: ParseState, entry: TraversalEntry, output: NativeAotReflectionType[]
): TraversalEntry[] => {
  const record = parseNativeFormatTypeRecord(state.reader, entry.handle);
  const ownName = state.reader.string(record.name);
  const name = entry.enclosingName ? `${entry.enclosingName}+${ownName}` : ownName;
  output.push({
    namespace: entry.namespaceName, name,
    methods: record.methods.map(handle => parseMemberName(state, handle, "method"))
      .filter((method): method is string => method !== null),
    fields: parseFields(state, record.fieldsOffset)
  });
  return record.nestedTypes.map(handle => ({
    kind: "type", handle, namespaceName: entry.namespaceName, enclosingName: name
  }));
};

const readNamespace = (state: ParseState, entry: TraversalEntry): TraversalEntry[] => {
  const record = parseNativeFormatNamespaceRecord(state.reader, entry.handle);
  const ownName = state.reader.string(record.name);
  const name = ownName && entry.namespaceName
    ? `${entry.namespaceName}.${ownName}` : ownName || entry.namespaceName;
  return [
    ...record.types.map((handle): TraversalEntry => ({
      kind: "type", handle, namespaceName: name, enclosingName: ""
    })),
    ...record.children.map((handle): TraversalEntry => ({
      kind: "namespace", handle, namespaceName: name, enclosingName: ""
    }))
  ];
};

const walkGraph = (
  state: ParseState, rootNamespace: NativeFormatHandle, output: NativeAotReflectionType[]
): void => {
  const pending: TraversalEntry[] = [{
    kind: "namespace", handle: rootNamespace, namespaceName: "", enclosingName: ""
  }];
  while (pending.length) {
    const entry = pending.pop()!;
    if (state.visited[entry.kind].has(entry.handle.offset)) continue;
    state.visited[entry.kind].add(entry.handle.offset);
    try {
      const children = entry.kind === "type"
        ? readType(state, entry, output) : readNamespace(state, entry);
      // Reverse push preserves the existing depth-first metadata order without recursive calls.
      for (let index = children.length - 1; index >= 0; index -= 1) pending.push(children[index]!);
    } catch (error) {
      state.warnings.add(recordWarning(entry.kind, entry.handle.offset, error));
    }
  }
};

const parseScope = (
  state: ParseState, handle: NativeFormatHandle
): NativeAotReflectionScope | null => {
  if (state.visited.scope.has(handle.offset)) return null;
  state.visited.scope.add(handle.offset);
  try {
    const record = parseNativeFormatScopeRecord(state.reader, handle);
    const types: NativeAotReflectionType[] = [];
    if (record.rootNamespace.offset) walkGraph(state, record.rootNamespace, types);
    return {
      name: state.reader.string(record.name),
      moduleName: state.reader.string(record.moduleName),
      version: record.version,
      types
    };
  } catch (error) {
    state.warnings.add(recordWarning("scope", handle.offset, error));
    return null;
  }
};

export const parseNativeAotReflectionMetadata = (bytes: Uint8Array): NativeAotReflectionMetadata => {
  if (bytes.byteLength > MAX_NATIVE_AOT_REFLECTION_METADATA_BYTES) {
    return { scopes: [], warnings: ["NativeFormat metadata exceeds its 32 MiB handle range."] };
  }
  const reader = new NativeFormatReader(bytes);
  if (reader.size < 4 || reader.uint32(0) !== NATIVE_AOT_METADATA_SIGNATURE) {
    return { scopes: [], warnings: ["NativeFormat metadata signature is missing or truncated."] };
  }
  try {
    const decoded = reader.handles(4, [NATIVE_FORMAT_SCOPE_HANDLE]);
    const state: ParseState = {
      reader,
      warnings: new Set<string>(),
      visited: { scope: new Set<number>(), namespace: new Set<number>(), type: new Set<number>() },
      memberNames: { method: new Map<number, string | null>(), field: new Map<number, string | null>() }
    };
    const scopes = decoded.value.map(handle => parseScope(state, handle))
      .filter((scope): scope is NativeAotReflectionScope => scope != null);
    return state.warnings.size ? { scopes, warnings: [...state.warnings] } : { scopes };
  } catch (error) {
    return { scopes: [], warnings: [`Could not decode NativeFormat root: ${errorMessage(error)}`] };
  }
};
