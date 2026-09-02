"use strict";

import {
  NATIVE_AOT_METADATA_SIGNATURE,
  type PeNativeAotReflectionMetadata,
  type PeNativeAotReflectionScope,
  type PeNativeAotReflectionType
} from "./format.js";
import {
  NativeFormatReader,
  type NativeFormatHandle
} from "./native-format-reader.js";
import {
  NATIVE_FORMAT_SCOPE_HANDLE,
  parseNativeFormatMethodName,
  parseNativeFormatNamespaceRecord,
  parseNativeFormatScopeRecord,
  parseNativeFormatTypeRecord
} from "./native-format-records.js";

// These are defensive browser-work limits, not NativeFormat format limits.
export const MAX_NATIVE_AOT_REFLECTION_METADATA_BYTES = 0x0200_0000;
// Defensive browser-work cap; NativeFormat itself has no smaller scope-count limit.
const MAX_SCOPES = 4096;

export interface NativeAotReflectionTraversalLimits {
  namespaces: number;
  types: number;
  methods: number;
  namespaceDepth: number;
}

const DEFAULT_TRAVERSAL_LIMITS: NativeAotReflectionTraversalLimits = {
  namespaces: 8192,
  types: 20_000,
  methods: 100_000,
  namespaceDepth: 128
};

interface ParseState {
  reader: NativeFormatReader;
  warnings: string[];
  visitedNamespaces: Set<number>;
  visitedTypes: Set<number>;
  methodCount: number;
  limits: NativeAotReflectionTraversalLimits;
}

const addWarning = (state: ParseState, message: string): void => {
  if (!state.warnings.includes(message)) state.warnings.push(message);
};

const parseMethods = (state: ParseState, handles: NativeFormatHandle[]): string[] => {
  const names: string[] = [];
  for (const handle of handles) {
    if (state.methodCount >= state.limits.methods) {
      addWarning(state, `Method count exceeds the safety limit of ${state.limits.methods}.`);
      break;
    }
    try {
      names.push(parseNativeFormatMethodName(state.reader, handle));
      state.methodCount += 1;
    } catch (error) {
      addWarning(state, recordWarning("method", handle.offset, error));
    }
  }
  return names;
};

const walkType = (
  state: ParseState,
  handle: NativeFormatHandle,
  namespaceName: string,
  enclosingName: string,
  output: PeNativeAotReflectionType[]
): void => {
  if (state.visitedTypes.has(handle.offset)) return;
  if (state.visitedTypes.size >= state.limits.types) {
    addWarning(state, `Type count exceeds the safety limit of ${state.limits.types}.`);
    return;
  }
  state.visitedTypes.add(handle.offset);
  try {
    const record = parseNativeFormatTypeRecord(state.reader, handle);
    const ownName = state.reader.string(record.name);
    const name = enclosingName ? `${enclosingName}+${ownName}` : ownName;
    output.push({ namespace: namespaceName, name, methods: parseMethods(state, record.methods) });
    record.nestedTypes.forEach(nested => walkType(state, nested, namespaceName, name, output));
  } catch (error) {
    addWarning(state, recordWarning("type", handle.offset, error));
  }
};

const walkNamespace = (
  state: ParseState,
  handle: NativeFormatHandle,
  parentName: string,
  depth: number,
  output: PeNativeAotReflectionType[]
): void => {
  if (state.visitedNamespaces.has(handle.offset)) return;
  if (depth > state.limits.namespaceDepth ||
    state.visitedNamespaces.size >= state.limits.namespaces) {
    addWarning(state, "Namespace traversal exceeded its safety limit.");
    return;
  }
  state.visitedNamespaces.add(handle.offset);
  try {
    const record = parseNativeFormatNamespaceRecord(state.reader, handle);
    const ownName = state.reader.string(record.name);
    const name = ownName && parentName ? `${parentName}.${ownName}` : ownName || parentName;
    record.types.forEach(type => walkType(state, type, name, "", output));
    record.children.forEach(child => walkNamespace(state, child, name, depth + 1, output));
  } catch (error) {
    addWarning(state, recordWarning("namespace", handle.offset, error));
  }
};

const recordWarning = (kind: string, offset: number, error: unknown): string =>
  `Could not decode NativeFormat ${kind} at 0x${offset.toString(16)}: ${errorMessage(error)}`;

const errorMessage = (error: unknown): string =>
  error instanceof Error ? error.message : "unknown decoding error";

const parseScope = (
  state: ParseState,
  handle: NativeFormatHandle
): PeNativeAotReflectionScope | null => {
  try {
    const record = parseNativeFormatScopeRecord(state.reader, handle);
    const types: PeNativeAotReflectionType[] = [];
    if (record.rootNamespace.offset) {
      walkNamespace(state, record.rootNamespace, "", 0, types);
    }
    return {
      name: state.reader.string(record.name),
      moduleName: state.reader.string(record.moduleName),
      version: record.version,
      types
    };
  } catch (error) {
    addWarning(state, recordWarning("scope", handle.offset, error));
    return null;
  }
};

export const parseNativeAotReflectionMetadata = (
  bytes: Uint8Array,
  limits: NativeAotReflectionTraversalLimits = DEFAULT_TRAVERSAL_LIMITS
): PeNativeAotReflectionMetadata => {
  const warnings: string[] = [];
  if (bytes.byteLength > MAX_NATIVE_AOT_REFLECTION_METADATA_BYTES) {
    return { scopes: [], warnings: ["NativeFormat metadata exceeds its 32 MiB handle range."] };
  }
  const reader = new NativeFormatReader(bytes);
  if (reader.size < 4 || reader.uint32(0) !== NATIVE_AOT_METADATA_SIGNATURE) {
    return { scopes: [], warnings: ["NativeFormat metadata signature is missing or truncated."] };
  }
  try {
    const decoded = reader.handles(4, [NATIVE_FORMAT_SCOPE_HANDLE], MAX_SCOPES);
    const state: ParseState = {
      reader,
      warnings,
      visitedNamespaces: new Set<number>(),
      visitedTypes: new Set<number>(),
      methodCount: 0,
      limits
    };
    const scopes = decoded.value.map(handle => parseScope(state, handle))
      .filter((scope): scope is PeNativeAotReflectionScope => scope != null);
    return warnings.length ? { scopes, warnings } : { scopes };
  } catch (error) {
    return { scopes: [], warnings: [`Could not decode NativeFormat root: ${errorMessage(error)}`] };
  }
};
