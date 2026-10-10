import {
  NATIVE_AOT_METADATA_SIGNATURE, type NativeAotReflectionMetadata,
  type NativeAotReflectionScope, type NativeAotReflectionType
} from "./format.js";
import { NativeFormatReader, type NativeFormatHandle, type NativeFormatLayout } from "./native-format-reader.js";
import { NativeFormatStore, type NativeFormatRecord } from "./native-format-store.js";
import { NativeFormatMembers } from "./native-format-members.js";

interface TraversalEntry {
  kind: "namespace" | "type";
  handle: NativeFormatHandle;
  namespaceName: string;
  enclosingName: string;
}

interface ParseState {
  store: NativeFormatStore;
  members: NativeFormatMembers;
  visited: Record<"scope" | "namespace" | "type", Set<number>>;
}

const handles = (record: NativeFormatRecord, name: string): NativeFormatHandle[] =>
  record.values[name] ? record.handles(name) : [];

const warning = (state: ParseState, kind: string, offset: number, error: unknown): void => {
  state.store.warnings.add(`Could not decode NativeFormat ${kind} at 0x${offset.toString(16)}: ` +
    `${error instanceof Error ? error.message : "unknown decoding error"}`);
};

const typeDefinition = (
  state: ParseState, record: NativeFormatRecord
): NonNullable<NativeAotReflectionType["definition"]> => ({
  flags: record.number("flags"), size: record.number("size"),
  packingSize: record.number("packingSize"),
  baseType: state.members.signatures.type(record.handle("baseType")),
  interfaces: handles(record, "interfaces").map(handle => state.members.signatures.type(handle)),
  genericParameters: state.members.generics(handles(record, "genericParameters")),
  properties: handles(record, "properties").map(handle => state.members.property(handle))
    .filter(property => property !== null),
  events: handles(record, "events").map(handle => state.members.event(handle))
    .filter(event => event !== null)
});

const readType = (
  state: ParseState, entry: TraversalEntry, output: NativeAotReflectionType[]
): TraversalEntry[] => {
  const record = state.store.record(entry.handle);
  const ownName = state.store.reader.string(record.handle("name"));
  const name = entry.enclosingName ? `${entry.enclosingName}+${ownName}` : ownName;
  const type: NativeAotReflectionType = {
    namespace: entry.namespaceName, name,
    methods: handles(record, "methods").map(handle => state.members.method(handle))
      .filter(method => method !== null),
    fields: handles(record, "fields").map(handle => state.members.field(handle))
      .filter(field => field !== null)
  };
  output.push(type);
  if (record.values["attributes"]) type.attributes = state.members.attributes.of(record);
  try { type.definition = typeDefinition(state, record); }
  catch (error) { warning(state, "type definition", entry.handle.offset, error); }
  return handles(record, "nestedTypes").map(handle => ({
    kind: "type", handle, namespaceName: entry.namespaceName, enclosingName: name
  }));
};

const readNamespace = (state: ParseState, entry: TraversalEntry): TraversalEntry[] => {
  const record = state.store.record(entry.handle);
  const ownName = state.store.reader.string(record.handle("name"));
  const name = ownName && entry.namespaceName
    ? `${entry.namespaceName}.${ownName}` : ownName || entry.namespaceName;
  return [
    ...handles(record, "types").map((handle): TraversalEntry => ({
      kind: "type", handle, namespaceName: name, enclosingName: ""
    })),
    ...handles(record, "children").map((handle): TraversalEntry => ({
      kind: "namespace", handle, namespaceName: name, enclosingName: ""
    }))
  ];
};

const walkGraph = (
  state: ParseState, root: NativeFormatHandle, output: NativeAotReflectionType[]
): void => {
  const pending: (TraversalEntry | { leave: string })[] = [{
    kind: "namespace", handle: root, namespaceName: "", enclosingName: ""
  }];
  const active = new Set<string>();
  while (pending.length) {
    const entry = pending.pop()!;
    if ("leave" in entry) { active.delete(entry.leave); continue; }
    const key = `${entry.kind}:${entry.handle.offset}`;
    if (active.has(key)) {
      warning(state, entry.kind, entry.handle.offset, new Error("Metadata graph contains a cycle."));
      continue;
    }
    if (state.visited[entry.kind].has(entry.handle.offset)) continue;
    state.visited[entry.kind].add(entry.handle.offset);
    active.add(key);
    pending.push({ leave: key });
    try {
      const children = entry.kind === "type"
        ? readType(state, entry, output) : readNamespace(state, entry);
      for (let index = children.length - 1; index >= 0; index -= 1) pending.push(children[index]!);
    } catch (error) { warning(state, entry.kind, entry.handle.offset, error); }
  }
};

const scopeVersion = (record: NativeFormatRecord): NativeAotReflectionScope["version"] => {
  const version = { major: record.number("major"), minor: record.number("minor"),
    build: record.number("build"), revision: record.number("revision") };
  if (Object.values(version).some(value => value > 0xffff)) {
    throw new Error("Version component exceeds UInt16.");
  }
  return version;
};

const parseScope = (state: ParseState, handle: NativeFormatHandle): NativeAotReflectionScope | null => {
  if (state.visited.scope.has(handle.offset)) return null;
  state.visited.scope.add(handle.offset);
  try {
    const record = state.store.record(handle);
    const types: NativeAotReflectionType[] = [];
    const scope = { name: state.store.reader.string(record.handle("name")),
      moduleName: state.store.reader.string(record.handle("moduleName")),
      version: scopeVersion(record), types,
      attributes: state.members.attributes.of(record),
      moduleAttributes: state.members.attributes.of(record, "moduleAttributes") };
    const root = record.handle("rootNamespace");
    if (root.offset) walkGraph(state, root, types);
    return scope;
  } catch (error) { warning(state, "scope", handle.offset, error); return null; }
};

export const parseNativeAotReflectionMetadata = (
  bytes: Uint8Array, layout: NativeFormatLayout = "dotnet10"
): NativeAotReflectionMetadata => {
  const reader = new NativeFormatReader(bytes, layout);
  if (reader.size < 4 || reader.uint32(0) !== NATIVE_AOT_METADATA_SIGNATURE) {
    return { scopes: [], warnings: ["NativeFormat metadata signature is missing or truncated."] };
  }
  try {
    // MetadataReader root contains a typed ScopeDefinition collection after its signature.
    // https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/tools/Common/Internal/Metadata/NativeFormat/NativeMetadataReader.cs
    const decoded = reader.handles(4, [0x38]);
    const store = new NativeFormatStore(reader, new Set<string>());
    const state: ParseState = { store, members: new NativeFormatMembers(store),
      visited: { scope: new Set(), namespace: new Set(), type: new Set() } };
    const scopes = decoded.value.map(handle => parseScope(state, handle))
      .filter(scope => scope !== null);
    return store.warnings.size ? { scopes, warnings: [...store.warnings] } : { scopes };
  } catch (error) {
    return { scopes: [], warnings: ["Could not decode NativeFormat root: " +
      `${error instanceof Error ? error.message : "unknown decoding error"}`] };
  }
};
