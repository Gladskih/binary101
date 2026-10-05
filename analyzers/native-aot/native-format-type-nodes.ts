import { NativeFormatError, type NativeFormatHandle } from "./native-format-reader.js";
import type { NativeFormatRecord, NativeFormatStore } from "./native-format-store.js";

export interface NativeFormatTypeNode {
  dependencies: NativeFormatHandle[];
  format: (names: string[]) => string;
}

const unaryNode = (record: NativeFormatRecord, field: string, suffix: string): NativeFormatTypeNode =>
  ({ dependencies: [record.handle(field)], format: names => `${names[0]}${suffix}` });

const namedNode = (
  store: NativeFormatStore, record: NativeFormatRecord, parent: NativeFormatHandle, separator: string
): NativeFormatTypeNode => {
  const name = store.reader.string(record.handle("name"));
  return { dependencies: parent.offset ? [parent] : [],
    format: names => names[0] ? `${names[0]}${separator}${name}` : name };
};

const definitionNode = (store: NativeFormatStore, record: NativeFormatRecord): NativeFormatTypeNode => {
  const enclosing = record.handle("enclosingType");
  return namedNode(store, record, enclosing.offset ? enclosing : record.handle("namespace"),
    enclosing.offset ? "+" : ".");
};

const referenceNode = (store: NativeFormatStore, record: NativeFormatRecord): NativeFormatTypeNode => {
  const parent = record.handle("parent");
  return namedNode(store, record, parent, parent.type === 0x3d ? "+" : ".");
};

const arrayNode = (record: NativeFormatRecord): NativeFormatTypeNode => {
  const rank = record.number("rank");
  const sizes = record.numbers("sizes");
  const bounds = record.numbers("lowerBounds");
  if (!rank || sizes.length > rank || bounds.length > rank) {
    throw new NativeFormatError("Array rank does not match its dimensions.");
  }
  // Describe dimensions directly: a hostile rank must not allocate rank-sized output.
  return unaryNode(record, "element", `[rank=${rank}; sizes=${sizes.join(",")}; ` +
    `lowerBounds=${bounds.join(",")}]`);
};

const instantiatedNode = (record: NativeFormatRecord): NativeFormatTypeNode => ({
  dependencies: [record.handle("genericType"), ...record.handles("arguments")],
  format: names => `${names[0]}<${names.slice(1).join(", ")}>`
});

const modifiedNode = (record: NativeFormatRecord): NativeFormatTypeNode => ({
  dependencies: [record.handle("type"), record.handle("modifier")],
  format: names => `${names[0]} mod${record.number("isOptional") ? "opt" : "req"}(${names[1]})`
});

const methodNode = (record: NativeFormatRecord): NativeFormatTypeNode => {
  const parameters = record.handles("parameters");
  const varargs = record.handles("varArgParameters");
  return { dependencies: [record.handle("returnType"), ...parameters, ...varargs],
    format: names => `fnptr[0x${record.number("callingConvention").toString(16)}; ` +
      `arity=${record.number("genericParameterCount")}] ${names[0]}(` +
      `${names.slice(1, parameters.length + 1).join(", ")}` +
      `${varargs.length ? `${parameters.length ? ", " : ""}..., ` +
        names.slice(parameters.length + 1).join(", ") : ""})` };
};

const typeNodes: Readonly<Record<number,
  (store: NativeFormatStore, record: NativeFormatRecord) => NativeFormatTypeNode>> = {
  0x01: (_store, record) => arrayNode(record),
  0x02: (_store, record) => unaryNode(record, "type", "&"),
  0x24: (_store, record) => unaryNode(record, "type", ""),
  0x25: (_store, record) => unaryNode(record, "signature", ""),
  0x2b: (_store, record) => methodNode(record),
  0x2c: (_store, record) => ({ dependencies: [], format: () => `!!${record.number("number")}` }),
  0x2d: (_store, record) => modifiedNode(record),
  0x2f: (store, record) => namedNode(store, record, record.handle("parent"), "."),
  0x30: (store, record) => namedNode(store, record, record.handle("parent"), "."),
  0x32: (_store, record) => unaryNode(record, "type", "*"),
  0x37: (_store, record) => unaryNode(record, "element", "[]"),
  0x38: () => ({ dependencies: [], format: () => "" }),
  0x39: () => ({ dependencies: [], format: () => "" }),
  0x3a: definitionNode,
  0x3c: (_store, record) => instantiatedNode(record),
  0x3d: referenceNode,
  0x3e: (_store, record) => unaryNode(record, "signature", ""),
  0x3f: (_store, record) => ({ dependencies: [], format: () => `!${record.number("number")}` })
};

export const readNativeFormatTypeNode = (
  store: NativeFormatStore, handle: NativeFormatHandle
): NativeFormatTypeNode => {
  const factory = typeNodes[handle.type];
  if (!factory) throw new NativeFormatError(`Unexpected type-signature handle ${handle.type}.`);
  return factory(store, store.record(handle));
};
