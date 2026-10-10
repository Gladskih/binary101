import type { NativeFormatHandle } from "./native-format-reader.js";
import type { NativeFormatRecord, NativeFormatStore } from "./native-format-store.js";
import type { NativeFormatSignatures } from "./native-format-signatures.js";
import type { NativeAotConstant } from "./native-format-constant-nodes.js";
import { NativeFormatConstants } from "./native-format-constants.js";

export interface NativeAotAttribute {
  type: string;
  constructorName: string;
  fixedArguments: NativeAotConstant[];
  namedArguments: { kind: "field" | "property"; name: string; type: string; value: NativeAotConstant }[];
}

export class NativeFormatAttributes {
  readonly constants: NativeFormatConstants;
  readonly #attributes = new Map<string, NativeAotAttribute | null>();
  constructor(readonly store: NativeFormatStore, readonly signatures: NativeFormatSignatures) {
    this.constants = new NativeFormatConstants(store, signatures);
  }

  #readConstructor(handle: NativeFormatHandle): { type: string; name: string } {
    const record = this.store.record(handle);
    if (handle.type === 0x36) return {
      type: this.signatures.type(record.handle("enclosingType")),
      name: this.store.reader.string(this.store.record(record.handle("method")).handle("name"))
    };
    if (handle.type !== 0x27) throw new Error("Attribute constructor is not a qualified method or member reference.");
    return { type: this.signatures.type(record.handle("parent")), name: this.store.reader.string(record.handle("name")) };
  }

  #named(handle: NativeFormatHandle): NativeAotAttribute["namedArguments"][number] {
    const record = this.store.record(handle);
    // NamedArgumentMemberKind is Property=0, Field=1, encoded with DecodeUnsigned.
    // https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/tools/Common/Internal/Metadata/NativeFormat/NativeFormatReaderCommonGen.cs
    const flags = record.number("flags");
    if (flags > 1) throw new Error("Invalid NativeFormat named-argument member kind.");
    return { kind: flags === 1 ? "field" : "property", name: this.store.reader.string(record.handle("name")),
      type: this.signatures.type(record.handle("type")), value: this.constants.value(record.handle("value")) };
  }

  read(handle: NativeFormatHandle): NativeAotAttribute | null {
    const key = `${handle.type}:${handle.offset}`;
    if (this.#attributes.has(key)) return this.#attributes.get(key)!;
    let attribute: NativeAotAttribute | null = null;
    try {
      if (handle.type !== 0x21 || !handle.offset) throw new Error("Invalid NativeFormat custom-attribute handle.");
      const record = this.store.record(handle);
      const constructor = this.#readConstructor(record.handle("constructor"));
      attribute = { type: constructor.type, constructorName: constructor.name,
        fixedArguments: (record.values["fixedArguments"] ? record.handles("fixedArguments") : [])
          .map(value => this.constants.value(value)), namedArguments: [] };
      for (const argument of record.values["namedArguments"] ? record.handles("namedArguments") : []) {
        try { attribute.namedArguments.push(this.#named(argument)); }
        catch (error) { this.#warning(argument, error); }
      }
    } catch (error) { this.#warning(handle, error); }
    this.#attributes.set(key, attribute);
    return attribute;
  }

  #warning(handle: NativeFormatHandle, error: unknown): void {
    this.store.warnings.add(`NativeFormat attribute at 0x${handle.offset.toString(16)}: ` +
      `${error instanceof Error ? error.message : "Attribute decoding failed."}`);
  }

  of(record: NativeFormatRecord, field = "attributes"): NativeAotAttribute[] {
    return (record.values[field] ? record.handles(field) : [])
      .map(handle => this.read(handle)).filter(value => value !== null);
  }
}
