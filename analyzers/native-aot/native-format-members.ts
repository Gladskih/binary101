import type {
  NativeAotGenericParameter, NativeAotParameter, NativeAotReflectionEvent,
  NativeAotReflectionField, NativeAotReflectionMethod, NativeAotReflectionProperty
} from "./format.js";
import type { NativeFormatHandle } from "./native-format-reader.js";
import { NativeFormatSignatures } from "./native-format-signatures.js";
import type { NativeFormatRecord, NativeFormatStore } from "./native-format-store.js";
import { NativeFormatAttributes } from "./native-format-attributes.js";

type ReflectedMember = NativeAotReflectionMethod | NativeAotReflectionField |
  NativeAotReflectionProperty | NativeAotReflectionEvent;

export class NativeFormatMembers {
  readonly signatures: NativeFormatSignatures;
  readonly attributes: NativeFormatAttributes;
  readonly #members = new Map<string, ReflectedMember | null>();

  constructor(readonly store: NativeFormatStore) {
    this.signatures = new NativeFormatSignatures(store);
    this.attributes = new NativeFormatAttributes(store, this.signatures);
  }

  #warning(kind: string, handle: NativeFormatHandle, error: unknown): void {
    this.store.warnings.add(`NativeFormat ${kind} at 0x${handle.offset.toString(16)}: ` +
      `${error instanceof Error ? error.message : "decoding failed"}`);
  }

  #member<TMember extends ReflectedMember>(
    handle: NativeFormatHandle, kind: string,
    decode: (record: NativeFormatRecord, member: TMember) => void
  ): TMember | null {
    if (!handle.offset) return null;
    const key = `${handle.type}:${handle.offset}`;
    if (this.#members.has(key)) return this.#members.get(key) as TMember | null;
    let member: TMember | null = null;
    const record = this.store.record(handle);
    try {
      member = { name: this.store.reader.string(record.handle("name")) } as TMember;
      member.flags = record.number("flags");
      decode(record, member);
      member.attributes = this.attributes.of(record);
    } catch (error) { if (!record.failure) this.#warning(kind, handle, error); }
    this.#members.set(key, member);
    return member;
  }

  method(handle: NativeFormatHandle): NativeAotReflectionMethod | null {
    return this.#member(handle, "method", (record, member: NativeAotReflectionMethod) => {
      member.implementationFlags = record.number("implementationFlags");
      const signature = this.signatures.method(record.handle("signature"));
      if (signature) member.signature = signature;
      member.parameters = this.parameters(record.handles("parameters"));
      member.genericParameters = this.generics(record.handles("genericParameters"));
    });
  }

  field(handle: NativeFormatHandle): NativeAotReflectionField | null {
    return this.#member(handle, "field", (record, member: NativeAotReflectionField) => {
      const signature = record.handle("signature");
      if (signature.offset) member.type = this.signatures.type(signature);
      member.offset = record.number("offset");
      const value = record.handle("defaultValue");
      if (value.offset) member.defaultValue = this.attributes.constants.value(value);
    });
  }

  property(handle: NativeFormatHandle): NativeAotReflectionProperty | null {
    return this.#member(handle, "property", (record, member: NativeAotReflectionProperty) => {
      const signature = record.handle("signature");
      if (signature.offset) {
        const shape = this.store.record(signature);
        member.callingConvention = shape.number("callingConvention");
        member.type = this.signatures.type(shape.handle("type"));
        member.parameters = shape.handles("parameters").map(handle => this.signatures.type(handle));
      }
      member.semantics = this.semantics(record.handles("semantics"));
      const value = record.handle("defaultValue");
      if (value.offset) member.defaultValue = this.attributes.constants.value(value);
    });
  }

  event(handle: NativeFormatHandle): NativeAotReflectionEvent | null {
    return this.#member(handle, "event", (record, member: NativeAotReflectionEvent) => {
      member.type = this.signatures.type(record.handle("type"));
      member.semantics = this.semantics(record.handles("semantics"));
    });
  }

  #records<TValue>(
    handles: NativeFormatHandle[], kind: string,
    decode: (record: NativeFormatRecord) => TValue
  ): TValue[] {
    const values: TValue[] = [];
    for (const handle of handles) {
      try { values.push(decode(this.store.record(handle))); }
      catch (error) { this.#warning(kind, handle, error); }
    }
    return values;
  }

  parameters(handles: NativeFormatHandle[]): NativeAotParameter[] {
    return this.#records(handles, "parameter", record => ({
      flags: record.number("flags"), sequence: record.number("sequence"),
      name: this.store.reader.string(record.handle("name")),
      attributes: this.attributes.of(record),
      ...(record.values["defaultValue"] && record.handle("defaultValue").offset
        ? { defaultValue: this.attributes.constants.value(record.handle("defaultValue")) } : {})
    }));
  }

  generics(handles: NativeFormatHandle[]): NativeAotGenericParameter[] {
    return this.#records(handles, "generic parameter", record => ({
      number: record.number("number"), flags: record.number("flags"), kind: record.number("kind"),
      name: this.store.reader.string(record.handle("name")),
      constraints: record.handles("constraints").map(handle => this.signatures.type(handle)),
      attributes: this.attributes.of(record)
    }));
  }

  semantics(handles: NativeFormatHandle[]): { attributes: number; method: string }[] {
    return this.#records(handles, "method semantics", record => ({
      attributes: record.number("attributes"),
      method: this.store.reader.string(this.store.record(record.handle("method")).handle("name"))
    }));
  }
}
