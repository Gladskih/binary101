import type { NativeFormatHandle } from "./native-format-reader.js";
import type { NativeFormatStore } from "./native-format-store.js";
import { readNativeFormatTypeNode, type NativeFormatTypeNode } from "./native-format-type-nodes.js";

export interface NativeAotMethodSignature {
  callingConvention: number;
  genericParameterCount: number;
  returnType: string;
  parameters: string[];
  varArgParameters: string[];
}

interface PendingType {
  handle: NativeFormatHandle;
  node?: NativeFormatTypeNode;
}

const handleKey = (handle: NativeFormatHandle): string => `${handle.type}:${handle.offset}`;

export class NativeFormatSignatures {
  readonly #names = new Map<string, string>();
  readonly #methods = new Map<number, NativeAotMethodSignature>();

  constructor(readonly store: NativeFormatStore) {}

  type(handle: NativeFormatHandle): string {
    if (!handle.offset) return "";
    const pending: PendingType[] = [{ handle }];
    const active = new Set<string>();
    while (pending.length) this.#readPending(pending, active);
    return this.#names.get(handleKey(handle))!;
  }

  #readPending(pending: PendingType[], active: Set<string>): void {
    const entry = pending.at(-1)!;
    const key = handleKey(entry.handle);
    if (this.#names.has(key)) { pending.pop(); return; }
    try {
      if (!entry.node) {
        entry.node = readNativeFormatTypeNode(this.store, entry.handle);
        active.add(key);
        this.#schedule(entry.node, pending, active);
        return;
      }
      this.#names.set(key, entry.node.format(entry.node.dependencies.map(handle =>
        handle.offset ? this.#names.get(handleKey(handle))! : "")));
    } catch (error) {
      this.store.warnings.add(`NativeFormat signature at 0x${entry.handle.offset.toString(16)}: ` +
        `${error instanceof Error ? error.message : "decoding failed"}`);
      this.#names.set(key, `<invalid type at 0x${entry.handle.offset.toString(16)}>`);
    }
    active.delete(key);
    pending.pop();
  }

  #schedule(node: NativeFormatTypeNode, pending: PendingType[], active: Set<string>): void {
    if (node.dependencies.some(handle => handle.offset && active.has(handleKey(handle)))) {
      throw new Error("Type-signature graph contains a cycle.");
    }
    for (let index = node.dependencies.length - 1; index >= 0; index -= 1) {
      const handle = node.dependencies[index]!;
      if (!handle.offset || this.#names.has(handleKey(handle))) continue;
      pending.push({ handle });
    }
  }

  method(handle: NativeFormatHandle): NativeAotMethodSignature | undefined {
    if (!handle.offset) return undefined;
    const cached = this.#methods.get(handle.offset);
    if (cached) return cached;
    const record = this.store.record(handle);
    const signature = {
      callingConvention: record.number("callingConvention"),
      genericParameterCount: record.number("genericParameterCount"),
      returnType: this.type(record.handle("returnType")),
      parameters: record.handles("parameters").map(handle => this.type(handle)),
      varArgParameters: record.handles("varArgParameters").map(handle => this.type(handle))
    };
    this.#methods.set(handle.offset, signature);
    return signature;
  }
}
