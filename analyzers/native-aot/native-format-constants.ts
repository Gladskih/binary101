import type { NativeFormatHandle } from "./native-format-reader.js";
import type { NativeFormatStore } from "./native-format-store.js";
import type { NativeFormatSignatures } from "./native-format-signatures.js";
import { readNativeFormatConstantNode, type NativeAotConstant,
  type NativeFormatConstantNode } from "./native-format-constant-nodes.js";

interface PendingConstant { handle: NativeFormatHandle; node?: NativeFormatConstantNode }
const keyOf = (handle: NativeFormatHandle): string => `${handle.type}:${handle.offset}`;

export class NativeFormatConstants {
  readonly #values = new Map<string, NativeAotConstant>();
  constructor(readonly store: NativeFormatStore, readonly signatures: NativeFormatSignatures) {}

  value(handle: NativeFormatHandle): NativeAotConstant {
    const pending: PendingConstant[] = [{ handle }];
    const active = new Set<string>();
    while (pending.length) this.#pending(pending, active);
    return this.#values.get(keyOf(handle))!;
  }

  #pending(pending: PendingConstant[], active: Set<string>): void {
    const entry = pending.at(-1)!;
    const key = keyOf(entry.handle);
    if (this.#values.has(key)) { pending.pop(); return; }
    try {
      if (!entry.handle.offset) {
        this.#values.set(key, { type: entry.handle.type === 0x1a ? "string" : "object", value: null });
      } else if (!entry.node) {
        entry.node = readNativeFormatConstantNode(this.store, this.signatures, entry.handle);
        active.add(key);
        this.#schedule(entry.node, pending, active);
        return;
      } else {
        this.#values.set(key, entry.node.format(entry.node.dependencies.map(handle =>
          this.#values.get(keyOf(handle))!)));
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : "Constant decoding failed.";
      this.store.warnings.add(`NativeFormat constant at 0x${entry.handle.offset.toString(16)}: ${message}`);
      this.#values.set(key, { type: "<invalid>", value: message });
    }
    active.delete(key);
    pending.pop();
  }

  #schedule(node: NativeFormatConstantNode, pending: PendingConstant[], active: Set<string>): void {
    if (node.dependencies.some(handle => active.has(keyOf(handle)))) {
      throw new Error("NativeFormat constant graph contains a cycle.");
    }
    for (let index = node.dependencies.length - 1; index >= 0; index--) {
      const handle = node.dependencies[index]!;
      if (!this.#values.has(keyOf(handle))) pending.push({ handle });
    }
  }
}
