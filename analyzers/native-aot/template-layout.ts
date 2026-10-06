import type { NativeFormatCursor } from "./native-format-cursor.js";
import type { NativeAotFunctionReferences } from "./function-references.js";
import { NativeLayoutTypeReader } from "./layout-type.js";
import { readDictionaryMethods } from "./dictionary-methods.js";

export interface NativeAotTemplateLayout {
  classConstructorRva: number | null;
  dictionaryMethods: { signatureOffset: number; flags: number; methodToken: number;
    entrypointRva: number | null }[];
}

// BagElementKind: DictionaryLayout=0x40 (relative offset), ClassConstructorPointer=0x4e
// (NativeStatics index). Other bag elements hold data or offsets, never inferred code pointers.
// https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/tools/Common/Internal/NativeFormat/NativeFormat.cs
// https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/tools/aot/ILCompiler.Compiler/Compiler/DependencyAnalysis/NativeLayoutVertexNode.cs
export class NativeAotTemplateLayouts {
  readonly #types = new NativeLayoutTypeReader();
  readonly #bags = new Map<number, Promise<NativeAotTemplateLayout>>();
  readonly #dictionaries = new Map<number, Promise<NativeAotTemplateLayout["dictionaryMethods"]>>();
  constructor(readonly layout: NativeFormatCursor, readonly references: NativeAotFunctionReferences,
    readonly issues: Set<string>) {}

  read(offset: number): Promise<NativeAotTemplateLayout> {
    const cached = this.#bags.get(offset);
    if (cached) return cached;
    const result = this.#bag(this.layout.fork(offset));
    this.#bags.set(offset, result);
    return result;
  }

  async #bag(cursor: NativeFormatCursor): Promise<NativeAotTemplateLayout> {
    const result: NativeAotTemplateLayout = { classConstructorRva: null, dictionaryMethods: [] };
    const seen = new Set<number>();
    try {
      for (;;) {
        const kind = cursor.unsigned();
        if (!kind) break;
        if (seen.has(kind)) throw new Error("NativeLayout bag contains a duplicate element.");
        seen.add(kind);
        if (kind === 64) {
          const field = cursor.reader.signed(cursor.offset);
          const target = cursor.offset + field.value;
          cursor.offset = field.nextOffset;
          result.dictionaryMethods = await this.#dictionary(target);
        } else if (kind === 78) result.classConstructorRva = await this.references.statics.resolve(cursor.unsigned());
        else cursor.unsigned();
      }
    } catch (error) {
      this.issues.add(error instanceof Error ? error.message : "NativeLayout bag read failed.");
    }
    return result;
  }

  #dictionary(offset: number): Promise<NativeAotTemplateLayout["dictionaryMethods"]> {
    const cached = this.#dictionaries.get(offset);
    if (cached) return cached;
    const result = Promise.all(readDictionaryMethods(this.layout.fork(offset), this.#types, this.issues)
      .map(async ({ entrypointIndex, ...method }) => ({ ...method,
        entrypointRva: entrypointIndex === null ? null : await this.references.native.resolve(entrypointIndex) })));
    this.#dictionaries.set(offset, result);
    return result;
  }
}
