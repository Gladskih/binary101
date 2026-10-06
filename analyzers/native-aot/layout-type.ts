import type { NativeFormatCursor } from "./native-format-cursor.js";
import type { NativeFormatReader } from "./native-format-reader.js";
import { nativeTypeLookbackOffset } from "./type-lookback.js";

type TypeTask = { kind: "type" | "bounds"; cursor: NativeFormatCursor } |
  { kind: "finish"; cursor: NativeFormatCursor; start: number };

// TypeSignatureKind grammar, including GetLookbackParser's canonical integer width:
// https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/nativeaot/System.Private.TypeLoader/src/Internal/Runtime/TypeLoader/NativeLayoutInfoLoadContext.cs
// https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/tools/Common/Internal/NativeFormat/NativeFormatReader.Metadata.cs
export class NativeLayoutTypeReader {
  readonly #ends = new WeakMap<NativeFormatReader, Map<number, number>>();

  skip(cursor: NativeFormatCursor): void {
    const active = new Set<number>();
    const ends = this.#ends.get(cursor.reader) ?? new Map<number, number>();
    this.#ends.set(cursor.reader, ends);
    const tasks: TypeTask[] = [{ kind: "type", cursor }];
    while (tasks.length) {
      const task = tasks.pop()!;
      if (task.kind === "finish") {
        ends.set(task.start, task.cursor.offset);
        active.delete(task.start);
      } else if (task.kind === "bounds") {
        task.cursor.indices();
        task.cursor.indices();
      } else this.#type(task.cursor, tasks, active, ends);
    }
  }

  #type(cursor: NativeFormatCursor, tasks: TypeTask[], active: Set<number>, ends: Map<number, number>): void {
    const start = cursor.offset;
    const cached = ends.get(start);
    if (cached !== undefined) { cursor.offset = cached; return; }
    if (active.has(start)) throw new Error("NativeLayout type lookback is cyclic.");
    const value = cursor.unsigned();
    const kind = value & 15;
    const data = value >>> 4;
    active.add(start);
    tasks.push({ kind: "finish", cursor, start });
    if ([4, 5, 6].includes(kind)) return;
    if (kind === 1) {
      const target = nativeTypeLookbackOffset(cursor.offset, data);
      if (target < 0 || target >= start) throw new Error("NativeLayout type lookback is outside its prefix.");
      tasks.push({ kind: "type", cursor: cursor.fork(target) });
      return;
    }
    this.#children(cursor, kind, data, tasks);
  }

  #children(cursor: NativeFormatCursor, kind: number, data: number, tasks: TypeTask[]): void {
    let count: number;
    if (kind === 2 && [1, 2, 3].includes(data)) count = 1;
    else if (kind === 3) count = data + 1;
    else if (kind === 10) {
      tasks.push({ kind: "bounds", cursor });
      count = 1;
    } else if (kind === 11) {
      cursor.unsigned();
      count = cursor.count() + 1;
    } else throw new Error("NativeLayout type has an unknown kind or modifier.");
    if (count > cursor.reader.size - cursor.offset) {
      throw new Error("NativeLayout nested types are outside the remaining bytes.");
    }
    for (let index = 0; index < count; index += 1) tasks.push({ kind: "type", cursor });
  }
}
