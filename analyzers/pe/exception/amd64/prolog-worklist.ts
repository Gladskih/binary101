import type { Amd64RuntimeFunctionTable } from "./runtime-function-table.js";

type FunctionRanges = Amd64RuntimeFunctionTable["functionsByUnwindRva"];
type FunctionRange = { begin: number; end: number; sourceUnwindInfoRva: number };
type RangeCursor = { rva: number; ranges: FunctionRange[]; index: number };
const firstBegin = (cursor: RangeCursor): number => cursor.ranges[cursor.index]!.begin;

const insert = (heap: RangeCursor[], cursor: RangeCursor): void => {
  let index = heap.length;
  heap.push(cursor);
  while (index > 0) {
    const parent = Math.floor((index - 1) / 2);
    if (firstBegin(heap[parent]!) <= firstBegin(cursor)) break;
    heap[index] = heap[parent]!;
    index = parent;
  }
  heap[index] = cursor;
};

const take = (heap: RangeCursor[]): RangeCursor => {
  const first = heap[0]!;
  const last = heap.pop()!;
  if (heap.length === 0) return first;
  let index = 0;
  while (index * 2 + 1 < heap.length) {
    let child = index * 2 + 1;
    if (child + 1 < heap.length && firstBegin(heap[child + 1]!) < firstBegin(heap[child]!)) child++;
    if (firstBegin(last) <= firstBegin(heap[child]!)) break;
    heap[index] = heap[child]!;
    index = child;
  }
  heap[index] = last;
  return first;
};

/** Merge per-description owners without copying a potentially million-row task list.
 * Ordinary sorted .pdata needs one cursor per description; malformed ordering is
 * checked explicitly and uses a sorted reference copy, preserving source objects.
 */
export const orderedAmd64PrologRanges = function* (groups: FunctionRanges) {
  const heap: RangeCursor[] = [];
  for (const [rva, ranges] of groups) {
    if (ranges.length === 0) continue;
    const ordered = ranges.every((range, index) => index === 0 || ranges[index - 1]!.begin <= range.begin);
    insert(heap, { rva, index: 0,
      ranges: ordered ? ranges : ranges.toSorted((left, right) => left.begin - right.begin) });
  }
  while (heap.length) {
    const cursor = take(heap);
    yield { rva: cursor.rva, range: cursor.ranges[cursor.index]! };
    cursor.index++;
    if (cursor.index < cursor.ranges.length) insert(heap, cursor);
  }
};
