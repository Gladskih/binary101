"use strict";

import type { GoRuntimeLayout } from "./types.js";

export interface GoRuntimeLayoutDefinition {
  id: GoRuntimeLayout;
  magic: number;
  headerWordCount: number;
  tableOffsetWord: number;
  functabFieldSize: (pointerSize: 4 | 8) => number;
  relativeFunctionEntries: boolean;
}

// Go runtime pcHeader and functab definitions:
// https://github.com/golang/go/blob/go1.16.15/src/runtime/symtab.go
// https://github.com/golang/go/blob/go1.18.10/src/runtime/symtab.go
// https://github.com/golang/go/blob/go1.20.14/src/runtime/symtab.go
// https://github.com/golang/go/blob/go1.26.4/src/runtime/symtab.go
export const SUPPORTED_GO_RUNTIME_LAYOUTS: readonly GoRuntimeLayoutDefinition[] = [
  {
    id: "go1.16-1.17",
    magic: 0xffff_fffa,
    headerWordCount: 7,
    tableOffsetWord: 2,
    functabFieldSize: pointerSize => pointerSize,
    relativeFunctionEntries: false
  },
  {
    id: "go1.18-1.19",
    magic: 0xffff_fff0,
    headerWordCount: 8,
    tableOffsetWord: 3,
    functabFieldSize: () => 4,
    relativeFunctionEntries: true
  },
  {
    id: "go1.20+",
    magic: 0xffff_fff1,
    headerWordCount: 8,
    tableOffsetWord: 3,
    functabFieldSize: () => 4,
    relativeFunctionEntries: true
  }
];

export const findGoRuntimeLayout = (
  magic: number
): GoRuntimeLayoutDefinition | null =>
  SUPPORTED_GO_RUNTIME_LAYOUTS.find(layout => layout.magic === magic) ?? null;
