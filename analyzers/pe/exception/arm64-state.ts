"use strict";

import type { PeLanguageHandler } from "./types.js";
import type { Arm64PackedStatistics } from "./arm64-packed-types.js";
import { createArm64PackedStatistics } from "./arm64-packed-statistics.js";
import type { Arm64DecodedUnwind, Arm64UnwindStatistics } from "./arm64-unwind-types.js";
import { createArm64UnwindStatistics } from "./arm64-unwind-statistics.js";

export type Arm64ExceptionState = {
  languageHandlers: PeLanguageHandler[];
  packed: Arm64PackedStatistics;
  unwind: Arm64UnwindStatistics;
  seenXdata: WeakSet<Arm64DecodedUnwind>;
  beginRvas: number[];
  rangeLengths: number[];
  handlerRvas: number[];
  handlerRvasSet: Set<number>;
  uniqueUnwindInfos: Set<string>;
  functionCount: number;
  invalidEntryCount: number;
  handlerUnwindInfoCount: number;
  chainedUnwindInfoCount: number;
  unexpectedXdataVersionCount: number;
  previousBegin: number | null;
  reportedUnsortedEntries: boolean;
};

export const createArm64ExceptionState = (): Arm64ExceptionState => ({
  languageHandlers: [],
  packed: createArm64PackedStatistics(),
  unwind: createArm64UnwindStatistics(),
  seenXdata: new WeakSet(),
  beginRvas: [],
  rangeLengths: [],
  handlerRvas: [],
  handlerRvasSet: new Set<number>(),
  uniqueUnwindInfos: new Set<string>(),
  functionCount: 0,
  invalidEntryCount: 0,
  handlerUnwindInfoCount: 0,
  chainedUnwindInfoCount: 0,
  unexpectedXdataVersionCount: 0,
  previousBegin: null,
  reportedUnsortedEntries: false
});

export const recordArm64HandlerRva = (
  state: Arm64ExceptionState,
  handlerRva: number | null
): void => {
  if (!handlerRva || state.handlerRvasSet.has(handlerRva)) return;
  state.handlerRvasSet.add(handlerRva);
  state.handlerRvas.push(handlerRva);
};
