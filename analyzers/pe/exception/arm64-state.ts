"use strict";

export type Arm64ExceptionState = {
  beginRvas: number[];
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
  beginRvas: [],
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
