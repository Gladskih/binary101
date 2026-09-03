"use strict";

/** Container adapter exposing NativeAOT data in image-relative addresses. */
export interface NativeAotVirtualImage {
  pointerSize: 4 | 8;
  isDataRange: (address: number, size: number, alignment: number) => boolean;
  isMappedRange: (address: number, size: number) => boolean;
  readData: (address: number, size: number, alignment: number) => Promise<DataView | null>;
  readPointerValue: (address: number) => Promise<bigint | null>;
  readPointerTarget: (address: number) => Promise<number | null>;
}
