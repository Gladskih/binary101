"use strict";

// Windows SDK 10.0.26100.0 winnt.h IMAGE_GUARD_FLAG_FID_* values, also
// published by Microsoft's generated Win32 metadata documentation:
// https://microsoft.github.io/windows-docs-rs/doc/windows/Win32/System/SystemServices/index.html
const GFIDS_FLAGS: ReadonlyArray<readonly [number, string]> = [
  [0x01, "FID_SUPPRESSED"],
  [0x02, "EXPORT_SUPPRESSED"],
  [0x04, "FID_LANGEXCPTHANDLER"],
  [0x08, "FID_XFG"]
];

// The four published flags occupy bits 0 through 3.
export const GFIDS_FLAG_MASK = 0x0f;

export const decodeGfidsFlags = (flags: number): string[] =>
  GFIDS_FLAGS.flatMap(([mask, name]) => ((flags & mask) !== 0 ? [name] : []));
