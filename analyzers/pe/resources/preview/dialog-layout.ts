"use strict";

import type { ResourcePreviewResult } from "./types.js";

export function addDialogLayoutPreview(
  data: Uint8Array, typeName: string
): ResourcePreviewResult | null {
  if (typeName !== "AFX_DIALOG_LAYOUT") return null;
  // MFC ReadResource: a WORD version, then four WORD ratios per control.
  // AfxClamp treats each ratio as signed and clamps it to 0..100.
  // https://github.com/adzm/atlmfc/blob/master/src/mfc/afxlayout.cpp
  if (data.length < 2) return { issues: ["AFX_DIALOG_LAYOUT version is truncated."] };
  const view = new DataView(data.buffer, data.byteOffset, data.length);
  const version = view.getUint16(0, true);
  if (version !== 0) return { issues: [`AFX_DIALOG_LAYOUT version ${version} is unsupported.`] };
  const controls: Array<{ moveX: number; moveY: number; sizeX: number; sizeY: number }> = [];
  for (let offset = 2; offset + 8 <= data.length; offset += 8) {
    const ratio = (wordOffset: number): number => Math.max(0,
      Math.min(100, view.getInt16(offset + wordOffset, true)));
    controls.push({ moveX: ratio(0), moveY: ratio(2), sizeX: ratio(4), sizeY: ratio(6) });
  }
  return { preview: { previewKind: "dialogLayout", dialogLayout: { version, controls } },
    ...((data.length - 2) % 8
      ? { issues: ["AFX_DIALOG_LAYOUT control record is truncated."] } : {}) };
}
