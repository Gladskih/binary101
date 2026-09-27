"use strict";

import type { ResourcePreviewResult } from "./types.js";

export const addToolbarPreview = (
  data: Uint8Array, typeName: string
): ResourcePreviewResult | null => {
  if (typeName !== "TOOLBAR") return null;
  // MFC CToolBarData consists of four WORDs followed by WORD command IDs.
  // Version 1 is used by CToolBar::LoadToolBar; ID 0 creates a separator.
  // https://github.com/adzm/atlmfc/blob/master/src/mfc/bartool.cpp
  if (data.length < 8) return { issues: ["TOOLBAR header is truncated."] };
  const view = new DataView(data.buffer, data.byteOffset, data.length);
  const version = view.getUint16(0, true);
  if (version !== 1) return { issues: [`TOOLBAR version ${version} is unsupported.`] };
  const width = view.getUint16(2, true);
  const height = view.getUint16(4, true);
  const count = view.getUint16(6, true);
  const issues: string[] = [];
  if (!width || !height) issues.push("TOOLBAR image dimensions are zero.");
  if (8 + count * 2 > data.length) issues.push("TOOLBAR command list is truncated.");
  if (8 + count * 2 < data.length) issues.push("TOOLBAR contains trailing bytes.");
  const items = Array.from({ length: Math.min(count, Math.floor((data.length - 8) / 2)) },
    (_item, index) => view.getUint16(8 + index * 2, true));
  return { preview: { previewKind: "toolbar", toolbar: { version, width, height, items } },
    ...(issues.length ? { issues } : {}) };
};
