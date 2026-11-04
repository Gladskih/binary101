"use strict";

import { indexResourceLeaves, resolveResourceReference, resourceAt } from "../resource-index.js";
import type { ResourceCatalog } from "../resource-index.js";
import type { ResourceDetailGroup, ResourceDialogPreview } from "./types.js";

// MFC ApplyLayoutDataTo walks child windows in order alongside layout records.
// https://github.com/adzm/atlmfc/blob/master/src/mfc/afxlayout.cpp#L414-L453
const findDialog = (
  catalog: ResourceCatalog, id: number | null, name: string | null, language: number | null
): ResourceDialogPreview | null => {
  const key = name ?? id;
  if (key === null) return null;
  const resolution = resolveResourceReference(catalog, "DIALOG", key, language);
  if (resolution.kind !== "exact" && resolution.kind !== "neutral") return null;
  return resourceAt(catalog, resolution.targets[0]!)?.dialogPreview ?? null;
};

export const linkDialogLayouts = (detail: ResourceDetailGroup[]): ResourceDetailGroup[] => {
  const catalog = indexResourceLeaves(detail);
  return detail.map(group => group.typeName === "AFX_DIALOG_LAYOUT" ? {
    ...group,
    entries: group.entries.map(entry => ({ ...entry,
      langs: entry.langs.map(lang => {
        const dialog = findDialog(catalog, entry.id, entry.name, lang.lang);
        if (!dialog || !lang.dialogLayout) return lang;
        return { ...lang, dialogLayout: { ...lang.dialogLayout,
          controls: lang.dialogLayout.controls.map((control, index) => {
            const target = dialog.controls[index];
            return target ? { ...control, dialogControl: {
              id: target.id, kind: target.kind, title: target.title
            } } : control;
          })
        } };
      })
    }))
  } : group);
};
