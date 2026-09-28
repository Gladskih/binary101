"use strict";

import type { ResourceDetailGroup, ResourceDialogPreview } from "./types.js";

// MFC ApplyLayoutDataTo walks child windows in order alongside layout records.
// https://github.com/adzm/atlmfc/blob/master/src/mfc/afxlayout.cpp#L414-L453
const findDialog = (
  detail: ResourceDetailGroup[], id: number | null, name: string | null, language: number | null
): ResourceDialogPreview | null => {
  if (id === null && name === null) return null;
  const group = detail.find(item => item.typeName === "DIALOG");
  const entry = group?.entries.find(item => item.id === id && item.name === name);
  return entry?.langs.find(item => item.lang === language)?.dialogPreview ?? null;
};

export const linkDialogLayouts = (detail: ResourceDetailGroup[]): ResourceDetailGroup[] =>
  detail.map(group => group.typeName === "AFX_DIALOG_LAYOUT" ? {
    ...group,
    entries: group.entries.map(entry => ({ ...entry,
      langs: entry.langs.map(lang => {
        const dialog = findDialog(detail, entry.id, entry.name, lang.lang);
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
