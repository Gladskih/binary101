"use strict";

import type { MsvcRttiTypeDescriptor } from "../../analyzers/pe/msvc-rtti/types.js";
import { getMsvcRttiTypeName } from "../../analyzers/pe/msvc-rtti/type-name.js";
import { escapeHtml } from "../../html-utils.js";
import type { PagedSortableTableCell } from "../paged-sortable-table.js";

export const msvcRttiTypeNameCell = (
  type: MsvcRttiTypeDescriptor | null | undefined
): PagedSortableTableCell => {
  if (!type) return { html: "(unresolved)", sortValue: "(unresolved)" };
  const name = getMsvcRttiTypeName(type);
  return {
    html: `<code>${escapeHtml(name)}</code>` + (name === type.decoratedName ? "" :
      `<br><code class="dim">${escapeHtml(type.decoratedName)}</code>`),
    sortValue: name
  };
};
