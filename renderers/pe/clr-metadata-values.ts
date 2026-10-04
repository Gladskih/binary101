"use strict";

import { escapeHtml } from "../../html-utils.js";
import type {
  PeClrConstantValue, PeClrMarshallingDescriptor, PeClrPermissionSet
} from "../../analyzers/pe/clr/metadata-value-types.js";

type MetadataValue = PeClrConstantValue | PeClrMarshallingDescriptor | PeClrPermissionSet;
export const metadataValueText = (cell: MetadataValue): string => {
  if (cell.kind === "constant") return cell.value == null ? "null" : String(cell.value);
  if (cell.kind === "marshal") {
    return `${cell.nativeType}${Object.entries(cell.parameters).map(([key, value]) => `; ${key}=${value}`).join("")}`;
  }
  if (cell.encoding === "xml") return cell.xml;
  return cell.attributes.map(attribute => `${attribute.typeName}: ` + attribute.namedArguments.map(argument =>
    `${argument.kind} ${argument.type} ${argument.name}=${argument.value}`).join("; ") +
    (attribute.issues?.length ? ` (${attribute.issues.join("; ")})` : "")).join("\n");
};

export const renderMetadataValue = (cell: MetadataValue): string =>
  escapeHtml(metadataValueText(cell));
