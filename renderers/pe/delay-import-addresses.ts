import { hex } from "../../binary-utils.js";
import { renderDefinitionRow } from "../../html-utils.js";
import { DELAY_IMPORT_ATTRIBUTE_DLATTR_RVA } from "../../analyzers/pe/imports/delay.js";

export const renderDelayImportAddressFields = (attributes: number): string =>
  renderDefinitionRow("Attributes", hex(attributes, 8),
    "Bit 0 (RvaBased) identifies address fields stored as RVAs. If clear, fields store legacy VAs.") +
  renderDefinitionRow("Stored address format",
    attributes & DELAY_IMPORT_ATTRIBUTE_DLATTR_RVA ? "RVA" : "Legacy VA",
    "The RVAs below are image-relative. Legacy values are converted using the preferred image base.");
