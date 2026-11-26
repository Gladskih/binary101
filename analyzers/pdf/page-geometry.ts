import { readArray } from "./syntax.js";
import type { PdfDictionary } from "./syntax.js";
import type { PdfRectangle } from "./types.js";

export interface PdfPageGeometry {
  mediaBox: PdfRectangle | null;
  cropBox: PdfRectangle | null;
  rotation: number | null;
}

const real = /^[+-]?(?:\d+(?:\.\d*)?|\.\d+)$/;

const number = (token: string | undefined): number | null => {
  if (!token || !real.test(token)) return null;
  const value = Number(token);
  return Number.isFinite(value) ? value : null;
};

const readBox = (token: string): PdfRectangle | null => {
  const values = readArray(token)?.map(number);
  if (values?.length !== 4) return null;
  const [left, bottom, right, top] = values;
  if (left == null || bottom == null || right == null || top == null) return null;
  return [left, bottom, right, top];
};

const inheritedBox = (
  token: string | undefined, previous: PdfRectangle | null, label: string, issues: string[]
): PdfRectangle | null => {
  if (token == null || token === "null") return previous;
  const box = readBox(token);
  if (!box) issues.push(label + " is not a supported four-number page rectangle.");
  return box;
};

const inheritedRotation = (
  token: string | undefined, previous: number | null, issues: string[]
): number | null => {
  if (token == null || token === "null") return previous;
  const rotation = number(token);
  if (rotation != null && Number.isSafeInteger(rotation) && rotation % 90 === 0) return rotation;
  issues.push("Page tree /Rotate is not an integer multiple of 90.");
  return null;
};

// ISO 32000-2, 7.7.3.4: these attributes may be inherited from a /Pages ancestor.
export const readPageGeometry = (
  fields: PdfDictionary["fields"], previous: PdfPageGeometry, issues: string[]
): PdfPageGeometry => ({
  mediaBox: inheritedBox(fields.get("MediaBox"), previous.mediaBox, "/MediaBox", issues),
  cropBox: inheritedBox(fields.get("CropBox"), previous.cropBox, "/CropBox", issues),
  rotation: inheritedRotation(fields.get("Rotate"), previous.rotation, issues)
});

export const readUserUnit = (token: string | undefined, issues: string[]): number | null => {
  // ISO 32000-2, Table 31: a page's default user-space unit is 1/72 inch.
  if (token == null || token === "null") return 1;
  const value = number(token);
  if (value != null && value > 0) return value;
  issues.push("Page /UserUnit is not a positive number.");
  return null;
};
