import { decodeRegistryText } from "./registry-text.js";
import { parseRegistryScript } from "./registry-parser.js";
import { registryParameters } from "./registry-parameters.js";
import { validateRegistryCom } from "./registry-analysis.js";
import type { ResourcePreviewResult } from "./types.js";

export const createRegistryPreview = (
  text: string, encoding: string, issues: string[]
): ResourcePreviewResult => {
  registryParameters(text, issues);
  const registry = parseRegistryScript(text, issues);
  validateRegistryCom(registry, issues);
  return {
    preview: { previewKind: "registry", registry, textPreview: text, textEncoding: encoding },
    ...(issues.length ? { issues } : {})
  };
};

export const addRegistryPreview = (
  data: Uint8Array, typeName: string, codePage: number | undefined
): ResourcePreviewResult | null => {
  if (typeName.toUpperCase() !== "REGISTRY" && typeName.toUpperCase() !== "RGS") return null;
  const issues: string[] = [];
  const { text, encoding } = decodeRegistryText(data, codePage ?? 0, issues);
  return createRegistryPreview(text, encoding, issues);
};
