"use strict";

import type { Demangler } from "llvm-msvc-demangle";
import { loadMsvcDemangler } from "#msvc-demangler-loader";
import type { MsvcRttiImage } from "./image.js";
import type { MsvcRttiTypeDescriptor } from "./types.js";

// Keep presentation out of parsed records. Weak keys release it with the owning type;
// tables, sorting, and lazy remounts reuse the single LLVM parse performed during analysis.
const typeNames = new WeakMap<MsvcRttiTypeDescriptor, string>();

export class MsvcRttiDemangleError extends Error {}

export const createMsvcRttiTypeNameDecoder = (
  loadDemangler: () => Promise<Demangler> = loadMsvcDemangler
) => {
  // A trapped instance is quarantined by the package. Each image gets its own instance
  // so a malformed file cannot poison later analyses. Initialization is lazy and shared.
  const demanglers = new WeakMap<MsvcRttiImage, Promise<Demangler>>();
  return async (image: MsvcRttiImage, type: MsvcRttiTypeDescriptor): Promise<boolean> => {
    try {
      let pending = demanglers.get(image);
      if (!pending) {
        pending = loadDemangler();
        demanglers.set(image, pending);
      }
      const result = (await pending).demangleTypeWithText(type.decoratedName);
      if (result.status === "error" || result.status === "limit") {
        throw new Error(result.warnings.join("; ") || result.status);
      }
      if (result.status !== "success") return false;
      const root = result.ast.nodes[result.ast.root];
      if (root?.kind !== "TagType" || (root.tag !== "Class" && root.tag !== "Struct")) return false;
      typeNames.set(type, result.text);
      return true;
    } catch (error) {
      throw new MsvcRttiDemangleError(
        `MSVC RTTI name analysis failed: ${error instanceof Error ? error.message : String(error)}`
      );
    }
  };
};

export const decodeMsvcRttiTypeName = createMsvcRttiTypeNameDecoder();

export const getMsvcRttiTypeName = (type: MsvcRttiTypeDescriptor): string =>
  typeNames.get(type) ?? type.decoratedName;
