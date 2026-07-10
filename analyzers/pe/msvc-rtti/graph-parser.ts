"use strict";

import type { MsvcRttiImage } from "./image.js";
import { buildMsvcRttiHierarchyTree } from "./hierarchy-tree.js";
import {
  IMAGE_RELATIVE_POINTER_SIZE,
  MAX_HIERARCHY_DEPTH
} from "./layout.js";
import {
  parseBaseClassDescriptor,
  parseClassHierarchyDescriptor,
  parseCompleteObjectLocator
} from "./structure-parsers.js";
import { parseMsvcRttiTypeDescriptor } from "./type-descriptor.js";
import type {
  MsvcRttiBaseClass,
  MsvcRttiClassHierarchy,
  MsvcRttiCompleteObjectLocator,
  MsvcRttiTypeDescriptor
} from "./types.js";

export interface MsvcRttiGraphParser {
  completeObjectLocator: (rva: number) => Promise<MsvcRttiCompleteObjectLocator | null>;
  getClassHierarchy: (rva: number) => MsvcRttiClassHierarchy | null;
  getTypeDescriptor: (rva: number) => MsvcRttiTypeDescriptor | null;
}

const readBaseClassDescriptorRvas = async (
  image: MsvcRttiImage,
  arrayRva: number,
  count: number
): Promise<number[] | null> => {
  const byteLength = count * IMAGE_RELATIVE_POINTER_SIZE;
  if (!Number.isSafeInteger(byteLength) || byteLength <= 0) return null;
  const view = await image.readData(arrayRva, byteLength, IMAGE_RELATIVE_POINTER_SIZE);
  if (!view) return null;
  const rvas: number[] = [];
  for (let index = 0; index < count; index += 1) {
    const rva = view.getUint32(index * IMAGE_RELATIVE_POINTER_SIZE, true);
    if (!rva) return null;
    rvas.push(rva);
  }
  return rvas;
};

const parseBaseClasses = async (
  image: MsvcRttiImage,
  descriptorRvas: number[],
  typeDescriptor: (rva: number) => Promise<MsvcRttiTypeDescriptor | null>
): Promise<MsvcRttiBaseClass[] | null> => {
  const entries: MsvcRttiBaseClass[] = [];
  for (const descriptorRva of descriptorRvas) {
    const parsed = await parseBaseClassDescriptor(image, descriptorRva);
    if (!parsed || !await typeDescriptor(parsed.typeDescriptorRva)) return null;
    entries.push({ descriptorRva, ...parsed, children: [] });
  }
  return entries;
};

export const createMsvcRttiGraphParser = (image: MsvcRttiImage): MsvcRttiGraphParser => {
  const typeDescriptors = new Map<number, MsvcRttiTypeDescriptor | null>();
  const classHierarchies = new Map<number, MsvcRttiClassHierarchy | null>();
  const completeObjectLocators = new Map<number, MsvcRttiCompleteObjectLocator | null>();
  const typeDescriptor = async (rva: number): Promise<MsvcRttiTypeDescriptor | null> => {
    if (typeDescriptors.has(rva)) return typeDescriptors.get(rva) ?? null;
    const parsed = await parseMsvcRttiTypeDescriptor(image, rva);
    typeDescriptors.set(rva, parsed);
    return parsed;
  };
  const hierarchy = async (
    rva: number,
    expectedTypeDescriptorRva: number,
    active: Set<number>,
    depth: number
  ): Promise<MsvcRttiClassHierarchy | null> => {
    const cached = classHierarchies.get(rva);
    if (cached !== undefined || classHierarchies.has(rva)) {
      return cached?.root.typeDescriptorRva === expectedTypeDescriptorRva ? cached : null;
    }
    if (depth >= MAX_HIERARCHY_DEPTH || active.has(rva)) return null;
    active.add(rva);
    const descriptor = await parseClassHierarchyDescriptor(image, rva);
    const descriptorRvas = descriptor
      ? await readBaseClassDescriptorRvas(image, descriptor.baseClassArrayRva, descriptor.numBaseClasses)
      : null;
    const entries = descriptorRvas
      ? await parseBaseClasses(image, descriptorRvas, typeDescriptor)
      : null;
    const root = entries ? buildMsvcRttiHierarchyTree(entries) : null;
    let valid = root?.typeDescriptorRva === expectedTypeDescriptorRva &&
      root.classHierarchyDescriptorRva === rva;
    if (valid && entries) {
      for (let index = 1; index < entries.length; index += 1) {
        const entry = entries[index]!;
        if (entry.classHierarchyDescriptorRva === rva ||
          !await hierarchy(entry.classHierarchyDescriptorRva, entry.typeDescriptorRva, active, depth + 1)) {
          valid = false;
          break;
        }
      }
    }
    active.delete(rva);
    const parsed = valid && descriptor && root
      ? { rva, attributes: descriptor.attributes, root }
      : null;
    classHierarchies.set(rva, parsed);
    return parsed;
  };
  const completeObjectLocator = async (
    rva: number
  ): Promise<MsvcRttiCompleteObjectLocator | null> => {
    if (completeObjectLocators.has(rva)) return completeObjectLocators.get(rva) ?? null;
    const parsed = await parseCompleteObjectLocator(image, rva);
    const type = parsed ? await typeDescriptor(parsed.typeDescriptorRva) : null;
    const classHierarchy = parsed && type
      ? await hierarchy(parsed.classHierarchyDescriptorRva, parsed.typeDescriptorRva, new Set(), 0)
      : null;
    const result = parsed && classHierarchy ? { rva, ...parsed } : null;
    completeObjectLocators.set(rva, result);
    return result;
  };
  return {
    completeObjectLocator,
    getClassHierarchy: rva => classHierarchies.get(rva) ?? null,
    getTypeDescriptor: rva => typeDescriptors.get(rva) ?? null
  };
};

