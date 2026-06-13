"use strict";

import type { FileRangeReader } from "../../file-range-reader.js";
import type {
  ResourceDirectoryEntry,
  ResourceDirectoryLabelReadResult
} from "./directory-rules.js";
import type { ResourceDataEntryLayout } from "./layout-rules.js";
import type { ResourceSpanResolver } from "./relative-offsets.js";
import type { ResourceLeafPath, ResourcePathNode } from "./tree-types.js";
import type { PeDataDirectory } from "../types.js";

const IMAGE_RESOURCE_DATA_ENTRY_SIZE = 16;

export interface ResourcePathNodeReadResult {
  node: ResourcePathNode;
  issues: string[];
  resourceStringRanges: ResourceDirectoryLabelReadResult["resourceStringRanges"];
}

export interface ResourceLeafPathReadResult {
  leaf: ResourceLeafPath | null;
  issues: string[];
  resourceDataEntry: ResourceDataEntryLayout | null;
}

const readResourceLabelPayload = async (
  reader: FileRangeReader,
  textOff: number,
  bytesLength: number,
  utf16Decoder: TextDecoder
): Promise<string> => {
  const bytesView = await reader.read(textOff, bytesLength);
  const bytes = new Uint8Array(
    bytesView.buffer,
    bytesView.byteOffset,
    bytesView.byteLength
  );
  return utf16Decoder.decode(bytes.subarray(0, bytes.length - (bytes.length % 2)));
};

export const createResourceLabelReader = (
  reader: FileRangeReader,
  dir: PeDataDirectory,
  resolver: ResourceSpanResolver,
  utf16Decoder: TextDecoder
): ((rel: number) => Promise<ResourceDirectoryLabelReadResult>) => {
  const resourceNameCache = new Map<number, Promise<ResourceDirectoryLabelReadResult>>();
  const readUcs2Label = (rel: number): Promise<ResourceDirectoryLabelReadResult> => {
    const cached = resourceNameCache.get(rel);
    if (cached) return cached;
    const pending = readUncachedResourceLabel(reader, dir, resolver, utf16Decoder, rel);
    resourceNameCache.set(rel, pending);
    return pending;
  };
  return readUcs2Label;
};

const readUncachedResourceLabel = async (
  reader: FileRangeReader,
  dir: PeDataDirectory,
  resolver: ResourceSpanResolver,
  utf16Decoder: TextDecoder,
  rel: number
): Promise<ResourceDirectoryLabelReadResult> => {
  const alignmentIssues = (rel & 1) !== 0
    ? [`Resource string name at ${resolver.formatRelOffset(rel)} is not word-aligned.`]
    : [];
  const headerOff = resolver.resolveRelOffset(rel, 2);
  if (headerOff == null) {
    return {
      text: "",
      issues: [
        ...alignmentIssues,
        resolver.describeRelOffsetFailure(
          rel,
          2,
          `Resource string name header at ${resolver.formatRelOffset(rel)}`
        )
      ],
      resourceStringRanges: []
    };
  }
  const view = await reader.read(headerOff, 2);
  if (view.byteLength < 2) {
    return {
      text: "",
      issues: [
        ...alignmentIssues,
        `Resource string name header at ${resolver.formatRelOffset(rel)} is truncated.`
      ],
      resourceStringRanges: []
    };
  }
  return await readMappedResourceLabel(
    reader,
    dir,
    rel,
    view.getUint16(0, true),
    resolver,
    utf16Decoder,
    alignmentIssues
  );
};

const readMappedResourceLabel = async (
  reader: FileRangeReader,
  dir: PeDataDirectory,
  rel: number,
  codeUnitLength: number,
  resolver: ResourceSpanResolver,
  utf16Decoder: TextDecoder,
  inheritedIssues: string[]
): Promise<ResourceDirectoryLabelReadResult> => {
  const declaredBytesLength = codeUnitLength * 2;
  const bytesLength = Math.min(declaredBytesLength, Math.max(0, dir.size - (rel + 2)));
  const textOff = resolver.resolveRelOffset(rel + 2, bytesLength);
  const range = { start: rel, end: rel + 2 + bytesLength };
  const truncationIssues = bytesLength < declaredBytesLength
    ? [`Resource string name at ${resolver.formatRelOffset(rel)} is truncated.`]
    : [];
  if (textOff == null) {
    return {
      text: "",
      issues: [
        ...inheritedIssues,
        ...truncationIssues,
        resolver.describeRelOffsetFailure(
          rel + 2,
          bytesLength,
          `Resource string name payload at ${resolver.formatRelOffset(rel + 2)}`
        )
      ],
      resourceStringRanges: [range]
    };
  }
  return {
    text: await readResourceLabelPayload(reader, textOff, bytesLength, utf16Decoder),
    issues: [...inheritedIssues, ...truncationIssues],
    resourceStringRanges: [range]
  };
};

export const createResourcePathNodeReader = (
  readUcs2Label: (rel: number) => Promise<ResourceDirectoryLabelReadResult>
): ((entry: ResourceDirectoryEntry) => Promise<ResourcePathNodeReadResult>) =>
  async (entry: ResourceDirectoryEntry): Promise<ResourcePathNodeReadResult> => {
    if (!entry.nameIsString) {
      return {
        node: { id: entry.nameOrId ?? null, name: null },
        issues: [],
        resourceStringRanges: []
      };
    }
    if (entry.nameOrId == null || entry.invalidNameOffset) {
      return { node: { id: null, name: null }, issues: [], resourceStringRanges: [] };
    }
    const label = await readUcs2Label(entry.nameOrId);
    return {
      node: { id: null, name: label.text },
      issues: label.issues,
      resourceStringRanges: label.resourceStringRanges
    };
  };

export const createResourceLeafPathReader = (
  view: (offset: number, length: number) => Promise<DataView>,
  resolver: ResourceSpanResolver
): ((target: number, nodes: ResourcePathNode[]) => Promise<ResourceLeafPathReadResult>) =>
  async (target: number, nodes: ResourcePathNode[]): Promise<ResourceLeafPathReadResult> => {
    const dataEntryOff = resolver.resolveRelOffset(target, IMAGE_RESOURCE_DATA_ENTRY_SIZE);
    if (dataEntryOff == null) {
      return {
        leaf: null,
        resourceDataEntry: null,
        issues: [
          resolver.describeRelOffsetFailure(
            target,
            IMAGE_RESOURCE_DATA_ENTRY_SIZE,
            `Resource data entry at ${resolver.formatRelOffset(target)}`
          )
        ]
      };
    }
    const dataEntry = await readResourceDataEntry(view, resolver, target, dataEntryOff, nodes);
    if (!dataEntry.leaf) return dataEntry;
    return dataEntry.leaf.reserved === 0
      ? dataEntry
      : {
          ...dataEntry,
          issues: [
            ...dataEntry.issues,
            "IMAGE_RESOURCE_DATA_ENTRY.Reserved is non-zero; the field should be 0."
          ]
        };
  };

const readResourceDataEntry = async (
  view: (offset: number, length: number) => Promise<DataView>,
  resolver: ResourceSpanResolver,
  target: number,
  dataEntryOff: number,
  nodes: ResourcePathNode[]
): Promise<ResourceLeafPathReadResult> => {
  const data = await view(dataEntryOff, IMAGE_RESOURCE_DATA_ENTRY_SIZE);
  if (data.byteLength < IMAGE_RESOURCE_DATA_ENTRY_SIZE) {
    return {
      leaf: null,
      resourceDataEntry: null,
      issues: [`Resource data entry at ${resolver.formatRelOffset(target)} is truncated.`]
    };
  }
  const dataRVA = data.getUint32(0, true);
  const dataFileOffset = resolver.resolveRvaOffset(dataRVA);
  const size = data.getUint32(4, true);
  const codePage = data.getUint32(8, true);
  const reserved = data.getUint32(12, true);
  return {
    leaf: {
      nodes,
      dataRVA,
      dataFileOffset,
      size,
      codePage,
      reserved
    },
    issues: [],
    resourceDataEntry: {
      start: target,
      end: target + IMAGE_RESOURCE_DATA_ENTRY_SIZE,
      dataRva: dataRVA,
      dataFileOffset,
      size
    }
  };
};
