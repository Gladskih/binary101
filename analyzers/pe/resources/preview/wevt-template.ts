"use strict";

import { readGuid } from "../../type-library/reader.js";
import type { ResourcePreviewResult, ResourceWevtEvent, ResourceWevtProvider } from "./types.js";
import { parseWevtSection } from "./wevt-sections.js";

// CRIM, WEVT and EVNT layouts:
// https://github.com/libyal/libfwevt/blob/main/documentation/Windows%20Event%20manifest%20binary%20format.asciidoc
const signature = (data: Uint8Array, offset: number): string =>
  offset >= 0 && offset + 4 <= data.length
    ? String.fromCharCode(...data.subarray(offset, offset + 4)) : "";

const within = (offset: number, size: number, end: number): boolean =>
  Number.isSafeInteger(offset) && Number.isSafeInteger(size) &&
  offset >= 0 && size >= 0 && offset <= end && size <= end - offset;

const parseEvents = (
  data: Uint8Array, view: DataView, offset: number, manifestEnd: number, issues: string[]
): ResourceWevtEvent[] => {
  if (!within(offset, 16, manifestEnd) || signature(data, offset) !== "EVNT") {
    issues.push("WEVT EVNT table is invalid or truncated.");
    return [];
  }
  const size = view.getUint32(offset + 4, true);
  const count = view.getUint32(offset + 8, true);
  if (size < 16 || !within(offset, size, manifestEnd)) {
    issues.push("WEVT EVNT table size is invalid.");
    return [];
  }
  const tableEnd = offset + size;
  const available = Math.floor((tableEnd - offset - 16) / 48);
  if (count > available) issues.push("WEVT event definitions are truncated.");
  return Array.from({ length: Math.min(count, available) }, (_, index) => {
    const base = offset + 16 + index * 48;
    const messageId = view.getUint32(base + 16, true);
    const templateOffset = view.getUint32(base + 20, true);
    if (templateOffset && !within(templateOffset, 4, manifestEnd)) {
      issues.push(`WEVT event ${view.getUint16(base, true)} has an invalid template offset.`);
    }
    return {
      id: view.getUint16(base, true), version: view.getUint8(base + 2),
      channel: view.getUint8(base + 3), level: view.getUint8(base + 4),
      opcode: view.getUint8(base + 5), task: view.getUint16(base + 6, true),
      keywords: `0x${view.getBigUint64(base + 8, true).toString(16).padStart(16, "0")}`,
      messageId: messageId === 0xffffffff ? null : messageId,
      templateOffset: templateOffset && within(templateOffset, 4, manifestEnd)
        ? templateOffset : null
    };
  });
};

const parseProvider = (
  data: Uint8Array, view: DataView, descriptor: number, manifestEnd: number,
  issues: string[]
): ResourceWevtProvider | null => {
  const guid = readGuid(view, descriptor);
  const offset = view.getUint32(descriptor + 16, true);
  if (!guid || !within(offset, 20, manifestEnd) || signature(data, offset) !== "WEVT") {
    issues.push("WEVT provider offset or signature is invalid.");
    return null;
  }
  const size = view.getUint32(offset + 4, true);
  const count = view.getUint32(offset + 12, true);
  if (size < 20 || !within(offset, size, manifestEnd)) {
    issues.push("WEVT provider size is invalid.");
    return null;
  }
  const available = Math.floor((size - 20) / 8);
  if (count > available) issues.push("WEVT provider element directory is truncated.");
  const events: ResourceWevtEvent[] = [];
  const elements: Array<{ kind: string; offset: number }> = [];
  const metadata: ResourceWevtProvider["metadata"] = [];
  const templates: ResourceWevtProvider["templates"] = [];
  for (let index = 0; index < Math.min(count, available); index += 1) {
    const elementOffset = view.getUint32(offset + 20 + index * 8, true);
    const kind = signature(data, elementOffset);
    if (!within(elementOffset, 12, manifestEnd)) {
      issues.push("WEVT provider element offset is invalid.");
      continue;
    }
    elements.push({ kind, offset: elementOffset });
    if (kind === "EVNT") {
      events.push(...parseEvents(data, view, elementOffset, manifestEnd, issues));
    }
    if (["CHAN", "KEYW", "LEVL", "OPCO", "TASK", "MAPS", "TTBL"].includes(kind)) {
      const section = parseWevtSection(data, elementOffset, manifestEnd, issues);
      metadata.push(...section.metadata);
      templates.push(...section.templates);
    }
  }
  const messageId = view.getUint32(offset + 8, true);
  return { guid, messageId: messageId === 0xffffffff ? null : messageId,
    elements, events, metadata, templates };
};

export function addWevtTemplatePreview(
  data: Uint8Array, typeName: string
): ResourcePreviewResult | null {
  if (typeName !== "WEVT_TEMPLATE") return null;
  if (data.length < 16 || signature(data, 0) !== "CRIM") {
    return { issues: ["WEVT_TEMPLATE CRIM header is invalid or truncated."] };
  }
  const view = new DataView(data.buffer, data.byteOffset, data.length);
  const size = view.getUint32(4, true);
  const count = view.getUint32(12, true);
  const issues: string[] = [];
  if (size < 16 || size > data.length) issues.push("WEVT_TEMPLATE CRIM size is invalid.");
  if (size < data.length && data.subarray(size).some(byte => byte !== 0)) {
    issues.push("WEVT_TEMPLATE has nonzero trailing bytes outside CRIM.");
  }
  const manifestEnd = size >= 16 && size <= data.length ? size : data.length;
  const available = Math.floor((manifestEnd - 16) / 20);
  if (count > available) issues.push("WEVT_TEMPLATE provider directory is truncated.");
  const providers: ResourceWevtProvider[] = [];
  for (let index = 0; index < Math.min(count, available); index += 1) {
    const provider = parseProvider(data, view, 16 + index * 20, manifestEnd, issues);
    if (provider) providers.push(provider);
  }
  return { preview: { previewKind: "wevtTemplate", wevtTemplate: {
    version: `${view.getUint16(8, true)}.${view.getUint16(10, true)}`, providers
  } }, ...(issues.length ? { issues } : {}) };
}
