"use strict";

import {
  ATTACHMENTS_ID,
  ATTACHED_FILE_ID,
  FILE_DATA_ID,
  FILE_DESCRIPTION_ID,
  FILE_MEDIA_TYPE_ID,
  FILE_NAME_ID,
  FILE_UID_ID
} from "./constants.js";
import { readElementAt, readUtf8, readUnsigned } from "./ebml.js";
import type { EbmlElementHeader } from "./ebml.js";
import type { Issues, WebmAttachedFile, WebmAttachments } from "./types.js";

const MAX_ATTACHMENT_STRING_BYTES = 16 * 1024;
const MAX_ATTACHMENTS_ELEMENTS = 10000;
const MAX_ATTACHMENTS_FILES = 1024;

const readStringElement = async (
  file: File,
  header: EbmlElementHeader,
  issues: Issues,
  label: string
): Promise<{ value: string | null; truncated: boolean }> => {
  if (header.size == null) {
    issues.push(`${label} has unknown size.`);
    return { value: null, truncated: true };
  }
  const maxAvailable = Math.max(0, file.size - header.dataOffset);
  const length = Math.min(header.size, maxAvailable, MAX_ATTACHMENT_STRING_BYTES);
  if (length <= 0) return { value: null, truncated: header.size > 0 };
  const dv = new DataView(await file.slice(header.dataOffset, header.dataOffset + length).arrayBuffer());
  return { value: readUtf8(dv, 0, dv.byteLength), truncated: header.size > length };
};

const readUnsignedElement = async (
  file: File,
  header: EbmlElementHeader,
  issues: Issues,
  label: string
): Promise<{ value: string | number | null; truncated: boolean }> => {
  if (header.size == null) {
    issues.push(`${label} has unknown size.`);
    return { value: null, truncated: true };
  }
  const maxAvailable = Math.max(0, file.size - header.dataOffset);
  const length = Math.min(header.size, maxAvailable);
  if (length <= 0) return { value: null, truncated: header.size > 0 };
  const dv = new DataView(await file.slice(header.dataOffset, header.dataOffset + length).arrayBuffer());
  const raw = readUnsigned(dv, 0, dv.byteLength, issues, label);
  if (raw == null) return { value: null, truncated: header.size > length };
  const value = raw > BigInt(Number.MAX_SAFE_INTEGER) ? raw.toString() : Number(raw);
  return { value, truncated: header.size > length };
};

const parseAttachedFile = async (
  file: File,
  attachedFile: EbmlElementHeader,
  issues: Issues
): Promise<WebmAttachedFile> => {
  const result: WebmAttachedFile = {
    fileName: null,
    description: null,
    mediaType: null,
    uid: null,
    dataSize: null,
    truncated: false
  };
  if (attachedFile.size == null) {
    result.truncated = true;
    issues.push("AttachedFile uses unknown size; unable to parse attachment metadata.");
    return result;
  }

  const maxAvailable = Math.max(0, file.size - attachedFile.dataOffset);
  const limit = Math.min(attachedFile.size, maxAvailable);
  if (attachedFile.size > maxAvailable) result.truncated = true;

  let cursor = 0;
  let elementCount = 0;
  while (cursor < limit) {
    elementCount += 1;
    if (elementCount > MAX_ATTACHMENTS_ELEMENTS) {
      result.truncated = true;
      issues.push("Attachment parsing aborted: too many nested elements.");
      break;
    }
    const header = await readElementAt(file, attachedFile.dataOffset + cursor, issues);
    if (!header || header.headerSize === 0) break;
    if (header.size == null) {
      result.truncated = true;
      break;
    }

    if (header.id === FILE_NAME_ID) {
      const { value, truncated } = await readStringElement(file, header, issues, "FileName");
      result.fileName = value?.trim() || null;
      if (truncated) result.truncated = true;
    } else if (header.id === FILE_MEDIA_TYPE_ID) {
      const { value, truncated } = await readStringElement(file, header, issues, "FileMediaType");
      result.mediaType = value?.trim() || null;
      if (truncated) result.truncated = true;
    } else if (header.id === FILE_DESCRIPTION_ID) {
      const { value, truncated } = await readStringElement(file, header, issues, "FileDescription");
      result.description = value?.trim() || null;
      if (truncated) result.truncated = true;
    } else if (header.id === FILE_UID_ID) {
      const { value, truncated } = await readUnsignedElement(file, header, issues, "FileUID");
      result.uid = value;
      if (truncated) result.truncated = true;
    } else if (header.id === FILE_DATA_ID) {
      result.dataSize = header.size;
      if (header.size != null && header.dataOffset + header.size > file.size) {
        result.truncated = true;
        issues.push("FileData is truncated; attachment payload extends beyond file size.");
      }
    }

    const next = cursor + header.headerSize + header.size;
    if (next <= cursor) {
      result.truncated = true;
      break;
    }
    cursor = next;
  }

  if (cursor < attachedFile.size) result.truncated = true;
  return result;
};

export const parseAttachments = async (
  file: File,
  attachmentsHeader: EbmlElementHeader,
  issues: Issues
): Promise<WebmAttachments> => {
  const attachments: WebmAttachments = { files: [], truncated: false };
  if (attachmentsHeader.id !== ATTACHMENTS_ID) return attachments;

  const declaredSize = attachmentsHeader.size;
  const maxAvailable = Math.max(0, file.size - attachmentsHeader.dataOffset);
  const limit = Math.min(declaredSize ?? maxAvailable, maxAvailable);
  if (declaredSize != null && declaredSize > maxAvailable) attachments.truncated = true;

  let cursor = 0;
  let elementCount = 0;
  while (cursor < limit) {
    elementCount += 1;
    if (elementCount > MAX_ATTACHMENTS_ELEMENTS) {
      attachments.truncated = true;
      issues.push("Attachments parsing aborted: too many elements.");
      break;
    }
    const header = await readElementAt(file, attachmentsHeader.dataOffset + cursor, issues);
    if (!header || header.headerSize === 0) break;
    if (header.size == null) {
      attachments.truncated = true;
      break;
    }
    if (header.id === ATTACHED_FILE_ID) {
      const parsed = await parseAttachedFile(file, header, issues);
      attachments.files.push(parsed);
      if (attachments.files.length >= MAX_ATTACHMENTS_FILES) {
        attachments.truncated = true;
        issues.push("Too many attachments; stopping parsing.");
        break;
      }
      if (parsed.truncated) attachments.truncated = true;
    }
    const next = cursor + header.headerSize + header.size;
    if (next <= cursor) {
      attachments.truncated = true;
      break;
    }
    cursor = next;
  }

  if (declaredSize != null && cursor < declaredSize) attachments.truncated = true;
  return attachments;
};

