"use strict";

import {
  createResourceDirectoryFixture,
  IMAGE_RESOURCE_DATA_ENTRY_SIZE
} from "../helpers/pe-resource-fixture.js";
import { createPeResourceSpecs } from "./pe-resource-preview-payloads.js";

export const RESOURCE_SECTION_RVA = 0x2000;

const align = (value: number, alignment: number): number =>
  Math.ceil(value / alignment) * alignment;

export const buildResourceSection = (): Uint8Array => {
  const specs = createPeResourceSpecs();
  const rootEntriesOffset = 16;
  let directoryOffset = rootEntriesOffset + specs.length * 8;
  const directoryRecords = specs.map(spec => {
    const nameDirectoryOffset = directoryOffset;
    directoryOffset += 24;
    const languageDirectoryOffset = directoryOffset;
    directoryOffset += 24;
    return { spec, nameDirectoryOffset, languageDirectoryOffset };
  });
  let dataEntryOffset = align(directoryOffset, 4);
  let payloadOffset = align(dataEntryOffset + specs.length * IMAGE_RESOURCE_DATA_ENTRY_SIZE, 4);
  const resourceBytes = createResourceDirectoryFixture(4096);

  resourceBytes.writeDirectory(0, 0, specs.length);
  directoryRecords.forEach((record, index) => {
    resourceBytes.writeDirectoryEntry(
      rootEntriesOffset + index * 8,
      record.spec.typeId,
      0x80000000 | record.nameDirectoryOffset
    );
    resourceBytes.writeDirectory(record.nameDirectoryOffset, 0, 1);
    resourceBytes.writeDirectoryEntry(
      record.nameDirectoryOffset + 16,
      record.spec.entryId,
      0x80000000 | record.languageDirectoryOffset
    );
    resourceBytes.writeDirectory(record.languageDirectoryOffset, 0, 1);
    resourceBytes.writeDirectoryEntry(
      record.languageDirectoryOffset + 16,
      record.spec.langId,
      dataEntryOffset
    );
    resourceBytes.writeDataEntry(
      dataEntryOffset,
      RESOURCE_SECTION_RVA + payloadOffset,
      record.spec.data.length,
      record.spec.codePage
    );
    resourceBytes.bytes.set(record.spec.data, payloadOffset);
    dataEntryOffset += IMAGE_RESOURCE_DATA_ENTRY_SIZE;
    payloadOffset = align(payloadOffset + record.spec.data.length, 4);
  });
  return resourceBytes.bytes.subarray(0, payloadOffset);
};
