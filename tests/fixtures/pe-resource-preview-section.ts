"use strict";

import { createResourceDirectoryFixture, IMAGE_RESOURCE_DATA_ENTRY_SIZE } from "../helpers/pe-resource-fixture.js";
import { createPeResourceSpecs } from "./pe-resource-preview-payloads.js";

export const RESOURCE_SECTION_RVA = 0x2000;

const align = (value: number, alignment: number): number => Math.ceil(value / alignment) * alignment;

export const buildResourceSection = (): Uint8Array => {
  const specs = createPeResourceSpecs();
  const groups = new Map<number, typeof specs>();
  for (const spec of specs) groups.set(spec.typeId, [...(groups.get(spec.typeId) || []), spec]);
  let directoryOffset = 16 + groups.size * 8;
  const directories = [...groups.entries()].sort(([left], [right]) => left - right).map(([typeId, entries]) => {
    const nameOffset = directoryOffset;
    directoryOffset += 16 + entries.length * 8;
    const records = entries.sort((left, right) => left.entryId - right.entryId).map(spec => {
      const languageOffset = directoryOffset;
      directoryOffset += 24;
      return { spec, languageOffset };
    });
    return { typeId, nameOffset, records };
  });
  let dataEntryOffset = align(directoryOffset, 4);
  let payloadOffset = align(dataEntryOffset + specs.length * IMAGE_RESOURCE_DATA_ENTRY_SIZE, 4);
  const resourceBytes = createResourceDirectoryFixture(payloadOffset + specs.reduce(
    (sum, spec) => sum + align(spec.data.length, 4), 0));
  resourceBytes.writeDirectory(0, 0, groups.size);
  directories.forEach((group, groupIndex) => {
    resourceBytes.writeDirectoryEntry(16 + groupIndex * 8, group.typeId, 0x80000000 | group.nameOffset);
    resourceBytes.writeDirectory(group.nameOffset, 0, group.records.length);
    group.records.forEach((record, entryIndex) => {
      resourceBytes.writeDirectoryEntry(group.nameOffset + 16 + entryIndex * 8,
        record.spec.entryId, 0x80000000 | record.languageOffset);
      resourceBytes.writeDirectory(record.languageOffset, 0, 1);
      resourceBytes.writeDirectoryEntry(record.languageOffset + 16, record.spec.langId, dataEntryOffset);
      resourceBytes.writeDataEntry(dataEntryOffset, RESOURCE_SECTION_RVA + payloadOffset,
        record.spec.data.length, record.spec.codePage);
      resourceBytes.bytes.set(record.spec.data, payloadOffset);
      dataEntryOffset += IMAGE_RESOURCE_DATA_ENTRY_SIZE;
      payloadOffset = align(payloadOffset + record.spec.data.length, 4);
    });
  });
  return resourceBytes.bytes;
};
