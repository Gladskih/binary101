import { createPeResourcePreviewFile, RESOURCE_SECTION_RAW_OFFSET } from "./pe-resource-preview-file.js";
import { RESOURCE_SECTION_RVA } from "./pe-resource-preview-section.js";
import {
  createResourceDirectoryFixture, IMAGE_RESOURCE_DIRECTORY_SIZE,
  IMAGE_RESOURCE_DIRECTORY_ENTRY_SIZE, IMAGE_RESOURCE_DATA_ENTRY_SIZE,
  resourceNameString, resourceSubdirectory
} from "../helpers/pe-resource-fixture.js";
import { MockFile } from "../helpers/mock-file.js";

export const REGISTRAR_SCRIPT = [
  // Registrar CLSID/ProgID from Microsoft's example, extended with values and recovery case:
  // https://learn.microsoft.com/en-us/cpp/atl/registry-scripting-examples
  "HKCR", "{", "    ATL.Registrar = s 'ATL Registrar Class'",
  "    { CLSID = s '{44EC053A-400F-11D0-9DCD-00A0C90391D3}' }",
  "    NoRemove CLSID", "    {",
  "        ForceRemove {44EC053A-400F-11D0-9DCD-00A0C90391D3} = s 'ATL Registrar Class'",
  "        {", "            ProgID = s 'ATL.Registrar'",
  "            InprocServer32 = s '%MODULE%'",
  "            { val ThreadingModel = s 'Apartment' }", "        }", "    }", "}",
  "HKCU { NoRemove Software { Sample { val Enabled = d '1'",
  "val Names = m 'one\\0two' val Bytes = b '00aaff' val Unsafe = s '<script>alert(1)</script>' } } }",
  "HKLM { Broken ="
].join("\r\n");

export const createPeRegistryFile = (text = REGISTRAR_SCRIPT, resourceCount = 1): MockFile => {
  const bytes = createPeResourcePreviewFile().data;
  const script = new TextEncoder().encode(text);
  const typeName = "REGISTRY";
  // Root header + one type entry; type header + resourceCount entries; then one
  // language header/entry and one data entry per resource. Sizes/flag bits come from:
  // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#resource-directory-table
  const typeOffset = IMAGE_RESOURCE_DIRECTORY_SIZE + IMAGE_RESOURCE_DIRECTORY_ENTRY_SIZE;
  const typeEntriesOffset = typeOffset + IMAGE_RESOURCE_DIRECTORY_SIZE;
  const languageDirectorySize = IMAGE_RESOURCE_DIRECTORY_SIZE + IMAGE_RESOURCE_DIRECTORY_ENTRY_SIZE;
  const languageOffset = typeEntriesOffset + resourceCount * IMAGE_RESOURCE_DIRECTORY_ENTRY_SIZE;
  const dataOffset = languageOffset + resourceCount * languageDirectorySize;
  const nameOffset = dataOffset + resourceCount * IMAGE_RESOURCE_DATA_ENTRY_SIZE;
  // A resource name has a 2-byte length and 2 bytes per UTF-16 code unit (same PE section).
  // Fixture policy: pad the payload to a data-entry-sized boundary for readable offsets.
  // ceil(end/alignment)*alignment is the first such boundary at or after the name end.
  const payloadOffset = Math.ceil((nameOffset + 2 + typeName.length * 2) /
    IMAGE_RESOURCE_DATA_ENTRY_SIZE) * IMAGE_RESOURCE_DATA_ENTRY_SIZE;
  const resources = createResourceDirectoryFixture(payloadOffset + script.length);
  resources.writeDirectory(0, 1, 0);
  resources.writeDirectoryEntry(IMAGE_RESOURCE_DIRECTORY_SIZE,
    resourceNameString(nameOffset), resourceSubdirectory(typeOffset));
  resources.writeUtf16Label(nameOffset, typeName);
  resources.writeDirectory(typeOffset, 0, resourceCount);
  for (let index = 0; index < resourceCount; index += 1) {
    // IDs starting at 101 are fixture policy. LANGID 0x0409 = 1033 is en-US; CP 65001 is UTF-8.
    // https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-lcid/
    // https://learn.microsoft.com/en-us/windows/win32/intl/code-page-identifiers
    resources.writeDirectoryEntry(typeEntriesOffset + index * IMAGE_RESOURCE_DIRECTORY_ENTRY_SIZE,
      101 + index, resourceSubdirectory(languageOffset + index * languageDirectorySize));
    resources.writeDirectory(languageOffset + index * languageDirectorySize, 0, 1);
    resources.writeDirectoryEntry(languageOffset + index * languageDirectorySize +
      IMAGE_RESOURCE_DIRECTORY_SIZE, 1033, dataOffset + index * IMAGE_RESOURCE_DATA_ENTRY_SIZE);
    resources.writeDataEntry(dataOffset + index * IMAGE_RESOURCE_DATA_ENTRY_SIZE,
      RESOURCE_SECTION_RVA + payloadOffset, script.length, 65001);
  }
  resources.bytes.set(script, payloadOffset);
  bytes.fill(0, RESOURCE_SECTION_RAW_OFFSET);
  bytes.set(resources.bytes, RESOURCE_SECTION_RAW_OFFSET);
  return new MockFile(bytes, "atl-registry.dll");
};
