import type { NativeAotFunctionMap, NativeAotFunctionMaps } from "./function-map-types.js";
import type { NativeAotMetadata, NativeAotMetadataSection } from "./format.js";
import type { NativeAotVirtualImage } from "./virtual-image-types.js";
import { NativeFormatCursor } from "./native-format-cursor.js";
import { NativeFormatReader, type NativeFormatLayout } from "./native-format-reader.js";
import { NativeAotFunctionReferences } from "./function-references.js";
import { NativeAotTemplateLayouts } from "./template-layout.js";
import { readClassConstructor } from "./class-constructors.js";
import { readNativeAotSectionBytes } from "./section-bytes.js";
import { readNativeAotHashEntries } from "./hash-map.js";
import { readStructMarshallingEntry } from "./struct-marshalling.js";
import { readDelegateMarshallingEntry } from "./delegate-marshalling.js";
import { readExactMethodEntry } from "./exact-methods.js";
import { readTemplateMethodEntry } from "./generic-templates.js";
import { NativeAotRuntimeTypes } from "./runtime-type-map.js";

// ReflectionMapBlob IDs are shifted by 300 in the NativeAOT ReadyToRun directory.
// https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/tools/Common/Internal/Runtime/MetadataBlob.cs
const isFunctionMapType = (type: number): type is NativeAotFunctionMap["type"] =>
  [301, 310, 316, 317, 321, 322, 336].includes(type);

const loadLayout = async (
  image: NativeAotVirtualImage, sections: NativeAotMetadataSection[], issues: Set<string>,
  wireLayout: NativeFormatLayout
): Promise<NativeFormatCursor> => {
  const layouts = sections.filter(section => section.type === 330);
  if (layouts.length !== 1) {
    issues.add("NativeLayoutInfo section is missing or ambiguous.");
    return new NativeFormatCursor(new NativeFormatReader(new Uint8Array()), 0);
  }
  return new NativeFormatCursor(new NativeFormatReader(
    await readNativeAotSectionBytes(image, layouts[0]!, issues), wireLayout), 0);
};

class FunctionMapReader {
  readonly #references: NativeAotFunctionReferences;
  readonly #layouts: NativeAotTemplateLayouts | undefined;
  readonly #types = new Map<number, number>();
  readonly #runtimeTypes: NativeAotRuntimeTypes;

  constructor(image: NativeAotVirtualImage, sections: NativeAotMetadataSection[],
    readonly layout: NativeFormatCursor | undefined, issues: Set<string>,
    version?: Pick<NativeAotMetadata, "majorVersion" | "minorVersion">) {
    this.#references = new NativeAotFunctionReferences(image, sections, issues);
    this.#runtimeTypes = new NativeAotRuntimeTypes(this.#references, version);
    this.#layouts = layout ? new NativeAotTemplateLayouts(layout, this.#references, issues) : undefined;
  }

  async read(type: NativeAotFunctionMap["type"], bytes: Uint8Array, issues: Set<string>):
  Promise<NativeAotFunctionMap> {
    if (type === 301) return { type, entries: await readNativeAotHashEntries(bytes,
      cursor => this.#runtimeTypes.read(cursor), issues), warnings: [...issues] };
    if (type === 310) return { type, entries: await readNativeAotHashEntries(bytes,
      cursor => readClassConstructor(cursor, this.#references), issues), warnings: [...issues] };
    if (type === 316) return { type, entries: await readNativeAotHashEntries(bytes,
      cursor => readStructMarshallingEntry(cursor, this.#references.common, issues), issues), warnings: [...issues] };
    if (type === 317) return { type, entries: await readNativeAotHashEntries(bytes,
      cursor => readDelegateMarshallingEntry(cursor, this.#references.common), issues), warnings: [...issues] };
    if (type === 321) return { type, entries: await readNativeAotHashEntries(bytes, async cursor => {
      const typeIndex = cursor.unsigned();
      const layoutOffset = cursor.unsigned();
      this.#references.common.validateDataIndex(typeIndex);
      return { typeIndex, layoutOffset, layout: await this.#layouts!.read(layoutOffset) };
    }, issues), warnings: [...issues] };
    if (type === 322) return { type, entries: await readNativeAotHashEntries(bytes,
      async cursor => {
        const entry = await readTemplateMethodEntry(cursor, this.layout!, this.#references.native, this.#types);
        return { ...entry, layout: await this.#layouts!.read(entry.layoutOffset) };
      }, issues), warnings: [...issues] };
    return { type, entries: await readNativeAotHashEntries(bytes,
      cursor => readExactMethodEntry(cursor, this.#references.native, this.layout), issues), warnings: [...issues] };
  }
}

const groupMaps = (sections: NativeAotMetadataSection[]) => {
  const groups = new Map<NativeAotFunctionMap["type"], NativeAotMetadataSection[]>();
  for (const section of sections) {
    if (!isFunctionMapType(section.type)) continue;
    const group = groups.get(section.type) ?? [];
    group.push(section);
    groups.set(section.type, group);
  }
  return groups;
};

const needsLayout = (groups: ReturnType<typeof groupMaps>, wireLayout: NativeFormatLayout): boolean =>
  groups.has(321) || groups.has(322) || (wireLayout === "dotnet9" && groups.has(336));

export const parseNativeAotFunctionMaps = async (
  image: NativeAotVirtualImage, sections: NativeAotMetadataSection[],
  version?: Pick<NativeAotMetadata, "majorVersion" | "minorVersion">
): Promise<NativeAotFunctionMaps | undefined> => {
  const groups = groupMaps(sections);
  if (!groups.size) return undefined;
  const issues = new Set<string>();
  const wireLayout = version && [9, 10].includes(version.majorVersion) ? "dotnet9" : "dotnet10";
  const layout = needsLayout(groups, wireLayout) ?
    await loadLayout(image, sections, issues, wireLayout) : undefined;
  const reader = new FunctionMapReader(image, sections, layout, issues, version);
  const maps: NativeAotFunctionMap[] = [];
  for (const [type, group] of groups) {
    if (group.length !== 1) {
      maps.push({ type, entries: [], warnings: ["NativeAOT function map section is ambiguous."] });
      continue;
    }
    const warnings = new Set<string>();
    const bytes = await readNativeAotSectionBytes(image, group[0]!, warnings);
    maps.push(await reader.read(type, bytes, warnings));
  }
  return { maps, warnings: [...issues] };
};
