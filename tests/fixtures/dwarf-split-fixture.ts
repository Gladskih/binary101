import { createDwarfSectionFile } from "./dwarf-semantic-fixture.js";
import { createDwarf4LineSectionWithProgram } from "./dwarf-line-fixture.js";
import { concatenateBytes, encodeAbbreviationTable, encodeCString, encodeDwarf32Unit,
  encodeDwarf64Unit, encodeUint16, encodeUint32, encodeUint64 } from "./dwarf-fixture-encoding.js";

// DWARF 5 7.3.5, 7.5.1, 7.26: split unit and per-unit package contributions.
export const splitAbbreviations = (version = 5): number[] => encodeAbbreviationTable([
  { code: 1, tag: 0x11, children: 1, attributes: [
    { name: 3, form: version === 5 ? 0x1a : 0x1f02 },
    ...version === 5 ? [] : [{ name: 0x2131, form: 7 }], { name: 0x79, form: 0x17 }
  ] },
  { code: 2, tag: 0x24, children: 0, attributes: [
    { name: 3, form: version === 5 ? 0x1a : 0x1f02 }, { name: 0x0b, form: 0x0b }
  ] },
  { code: 3, tag: 0x2e, children: 0, attributes: [
    { name: 3, form: version === 5 ? 0x1a : 0x1f02 }, { name: 0x49, form: 0x13 },
    { name: 0x3a, form: 0x0b }, { name: 0x3b, form: 0x0b }
  ] }
]);

export const splitInformation = (signature = 2n, version = 5): number[] => {
  const root = concatenateBytes([1, 0], version === 5 ? [] : encodeUint64(signature), encodeUint32(0));
  return encodeDwarf32Unit(concatenateBytes(encodeUint16(version),
    version === 5 ? concatenateBytes([5, 8], encodeUint32(0), encodeUint64(signature))
      : concatenateBytes(encodeUint32(0), [8]),
    root, [2, 1, 4, 3, 2], encodeUint32((version === 5 ? 20 : 11) + root.length), [1, 7, 0]
  ));
};

const splitStrings = (source: string, name: string) => {
  const contents = [source, "int", name, "COUNT 42"].map(encodeCString);
  let offset = 0;
  return { bytes: contents.flat(), offsets: contents.map(bytes => {
    const start = offset;
    offset += bytes.length;
    return start;
  }) };
};

export const createDwarfSplitContents = (signature = 2n, version = 5, source = "main.c", name = "calculate") => {
  const strings = splitStrings(source, name);
  const offsets = strings.offsets.flatMap(encodeUint64);
  return [
    { name: ".debug_info.dwo", bytes: splitInformation(signature, version) },
    { name: ".debug_abbrev.dwo", bytes: splitAbbreviations(version) },
    { name: ".debug_str.dwo", bytes: strings.bytes },
    { name: ".debug_str_offsets.dwo", bytes: version === 5
      ? encodeDwarf64Unit(concatenateBytes(encodeUint16(5), encodeUint16(0), offsets))
      : strings.offsets.flatMap(encodeUint32) },
    { name: ".debug_line.dwo", bytes: createDwarf4LineSectionWithProgram([], source) },
    { name: ".debug_macro.dwo", bytes: concatenateBytes(encodeUint16(5), [2], encodeUint32(0),
      [3, 1, 1, 11, 0, 3, 4, 0]) }
  ];
};

export const createDwarfSplitFixture = (version = 5) => createDwarfSectionFile(createDwarfSplitContents(2n, version));

export const createDwarfPackageFixture = () => {
  const first = createDwarfSplitContents();
  const second = createDwarfSplitContents(3n, 5, "other.c", "otherFunction");
  const strings = first.find(section => section.name === ".debug_str.dwo")!.bytes;
  const otherOffsets = splitStrings("other.c", "otherFunction").offsets.map(offset => offset + strings.length);
  second.find(section => section.name === ".debug_str_offsets.dwo")!.bytes = encodeDwarf64Unit(
    concatenateBytes(encodeUint16(5), encodeUint16(0), otherOffsets.flatMap(encodeUint64)));
  const names = [".debug_info.dwo", ".debug_abbrev.dwo", ".debug_line.dwo", ".debug_str_offsets.dwo", ".debug_macro.dwo"];
  const sizes = names.map(name => first.find(section => section.name === name)!.bytes.length);
  return createDwarfSectionFile([
    { name: ".debug_cu_index", bytes: concatenateBytes([5, 0, 0, 0],
      [5, 2, 4].flatMap(encodeUint32), [0n, 0n, 2n, 3n].flatMap(encodeUint64),
      [0, 0, 1, 2, 1, 3, 4, 6, 7].flatMap(encodeUint32),
      [...sizes.map(() => 0), ...sizes, ...sizes,
        ...names.map(name => second.find(section => section.name === name)!.bytes.length)].flatMap(encodeUint32)) },
    ...first.map(section => ({ name: section.name, bytes: concatenateBytes(section.bytes,
      second.find(other => other.name === section.name)!.bytes) }))
  ]);
};

export const splitSkeleton = (filename = "main.dwo", signature = 2n): number[] => encodeDwarf32Unit(
  concatenateBytes(encodeUint16(5), [4, 8], encodeUint32(0), encodeUint64(signature), [1],
    encodeCString(filename), encodeUint32(8))
);

export const splitSkeletonAbbreviations = (): number[] => encodeAbbreviationTable([
  { code: 1, tag: 0x4a, children: 0, attributes: [{ name: 0x76, form: 8 }, { name: 0x73, form: 0x17 }] }
]);

export const splitTypeInformation = (signature = 7n): number[] => encodeDwarf32Unit(
  concatenateBytes(encodeUint16(4), encodeUint32(0), [8], encodeUint64(signature), encodeUint32(23), [1])
);

