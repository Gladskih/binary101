import type { NativeAotFunctionMap } from "../../analyzers/native-aot/function-map-types.js";
import type { NativeAotRuntimeType } from "../../analyzers/native-aot/runtime-type-map.js";
import { collectNativeAotFunctionMapSeeds } from "../../analyzers/native-aot/function-map-seeds.js";
import type { AnalysisStatistic } from "../analysis-statistics.js";

const fact = (label: string, value: number, description: string): AnalysisStatistic => ({ label, value, description });
const distinct = (values: (number | null | undefined)[]): number =>
  new Set(values.filter(value => value != null)).size;

const typeStatistics = (types: NativeAotRuntimeType[]): AnalysisStatistic[] => {
  // HasFinalizer (0x00100000) and special dispatch slots (0xfffe/0xffff):
  // https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/tools/Common/Internal/Runtime/MethodTable.Constants.cs
  // https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/tools/Common/Internal/Runtime/RuntimeConstants.cs
  const slots = types.flatMap(type => type.slots);
  const sealed = types.flatMap(type => type.tail?.sealedSlots ?? []);
  const dispatch = types.flatMap(type => type.tail?.dispatchMap?.entries ?? []);
  return [
    fact("Decoded runtime types", types.length, "Runtime type layouts connect retained metadata to compiled code."),
    fact("Virtual method slots", slots.filter(slot => slot.kind === "method").length,
      "Slots that point into executable code; several types may share an implementation."),
    fact("Dictionary/data slots", slots.filter(slot => slot.kind === "data").length,
      "Generic context and other data are kept out of instruction seeds."),
    fact("Empty virtual slots", slots.filter(slot => slot.kind === "null").length,
      "Unused or unavailable entries do not identify code."),
    fact("Finalizable types", types.filter(type => type.flags & 0x00100000).length,
      "These types declare a finalizer, which the garbage collector can call."),
    fact("Distinct finalizer methods", distinct(types.map(type => type.tail?.finalizerRva)),
      "Validated finalizer code; inherited finalizers can be shared by many types."),
    fact("Interface dispatch records", dispatch.length,
      "Connections from interface methods to class or default implementations."),
    fact("Static interface dispatch records", dispatch.filter(entry => entry.kind.includes("static")).length,
      "Static virtual interface methods may also need a generic context."),
    fact("Special interface resolutions", dispatch.filter(entry => entry.implementationSlot >= 0xfffe).length,
      "Reabstraction or ambiguous diamond inheritance describes resolution failure, not a method."),
    fact("Referenced sealed slots", sealed.length,
      "Explicit dispatch references identify slots in a compact table that has no stored entry count."),
    fact("Distinct sealed methods", distinct(sealed.map(slot => slot.targetRva)),
      "Validated implementations omitted from ordinary virtual tables."),
    fact("Instantiating-thunk references", sealed.filter(slot => slot.requiresInstantiatingThunk).length,
      "Tagged interface targets require generic context; the tag is removed before disassembly.")
  ];
};

const marshallingStatistics = (map: Extract<NativeAotFunctionMap, { type: 316 | 317 }>): AnalysisStatistic[] => {
  if (map.type === 316) return [
    fact("Types with known native size", map.entries.filter(entry => entry.nativeSize !== undefined).length,
      "The unmanaged representation can differ from the managed object's layout."),
    fact("Named native fields", map.entries.reduce((count, entry) => count + entry.fields.length, 0),
      "Field names and offsets describe the unmanaged layout below."),
    fact("Marshal routines", distinct(map.entries.map(entry => entry.marshalRva)), "Convert managed values to native data."),
    fact("Unmarshal routines", distinct(map.entries.map(entry => entry.unmarshalRva)), "Convert native data to managed values."),
    fact("Cleanup routines", distinct(map.entries.map(entry => entry.cleanupRva)), "Release resources held by native data.")
  ];
  return [
    fact("Open static delegate stubs", distinct(map.entries.map(entry => entry.openStaticRva)),
      "Bridge an unmanaged call to a static managed delegate target."),
    fact("Closed delegate stubs", distinct(map.entries.map(entry => entry.closedRva)),
      "Bridge a call that retains a delegate instance or bound target."),
    fact("Forward-creation stubs", distinct(map.entries.map(entry => entry.forwardCreationRva)),
      "Create a managed wrapper for a native function pointer.")
  ];
};

const templateStatistics = (map: Extract<NativeAotFunctionMap, { type: 321 | 322 }>): AnalysisStatistic[] => [
  fact("Class constructors", distinct(map.entries.map(entry => entry.layout?.classConstructorRva)),
    "Type initialization code referenced by generic templates."),
  fact("Dictionary method references", map.entries.reduce((count, entry) =>
    count + (entry.layout?.dictionaryMethods.length ?? 0), 0),
  "Typed dictionary entries identify code; untyped dictionary data does not."),
  fact("Distinct dictionary methods", distinct(map.entries.flatMap(entry =>
    entry.layout?.dictionaryMethods.map(method => method.entrypointRva) ?? [])),
  "Generic templates can share the same compiled method bodies.")
];

export const nativeAotFunctionMapStatistics = (map: NativeAotFunctionMap): AnalysisStatistic[] => {
  const common = [
    fact("Map records", map.entries.length, "Retained records describe runtime relationships, not necessarily unique code."),
    fact("Distinct code entry points", collectNativeAotFunctionMapSeeds({ maps: [map], warnings: [] })[0]?.rvas.length ?? 0,
      "Validated instruction starts contributed by this map; other sources may identify the same methods.")
  ];
  if (map.type === 301) return [...common, ...typeStatistics([...new Set(map.entries.flatMap(entry =>
    entry.runtimeType ? [entry.runtimeType] : []))])];
  if (map.type === 316 || map.type === 317) return [...common, ...marshallingStatistics(map)];
  if (map.type === 321 || map.type === 322) return [...common, ...templateStatistics(map)];
  if (map.type === 336) return [...common, fact("Generic method instantiations",
    map.entries.filter(entry => entry.genericArgumentIndices.length).length,
    "Concrete generic arguments are associated with compiled method implementations.")];
  return common;
};
