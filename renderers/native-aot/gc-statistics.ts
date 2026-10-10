import type { NativeAotRuntimeType } from "../../analyzers/native-aot/runtime-type-map.js";
import type { AnalysisStatistic } from "../analysis-statistics.js";

export const nativeAotGcStatistics = (types: NativeAotRuntimeType[]): AnalysisStatistic[] => {
  const descriptors = types.flatMap(type => type.gcDescriptor ? [type.gcDescriptor] : []);
  return [
    { label: "Decoded GC layouts", value: descriptors.length,
      description: "Describe where the garbage collector finds object references; these are data, not code seeds." },
    { label: "Object reference regions", value: descriptors.reduce((count, descriptor) =>
      count + (descriptor.kind === "object" ? descriptor.series.length : 0), 0),
    description: "Consecutive reference fields share a region; separated fields require separate regions." },
    { label: "Arrays containing only references", value: descriptors.filter(descriptor =>
      descriptor.kind === "array-all-references").length,
    description: "Every element cell is a reference, so one region can describe an array of any length." },
    { label: "Arrays with mixed value layouts", value: descriptors.filter(descriptor =>
      descriptor.kind === "array-repeating").length,
    description: "A repeating pattern separates reference fields from ordinary data in each value-type element." },
    { label: "Metadata-only types with reference fields", value: types.filter(type =>
      (type.flags & 0x01000000) && !type.numVtableSlots).length,
    description: "These necessary MethodTables cannot be allocated and have no GC descriptor to decode." }
  ];
};
