import type { ManagedGcInfo } from "../analyzers/native-aot/gc-info-types.js";
import type { AnalysisStatistic } from "./analysis-statistics.js";

export const managedGcStatistics = (methods: ManagedGcInfo[]): AnalysisStatistic[] => {
  // GcSlotFlags: INTERIOR=1, PINNED=2, UNTRACKED=4.
  // https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/inc/gcinfotypes.h
  const counts = { registers: 0, stack: 0, interior: 0, pinned: 0, untracked: 0,
    points: 0, ranges: 0, transitions: 0, partial: 0 };
  for (const method of methods) {
    for (const slot of method.slots) {
      counts.registers += Number(slot.kind === "register");
      counts.stack += Number(slot.kind === "stack");
      counts.interior += Number((slot.flags & 1) !== 0);
      counts.pinned += Number((slot.flags & 2) !== 0);
      counts.untracked += Number((slot.flags & 4) !== 0);
    }
    counts.points += method.safePoints.length;
    counts.ranges += method.interruptibleRanges.length;
    counts.transitions += method.transitions.length;
    counts.partial += Number(!!method.warnings?.length);
  }
  return [
    { label: "Methods with GC maps", value: methods.length,
      description: "Maps tell the collector where managed references survive in native code." },
    { label: "Register root slots", value: counts.registers,
      description: "Registers that may hold references; each method has its own slot numbering." },
    { label: "Stack root slots", value: counts.stack,
      description: "Frame-relative stack locations that may keep managed objects alive." },
    { label: "Interior root slots", value: counts.interior,
      description: "References may point inside an object rather than at its beginning." },
    { label: "Pinned root slots", value: counts.pinned,
      description: "These references prevent their target objects from moving during collection." },
    { label: "Untracked root slots", value: counts.untracked,
      description: "Roots reported throughout the method rather than through liveness transitions." },
    { label: "GC safe points", value: counts.points,
      description: "Call-return positions with reference liveness; these are not instruction-start seeds." },
    { label: "GC interruptible ranges", value: counts.ranges,
      description: "Code intervals where the collector can determine live references between calls." },
    { label: "Root liveness transitions", value: counts.transitions,
      description: "Changes in which tracked roots are live within interruptible code." },
    { label: "Partial GC maps", value: counts.partial,
      description: "Readable records retained with warnings when later data is malformed or truncated." }
  ];
};
