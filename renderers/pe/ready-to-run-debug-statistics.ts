import type { ReadyToRunDebugMethod } from "../../analyzers/pe/clr/ready-to-run-debug-types.js";
import type { AnalysisStatistic } from "../analysis-statistics.js";

export const readyToRunDebugStatistics = (methods: ReadyToRunDebugMethod[]): AnalysisStatistic[] => {
  const counts = { bounds: 0, il: 0, prologs: 0, epilogs: 0, calls: 0, emptyStack: 0,
    variables: 0, implicit: 0, byref: 0 };
  for (const method of methods) {
    for (const bound of method.bounds) {
      counts.bounds++;
      counts.il += Number(bound.ilOffset >= 0);
      counts.prologs += Number(bound.ilOffset === -2);
      counts.epilogs += Number(bound.ilOffset === -3);
      counts.calls += Number((bound.source & 20) !== 0);
      counts.emptyStack += Number((bound.source & 2) !== 0);
    }
    for (const variable of method.variables) {
      counts.variables++;
      counts.implicit += Number(variable.variableNumber < 0);
      counts.byref += Number(variable.location.kind === "register-byref" ||
        variable.location.kind === "stack-byref");
    }
  }
  return [
    { label: "Functions with debug records", value: methods.length,
      description: "Runtime functions whose compressed IL mappings or variable records were decoded." },
    { label: "Native/IL mappings", value: counts.bounds,
      description: "Mappings associate machine code positions with IL, prologs, epilogs or unmapped code." },
    { label: "Mappings to IL instructions", value: counts.il,
      description: "These mappings identify an actual IL byte offset rather than a special marker." },
    { label: "Prolog mappings", value: counts.prologs,
      description: "Prologs establish the native stack frame before the managed method body." },
    { label: "Epilog mappings", value: counts.epilogs,
      description: "Epilogs restore the native frame before returning from the method." },
    { label: "Call mappings", value: counts.calls,
      description: "The compiler marks call sites or call instructions for the debugger." },
    { label: "Empty evaluation-stack mappings", value: counts.emptyStack,
      description: "The managed IL evaluation stack is empty at these mapped positions." },
    { label: "Variable lifetime records", value: counts.variables,
      description: "A variable can move between registers and stack slots across native code ranges." },
    { label: "Implicit argument lifetimes", value: counts.implicit,
      description: "Hidden arguments can carry generic context, a return buffer or a varargs handle." },
    { label: "Indirect variable lifetimes", value: counts.byref,
      description: "The reported register or stack slot holds the variable's address instead of its value." }
  ];
};
