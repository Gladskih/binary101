import type { Amd64UnwindCodeStatus } from "./unwind-code-slots.js";
import { AMD64_UNWIND_OPERATION_NAMES } from "./unwind-operations.js";
import type { Amd64UnwindOpcode, Amd64UnwindOperationVisitor,
  Amd64UnwindV12Header, Amd64UnwindV12Statistics } from "./unwind-v12-types.js";

const registerName = (register: number): string =>
  ["RAX", "RCX", "RDX", "RBX", "RSP", "RBP", "RSI", "RDI"][register] ?? `R${register}`;

const incrementOrdered = (counts: Float64Array, order: number[], index: number): void => {
  if (counts[index] === 0) order.push(index);
  counts[index] = counts[index]! + 1;
};

const incrementMap = (counts: Map<number, number>, key: number): void => {
  counts.set(key, (counts.get(key) ?? 0) + 1);
};

const namedCounts = (counts: Float64Array, order: number[], name: (index: number) => string) =>
  Object.fromEntries(order.map(index => [name(index), counts[index]!]));

const numericCounts = (counts: Float64Array): Record<number, number> => {
  const result: Record<number, number> = {};
  for (let index = 0; index < counts.length; index++) {
    if (counts[index]) result[index] = counts[index]!;
  }
  return result;
};

/** One accumulator per scan. Decode directly into numeric counters, then build
 * public dictionaries once; codex.exe spent 0.21 s updating generic dictionaries.
 * Float64 counters retain JS-number counts without a 32-bit wraparound.
 */
export class Amd64UnwindV12StatisticsBuilder {
  #blocks = 0;
  #incomplete = 0;
  // UNWIND_CODE has four-bit opcode/register fields; UNWIND_INFO has byte
  // PrologSize and four-bit FrameOffset scaled by 16. These bound categories,
  // not the accepted number of records or the unbounded operand histograms.
  // https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64#struct-unwind_info
  readonly #operations = new Float64Array(16);
  readonly #registers = new Float64Array(32);
  readonly #frames = new Float64Array(16);
  readonly #frameOffsets = new Float64Array(256);
  readonly #prologs = new Float64Array(256);
  readonly #machineFrames = new Float64Array(2);
  readonly #operationOrder: number[] = [];
  readonly #registerOrder: number[] = [];
  readonly #frameOrder: number[] = [];
  readonly #allocations = new Map<number, number>();
  readonly #saveOffsets = new Map<number, number>();

  readonly visitOperation: Amd64UnwindOperationVisitor = (_codeOffset, opcode, info, operand) => {
    incrementOrdered(this.#operations, this.#operationOrder, opcode);
    if (opcode === 1 || opcode === 2) {
      incrementMap(this.#allocations, operand);
      return;
    }
    if (opcode === 10) {
      this.#machineFrames[info] = this.#machineFrames[info]! + 1;
      return;
    }
    if (opcode === 3) return;
    incrementOrdered(this.#registers, this.#registerOrder, info + (opcode >= 8 ? 16 : 0));
    if (opcode !== 0) incrementMap(this.#saveOffsets, operand);
  };

  recordBlock(header: Amd64UnwindV12Header, analysis: Amd64UnwindCodeStatus): void {
    this.#blocks++;
    if (analysis.isTruncated || analysis.issues.length) this.#incomplete++;
    this.#prologs[header.prologSize] = this.#prologs[header.prologSize]! + 1;
    if (header.frameRegister) {
      incrementOrdered(this.#frames, this.#frameOrder, header.frameRegister);
      this.#frameOffsets[header.frameOffset] = this.#frameOffsets[header.frameOffset]! + 1;
    }
  }

  build(): Amd64UnwindV12Statistics {
    return {
      blockCount: this.#blocks,
      incompleteBlockCount: this.#incomplete,
      operationCounts: namedCounts(this.#operations, this.#operationOrder,
        opcode => AMD64_UNWIND_OPERATION_NAMES[opcode as Amd64UnwindOpcode]),
      registerCounts: namedCounts(this.#registers, this.#registerOrder,
        index => index < 16 ? registerName(index) : `XMM${index - 16}`),
      allocationCounts: Object.fromEntries(this.#allocations),
      saveOffsetCounts: Object.fromEntries(this.#saveOffsets),
      frameRegisterCounts: namedCounts(this.#frames, this.#frameOrder, registerName),
      frameOffsetCounts: numericCounts(this.#frameOffsets),
      machineFrameCounts: {
        ...(this.#machineFrames[0] ? { 40: this.#machineFrames[0] } : {}),
        ...(this.#machineFrames[1] ? { 48: this.#machineFrames[1] } : {})
      },
      prologSizeCounts: numericCounts(this.#prologs)
    };
  }
}
