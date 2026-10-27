import type { EhImage, MsvcEhAnalysis, MsvcEhRecord } from "./types.js";
import type { EhPersonality } from "./personality.js";
import type { PeLoadConfig, PeLoadConfigTable } from "../load-config/index.js";
import { ehMetadataRva } from "./validation.js";
import { parseFh3 } from "./fh3.js";
import { X86_RELATIVE_JUMP } from "../code-thunks/x86-encoding.js";

const sehRegistration = (rva: number, identity: EhPersonality | null): MsvcEhRecord | null => {
  if (identity?.name !== "_except_handler3" && identity?.name !== "_except_handler4") return null;
  // Handler identity is proven; stack registrations and encrypted scope tables are not decoded.
  // https://llvm.org/docs/ExceptionHandling.html#background-on-windows-exceptions
  return { handlerRva: rva, registration: identity.name,
    evidence: `SafeSEH allows this handler; ${identity.evidence}. Scope tables not decoded.`, functionRvas: [] };
};

const readFh3Stub = async (image: EhImage, handlerRva: number) => {
  // LLVM X86WinEHState.cpp emits EAX=FuncInfo; JMP __CxxFrameHandler3 and .safeseh.
  // MSVC 14.51 /Od also emits two one-byte NOPs; /O2 is tested without them.
  // https://github.com/llvm/llvm-project/blob/main/llvm/lib/Target/X86/X86WinEHState.cpp
  const first = await image.read(handlerRva, 2);
  const rva = first?.getUint16(0, true) === 0x9090 ? handlerRva + 2 : handlerRva;
  if (!image.code(rva, 10)) return null;
  const stub = await image.read(rva, 10);
  return stub && stub.getUint8(0) === 0xb8 && stub.getUint8(5) === X86_RELATIVE_JUMP.opcode
    ? { infoRva: ehMetadataRva(image, stub.getUint32(1, true)),
      target: rva + 5 + X86_RELATIVE_JUMP.length + stub.getInt32(5 + X86_RELATIVE_JUMP.displacement, true) }
    : null;
};

const analyzeHandler = async (
  image: EhImage, rva: number, resolve: (rva: number) => Promise<EhPersonality | null>
): Promise<MsvcEhRecord | string | null> => {
  const registration = sehRegistration(rva, await resolve(rva));
  if (registration) return registration;
  const stub = await readFh3Stub(image, rva);
  if (!stub) return null;
  const personality = await resolve(stub.target);
  if (personality?.name !== "__CxxFrameHandler3") return null;
  const info = await parseFh3(image, stub.infoRva);
  return info ? { handlerRva: rva, personality: personality.name,
    evidence: `SafeSEH entry, exact EAX/FuncInfo stub, ${personality.evidence}`,
    functionRvas: [], functionInfo: info } :
    `SafeSEH handler RVA 0x${rva.toString(16)} references ${personality.name}, but its FuncInfo metadata was not validated.`;
};

const readableSafeSehTable = (table: PeLoadConfigTable | undefined): table is PeLoadConfigTable =>
  table !== undefined && !table.truncated && !table.warnings?.length;

export const analyzeX86Eh = async (
  image: EhImage, resolve: (rva: number) => Promise<EhPersonality | null>, loadConfig?: PeLoadConfig | null
): Promise<MsvcEhAnalysis> => {
  const records: MsvcEhAnalysis["records"] = [];
  const warnings: string[] = [];
  const table = loadConfig?.tables?.safeSehHandler;
  if (!readableSafeSehTable(table)) return { records, warnings };
  for (const entry of table.entries) {
    const result = await analyzeHandler(image, entry.rva, resolve);
    if (typeof result === "string") warnings.push(result);
    else if (result) records.push(result);
  }
  return { records, warnings };
};
