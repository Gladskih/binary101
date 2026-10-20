import { PortablePdbTypeNames } from "./portable-pdb-type-names.js";
import type { PeClrMetadataTables } from "../clr/types.js";
import type { PeDebugSection } from "../core/parse-result.js";
import type { PortablePdbConstant } from "./portable-pdb-constants.js";
import type { PortablePdbLocal } from "./portable-pdb-types.js";

// Portable PDB LocalConstantSig: Decimal has sign/scale byte + 96-bit magnitude;
// DateTime is an int64 tick count, without DateTime kind/time-zone flags.
// https://github.com/dotnet/runtime/blob/main/docs/design/specs/PortablePdb-Metadata.md#localconstantsig-blob
const decimalValue = (bytes: number[]): string => {
  if (bytes.length !== 13) throw new Error("Decimal payload must contain 13 bytes");
  const scale = bytes[0]! & 127;
  if (scale > 28) throw new Error("Decimal scale exceeds 28");
  let magnitude = 0n;
  for (let index = 12; index >= 1; index--) magnitude = magnitude * 256n + BigInt(bytes[index]!);
  const digits = magnitude.toString().padStart(scale + 1, "0");
  const text = scale ? `${digits.slice(0, -scale)}.${digits.slice(-scale)}` : digits;
  return bytes[0]! & 128 && magnitude !== 0n ? `-${text}` : text;
};

const dateTimeValue = (bytes: number[]): string => {
  if (bytes.length !== 8) throw new Error("DateTime payload must contain eight bytes");
  const ticks = new DataView(Uint8Array.from(bytes).buffer).getBigInt64(0, true);
  // DateTime ticks: 100 ns since 0001-01-01; MaxValue is 9999-12-31T23:59:59.9999999.
  // https://github.com/dotnet/runtime/blob/main/src/libraries/System.Private.CoreLib/src/System/DateTime.cs
  if (ticks < 0n || ticks > 3155378975999999999n) throw new Error("DateTime ticks are out of range");
  const seconds = Number(ticks / 10000000n) * 1000 - 62135596800000;
  return `${new Date(seconds).toISOString().slice(0, 19)}.${(ticks % 10000000n).toString().padStart(7, "0")}`;
};

export const resolvePortablePdbConstantValue = (
  constant: PortablePdbConstant, typeName: string | null, issues: string[]
): PortablePdbConstant => {
  if (!constant.data?.length) return constant;
  if (typeName !== "System.Decimal" && typeName !== "System.DateTime") return constant;
  try {
    const { data, ...rest } = constant;
    return { ...rest, value: typeName === "System.Decimal" ? decimalValue(data) : dateTimeValue(data) };
  } catch (error) {
    issues.push(`Portable PDB local constant: ${(error as Error).message}.`);
    return constant;
  }
};


export const resolveDebugConstants = (
  debug: PeDebugSection | null, metadata: PeClrMetadataTables | undefined
): PeDebugSection | null => {
  if (!debug?.entries || !metadata) return debug;
  const names = new PortablePdbTypeNames(metadata);
  const decoded = new WeakMap<PortablePdbConstant, PortablePdbConstant>();
  const issues: string[] = [];
  const localValue = (local: PortablePdbLocal): PortablePdbLocal => {
    if (local.kind !== "constant" || !local.constant) return local;
    let constant = decoded.get(local.constant);
    if (!constant) {
      constant = resolvePortablePdbConstantValue(local.constant, names.get(local.constant.typeReference), issues);
      decoded.set(local.constant, constant);
    }
    return { ...local, constant };
  };
  const entries = debug.entries.map(entry => {
    const embedded = entry.embeddedPortablePdb;
    if (!embedded?.portablePdb) return entry;
    return { ...entry, embeddedPortablePdb: { ...embedded, portablePdb: {
      ...embedded.portablePdb, locals: embedded.portablePdb.locals.map(localValue)
    } } };
  });
  return { ...debug, entries, ...(issues.length
    ? { warning: [debug.warning, ...issues].filter(Boolean).join(" ") } : {}) };
};
