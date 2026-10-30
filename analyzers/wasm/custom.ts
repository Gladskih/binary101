import type { WasmReader } from "./reader.js";
import type { WasmParseResult, WasmSection } from "./types.js";

// https://webassembly.github.io/spec/core/appendix/custom.html#name-section
const readNameMap = async (reader: WasmReader, names: Record<number, string>): Promise<void> => {
  const count = await reader.count();
  let previous = -1;
  for (let index = 0; index < count; index++) {
    const target = await reader.u32();
    if (target <= previous) throw new Error("Name map indices are not strictly increasing");
    names[target] = await reader.name();
    previous = target;
  }
};

const parseNames = async (reader: WasmReader, result: WasmParseResult): Promise<void> => {
  let previous = -1;
  while (reader.remaining) {
    const id = await reader.byte();
    const payload = reader.child(await reader.u32());
    if (id <= previous) result.issues.push("Name subsections are duplicated or out of order");
    if (id === 0) result.moduleName = await payload.name();
    else if (id === 1) await readNameMap(payload, result.functionNames);
    else await payload.skip(payload.remaining);
    payload.finish();
    previous = id;
  }
};

const parseProducers = async (reader: WasmReader, result: WasmParseResult): Promise<void> => {
  // https://github.com/WebAssembly/tool-conventions/blob/main/ProducersSection.md
  const count = await reader.count();
  for (let index = 0; index < count; index++) {
    const field = await reader.name();
    const values = await reader.count();
    for (let value = 0; value < values; value++) {
      result.producers.push({ field, name: await reader.name(), version: await reader.name() });
    }
  }
};

const parseFeatures = async (reader: WasmReader, result: WasmParseResult): Promise<void> => {
  // https://github.com/WebAssembly/tool-conventions/blob/main/Linking.md#target-features-section
  const count = await reader.count();
  for (let index = 0; index < count; index++) {
    const prefix = await reader.byte();
    if (prefix !== 0x2b && prefix !== 0x2d) result.issues.push(`Unknown target feature prefix ${prefix}`);
    result.features.push({ prefix: String.fromCharCode(prefix), name: await reader.name() });
  }
};

export const parseCustom = async (reader: WasmReader, section: WasmSection,
  result: WasmParseResult): Promise<void> => {
  section.customName = await reader.name();
  switch (section.customName) {
    case "name": await parseNames(reader, result); break;
    case "producers": await parseProducers(reader, result); break;
    case "target_features": await parseFeatures(reader, result); break;
    default: await reader.skip(reader.remaining);
  }
};
