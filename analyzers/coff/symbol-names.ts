import { createPeSymbolNameDecoder } from "../pe/symbol-name.js";

// Keep presentation separate from linker identity and COFF auxiliary-record dispatch.
const displayNames = new WeakMap<{ name: string }, string>();

export const createCoffSymbolNameDecoder = (
  reportFailure: (message: string) => void, createDecoder = createPeSymbolNameDecoder
) => {
  const decode = createDecoder(message =>
    reportFailure("COFF symbol demangling unavailable: " + message));
  return async (symbol: { name: string }): Promise<void> => {
    const decoded = await decode(symbol.name);
    if (decoded) displayNames.set(symbol, decoded.text);
  };
};

export const getCoffSymbolDisplayName = (symbol: { name: string }): string =>
  displayNames.get(symbol) ?? symbol.name;
