// WebAssembly core binary grammar: https://webassembly.github.io/spec/core/binary/modules.html
export const wasmUnsigned = (value: number): number[] => {
  const bytes: number[] = [];
  let remaining = value;
  do {
    const byte = remaining % 128;
    remaining = Math.floor(remaining / 128);
    bytes.push(byte | (remaining ? 0x80 : 0));
  } while (remaining);
  return bytes;
};

export const wasmString = (value: string): number[] => {
  const bytes = [...new TextEncoder().encode(value)];
  return [...wasmUnsigned(bytes.length), ...bytes];
};

export const wasmSection = (id: number, payload: number[]): number[] =>
  [id, ...wasmUnsigned(payload.length), ...payload];

export const wasmModule = (...sections: number[][]): File =>
  new File([new Uint8Array([0, 97, 115, 109, 1, 0, 0, 0, ...sections.flat()])],
    "analysis-demo.wasm", { type: "application/wasm" });

export const createWasmFile = (): File => wasmModule(
  wasmSection(1, [3, 0x60, 1, 0x7f, 0, 0x60, 2, 0x7f, 0x7f, 1, 0x7f, 0x60, 0, 0]),
  wasmSection(2, [1, ...wasmString("env"), ...wasmString("log"), 0, 0]),
  wasmSection(3, [2, 1, 2]),
  wasmSection(4, [1, 0x70, 1, 1, 4]),
  wasmSection(5, [1, 1, 1, 2]),
  wasmSection(6, [1, 0x7f, 0, 0x41, 42, 0x0b]),
  wasmSection(7, [4, ...wasmString("add"), 0, 1, ...wasmString("memory"), 2, 0,
    ...wasmString("callbacks"), 1, 0, ...wasmString("answer"), 3, 0]),
  wasmSection(8, [2]),
  wasmSection(9, [1, 0, 0x41, 0, 0x0b, 1, 1]),
  wasmSection(10, [2, 7, 0, 0x20, 0, 0x20, 1, 0x6a, 0x0b,
    6, 0, 0x41, 42, 0x10, 0, 0x0b]),
  wasmSection(11, [1, 0, 0x41, 0, 0x0b, ...wasmString("Hello, WebAssembly!")]),
  wasmSection(0, [...wasmString("name"), ...wasmSection(0, wasmString("analysis-demo")),
    ...wasmSection(1, [3, 0, ...wasmString("log"), 1, ...wasmString("add"),
      2, ...wasmString("initialize")])]),
  wasmSection(0, [...wasmString("producers"), 1, ...wasmString("processed-by"), 1,
    ...wasmString("Binary101 fixture"), ...wasmString("1")]),
  wasmSection(0, [...wasmString("target_features"), 1, 0x2b, ...wasmString("mutable-globals")])
);
