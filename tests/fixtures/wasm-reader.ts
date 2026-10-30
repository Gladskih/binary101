import { WasmReader } from "../../analyzers/wasm/reader.js";
import { WasmStream } from "../../analyzers/wasm/stream.js";

export const wasmReader = (bytes: number[], chunkSize = Math.max(1, bytes.length)): WasmReader => {
  let position = 0;
  const stream = new ReadableStream<Uint8Array>({
    pull: controller => {
      if (position === bytes.length) { controller.close(); return; }
      controller.enqueue(new Uint8Array(bytes.slice(position, position + chunkSize)));
      position = Math.min(bytes.length, position + chunkSize);
    }
  });
  return new WasmReader(new WasmStream(stream.getReader(), bytes.length));
};
