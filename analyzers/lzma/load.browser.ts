import wasmURL from "lzma-sdk-decode/lzma-sdk-decode.wasm?url";
import { createDecoder } from "lzma-sdk-decode";

export const loadLzmaDecoder = async () => createDecoder({ wasmURL });
