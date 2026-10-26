import { createDecoder } from "lzma-sdk-decode";

export const loadLzmaDecoder = async () => createDecoder();
