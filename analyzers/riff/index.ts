"use strict";

export type { RiffChunk, RiffParseResult, RiffParserOptions, RiffStats } from "./types.js";
export { parseRiff, parseRiffFromView, readFourCc } from "./chunk-parser.js";
export { flattenChunks, findFirstChunk, findListChunks } from "./chunk-query.js";
export type { RiffInfoTag } from "./info-tags.js";
export { parseInfoTags } from "./info-tags.js";
