"use strict";

import type { RiffChunk } from "./types.js";

const walkChunks = (
  chunks: RiffChunk[] | null | undefined,
  visit: (chunk: RiffChunk) => void
): void => {
  if (!chunks) return;
  for (const chunk of chunks) {
    visit(chunk);
    if (chunk.children && chunk.children.length > 0) {
      walkChunks(chunk.children, visit);
    }
  }
};

export const flattenChunks = (chunks: RiffChunk[]): RiffChunk[] => {
  const all: RiffChunk[] = [];
  walkChunks(chunks, chunk => all.push(chunk));
  return all;
};

export const findFirstChunk = (chunks: RiffChunk[], id: string): RiffChunk | null => {
  let found: RiffChunk | null = null;
  walkChunks(chunks, chunk => {
    if (!found && chunk.id === id) found = chunk;
  });
  return found;
};

export const findListChunks = (chunks: RiffChunk[], listType: string): RiffChunk[] => {
  const matches: RiffChunk[] = [];
  walkChunks(chunks, chunk => {
    if (chunk.id === "LIST" && chunk.listType === listType) matches.push(chunk);
  });
  return matches;
};
