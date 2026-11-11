export const renderCollectionStart = (
  summaryHtml: string,
  count: number,
  attributesHtml = ""
): string => {
  if (!Number.isSafeInteger(count) || count < 1) return "";
  if (count === 1) {
    return `<section${attributesHtml}><h5 class="collectionSummary">${summaryHtml}</h5>`;
  }
  return `<details${attributesHtml}><summary class="collectionSummary">${summaryHtml}</summary>`;
};

export const renderCollectionEnd = (count: number): string =>
  !Number.isSafeInteger(count) || count < 1 ? "" : count === 1 ? "</section>" : "</details>";

export const renderCountedCollection = (
  summaryHtml: string,
  contentHtml: string,
  count: number,
  attributesHtml = ""
): string => {
  if (!Number.isSafeInteger(count) || count < 1) return "";
  return renderCollectionStart(summaryHtml, count, attributesHtml) + contentHtml + renderCollectionEnd(count);
};
