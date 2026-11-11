export const markSupplementalAnalysis = (html: string): string =>
  html.replace(/^<section\b/u, '<section data-analysis-origin="supplemental"');
