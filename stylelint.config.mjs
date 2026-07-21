/** @type {import("stylelint").Config} */
export default {
  extends: ["stylelint-config-standard"],
  plugins: ["@stylistic/stylelint-plugin"],
  rules: {
    "@stylistic/max-line-length": 100,
    // Keep the established compact layout while enforcing a readable maximum line length.
    "at-rule-empty-line-before": null,
    "declaration-block-single-line-max-declarations": null,
    "rule-empty-line-before": null,
    // Components are independent, so global source order does not reflect their DOM relationship.
    "no-descending-specificity": null,
    "selector-class-pattern": "^[a-z][a-zA-Z0-9]*(?:(?:__|--)[a-z][a-zA-Z0-9]*)*$",
    "selector-id-pattern": "^[a-z][a-zA-Z0-9]*$",
    "keyframes-name-pattern": "^[a-z][a-zA-Z0-9]*$",
  },
};
