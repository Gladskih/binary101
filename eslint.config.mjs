import js from "@eslint/js";
import globals from "globals";

const sharedRules = {
  "prefer-const": "error",
  "no-var": "error",
  "max-len": [
    "error",
    {
      code: 120,
      ignoreUrls: true,
      ignoreStrings: true,
      ignoreTemplateLiterals: true,
      ignoreRegExpLiterals: true,
      ignoreComments: true
    }
  ],
  "max-lines": [
    "error",
    {
      max: 300,
      skipComments: true
    }
  ]
};

/** @type {import("eslint").FlatConfig[]} */
export default [
  js.configs.recommended,
  {
    files: ["**/*.js"],
    languageOptions: {
      ecmaVersion: "latest",
      sourceType: "module",
      globals: {
        ...globals.browser
      }
    },
    rules: sharedRules
  },
  {
    files: ["tests/**/*.{js,mjs}", "playwright.config.mjs"],
    languageOptions: {
      ecmaVersion: "latest",
      sourceType: "module",
      globals: {
        ...globals.node
      }
    },
    rules: sharedRules
  }
];

