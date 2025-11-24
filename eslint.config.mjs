import js from "@eslint/js";
import globals from "globals";
import tsParser from "@typescript-eslint/parser";
import tsPlugin from "@typescript-eslint/eslint-plugin";

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
    files: ["**/*.ts"],
    languageOptions: {
      parser: tsParser,
      parserOptions: {
        ecmaVersion: "latest",
        sourceType: "module",
        project: "./tsconfig.json"
      },
      globals: {
        ...globals.browser
      }
    },
    plugins: {
      "@typescript-eslint": tsPlugin
    },
    rules: {
      ...sharedRules,
      "no-unused-vars": "off",
      "@typescript-eslint/no-unused-vars": [
        "error",
        {
          args: "all",
          argsIgnorePattern: "^_",
          varsIgnorePattern: "^_",
          caughtErrors: "none"
        }
      ]
    }
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
  },
  {
    ignores: ["dist/**", "coverage/**", "test-results/**"]
  }
];

