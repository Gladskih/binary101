import js from "@eslint/js";
import globals from "globals";
import tsParser from "@typescript-eslint/parser";
import tsPlugin from "@typescript-eslint/eslint-plugin";

const constantAliasRestrictedSyntaxRules = [
  {
    selector:
      'Program > VariableDeclaration[kind="const"] > VariableDeclarator[id.type="Identifier"][init.type="Identifier"]',
    message: "Constant aliases are forbidden. Import with an alias or use the original name directly."
  }
];

const restrictedSyntaxRules = [
  {
    selector: "ExportAllDeclaration[source]",
    message: "Re-exports are forbidden. Import explicitly in the target file instead."
  },
  {
    selector: "ExportNamedDeclaration[source]",
    message: "Re-exports are forbidden. Import explicitly in the target file instead."
  },
  ...constantAliasRestrictedSyntaxRules
];

const existingReExportFiles = [
  "analyzers/elf/disassembly.ts",
  "analyzers/index.ts",
  "analyzers/macho/index.ts",
  "analyzers/mpegps/index.ts",
  "analyzers/pcap/types.ts",
  "analyzers/pcapng/index.ts",
  "analyzers/pcapng/types.ts",
  "analyzers/pe/authenticode/pkijs-runtime.js",
  "analyzers/pe/clr/index.ts",
  "analyzers/pe/debug/directory.ts",
  "analyzers/pe/disassembly/entrypoint/iced.ts",
  "analyzers/pe/disassembly/index.ts",
  "analyzers/pe/exception/index.ts",
  "analyzers/pe/imports/linking.ts",
  "analyzers/pe/index.ts",
  "analyzers/pe/packers/index.ts",
  "analyzers/pe/resources/core.ts",
  "analyzers/probes.ts",
  "analyzers/rar/index.ts",
  "analyzers/riff/index.ts",
  "analyzers/sevenz/index.ts",
  "analyzers/tar/index.ts",
  "analyzers/zip/index.ts",
  "renderers/paged-sortable-table.ts",
  "renderers/index.ts",
  "renderers/pe/directories.ts",
  "renderers/pe/entrypoint-disassembly-explorer.ts",
  "renderers/pe/import-sections.ts",
  "tests/external/elf-wsl-readelf-fixtures.ts",
  "tests/fixtures/pe-debug-view-subject.ts",
  "ui/analysis-paged-tables.ts"
];

const sharedRules = {
  "prefer-const": "error",
  "no-var": "error",
  "no-param-reassign": "error",
  "no-restricted-syntax": ["error", ...restrictedSyntaxRules],
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
  ],
  "max-params": ["error", 8],
  "max-lines-per-function": [
    "error",
    {
      max: 100,
      IIFEs: true,
    }
  ]
};

const tsRuleOverrides = {
  "no-unused-vars": "off",
  "@typescript-eslint/no-unused-vars": [
    "error",
    {
      args: "all",
      argsIgnorePattern: "^_",
      varsIgnorePattern: "^_",
      caughtErrors: "none"
    }
  ],
  "@typescript-eslint/no-explicit-any": "error",
  "@typescript-eslint/no-unsafe-argument": "error",
  "@typescript-eslint/no-unsafe-assignment": "error",
  "@typescript-eslint/no-unsafe-call": "error",
  "@typescript-eslint/no-unsafe-member-access": "error",
  "@typescript-eslint/no-unsafe-return": "error",
  "@typescript-eslint/no-unsafe-unary-minus": "error",
  "@typescript-eslint/ban-ts-comment": [
    "error",
    {
      "ts-ignore": true,
      "ts-nocheck": true,
      "ts-check": false,
      "ts-expect-error": "allow-with-description",
      minimumDescriptionLength: 5
    }
  ],
  "@typescript-eslint/no-floating-promises": "error",
  "@typescript-eslint/no-misused-promises": "error",
  "@typescript-eslint/consistent-type-imports": [
    "error",
    {
      prefer: "type-imports",
      fixStyle: "separate-type-imports"
    }
  ]
};

/** @type {import("eslint").FlatConfig[]} */
export default [
  js.configs.recommended,
  {
    files: ["**/*.{js,mjs}"],
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
    ignores: ["tests/**/*", "scripts/**/*"],
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
      ...tsRuleOverrides
    }
  },
  {
    files: ["scripts/**/*.ts"],
    languageOptions: {
      parser: tsParser,
      parserOptions: {
        ecmaVersion: "latest",
        sourceType: "module",
        project: "./tsconfig.scripts.json"
      },
      globals: {
        ...globals.node
      }
    },
    plugins: {
      "@typescript-eslint": tsPlugin
    },
    rules: {
      ...sharedRules,
      ...tsRuleOverrides
    }
  },
  {
    files: ["tests/**/*.ts"],
    languageOptions: {
      parser: tsParser,
      parserOptions: {
        ecmaVersion: "latest",
        sourceType: "module",
        project: "./tsconfig.tests.json"
      },
      globals: {
        ...globals.node
      }
    },
    plugins: {
      "@typescript-eslint": tsPlugin
    },
    rules: {
      ...sharedRules,
      ...tsRuleOverrides
    }
  },
  {
    files: [
      "renderers/**/*.ts",
      "analyzers/lnk/**/*.ts",
      "analyzers/rar/**/*.ts"
    ],
    rules: {
      "@typescript-eslint/ban-ts-comment": "off"
    }
  },
  {
    files: existingReExportFiles,
    rules: {
      "no-restricted-syntax": ["error", ...constantAliasRestrictedSyntaxRules]
    }
  },
  {
    files: [
      "eslint.config.mjs",
      "playwright.config.mjs",
      "scripts/**/*.mjs",
      "tests/**/*.{js,mjs}"
    ],
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
    ignores: [
      "dist/**",
      "coverage/**",
      "test-results/**",
      ".stryker-tmp/**",
      "public/vendor/**"
    ]
  }
];

