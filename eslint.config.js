import js from "@eslint/js";
import tseslint from "typescript-eslint";
import prettier from "eslint-config-prettier";

export default tseslint.config(
  // Global ignores
  {
    ignores: ["dist/**", "node_modules/**", "examples/appointments/run.ts"],
  },

  // Base JS recommended
  js.configs.recommended,

  // TypeScript recommended (non-type-checked to avoid tsconfig projection noise)
  ...tseslint.configs.recommended,

  // Prettier disables stylistic rules that conflict with formatter
  prettier,

  // Project-specific overrides
  {
    files: ["src/**/*.ts", "test/**/*.ts"],
    rules: {
      // Warn on any rather than error — intentional casts exist in the codebase
      "@typescript-eslint/no-explicit-any": "warn",
      // Catch unused vars (TypeScript-aware version)
      "@typescript-eslint/no-unused-vars": [
        "error",
        {
          argsIgnorePattern: "^_",
          varsIgnorePattern: "^_",
          ignoreRestSiblings: true,
        },
      ],
      // Turn off base rule in favor of TS-aware version
      "no-unused-vars": "off",
      // Allow empty catch blocks (intentional swallow-and-fallthrough patterns)
      "no-empty": ["error", { allowEmptyCatch: true }],
    },
  },
);
