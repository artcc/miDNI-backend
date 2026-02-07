import globals from "globals";
import js from "@eslint/js";

export default [
  js.configs.recommended,
  {
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: "commonjs",
      globals: {
        ...globals.node,
      },
    },
    rules: {
      "no-unused-vars": ["warn", { argsIgnorePattern: "^_" }],
      "no-console": "off",
      eqeqeq: "error",
      curly: ["error", "multi-line"],
      semi: ["error", "never"],
      "no-throw-literal": "error",
      "prefer-const": "error",
      "no-var": "error",
    },
  },
  {
    ignores: ["node_modules/", "coverage/", "dist/", "eslint.config.mjs"],
  },
];
