import js from "@eslint/js";

const browserGlobals = {
  document: "readonly",
  Event: "readonly",
  localStorage: "readonly",
  navigator: "readonly",
  Number: "readonly",
  window: "readonly",
};

const nodeGlobals = {
  console: "readonly",
  module: "readonly",
  process: "readonly",
  URL: "readonly",
};

export default [
  {
    ignores: [
      "internal/web/static/htmx.min.js",
      "internal/web/static/tailwind.css",
      "node_modules/**",
    ],
  },
  js.configs.recommended,
  {
    files: [
      "internal/web/static/auto-refresh.js",
      "internal/web/static/theme-init.js",
    ],
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: "script",
      globals: browserGlobals,
    },
  },
  {
    files: ["scripts/build-web-assets.mjs"],
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: "module",
      globals: nodeGlobals,
    },
  },
];
