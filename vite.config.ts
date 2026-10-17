import { fileURLToPath } from "node:url";
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

const root = fileURLToPath(new URL(".", import.meta.url));

export default defineConfig({
  root,
  publicDir: false,
  plugins: [react()],
  resolve: {
    alias: {
      "@": root,
    },
  },
  build: {
    outDir: "public/assets",
    emptyOutDir: false,
    target: "es2022",
    rollupOptions: {
      input: "frontend/main.tsx",
      output: {
        entryFileNames: "sculpture-hero.js",
        chunkFileNames: "sculpture-hero-[name].js",
        assetFileNames: "[name][extname]",
        inlineDynamicImports: true,
      },
    },
  },
});
