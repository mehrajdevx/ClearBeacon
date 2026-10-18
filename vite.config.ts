import { copyFile, mkdir } from "node:fs/promises";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

const root = fileURLToPath(new URL(".", import.meta.url));
const require = createRequire(import.meta.url);

export default defineConfig({
  root,
  publicDir: false,
  plugins: [
    react(),
    {
      name: "copy-tesseract-runtime",
      async closeBundle() {
        const output = new URL("./public/assets/ocr/", import.meta.url);
        await mkdir(output, { recursive: true });
        await Promise.all([
          copyFile(
            require.resolve("tesseract.js/dist/worker.min.js"),
            new URL("worker.min.js", output),
          ),
          copyFile(
            require.resolve("tesseract.js-core/tesseract-core-lstm.wasm.js"),
            new URL("tesseract-core-lstm.wasm.js", output),
          ),
          copyFile(
            require.resolve("tesseract.js-core/tesseract-core-lstm.wasm"),
            new URL("tesseract-core-lstm.wasm", output),
          ),
        ]);
      },
    },
  ],
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
      input: {
        "sculpture-hero": "frontend/main.tsx",
        "qr-decoder": "frontend/qr-decoder.ts",
        "image-ocr": "frontend/image-ocr.tsx",
      },
      output: {
        entryFileNames: "[name].js",
        chunkFileNames: "sculpture-hero-[name].js",
        assetFileNames: "[name][extname]",
      },
    },
  },
});
