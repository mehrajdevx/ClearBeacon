import { readFile, writeFile } from "node:fs/promises";

const componentPath = new URL("../components/ui/liquid-sculpture-hero.tsx", import.meta.url);
const stylesheetPath = new URL("../public/liquid-sculpture-hero.css", import.meta.url);
const component = await readFile(componentPath, "utf8");
const match = component.match(/const CSS = `\r?\n([\s\S]*?)\r?\n`/);

if (!match) {
  throw new Error("Could not extract the liquid sculpture hero stylesheet.");
}

await writeFile(stylesheetPath, `${match[1].trim()}\n`, "utf8");
