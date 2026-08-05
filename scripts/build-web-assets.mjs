import { copyFile, mkdir } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../", import.meta.url));
const htmxSource = resolve(root, "node_modules", "htmx.org", "dist", "htmx.min.js");
const htmxDest = resolve(root, "internal", "web", "static", "htmx.min.js");

await mkdir(dirname(htmxDest), { recursive: true });
await copyFile(htmxSource, htmxDest);

console.log(`Copied ${htmxSource} -> ${htmxDest}`);
