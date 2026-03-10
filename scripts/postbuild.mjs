/**
 * Marks the CommonJS output directory as CJS.
 *
 * The root package.json declares `"type": "module"`, which would otherwise
 * cause Node to parse the `.js` files under dist/cjs as ESM. Dropping a
 * scoped package.json alongside them is the standard way to emit dual
 * ESM/CJS output from `tsc` alone, with no bundler involved.
 */
import { writeFileSync, existsSync, mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const cjsDir = resolve(root, "dist/cjs");

if (!existsSync(cjsDir)) {
    console.error("postbuild: dist/cjs is missing — did `npm run build:cjs` run?");
    process.exit(1);
}

mkdirSync(cjsDir, { recursive: true });
writeFileSync(
    resolve(cjsDir, "package.json"),
    JSON.stringify({ type: "commonjs" }, null, 2) + "\n",
);

console.log("postbuild: wrote dist/cjs/package.json");
