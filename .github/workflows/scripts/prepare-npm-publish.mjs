import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";

const packageDir = process.argv[2];

if (!packageDir) {
  console.error("usage: prepare-npm-publish.mjs <package-dir>");
  process.exit(1);
}

const packagePath = path.join(packageDir, "package.json");
const pkg = JSON.parse(await readFile(packagePath, "utf8"));

for (const [name, spec] of Object.entries(pkg.dependencies ?? {})) {
  if (name.startsWith("@exowarexyz/") && typeof spec === "string" && spec.startsWith("file:")) {
    pkg.dependencies[name] = pkg.version;
  }
}

await writeFile(packagePath, `${JSON.stringify(pkg, null, 2)}\n`);
