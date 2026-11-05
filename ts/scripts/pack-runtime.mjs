/** Private runtime pack with a derived registry lock; no publish or test lifecycle. */
import { access, mkdir, readFile, writeFile, unlink } from "node:fs/promises";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { resolve } from "node:path";
const manifest = JSON.parse(await readFile("package.json", "utf8"));
if (manifest.private !== true)
  throw new Error("Runtime package must remain private");
for (const asset of [
  "dist/examples/authorization-server/main.js",
  "dist/examples/minimal-mcp-server/main.js",
  "dist/packages/store-postgres/migrations/001_machine.sql",
])
  await access(asset);
const destination = resolve(
  process.argv[2] ?? `.artifacts/runtime-pack-${Date.now()}`,
);
await mkdir(destination, { recursive: true });
const derived = await readFile("package-lock.json");
const sha = (value) => createHash("sha256").update(value).digest("hex");
let created = false;
try {
  await writeFile("npm-shrinkwrap.json", derived, { flag: "wx", mode: 0o644 });
  created = true;
  const output = execFileSync(
    "npm",
    ["pack", "--ignore-scripts", "--json", "--pack-destination", destination],
    { encoding: "utf8" },
  );
  const result = JSON.parse(output)[0];
  const files = result.files.map((file) => file.path);
  if (
    !files.includes("npm-shrinkwrap.json") ||
    files.some((file) =>
      /(^|\/)\.(artifacts|local)(\/|$)|(^|\/)\.env$|\.log$|\.tap$|^tests\//.test(
        file,
      ),
    )
  )
    throw new Error("Runtime package inclusion policy failed");
  process.stdout.write(
    JSON.stringify({
      private: true,
      destination,
      filename: result.filename,
      integrity: result.integrity,
      shasum: result.shasum,
      entryCount: result.entryCount,
      unpackedSize: result.unpackedSize,
      registryLockSha256: sha(derived),
      executionDataExcluded: true,
    }) + "\n",
  );
} finally {
  if (created) {
    if (sha(await readFile("npm-shrinkwrap.json")) !== sha(derived))
      throw new Error("Derived shrinkwrap changed; retained for review");
    await unlink("npm-shrinkwrap.json");
  }
}
