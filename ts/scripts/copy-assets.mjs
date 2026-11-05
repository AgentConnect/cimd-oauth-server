import { cp, mkdir } from "node:fs/promises";
await mkdir(
  new URL("../dist/packages/store-postgres/migrations/", import.meta.url),
  { recursive: true },
);
await cp(
  new URL(
    "../packages/store-postgres/migrations/001_machine.sql",
    import.meta.url,
  ),
  new URL(
    "../dist/packages/store-postgres/migrations/001_machine.sql",
    import.meta.url,
  ),
);
