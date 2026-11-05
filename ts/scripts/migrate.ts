import { readFile } from "node:fs/promises";
import { Pool } from "pg";
import { required } from "../examples/config.js";
const pool = new Pool({ connectionString: required("DATABASE_URL") });
const client = await pool.connect();
try {
  await client.query("BEGIN");
  await client.query("SELECT pg_advisory_xact_lock(573015038)");
  await client.query(
    await readFile(
      new URL(
        "../packages/store-postgres/migrations/001_machine.sql",
        import.meta.url,
      ),
      "utf8",
    ),
  );
  await client.query("COMMIT");
  process.stdout.write("Migration 1 applied\n");
} catch {
  await client.query("ROLLBACK");
  process.stderr.write("Migration failed\n");
  process.exitCode = 1;
} finally {
  client.release();
  await pool.end();
}
