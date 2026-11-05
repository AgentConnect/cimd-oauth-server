import { randomBytes, randomUUID, timingSafeEqual } from "node:crypto";
import { Pool, type PoolClient } from "pg";
import { digest, httpsUrl, scopes } from "../oauth-core/parse.js";
import { fail, ProtocolError } from "../oauth-core/errors.js";
import type { VerifiedClient } from "../oauth-core/client.js";
export type Policy = {
  resource: string;
  scopes: string[];
  ttl: number;
  maxNewClientsHour: number;
  maxRequestsClientMinute: number;
  maxRequestsMinute: number;
  custodyCondition: string;
  enabled: boolean;
};
export type TokenResult = {
  access_token: string;
  token_type: "Bearer";
  expires_in: number;
  scope: string;
};
export class PostgresStore {
  readonly namespace: string;
  constructor(
    readonly pool: Pool,
    readonly issuer: string,
  ) {
    this.namespace = digest(issuer);
  }
  async ready(): Promise<void> {
    const r = await this.pool.query(
      "SELECT max(version) AS version FROM schema_migrations",
    );
    if (r.rows[0]?.version !== 1) fail("schema_unavailable", 503);
    if (
      !(
        await this.pool.query(
          "SELECT 1 FROM request_limits WHERE namespace=$1",
          [this.namespace],
        )
      ).rowCount
    )
      fail("admission_unconfigured", 503);
  }
  async isBlocked(clientId: string): Promise<boolean> {
    const r = await this.pool.query(
      "SELECT blocked FROM client_blocks WHERE namespace=$1 AND client_id=$2",
      [this.namespace, clientId],
    );
    return r.rows[0]?.blocked === true;
  }
  async configureRequestLimits(limits: {
    globalMinute: number;
    originMinute: number;
    clientMinute: number;
    sourceMinute: number;
  }): Promise<void> {
    if (
      !Object.values(limits).every(
        (n) => Number.isInteger(n) && n > 0 && n <= 100000,
      )
    )
      fail("invalid_request_limits");
    await this.pool.query(
      `INSERT INTO request_limits(namespace,global_minute,origin_minute,client_minute,source_minute) VALUES($1,$2,$3,$4,$5)
      ON CONFLICT(namespace) DO UPDATE SET global_minute=EXCLUDED.global_minute,origin_minute=EXCLUDED.origin_minute,client_minute=EXCLUDED.client_minute,source_minute=EXCLUDED.source_minute`,
      [
        this.namespace,
        limits.globalMinute,
        limits.originMinute,
        limits.clientMinute,
        limits.sourceMinute,
      ],
    );
  }
  async preflight(clientId: string, source: string): Promise<void> {
    const origin = httpsUrl(clientId).origin;
    const accepted = await this.transaction(
      `preflight:${this.namespace}`,
      async (c) => {
        const limits = (
          await c.query(
            "SELECT * FROM request_limits WHERE namespace=$1 FOR UPDATE",
            [this.namespace],
          )
        ).rows[0];
        if (!limits) fail("admission_unconfigured", 503);
        const minute = Math.floor(Date.now() / 60000);
        // Global first: rejected floods never allocate unbounded attacker-selected buckets.
        for (const [bucket, limit] of [
          ["preflight:global", limits.global_minute],
          [`preflight:origin:${digest(origin)}`, limits.origin_minute],
          [`preflight:client:${digest(clientId)}`, limits.client_minute],
          [`preflight:source:${digest(source)}`, limits.source_minute],
        ] as const) {
          const r = await c.query(
            `INSERT INTO rate_buckets(namespace,bucket,window_start,expires_at,count) VALUES($1,$2,$3,to_timestamp((($3::bigint+1)*60)::double precision),1)
          ON CONFLICT(namespace,bucket,window_start) DO UPDATE SET count=rate_buckets.count+1 RETURNING count`,
            [this.namespace, bucket, minute],
          );
          if (r.rows[0].count > limit) return false;
        }
        return true;
      },
    );
    if (!accepted) fail("temporarily_unavailable", 429);
  }
  async configurePolicy(p: Policy): Promise<void> {
    httpsUrl(p.resource);
    scopes(p.scopes.join(" "));
    if (
      !p.custodyCondition ||
      ![
        p.ttl,
        p.maxNewClientsHour,
        p.maxRequestsClientMinute,
        p.maxRequestsMinute,
      ].every((n) => Number.isInteger(n) && n > 0) ||
      p.ttl > 3600
    )
      fail("invalid_policy");
    await this.pool.query(
      `INSERT INTO admission_policies(namespace,resource,enabled,scopes,ttl,max_new_clients_hour,max_requests_client_minute,max_requests_minute,custody_condition)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT(namespace,resource) DO UPDATE SET
      enabled=EXCLUDED.enabled, scopes=EXCLUDED.scopes,ttl=EXCLUDED.ttl,max_new_clients_hour=EXCLUDED.max_new_clients_hour,
      max_requests_client_minute=EXCLUDED.max_requests_client_minute,max_requests_minute=EXCLUDED.max_requests_minute,
      custody_condition=EXCLUDED.custody_condition,generation=admission_policies.generation+1`,
      [
        this.namespace,
        p.resource,
        p.enabled,
        [...new Set(p.scopes)].sort(),
        p.ttl,
        p.maxNewClientsHour,
        p.maxRequestsClientMinute,
        p.maxRequestsMinute,
        p.custodyCondition,
      ],
    );
  }
  async provisionResourceServer(
    id: string,
    secret: string,
    resources: string[],
  ): Promise<void> {
    if (
      !/^[A-Za-z0-9_-]{1,128}$/.test(id) ||
      Buffer.byteLength(secret) < 32 ||
      secret.includes(":") ||
      !resources.length
    )
      fail("invalid_rs_configuration");
    resources.forEach(httpsUrl);
    await this.pool.query(
      `INSERT INTO resource_servers(namespace,id,secret_digest,resources) VALUES($1,$2,$3,$4)
      ON CONFLICT(namespace,id) DO UPDATE SET secret_digest=EXCLUDED.secret_digest,resources=EXCLUDED.resources,enabled=true`,
      [this.namespace, id, digest(secret), resources],
    );
  }
  private async lock(c: PoolClient, clientId: string): Promise<void> {
    await c.query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))", [
      `${this.namespace}:${clientId}`,
    ]);
  }
  private async replay(c: PoolClient, v: VerifiedClient): Promise<boolean> {
    const now = Math.floor(Date.now() / 1000);
    if (
      v.issuer !== this.issuer ||
      v.metadataExpires <= now ||
      v.expires + 5 <= now ||
      v.issuedAt > now + 5
    )
      return false;
    const r = await c.query(
      `INSERT INTO assertion_replays(namespace,client_id,jti_digest,expires_at) VALUES($1,$2,$3,to_timestamp($4)) ON CONFLICT DO NOTHING RETURNING jti_digest`,
      [this.namespace, v.clientId, v.jtiDigest, v.expires + 5],
    );
    return r.rowCount === 1;
  }
  private async transaction<T>(
    clientId: string,
    f: (c: PoolClient) => Promise<T>,
  ): Promise<T> {
    const c = await this.pool.connect();
    let committed = false;
    try {
      await c.query("BEGIN");
      await c.query("SET LOCAL statement_timeout='5s'");
      await c.query("SET LOCAL lock_timeout='3s'");
      await this.lock(c, clientId);
      const value = await f(c);
      await c.query("COMMIT");
      committed = true;
      return value;
    } catch (error) {
      // COMMIT acknowledgement may be lost. Never retry an assertion or issue another token here.
      if (!committed) await c.query("ROLLBACK").catch(() => {});
      throw error;
    } finally {
      c.release();
    }
  }
  private async audit(
    c: PoolClient,
    clientId: string,
    category: string,
    generation?: string,
  ): Promise<void> {
    await c.query(
      "INSERT INTO audit_events(namespace,client_ref,category,policy_generation) VALUES($1,$2,$3,$4)",
      [this.namespace, digest(clientId), category, generation ?? null],
    );
  }
  async issue(
    v: VerifiedClient,
    resource: string,
    requested: string[],
  ): Promise<TokenResult> {
    const result = await this.transaction(v.clientId, async (c) => {
      if (!(await this.replay(c, v))) return { error: "invalid_client" };
      const deny = async (error: string, generation?: string) => {
        await this.audit(c, v.clientId, error, generation);
        return { error };
      };
      if (
        (
          await c.query(
            "SELECT blocked FROM client_blocks WHERE namespace=$1 AND client_id=$2",
            [this.namespace, v.clientId],
          )
        ).rows[0]?.blocked
      )
        return deny("unauthorized_client");
      try {
        requested = scopes(requested.join(" "));
      } catch {
        return deny("invalid_scope");
      }
      const p = (
        await c.query(
          "SELECT * FROM admission_policies WHERE namespace=$1 AND resource=$2 FOR UPDATE",
          [this.namespace, resource],
        )
      ).rows[0];
      if (!p?.enabled) return deny("invalid_target");
      if (!requested.length || requested.some((s) => !p.scopes.includes(s)))
        return deny("invalid_scope", p.generation);
      const minute = Math.floor(Date.now() / 60000);
      const hour = Math.floor(Date.now() / 3600000);
      const consume = async (
        bucket: string,
        window: number,
        limit: number,
        seconds = 60,
      ) => {
        const r = await c.query(
          `INSERT INTO rate_buckets(namespace,bucket,window_start,expires_at,count) VALUES($1,$2,$3,to_timestamp((($3::bigint+1)*$4::bigint)::double precision),1) ON CONFLICT(namespace,bucket,window_start) DO UPDATE SET count=rate_buckets.count+1 RETURNING count`,
          [this.namespace, bucket, window, seconds],
        );
        return r.rows[0].count <= limit;
      };
      if (
        !(await consume(
          `global:${digest(resource)}`,
          minute,
          p.max_requests_minute,
        )) ||
        !(await consume(
          `client:${digest(v.clientId)}:${digest(resource)}`,
          minute,
          p.max_requests_client_minute,
        ))
      )
        return deny("rate_limited", p.generation);
      let client = (
        await c.query(
          "SELECT * FROM clients WHERE namespace=$1 AND client_id=$2 FOR UPDATE",
          [this.namespace, v.clientId],
        )
      ).rows[0];
      if (client && !client.enabled)
        return deny("unauthorized_client", p.generation);
      if (!client) {
        if (
          !(await consume(
            `new:${digest(resource)}`,
            hour,
            p.max_new_clients_hour,
            3600,
          ))
        )
          return deny("rate_limited", p.generation);
        client = (
          await c.query(
            "INSERT INTO clients(namespace,client_id,subject) VALUES($1,$2,$3) RETURNING *",
            [this.namespace, v.clientId, randomUUID()],
          )
        ).rows[0];
      }
      await c.query(
        `INSERT INTO metadata_snapshots(namespace,client_id,digest,jwks_digest,thumbprint,expires_at) VALUES($1,$2,$3,$4,$5,to_timestamp($6)) ON CONFLICT DO NOTHING`,
        [
          this.namespace,
          v.clientId,
          v.metadataDigest,
          v.jwksDigest,
          v.thumbprint,
          v.metadataExpires,
        ],
      );
      const grant = (
        await c.query(
          `INSERT INTO machine_grants(id,namespace,client_id,resource,scopes,policy_generation,grant_key) VALUES($1,$2,$3,$4,$5,$6,$7)
        ON CONFLICT(namespace,grant_key) DO UPDATE SET policy_generation=EXCLUDED.policy_generation RETURNING *`,
          [
            randomUUID(),
            this.namespace,
            v.clientId,
            resource,
            requested,
            p.generation,
            digest(JSON.stringify([v.clientId, resource, requested])),
          ],
        )
      ).rows[0];
      if (
        grant.client_id !== v.clientId ||
        grant.resource !== resource ||
        JSON.stringify(grant.scopes) !== JSON.stringify(requested)
      )
        fail("grant_integrity_failure", 503);
      if (!grant.enabled) return deny("unauthorized_client", p.generation);
      const token = randomBytes(32).toString("base64url");
      const now = Math.floor(Date.now() / 1000);
      await c.query(
        `INSERT INTO access_tokens(digest,namespace,client_id,grant_id,resource,scopes,issued_at,expires_at,client_generation,grant_generation,policy_generation)
        VALUES($1,$2,$3,$4,$5,$6,to_timestamp($7),to_timestamp($8),$9,$10,$11)`,
        [
          digest(token),
          this.namespace,
          v.clientId,
          grant.id,
          resource,
          requested,
          now,
          now + p.ttl,
          client.generation,
          grant.generation,
          p.generation,
        ],
      );
      await this.audit(c, v.clientId, "issued", p.generation);
      return {
        token: {
          access_token: token,
          token_type: "Bearer" as const,
          expires_in: p.ttl as number,
          scope: requested.join(" "),
        },
      };
    });
    if ("error" in result)
      throw new ProtocolError(
        result.error!,
        result.error === "rate_limited"
          ? 429
          : result.error === "invalid_client"
            ? 401
            : 400,
      );
    return result.token!;
  }
  async introspect(
    id: string,
    secret: string,
    token: string,
  ): Promise<Record<string, unknown>> {
    const rs = (
      await this.pool.query(
        "SELECT * FROM resource_servers WHERE namespace=$1 AND id=$2 AND enabled",
        [this.namespace, id],
      )
    ).rows[0];
    const supplied = Buffer.from(digest(secret), "hex");
    const expected = Buffer.from(rs?.secret_digest ?? "0".repeat(64), "hex");
    if (!timingSafeEqual(supplied, expected) || !rs)
      fail("invalid_client", 401);
    const t = (
      await this.pool.query(
        `SELECT t.*, c.subject FROM access_tokens t
      JOIN clients c ON c.namespace=t.namespace AND c.client_id=t.client_id
      JOIN machine_grants g ON g.id=t.grant_id JOIN admission_policies p ON p.namespace=t.namespace AND p.resource=t.resource
      LEFT JOIN client_blocks b ON b.namespace=c.namespace AND b.client_id=c.client_id
      WHERE t.namespace=$1 AND t.digest=$2 AND t.revoked_at IS NULL AND t.expires_at>now()
      AND c.enabled AND g.enabled AND p.enabled AND NOT COALESCE(b.blocked,false)
      AND t.client_generation=c.generation AND t.grant_generation=g.generation AND t.policy_generation=p.generation
      AND t.resource=ANY($3::text[])`,
        [this.namespace, digest(token), rs.resources],
      )
    ).rows[0];
    if (!t) return { active: false };
    return {
      active: true,
      iss: this.issuer,
      sub: t.subject,
      client_id: t.client_id,
      aud: t.resource,
      scope: t.scopes.join(" "),
      exp: Math.floor(t.expires_at.getTime() / 1000),
      iat: Math.floor(t.issued_at.getTime() / 1000),
      token_type: "Bearer",
      subject_type: "client",
      authorization_generation: String(t.policy_generation),
    };
  }
  async rejectVerified(v: VerifiedClient, code: string): Promise<never> {
    const accepted = await this.transaction(v.clientId, async (c) => {
      if (!(await this.replay(c, v))) return false;
      await this.audit(c, v.clientId, code);
      return true;
    });
    return fail(accepted ? code : "invalid_client", accepted ? 400 : 401);
  }
  async invalidateForRecovery(): Promise<void> {
    // Recovery remains an operator action: never automatically re-enable restored policies.
    await this.pool.query(
      "UPDATE admission_policies SET enabled=false,generation=generation+1 WHERE namespace=$1",
      [this.namespace],
    );
  }
  async revoke(v: VerifiedClient, token: string): Promise<void> {
    const ok = await this.transaction(v.clientId, async (c) => {
      if (!(await this.replay(c, v))) return false;
      await c.query(
        "UPDATE access_tokens SET revoked_at=now() WHERE namespace=$1 AND client_id=$2 AND digest=$3",
        [this.namespace, v.clientId, digest(token)],
      );
      await this.audit(c, v.clientId, "revocation");
      return true;
    });
    if (!ok) fail("invalid_client", 401);
  }
  async blockClient(clientId: string, blocked: boolean): Promise<void> {
    await this.transaction(clientId, async (c) => {
      await c.query(
        `INSERT INTO client_blocks(namespace,client_id,blocked) VALUES($1,$2,$3) ON CONFLICT(namespace,client_id) DO UPDATE SET blocked=EXCLUDED.blocked,generation=client_blocks.generation+1`,
        [this.namespace, clientId, blocked],
      );
      await c.query(
        "UPDATE clients SET generation=generation+1 WHERE namespace=$1 AND client_id=$2",
        [this.namespace, clientId],
      );
      await this.audit(c, clientId, blocked ? "blocked" : "unblocked");
    });
  }
  async disableGrant(clientId: string, grantId: string): Promise<void> {
    await this.transaction(clientId, async (c) => {
      await c.query(
        "UPDATE machine_grants SET enabled=false,generation=generation+1 WHERE namespace=$1 AND client_id=$2 AND id=$3",
        [this.namespace, clientId, grantId],
      );
    });
  }
  async cleanup(): Promise<void> {
    await this.pool.query(
      "DELETE FROM assertion_replays WHERE namespace=$1 AND expires_at < now()",
      [this.namespace],
    );
    await this.pool.query(
      "DELETE FROM rate_buckets WHERE namespace=$1 AND expires_at < now()",
      [this.namespace],
    );
    await this.pool.query(
      "DELETE FROM metadata_snapshots WHERE namespace=$1 AND expires_at < now()",
      [this.namespace],
    );
    await this.pool.query(
      "DELETE FROM access_tokens WHERE namespace=$1 AND expires_at < now()-interval '1 day'",
      [this.namespace],
    );
  }
}
