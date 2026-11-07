import { readFile } from "node:fs/promises";
import { Pool } from "pg";
import { createAuthorizationServer } from "../../packages/oauth-as/app.js";
import { ClientAuthenticator } from "../../packages/oauth-core/client.js";
import { TokenVerifier } from "../../packages/oauth-rs/index.js";
import { AnpVerifier, publicDidResolver } from "../../packages/anp/index.js";
import { PapSessionVerifier } from "../../packages/pap/session.js";
import {
  createServiceAgent,
  type ProtocolServices,
} from "../../packages/service-agent/index.js";
import {
  createWebsiteServices,
  type ProtocolDocument,
} from "../../packages/service-agent/website.js";
import {
  listen,
  productionFetcher,
  required,
  storeFromEnv,
} from "../config.js";

/** One process and canonical HTTPS origin for AS, MCP, ANP and signed-out PAP. */
export async function startServiceAgent(
  services: ProtocolServices,
): Promise<void> {
  const origin = required("SERVICE_ORIGIN");
  const store = storeFromEnv();
  await store.ready();
  if (store.issuer !== origin)
    throw new Error("OAUTH_ISSUER must equal SERVICE_ORIGIN");
  const fetcher = productionFetcher();
  const scopes = required("OAUTH_SCOPES").split(" ");
  const app = createServiceAgent({
    origin,
    services,
    anp: new AnpVerifier(publicDidResolver(fetcher)),
    pap: new PapSessionVerifier(fetcher, origin),
    mcp: new TokenVerifier(fetcher, {
      issuer: origin,
      introspectionEndpoint: origin + "/oauth/introspect",
      resource: origin + "/mcp",
      rsId: required("RS_ID"),
      rsSecret: required("RS_SECRET"),
      allowedScopes: scopes,
    }),
    authorizationServer: createAuthorizationServer(
      store,
      new ClientAuthenticator(fetcher, origin),
      scopes,
    ),
  });
  listen(app, 9445);
}
export async function startWebsite(): Promise<void> {
  const catalog = JSON.parse(
    await readFile(required("PROTOCOL_CATALOG_FILE"), "utf8"),
  ) as ProtocolDocument[];
  const pool = new Pool({ connectionString: required("DATABASE_URL"), max: 4 });
  const services = await createWebsiteServices(catalog, pool);
  await startServiceAgent(services);
}
