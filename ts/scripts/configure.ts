import { required, storeFromEnv } from "../examples/config.js";
const store = storeFromEnv();
try {
  if (process.env.ADMISSION_POLICY !== "open_basic")
    throw new Error("Explicit open_basic policy required");
  await store.configureRequestLimits({
    globalMinute: Number(required("FETCH_GLOBAL_MINUTE")),
    originMinute: Number(required("FETCH_ORIGIN_MINUTE")),
    clientMinute: Number(required("FETCH_CLIENT_MINUTE")),
    sourceMinute: Number(required("FETCH_SOURCE_MINUTE")),
  });
  await store.configurePolicy({
    resource: required("MCP_RESOURCE"),
    scopes: required("OAUTH_SCOPES").split(" "),
    ttl: Number(required("TOKEN_TTL_SECONDS")),
    maxNewClientsHour: Number(required("MAX_NEW_CLIENTS_HOUR")),
    maxRequestsClientMinute: Number(required("MAX_REQUESTS_CLIENT_MINUTE")),
    maxRequestsMinute: Number(required("MAX_REQUESTS_MINUTE")),
    custodyCondition: required("ACCEPTED_CUSTODY_CONDITION"),
    enabled: true,
  });
  await store.provisionResourceServer(
    required("RS_ID"),
    required("RS_SECRET"),
    [required("MCP_RESOURCE")],
  );
  process.stdout.write("Machine policy and resource server configured\n");
} finally {
  await store.pool.end();
}
