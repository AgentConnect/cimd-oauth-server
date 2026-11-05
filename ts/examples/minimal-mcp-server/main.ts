import { TokenVerifier } from "../../packages/oauth-rs/index.js";
import { createMcpApp } from "./app.js";
import { listen, productionFetcher, required } from "../config.js";
const verifier = new TokenVerifier(productionFetcher(), {
  issuer: required("OAUTH_ISSUER"),
  introspectionEndpoint: required("INTROSPECTION_ENDPOINT"),
  resource: required("MCP_RESOURCE"),
  rsId: required("RS_ID"),
  rsSecret: required("RS_SECRET"),
  allowedScopes: required("OAUTH_SCOPES").split(" "),
});
listen(createMcpApp(verifier), 9443);
