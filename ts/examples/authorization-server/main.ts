import { createAuthorizationServer } from "../../packages/oauth-as/app.js";
import { ClientAuthenticator } from "../../packages/oauth-core/client.js";
import {
  listen,
  productionFetcher,
  required,
  storeFromEnv,
} from "../config.js";
const store = storeFromEnv();
await store.ready();
const fetcher = productionFetcher();
const app = createAuthorizationServer(
  store,
  new ClientAuthenticator(fetcher, store.issuer),
  required("OAUTH_SCOPES").split(" "),
);
listen(app, 8443);
