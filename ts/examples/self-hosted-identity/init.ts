import { generateKeyPair, exportJWK } from "jose";
import { mkdir, writeFile } from "node:fs/promises";
import { required } from "../config.js";
import { httpsUrl } from "../../packages/oauth-core/parse.js";
const root = required("IDENTITY_STATE_DIR");
const clientId = required("IDENTITY_CLIENT_ID");
const u = httpsUrl(clientId);
const { privateKey, publicKey } = await generateKeyPair("ES256", {
  extractable: true,
});
const kid = "identity-1";
await mkdir(root, { recursive: true, mode: 0o700 });
await writeFile(
  `${root}/private.jwk.json`,
  JSON.stringify({ ...(await exportJWK(privateKey)), kid, alg: "ES256" }),
  { mode: 0o600, flag: "wx" },
);
await writeFile(
  `${root}/jwks.json`,
  JSON.stringify({
    keys: [{ ...(await exportJWK(publicKey)), kid, alg: "ES256", use: "sig" }],
  }),
  { flag: "wx" },
);
await writeFile(
  `${root}/client.json`,
  JSON.stringify({
    client_id: clientId,
    client_name: "Self-hosted machine",
    jwks_uri: new URL("/jwks.json", u).href,
    grant_types: ["client_credentials"],
    response_types: [],
    redirect_uris: [],
    token_endpoint_auth_method: "private_key_jwt",
    token_endpoint_auth_signing_alg: "ES256",
  }),
  { flag: "wx" },
);
process.stdout.write("Isolated identity initialized\n");
