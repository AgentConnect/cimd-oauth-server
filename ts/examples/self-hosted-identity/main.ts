import { readFileSync } from "node:fs";
import express from "express";
import { required, listen } from "../config.js";
import { httpsUrl } from "../../packages/oauth-core/parse.js";
const root = required("IDENTITY_STATE_DIR");
const clientId = required("IDENTITY_CLIENT_ID");
const app = express();
app.disable("x-powered-by");
app.get(httpsUrl(clientId).pathname, (_req, res) =>
  res.type("application/json").send(readFileSync(`${root}/client.json`)),
);
app.get("/jwks.json", (_req, res) =>
  res.type("application/jwk-set+json").send(readFileSync(`${root}/jwks.json`)),
);
listen(app, 10443);
