import { PapSessionVerifier } from "../../packages/pap/session.js";
import { createPapApp } from "./app.js";
import { listen, productionFetcher, required } from "../config.js";
listen(
  createPapApp(
    new PapSessionVerifier(productionFetcher(), required("PAP_ORIGIN")),
  ),
  9444,
);
