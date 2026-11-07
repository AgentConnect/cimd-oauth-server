import { test } from "node:test";
import { nativeWebsiteRoundTrip } from "../scripts/native-website.js";
process.env.NODE_ENV = "test";
test(
  "one actual native shared identity reads and posts through ANP MCP and PAP",
  nativeWebsiteRoundTrip,
);
