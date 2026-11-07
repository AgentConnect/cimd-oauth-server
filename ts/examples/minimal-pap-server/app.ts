import express from "express";
import { PapSessionVerifier } from "../../packages/pap/session.js";
import { ProtocolError, fail } from "../../packages/oauth-core/errors.js";
export function createPapApp(verifier: PapSessionVerifier) {
  const app = express();
  app.disable("x-powered-by");
  app.set("trust proxy", false);
  const origin = verifier.company;
  app.get("/.well-known/poppy.json", (_req, res) =>
    res.json({
      protocol_version: "0.3",
      organization: {
        name: "PAP hello demo",
        domain: new URL(origin).hostname,
      },
      apis: [
        {
          type: "openapi",
          url: origin + "/openapi.json",
          description: "Signed-out PAP hello",
        },
      ],
    }),
  );
  app.get("/openapi.json", (_req, res) =>
    res.json({
      openapi: "3.1.0",
      info: { title: "PAP hello demo", version: "1.0.0" },
      servers: [{ url: origin }],
      paths: {
        "/api/hello": {
          get: {
            operationId: "demo.hello",
            responses: {
              "200": {
                description: "Verified PAP request",
                content: {
                  "application/json": {
                    schema: {
                      type: "object",
                      properties: {
                        message: { type: "string" },
                        authenticated: { type: "boolean" },
                      },
                      required: ["message", "authenticated"],
                    },
                  },
                },
              },
            },
          },
        },
      },
    }),
  );
  app.get("/api/hello", async (req, res) => {
    try {
      const values = req.rawHeaders
        .filter((_, i) => i % 2 === 0)
        .map((h) => h.toLowerCase());
      if (
        values.filter((h) => h === "poppy-session").length !== 1 ||
        req.headers.authorization ||
        req.headers.host !== new URL(origin).host
      )
        fail("invalid_session");
      await verifier.verify(
        req.get("poppy-session") ?? "",
        req.method,
        origin + req.originalUrl,
      );
      res.json({ message: "Hello from PAP demo", authenticated: true });
    } catch (error) {
      const e =
        error instanceof ProtocolError
          ? error
          : new ProtocolError("invalid_session");
      res.status(e.status).json({ error: e.code });
    }
  });
  return app;
}
