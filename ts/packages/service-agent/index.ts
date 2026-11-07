import express, { type ErrorRequestHandler } from "express";
import type { Express } from "express";
import { AnpVerifier } from "../anp/index.js";
import { PapSessionVerifier } from "../pap/session.js";
import { TokenVerifier } from "../oauth-rs/index.js";
import {
  createMcpApp,
  type McpTool,
} from "../../examples/minimal-mcp-server/app.js";
import { fail, ProtocolError } from "../oauth-core/errors.js";
import { httpsUrl } from "../oauth-core/parse.js";

export interface Caller {
  protocol: "anp" | "mcp" | "pap";
  subject: string;
}
export interface ProtocolServices {
  listProtocols(args: Record<string, unknown>): Promise<unknown>;
  getProtocol(args: Record<string, unknown>): Promise<unknown>;
  createMessage(
    args: Record<string, unknown>,
    caller: Caller,
  ): Promise<unknown>;
}
const string = { type: "string" };
const definitions = [
  {
    name: "protocol_list",
    method: "get",
    path: "/protocols",
    description: "List published protocol versions and documents",
    scope: "protocol.read",
    properties: { version: string, language: string },
    required: [] as string[],
  },
  {
    name: "protocol_get",
    method: "get",
    path: "/protocols/{version}/{document}",
    description: "Read a specific version of a protocol document",
    scope: "protocol.read",
    properties: { version: string, document: string, language: string },
    required: ["version", "document"],
  },
  {
    name: "message_create",
    method: "post",
    path: "/messages",
    description: "Leave a text message for the website",
    scope: "message.write",
    properties: { message: { type: "string", minLength: 1, maxLength: 4000 } },
    required: ["message"],
  },
] as const;
function argumentsFor(
  definition: (typeof definitions)[number],
  value: unknown,
): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value))
    fail("invalid_arguments");
  const args = value as Record<string, unknown>;
  if (
    Object.keys(args).some((key) => !(key in definition.properties)) ||
    definition.required.some(
      (key) => typeof args[key] !== "string" || !args[key],
    ) ||
    Object.values(args).some((value) => typeof value !== "string")
  )
    fail("invalid_arguments");
  if (
    definition.name === "message_create" &&
    (String(args.message).length > 4000 || !String(args.message).trim())
  )
    fail("invalid_arguments");
  return args;
}
export function serviceOpenApi(origin: string, protocol: "anp" | "pap") {
  return {
    openapi: "3.1.0",
    info: { title: "Service Agent", version: "0.1.0" },
    servers: [{ url: origin }],
    paths: Object.fromEntries(
      definitions.map((definition) => [
        `/${protocol}/api${definition.path}`,
        {
          [definition.method]: {
            operationId: definition.name,
            description: definition.description,
            ...(definition.method === "post"
              ? {
                  requestBody: {
                    required: true,
                    content: {
                      "application/json": {
                        schema: {
                          type: "object",
                          properties: definition.properties,
                          required: definition.required,
                          additionalProperties: false,
                        },
                      },
                    },
                  },
                }
              : {
                  parameters: Object.entries(definition.properties).map(
                    ([name, schema]) => ({
                      name,
                      in: definition.path.includes(`{${name}}`)
                        ? "path"
                        : "query",
                      required: definition.required.some(
                        (value) => value === name,
                      ),
                      schema,
                    }),
                  ),
                }),
            responses: {
              "200": {
                description: "Operation completed",
                content: { "application/json": { schema: { type: "object" } } },
              },
            },
          },
        },
      ]),
    ),
  };
}
export function createServiceAgent(options: {
  origin: string;
  services: ProtocolServices;
  anp: AnpVerifier;
  pap: PapSessionVerifier;
  mcp: TokenVerifier;
  authorizationServer?: Express;
}) {
  const { origin, services } = options;
  if (
    httpsUrl(origin).origin !== origin ||
    options.pap.company !== origin ||
    options.mcp.config.resource !== origin + "/mcp"
  )
    fail("invalid_service_configuration");
  const app = express();
  app.disable("x-powered-by");
  app.set("trust proxy", false);
  const invoke = async (
    definition: (typeof definitions)[number],
    input: unknown,
    caller: Caller,
  ) => {
    const args = argumentsFor(definition, input);
    if (definition.name === "protocol_list")
      return services.listProtocols(args);
    if (definition.name === "protocol_get") return services.getProtocol(args);
    return services.createMessage(args, caller);
  };
  app.get("/.well-known/agent-descriptions", (_req, res) =>
    res.json({
      "@context": {
        "@vocab": "https://schema.org/",
        ad: "https://agent-network-protocol.com/ad#",
      },
      "@type": "CollectionPage",
      url: origin + "/.well-known/agent-descriptions",
      items: [
        {
          "@type": "ad:AgentDescription",
          name: "ANP Official Website",
          "@id": origin + "/agents/official/ad.json",
        },
      ],
    }),
  );
  app.get("/.well-known/poppy.json", (_req, res) =>
    res.json({
      protocol_version: "0.3",
      organization: {
        name: "ANP Official Website",
        domain: new URL(origin).hostname,
      },
      apis: [{ type: "openapi", url: origin + "/pap/openapi.json" }],
    }),
  );
  app.get("/pap/openapi.json", (_req, res) =>
    res.json(serviceOpenApi(origin, "pap")),
  );
  const authenticate = async (
    req: express.Request,
    protocol: "anp" | "pap",
  ): Promise<Caller> => {
    if (req.headers.host !== new URL(origin).host) fail("invalid_host", 400);
    const names = req.rawHeaders
      .filter((_, index) => index % 2 === 0)
      .map((value) => value.toLowerCase());
    for (const name of [
      "signature",
      "signature-input",
      "content-digest",
      "poppy-session",
      "authorization",
    ])
      if (names.filter((value) => value === name).length > 1)
        fail("invalid_authentication", 401);
    if (protocol === "anp") {
      const headers = Object.fromEntries(
        Object.entries(req.headers).filter(
          (entry): entry is [string, string] => typeof entry[1] === "string",
        ),
      );
      const result = await options.anp.verify(
        req.method,
        origin + req.originalUrl,
        headers,
        Buffer.isBuffer(req.body) ? req.body : undefined,
      );
      return { protocol, subject: result.did };
    }
    if (req.headers.authorization) fail("invalid_session");
    const result = await options.pap.verify(
      req.get("poppy-session") ?? "",
      req.method,
      origin + req.originalUrl,
    );
    return { protocol, subject: result.clientId + ":" + result.sub };
  };
  app.get("/agents/official/ad.json", async (req, res) => {
    await authenticate(req, "anp");
    res.json({
      protocolType: "ANP",
      protocolVersion: "1.0.0",
      type: "AgentDescription",
      name: "ANP Official Website",
      url: origin + "/agents/official/ad.json",
      description: "Read published ANP specifications and leave a message.",
      securityDefinitions: {
        didwba: { scheme: "didwba", in: "header", name: "Signature" },
      },
      security: "didwba",
      Infomations: [
        {
          type: "Information",
          description: "Published protocol versions and documents",
          url: origin + "/anp/catalog.json",
        },
      ],
      interfaces: [
        {
          type: "StructuredInterface",
          protocol: "OpenAPI",
          url: origin + "/anp/openapi.json",
        },
      ],
    });
  });
  app.get("/anp/openapi.json", async (req, res) => {
    await authenticate(req, "anp");
    res.json(serviceOpenApi(origin, "anp"));
  });
  app.get("/anp/catalog.json", async (req, res) => {
    await authenticate(req, "anp");
    res.json(await services.listProtocols({}));
  });
  for (const protocol of ["anp", "pap"] as const) {
    for (const definition of definitions) {
      const path = `/${protocol}/api${definition.path.replace(/\{([^}]+)\}/g, ":$1")}`;
      app[definition.method](
        path,
        express.raw({ type: "application/json", limit: "16kb" }),
        async (req, res) => {
          const caller = await authenticate(req, protocol);
          const args =
            definition.method === "post"
              ? JSON.parse(
                  Buffer.isBuffer(req.body) ? req.body.toString("utf8") : "{}",
                )
              : { ...req.query, ...req.params };
          res.json(await invoke(definition, args, caller));
        },
      );
    }
  }
  const tools: Record<string, McpTool> = Object.fromEntries(
    definitions.map((definition) => [
      definition.name,
      {
        description: definition.description,
        scope: definition.scope,
        readOnly: definition.method === "get",
        inputSchema: {
          type: "object",
          properties: definition.properties,
          required: [...definition.required],
          additionalProperties: false,
        },
        execute: (args, principal) =>
          invoke(definition, args, {
            protocol: "mcp",
            subject: principal.clientId,
          }),
      } satisfies McpTool,
    ]),
  );
  app.use(createMcpApp(options.mcp, tools));
  if (options.authorizationServer) app.use(options.authorizationServer);
  app.use(((error, req, res, _next) => {
    const e =
      error instanceof ProtocolError
        ? error
        : new ProtocolError(
            error instanceof SyntaxError ? "invalid_arguments" : "server_error",
            error instanceof SyntaxError ? 400 : 500,
          );
    if (
      (e.status === 401 && req.path.startsWith("/anp/")) ||
      (e.status === 401 && req.path === "/agents/official/ad.json")
    ) {
      res.set("WWW-Authenticate", 'DIDWba error="invalid_signature"');
      res.set(
        "Accept-Signature",
        'sig1=("@method" "@target-uri");created;expires;nonce;keyid',
      );
    }
    res.status(e.status).json({ error: e.code });
  }) satisfies ErrorRequestHandler);
  return app;
}
