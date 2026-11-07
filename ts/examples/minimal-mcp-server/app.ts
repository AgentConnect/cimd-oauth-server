import express, { type ErrorRequestHandler } from "express";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import {
  TokenVerifier,
  authorizeOperation,
  protectedResourceMetadata,
  TOOL_SCOPES,
  type VerifiedPrincipal,
} from "../../packages/oauth-rs/index.js";
import { ProtocolError, fail } from "../../packages/oauth-core/errors.js";
import {
  httpsUrl,
  metadataPath,
  object,
  strictJson,
} from "../../packages/oauth-core/parse.js";
export interface McpTool {
  scope: string;
  description: string;
  inputSchema: {
    type: "object";
    properties?: Record<string, unknown>;
    required?: string[];
    additionalProperties?: boolean;
  };
  readOnly: boolean;
  execute(
    args: Record<string, unknown>,
    principal: VerifiedPrincipal,
  ): Promise<unknown>;
}
export function createMcpApp(
  verifier: TokenVerifier,
  tools: Record<string, McpTool> = {},
) {
  const app = express();
  app.disable("x-powered-by");
  app.set("trust proxy", false);
  const c = verifier.config;
  const toolScopes = {
    ...TOOL_SCOPES,
    ...Object.fromEntries(
      Object.entries(tools).map(([name, tool]) => [name, tool.scope]),
    ),
  };
  const metadata = metadataPath(c.resource, "oauth-protected-resource");
  app.get(metadata, (_req, res) =>
    res.json(protectedResourceMetadata(c.resource, c.issuer, c.allowedScopes)),
  );
  app.get("/ready", async (_req, res) => {
    await verifier.ready();
    res.json({ ready: true });
  });
  const path = httpsUrl(c.resource).pathname;
  app.post(
    path,
    express.text({ type: "application/json", limit: "64kb" }),
    async (req, res) => {
      if (
        req.headers.origin &&
        req.headers.origin !== httpsUrl(c.resource).origin
      )
        fail("invalid_origin", 403);
      const principal = await verifier.verify(req.headers.authorization);
      if (typeof req.body !== "string") fail("invalid_request");
      const message = object(strictJson(req.body));
      if (typeof message.method !== "string") fail("invalid_request");
      const params = message.params === undefined ? {} : object(message.params);
      authorizeOperation(
        principal,
        message.method as string,
        typeof params.name === "string" ? params.name : undefined,
        toolScopes,
      );
      // Reject the modern probe at the RPC layer before the legacy transport
      // rejects its newer protocol-version header at the HTTP layer.
      if (message.method === "server/discover") {
        if (
          message.jsonrpc !== "2.0" ||
          (typeof message.id !== "string" && typeof message.id !== "number")
        )
          fail("invalid_request");
        res.json({
          jsonrpc: "2.0",
          id: message.id,
          error: { code: -32601, message: "Method not found" },
        });
        return;
      }
      const server = new Server(
        { name: "cimd-machine-mcp", version: "0.1.0" },
        { capabilities: { tools: {} } },
      );
      const descriptions: Record<string, string> = {
        identity_get: "Read the verified machine identity",
        catalog_list: "Read the fixed demonstration catalog",
      };
      server.setRequestHandler(ListToolsRequestSchema, async () => ({
        tools: Object.entries(toolScopes)
          .filter(([, scope]) => principal.scopes.includes(scope))
          .map(([name]) => ({
            name,
            description: tools[name]?.description ?? descriptions[name],
            inputSchema: tools[name]?.inputSchema ?? {
              type: "object" as const,
              properties: {},
              additionalProperties: false,
            },
            annotations: {
              readOnlyHint: tools[name]?.readOnly ?? true,
              destructiveHint: false,
              openWorldHint: false,
            },
          })),
      }));
      server.setRequestHandler(CallToolRequestSchema, async (request) => {
        authorizeOperation(
          principal,
          "tools/call",
          request.params.name,
          toolScopes,
        );
        const custom = tools[request.params.name];
        const result = custom
          ? await custom.execute(request.params.arguments ?? {}, principal)
          : request.params.name === "identity_get"
            ? {
                client_id: principal.clientId,
                subject: principal.subject,
                resource: principal.resource,
                scope: principal.scopes.join(" "),
              }
            : {
                items: [
                  { id: "sample-notebook", name: "Notebook" },
                  { id: "sample-pencil", name: "Pencil" },
                ],
              };
        return {
          content: [{ type: "text" as const, text: JSON.stringify(result) }],
        };
      });
      const transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: undefined,
        enableJsonResponse: true,
      });
      res.on("close", () => {
        void transport.close();
        void server.close();
      });
      await server.connect(transport);
      await transport.handleRequest(req, res, message);
    },
  );
  app.all(path, async (req, res) => {
    await verifier.verify(req.headers.authorization);
    res.status(405).set("Allow", "POST").end();
  });
  app.use(((err, _req, res, _next) => {
    const e =
      err instanceof ProtocolError
        ? err
        : new ProtocolError("server_error", 503);
    if (e.status === 401 || e.status === 403)
      res.set(
        "WWW-Authenticate",
        `Bearer error="${e.code}", resource_metadata="${new URL(metadata, c.resource).href}"${e.status === 403 ? ', scope="agent.self.read catalog.read"' : ""}`,
      );
    if (e.status === 503) res.set("Retry-After", "1");
    res.status(e.status).json({ error: e.code });
  }) satisfies ErrorRequestHandler);
  return app;
}
