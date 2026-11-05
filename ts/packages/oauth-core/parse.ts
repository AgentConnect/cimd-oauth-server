import { createHash } from "node:crypto";
import { fail } from "./errors.js";
export const digest = (value: string | Buffer): string =>
  createHash("sha256").update(value).digest("hex");
export function strictJson(bytes: Buffer | string): unknown {
  const text =
    typeof bytes === "string"
      ? bytes
      : new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(
          bytes,
        );
  if (text.startsWith("\uFEFF")) fail("invalid_json");
  let i = 0;
  const ws = () => {
    while (/[\x20\x09\x0a\x0d]/.test(text[i] ?? "") && i < text.length) i++;
  };
  const str = (): string => {
    const start = i++;
    while (i < text.length) {
      const c = text[i++];
      if (c === "\\") {
        i++;
        continue;
      }
      if (c === '"') {
        try {
          return JSON.parse(text.slice(start, i)) as string;
        } catch {
          fail("invalid_json");
        }
      }
    }
    return fail("invalid_json");
  };
  const value = (depth: number): void => {
    if (depth > 32) fail("invalid_json");
    ws();
    if (text[i] === '"') {
      str();
      return;
    }
    if (text[i] === "{") {
      i++;
      ws();
      const keys = new Set<string>();
      if (text[i] === "}") {
        i++;
        return;
      }
      for (;;) {
        if (text[i] !== '"') fail("invalid_json");
        const key = str();
        if (keys.has(key)) fail("duplicate_json_member");
        keys.add(key);
        ws();
        if (text[i++] !== ":") fail("invalid_json");
        value(depth + 1);
        ws();
        if (text[i] === "}") {
          i++;
          return;
        }
        if (text[i++] !== ",") fail("invalid_json");
        ws();
      }
    }
    if (text[i] === "[") {
      i++;
      ws();
      if (text[i] === "]") {
        i++;
        return;
      }
      for (;;) {
        value(depth + 1);
        ws();
        if (text[i] === "]") {
          i++;
          return;
        }
        if (text[i++] !== ",") fail("invalid_json");
      }
    }
    const m =
      /^(?:true|false|null|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?)/.exec(
        text.slice(i),
      );
    if (!m) fail("invalid_json");
    i += m![0].length;
  };
  value(0);
  ws();
  if (i !== text.length) fail("invalid_json");
  try {
    return JSON.parse(text) as unknown;
  } catch {
    return fail("invalid_json");
  }
}
export function object(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value))
    fail("invalid_document");
  return value as Record<string, unknown>;
}
export function httpsUrl(value: string): URL {
  if (Buffer.byteLength(value) > 2048 || /[\\\x00-\x20\x7f-\uffff]/.test(value))
    fail("invalid_url");
  let u: URL;
  try {
    u = new URL(value);
  } catch {
    return fail("invalid_url");
  }
  const rawPath = value.replace(/^https:\/\/[^/]+/i, "").split(/[?#]/)[0] ?? "";
  if (rawPath.split("/").some((segment) => /^(?:\.|%2e){1,2}$/i.test(segment)))
    fail("invalid_url");
  if (u.protocol !== "https:" || u.username || u.password || u.hash)
    fail("invalid_url");
  return u;
}
export function scopes(value: string): string[] {
  if (
    !value ||
    value.length > 1024 ||
    !/^[\x21\x23-\x5b\x5d-\x7e]+(?: [\x21\x23-\x5b\x5d-\x7e]+)*$/.test(value)
  )
    fail("invalid_scope");
  return [...new Set(value.split(" "))].sort();
}
export function form(
  text: string,
  allowed: readonly string[],
): Record<string, string> {
  if (Buffer.byteLength(text) > 24 * 1024 || /%(?![\da-f]{2})/i.test(text))
    fail("invalid_request");
  const out: Record<string, string> = Object.create(null) as Record<
    string,
    string
  >;
  let count = 0;
  for (const [k, v] of new URLSearchParams(text)) {
    if (++count > 12 || !allowed.includes(k) || Object.hasOwn(out, k) || !v)
      fail("invalid_request");
    out[k] = v;
  }
  return out;
}
export function metadataPath(
  identifier: string,
  kind: "oauth-authorization-server" | "oauth-protected-resource",
): string {
  const u = httpsUrl(identifier);
  if (u.search) fail("invalid_url");
  return `/.well-known/${kind}${u.pathname === "/" ? "" : u.pathname.replace(/\/$/, "")}`;
}
