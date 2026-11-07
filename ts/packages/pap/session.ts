/** Minimal PAP 0.3 signed-out Session verification and in-memory continuity. */
import { calculateJwkThumbprint, importJWK, compactVerify } from "jose";
import { loadClientMaterials } from "../oauth-core/metadata.js";
import { SafeHttpFetcher } from "../oauth-core/fetch.js";
import { httpsUrl, object, strictJson } from "../oauth-core/parse.js";
import { fail, ProtocolError } from "../oauth-core/errors.js";

const text = (value: unknown, max = 256): string => {
  if (
    typeof value !== "string" ||
    !value ||
    value.length > max ||
    /\p{Cc}/u.test(value)
  )
    fail("invalid_session");
  return value as string;
};
const integer = (value: unknown): number => {
  if (!Number.isSafeInteger(value) || (value as number) < 0)
    fail("invalid_session");
  return value as number;
};
function jwt(raw: string, typ: string, fields: string[]) {
  const parts = raw.split(".");
  if (
    raw.length > 16384 ||
    parts.length !== 3 ||
    parts.some((p) => !/^[A-Za-z0-9_-]+$/.test(p))
  )
    fail("invalid_session");
  const header = object(strictJson(Buffer.from(parts[0]!, "base64url")));
  const claims = object(strictJson(Buffer.from(parts[1]!, "base64url")));
  if (
    header.alg !== "ES256" ||
    header.typ !== typ ||
    Object.keys(header).some((k) => !fields.includes(k))
  )
    fail("invalid_session");
  return { header, claims };
}
export type PapSession = Readonly<{
  clientId: string;
  sid: string;
  sub: string;
  agentId?: string;
}>;
export class PapSessionVerifier {
  private sessions = new Map<string, PapSession>();
  private replays = new Map<string, number>();
  constructor(
    private readonly fetcher: SafeHttpFetcher,
    readonly company: string,
  ) {
    if (httpsUrl(company).origin !== company) fail("invalid_company");
  }
  get sessionCount(): number {
    return this.sessions.size;
  }
  async verify(
    raw: string,
    method: string,
    target: string,
  ): Promise<PapSession> {
    try {
      const { header, claims } = jwt(raw, "poppy-session+jwt", [
        "alg",
        "typ",
        "kid",
        "poppy_dlg",
      ]);
      const clientId = text(claims.iss, 2048);
      const delegation = text(header.poppy_dlg, 12000);
      const dlg = jwt(delegation, "poppy-delegation+jwt", [
        "alg",
        "typ",
        "kid",
      ]);
      const material = await loadClientMaterials(this.fetcher, clientId);
      const identityKey = material.keys.find(
        (k) => k.kid === text(dlg.header.kid, 1024),
      );
      if (!identityKey) fail("invalid_session");
      await compactVerify(delegation, await importJWK(identityKey!, "ES256"), {
        algorithms: ["ES256"],
      });
      const now = Math.floor(Date.now() / 1000);
      const issued = integer(dlg.claims.iat),
        expires = integer(dlg.claims.exp);
      text(dlg.claims.jti);
      if (
        dlg.claims.iss !== clientId ||
        Object.keys(dlg.claims).some(
          (k) => !["iss", "cnf", "iat", "exp", "jti"].includes(k),
        ) ||
        issued > now + 5 ||
        expires <= now ||
        expires <= issued ||
        expires - issued > 86400
      )
        fail("invalid_session");
      const cnf = object(dlg.claims.cnf);
      if (Object.keys(cnf).length !== 1) fail("invalid_session");
      const key = object(cnf.jwk);
      if (
        key.kty !== "EC" ||
        key.crv !== "P-256" ||
        ["d", "p", "q", "k"].some((k) => k in key)
      )
        fail("invalid_session");
      if (header.kid !== (await calculateJwkThumbprint(key, "sha256")))
        fail("invalid_session");
      await compactVerify(raw, await importJWK(key, "ES256"), {
        algorithms: ["ES256"],
      });
      const iat = integer(claims.iat);
      const url = httpsUrl(target);
      url.search = "";
      url.hash = "";
      const htu = text(claims.htu, 2048);
      if (
        claims.aud !== this.company ||
        claims.htm !== method ||
        htu.includes("?") ||
        htu.includes("#") ||
        httpsUrl(htu).href !== url.href ||
        url.origin !== this.company ||
        iat < now - 60 ||
        iat > now + 5 ||
        iat >= expires ||
        claims.ath !== undefined
      )
        fail("invalid_session");
      const session: PapSession = Object.freeze({
        clientId,
        sid: text(claims.sid),
        sub: text(claims.sub),
        ...(claims.agent_id === undefined
          ? {}
          : { agentId: text(claims.agent_id) }),
      });
      const id = JSON.stringify([clientId, session.sid]);
      const previous = this.sessions.get(id);
      if (
        previous &&
        (previous.sub !== session.sub || previous.agentId !== session.agentId)
      )
        fail("invalid_session");
      for (const [id, until] of this.replays)
        if (until < now) this.replays.delete(id);
      const replay = JSON.stringify([clientId, text(claims.jti)]);
      if (this.replays.has(replay)) fail("invalid_session");
      this.replays.set(replay, Math.min(expires, iat + 60));
      this.sessions.set(id, session);
      return session;
    } catch (error) {
      if (
        error instanceof ProtocolError &&
        error.code === "temporarily_unavailable"
      )
        throw error;
      return fail("invalid_session");
    }
  }
}
