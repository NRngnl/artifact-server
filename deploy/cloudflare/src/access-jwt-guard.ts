/**
 * Require a valid Cloudflare Access application token on every request. This
 * is defense in depth behind the Access self-hosted apps: it stops traffic that
 * reaches the Worker without passing Access (for example via workers.dev or a
 * misconfigured route). Local member status remains the authorization boundary.
 */
import {
  createRemoteJWKSet,
  customFetch,
  jwtVerify,
  type JWTPayload,
  type RemoteJWKSetOptions,
} from "jose";

export interface AccessJwtGuardConfig {
  readonly audiences: readonly string[];
  readonly fetch?: typeof fetch;
  readonly teamDomain: string;
}

export type AccessJwtGuard = (request: Request) => Promise<JWTPayload | Response | null>;

const clockToleranceSeconds = 60;

/** Return verified claims, null for health probes, or a bare 403. */
export function createAccessJwtGuard(config: AccessJwtGuardConfig): AccessJwtGuard {
  const teamDomain = config.teamDomain.replace(/\/+$/u, "");
  // jose caches keys, refetches on an unknown kid, and rate-limits refetches
  // to one per cooldown window so forged kids cannot hammer the certs URL.
  const options: RemoteJWKSetOptions = {
    cooldownDuration: 30_000,
    timeoutDuration: 5_000,
  };
  if (config.fetch !== undefined) options[customFetch] = config.fetch;
  const keys = createRemoteJWKSet(
    new URL(`${teamDomain}/cdn-cgi/access/certs`),
    options,
  );
  const audience = [...config.audiences];
  return async (request) => {
    const url = new URL(request.url);
    if (request.method === "GET" && url.pathname === "/health") return null;
    const token = request.headers.get("Cf-Access-Jwt-Assertion");
    if (token === null || token === "") return forbidden();
    try {
      const {payload} = await jwtVerify(token, keys, {
        algorithms: ["RS256"],
        audience,
        clockTolerance: clockToleranceSeconds,
        issuer: teamDomain,
        requiredClaims: ["exp"],
      });
      return payload;
    } catch {
      return forbidden();
    }
  };
}

/** Parse guard configuration from Worker variables; null when not configured. */
export function accessJwtGuardConfig(
  teamDomain: string | undefined,
  audiences: string | undefined,
): AccessJwtGuardConfig | null {
  const parsedAudiences = (audiences ?? "")
    .split(",")
    .map((value) => value.trim())
    .filter((value) => value !== "");
  if (teamDomain === undefined || teamDomain === "" || parsedAudiences.length === 0) {
    return null;
  }
  return {audiences: parsedAudiences, teamDomain};
}

function forbidden(): Response {
  return new Response(null, {
    headers: {"Cache-Control": "no-store"},
    status: 403,
  });
}
