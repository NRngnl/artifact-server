import {afterEach, beforeEach, describe, expect, test, vi} from "vitest";
import {
  exportJWK,
  generateKeyPair,
  SignJWT,
  type CryptoKey,
  type JWK,
} from "jose";

import {
  accessJwtGuardConfig,
  createAccessJwtGuard,
  type AccessJwtGuard,
} from "../src/access-jwt-guard.js";

const team = "https://example-team.cloudflareaccess.com";
const audience = "aud-tag-application";

interface SigningKey {
  readonly jwk: JWK;
  readonly kid: string;
  readonly privateKey: CryptoKey;
}

async function signingKey(kid: string): Promise<SigningKey> {
  const pair = await generateKeyPair("RS256");
  return {
    jwk: {...await exportJWK(pair.publicKey), alg: "RS256", kid, use: "sig"},
    kid,
    privateKey: pair.privateKey,
  };
}

describe("Cloudflare Access JWT guard", () => {
  let current: SigningKey;
  let published: SigningKey[];
  let certFetches: number;
  let certUrls: string[];
  let guard: AccessJwtGuard;

  beforeEach(async () => {
    vi.useFakeTimers({toFake: ["Date"]});
    vi.setSystemTime(new Date("2026-10-15T00:00:00.000Z"));
    current = await signingKey("kid-1");
    published = [current];
    certFetches = 0;
    certUrls = [];
    guard = createAccessJwtGuard({
      audiences: ["other-aud", audience],
      fetch: async (input) => {
        certUrls.push(new Request(input).url);
        certFetches += 1;
        return Response.json({keys: published.map((key) => key.jwk)});
      },
      teamDomain: `${team}/`,
    });
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  const token = (
    key: SigningKey,
    claims: {aud?: string; iss?: string; exp?: number; nbf?: number} = {},
  ): Promise<string> => {
    const now = Math.floor(Date.now() / 1000);
    return new SignJWT({email: "ada@example.com"})
      .setProtectedHeader({alg: "RS256", kid: key.kid})
      .setAudience(claims.aud ?? audience)
      .setIssuer(claims.iss ?? team)
      .setIssuedAt(now)
      .setNotBefore(claims.nbf ?? now)
      .setExpirationTime(claims.exp ?? now + 600)
      .sign(key.privateKey);
  };

  const status = async (
    assertion: string | null,
    path = "/api/v1/session",
    method = "GET",
  ): Promise<number> => {
    const headers = new Headers();
    if (assertion !== null) headers.set("Cf-Access-Jwt-Assertion", assertion);
    const denied = await guard(new Request(`https://artifacts.example.com${path}`, {
      headers,
      method,
    }));
    return denied instanceof Response ? denied.status : 200;
  };

  test("a valid Access token returns verified claims; skew within 60s is tolerated", async () => {
    const assertion = await token(current);
    expect(await status(assertion)).toBe(200);
    expect(await guard(new Request("https://artifacts.example.com/auth/login", {
      headers: {"Cf-Access-Jwt-Assertion": assertion},
    }))).toMatchObject({email: "ada@example.com", iss: team, aud: audience});
    const now = Math.floor(Date.now() / 1000);
    expect(await status(await token(current, {exp: now - 30}))).toBe(200);
  });

  test("missing, expired, wrong-audience, wrong-issuer, and forged tokens get a bare 403", async () => {
    const now = Math.floor(Date.now() / 1000);
    const forged = await signingKey("kid-1");
    const cases = [
      null,
      "",
      "not-a-jwt",
      await token(current, {exp: now - 120}),
      await token(current, {nbf: now + 120}),
      await token(current, {aud: "unknown-aud"}),
      await token(current, {iss: "https://evil.cloudflareaccess.com"}),
      await token(forged),
    ];
    const statuses = await Promise.all(cases.map((assertion) => status(assertion)));
    expect(statuses).toEqual(cases.map(() => 403));
    const denied = await guard(new Request("https://artifacts.example.com/"));
    expect(denied).toBeInstanceOf(Response);
    if (!(denied instanceof Response)) throw new Error("Expected a denial response");
    expect(await denied.text()).toBe("");
  });

  test("only GET /health is exempt", async () => {
    expect(await status(null, "/health")).toBe(200);
    expect(await status(null, "/health", "POST")).toBe(403);
    expect(await status(null, "/health/extra")).toBe(403);
  });

  test("key rotation refetches the certs on an unknown kid, rate-limited", async () => {
    expect(await status(await token(current))).toBe(200);
    expect(certFetches).toBe(1);
    expect(certUrls).toEqual([`${team}/cdn-cgi/access/certs`]);
    const rotated = await signingKey("kid-2");
    published = [rotated];
    // Inside the cooldown a flood of unknown kids cannot trigger refetches.
    expect(await status(await token(rotated))).toBe(403);
    expect(await status(await token(rotated))).toBe(403);
    expect(certFetches).toBe(1);
    vi.setSystemTime(Date.now() + 31_000);
    expect(await status(await token(rotated))).toBe(200);
    expect(certFetches).toBe(2);
  });

  test("configuration is off unless both team domain and audiences are set", () => {
    expect(accessJwtGuardConfig(undefined, audience)).toBeNull();
    expect(accessJwtGuardConfig(team, " , ")).toBeNull();
    expect(accessJwtGuardConfig(team, `${audience}, other`)).toEqual({
      audiences: [audience, "other"],
      teamDomain: team,
    });
  });
});
