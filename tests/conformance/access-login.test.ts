import {mkdtemp, rm} from "node:fs/promises";
import {createServer, type Server} from "node:http";
import {once} from "node:events";
import {tmpdir} from "node:os";
import path from "node:path";

import {getRequestListener} from "@hono/node-server";
import {ManagedRuntime, Redacted} from "effect";
import {exportJWK, generateKeyPair, SignJWT, type JWTPayload} from "jose";
import {afterEach, beforeEach, describe, expect, test, vi} from "vitest";
import {z} from "zod";

import {accessBrowserLogin} from "../../deploy/cloudflare/src/access-browser-login.js";
import {createAccessJwtGuard} from "../../deploy/cloudflare/src/access-jwt-guard.js";
import type {ApplicationRuntime} from "../../src/application/application-runtime.js";
import {browserLoginKinds, privateTeamBrowserAccess} from "../../src/core/browser-access.js";
import {SystemClock, SystemIdGenerator} from "../../src/core/system.js";
import {createHttpApp} from "../../src/http/create-http-app.js";
import {createLocalApplicationLayer} from "../../src/local/create-local-application-layer.js";
import {LocalBlobStore} from "../../src/storage/local-blob-store.js";
import {LocalStagingStore} from "../../src/storage/local-staging-store.js";
import {SqliteArtifactRepository} from "../../src/storage/sqlite-artifact-repository.js";
import {SqliteIdentityRepository} from "../../src/storage/sqlite-identity-repository.js";
import {reserveLoopbackPort} from "../support/runtime-harness.js";

const team = "https://example-team.cloudflareaccess.com";
const appAudience = "app-audience";
const contentAudience = "content-audience";
const apiToken = "access-login-test-api-token";
const principalSchema = z.object({principal: z.object({id: z.string(), membershipRole: z.string()})});
const memberSchema = z.object({member: z.object({id: z.string()})});

function sessionCookies(response: Response): string {
  const jar = new Map<string, string>();
  for (const cookie of response.headers.getSetCookie()) {
    const pair = cookie.split(";")[0] ?? "";
    jar.set(pair.split("=")[0] ?? "", pair);
  }
  return [...jar.values()].join("; ");
}

describe.each([false, true])("Cloudflare Access browser login (autoAdmit=%s)", (autoAdmit) => {
  let directory: string;
  let repository: SqliteArtifactRepository;
  let identities: SqliteIdentityRepository;
  let runtime: ApplicationRuntime;
  let server: Server;
  let origin: string;
  let privateKey: CryptoKey;

  beforeEach(async () => {
    directory = await mkdtemp(path.join(tmpdir(), "artifact-access-login-"));
    const database = path.join(directory, "installation.db");
    repository = new SqliteArtifactRepository(database);
    identities = new SqliteIdentityRepository(database);
    const pair = await generateKeyPair("RS256");
    privateKey = pair.privateKey;
    const jwk = {...await exportJWK(pair.publicKey), kid: "access-test", alg: "RS256"};
    const guard = createAccessJwtGuard({
      audiences: [appAudience, contentAudience],
      fetch: async () => Response.json({keys: [jwk]}),
      teamDomain: team,
    });
    const verified = new WeakMap<Request, JWTPayload>();
    const trustedBrowserLogin = accessBrowserLogin({
      ARTIFACT_SERVER_CF_ACCESS_LOGIN: "true",
      ARTIFACT_SERVER_CF_ACCESS_APP_AUDIENCE: appAudience,
      ARTIFACT_SERVER_CF_ACCESS_AUDIENCES: `${appAudience},${contentAudience}`,
      ARTIFACT_SERVER_CF_ACCESS_TEAM_DOMAIN: team,
    }, verified);
    if (trustedBrowserLogin === undefined) throw new Error("Access login must be configured");
    runtime = ManagedRuntime.make(createLocalApplicationLayer({
      apiToken: Redacted.make(apiToken), autoAdmitExternalMembers: autoAdmit,
      blobs: new LocalBlobStore(path.join(directory, "blobs")),
      bootstrapAdministratorEmail: "admin@example.test", clock: new SystemClock(),
      dispatches: repository, externalApiBearerVerifier: null, externalMcpBearerVerifier: null,
      externalMcpOAuthVerifier: null, ids: new SystemIdGenerator(), identityRepository: identities,
      installationId: "access-test", interactiveIdentityProvider: null, localBootstrapCredential: null,
      protectBootstrapAdministrator: false, repository,
      staging: new LocalStagingStore(path.join(directory, "staging")),
    }));
    await runtime.context();
    const port = await reserveLoopbackPort();
    origin = `http://127.0.0.1:${port}`;
    const app = createHttpApp({
      applicationRuntime: runtime, blobs: new LocalBlobStore(path.join(directory, "blobs")),
      browserAccess: privateTeamBrowserAccess(browserLoginKinds.cloudflareAccess),
      contentDomain: "content.example.test", trustedApplicationOrigin: origin, trustedBrowserLogin,
      completedRequestLogSampleRate: 0,
    });
    server = createServer(getRequestListener(async (request) => {
      const claims = await guard(request);
      if (claims instanceof Response) return claims;
      if (claims !== null) verified.set(request, claims);
      return app.fetch(request);
    }));
    server.listen(port, "127.0.0.1");
    await once(server, "listening");
  });

  afterEach(async () => {
    server.closeAllConnections();
    await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
    await runtime.dispose();
    identities.close();
    repository.close();
    await rm(directory, {force: true, recursive: true});
  });

  async function jwt(claims: JWTPayload = {email: "admin@example.test", sub: "admin-sub"}, audience = appAudience) {
    return new SignJWT(claims).setProtectedHeader({alg: "RS256", kid: "access-test"})
      .setIssuer(team).setAudience(audience).setExpirationTime("5m").sign(privateKey);
  }

  function get(url: string, token: string, cookie = "", headers: HeadersInit = {}) {
    const merged = new Headers(headers);
    if (!merged.has("Sec-Fetch-Site")) merged.set("Sec-Fetch-Site", "same-origin");
    if (merged.get("Sec-Fetch-Site") === "") merged.delete("Sec-Fetch-Site");
    merged.set("Cf-Access-Jwt-Assertion", token);
    merged.set("Cookie", cookie);
    return fetch(`${origin}${url}`, {headers: merged, redirect: "manual"});
  }

  async function administratorHeaders() {
    const token = await jwt();
    const login = await get("/auth/login", token);
    const cookie = sessionCookies(login);
    return {Cookie: cookie, "X-CSRF-Token": /artifact_csrf=([^;]+)/u.exec(cookie)?.[1] ?? "",
      Origin: origin, "Cf-Access-Jwt-Assertion": token, "Content-Type": "application/json",
      "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "cors"};
  }

  async function admit(email: string) {
    const response = await fetch(`${origin}/api/v1/members`, {
      headers: await administratorHeaders(),
      method: "POST", body: JSON.stringify({email, displayName: email, role: "member"}),
    });
    expect(response.status).toBe(201);
    return memberSchema.parse(await response.json()).member.id;
  }

  test("a verified user gets normal session cookies and a safe redirect without an OIDC round trip", async () => {
    const token = await jwt({email: "admin@example.test", sub: "admin-sub", name: "Administrator"});
    const binding = vi.spyOn(identities, "bindExternalIdentity");
    const login = await get("/auth/login?returnTo=/review/settings", token);
    expect(login.status).toBe(303);
    expect(login.headers.get("location")).toBe("/review/settings");
    expect(login.headers.getSetCookie().join(";")).toContain("HttpOnly");
    expect(login.headers.getSetCookie().join(";")).toContain("artifact_csrf=");
    const session = await get("/api/v1/session", token, sessionCookies(login));
    expect(session.status).toBe(200);
    expect(principalSchema.parse(await session.json()).principal.membershipRole).toBe("administrator");
    expect(binding).toHaveBeenCalledTimes(1);
    const again = await get("/auth/login?returnTo=/review", token, sessionCookies(login));
    expect(binding).toHaveBeenCalledTimes(1);
    binding.mockRestore();
    expect(again.status).toBe(303);
    expect(again.headers.getSetCookie()).toHaveLength(0);
  });

  test("the first HTML navigation establishes a session transparently", async () => {
    const login = await get("/review", await jwt(), "", {Accept: "text/html"});
    expect(login.status).toBe(303);
    expect(login.headers.get("location")).toBe("/review");
    expect(sessionCookies(login)).toContain("artifact_session=");
  });

  test("service tokens, content AUDs, and forged user headers cannot become a session", async () => {
    await Promise.all([await jwt({sub: "service", common_name: "automation"}),
      await jwt({sub: "service", email: "admin@example.test", common_name: "automation"}),
      await jwt({email: "admin@example.test", sub: "admin-sub"}, contentAudience)].map(async (token) => {
      const response = await get("/auth/login", token, "", {"Cf-Access-Authenticated-User-Email": "admin@example.test"});
      expect(response.status).toBe(401);
      expect(response.headers.getSetCookie()).toHaveLength(0);
    }));
    const forged = await get("/auth/login", "invalid", "", {"Cf-Access-Authenticated-User-Email": "admin@example.test"});
    expect(forged.status).toBe(403);
    expect(forged.headers.getSetCookie()).toHaveLength(0);
  });

  test("local admission remains authoritative, including when auto-admission is enabled", async () => {
    await get("/auth/login", await jwt());
    const unknownToken = await jwt({email: "unknown@example.test", sub: "unknown-sub"});
    const unknown = await get("/auth/login", unknownToken);
    expect(unknown.status).toBe(autoAdmit ? 303 : 403);
    expect(unknown.headers.getSetCookie()).toHaveLength(autoAdmit ? 2 : 0);
    const memberId = await admit("leaver@example.test");
    const leaverToken = await jwt({email: "leaver@example.test", sub: "leaver-sub"});
    const leaverLogin = await get("/auth/login", leaverToken);
    expect(leaverLogin.status).toBe(303);
    const deactivated = await fetch(`${origin}/api/v1/members/${memberId}/deactivate`, {
      method: "POST", headers: await administratorHeaders(),
    });
    expect(deactivated.status).toBe(200);
    const denied = await get("/auth/login", leaverToken);
    expect(denied.status).toBe(403);
    expect(denied.headers.getSetCookie()).toHaveLength(0);
    const stale = await get("/api/v1/session", leaverToken, sessionCookies(leaverLogin));
    expect(stale.status).not.toBe(200);
  });

  test("a different verified member replaces a stale session; unsafe requests do not run as either identity", async () => {
    const adminToken = await jwt();
    const adminLogin = await get("/auth/login", adminToken);
    const memberId = await admit("member@example.test");
    const memberToken = await jwt({email: "member@example.test", sub: "member-sub"});
    const unsafe = await fetch(`${origin}/api/v1/members`, {
      method: "POST", headers: {Cookie: sessionCookies(adminLogin), "Cf-Access-Jwt-Assertion": memberToken,
        "Content-Type": "application/json", Origin: origin, "Sec-Fetch-Site": "same-origin"},
      body: JSON.stringify({email: "not-created@example.test", displayName: "Forbidden", role: "member"}),
    });
    expect(unsafe.status).toBe(401);
    const old = await get("/api/v1/session", adminToken, sessionCookies(adminLogin));
    expect(old.status).toBe(303);
    const switched = await get("/api/v1/session", memberToken, sessionCookies(old));
    expect(switched.status).toBe(303);
    const session = await get("/api/v1/session", memberToken, sessionCookies(switched));
    expect(session.status).toBe(200);
    expect(principalSchema.parse(await session.json()).principal.id).toBe(memberId);
    const bearer = await get("/api/v1/session", memberToken, sessionCookies(old), {Authorization: `Bearer ${apiToken}`});
    expect(bearer.status).toBe(200);
    expect(principalSchema.parse(await bearer.json()).principal.id).not.toBe(memberId);
  });

  test.each(["cross-site", "same-site", ""])("%s navigation may sign in fresh but cannot replace sessions", async (site) => {
    const token = await jwt();
    const headers = {"Sec-Fetch-Site": site, Accept: "text/html"};
    // Access always returns the browser through a cross-site redirect chain.
    const login = await get("/review", token, "", headers);
    expect(login.status).toBe(303);
    const cookie = sessionCookies(login);
    expect(await identities.listMembers("access-test")).toHaveLength(1);
    const apiWithoutSession = await get("/api/v1/session", token, "", {"Sec-Fetch-Site": site});
    expect(apiWithoutSession.headers.getSetCookie()).toHaveLength(0);
    const other = await jwt({email: "other@example.test", sub: "other-sub"});
    const mismatched = await get("/auth/login", other, cookie, headers);
    expect(mismatched.status).toBe(401);
    expect(mismatched.headers.getSetCookie()).toHaveLength(0);
    expect(await identities.listMembers("access-test")).toHaveLength(1);
    const invalidIdentity = await jwt({sub: "service", common_name: "automation"});
    expect((await get("/auth/login", invalidIdentity, cookie, headers)).status).toBe(401);
    const matching = await get("/api/v1/session", token, cookie, headers);
    expect(matching.status).toBe(200);
    expect(matching.headers.getSetCookie()).toHaveLength(0);
    expect((await get("/auth/logout", token, cookie, headers)).status).toBe(401);
    expect((await get("/api/v1/session", token, cookie, headers)).status).toBe(200);
  });

  test("direct logout revokes the session before redirecting", async () => {
    const token = await jwt();
    const cookie = sessionCookies(await get("/auth/login", token));
    const logout = await get("/auth/logout", token, cookie);
    expect(logout.status).toBe(303);
    expect(logout.headers.get("location")).toBe(`${team}/cdn-cgi/access/logout`);
    expect(logout.headers.getSetCookie().join(";")).toContain("Max-Age=0");
    expect((await get("/api/v1/session", token, cookie, {"Sec-Fetch-Site": "cross-site"})).status).toBe(401);
  });

  test("returnTo cannot redirect off origin and logout leads to Access logout", async () => {
    const token = await jwt();
    await Promise.all(["https://evil.example/", "//evil.example/", "/\\\\evil.example/", "/..//evil.example/"].map(async (target) => {
      const login = await get(`/auth/login?returnTo=${encodeURIComponent(target)}`, token);
      expect(login.status).toBe(303);
      expect(login.headers.get("location")).toBe("/api/v1/session");
    }));
    const login = await get("/auth/login", token);
    const cookie = sessionCookies(login);
    const csrf = /artifact_csrf=([^;]+)/u.exec(cookie)?.[1] ?? "";
    const logout = await fetch(`${origin}/api/v1/session/logout`, {
      method: "POST", headers: {Cookie: cookie, Origin: origin, "X-CSRF-Token": csrf,
        "Cf-Access-Jwt-Assertion": token, "Sec-Fetch-Site": "same-origin"},
    });
    expect(logout.status).toBe(204);
    expect(logout.headers.getSetCookie().join(";")).toContain("Max-Age=0");
    const redirect = await get("/auth/logout", token);
    expect(redirect.status).toBe(303);
    expect(redirect.headers.get("location")).toBe(`${team}/cdn-cgi/access/logout`);
  });
});
