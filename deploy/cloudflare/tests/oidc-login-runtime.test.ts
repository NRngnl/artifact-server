import {createServer, type Server} from "node:http";
import {mkdtemp, rm} from "node:fs/promises";
import {tmpdir} from "node:os";
import {join} from "node:path";

import {z} from "zod";
import {exportJWK, generateKeyPair, SignJWT, type JWK} from "jose";
import {unstable_dev, type Unstable_DevWorker} from "wrangler";
import {afterAll, beforeAll, describe, expect, it} from "vitest";

const apiToken = "cloudflare-oidc-test-api-token-00000001";
const origin = "https://artifacts.example.test";
const contentDomain = "content.example.test";
const clientId = "artifact-server-cloudflare";

const assignedAddressSchema = z.object({
  port: z.number().int().positive(),
});
const notReadySchema = z.object({
  error: z.string(),
  message: z.string(),
}).loose();

let issuerOrigin: string;
let issuer: Server;
let accessKey: CryptoKey;
let accessJwk: JWK;

beforeAll(async () => {
  const pair = await generateKeyPair("RS256");
  accessKey = pair.privateKey;
  accessJwk = {...await exportJWK(pair.publicKey), kid: "access-runtime", alg: "RS256"};
  issuer = await startDiscoveryStub();
  const address = assignedAddressSchema.parse(issuer.address());
  issuerOrigin =
    `http://127.0.0.1:${address.port}/cdn-cgi/access/sso/oidc/${clientId}`;
}, 30_000);

afterAll(async () => {
  await new Promise<void>((resolve, reject) => {
    issuer.close((cause) => cause === undefined ? resolve() : reject(cause));
  });
});

describe("Cloudflare Worker browser-login provider", () => {
  it("uses verified Access claims on the prepared application request, without OIDC", async () => {
    const directory = await mkdtemp(join(tmpdir(), "artifact-server-access-"));
    const team = new URL(issuerOrigin).origin;
    const appAudience = "a".repeat(64);
    const contentAudience = "b".repeat(64);
    const sign = (claims: {email?: string; sub: string; common_name?: string}, aud = appAudience) =>
      new SignJWT(claims).setProtectedHeader({alg: "RS256", kid: "access-runtime"})
        .setIssuer(team).setAudience(aud).setExpirationTime("5m").sign(accessKey);
    const token = await sign({email: "administrator@example.test", sub: "administrator"});
    const worker = await startWorker(directory, {
      ARTIFACT_SERVER_CF_ACCESS_LOGIN: "true",
      ARTIFACT_SERVER_CF_ACCESS_TEAM_DOMAIN: team,
      ARTIFACT_SERVER_CF_ACCESS_AUDIENCES: `${appAudience},${contentAudience}`,
      ARTIFACT_SERVER_CF_ACCESS_APP_AUDIENCE: appAudience,
    });
    try {
      const started = await worker.fetch(`${origin}/auth/login?returnTo=/review`, {
        headers: {"Cf-Access-Jwt-Assertion": token, "Sec-Fetch-Site": "none"}, redirect: "manual",
      });
      expect(started.status).toBe(303);
      expect(started.headers.get("location")).toBe("/review");
      const cookies = started.headers.getSetCookie().map((cookie) => cookie.split(";")[0]).join("; ");
      expect(cookies).toContain("__Host-artifact_session=");
      expect(cookies).toContain("__Host-artifact_csrf=");
      const session = await worker.fetch(`${origin}/api/v1/session`, {
        headers: {Cookie: cookies, "Cf-Access-Jwt-Assertion": token},
      });
      expect(session.status).toBe(200);
      expect(z.object({principal: z.object({membershipRole: z.string()})}).parse(await session.json())
        .principal.membershipRole).toBe("administrator");
      const service = await worker.fetch(`${origin}/auth/login`, {
        headers: {"Cf-Access-Jwt-Assertion": await sign({sub: "service", common_name: "automation"})}, redirect: "manual",
      });
      expect(service.status).toBe(401);
      expect(service.headers.getSetCookie()).toHaveLength(0);
      const content = await worker.fetch(`${origin}/auth/login`, {
        headers: {"Cf-Access-Jwt-Assertion": await sign({email: "administrator@example.test", sub: "administrator"}, contentAudience)},
        redirect: "manual",
      });
      expect(content.status).toBe(401);
      expect(content.headers.getSetCookie()).toHaveLength(0);
      const logout = await worker.fetch(`${origin}/auth/logout`, {
        headers: {"Cf-Access-Jwt-Assertion": token, Cookie: cookies, "Sec-Fetch-Site": "same-origin"}, redirect: "manual",
      });
      expect(logout.status).toBe(303);
      expect(logout.headers.get("location")).toBe(`${team}/cdn-cgi/access/logout`);
    } finally {
      await worker.stop();
      await rm(directory, {force: true, recursive: true});
    }
  }, 120_000);

  it("starts generic OIDC login from a path-based issuer", async () => {
    const directory = await mkdtemp(join(tmpdir(), "artifact-server-oidc-"));
    const worker = await startWorker(directory, {
      ARTIFACT_SERVER_OIDC_CLIENT_ID: clientId,
      ARTIFACT_SERVER_OIDC_ISSUER: issuerOrigin,
    });
    try {
      const started = await worker.fetch(`${origin}/auth/login`, {
        redirect: "manual",
      });
      expect(started.status).toBe(302);
      const location = new URL(started.headers.get("location") ?? "");
      expect(location.origin).toBe(new URL(issuerOrigin).origin);
      expect(location.pathname).toBe(
        `/cdn-cgi/access/sso/oidc/${clientId}/authorize`,
      );
      expect(location.searchParams.get("client_id")).toBe(clientId);
      expect(location.searchParams.get("redirect_uri"))
        .toBe(`${origin}/auth/callback`);
      expect(location.searchParams.get("response_type")).toBe("code");
      expect(location.searchParams.get("scope")).toBe("openid email profile");
      expect(location.searchParams.get("code_challenge_method")).toBe("S256");
      expect(location.searchParams.get("code_challenge")).toBeTruthy();
      expect(location.searchParams.get("state")).toBeTruthy();
      expect(location.searchParams.get("nonce")).toBeTruthy();
    } finally {
      await worker.stop();
      await rm(directory, {force: true, recursive: true});
    }
  }, 120_000);

  it("refuses to start with both WorkOS and OIDC configured", async () => {
    const directory = await mkdtemp(join(tmpdir(), "artifact-server-oidc-both-"));
    const worker = await startWorker(directory, {
      ARTIFACT_SERVER_OIDC_CLIENT_ID: clientId,
      ARTIFACT_SERVER_OIDC_ISSUER: issuerOrigin,
      ARTIFACT_SERVER_WORKOS_API_KEY: "sk_workos_test",
      ARTIFACT_SERVER_WORKOS_CLIENT_ID: "client_workos_test",
      ARTIFACT_SERVER_WORKOS_ISSUER: "https://workos.example.test",
    });
    try {
      const ready = await worker.fetch(`${origin}/ready`);
      expect(ready.status).toBe(503);
      expect(notReadySchema.parse(await ready.json()).error)
        .toBe("artifact_server_not_ready");
    } finally {
      await worker.stop();
      await rm(directory, {force: true, recursive: true});
    }
  }, 120_000);

  it("refuses to start with a partial OIDC configuration", async () => {
    const directory = await mkdtemp(
      join(tmpdir(), "artifact-server-oidc-partial-"),
    );
    const worker = await startWorker(directory, {
      ARTIFACT_SERVER_OIDC_CLIENT_ID: clientId,
    });
    try {
      const ready = await worker.fetch(`${origin}/ready`);
      expect(ready.status).toBe(503);
      expect(notReadySchema.parse(await ready.json()).error)
        .toBe("artifact_server_not_ready");
    } finally {
      await worker.stop();
      await rm(directory, {force: true, recursive: true});
    }
  }, 120_000);

  it("fails private-team runtime initialization when no provider is configured", async () => {
    const directory = await mkdtemp(join(tmpdir(), "artifact-server-oidc-none-"));
    const worker = await startWorker(directory, {});
    try {
      const started = await worker.fetch(`${origin}/auth/login`, {
        redirect: "manual",
      });
      expect(started.status).toBe(503);
      expect(notReadySchema.parse(await started.json()).error)
        .toBe("artifact_server_not_ready");
    } finally {
      await worker.stop();
      await rm(directory, {force: true, recursive: true});
    }
  }, 120_000);
});

function startDiscoveryStub(): Promise<Server> {
  const server = createServer((request, response) => {
    if (request.url === "/cdn-cgi/access/certs") {
      response.writeHead(200, {"content-type": "application/json"});
      response.end(JSON.stringify({keys: [accessJwk]}));
      return;
    }
    const issuerPath = `/cdn-cgi/access/sso/oidc/${clientId}`;
    if (request.url !== `${issuerPath}/.well-known/openid-configuration`) {
      response.writeHead(404).end();
      return;
    }
    const host = request.headers.host ?? "127.0.0.1";
    const requestIssuer = `http://${host}${issuerPath}`;
    const document = {
      authorization_endpoint: `${requestIssuer}/authorize`,
      issuer: requestIssuer,
      jwks_uri: `${requestIssuer}/jwks`,
      token_endpoint: `${requestIssuer}/token`,
    };
    response.writeHead(200, {"content-type": "application/json"});
    response.end(JSON.stringify(document));
  });
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => resolve(server));
  });
}

function startWorker(
  persistenceDirectory: string,
  loginVariables: Record<string, string>,
): Promise<Unstable_DevWorker> {
  return unstable_dev("src/worker.ts", {
    bundle: true,
    config: "wrangler.test.jsonc",
    compatibilityDate: "2026-08-15",
    compatibilityFlags: ["nodejs_compat"],
    experimental: {
      d1Databases: [{
        binding: "ARTIFACT_SERVER_D1_DATABASE",
        database_id: "artifact-server-test-d1",
        database_name: "artifact-server-test-d1",
      }],
      disableExperimentalWarning: true,
      disableDevRegistry: true,
      testScheduled: true,
      watch: false,
    },
    inspect: false,
    local: true,
    logLevel: "error",
    persist: true,
    persistTo: persistenceDirectory,
    r2: [{
      binding: "ARTIFACT_SERVER_R2_BUCKET",
      bucket_name: "artifact-server-test-r2",
    }],
    vars: {
      ARTIFACT_SERVER_API_TOKEN: apiToken,
      ARTIFACT_SERVER_BOOTSTRAP_ADMIN_EMAIL: "administrator@example.test",
      ARTIFACT_SERVER_CONTENT_DOMAIN: contentDomain,
      ARTIFACT_SERVER_INSTALLATION_ID: "cloudflare-oidc-test",
      ARTIFACT_SERVER_ORIGIN: origin,
      ARTIFACT_SERVER_QUALIFICATION_MODE: "enabled",
      ARTIFACT_SERVER_REQUEST_LOG_SAMPLE_RATE: "0",
      ...loginVariables,
    },
  });
}
