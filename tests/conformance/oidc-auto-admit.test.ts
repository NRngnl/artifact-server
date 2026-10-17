import path from "node:path";
import {DatabaseSync} from "node:sqlite";

import {afterEach, beforeEach, describe, expect, test} from "vitest";
import {Redacted} from "effect";
import {z} from "zod";

import {createOidcIdentityProvider} from
  "../../src/identity/oidc-identity-provider.js";
import {
  browserLoginKinds,
  privateTeamBrowserAccess,
} from "../../src/core/browser-access.js";
import {
  createTestInstallation,
  removeTestInstallation,
  reserveLoopbackPort,
  startTestServer,
  type RunningTestServer,
  type TestInstallation,
} from "../support/runtime-harness.js";
import {
  startStubOidcLogin,
  startStubOidcProvider,
  type RunningStubOidcProvider,
} from "../support/stub-oidc-provider.js";

const administratorEmail = "administrator@example.test";
const clientSecret = "stub-oidc-client-secret-with-entropy";
const sessionSchema = z.object({
  principal: z.object({id: z.string(), membershipRole: z.string()}),
});
const failureSchema = z.object({error: z.object({code: z.string()})});
const countSchema = z.object({total: z.number().int().nonnegative()});

interface Login {
  readonly cookieHeader: string;
  readonly csrf: string;
  readonly id: string;
  readonly role: string;
}

describe("opt-in OIDC auto-admission", () => {
  let installation: TestInstallation;
  let provider: RunningStubOidcProvider;
  let server: RunningTestServer | null = null;

  beforeEach(async () => {
    installation = await createTestInstallation();
    provider = await startStubOidcProvider({
      clientId: "artifact-server-oidc-test",
      clientSecret,
    });
  });

  afterEach(async () => {
    if (server !== null) await server.stop();
    server = null;
    await provider.stop();
    await removeTestInstallation(installation);
  });

  test("auto-admission admits a new verified identity as member while the bootstrap administrator stays administrator", async () => {
    server = await startServer(true);
    const administrator = await login(server, administratorEmail, "sub-admin");
    expect(administrator.role).toBe("administrator");

    const newcomer = await login(server, "newcomer@example.test", "sub-new");
    expect(newcomer.role).toBe("member");
    const again = await login(server, "newcomer@example.test", "sub-new");
    expect(again.id).toBe(newcomer.id);
    expect(rowCount("installation_members")).toBe(2);
  });

  test("unknown identities are refused when off; unverified and deactivated identities are refused when on", async () => {
    const off = await startServer(false);
    await login(off, administratorEmail, "sub-admin");
    expect(await refusal(off, "stranger@example.test", "sub-x")).toBe(
      "IDENTITY_ADMISSION_DENIED",
    );
    expect(rowCount("installation_members")).toBe(1);
    await off.stop();

    server = await startServer(true);
    provider.claims.emailVerified = false;
    expect(await refusal(server, "unverified@example.test", "sub-u")).toBe(
      "IDENTITY_ADMISSION_DENIED",
    );
    provider.claims.emailVerified = null;

    const administrator = await login(server, administratorEmail, "sub-admin");
    const member = await login(server, "leaver@example.test", "sub-leaver");
    const deactivated = await fetch(
      `${server.baseUrl}/api/v1/members/${member.id}/deactivate`,
      {
        headers: {
          Cookie: administrator.cookieHeader,
          Origin: server.baseUrl,
          "Sec-Fetch-Mode": "cors",
          "Sec-Fetch-Site": "same-origin",
          "X-CSRF-Token": administrator.csrf,
        },
        method: "POST",
      },
    );
    expect(deactivated.status).toBe(200);
    const sessionsBefore = rowCount("application_sessions");

    // Same subject and a fresh subject with the same email both stay refused.
    expect(await refusal(server, "leaver@example.test", "sub-leaver")).toBe(
      "IDENTITY_ADMISSION_DENIED",
    );
    expect(await refusal(server, "Leaver@Example.test", "sub-leaver-2")).toBe(
      "IDENTITY_ADMISSION_DENIED",
    );
    expect(rowCount("installation_members")).toBe(2);
    expect(rowCount("application_sessions")).toBe(sessionsBefore);
  });

  async function startServer(autoAdmit: boolean): Promise<RunningTestServer> {
    const port = await reserveLoopbackPort();
    const applicationOrigin = `http://127.0.0.1:${port}`;
    return startTestServer(installation, {
      applicationOrigin,
      autoAdmitExternalMembers: autoAdmit,
      bootstrapAdministratorEmail: administratorEmail,
      browserAccess: privateTeamBrowserAccess(browserLoginKinds.oidc),
      interactiveIdentityProvider: createOidcIdentityProvider({
        applicationOrigin,
        clientId: provider.clientId,
        clientSecret: Redacted.make(clientSecret, {label: "oidc-client-secret"}),
        issuer: provider.issuer,
        scopes: "openid email profile",
      }),
      port,
    });
  }

  async function callback(
    running: RunningTestServer,
    email: string,
    subject: string,
  ): Promise<Response> {
    provider.claims.email = email;
    provider.claims.subject = subject;
    const authorization = await startStubOidcLogin(running.baseUrl);
    return fetch(authorization.callbackUrl, {
      headers: {Cookie: authorization.handshakeCookie},
      redirect: "manual",
    });
  }

  async function login(
    running: RunningTestServer,
    email: string,
    subject: string,
  ): Promise<Login> {
    const completed = await callback(running, email, subject);
    expect(completed.status).toBe(303);
    const pairs = completed.headers.getSetCookie().map((value) =>
      value.split(";", 1)[0] ?? ""
    );
    const csrfPair = pairs.find((pair) => pair.startsWith("artifact_csrf="));
    const cookieHeader = pairs
      .filter((pair) =>
        pair.startsWith("artifact_session=") || pair.startsWith("artifact_csrf=")
      )
      .join("; ");
    const session = await fetch(`${running.baseUrl}/api/v1/session`, {
      headers: {Cookie: cookieHeader},
    });
    const principal = sessionSchema.parse(await session.json()).principal;
    return {
      cookieHeader,
      csrf: csrfPair?.slice("artifact_csrf=".length) ?? "",
      id: principal.id,
      role: principal.membershipRole,
    };
  }

  async function refusal(
    running: RunningTestServer,
    email: string,
    subject: string,
  ): Promise<string> {
    const completed = await callback(running, email, subject);
    expect(completed.status).toBe(403);
    expect(completed.headers.getSetCookie()).toEqual([]);
    return failureSchema.parse(await completed.json()).error.code;
  }

  function rowCount(table: string): number {
    const database = new DatabaseSync(
      path.join(installation.dataDirectory, "artifact-server.db"),
      {readOnly: true},
    );
    try {
      return countSchema.parse(
        database.prepare(`SELECT COUNT(*) AS total FROM ${table}`).get(),
      ).total;
    } finally {
      database.close();
    }
  }
});
