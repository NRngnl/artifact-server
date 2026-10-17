import {mkdtemp, rm} from "node:fs/promises";
import {tmpdir} from "node:os";
import path from "node:path";

import {afterEach, beforeEach, describe, expect, test, vi} from "vitest";
import {z} from "zod";

import {SqliteIdentityRepository} from
  "../../../src/storage/sqlite-identity-repository.js";
import type {IdentityRepository} from "../../../src/core/identity-ports.js";
import {reconcileAccessPolicy, withAccessPolicySync} from "../src/access-policy-sync.js";

const installationId = "access-sync-installation";
const bootstrapEmail = "admin@example.com";
const policyUrl =
  "https://api.cloudflare.com/client/v4/accounts/acct/access/policies/pol";

const putBodySchema = z.looseObject({include: z.array(z.json())});

interface PolicyServer {
  readonly fetch: typeof fetch;
  readonly puts: Array<z.infer<typeof putBodySchema>>;
  include: Array<z.infer<ReturnType<typeof z.json>>>;
  mode: "ok" | "fail" | "hang";
}

function policyServer(): PolicyServer {
  const server: PolicyServer = {
    fetch: async (input, init) => {
      const request = new Request(input, init);
      expect(request.url).toBe(policyUrl);
      expect(request.headers.get("authorization")).toBe("Bearer secret-token");
      if (server.mode === "fail") return new Response("{}", {status: 500});
      if (server.mode === "hang") {
        return new Promise<Response>((_resolve, reject) => {
          init?.signal?.addEventListener("abort", () =>
            reject(init.signal?.reason));
        });
      }
      if (request.method === "PUT") {
        const body = putBodySchema.parse(await request.json());
        server.puts.push(body);
        server.include = body.include;
        return Response.json({result: body, success: true});
      }
      return Response.json({
        result: {
          created_at: "2026-01-01T00:00:00Z",
          decision: "allow",
          exclude: [],
          id: "pol",
          include: server.include,
          name: "artifact-server-members",
          require: [],
          session_duration: "24h",
        },
        success: true,
      });
    },
    include: [{email: {email: bootstrapEmail}}],
    mode: "ok",
    puts: [],
  };
  return server;
}

describe("Cloudflare Access policy sync", () => {
  let directory: string;
  let inner: SqliteIdentityRepository;
  let server: PolicyServer;
  let repository: IdentityRepository;
  let counter = 0;

  beforeEach(async () => {
    directory = await mkdtemp(path.join(tmpdir(), "access-sync-"));
    inner = new SqliteIdentityRepository(path.join(directory, "identity.db"));
    server = policyServer();
    repository = withAccessPolicySync(inner, {
      accountId: "acct",
      apiToken: "secret-token",
      bootstrapAdministratorEmail: bootstrapEmail,
      fetch: server.fetch,
      policyId: "pol",
      timeoutMs: 50,
    });
  });

  afterEach(async () => {
    vi.restoreAllMocks();
    inner.close();
    await rm(directory, {force: true, recursive: true});
  });

  const admit = (email: string, role: "administrator" | "member" = "member") =>
    repository.admitMember({
      createdAt: "2026-01-01T00:00:00.000Z",
      displayName: email,
      email,
      id: `member-${++counter}`,
      installationId,
      role,
    });

  test("admit adds the email and keeps every writable field", async () => {
    await admit("ada@example.com");
    expect(server.include).toEqual([
      {email: {email: bootstrapEmail}},
      {email: {email: "ada@example.com"}},
    ]);
    expect(server.puts[0]).toEqual({
      decision: "allow",
      exclude: [],
      include: server.include,
      name: "artifact-server-members",
      require: [],
      session_duration: "24h",
    });
  });

  test("admit is idempotent and case-insensitive", async () => {
    server.include.push({email: {email: "Ada@Example.com"}});
    await admit("ada@example.com");
    expect(server.puts).toEqual([]);
  });

  test("deactivate removes the email but never the bootstrap admin", async () => {
    const admin = await admit(bootstrapEmail, "administrator");
    await admit("second-admin@example.com", "administrator");
    const member = await admit("ada@example.com");
    await repository.deactivateMember(installationId, member.id, "2026-01-02T00:00:00.000Z");
    expect(server.include).toEqual([
      {email: {email: bootstrapEmail}},
      {email: {email: "second-admin@example.com"}},
    ]);
    const putsBefore = server.puts.length;
    await repository.deactivateMember(installationId, admin.id, "2026-01-02T00:00:00.000Z");
    expect(server.puts.length).toBe(putsBefore);
    expect(server.include).toContainEqual({email: {email: bootstrapEmail}});
  });

  test("removal that would empty the include list is refused", async () => {
    server.include = [{email: {email: "solo@example.com"}}];
    const warn = vi.spyOn(console, "warn").mockImplementation(() => undefined);
    const member = await admit("solo@example.com");
    await repository.deactivateMember(installationId, member.id, "2026-01-02T00:00:00.000Z");
    expect(server.include).toEqual([{email: {email: "solo@example.com"}}]);
    expect(String(warn.mock.calls[0]?.[0])).toContain("refused_empty_include");
  });

  test("reconcile repairs drift, preserves manual rules, and skips unchanged policies", async () => {
    const active = await admit("ada@example.com");
    const inactive = await admit("leaver@example.com");
    await repository.deactivateMember(installationId, inactive.id, "2026-01-02T00:00:00.000Z");
    server.include = [
      {email: {email: " LEAVER@EXAMPLE.COM "}},
      {email: {email: "manual@example.com"}},
      {group: {id: "manual-group"}},
    ];
    server.puts.length = 0;
    const config = {accountId: "acct", apiToken: "secret-token", policyId: "pol",
      bootstrapAdministratorEmail: " ADMIN@EXAMPLE.COM ", fetch: server.fetch};
    const log = vi.spyOn(console, "info").mockImplementation(() => undefined);
    await reconcileAccessPolicy(repository, installationId, config);
    expect(server.include).toEqual([
      {email: {email: "manual@example.com"}}, {group: {id: "manual-group"}},
      {email: {email: bootstrapEmail}}, {email: {email: active.email}},
    ]);
    expect(server.puts).toHaveLength(1);
    expect(log.mock.calls).toEqual([[JSON.stringify({event: "cloudflare_access_policy_reconciled", added: 2, removed: 1})]]);
    server.include[3] = {email: {email: " ADA@EXAMPLE.COM "}};
    await reconcileAccessPolicy(repository, installationId, config);
    expect(server.puts).toHaveLength(1);
  });

  test("API failure and timeout do not fail the member change or leak secrets", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => undefined);
    server.mode = "fail";
    const failed = await admit("ada@example.com");
    server.mode = "hang";
    const timedOut = await admit("bob@example.com");
    expect((await inner.findMember(installationId, failed.id))?.status).toBe("active");
    expect((await inner.findMember(installationId, timedOut.id))?.status).toBe("active");
    const logs = warn.mock.calls.map((call) => String(call[0]));
    expect(logs[0]).toContain("get_http_500");
    expect(logs[1]).toContain("timeout");
    for (const line of logs) {
      expect(line).not.toContain("secret-token");
      expect(line).not.toContain("@example.com");
    }
  });
});
