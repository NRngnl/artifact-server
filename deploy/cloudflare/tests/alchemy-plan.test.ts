import * as Alchemy from "alchemy";
import * as Cloudflare from "alchemy/Cloudflare";
import * as Provider from "alchemy/Provider";
import * as Test from "alchemy/Test/Core";
import * as Effect from "effect/Effect";
import * as Layer from "effect/Layer";
import * as Redacted from "effect/Redacted";
import { describe, expect, it } from "vitest";

import {
  type CloudflareZoneResolver,
  defineCloudflareFoundation,
} from "../src/stack.js";
import {
  validDeploymentInput,
  validDeploymentOutput,
} from "./fixtures.js";

const providerWriteAttempt = new Error(
  "A provider write was attempted during an Alchemy plan",
);
const writeForbidden = () => Effect.die(providerWriteAttempt);
const mismatchedZoneResolver: CloudflareZoneResolver = () =>
  Effect.succeed("f".repeat(32));
const unexpectedZoneResolver: CloudflareZoneResolver = () =>
  Effect.die(new Error("private ingress attempted a DNS zone lookup"));
type PlanWorker = Alchemy.Resource<
  "Cloudflare.Worker",
  object,
  object
>;
const PlanWorker = Alchemy.Resource<PlanWorker>("Cloudflare.Worker");

const databaseProvider = Provider.succeed(
  Cloudflare.D1.Database,
  {
    reconcile: writeForbidden,
    delete: writeForbidden,
  },
);
const bucketProvider = Provider.succeed(
  Cloudflare.R2.Bucket,
  {
    reconcile: writeForbidden,
    delete: writeForbidden,
  },
);
const dnsRecordProvider = Provider.succeed(
  Cloudflare.DNS.Record,
  {
    reconcile: writeForbidden,
    delete: writeForbidden,
  },
);
const workerProvider = Provider.succeed(
  PlanWorker,
  {
    reconcile: writeForbidden,
    delete: writeForbidden,
  },
);
const individualProviders = Layer.mergeAll(
  databaseProvider,
  bucketProvider,
  dnsRecordProvider,
  workerProvider,
);
const providerCollection = Layer.succeed(
  Cloudflare.Providers,
  Cloudflare.Providers.of({
    kind: "ProviderCollection",
    providers: {},
    get: () => undefined,
  }),
);
const cloudflareEnvironment = Layer.succeed(
  Cloudflare.CloudflareEnvironment,
  Effect.succeed({
    type: "apiToken",
    apiToken: Redacted.make("test-only-cloudflare-credential"),
    accountId: validDeploymentInput.cloudflareAccountId,
    source: {
      type: "env",
    },
  }),
);
const cloudflareCredentials = Layer.succeed(
  Cloudflare.Credentials,
  Effect.succeed({
    type: "apiToken",
    apiToken: Redacted.make("test-only-cloudflare-credential"),
    apiBaseUrl: "https://api.cloudflare.invalid/client/v4",
  }),
);
const providers = Layer.mergeAll(
  individualProviders,
  providerCollection,
  cloudflareEnvironment,
  cloudflareCredentials,
);
const options = {
  providers,
  state: Alchemy.inMemoryState(),
  stage: validDeploymentInput.stage,
  sidecar: false,
} satisfies Test.MakeOptions;

describe("Alchemy foundation plan", () => {
  it("plans Access login, the public Worker, D1, R2, and content DNS without provider writes", async () => {
    const resolvedHostnames: string[] = [];
    const resolveZoneId: CloudflareZoneResolver = ({ hostname }) => {
      resolvedHostnames.push(hostname);
      return Effect.succeed(
        hostname === validDeploymentInput.applicationDomain
          ? validDeploymentInput.dnsZoneIds?.application ?? ""
          : validDeploymentInput.dnsZoneIds?.content ?? "",
      );
    };
    const accessInput = {...validDeploymentInput,
      accessLogin: true, accessAppAudience: "a".repeat(64),
      accessAudiences: ["a".repeat(64), "b".repeat(64)],
      accessTeamDomain: "https://example-team.cloudflareaccess.com"};
    const scratch = Test.scratchStack(options, "foundation-plan");
    const plan = await Test.run(
      scratch.plan(
        defineCloudflareFoundation(
          accessInput,
          Redacted.make("test-only-runtime-token-value"),
          resolveZoneId,
        ),
      ),
      options,
    );
    const resources = Object.values(plan.resources);

    expect(resources).toHaveLength(4);
    expect(
      resources
        .map(({ resource }) => resource.Type)
        .toSorted((left, right) => left.localeCompare(right)),
    ).toEqual([
      "Cloudflare.D1Database",
      "Cloudflare.DNS.Record",
      "Cloudflare.R2.Bucket",
      "Cloudflare.Worker",
    ]);
    expect(resources.every(({ action }) => action === "create")).toBe(
      true,
    );
    expect(resolvedHostnames).toEqual([
      validDeploymentInput.applicationDomain,
      validDeploymentInput.contentDomain,
    ]);
    expect(
      Object.keys(plan.output).toSorted((left, right) =>
        left.localeCompare(right)
      ),
    ).toEqual(
      Object.keys(validDeploymentOutput).toSorted((left, right) =>
        left.localeCompare(right)
      ),
    );
    expect(plan.output).toMatchObject({
      applicationUrl: "https://artifacts.example.com",
      contentDomain: "artifact-content.example.net",
      healthUrl: "https://artifacts.example.com/health",
      installationId: "review:development",
      mcpUrl: "https://artifacts.example.com/mcp",
      readinessUrl: "https://artifacts.example.com/ready",
      stateBackend: "cloudflare:alchemy-state-store",
    });

    const retained = resources
      .filter(({ resource }) =>
        resource.Type === "Cloudflare.D1Database" ||
        resource.Type === "Cloudflare.R2.Bucket"
      )
      .map(({ resource }) => resource.RemovalPolicy);
    expect(retained).toEqual(["retain", "retain"]);

    const worker = resources.find(
      ({ resource }) => resource.Type === "Cloudflare.Worker",
    );
    expect(worker?.resource.Props).toMatchObject({
      env: {
        ARTIFACT_SERVER_CF_ACCESS_LOGIN: "true",
        ARTIFACT_SERVER_CF_ACCESS_APP_AUDIENCE: accessInput.accessAppAudience,
        ARTIFACT_SERVER_CF_ACCESS_AUDIENCES: accessInput.accessAudiences.join(","),
        ARTIFACT_SERVER_CF_ACCESS_TEAM_DOMAIN: accessInput.accessTeamDomain,
      },
      assets: {
        htmlHandling: "none",
        notFoundHandling: "none",
        runWorkerFirst: true,
      },
      compatibility: {
        date: validDeploymentInput.compatibilityDate,
        flags: ["nodejs_compat"],
      },
      crons: ["*/15 * * * *"],
      domain: {
        name: validDeploymentInput.applicationDomain,
      },
      routes: [{
        pattern: `*.${validDeploymentInput.contentDomain}/*`,
        zoneId: validDeploymentInput.dnsZoneIds?.content,
      }],
      workersDev: false,
    });

    const contentDns = resources.find(
      ({ resource }) => resource.Type === "Cloudflare.DNS.Record",
    );
    expect(contentDns?.resource.Props).toMatchObject({
      content: "100::",
      name: `*.${validDeploymentInput.contentDomain}`,
      proxied: true,
      type: "AAAA",
      zoneId: validDeploymentInput.dnsZoneIds?.content,
    });
  });

  it("rejects a configured zone that does not own both domains", async () => {
    const scratch = Test.scratchStack(options, "zone-mismatch");

    await expect(
      Test.run(
        scratch.plan(
          defineCloudflareFoundation(
            validDeploymentInput,
            Redacted.make("test-only-runtime-token-value"),
            mismatchedZoneResolver,
          ),
        ),
        options,
      ),
    ).rejects.toThrow(
      "dnsZoneIds.application does not match the application domain zone inferred by Cloudflare",
    );
  });

  it("binds hosted WorkOS settings only as one complete deployment contract", async () => {
    const hostedInput = {
      ...validDeploymentInput,
      workosApiKeySecretRef:
        "cloudflare-secrets-store://artifact-server-workos",
      workosClientId: "client_01_artifact_server",
      workosIssuer: "https://artifact-server-staging.authkit.example",
    };
    const resolveZoneId: CloudflareZoneResolver = ({hostname}) =>
      Effect.succeed(
        hostname === hostedInput.applicationDomain
          ? hostedInput.dnsZoneIds?.application ?? ""
          : hostedInput.dnsZoneIds?.content ?? "",
      );
    const scratch = Test.scratchStack(options, "hosted-auth-plan");
    const plan = await Test.run(
      scratch.plan(
        defineCloudflareFoundation(
          hostedInput,
          Redacted.make("test-only-runtime-token-value"),
          resolveZoneId,
          {workOsApiKey: Redacted.make("test-only-workos-key-value")},
        ),
      ),
      options,
    );
    const worker = Object.values(plan.resources).find(
      ({resource}) => resource.Type === "Cloudflare.Worker",
    );

    expect(worker?.resource.Props).toMatchObject({
      env: {
        ARTIFACT_SERVER_WORKOS_CLIENT_ID: hostedInput.workosClientId,
        ARTIFACT_SERVER_WORKOS_ISSUER: hostedInput.workosIssuer,
      },
    });

    await expect(
      Test.run(
        scratch.plan(
          defineCloudflareFoundation(
            hostedInput,
            Redacted.make("test-only-runtime-token-value"),
            resolveZoneId,
          ),
        ),
        options,
      ),
    ).rejects.toThrow(
      "Configured WorkOS authentication requires its deployment secret.",
    );
  });

  it("binds generic OIDC settings without WorkOS", async () => {
    const oidcInput = {
      ...validDeploymentInput,
      oidcClientId: "artifact-server-cloudflare",
      oidcClientSecretRef:
        "cloudflare-secrets-store://artifact-server-oidc-client-secret",
      oidcIssuer:
        "https://team.cloudflareaccess.com/cdn-cgi/access/sso/oidc/client-id",
      oidcScopes: "openid email profile",
    };
    const resolveZoneId: CloudflareZoneResolver = ({hostname}) =>
      Effect.succeed(
        hostname === oidcInput.applicationDomain
          ? oidcInput.dnsZoneIds?.application ?? ""
          : oidcInput.dnsZoneIds?.content ?? "",
      );
    const scratch = Test.scratchStack(options, "oidc-auth-plan");
    const oidcClientSecret = "test-only-oidc-client-secret-value";
    const plan = await Test.run(
      scratch.plan(
        defineCloudflareFoundation(
          oidcInput,
          Redacted.make("test-only-runtime-token-value"),
          resolveZoneId,
          {oidcClientSecret: Redacted.make(oidcClientSecret)},
        ),
      ),
      options,
    );
    const worker = Object.values(plan.resources).find(
      ({resource}) => resource.Type === "Cloudflare.Worker",
    );
    const environment = worker?.resource.Props.env;

    expect(environment).toMatchObject({
      ARTIFACT_SERVER_OIDC_CLIENT_ID: oidcInput.oidcClientId,
      ARTIFACT_SERVER_OIDC_ISSUER: oidcInput.oidcIssuer,
      ARTIFACT_SERVER_OIDC_SCOPES: oidcInput.oidcScopes,
    });
    expect(environment).not.toHaveProperty("ARTIFACT_SERVER_WORKOS_CLIENT_ID");
    expect(JSON.stringify(environment)).not.toContain(oidcClientSecret);

    await expect(
      Test.run(
        scratch.plan(
          defineCloudflareFoundation(
            oidcInput,
            Redacted.make("test-only-runtime-token-value"),
            resolveZoneId,
          ),
        ),
        options,
      ),
    ).rejects.toThrow(
      "Configured OIDC authentication requires its deployment secret.",
    );
  });

  it("binds Access auto-admission, policy sync, and JWT enforcement", async () => {
    const accessInput = {
      ...validDeploymentInput,
      accessAudiences: ["abc123def456", "fedcba654321"],
      accessSyncApiTokenSecretRef:
        "cloudflare-secrets-store://artifact-server-access-sync-token",
      accessSyncPolicyId: "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0",
      accessTeamDomain: "https://team.cloudflareaccess.com",
      autoAdmitOidcMembers: true,
      oidcClientId: "artifact-server-cloudflare",
      oidcIssuer:
        "https://team.cloudflareaccess.com/cdn-cgi/access/sso/oidc/client-id",
    };
    const resolveZoneId: CloudflareZoneResolver = ({hostname}) =>
      Effect.succeed(
        hostname === accessInput.applicationDomain
          ? accessInput.dnsZoneIds.application
          : accessInput.dnsZoneIds.content,
      );
    const scratch = Test.scratchStack(options, "access-plan");
    const syncToken = "test-only-access-sync-token-value";
    const plan = await Test.run(
      scratch.plan(
        defineCloudflareFoundation(
          accessInput,
          Redacted.make("test-only-runtime-token-value"),
          resolveZoneId,
          {accessSyncApiToken: Redacted.make(syncToken)},
        ),
      ),
      options,
    );
    const worker = Object.values(plan.resources).find(
      ({resource}) => resource.Type === "Cloudflare.Worker",
    );
    const environment = worker?.resource.Props.env;

    expect(environment).toMatchObject({
      ARTIFACT_SERVER_AUTO_ADMIT_OIDC_MEMBERS: "true",
      ARTIFACT_SERVER_CF_ACCESS_AUDIENCES: "abc123def456,fedcba654321",
      ARTIFACT_SERVER_CF_ACCESS_SYNC_ACCOUNT_ID: accessInput.cloudflareAccountId,
      ARTIFACT_SERVER_CF_ACCESS_SYNC_POLICY_ID: accessInput.accessSyncPolicyId,
      ARTIFACT_SERVER_CF_ACCESS_TEAM_DOMAIN: accessInput.accessTeamDomain,
    });
    expect(JSON.stringify(environment)).not.toContain(syncToken);

    await expect(
      Test.run(
        scratch.plan(
          defineCloudflareFoundation(
            accessInput,
            Redacted.make("test-only-runtime-token-value"),
            resolveZoneId,
          ),
        ),
        options,
      ),
    ).rejects.toThrow(
      "Configured Access policy sync requires its deployment secret.",
    );
  });

  it("keeps private ingress off domains and workers.dev", async () => {
    const {
      dnsZoneIds: _dnsZoneIds,
      ...deploymentInputWithoutZone
    } = validDeploymentInput;
    const privateDeploymentInput = {
      ...deploymentInputWithoutZone,
      ingress: "private" as const,
    };
    const scratch = Test.scratchStack(options, "private-ingress");
    const plan = await Test.run(
      scratch.plan(
        defineCloudflareFoundation(
          privateDeploymentInput,
          Redacted.make("test-only-runtime-token-value"),
          unexpectedZoneResolver,
        ),
      ),
      options,
    );
    const worker = Object.values(plan.resources).find(
      ({ resource }) => resource.Type === "Cloudflare.Worker",
    );

    expect(worker?.resource.Props).not.toHaveProperty("domain");
    expect(worker?.resource.Props).toMatchObject({
      workersDev: false,
    });
  });
});
