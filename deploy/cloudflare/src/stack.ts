import * as Alchemy from "alchemy";
import * as Cloudflare from "alchemy/Cloudflare";
import * as Output from "alchemy/Output";
import * as Effect from "effect/Effect";
import type * as Redacted from "effect/Redacted";

import type { CloudflareDeploymentInput } from "./deployment-input.ts";
import {
  buildCloudflareDeploymentManifest,
  type CloudflareDeploymentManifest,
} from "./deployment-manifest.ts";

const WORKER_ENTRYPOINT = new URL("./worker.ts", import.meta.url).pathname;
const WEB_ASSET_DIRECTORY = new URL("../../../dist/web", import.meta.url).pathname;

export type CloudflareZoneResolver =
  typeof Cloudflare.Zone.resolveZoneId;

/** Secret values supplied to the Cloudflare authentication adapters. */
export interface CloudflareAuthenticationSecrets {
  readonly accessSyncApiToken?: Redacted.Redacted;
  readonly oidcClientSecret?: Redacted.Redacted;
  readonly workOsApiKey?: Redacted.Redacted;
}

const accountMismatch = (
  expectedAccountId: string,
  actualAccountId: string,
) =>
  expectedAccountId === actualAccountId
    ? Effect.void
    : Effect.die(
        new Error(
          "cloudflareAccountId does not match the authenticated Alchemy account",
        ),
      );

const validatePublicDnsZone = Effect.fn("validatePublicDnsZone")(
  function* (
    input: CloudflareDeploymentInput,
    accountId: string,
    resolveZoneId: CloudflareZoneResolver,
  ) {
    if (input.ingress !== "public") {
      return;
    }
    const configuredZoneIds = input.dnsZoneIds;
    if (configuredZoneIds === undefined) {
      yield* Effect.die(
        new Error("public ingress requires dnsZoneIds"),
      );
      return;
    }
    const [applicationZoneId, contentZoneId] = yield* Effect.all([
      resolveZoneId({
        accountId,
        hostname: input.applicationDomain,
        zone: undefined,
      }).pipe(Effect.orDie),
      resolveZoneId({
        accountId,
        hostname: input.contentDomain,
        zone: undefined,
      }).pipe(Effect.orDie),
    ]);
    if (applicationZoneId !== configuredZoneIds.application) {
      yield* Effect.die(
        new Error(
          "dnsZoneIds.application does not match the application domain zone inferred by Cloudflare",
        ),
      );
    }
    if (contentZoneId !== configuredZoneIds.content) {
      yield* Effect.die(
        new Error(
          "dnsZoneIds.content does not match the content domain zone inferred by Cloudflare",
        ),
      );
    }
  },
);

const requireContentDnsZoneId = (
  input: CloudflareDeploymentInput,
): Effect.Effect<string> => input.dnsZoneIds === undefined
  ? Effect.die(new Error("public ingress requires a content DNS zone"))
  : Effect.succeed(input.dnsZoneIds.content);

const defineDurableResources = Effect.fn("defineDurableResources")(
  function* (manifest: CloudflareDeploymentManifest) {
    const database = yield* Cloudflare.D1.Database("Records", {
      name: manifest.resourceNames.database,
      readReplication: { mode: "disabled" },
    }).pipe(Alchemy.RemovalPolicy.retain());

    const bucket = yield* Cloudflare.R2.Bucket("Objects", {
      name: manifest.resourceNames.bucket,
      lifecycleRules: [
        {
          id: "abort-incomplete-uploads",
          abortMultipartUploadsTransition: {
            condition: {
              type: "Age",
              maxAge: 7 * 24 * 60 * 60,
            },
          },
        },
      ],
    }).pipe(Alchemy.RemovalPolicy.retain());

    return { database, bucket };
  },
);

export const defineCloudflareFoundation = Effect.fn(
  "defineCloudflareFoundation",
)(function* (
  input: CloudflareDeploymentInput,
  apiToken: Redacted.Redacted,
  resolveZoneId: CloudflareZoneResolver =
    Cloudflare.Zone.resolveZoneId,
  authenticationSecrets: CloudflareAuthenticationSecrets = {},
) {
  const manifest = buildCloudflareDeploymentManifest(input);
  const credentials = yield* yield* Cloudflare.CloudflareEnvironment;
  yield* accountMismatch(
    input.cloudflareAccountId,
    credentials.accountId,
  );
  yield* validatePublicDnsZone(
    input,
    credentials.accountId,
    resolveZoneId,
  );

  const { database, bucket } = yield* defineDurableResources(manifest);
  const artifacts = input.cloudflareArtifactsNamespace === undefined
    ? undefined
    : yield* Cloudflare.Artifacts.Namespace("ARTIFACTS", {
      namespace: input.cloudflareArtifactsNamespace,
    });

  const contentWildcardDns = input.ingress === "public"
    ? yield* Cloudflare.DNS.Record("ContentWildcardDns", {
      comment: "Artifact Server version content",
      content: "100::",
      name: `*${input.contentHostSuffix ?? `.${input.contentDomain}`}`,
      proxied: true,
      ttl: "1",
      type: "AAAA",
      zoneId: input.dnsZoneIds?.content ?? "",
    })
    : undefined;

  const qualificationMode = input.stage.startsWith("probe-runtime-");
  let workerEnvironment: Cloudflare.WorkerProps["env"] = {
    ...manifest.runtimeConfiguration,
    ARTIFACT_SERVER_API_TOKEN: apiToken,
    ARTIFACT_SERVER_INSTALLATION_ID:
      `${input.installationName}:${input.environment}`,
    ARTIFACT_SERVER_D1_DATABASE: database,
    ARTIFACT_SERVER_R2_BUCKET: bucket,
  };
  if (qualificationMode) {
    workerEnvironment = {
      ...workerEnvironment,
      ARTIFACT_SERVER_QUALIFICATION_MODE: "enabled",
    };
  }
  if (artifacts !== undefined) {
    workerEnvironment = {
      ...workerEnvironment,
      ARTIFACTS: artifacts,
      ARTIFACT_SERVER_CLOUDFLARE_ARTIFACTS_ACCOUNT_ID:
        input.cloudflareAccountId,
      ARTIFACT_SERVER_CLOUDFLARE_ARTIFACTS_NAMESPACE:
        input.cloudflareArtifactsNamespace,
    };
  }
  if (
    input.workosApiKeySecretRef !== undefined &&
    input.workosClientId !== undefined && input.workosIssuer !== undefined
  ) {
    if (authenticationSecrets.workOsApiKey === undefined) {
      return yield* Effect.die(
        new Error("Configured WorkOS authentication requires its deployment secret."),
      );
    }
    workerEnvironment = {
      ...workerEnvironment,
      ARTIFACT_SERVER_WORKOS_API_KEY: authenticationSecrets.workOsApiKey,
      ARTIFACT_SERVER_WORKOS_CLIENT_ID: input.workosClientId,
      ARTIFACT_SERVER_WORKOS_ISSUER: input.workosIssuer,
    };
  }
  if (input.oidcClientId !== undefined && input.oidcIssuer !== undefined) {
    workerEnvironment = {
      ...workerEnvironment,
      ARTIFACT_SERVER_OIDC_CLIENT_ID: input.oidcClientId,
      ARTIFACT_SERVER_OIDC_ISSUER: input.oidcIssuer,
    };
    if (input.oidcClientSecretRef !== undefined) {
      const oidcClientSecret = authenticationSecrets.oidcClientSecret;
      if (oidcClientSecret === undefined) {
        return yield* Effect.die(
          new Error(
            "Configured OIDC authentication requires its deployment secret.",
          ),
        );
      }
      workerEnvironment = {
        ...workerEnvironment,
        ARTIFACT_SERVER_OIDC_CLIENT_SECRET: oidcClientSecret,
      };
    }
    if (input.oidcScopes !== undefined) {
      workerEnvironment = {
        ...workerEnvironment,
        ARTIFACT_SERVER_OIDC_SCOPES: input.oidcScopes,
      };
    }
  }
  if (input.autoAdmitOidcMembers === true) {
    workerEnvironment = {
      ...workerEnvironment,
      ARTIFACT_SERVER_AUTO_ADMIT_OIDC_MEMBERS: "true",
    };
  }
  if (
    input.accessSyncPolicyId !== undefined &&
    input.accessSyncApiTokenSecretRef !== undefined
  ) {
    if (authenticationSecrets.accessSyncApiToken === undefined) {
      return yield* Effect.die(
        new Error("Configured Access policy sync requires its deployment secret."),
      );
    }
    workerEnvironment = {
      ...workerEnvironment,
      ARTIFACT_SERVER_CF_ACCESS_SYNC_ACCOUNT_ID: input.cloudflareAccountId,
      ARTIFACT_SERVER_CF_ACCESS_SYNC_API_TOKEN:
        authenticationSecrets.accessSyncApiToken,
      ARTIFACT_SERVER_CF_ACCESS_SYNC_POLICY_ID: input.accessSyncPolicyId,
    };
  }
  if (input.accessTeamDomain !== undefined && input.accessAudiences !== undefined) {
    workerEnvironment = {
      ...workerEnvironment,
      ARTIFACT_SERVER_CF_ACCESS_AUDIENCES: input.accessAudiences.join(","),
      ARTIFACT_SERVER_CF_ACCESS_TEAM_DOMAIN: input.accessTeamDomain,
    };
  }
  if (input.accessLogin === true) {
    workerEnvironment = {
      ...workerEnvironment,
      ARTIFACT_SERVER_CF_ACCESS_LOGIN: "true",
      ARTIFACT_SERVER_CF_ACCESS_APP_AUDIENCE: input.accessAppAudience,
    };
  }
  const workerProps: Cloudflare.WorkerProps = {
    assets: {
      directory: WEB_ASSET_DIRECTORY,
      htmlHandling: "none",
      notFoundHandling: "none",
      runWorkerFirst: true,
    },
    name: manifest.resourceNames.worker,
    main: WORKER_ENTRYPOINT,
    compatibility: {
      date: input.compatibilityDate,
      flags: ["nodejs_compat"],
    },
    crons: ["*/15 * * * *"],
    workersDev: qualificationMode,
    env: workerEnvironment,
    observability: {
      enabled: true,
      logs: {
        enabled: true,
        invocationLogs: true,
        headSamplingRate: input.requestLogSampleRate ?? 0.01,
      },
    },
    tags: [...manifest.workerTags],
  };
  if (input.ingress === "public") {
    const contentZoneId = yield* requireContentDnsZoneId(input);
    workerProps.domain = {
      name: input.applicationDomain,
    };
    workerProps.routes = [{
      pattern: manifest.routes.content,
      zoneId: contentZoneId,
    }];
  }
  const worker = yield* Cloudflare.Worker(
    "Application",
    workerProps,
  );

  const applicationUrl = manifest.applicationOrigin;
  const bundleDigest = Output.map(
    worker.hash,
    (hash) =>
      `sha256:${hash?.bundle ?? "0".repeat(64)}`,
  );
  const supportManifestLocation = Output.interpolate`r2://${bucket.bucketName}/support/installation-manifest.json`;
  const output = {
    installationId: `${input.installationName}:${input.environment}`,
    applicationUrl,
    contentDomain: input.contentDomain,
    mcpUrl: `${applicationUrl}/mcp`,
    healthUrl: `${applicationUrl}/health`,
    readinessUrl: `${applicationUrl}/ready`,
    imageDigest: bundleDigest,
    runtimeResourceId: worker.workerId,
    databaseResourceId: database.databaseId,
    objectStorageResourceId: bucket.bucketName,
    workloadIdentityResourceId: worker.workerId,
    secretResourceIds: {
      alchemyStateStore:
        "cloudflare-secrets-store://alchemy-state-store",
    },
    networkResourceIds: input.dnsZoneIds === undefined
      ? {}
      : {
        applicationDnsZoneId: input.dnsZoneIds.application,
        contentWildcardDnsRecordId:
          contentWildcardDns?.recordId ?? "",
        contentDnsZoneId: input.dnsZoneIds.content,
      },
    logDestination: Output.interpolate`cloudflare-workers://${worker.workerName}`,
    stateBackend: "cloudflare:alchemy-state-store",
    supportManifestLocation,
  };

  return qualificationMode
    ? {...output, qualificationUrl: worker.url}
    : output;
});
