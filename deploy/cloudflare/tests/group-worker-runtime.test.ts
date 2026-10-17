import {mkdtemp, rm} from "node:fs/promises";
import {tmpdir} from "node:os";
import {join} from "node:path";

import {expect, it} from "vitest";
import {unstable_dev} from "wrangler";

it.each([
  {suffix: `-${"a".repeat(16)}.content.example.test`, status: 200},
  {suffix: "-team.extra.content.example.test", status: 503},
  {suffix: "-te--am.content.example.test", status: 503},
])("validates runtime suffix $suffix before initialization", async ({suffix, status}) => {
  const directory = await mkdtemp(join(tmpdir(), "artifact-group-runtime-"));
  const worker = await unstable_dev("src/worker.ts", {
    bundle: true, config: "wrangler.test.jsonc", compatibilityDate: "2026-08-15",
    compatibilityFlags: ["nodejs_compat"], inspect: false, local: true, logLevel: "error",
    persist: true, persistTo: directory,
    experimental: {
      d1Databases: [{binding: "ARTIFACT_SERVER_D1_DATABASE",
        database_id: "artifact-group-test-d1", database_name: "artifact-group-test-d1"}],
      disableExperimentalWarning: true, disableDevRegistry: true, watch: false,
    },
    r2: [{binding: "ARTIFACT_SERVER_R2_BUCKET", bucket_name: "artifact-group-test-r2"}],
    vars: {
      ARTIFACT_SERVER_API_TOKEN: "cloudflare-test-api-token-0000000000000001",
      ARTIFACT_SERVER_BOOTSTRAP_ADMIN_EMAIL: "administrator@example.test",
      ARTIFACT_SERVER_CONTENT_DOMAIN: "content.example.test",
      ARTIFACT_SERVER_CONTENT_HOST_SUFFIX: suffix,
      ARTIFACT_SERVER_INSTALLATION_ID: "group-runtime-test",
      ARTIFACT_SERVER_OIDC_CLIENT_ID: "cloudflare-worker-test",
      ARTIFACT_SERVER_OIDC_ISSUER: "https://identity.example.test",
      ARTIFACT_SERVER_ORIGIN: "https://artifacts.example.test",
      ARTIFACT_SERVER_REQUEST_LOG_SAMPLE_RATE: "0",
    },
  });
  try {
    const response = await worker.fetch("https://artifacts.example.test/health");
    expect(response.status).toBe(status);
  } finally {
    await worker.stop();
    await rm(directory, {force: true, recursive: true});
  }
}, 30_000);
