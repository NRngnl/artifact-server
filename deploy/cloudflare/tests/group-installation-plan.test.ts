import * as Alchemy from "alchemy";
import * as Cloudflare from "alchemy/Cloudflare";
import * as Provider from "alchemy/Provider";
import * as Test from "alchemy/Test/Core";
import * as Effect from "effect/Effect";
import * as Layer from "effect/Layer";
import * as Redacted from "effect/Redacted";
import {afterEach, expect, it, vi} from "vitest";

import {defineCloudflareFoundation} from "../src/stack.js";
import {validDeploymentInput} from "./fixtures.js";

const forbidden = () => Effect.die(new Error("Group plans must never write providers"));
const readOnlyProvider = {reconcile: forbidden, delete: forbidden};
type PlanWorker = Alchemy.Resource<"Cloudflare.Worker", object, object>;
const PlanWorker = Alchemy.Resource<PlanWorker>("Cloudflare.Worker");
const providers = Layer.mergeAll(
  Provider.succeed(Cloudflare.D1.Database, readOnlyProvider),
  Provider.succeed(Cloudflare.R2.Bucket, readOnlyProvider),
  Provider.succeed(Cloudflare.DNS.Record, readOnlyProvider),
  Provider.succeed(PlanWorker, readOnlyProvider),
  Layer.succeed(Cloudflare.Providers, Cloudflare.Providers.of({
    kind: "ProviderCollection", providers: {}, get: () => undefined,
  })),
  Layer.succeed(Cloudflare.CloudflareEnvironment, Effect.succeed({
    type: "apiToken", apiToken: Redacted.make("test-only-cloudflare-credential"),
    accountId: validDeploymentInput.cloudflareAccountId, source: {type: "env"},
  })),
  Layer.succeed(Cloudflare.Credentials, Effect.succeed({
    type: "apiToken", apiToken: Redacted.make("test-only-cloudflare-credential"),
    apiBaseUrl: "https://api.cloudflare.invalid/client/v4",
  })),
);
const options = {providers, state: Alchemy.inMemoryState(),
  stage: validDeploymentInput.stage, sidecar: false} satisfies Test.MakeOptions;

afterEach(() => vi.unstubAllEnvs());

it("plans isolated flat DNS, route, and runtime suffix without writes", async () => {
  vi.stubEnv("ALCHEMY_STACK_NAME", "artifact-server-team");
  const input = {...validDeploymentInput,
    contentHostSuffix: `-team.${validDeploymentInput.contentDomain}`};
  const scratch = Test.scratchStack(options, "flat-content-plan");
  const plan = await Test.run(scratch.plan(defineCloudflareFoundation(
    input, Redacted.make("test-only-runtime-token-value"),
    ({hostname}) => Effect.succeed(hostname === input.applicationDomain
      ? input.dnsZoneIds.application : input.dnsZoneIds.content),
  )), options);
  const resources = Object.values(plan.resources);
  const dns = resources.find(({resource}) => resource.Type === "Cloudflare.DNS.Record");
  const worker = resources.find(({resource}) => resource.Type === "Cloudflare.Worker");
  expect(dns?.resource.Props).toMatchObject({name: `*${input.contentHostSuffix}`});
  expect(worker?.resource.Props).toMatchObject({
    env: {ARTIFACT_SERVER_CONTENT_HOST_SUFFIX: input.contentHostSuffix},
    routes: expect.arrayContaining([{
      pattern: `*${input.contentHostSuffix}/*`, zoneId: input.dnsZoneIds.content,
    }]),
  });
});

it("refuses the private stack before resolving any provider resources", async () => {
  vi.stubEnv("ALCHEMY_STACK_NAME", "artifact-server-cloudflare");
  const input = {...validDeploymentInput,
    contentHostSuffix: `-team.${validDeploymentInput.contentDomain}`};
  const scratch = Test.scratchStack(options, "blocked-group-plan");
  await expect(Test.run(scratch.plan(defineCloudflareFoundation(
    input, Redacted.make("test-only-runtime-token-value"),
    () => Effect.die(new Error("Group guard ran after provider lookup")),
  )), options)).rejects.toThrow("distinct ALCHEMY_STACK_NAME");
});
