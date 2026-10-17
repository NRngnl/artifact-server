import * as Effect from "effect/Effect";
import { describe, expect, it } from "vitest";

import {
  parseCloudDeploymentOutput,
} from "../../../src/deployment/index.js";
import {
  CLOUDFLARE_COMPATIBILITY_DATE,
  parseCloudflareDeploymentInput,
} from "../src/deployment-input.js";
import {
  validDeploymentInput,
  validDeploymentOutput,
} from "./fixtures.js";

describe("Cloudflare deployment boundary", () => {
  it("uses the shared input and output contract", async () => {
    const input = await Effect.runPromise(
      parseCloudflareDeploymentInput(validDeploymentInput),
    );
    const output = await Effect.runPromise(
      parseCloudDeploymentOutput(input, validDeploymentOutput),
    );

    expect(input).toEqual(validDeploymentInput);
    expect(output).toEqual(validDeploymentOutput);
  });

  it("rejects a compatibility date that differs from the package pin", async () => {
    const result = await Effect.runPromiseExit(
      parseCloudflareDeploymentInput({
        ...validDeploymentInput,
        compatibilityDate: "2026-08-14",
      }),
    );

    expect(CLOUDFLARE_COMPATIBILITY_DATE).toBe("2026-08-15");
    expect(result._tag).toBe("Failure");
  });

  it("accepts Access as the sole login provider with opt-in admission", async () => {
    const input = {
      ...validDeploymentInput,
      accessLogin: true,
      accessAppAudience: "a".repeat(64),
      accessAudiences: ["a".repeat(64), "b".repeat(64)],
      accessTeamDomain: "https://example-team.cloudflareaccess.com",
      autoAdmitOidcMembers: true,
    };
    expect(await Effect.runPromise(parseCloudflareDeploymentInput(input))).toEqual(input);
  });

  it.each([
    {},
    {accessTeamDomain: "https://example-team.cloudflareaccess.com"},
    {accessTeamDomain: "https://example-team.cloudflareaccess.com", accessAudiences: ["a".repeat(64)]},
    {accessTeamDomain: "https://example-team.cloudflareaccess.com", accessAudiences: ["a".repeat(64)], accessAppAudience: "b".repeat(64)},
    {accessTeamDomain: "https://example-team.cloudflareaccess.com", accessAudiences: ["a".repeat(64)], accessAppAudience: "a".repeat(64), oidcClientId: "oidc-client", oidcIssuer: "https://issuer.example.com"},
    {accessTeamDomain: "https://example-team.cloudflareaccess.com", accessAudiences: ["a".repeat(64)], accessAppAudience: "a".repeat(64), workosClientId: "client_workos", workosIssuer: "https://issuer.example.com", workosApiKeySecretRef: "secret/workos"},
  ])("rejects incomplete, mixed-provider, and wrong-AUD Access login configuration: %j", async (settings) => {
    const result = await Effect.runPromiseExit(parseCloudflareDeploymentInput({
      ...validDeploymentInput, accessLogin: true, ...settings,
    }));
    expect(result._tag).toBe("Failure");
  });

  it("rejects local state for the shared entrypoint", async () => {
    const result = await Effect.runPromiseExit(
      parseCloudflareDeploymentInput({
        ...validDeploymentInput,
        stateStore: "local",
      }),
    );

    expect(result._tag).toBe("Failure");
  });
});
