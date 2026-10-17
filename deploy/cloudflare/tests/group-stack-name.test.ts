import {afterEach, describe, expect, it, vi} from "vitest";

import {buildCloudflareDeploymentManifest} from "../src/deployment-manifest.ts";
import {effectiveStackName} from "../src/stack-name.ts";
import {validDeploymentInput} from "./fixtures.ts";

afterEach(() => vi.unstubAllEnvs());
const groupInput = {...validDeploymentInput,
  contentHostSuffix: `-team.${validDeploymentInput.contentDomain}`};

describe("group stack namespace", () => {
  it.each([undefined, "artifact-server-cloudflare"])("rejects private state name %s", (name) => {
    vi.stubEnv("ALCHEMY_STACK_NAME", name);
    expect(() => buildCloudflareDeploymentManifest(groupInput)).toThrow("distinct ALCHEMY_STACK_NAME");
  });

  it.each(["", "../private", "UPPER", "-prefix", "a".repeat(62), "group.name", "group/name"])(
    "rejects malformed stack name %s", (name) => {
      vi.stubEnv("ALCHEMY_STACK_NAME", name);
      expect(() => effectiveStackName()).toThrow("ALCHEMY_STACK_NAME must match");
    },
  );

  it.each(["team", "a".repeat(61)])("uses the same effective name in the manifest: %s", (name) => {
    vi.stubEnv("ALCHEMY_STACK_NAME", name);
    expect(effectiveStackName(groupInput.contentHostSuffix)).toBe(name);
    expect(buildCloudflareDeploymentManifest(groupInput).stackName).toBe(name);
  });

  it("preserves the default dotted deployment", () => {
    vi.stubEnv("ALCHEMY_STACK_NAME", undefined);
    expect(buildCloudflareDeploymentManifest(validDeploymentInput).stackName)
      .toBe("artifact-server-cloudflare");
  });
});
