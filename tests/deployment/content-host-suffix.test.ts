import {Effect} from "effect";
import {describe, expect, test} from "vitest";

import {parseCloudDeploymentInput} from "../../src/deployment/cloud-deployment-contract.js";
import {validDeploymentInput} from "../../deploy/cloudflare/tests/fixtures.js";

const suffix = `-team.${validDeploymentInput.contentDomain}`;

describe("Cloudflare content-host suffix contract", () => {
  test("accepts an optional installation suffix without changing the default", async () => {
    expect(await Effect.runPromise(parseCloudDeploymentInput(validDeploymentInput)))
      .toEqual(validDeploymentInput);
    const input = {...validDeploymentInput, contentHostSuffix: suffix};
    expect(await Effect.runPromise(parseCloudDeploymentInput(input))).toEqual(input);
  });

  test.each(["a", "a-b", "a".repeat(16)])("accepts bounded group %s", async (group) => {
    const input = {...validDeploymentInput,
      contentHostSuffix: `-${group}.${validDeploymentInput.contentDomain}`};
    expect(await Effect.runPromise(parseCloudDeploymentInput(input))).toEqual(input);
  });

  test.each([
    "", ".content.example.org", "team.content.example.org", "-TEAM.content.example.org",
    "-team.other.net", "-team.content.example.org.evil.test",
    `-${"a".repeat(17)}.${validDeploymentInput.contentDomain}`,
    `--team.${validDeploymentInput.contentDomain}`,
    `-team-.${validDeploymentInput.contentDomain}`,
    `-te--am.${validDeploymentInput.contentDomain}`,
    `-team.extra.${validDeploymentInput.contentDomain}`,
    `-team..${validDeploymentInput.contentDomain}`,
    `-team:443.${validDeploymentInput.contentDomain}`,
    `-team/path.${validDeploymentInput.contentDomain}`,
    `-team.${validDeploymentInput.contentDomain}.`,
  ])("rejects malformed or foreign suffix %s", async (contentHostSuffix) => {
    const result = await Effect.runPromiseExit(parseCloudDeploymentInput({
      ...validDeploymentInput, contentHostSuffix,
    }));
    expect(result._tag).toBe("Failure");
  });

});
