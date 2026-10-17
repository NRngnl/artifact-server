import * as Alchemy from "alchemy";
import {effectiveStackName} from "./src/stack-name.ts";
import * as Cloudflare from "alchemy/Cloudflare";
import * as Config from "effect/Config";
import * as Effect from "effect/Effect";

import {
  cloudflareDeploymentDocumentConfig,
  parseCloudflareDeploymentInput,
} from "./src/deployment-input.ts";
import {
  type CloudflareAuthenticationSecrets,
  defineCloudflareFoundation,
} from "./src/stack.ts";

export default Alchemy.Stack(
  effectiveStackName(),
  {
    providers: Cloudflare.providers(),
    state: Cloudflare.state(),
  },
  Effect.gen(function* () {
    const document = yield* cloudflareDeploymentDocumentConfig;
    const input = yield* parseCloudflareDeploymentInput(document);
    effectiveStackName(input.contentHostSuffix);
    const apiToken = yield* Config.Redacted("ARTIFACT_SERVER_API_TOKEN");
    let authenticationSecrets: CloudflareAuthenticationSecrets = {};
    if (input.workosApiKeySecretRef !== undefined) {
      authenticationSecrets = {
        ...authenticationSecrets,
        workOsApiKey: yield* Config.Redacted("ARTIFACT_SERVER_WORKOS_API_KEY"),
      };
    }
    if (input.oidcClientSecretRef !== undefined) {
      authenticationSecrets = {
        ...authenticationSecrets,
        oidcClientSecret:
          yield* Config.Redacted("ARTIFACT_SERVER_OIDC_CLIENT_SECRET"),
      };
    }
    if (input.accessSyncApiTokenSecretRef !== undefined) {
      authenticationSecrets = {
        ...authenticationSecrets,
        accessSyncApiToken:
          yield* Config.Redacted("ARTIFACT_SERVER_CF_ACCESS_SYNC_API_TOKEN"),
      };
    }
    return yield* defineCloudflareFoundation(
      input,
      apiToken,
      undefined,
      authenticationSecrets,
    );
  }),
);
