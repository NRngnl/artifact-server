import type {JWTPayload} from "jose";
import {z} from "zod";

import type {TrustedBrowserLogin} from "../../../src/http/trusted-browser-login.js";
import {accessJwtGuardConfig} from "./access-jwt-guard.js";

const userClaims = z.object({
  aud: z.union([z.string(), z.array(z.string())]),
  common_name: z.never().optional(),
  email: z.email(),
  name: z.string().optional(),
  sub: z.string().trim().min(1),
});

export function accessBrowserLogin(
  environment: {
    readonly ARTIFACT_SERVER_CF_ACCESS_LOGIN?: string;
    readonly ARTIFACT_SERVER_CF_ACCESS_APP_AUDIENCE?: string;
    readonly ARTIFACT_SERVER_CF_ACCESS_AUDIENCES?: string;
    readonly ARTIFACT_SERVER_CF_ACCESS_TEAM_DOMAIN?: string;
    readonly ARTIFACT_SERVER_OIDC_CLIENT_ID?: string;
    readonly ARTIFACT_SERVER_OIDC_CLIENT_SECRET?: string;
    readonly ARTIFACT_SERVER_OIDC_ISSUER?: string;
    readonly ARTIFACT_SERVER_OIDC_SCOPES?: string;
    readonly ARTIFACT_SERVER_WORKOS_API_KEY?: string;
    readonly ARTIFACT_SERVER_WORKOS_CLIENT_ID?: string;
    readonly ARTIFACT_SERVER_WORKOS_ISSUER?: string;
  },
  verifiedClaims: WeakMap<Request, JWTPayload>,
): TrustedBrowserLogin | undefined {
  if (environment.ARTIFACT_SERVER_CF_ACCESS_LOGIN !== "true") return undefined;
  const config = accessJwtGuardConfig(
    environment.ARTIFACT_SERVER_CF_ACCESS_TEAM_DOMAIN,
    environment.ARTIFACT_SERVER_CF_ACCESS_AUDIENCES,
  );
  const audience = environment.ARTIFACT_SERVER_CF_ACCESS_APP_AUDIENCE;
  if (config === null || audience === undefined || !config.audiences.includes(audience)) {
    throw new Error("Access login requires a team domain and an application audience included in access audiences.");
  }
  if ([environment.ARTIFACT_SERVER_OIDC_CLIENT_ID, environment.ARTIFACT_SERVER_OIDC_CLIENT_SECRET,
    environment.ARTIFACT_SERVER_OIDC_ISSUER, environment.ARTIFACT_SERVER_OIDC_SCOPES,
    environment.ARTIFACT_SERVER_WORKOS_API_KEY, environment.ARTIFACT_SERVER_WORKOS_CLIENT_ID,
    environment.ARTIFACT_SERVER_WORKOS_ISSUER].some((value) => value !== undefined)) {
    throw new Error("Access login cannot be combined with OIDC or WorkOS.");
  }
  const teamDomain = config.teamDomain.replace(/\/+$/u, "");
  return {
    identity: (request) => {
      const parsed = userClaims.safeParse(verifiedClaims.get(request));
      if (!parsed.success) return null;
      const claims = parsed.data;
      const audiences = [claims.aud].flat();
      if (!audiences.includes(audience)) return null;
      return {
        displayName: claims.name?.trim() || claims.email.split("@")[0] || claims.email,
        email: claims.email,
        emailVerified: true,
        provider: `cloudflare-access:${teamDomain}`,
        subject: claims.sub,
      };
    },
    logoutUrl: `${teamDomain}/cdn-cgi/access/logout`,
  };
}
