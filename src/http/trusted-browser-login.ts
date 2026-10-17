import {Effect, Redacted} from "effect";
import type {Context, MiddlewareHandler} from "hono";

import {InstallationAccessService} from "../application/installation-access.js";
import {safeReturnTo} from "../application/interactive-login.js";
import {AuthenticationRequired} from "../core/errors.js";
import type {ExternalIdentity, IssuedApplicationSession} from "../core/installation-identity.js";
import type {HttpAppDependencies, HttpEnvironment} from "./create-http-app.js";

/** Deployment-owned verifier; never derive this identity from unverified headers. */
export interface TrustedBrowserLogin {
  readonly identity: (request: Request) => ExternalIdentity | null;
  readonly logoutUrl: string;
}

export function permitsBrowserSessionChange(request: Request): boolean {
  const site = request.headers.get("Sec-Fetch-Site");
  return site === "same-origin" || site === "none";
}

/** Cross-site reads must not admit members, bind identities, issue, or revoke. */
async function requireMatchingSession(
  dependencies: HttpAppDependencies,
  identity: ExternalIdentity,
  memberId: string | undefined,
): Promise<void> {
  if (memberId === undefined) {
    throw new AuthenticationRequired({message: "Sign in from the application origin."});
  }
  const expected = await dependencies.applicationRuntime.runPromise(
    InstallationAccessService.use((access) => access.authenticateExternalSubject(identity.provider, identity.subject)),
  );
  if (expected?.id !== memberId) {
    throw new AuthenticationRequired({message: "Sign in from the application origin."});
  }
}

export function trustedBrowserLoginMiddleware(
  dependencies: HttpAppDependencies,
  cookies: {
    readonly read: (context: Context<HttpEnvironment>) => string | undefined;
    readonly clear: (context: Context<HttpEnvironment>) => void;
    readonly issue: (context: Context<HttpEnvironment>, issued: IssuedApplicationSession) => void;
  },
): MiddlewareHandler<HttpEnvironment> {
  return async (context, next) => {
    const login = dependencies.trustedBrowserLogin;
    const url = new URL(context.req.url);
    if (login === undefined || url.origin !== dependencies.trustedApplicationOrigin ||
      context.req.header("authorization") !== undefined ||
      ["/auth/logout", "/health"].includes(url.pathname)) return next();
    const credential = cookies.read(context);
    const interactive = context.req.method === "GET" &&
      (url.pathname === "/auth/login" || context.req.header("accept")?.includes("text/html") === true);
    if (credential === undefined && !interactive) return next();
    // Access sign-in always lands via a cross-site redirect chain, so a cross-site
    // navigation may create a first session (identity is the browser's own verified
    // Access JWT); it may never revoke or replace an existing one.
    const mayChangeSession = permitsBrowserSessionChange(context.req.raw) ||
      (credential === undefined && interactive);
    const token = credential === undefined ? null : Redacted.make(credential, {label: "application-session"});
    const revoke = async () => {
      if (mayChangeSession && token !== null) {
        await dependencies.applicationRuntime.runPromise(
          InstallationAccessService.use((access) => access.revokeSession(token)),
        );
        cookies.clear(context);
      }
    };
    const identity = login.identity(context.req.raw);
    if (identity === null) {
      await revoke();
      throw new AuthenticationRequired({message: "A verified browser identity is required."});
    }
    const current = token === null ? null : await dependencies.applicationRuntime.runPromise(
      InstallationAccessService.use((access) => access.authenticateSession(token)).pipe(
        Effect.catchTag("AuthenticationRequired", () => Effect.succeed(null)),
      ),
    );
    if (!mayChangeSession) {
      await requireMatchingSession(dependencies, identity, current?.principal.id);
      return next();
    }
    let matches: boolean;
    try {
      const expected = await dependencies.applicationRuntime.runPromise(
        InstallationAccessService.use((access) => access.authenticateExternalIdentity(identity)),
      );
      matches = current?.principal.id === expected.id;
    } catch (error) {
      await revoke();
      throw error;
    }
    if (!matches) {
      await revoke();
      if (!interactive && context.req.method !== "GET") {
        throw new AuthenticationRequired({message: "The browser identity changed. Sign in again."});
      }
      const issued = await dependencies.applicationRuntime.runPromise(
        InstallationAccessService.use((access) => access.completeExternalIdentity(identity)),
      );
      cookies.issue(context, issued);
      context.header("Cache-Control", "private, no-store");
      context.header("Referrer-Policy", "no-referrer");
      const returnTo = url.pathname === "/auth/login"
        ? url.searchParams.get("returnTo") ?? "/review"
        : `${url.pathname}${url.search}`;
      return context.redirect(safeReturnTo(returnTo), 303);
    }
    if (url.pathname === "/auth/login") {
      return context.redirect(safeReturnTo(url.searchParams.get("returnTo") ?? "/review"), 303);
    }
    return next();
  };
}
