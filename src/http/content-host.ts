import {assertContentTokenBudget, contentTokenCharacterLimit,
  validateContentHostSuffix} from "../core/content-host-policy.js";
import {previewLeaseToken} from "../core/preview-lease-token.js";

/** Resolve a content suffix; pre-composed suffixes also serve legacy URL callers. */
export function contentHostSuffix(contentDomain: string, suffix?: string): string {
  const resolved = (suffix ?? (/^[.-]/u.test(contentDomain) ? contentDomain : `.${contentDomain}`))
    .toLowerCase();
  if (resolved.startsWith("-")) {
    validateContentHostSuffix(resolved.slice(resolved.indexOf(".") + 1), resolved);
  }
  return resolved;
}

/** Build an immutable, live, or review hostname, asserting the full label budget. */
export function contentHostname(token: string, suffix: string): string {
  const resolved = contentHostSuffix(suffix);
  assertContentTokenBudget(resolved);
  if (token.length > contentTokenCharacterLimit(resolved)) {
    throw new Error("Content hostname exceeds one DNS label");
  }
  return `${token}${resolved}`.toLowerCase();
}

/** Parse generated shapes strictly; retain untyped tokens from the legacy schema. */
export function tokenFromContentHostname(hostname: string, suffix: string): string | null {
  const normalizedHostname = hostname.toLowerCase();
  const normalizedSuffix = suffix.toLowerCase();
  if (!normalizedHostname.endsWith(normalizedSuffix)) return null;
  const candidate = normalizedHostname.slice(0, -normalizedSuffix.length);
  if (candidate.length > contentTokenCharacterLimit(normalizedSuffix)) return null;
  if (/^[a-f0-9]{36}$/u.test(candidate)
    || /^live-[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/u.test(candidate)) return candidate;
  const expectedReview = previewLeaseToken("a".repeat(56), contentTokenCharacterLimit(normalizedSuffix));
  const reviewPrefix = normalizedSuffix.startsWith("-") ? "review" : "review-";
  if (candidate.startsWith(reviewPrefix) && candidate.length === expectedReview.length
    && /^[a-f0-9]+$/u.test(candidate.slice(reviewPrefix.length))) return candidate;
  // Historical schema allowed arbitrary 16–100 character tokens. Reserve generated
  // namespaces so typed tokens with another installation's suffix cannot fall back.
  if (/^(?:live-|review-|review[a-f0-9]{40}|[a-f0-9]{16,})/u.test(candidate)) return null;
  return /^[a-z0-9_-]{16,100}$/u.test(candidate) ? candidate : null;
}

/** Malformed or sibling content hosts must never fall through to application routes. */
export function isUnassignedContentHostname(hostname: string, suffix: string,
  applicationHostname: string | null): boolean {
  const domain = suffix.slice(suffix.indexOf(".") + 1);
  return hostname !== applicationHostname && hostname.endsWith(`.${domain}`)
    && tokenFromContentHostname(hostname, suffix) === null;
}

/** Flat frames permit only their exact content host, never sibling installations. */
export function contentHostCspSources(suffix: string, requestUrl?: URL): string {
  const domain = suffix.slice(suffix.indexOf(".") + 1).toLowerCase();
  if (!suffix.startsWith("-")) return `http://*.${domain}:* https://*.${domain}`;
  const host = requestUrl?.searchParams.get("content-host") ?? "";
  if (host !== host.toLowerCase() || tokenFromContentHostname(host, suffix) === null) return "'none'";
  const loopback = requestUrl !== undefined
    && /^(?:localhost|127\.0\.0\.1|\[::1\]|.*\.localhost)$/u.test(requestUrl.hostname);
  return `${loopback ? `http://${host}:* ` : ""}https://${host}`;
}
