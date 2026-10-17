import {previewLeaseToken} from "./preview-lease-token.js";

/** A flat suffix has exactly one bounded installation label before the domain. */
export function validateContentHostSuffix(domain: string, suffix?: string): void {
  if (suffix === undefined) return;
  const end = `.${domain}`;
  const group = suffix.startsWith("-") && suffix.endsWith(end)
    ? suffix.slice(1, -end.length) : "";
  if (!/^[a-z0-9](?:[a-z0-9-]{0,14}[a-z0-9])?$/u.test(group)
    || group.includes("--")) {
    throw new Error("contentHostSuffix must be -<1–16 character label>.<contentDomain>");
  }
  assertContentTokenBudget(suffix);
}

/** Maximum token characters available before this installation's suffix. */
export function contentTokenCharacterLimit(suffix: string): number {
  return 63 - (suffix.startsWith("-") ? suffix.indexOf(".") : 0);
}

/** Check every generated token kind against the complete first DNS label. */
export function assertContentTokenBudget(suffix: string): void {
  const limit = contentTokenCharacterLimit(suffix);
  const maxTokenLength = Math.max(36, 41, previewLeaseToken("a".repeat(56), limit).length);
  if (maxTokenLength > limit) throw new Error("Content hostname exceeds one DNS label");
}
