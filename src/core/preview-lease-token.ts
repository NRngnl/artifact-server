/** Keep the legacy dotted token; flat hosts omit one separator to retain 160 bits. */
export function previewLeaseToken(digest: string, characterLimit = 63): string {
  const prefix = characterLimit === 63 ? "review-" : "review";
  const hexLength = characterLimit - prefix.length;
  if (hexLength < 40 || hexLength > 56 || !/^[a-f0-9]{56,}$/u.test(digest)) {
    throw new Error("Preview lease tokens require at least 160 bits within one DNS label");
  }
  return `${prefix}${digest.slice(0, hexLength)}`;
}

/** Both formats are discriminators only; hostname parsing validates the full token. */
export function isReviewLeaseToken(token: string): boolean {
  return token.startsWith("review-") || /^review[a-f0-9]{40,55}$/u.test(token);
}
