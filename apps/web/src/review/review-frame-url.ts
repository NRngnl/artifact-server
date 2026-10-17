/** Bind the frame response's CSP to the lease already issued for this preview. */
export function reviewFrameUrl(baseHref: string | undefined): string {
  if (baseHref === undefined) return "/review-frame";
  return `/review-frame?${new URLSearchParams({"content-host": new URL(baseHref).hostname})}`;
}
