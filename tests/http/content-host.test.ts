import {describe, expect, test} from "vitest";
import {contentTokenCharacterLimit} from "../../src/core/content-host-policy.js";
import {previewLeaseToken} from "../../src/core/preview-lease-token.js";

import {contentHostname, contentHostCspSources, contentHostSuffix,
  tokenFromContentHostname} from "../../src/http/content-host.js";
import {contentBootstrapBrowserUrl, versionBrowserUrl, versionFileBrowserUrl} from
  "../../src/http/artifact-http-links.js";

const token = "a1".repeat(18);
const domain = "content.example.org";
const flat = "-team.content.example.org";

describe("content-host installation isolation", () => {
  test("default hosts and all URL bytes remain unchanged", () => {
    const suffix = contentHostSuffix(domain);
    expect(suffix).toBe(".content.example.org");
    expect(contentHostname(token, suffix)).toBe(`${token}.content.example.org`);
    expect(tokenFromContentHostname(`${token}.content.example.org`, suffix)).toBe(token);
    expect(versionBrowserUrl(new URL("http://app.example.com:3210"), domain, token))
      .toBe(`http://${token}.content.example.org:3210/`);
    expect(contentHostCspSources(suffix))
      .toBe("http://*.content.example.org:* https://*.content.example.org");
  });

  test("flat hosts round-trip case insensitively and build every content link", () => {
    const suffix = contentHostSuffix(domain, flat);
    const origin = new URL("https://app.example.com");
    expect(contentHostname(token.toUpperCase(), suffix.toUpperCase()))
      .toBe(`${token}${flat}`);
    expect(tokenFromContentHostname(`${token}${flat}`.toUpperCase(), suffix))
      .toBe(token);
    expect(versionBrowserUrl(origin, suffix, token)).toBe(`https://${token}${flat}/`);
    expect(versionFileBrowserUrl(origin, suffix, token, "a b/index.html"))
      .toBe(`https://${token}${flat}/a%20b/index.html`);
    expect(new URL(contentBootstrapBrowserUrl(origin, suffix, token, "bootstrap-secret")).hostname)
      .toBe(`${token}${flat}`);
    expect(contentHostCspSources(suffix)).toBe("'none'");
    const frame = new URL(`https://app.example.com/review-frame?content-host=${token}${flat}`);
    expect(contentHostCspSources(suffix, frame)).toBe(`https://${token}${flat}`);
    frame.searchParams.set("content-host", `${token}-other.content.example.org`);
    expect(contentHostCspSources(suffix, frame)).toBe("'none'");
  });

  test.each([
    [`${token}.content.example.org`, flat],
    [`${token}-other.content.example.org`, flat],
    [`${token}-team.content.example.org`, ".content.example.org"],
    [`${token}-other-team.content.example.org`, flat],
    [`${token}.nested-team.content.example.org`, flat],
    [`${token}-team.content.example.org.evil.test`, flat],
    ["short-team.content.example.org", flat],
    [`${"a".repeat(101)}${flat}`, flat],
    [`${token}%20${flat}`, flat],
  ])("rejects foreign or malformed host %s with suffix %s", (hostname, suffix) => {
    expect(tokenFromContentHostname(hostname, suffix)).toBeNull();
  });

  test.each(["live-12345678-1234-1234-1234-123456789abc", "legacy-project-content-token",
    "lively-legacy-content-token", "reviewer-legacy-content-token"])(
    "preserves existing legacy and typed content token %s", (typedToken) => {
      for (const suffix of [contentHostSuffix(domain), flat]) {
        expect(tokenFromContentHostname(contentHostname(typedToken, suffix), suffix))
          .toBe(typedToken);
      }
    },
  );

  test.each([".content.example.org", flat, `-${"a".repeat(16)}.content.example.org`])(
    "review tokens retain at least 160 bits within the full label for %s", (suffix) => {
      const lease = previewLeaseToken("a".repeat(64), contentTokenCharacterLimit(suffix));
      const host = contentHostname(lease, suffix);
      expect(host.split(".")[0]?.length).toBe(63);
      expect(lease.replace(/^review-?/u, "").length).toBeGreaterThanOrEqual(40);
      expect(tokenFromContentHostname(host, suffix)).toBe(lease);
      expect(tokenFromContentHostname(host, ".content.example.org"))
        .toBe(suffix.startsWith("-") ? null : lease);
    },
  );

  test.each([`live-12345678-1234-1234-1234-123456789abc-team`,
    `review-${"a".repeat(56)}-team`, `review-${"x".repeat(40)}`,
    `review-${"a".repeat(55)}`, "live-not-a-uuid", "a".repeat(35)])(
    "rejects malformed typed or immutable token %s", (candidate) => {
      expect(tokenFromContentHostname(`${candidate}.${domain}`, `.${domain}`)).toBeNull();
    },
  );

  test("hostname construction refuses an oversized review label", () => {
    expect(() => contentHostname(`review-${"a".repeat(56)}`, flat)).toThrow("DNS label");
  });
});
