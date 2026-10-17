import {once} from "node:events";
import {mkdir, writeFile} from "node:fs/promises";
import {createServer} from "node:http";
import path from "node:path";

import {getRequestListener} from "@hono/node-server";
import {ManagedRuntime, Redacted} from "effect";
import {describe, expect, test} from "vitest";
import {z} from "zod";
import {createNodeWebAssetStore} from "../../src/http/node-web-assets.js";
import {reviewFrameUrl} from "../../apps/web/src/review/review-frame-url.js";

import {localOwnerBrowserAccess} from "../../src/core/browser-access.js";
import {SystemClock, SystemIdGenerator} from "../../src/core/system.js";
import {createHttpApp} from "../../src/http/create-http-app.js";
import {createLocalApplicationLayer} from "../../src/local/create-local-application-layer.js";
import {LocalBlobStore} from "../../src/storage/local-blob-store.js";
import {LocalStagingStore} from "../../src/storage/local-staging-store.js";
import {SqliteArtifactRepository} from "../../src/storage/sqlite-artifact-repository.js";
import {SqliteIdentityRepository} from "../../src/storage/sqlite-identity-repository.js";
import {publishNew} from "../support/publishing.js";
import {apiHeaders, createTestInstallation, fetchVersion, removeTestInstallation,
  reserveLoopbackPort} from "../support/runtime-harness.js";

const domain = "content.example.test";

describe.each([undefined, `-team.${domain}`, `-${"a".repeat(16)}.${domain}`])("HTTP content routing (suffix=%s)", (suffix) => {
  test("publication links deliver bytes only on this installation's content hosts", async () => {
    const installation = await createTestInstallation();
    const database = path.join(installation.dataDirectory, "installation.db");
    const repository = new SqliteArtifactRepository(database, "suffix-test");
    const identities = new SqliteIdentityRepository(database);
    const blobs = new LocalBlobStore(path.join(installation.dataDirectory, "blobs"));
    const runtime = ManagedRuntime.make(createLocalApplicationLayer({
      apiToken: Redacted.make(installation.apiToken), blobs,
      bootstrapAdministratorEmail: "admin@example.test", clock: new SystemClock(),
      dispatches: repository, externalApiBearerVerifier: null, externalMcpBearerVerifier: null,
      externalMcpOAuthVerifier: null, ids: new SystemIdGenerator(), identityRepository: identities,
      installationId: "suffix-test", interactiveIdentityProvider: null, localBootstrapCredential: null,
      protectBootstrapAdministrator: false, repository,
      staging: new LocalStagingStore(path.join(installation.dataDirectory, "staging")),
    }));
    await runtime.context();
    const port = await reserveLoopbackPort();
    const origin = `http://127.0.0.1:${port}`;
    let dependencies: Parameters<typeof createHttpApp>[0] = {
      applicationRuntime: runtime, blobs, browserAccess: localOwnerBrowserAccess,
      completedRequestLogSampleRate: 0, contentDomain: domain, trustedApplicationOrigin: origin,
    };
    if (suffix !== undefined) dependencies = {...dependencies, contentHostSuffix: suffix};
    const assetsRoot = path.join(installation.dataDirectory, "web");
    await mkdir(assetsRoot);
    await writeFile(path.join(assetsRoot, "review-frame.html"), "<!doctype html><title>Frame</title>");
    const app = createHttpApp({...dependencies, webAssets: createNodeWebAssetStore(assetsRoot)});
    const listener = createServer(getRequestListener(app.fetch));
    listener.listen(port, "127.0.0.1");
    await once(listener, "listening");
    const server = {baseUrl: origin, hostname: "127.0.0.1", port, stop: async () => {
      listener.closeAllConnections();
      await new Promise<void>((resolve, reject) => {
        listener.close((error) => error === undefined ? resolve() : reject(error));
      });
    }};
    try {
      const published = await publishNew(server, installation, {
        accessSetting: "public_link", content: "<!doctype html><title>Group content</title>",
        idempotencyKey: "suffix-publication", path: "index.html",
      });
      expect(published.response.status).toBe(201);
      const token = published.body.version.contentToken;
      const versionUrl = new URL(published.body.links.version);
      expect(versionUrl.hostname).toBe(`${token}${suffix ?? `.${domain}`}`);
      const delivered = await fetchVersion(server, versionUrl.toString());
      expect(delivered.status).toBe(200);
      expect(await delivered.text()).toBe("<!doctype html><title>Group content</title>");
      const leaseResponse = await fetch(new URL(
        `/api/v1/artifacts/${published.body.artifact.id}/versions/${published.body.version.id}/preview-leases`, origin,
      ), {method: "POST", headers: apiHeaders(installation, "suffix-preview-lease")});
      expect(leaseResponse.status).toBe(201);
      const lease = z.object({baseUrl: z.url()}).parse(await leaseResponse.json());
      const leaseUrl = new URL(lease.baseUrl);
      expect(leaseUrl.hostname.split(".")[0]?.length).toBeLessThanOrEqual(63);
      const preview = await fetchVersion(server, lease.baseUrl);
      expect(preview.status).toBe(200);
      expect(await preview.text()).toBe("<!doctype html><title>Group content</title>");
      const frame = await fetch(new URL(reviewFrameUrl(lease.baseUrl), origin));
      expect(frame.status).toBe(200);
      const csp = frame.headers.get("content-security-policy");
      const contentSources = suffix === undefined
        ? `http://*.${domain}:* https://*.${domain}`
        : `http://${leaseUrl.hostname}:* https://${leaseUrl.hostname}`;
      expect(csp).toContain(`connect-src ${contentSources}`);
      expect(csp?.includes("*.")).toBe(suffix === undefined);
      const unbound = await fetch(new URL("/review-frame", origin));
      expect(unbound.headers.get("content-security-policy"))
        .toContain(`connect-src ${suffix === undefined ? contentSources : "'none'"}`);
      const foreignSuffixes = suffix === undefined ? [`-team.${domain}`] : [`.${domain}`, `-other.${domain}`];
      await Promise.all(foreignSuffixes.map(async (foreign) => {
        const foreignUrl = new URL(versionUrl);
        foreignUrl.hostname = `${token}${foreign}`;
        const response = await fetchVersion(server, foreignUrl.toString());
        expect(response.status).not.toBe(200);
        expect(await response.text()).not.toContain("<title>Group content</title>");
        const applicationRoute = await fetchVersion(server, new URL("/auth/context", foreignUrl).toString());
        expect(applicationRoute.status).toBe(404);
        expect(applicationRoute.headers.getSetCookie()).toEqual([]);
      }));
    } finally {
      await server.stop();
      await runtime.dispose();
      identities.close();
      repository.close();
      await removeTestInstallation(installation);
    }
  });
});
