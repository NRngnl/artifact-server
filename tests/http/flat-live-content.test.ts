import {writeFile} from "node:fs/promises";
import path from "node:path";

import {expect, test} from "vitest";
import {z} from "zod";

import {apiHeaders, createTestInstallation, fetchVersion, removeTestInstallation,
  startTestServer} from "../support/runtime-harness.js";

test("flat live hosts exchange a session and serve changed source bytes", async () => {
  const installation = await createTestInstallation();
  const source = await createTestInstallation();
  const suffix = `-${"a".repeat(16)}.localhost`;
  const server = await startTestServer(installation, {
    contentDomain: suffix, linkRoots: [source.dataDirectory], linkedFiles: "on",
  });
  try {
    const file = path.join(source.dataDirectory, "live.md");
    await writeFile(file, "# initial bytes\n");
    const response = await fetch(new URL("/api/v1/artifacts/link", server.baseUrl), {
      method: "POST", headers: apiHeaders(installation, "flat-live-link-0001"),
      body: JSON.stringify({path: file}),
    });
    expect(response.status).toBe(201);
    const linked = z.object({artifact: z.object({id: z.string()}),
      links: z.object({live: z.url()})}).parse(await response.json());
    const host = new URL(linked.links.live).hostname;
    expect(host).toMatch(/^live-[a-f0-9-]+-a{16}\.localhost$/u);
    expect(host.split(".")[0]?.length).toBeLessThanOrEqual(63);
    expect((await fetchVersion(server, linked.links.live)).status).toBe(401);
    const sessionResponse = await fetch(new URL(
      `/api/v1/artifacts/${linked.artifact.id}/live-sessions`, server.baseUrl,
    ), {method: "POST", headers: apiHeaders(installation, "flat-live-session")});
    expect(sessionResponse.status).toBe(201);
    const session = z.object({bootstrapUrl: z.url()}).parse(await sessionResponse.json());
    const exchange = await fetchVersion(server, session.bootstrapUrl);
    expect(exchange.status).toBe(200);
    const cookie = exchange.headers.getSetCookie().find((value) => value.includes("artifact_content="));
    expect(cookie).toBeDefined();
    await writeFile(file, "# changed bytes\n");
    const delivered = await fetchVersion(server, linked.links.live, "GET", {
      Cookie: cookie?.split(";")[0] ?? "",
    });
    expect(delivered.status).toBe(200);
    expect(await delivered.text()).toBe("# changed bytes\n");
    const foreign = new URL(linked.links.live);
    foreign.hostname = host.replace(suffix, ".localhost");
    expect((await fetchVersion(server, foreign.toString())).status).not.toBe(200);
  } finally {
    await server.stop();
    await removeTestInstallation(installation);
    await removeTestInstallation(source);
  }
});
