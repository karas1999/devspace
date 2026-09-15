import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { once } from "node:events";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { loadConfig } from "./config.js";
import { SqliteOAuthStore } from "./oauth-store.js";
import { createServer } from "./server.js";
import { writeTestDevspaceConfig } from "./test-support/config.test.js";

test("HTTP MCP enforces canonical and exact alias bearer resources", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "devspace-http-oauth-"));
  const canonical = "https://agent.example.com/mcp";
  const alias = "https://tunnel.example.com/v1/mcp/tunnel_123";
  const config = loadConfig(writeTestDevspaceConfig(join(root, "config"), {
    server: { publicBaseUrl: "https://agent.example.com" },
    storage: { stateDir: join(root, "state") },
    workspaces: { allowedRoots: [root] },
    oauth: { allowedResourceUrls: [alias] },
    logging: { level: "silent" },
  }));
  assert.ok(config.oauth);
  const store = new SqliteOAuthStore(config.stateDir);
  const client = store.registerClient({
    redirect_uris: ["https://chatgpt.com/connector_platform_oauth_redirect"],
  }, config.oauth.allowedRedirectHosts);
  const cases = [
    { resource: canonical, accepted: true },
    { resource: alias, accepted: true },
    { resource: `${alias}/child`, accepted: false },
    { resource: `${alias}?other=1`, accepted: false },
    { resource: "https://tunnel.example.com/v1/mcp/other", accepted: false },
  ];
  for (const { resource } of cases) {
    store.saveAccessToken(createHash("sha256").update(resource).digest("base64url"), {
      clientId: client.client_id, scopes: ["devspace"],
      expiresAt: Math.floor(Date.now() / 1000) + 3600, resource,
    });
  }
  store.close();
  const running = createServer(config);
  const listener = running.app.listen(0, "127.0.0.1");
  t.after(async () => {
    await running.close();
    listener.closeAllConnections();
    await new Promise<void>((resolve, reject) => listener.close((error) => error ? reject(error) : resolve()));
    await rm(root, { recursive: true, force: true });
  });
  await once(listener, "listening");
  const address = listener.address();
  assert.ok(address && typeof address !== "string");
  for (const { resource, accepted } of cases) {
    const response: Response = await fetch(`http://127.0.0.1:${address.port}/mcp`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${resource}`,
        "Content-Type": "application/json",
        Accept: "application/json, text/event-stream",
      },
      body: JSON.stringify({
        jsonrpc: "2.0", id: 1, method: "initialize",
        params: { protocolVersion: "2025-03-26", capabilities: {}, clientInfo: { name: "resource-test", version: "1.0.0" } },
      }),
      signal: AbortSignal.timeout(5000),
    });
    const body = await response.text();
    assert.equal(response.status, accepted ? 200 : 401, `${resource}: ${body}`);
    if (accepted) assert.match(body, /"serverInfo"/);
  }
});

test("HTTP MCP allows unauthenticated loopback requests when auth mode is none", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "devspace-http-no-auth-"));
  const env = writeTestDevspaceConfig(join(root, "config"), {
    storage: { stateDir: join(root, "state") },
    workspaces: { allowedRoots: [root] },
    logging: { level: "silent" },
  });
  const config = loadConfig({
    ...env,
    DEVSPACE_AUTH_MODE: "none",
    DEVSPACE_OAUTH_OWNER_TOKEN: "",
  });
  assert.equal(config.authMode, "none");
  assert.equal(config.oauth, undefined);
  assert.throws(
    () => createServer({ ...config, host: "0.0.0.0" }),
    /requires server\.host to be localhost, 127\.0\.0\.1, or ::1/,
  );

  const running = createServer(config);
  const listener = running.app.listen(0, "127.0.0.1");
  t.after(async () => {
    await running.close();
    listener.closeAllConnections();
    await new Promise<void>((resolve, reject) => listener.close((error) => error ? reject(error) : resolve()));
    await rm(root, { recursive: true, force: true });
  });
  await once(listener, "listening");
  const address = listener.address();
  assert.ok(address && typeof address !== "string");

  const response = await fetch(`http://127.0.0.1:${address.port}/mcp`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json, text/event-stream",
    },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: {
        protocolVersion: "2025-03-26",
        capabilities: {},
        clientInfo: { name: "no-auth-test", version: "1.0.0" },
      },
    }),
    signal: AbortSignal.timeout(5000),
  });
  const body = await response.text();
  assert.equal(response.status, 200, body);
  assert.match(body, /\"serverInfo\"/);

  const discoverResponse = await fetch(`http://127.0.0.1:${address.port}/mcp`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json, text/event-stream",
      "Mcp-Method": "server/discover",
      "Mcp-Protocol-Version": "2026-07-28",
    },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: "discover-no-auth",
      method: "server/discover",
      params: {
        _meta: {
          "io.modelcontextprotocol/protocolVersion": "2026-07-28",
          "io.modelcontextprotocol/clientCapabilities": {},
        },
      },
    }),
    signal: AbortSignal.timeout(5000),
  });
  const discoverBody = await discoverResponse.text();
  assert.equal(discoverResponse.status, 200, discoverBody);
  assert.match(discoverBody, /2026-07-28/);
});
