import assert from "node:assert/strict";
import { mkdtemp, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import test, { type TestContext } from "node:test";

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";

import idaMcp from "./ida-mcp.ts";

type Handler = (...args: unknown[]) => unknown;

function requireHandler(
  handlers: ReadonlyMap<string, Handler>,
  event: string,
): Handler {
  const handler = handlers.get(event);
  assert.ok(handler, `missing ${event} handler`);
  return handler;
}

// The extension caches the MCP tool list in its state directory.
async function useStateDir(t: TestContext): Promise<string> {
  const previous = process.env.IDA_MCP_STATE_DIR;
  const stateDir = await mkdtemp(join(tmpdir(), "ida-mcp-test-"));
  process.env.IDA_MCP_STATE_DIR = stateDir;
  t.after(async () => {
    if (previous === undefined) delete process.env.IDA_MCP_STATE_DIR;
    else process.env.IDA_MCP_STATE_DIR = previous;
    await rm(stateDir, { recursive: true, force: true });
  });
  return stateDir;
}

test("OMP waits for MCP tool registration at the first agent start", async (t) => {
  await useStateDir(t);
  const originalConnect = Reflect.get(Client.prototype, "connect");
  const originalListTools = Reflect.get(Client.prototype, "listTools");
  const originalClose = Reflect.get(Client.prototype, "close");
  t.after(() => {
    Reflect.set(Client.prototype, "connect", originalConnect);
    Reflect.set(Client.prototype, "listTools", originalListTools);
    Reflect.set(Client.prototype, "close", originalClose);
  });

  let releaseToolDiscovery: (() => void) | undefined;
  const toolDiscoveryBlocked = new Promise<void>((resolve) => {
    releaseToolDiscovery = resolve;
  });
  let discoveryStarted = false;
  Reflect.set(Client.prototype, "connect", async () => undefined);
  Reflect.set(Client.prototype, "listTools", async () => {
    discoveryStarted = true;
    await toolDiscoveryBlocked;
    return {
      tools: [
        {
          name: "execute_python",
          description: "Run Python",
          inputSchema: { type: "object" },
        },
      ],
    };
  });
  Reflect.set(Client.prototype, "close", async () => undefined);

  const handlers = new Map<string, Handler>();
  const registeredTools: string[] = [];
  const statusEvents: { channel: string; data: unknown }[] = [];
  let widgetCalls = 0;
  const pi = {
    arktype: {},
    zod: {},
    events: {
      emit(channel: string, data: unknown) {
        statusEvents.push({ channel, data });
      },
    },
    registerFlag() {},
    getFlag() {
      return false;
    },
    on(event: string, handler: Handler) {
      handlers.set(event, handler);
    },
    registerTool(tool: unknown) {
      if (
        tool !== null &&
        typeof tool === "object" &&
        "name" in tool &&
        typeof tool.name === "string"
      ) {
        registeredTools.push(tool.name);
      }
    },
  } as unknown as ExtensionAPI;
  const ctx = {
    ui: {
      setWidget() {
        widgetCalls++;
      },
    },
  };

  idaMcp(pi);

  const sessionStartResult = requireHandler(handlers, "session_start")({}, ctx);
  assert.equal(
    sessionStartResult,
    undefined,
    "session startup must not await MCP",
  );
  await new Promise<void>((resolve) => setImmediate(resolve));
  assert.equal(discoveryStarted, true);
  assert.deepEqual(registeredTools, []);

  let agentStartFinished = false;
  const agentStart = Promise.resolve(
    requireHandler(handlers, "before_agent_start")({}, ctx),
  ).then(() => {
    agentStartFinished = true;
  });
  await Promise.resolve();
  assert.equal(agentStartFinished, false);
  assert.deepEqual(registeredTools, []);

  releaseToolDiscovery?.();
  await agentStart;
  assert.deepEqual(registeredTools, ["ida_execute_python"]);

  await requireHandler(handlers, "session_shutdown")({}, ctx);
  assert.equal(widgetCalls, 0, "OMP must not draw the Pi status widget");
  assert.deepEqual(statusEvents, [
    {
      channel: "mcp:connection-status",
      data: { type: "connecting", serverNames: ["ida"] },
    },
    {
      channel: "mcp:connection-status",
      data: { type: "connected", serverName: "ida" },
    },
  ]);
});

test("open_database resolves paths from the agent workspace", async (t) => {
  await useStateDir(t);
  const originalConnect = Reflect.get(Client.prototype, "connect");
  const originalListTools = Reflect.get(Client.prototype, "listTools");
  const originalCallTool = Reflect.get(Client.prototype, "callTool");
  const originalClose = Reflect.get(Client.prototype, "close");
  t.after(() => {
    Reflect.set(Client.prototype, "connect", originalConnect);
    Reflect.set(Client.prototype, "listTools", originalListTools);
    Reflect.set(Client.prototype, "callTool", originalCallTool);
    Reflect.set(Client.prototype, "close", originalClose);
  });

  Reflect.set(Client.prototype, "connect", async () => undefined);
  Reflect.set(Client.prototype, "listTools", async () => ({
    tools: [{ name: "open_database", inputSchema: { type: "object" } }],
  }));
  Reflect.set(Client.prototype, "close", async () => undefined);
  const forwarded: Record<string, unknown>[] = [];
  Reflect.set(
    Client.prototype,
    "callTool",
    async (request: { arguments: Record<string, unknown> }) => {
      forwarded.push(request.arguments);
      return { content: [{ type: "text", text: "opened" }] };
    },
  );

  const handlers = new Map<string, Handler>();
  let openDatabase: {
    execute: (...args: unknown[]) => Promise<unknown>;
  } | undefined;
  const pi = {
    on(event: string, handler: Handler) {
      handlers.set(event, handler);
    },
    registerTool(tool: unknown) {
      openDatabase = tool as typeof openDatabase;
    },
  } as unknown as ExtensionAPI;
  const ctx = {
    cwd: resolve("agent-workspace"),
    ui: { setWidget() {} },
    sessionManager: { getSessionFile: () => undefined },
  };

  idaMcp(pi);
  requireHandler(handlers, "session_start")({}, ctx);
  await requireHandler(handlers, "input")({}, ctx);
  assert.ok(openDatabase);

  const relativeArgs = { path: "tests/crackme03.elf" };
  const absolutePath = resolve(ctx.cwd, "binary.elf");
  await openDatabase.execute("call-1", relativeArgs, undefined, undefined, ctx);
  await openDatabase.execute(
    "call-2",
    { path: absolutePath },
    undefined,
    undefined,
    ctx,
  );
  await openDatabase.execute(
    "call-3",
    { path: "~/binary.elf" },
    undefined,
    undefined,
    ctx,
  );

  assert.deepEqual(forwarded, [
    { path: resolve(ctx.cwd, "tests/crackme03.elf") },
    { path: absolutePath },
    { path: "~/binary.elf" },
  ]);
  assert.deepEqual(relativeArgs, { path: "tests/crackme03.elf" });
  await requireHandler(handlers, "session_shutdown")({}, ctx);
});

function mockClient(
  t: TestContext,
  methods: Record<string, (...args: never[]) => Promise<unknown>>,
) {
  for (const [name, method] of Object.entries(methods)) {
    const original = Reflect.get(Client.prototype, name);
    Reflect.set(Client.prototype, name, method);
    t.after(() => Reflect.set(Client.prototype, name, original));
  }
}

interface FakeTool {
  name: string;
  execute: (...args: unknown[]) => Promise<unknown>;
}

interface StatusEvent {
  type: string;
  serverName?: string;
  error?: string;
}

function ompSession(sessionFile: string) {
  const handlers = new Map<string, Handler>();
  const tools = new Map<string, FakeTool>();
  const statusEvents: StatusEvent[] = [];
  const pi = {
    arktype: {},
    zod: {},
    events: {
      emit(_channel: string, data: StatusEvent) {
        statusEvents.push(data);
      },
    },
    registerFlag() {},
    getFlag() {
      return false;
    },
    on(event: string, handler: Handler) {
      handlers.set(event, handler);
    },
    registerTool(tool: FakeTool) {
      tools.set(tool.name, tool);
    },
  } as unknown as ExtensionAPI;
  const ctx = {
    cwd: resolve("agent-workspace"),
    ui: { setWidget() {} },
    sessionManager: { getSessionFile: () => sessionFile },
  };
  idaMcp(pi);
  return {
    tools,
    statusEvents,
    emit: (event: string) => requireHandler(handlers, event)({}, ctx),
    call(name: string) {
      const tool = tools.get(name);
      assert.ok(tool, `missing ${name} tool`);
      return tool.execute("call", {}, undefined, undefined, ctx);
    },
  };
}

// A fake MCP server; `failures` connects fail before one succeeds, and `gate`
// holds connects until it resolves.
function fakeMcp(t: TestContext) {
  const mcp = {
    connects: 0,
    closes: 0,
    calls: [] as unknown[],
    failures: 0,
    gate: undefined as Promise<void> | undefined,
  };
  mockClient(t, {
    connect: async () => {
      mcp.connects++;
      await mcp.gate;
      if (mcp.failures > 0) {
        mcp.failures--;
        throw new Error("spawn uv ENOENT");
      }
    },
    listTools: async () => ({
      tools: [{ name: "list_databases", inputSchema: { type: "object" } }],
    }),
    callTool: async (request: never) => {
      mcp.calls.push(request);
      return { content: [{ type: "text", text: "[]" }] };
    },
    close: async () => {
      mcp.closes++;
    },
  });
  return mcp;
}

function gate() {
  let release!: () => void;
  const promise = new Promise<void>((resolve) => {
    release = resolve;
  });
  return { promise, release };
}

const tick = () => new Promise<void>((resolve) => setImmediate(resolve));

// Runs one session on an empty cache so it discovers and caches the tools.
async function populateToolCache(stateDir: string): Promise<string> {
  const session = ompSession("/sessions/discovery.jsonl");
  await session.emit("session_start");
  await session.emit("before_agent_start");
  await session.emit("session_shutdown");
  const [file] = await readdir(join(stateDir, "extension-tools"));
  assert.ok(file, "discovery must write the tool cache");
  return join(stateDir, "extension-tools", file);
}

test("OMP registers cached tools and starts MCP on the first call", async (t) => {
  const stateDir = await useStateDir(t);
  const mcp = fakeMcp(t);

  // A cache miss discovers the tools at startup and caches them.
  const cachePath = await populateToolCache(stateDir);
  assert.equal(mcp.connects, 1);
  assert.equal(mcp.closes, 1);
  const cache = JSON.parse(await readFile(cachePath, "utf8")) as {
    tools: { name: string }[];
  };
  assert.deepEqual(
    cache.tools.map((tool) => tool.name),
    ["list_databases"],
  );

  // With the cache, tools are registered before MCP starts.
  const session = ompSession("/sessions/second.jsonl");
  await session.emit("session_start");
  await session.emit("before_agent_start");
  assert.deepEqual([...session.tools.keys()], ["ida_list_databases"]);
  assert.equal(mcp.connects, 1, "a cached session must not start MCP");
  assert.deepEqual(session.statusEvents, []);

  await session.call("ida_list_databases");
  await session.call("ida_list_databases");
  assert.equal(mcp.connects, 2, "calls share the session's MCP server");
  assert.deepEqual(mcp.calls, [
    {
      name: "list_databases",
      arguments: {},
      _meta: { omp_session_path: "/sessions/second.jsonl" },
    },
    {
      name: "list_databases",
      arguments: {},
      _meta: { omp_session_path: "/sessions/second.jsonl" },
    },
  ]);
  assert.deepEqual(session.statusEvents, [
    { type: "connecting", serverNames: ["ida"] },
    { type: "connected", serverName: "ida" },
  ]);
  await session.emit("session_shutdown");
  assert.equal(mcp.closes, 2);
});

test("concurrent first calls start one MCP server", async (t) => {
  const stateDir = await useStateDir(t);
  const mcp = fakeMcp(t);
  await populateToolCache(stateDir);
  const session = ompSession("/sessions/concurrent.jsonl");
  await session.emit("session_start");
  await session.emit("before_agent_start");

  const start = gate();
  mcp.gate = start.promise;
  const calls = Promise.all([
    session.call("ida_list_databases"),
    session.call("ida_list_databases"),
  ]);
  await tick();
  start.release();
  await calls;
  assert.equal(mcp.connects, 2, "one discovery start plus one lazy start");
  assert.equal(mcp.calls.length, 2);
  await session.emit("session_shutdown");
});

test("shutdown during a lazy start closes the MCP child", async (t) => {
  const stateDir = await useStateDir(t);
  const mcp = fakeMcp(t);
  await populateToolCache(stateDir);
  const session = ompSession("/sessions/shutdown.jsonl");
  await session.emit("session_start");
  await session.emit("before_agent_start");

  const start = gate();
  mcp.gate = start.promise;
  const call = session.call("ida_list_databases");
  await tick();
  const closesBefore = mcp.closes;
  await session.emit("session_shutdown");
  assert.equal(mcp.closes, closesBefore + 1, "shutdown closes the child");
  start.release();
  await assert.rejects(call, /session ended during startup/);
  assert.equal(session.statusEvents.at(-1)?.type, "connecting");

  await assert.rejects(
    session.call("ida_list_databases"),
    /session has ended/,
  );
  assert.equal(mcp.connects, 2, "an ended session must not start MCP");
});

test("a failed tool discovery is retried at the next agent start", async (t) => {
  await useStateDir(t);
  const mcp = fakeMcp(t);
  mcp.failures = 1;
  const session = ompSession("/sessions/discovery-retry.jsonl");
  await session.emit("session_start");
  await session.emit("before_agent_start");
  assert.deepEqual([...session.tools.keys()], []);
  assert.equal(session.statusEvents.at(-1)?.type, "failed");

  await session.emit("before_agent_start");
  assert.deepEqual([...session.tools.keys()], ["ida_list_databases"]);
  assert.equal(mcp.connects, 2);
  assert.equal(session.statusEvents.at(-1)?.type, "connected");
  await session.emit("session_shutdown");
});

test("a lazy startup failure is reported by the tool call", async (t) => {
  const stateDir = await useStateDir(t);
  const mcp = fakeMcp(t);
  await populateToolCache(stateDir);
  mcp.failures = 2;

  const session = ompSession("/sessions/failing.jsonl");
  await session.emit("session_start");
  await session.emit("before_agent_start");
  assert.equal(mcp.connects, 1);

  await assert.rejects(
    session.call("ida_list_databases"),
    /failed to start: spawn uv ENOENT\nLog: .*stderr\.log/,
  );
  const failure = session.statusEvents.at(-1);
  assert.equal(failure?.type, "failed");
  assert.equal(failure?.serverName, "ida");
  assert.match(
    failure?.error ?? "",
    /^spawn uv ENOENT — Log: .*stderr\.log$/,
  );

  await assert.rejects(session.call("ida_list_databases"), /spawn uv ENOENT/);
  assert.equal(mcp.connects, 3, "the next call retries startup");
  await session.emit("session_shutdown");
});

test("empty, malformed, and stale tool caches are misses", async (t) => {
  const stateDir = await useStateDir(t);
  const mcp = fakeMcp(t);
  const cachePath = await populateToolCache(stateDir);
  const { key, tools } = JSON.parse(await readFile(cachePath, "utf8")) as {
    key: string;
    tools: unknown[];
  };

  const invalidCaches = [
    JSON.stringify({ key, tools: [] }),
    JSON.stringify({ key, tools: [null] }),
    JSON.stringify({ key, tools: [{ name: "list_databases" }] }),
    JSON.stringify({ key: "stale", tools }),
    "{",
  ];
  for (const contents of invalidCaches) {
    await writeFile(cachePath, contents);
    const connectsBefore = mcp.connects;
    const session = ompSession("/sessions/invalid-cache.jsonl");
    await session.emit("session_start");
    await session.emit("before_agent_start");
    assert.deepEqual([...session.tools.keys()], ["ida_list_databases"]);
    assert.equal(mcp.connects, connectsBefore + 1, contents);
    await session.emit("session_shutdown");
  }
});
