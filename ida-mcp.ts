import { createHash, randomUUID } from "node:crypto";
import { readdirSync, readFileSync } from "node:fs";
import { mkdir, mkdtemp, rename, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { homedir, tmpdir } from "node:os";
import { delimiter, dirname, isAbsolute, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import type { Tool as McpTool } from "@modelcontextprotocol/sdk/types.js";
import {
  DEFAULT_MAX_BYTES,
  DEFAULT_MAX_LINES,
  formatSize,
  highlightCode,
  keyHint,
  truncateHead,
  type ExtensionAPI,
  type ExtensionContext,
  type Theme,
} from "@earendil-works/pi-coding-agent";
import { Text } from "@earendil-works/pi-tui";

const PACKAGE_ROOT = dirname(fileURLToPath(import.meta.url));
const PACKAGE_VERSION = (
  createRequire(import.meta.url)("./package.json") as { version: string }
).version;
// The MCP SDK requires a request timer. Use Node's largest reliable delay so
// Pi does not impose a meaningful operation cutoff; backends enforce their own
// operation-specific timeouts.
const CALL_TIMEOUT_MS = 2_147_483_647;
const STDERR_CAPTURE_MAX_CHARS = 1024 * 1024;
const STATUS_WIDGET_KEY = "ida-mcp:status-bar";
const STATUS_HIDE_DELAY_MS = 4000;
// OMP reports every MCP server's connection state on this event-bus channel and
// renders it as one combined status line; the widget is only for Pi.
const OMP_MCP_STATUS_CHANNEL = "mcp:connection-status";
const OMP_MCP_SERVER_NAME = "ida";
const DISCOVERABLE_TOOLS_FLAG = "ida-tools-discoverable";

type PiContent =
  | { type: "text"; text: string }
  | { type: "image"; data: string; mimeType: string };

interface McpServer {
  client: Client;
  tools: McpTool[];
}

/** Mirrors `get_mcp_state_dir()` in ida_mcp/paths.py. */
function mcpStateDir(): string {
  const expandHome = (path: string) =>
    path.replace(/^~(?=$|[\\/])/, homedir());
  if (process.env.IDA_MCP_STATE_DIR)
    return expandHome(process.env.IDA_MCP_STATE_DIR);
  const idausr = process.env.IDAUSR?.split(delimiter)[0]?.trim();
  if (idausr) return join(expandHome(idausr), "mcp");
  return process.platform === "win32"
    ? join(process.env.APPDATA ?? homedir(), "Hex-Rays", "IDA Pro", "mcp")
    : join(homedir(), ".idapro", "mcp");
}

// Sessions register tools from this cache and start the server only when a
// tool is called. Each checkout has its own file, keyed by a hash of the files
// the server builds its tool list from, so editing them without a version bump
// still invalidates it. Every server start rewrites it.
function toolCache(): { path: string; key: string } {
  const sources = [
    ...readdirSync(join(PACKAGE_ROOT, "ida_mcp"))
      .filter((name) => name.endsWith(".py"))
      .sort()
      .map((name) => join("ida_mcp", name)),
    "pyproject.toml",
    "uv.lock",
  ];
  const key = createHash("sha256");
  for (const source of sources) {
    const contents = readFileSync(join(PACKAGE_ROOT, source));
    key.update(`${source}\0${contents.length}\0`).update(contents);
  }
  const root = createHash("sha256").update(PACKAGE_ROOT).digest("hex");
  return {
    path: join(mcpStateDir(), "extension-tools", `${root.slice(0, 16)}.json`),
    key: key.digest("hex"),
  };
}

// Registration needs a name and an input schema; anything else is a miss.
function isCachedTool(value: unknown): value is McpTool {
  return (
    typeof value === "object" &&
    value !== null &&
    "name" in value &&
    typeof value.name === "string" &&
    "inputSchema" in value &&
    typeof value.inputSchema === "object" &&
    value.inputSchema !== null
  );
}

// Read synchronously so a cache miss starts discovery within session_start.
function readToolCache(): McpTool[] | undefined {
  try {
    const { path, key } = toolCache();
    const cache: unknown = JSON.parse(readFileSync(path, "utf8"));
    if (
      typeof cache !== "object" ||
      cache === null ||
      !("key" in cache) ||
      cache.key !== key ||
      !("tools" in cache)
    )
      return undefined;
    const { tools } = cache;
    return Array.isArray(tools) &&
      tools.length > 0 &&
      tools.every(isCachedTool)
      ? tools
      : undefined;
  } catch {
    return undefined;
  }
}

async function writeToolCache(tools: McpTool[]): Promise<void> {
  try {
    const { path, key } = toolCache();
    const temporaryPath = `${path}.${randomUUID()}.tmp`;
    await mkdir(dirname(path), { recursive: true });
    await writeFile(temporaryPath, JSON.stringify({ key, tools }), "utf8");
    await rename(temporaryPath, path);
  } catch {
    // Without a cache, the next session discovers tools at startup again.
  }
}

async function saveStartupLog(output: string): Promise<string | undefined> {
  if (!output.trim()) return undefined;

  try {
    const dir = await mkdtemp(join(tmpdir(), "pi-ida-mcp-startup-"));
    const path = join(dir, "stderr.log");
    await writeFile(path, output, "utf8");
    return path;
  } catch {
    return undefined;
  }
}

/**
 * Turn off OMP's built-in IDA integration (the `ida` tool and IDA views in
 * `read`), which this extension replaces. The override is runtime-only (never
 * written to the user's config) and OMP drops the built-in tools live, so this
 * need not finish before the session starts.
 */
async function disableOmpBuiltinIda(pi: ExtensionAPI): Promise<void> {
  try {
    // The registry exists only under OMP, so a static import would break
    // loading under Pi. OMP resolves only literal specifiers to its own copy,
    // and type checking runs against Pi's packages, which lack this module.
    const registry: {
      lookup(
        id: string,
      ): { override(scope: unknown, value: unknown): void } | undefined;
    } = await import(
      // @ts-ignore
      "@oh-my-pi/pi-coding-agent/config/registry"
    );
    const host = pi as unknown as { pi: { settings: unknown } };
    registry.lookup("ida.enabled")?.override(host.pi.settings, false);
  } catch {
    // An OMP without the settings registry keeps its built-in integration.
  }
}

function renderToolCall(
  toolName: string,
  args: Record<string, unknown> | undefined,
  theme: Theme,
  expanded: boolean,
): Text {
  let text = theme.fg("toolTitle", theme.bold(toolName));
  const mcpToolName = toolName.startsWith("ida_")
    ? toolName.slice(4)
    : toolName;

  if (mcpToolName === "execute_python" && typeof args?.code === "string") {
    if (typeof args.instance_id === "string") {
      text += ` ${theme.fg("muted", args.instance_id)}`;
    }

    const lines = highlightCode(args.code.replaceAll("\t", "    "), "python");
    const maxLines = expanded ? lines.length : 10;
    const displayed = lines.slice(0, maxLines);
    text += `\n\n${displayed.join("\n")}`;

    const remaining = lines.length - displayed.length;
    if (remaining > 0) {
      text +=
        theme.fg("muted", `\n... (${remaining} more lines,`) +
        ` ${keyHint("app.tools.expand", "to expand")}${theme.fg("muted", ")")}`;
    }
    return new Text(text, 0, 0);
  }

  const serialized = args ? JSON.stringify(args, null, 2) : undefined;
  if (serialized && serialized !== "{}") {
    text += `\n\n${theme.fg("toolOutput", serialized)}`;
  }
  return new Text(text, 0, 0);
}

export default function idaMcp(pi: ExtensionAPI) {
  const agentKind = "arktype" in pi && "zod" in pi ? "omp" : "pi";
  if (agentKind === "omp") {
    void disableOmpBuiltinIda(pi);
    pi.registerFlag(DISCOVERABLE_TOOLS_FLAG, {
      description:
        "Mount IDA tools under xd:// instead of exposing them directly in OMP",
      type: "boolean",
      default: false,
    });
  }

  const sessionPathField = `${agentKind}_session_path`;
  let client: Client | undefined;
  let connectingClient: Client | undefined;
  let connection: Promise<McpServer> | undefined;
  let startupPromise: Promise<void> | undefined;
  let pendingOmpToolRegistration: (() => void) | undefined;
  let sessionRunning = false;
  let statusHideTimer: NodeJS.Timeout | undefined;
  let statusWidgetMounted = false;
  let requestStatusRender: (() => void) | undefined;
  let statusWidgetState:
    | {
        state: "starting" | "ready" | "error";
        details: string[];
      }
    | undefined;

  const clearStatusWidget = (ctx: ExtensionContext) => {
    if (agentKind === "omp") return;
    if (statusHideTimer) {
      clearTimeout(statusHideTimer);
      statusHideTimer = undefined;
    }
    statusWidgetState = undefined;
    statusWidgetMounted = false;
    requestStatusRender = undefined;
    ctx.ui.setWidget(STATUS_WIDGET_KEY, undefined);
  };

  const showStatus = (
    ctx: ExtensionContext,
    state: "starting" | "ready" | "error",
    detail?: string | string[],
  ) => {
    if (agentKind === "omp") {
      const details = detail ? (Array.isArray(detail) ? detail : [detail]) : [];
      pi.events.emit(
        OMP_MCP_STATUS_CHANNEL,
        state === "starting"
          ? { type: "connecting", serverNames: [OMP_MCP_SERVER_NAME] }
          : state === "ready"
            ? { type: "connected", serverName: OMP_MCP_SERVER_NAME }
            : {
                type: "failed",
                serverName: OMP_MCP_SERVER_NAME,
                error: details.join(" — ") || "startup failed",
              },
      );
      return;
    }

    if (statusHideTimer) {
      clearTimeout(statusHideTimer);
      statusHideTimer = undefined;
    }
    statusWidgetState = {
      state,
      details: detail ? (Array.isArray(detail) ? detail : [detail]) : [],
    };

    // Pi currently removes and reinserts a widget every time setWidget() is
    // called, which changes Map insertion order relative to other extensions.
    // Mount once and mutate our component state so adjacent status widgets do
    // not swap positions while their asynchronous connections settle.
    if (!statusWidgetMounted) {
      statusWidgetMounted = true;
      ctx.ui.setWidget(
        STATUS_WIDGET_KEY,
        (tui, theme) => {
          const requestRender = () => tui.requestRender();
          requestStatusRender = requestRender;
          return {
            invalidate() {},
            dispose() {
              if (requestStatusRender === requestRender) {
                requestStatusRender = undefined;
              }
            },
            render(): string[] {
              const current = statusWidgetState;
              if (!current) return [];
              const icon =
                current.state === "ready"
                  ? theme.fg("success", "●")
                  : current.state === "error"
                    ? theme.fg("error", "●")
                    : theme.fg("warning", "○");
              const label =
                current.state === "starting"
                  ? "starting…"
                  : current.state === "ready"
                    ? "ready"
                    : "startup failed";
              const header = [
                `${icon} ${theme.fg("accent", theme.bold("Hex-Rays IDA MCP"))}`,
                theme.fg(current.state === "error" ? "error" : "muted", label),
              ].join(theme.fg("dim", "  ·  "));
              const detailLines = current.details.map((line) =>
                theme.fg("dim", `  ${line}`),
              );
              return [header, ...detailLines];
            },
          };
        },
        { placement: "belowEditor" },
      );
    } else {
      requestStatusRender?.();
    }

    if (state === "ready") {
      statusHideTimer = setTimeout(
        () => clearStatusWidget(ctx),
        STATUS_HIDE_DELAY_MS,
      );
    }
  };

  const startMcp = async (ctx: ExtensionContext): Promise<McpServer> => {
    showStatus(ctx, "starting");
    const next = new Client({ name: "ida", version: PACKAGE_VERSION });
    connectingClient = next;
    let capturedStderr = "";
    let captureStderr = true;
    const transport = new StdioClientTransport({
      command: "uv",
      args: [
        "run",
        "--no-dev",
        "ida-mcp",
        "stdio",
        `--agent=${agentKind}`,
      ],
      cwd: PACKAGE_ROOT,
      stderr: "pipe",
      env: {
        ...(process.env.IDA_MCP_ID
          ? { IDA_MCP_ID: process.env.IDA_MCP_ID }
          : {}),
        ...(process.env.IDAUSR ? { IDAUSR: process.env.IDAUSR } : {}),
        ...(process.env.IDA_NEXUS_STATE_DIR
          ? { IDA_NEXUS_STATE_DIR: process.env.IDA_NEXUS_STATE_DIR }
          : {}),
        ...(process.env.IDA_MCP_IDLE_TIMEOUT
          ? { IDA_MCP_IDLE_TIMEOUT: process.env.IDA_MCP_IDLE_TIMEOUT }
          : {}),
      },
    });

    transport.stderr?.on("data", (chunk: unknown) => {
      if (!captureStderr) return;
      const text = Buffer.isBuffer(chunk)
        ? chunk.toString("utf8")
        : String(chunk);
      capturedStderr = (capturedStderr + text).slice(-STDERR_CAPTURE_MAX_CHARS);
    });

    let tools: McpTool[];
    try {
      await next.connect(transport);
      ({ tools } = await next.listTools());
    } catch (error) {
      if (connectingClient === next) connectingClient = undefined;
      await next.close().catch(() => undefined);
      if (!sessionRunning) throw error;

      const message = error instanceof Error ? error.message : String(error);
      const logContents = capturedStderr
        ? `Hex-Rays IDA MCP failed to start: ${message}\n\n${capturedStderr}`
        : `Hex-Rays IDA MCP failed to start: ${message}\n`;
      const logPath = await saveStartupLog(logContents);
      const details = [message, ...(logPath ? [`Log: ${logPath}`] : [])];
      showStatus(ctx, "error", details);
      throw new Error(
        `Hex-Rays IDA MCP failed to start: ${details.join("\n")}`,
      );
    }
    if (!sessionRunning || connectingClient !== next) {
      await next.close().catch(() => undefined);
      throw new Error("The Hex-Rays IDA MCP session ended during startup");
    }
    client = next;
    connectingClient = undefined;
    captureStderr = false;
    capturedStderr = "";
    await writeToolCache(tools);
    showStatus(ctx, "ready");
    return { client: next, tools };
  };

  // Tools start the server on first use; a failed start is retried next call.
  const connectMcp = (ctx: ExtensionContext): Promise<McpServer> => {
    if (!sessionRunning) {
      return Promise.reject(
        new Error("The Hex-Rays IDA MCP session has ended"),
      );
    }
    if (!connection) {
      const pending = startMcp(ctx);
      connection = pending;
      pending.catch(() => {
        if (connection === pending) connection = undefined;
      });
    }
    return connection;
  };

  const registerSessionTools = async (ctx: ExtensionContext): Promise<void> => {
    // A cache miss starts the server once to discover the tools.
    const tools =
      readToolCache() ??
      (await connectMcp(ctx).then(
        (server) => server.tools,
        () => undefined,
      ));
    if (!tools) {
      // Discovery failed; the next input or agent start retries it.
      if (sessionRunning) startupPromise = undefined;
      return;
    }
    if (sessionRunning) {
      const ompToolOptions =
        agentKind === "omp"
          ? {
              loadMode:
                pi.getFlag(DISCOVERABLE_TOOLS_FLAG) === true
                  ? ("discoverable" as const)
                  : ("essential" as const),
            }
          : {};
      const registerTools = () => {
        for (const tool of tools) {
          const piToolName = tool.name.startsWith("ida_")
            ? tool.name
            : `ida_${tool.name}`;
          pi.registerTool({
            ...ompToolOptions,
            name: piToolName,
            // The SDK negotiates 2025-11-25, where the title is top level;
            // annotations.title is the pre-2025-06-18 location.
            label: tool.title ?? tool.annotations?.title ?? `IDA ${tool.name}`,
            description:
              tool.description ?? `Call the Hex-Rays IDA MCP ${tool.name} tool`,
            // MCP and Pi both use JSON Schema for tool inputs. The SDK's type is
            // structurally compatible, but it is not branded as a TypeBox schema.
            parameters: tool.inputSchema as unknown as Parameters<
              typeof pi.registerTool
            >[0]["parameters"],
            renderCall(args, theme, context) {
              return renderToolCall(
                piToolName,
                args as Record<string, unknown> | undefined,
                theme,
                context.expanded,
              );
            },
            async execute(_id, params, signal, onUpdate, ctx) {
              const server = await connectMcp(ctx);

              const sessionPath = ctx.sessionManager.getSessionFile();
              const args = params as Record<string, unknown>;
              const path = args.path;
              // The MCP server runs from PACKAGE_ROOT; agent paths use ctx.cwd.
              // Leave home paths for Nexus to expand on the server side.
              const forwardedArgs =
                tool.name === "open_database" &&
                typeof path === "string" &&
                path.length > 0 &&
                !isAbsolute(path) &&
                !path.startsWith("~")
                  ? { ...args, path: resolve(ctx.cwd, path) }
                  : args;
              const result = await server.client.callTool(
                {
                  name: tool.name,
                  arguments: forwardedArgs,
                  ...(sessionPath
                    ? { _meta: { [sessionPathField]: sessionPath } }
                    : {}),
                },
                undefined,
                {
                  signal,
                  timeout: CALL_TIMEOUT_MS,
                  onprogress(progress) {
                    const total = progress.total ? `/${progress.total}` : "";
                    onUpdate?.({
                      content: [
                        {
                          type: "text",
                          text: `Hex-Rays IDA MCP progress: ${progress.progress}${total}`,
                        },
                      ],
                      details: {},
                    });
                  },
                },
              );

              if (!Array.isArray(result.content)) {
                return {
                  content: [
                    {
                      type: "text",
                      text: JSON.stringify(
                        result.toolResult ?? result,
                        null,
                        2,
                      ),
                    },
                  ],
                  details: {},
                };
              }

              const images: PiContent[] = [];
              const textParts: string[] = [];
              for (const item of result.content) {
                if (item.type === "text") textParts.push(item.text);
                else if (item.type === "image") {
                  images.push({
                    type: "image",
                    data: item.data,
                    mimeType: item.mimeType,
                  });
                } else textParts.push(JSON.stringify(item, null, 2));
              }
              if (textParts.length === 0 && result.structuredContent) {
                textParts.push(
                  JSON.stringify(result.structuredContent, null, 2),
                );
              }

              const fullText = textParts.join("\n");
              const truncated = truncateHead(fullText, {
                maxBytes: DEFAULT_MAX_BYTES,
                maxLines: DEFAULT_MAX_LINES,
              });
              let text = truncated.content;
              let fullOutputPath: string | undefined;
              if (truncated.truncated) {
                const dir = await mkdtemp(join(tmpdir(), "pi-ida-mcp-"));
                fullOutputPath = join(dir, `${tool.name}.txt`);
                await writeFile(fullOutputPath, fullText, "utf8");
                text += `\n\n[Output truncated to ${DEFAULT_MAX_LINES} lines or ${formatSize(DEFAULT_MAX_BYTES)}. Full output: ${fullOutputPath}]`;
              }

              if (result.isError)
                throw new Error(text || `${tool.name} failed`);
              return {
                content: [
                  ...(text ? [{ type: "text" as const, text }] : []),
                  ...images,
                ],
                details: fullOutputPath ? { fullOutputPath } : {},
              };
            },
          });
        }
      };

      if (agentKind === "omp") pendingOmpToolRegistration = registerTools;
      else registerTools();
    }
  };

  const ensureToolsRegistered = async (
    ctx: ExtensionContext,
  ): Promise<void> => {
    if (sessionRunning) startupPromise ??= registerSessionTools(ctx);
    await startupPromise;
    const registerTools = pendingOmpToolRegistration;
    pendingOmpToolRegistration = undefined;
    registerTools?.();
  };

  pi.on("session_start", (_event, ctx) => {
    if (startupPromise) return;
    sessionRunning = true;
    startupPromise = registerSessionTools(ctx);
  });

  pi.on("input", async (_event, ctx) => {
    await ensureToolsRegistered(ctx);
    return { action: "continue" };
  });

  pi.on("before_agent_start", async (_event, ctx) => {
    if (agentKind === "omp") await ensureToolsRegistered(ctx);
  });

	pi.on("session_shutdown", async (_event, ctx) => {
		sessionRunning = false;
		clearStatusWidget(ctx);
		const active = client;
		const connecting = connectingClient;
		client = undefined;
		connectingClient = undefined;
		connection = undefined;
		startupPromise = undefined;
		pendingOmpToolRegistration = undefined;
		// The host caps shutdown handlers at 2s; a stuck MCP pipe must not
		// outlive the session as an orphaned server process. Bound each close
		// so a hung transport always settles inside the budget. The timer
		// resolves on its own — it must NOT call close() again, or a hung
		// first close would wedge the race on the second close too.
		const closeSoon = (c: Client): Promise<void> =>
			// setTimeout executor (not withResolvers): the repo typechecks at ES2022.
			Promise.race([c.close(), new Promise<void>(resolve => setTimeout(resolve, 1500))]).catch(
				() => undefined,
			);
		await Promise.all([
			active ? closeSoon(active) : undefined,
			connecting && connecting !== active ? closeSoon(connecting) : undefined,
		]);
	});
}
