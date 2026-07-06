/**
 * P3′ payfetch — stdio MCP server (SPEC §9). Transport + tool registration only;
 * ZERO business logic (that lives in the engine, wrapped by tools.ts).
 *
 * Responsibilities:
 *  - Build the engine from the environment (config.ts) and serve the five §9
 *    tools over a stdio `@modelcontextprotocol/sdk` Server named "payfetch".
 *  - Bridge server→client elicitation to the engine's `deps.elicit` (SPEC §6):
 *    the installed SDK (@modelcontextprotocol/sdk) supports `server.elicitInput`,
 *    so the bridge is wired. After the client connects, if it did NOT advertise
 *    the `elicitation` capability, `deps.elicit` is dropped to `null` so the
 *    engine takes the operator's `approval.elicitFallback` path (fail-closed).
 *
 * Invariants:
 *  - STDOUT is the JSON-RPC channel; all logging goes to STDERR (config.ts log).
 *  - Key material never reaches a tool result or an error message (scrubbed at
 *    the CallTool boundary; SPEC §12).
 *  - The single-writer ledger lock is released on shutdown (SPEC §8.1).
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ErrorCode,
  ListToolsRequestSchema,
  McpError,
} from "@modelcontextprotocol/sdk/types.js";

import { CLIENT_VERSION, USDC_DECIMALS } from "../core/constants.js";
import type { RemainingBudgets } from "../core/budget.js";
import type { GuardResult } from "../guards/types.js";
import { createPayfetch } from "../index.js";
import type {
  ElicitDecision,
  ElicitFn,
  ElicitRequest,
} from "../payer/types.js";
import {
  ConfigError,
  buildFromEnv,
  realConfigIo,
  scrubSecrets,
  type ConfigIo,
  type EnvRecord,
} from "../config.js";
import {
  PAYFETCH_TOOLS,
  UnknownToolError,
  dispatchTool,
  type ToolContext,
} from "./tools.js";

/** The stdio MCP server name (SPEC §9). */
export const MCP_SERVER_NAME = "payfetch";

// ---------------------------------------------------------------------------
// Elicitation bridge (SPEC §6) — server→client approval prompt
// ---------------------------------------------------------------------------

/**
 * Bridge the engine's `ElicitFn` to `server.elicitInput`. Presents the §6 prompt
 * content (host, resource, amount, network/asset, guard results, remaining
 * budgets) and a single approve-once / deny choice (NO "always allow" in v1 — an
 * approval never widens future authority). The engine owns the approval TIMEOUT;
 * this bridge just resolves the human's decision (or a throw → engine denies).
 */
export function makeElicitBridge(server: Server): ElicitFn {
  return async (req: ElicitRequest): Promise<ElicitDecision> => {
    const result = await server.elicitInput({
      message: buildElicitMessage(req),
      requestedSchema: {
        type: "object",
        properties: {
          approve: {
            type: "boolean",
            title: "Approve this payment",
            description:
              "Approve this SINGLE payment (false = deny). This authorizes one payment only; it does not change any spending limit or list.",
          },
        },
        required: ["approve"],
      },
    });
    // Map the MCP elicitation action to an ElicitDecision (SPEC §6, P3 fix):
    //  - "accept" + approve:true  → APPROVED (the human said yes to THIS payment).
    //  - "accept" + approve:false → a genuine human DENIAL (they unchecked it).
    //  - "decline"                → a genuine human DENIAL (they declined the prompt).
    //  - "cancel" / anything else → CANCELLED: the client dismissed the dialog
    //    without a human decision (e.g. Claude Desktop advertises `elicitation` but
    //    returns `cancel` immediately). This is NOT a denial — the engine routes it
    //    through `approval.elicitFallback`, and never mistakes an un-renderable
    //    dialog for a human saying "no".
    if (result.action === "accept") {
      return { approved: result.content?.approve === true, cancelled: false };
    }
    if (result.action === "decline") {
      return { approved: false, cancelled: false };
    }
    return { approved: false, cancelled: true };
  };
}

function fmtUsd(n: number): string {
  return `$${n.toFixed(USDC_DECIMALS)}`;
}

function buildElicitMessage(req: ElicitRequest): string {
  const lines: string[] = [];
  lines.push(`Approve a payment of ${fmtUsd(req.amountUsd)} to ${req.host}?`);
  lines.push(`Resource: ${req.resource ?? "(unspecified)"}`);
  lines.push(`Network / asset: ${req.networkLabel} / ${req.assetLabel}`);

  const guards = req.guards as GuardResult[];
  if (guards.length > 0) {
    lines.push("Trust / safety checks:");
    for (const g of guards) {
      const score = typeof g.detail?.score === "number" ? ` (score ${g.detail.score})` : "";
      lines.push(`  - ${g.id}: ${g.verdict}${score}`);
    }
  }

  const b = req.remainingBudgets as RemainingBudgets;
  const totalStr = b.totalRemainingUsd == null ? "unset" : fmtUsd(b.totalRemainingUsd);
  lines.push(
    `Remaining today — day: ${fmtUsd(b.dayRemainingUsd)}, host: ${fmtUsd(b.hostRemainingUsd)}, total: ${totalStr}`,
  );
  lines.push(
    "Approving authorizes THIS payment only. Spending limits are set by the operator's config and cannot be changed here.",
  );
  return lines.join("\n");
}

// ---------------------------------------------------------------------------
// Handler registration
// ---------------------------------------------------------------------------

function registerHandlers(server: Server, ctx: ToolContext): void {
  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: PAYFETCH_TOOLS.map((t) => ({
      name: t.name,
      description: t.description,
      inputSchema: t.inputSchema,
    })),
  }));

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name } = request.params;
    const rawArgs = (request.params.arguments ?? {}) as Record<string, unknown>;
    try {
      const output = await dispatchTool(ctx, name, rawArgs);
      return { content: [{ type: "text", text: JSON.stringify(output, null, 2) }] };
    } catch (err) {
      // An unknown tool is a protocol error; everything else is a tool-error
      // result the agent can read. Scrub key material at the boundary (SPEC §12).
      if (err instanceof UnknownToolError) {
        throw new McpError(ErrorCode.MethodNotFound, err.message);
      }
      const message = scrubSecrets(String((err as Error)?.message ?? err), []);
      return {
        content: [{ type: "text", text: JSON.stringify({ error: message }) }],
        isError: true,
      };
    }
  });
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/**
 * Build the engine from the environment and serve it over stdio (SPEC §9). The
 * `env`/`io` seams keep this testable; defaults are `process.env` + the real IO.
 * Resolves once the transport is connected; the process then lives on the stdio
 * stream until the client disconnects or a signal arrives.
 */
export async function runStdioServer(
  env: EnvRecord = process.env,
  io: ConfigIo = realConfigIo(),
): Promise<void> {
  const opts = buildFromEnv(env, io);

  const server = new Server(
    { name: MCP_SERVER_NAME, version: CLIENT_VERSION },
    { capabilities: { tools: {} } },
  );

  // Wire the elicitation bridge into the mutable DI record BEFORE building the
  // engine (which captures the same `deps` object by reference).
  opts.deps.elicit = makeElicitBridge(server);

  const pf = createPayfetch(opts);

  // M6 (self-approval fail-fast): PAYFETCH_APPROVER=1 with a queue-capable
  // approval mode (`approval.mode "queue"`, or "elicit" with elicitFallback
  // "queue") lets the tool-driven agent approve its OWN payments — there is no
  // requester/approver separation and no out-of-band approve channel. Refuse to
  // start (release the single-writer lock first) rather than run misconfigured.
  // The bin wrapper surfaces ConfigError and exits non-zero (SPEC §6, fix M6).
  if (opts.approver === true && pf.engine.queueCapableNow()) {
    pf.close();
    throw new ConfigError(
      "payfetch: refusing to start — PAYFETCH_APPROVER=1 with a queue-capable " +
        "approval mode (approval.mode 'queue', or 'elicit' with elicitFallback " +
        "'queue') lets the tool-driven agent approve its own payments (no " +
        "requester/approver separation). Use approval.mode 'elicit' with " +
        "elicitFallback 'deny' (human-in-the-loop via MCP elicitation), or start " +
        "without PAYFETCH_APPROVER=1. (security fix M6)",
    );
  }

  const ctx: ToolContext = { pf, dataDir: opts.deps.dataDir };
  registerHandlers(server, ctx);

  let closed = false;
  const shutdown = (): void => {
    if (closed) return;
    closed = true;
    try {
      pf.close();
    } catch {
      /* best-effort lock release on shutdown */
    }
  };
  server.onclose = shutdown;
  process.once("SIGINT", () => {
    shutdown();
    process.exit(0);
  });
  process.once("SIGTERM", () => {
    shutdown();
    process.exit(0);
  });

  const transport = new StdioServerTransport();
  await server.connect(transport);

  // SPEC §6: if the connected client did NOT advertise elicitation, drop the
  // bridge to null so the engine uses `approval.elicitFallback` (fail-closed)
  // rather than attempting an elicitation the client cannot service.
  const clientCaps = server.getClientCapabilities();
  if (!clientCaps || !clientCaps.elicitation) {
    opts.deps.elicit = null;
  }
}
