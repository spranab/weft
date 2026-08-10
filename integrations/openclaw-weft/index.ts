import {
  definePluginEntry,
  type OpenClawPluginApi,
} from "openclaw/plugin-sdk/plugin-entry";
import { weftConfigSchema, resolveConfig } from "./src/config.js";
import { WeftClient } from "./src/client.js";
import { registerWeftTools } from "./src/tools.js";

/**
 * Weft — the execution ledger for autonomous coding agents.
 *
 * Gives an OpenClaw agent a verification-gated place to land work: it leases
 * intents, edits a materialized workspace by line number, and submits changes
 * that land only when the gate's evidence and policy pass. Every landed line
 * carries signed provenance — which model, under whose delegated authority —
 * back to a human authority key.
 *
 * Security posture, by construction:
 *  - no subprocesses, no filesystem access beyond the agent key, no eval;
 *  - network I/O goes exclusively to the configured weftd hub;
 *  - the Ed25519 private key never leaves this machine — the hub returns a
 *    digest to sign and only ever receives signatures;
 *  - workspace files whose authors lack the `instruct` capability are
 *    surfaced with an explicit untrusted-data hedge (Weft RFC §12.1), so
 *    repository text cannot quietly become agent instructions.
 *
 * Enable with:
 *   plugins.entries."weft".enabled = true
 */
export default definePluginEntry({
  id: "weft",
  name: "Weft",
  description:
    "Land agent work through a verification gate: intents, line-numbered " +
    "workspaces, evidence-gated submissions, and provenance to an authority key.",
  configSchema: weftConfigSchema,
  register(api: OpenClawPluginApi) {
    const cfg = resolveConfig(api.pluginConfig);
    const client = new WeftClient(cfg);

    registerWeftTools(api, client, cfg);

    api.registerService({
      id: "weft",
      async start() {
        try {
          const status = await client.status();
          api.logger.info(
            `[weft] hub ${cfg.hub} — repo ${
              status.repo ? status.repo.slice(0, 12) + "…" : "none yet"
            }, trunk seq ${status.trunk_seq}; agent key ${client.publicKeyHex().slice(0, 16)}…`,
          );
          if (!(await client.hasCapability("publish_change"))) {
            api.logger.warn(
              `[weft] no capability is delegated to this agent key yet. ` +
                `Open the Weft console → Access → mint a Contributor ` +
                `capability for ${client.publicKeyHex()}. Reads work meanwhile.`,
            );
          }
        } catch (error) {
          api.logger.warn(
            `[weft] hub not reachable at ${cfg.hub}: ${
              error instanceof Error ? error.message : String(error)
            }. Tools stay registered and retry per call.`,
          );
        }
      },
    });
  },
});
