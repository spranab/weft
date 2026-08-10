import { Type } from "typebox";
import { homedir } from "node:os";
import { join } from "node:path";

export const weftConfigSchema = Type.Object(
  {
    hub: Type.Optional(
      Type.String({
        description:
          "weftd hub base URL. Defaults to http://127.0.0.1:8747 (or WEFT_HUB).",
      }),
    ),
    keyPath: Type.Optional(
      Type.String({
        description:
          "Where this agent's Ed25519 seed lives. Created on first use; " +
          "never transmitted. Defaults to ~/.openclaw/weft-agent.key (or WEFT_KEY).",
      }),
    ),
    model: Type.Optional(
      Type.String({
        description:
          "Model tag recorded in each change's provenance. Defaults to WEFT_MODEL, else 'openclaw'.",
      }),
    ),
    timeoutMs: Type.Optional(
      Type.Integer({
        minimum: 1000,
        maximum: 120000,
        description: "Per-request timeout against the hub. Default 15000.",
      }),
    ),
    submitTimeoutMs: Type.Optional(
      Type.Integer({
        minimum: 1000,
        maximum: 600000,
        description:
          "How long to wait for the gate's verdict after proposing. Default 20000.",
      }),
    ),
  },
  { additionalProperties: false },
);

export interface ResolvedConfig {
  hub: string;
  keyPath: string;
  model: string;
  timeoutMs: number;
  submitTimeoutMs: number;
}

export function resolveConfig(raw: unknown): ResolvedConfig {
  const c = (raw ?? {}) as Record<string, unknown>;
  const str = (v: unknown, fallback: string) =>
    typeof v === "string" && v.trim().length > 0 ? v.trim() : fallback;
  const num = (v: unknown, fallback: number) =>
    typeof v === "number" && Number.isFinite(v) ? v : fallback;
  return {
    hub: str(c.hub, process.env.WEFT_HUB ?? "http://127.0.0.1:8747").replace(/\/$/, ""),
    keyPath: str(
      c.keyPath,
      process.env.WEFT_KEY ?? join(homedir(), ".openclaw", "weft-agent.key"),
    ),
    model: str(c.model, process.env.WEFT_MODEL ?? "openclaw"),
    timeoutMs: num(c.timeoutMs, 15000),
    submitTimeoutMs: num(c.submitTimeoutMs, 20000),
  };
}
