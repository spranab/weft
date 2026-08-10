/**
 * Ambient declarations for the host-provided OpenClaw plugin SDK modules.
 *
 * When OpenClaw loads this plugin, the `openclaw/plugin-sdk/*` specifiers
 * resolve inside the host process — the plugin never bundles the SDK.
 * These declarations are a minimal structural mirror of the surface this
 * plugin uses, so the package typechecks and tests standalone. They are
 * intentionally conservative: fields we do not use are typed as unknown.
 *
 * Reference: openclaw/openclaw extensions/memory-lancedb (the in-tree
 * memory-slot plugin this plugin mirrors the contract of).
 */

declare module "openclaw/plugin-sdk/plugin-entry" {
  import type { TSchema } from "typebox";

  export interface PluginToolTextContent {
    type: "text";
    text: string;
  }

  export interface PluginToolResult {
    content: PluginToolTextContent[];
    details?: Record<string, unknown>;
    isError?: boolean;
  }

  export interface PluginToolDefinition {
    name: string;
    label?: string;
    description: string;
    parameters: TSchema;
    execute(
      toolCallId: string,
      params: unknown,
    ): Promise<PluginToolResult> | PluginToolResult;
  }

  export interface PluginToolFactoryContext {
    agentId?: string;
    sessionKey?: string;
    config?: unknown;
    [key: string]: unknown;
  }

  export type PluginToolRegistration =
    | PluginToolDefinition
    | ((ctx: PluginToolFactoryContext) => PluginToolDefinition | null);

  export interface PluginHookContext {
    agentId?: string;
    sessionKey?: string;
    [key: string]: unknown;
  }

  export interface BeforePromptBuildEvent {
    messages?: unknown[];
    [key: string]: unknown;
  }

  export interface BeforePromptBuildResult {
    prependContext?: string;
  }

  export interface AgentEndEvent {
    messages?: unknown[];
    success?: boolean;
    [key: string]: unknown;
  }

  export interface SessionEndEvent {
    [key: string]: unknown;
  }

  export interface PluginServiceDefinition {
    id: string;
    start(): void | Promise<void>;
    stop?(): void | Promise<void>;
  }

  export interface PluginLogger {
    debug?(message: string): void;
    info(message: string): void;
    warn(message: string): void;
    error(message: string): void;
  }

  export interface OpenClawPluginApi {
    pluginConfig?: Record<string, unknown>;
    logger: PluginLogger;
    registerTool(
      tool: PluginToolRegistration,
      opts?: { name?: string; optional?: boolean },
    ): void;
    registerService(service: PluginServiceDefinition): void;
    on(
      event: "before_prompt_build",
      handler: (
        event: BeforePromptBuildEvent,
        ctx: PluginHookContext,
      ) =>
        | Promise<BeforePromptBuildResult | undefined>
        | BeforePromptBuildResult
        | undefined,
    ): void;
    on(
      event: "agent_end",
      handler: (
        event: AgentEndEvent,
        ctx: PluginHookContext,
      ) => Promise<void> | void,
    ): void;
    on(
      event: "session_end",
      handler: (
        event: SessionEndEvent,
        ctx: PluginHookContext,
      ) => Promise<void> | void,
    ): void;
  }

  export interface PluginEntryDefinition {
    id: string;
    name: string;
    description?: string;
    kind?: "memory" | "context-engine" | (string & {});
    configSchema?: TSchema;
    register(api: OpenClawPluginApi): void | Promise<void>;
  }

  export function definePluginEntry(
    definition: PluginEntryDefinition,
  ): PluginEntryDefinition;
}

declare module "openclaw/plugin-sdk/routing" {
  // NOTE: verified against the real OpenClaw 2026.7.1-2 host
  // (dist/plugin-sdk/routing.d.ts). `isIncognitoSessionKey` is NOT
  // exported by the real host and must not be declared here — importing
  // it type-checks but crashes at runtime inside the host.
  export function normalizeAgentId(
    agentId: string | undefined,
  ): string | undefined;
}
