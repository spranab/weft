import {
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign as edSign,
  type KeyObject,
} from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync, existsSync, chmodSync } from "node:fs";
import { dirname } from "node:path";
import type { ResolvedConfig } from "./config.js";

export class WeftError extends Error {}

const DER_PRIV_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
const DER_PUB_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

/**
 * Signing client for a weftd hub.
 *
 * Every write follows the same three-step flow the browser console uses:
 * POST /prepare (the hub canonicalizes the object and returns the 32-byte
 * digest to sign) → sign locally → POST /submit with the signature. The hub
 * verifies before storing, so it never needs — and never receives — the key.
 */
export class WeftClient {
  private seed: Buffer;
  private capability: string | null = null;

  constructor(private cfg: ResolvedConfig) {
    this.seed = loadOrCreateSeed(cfg.keyPath);
  }

  /** The raw 32-byte Ed25519 seed, wrapped as a PKCS#8 key object. */
  private privateKey(): KeyObject {
    return createPrivateKey({
      key: Buffer.concat([DER_PRIV_PREFIX, this.seed]),
      format: "der",
      type: "pkcs8",
    });
  }

  publicKeyHex(): string {
    const der = createPublicKey(this.privateKey()).export({
      format: "der",
      type: "spki",
    }) as Buffer;
    return der.subarray(DER_PUB_PREFIX.length).toString("hex");
  }

  private signDigest(digest: Buffer): string {
    return edSign(null, digest, this.privateKey()).toString("hex");
  }

  private async get<T>(path: string): Promise<T> {
    const res = await fetch(`${this.cfg.hub}${path}`, {
      signal: AbortSignal.timeout(this.cfg.timeoutMs),
    });
    if (!res.ok) throw new WeftError(`GET ${path} → ${res.status}`);
    return (await res.json()) as T;
  }

  private async post<T>(path: string, body: unknown): Promise<T> {
    const res = await fetch(`${this.cfg.hub}${path}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(this.cfg.timeoutMs),
    });
    const text = await res.text();
    if (!res.ok) throw new WeftError(`${path}: ${text.slice(0, 200)}`);
    return JSON.parse(text) as T;
  }

  /** /prepare → sign → /submit. Byte strings cross as "hex:<hex>". */
  async publish(
    type: string,
    body: Record<string, unknown>,
    auth?: string,
  ): Promise<string> {
    const policy = await this.get<{ repo: string | null }>("/policy");
    if (!policy.repo) {
      throw new WeftError("hub has no repository yet — create one in the console");
    }
    const env: Record<string, unknown> = {
      repo: `hex:${policy.repo}`,
      type,
      ts: Date.now(),
      author: `hex:${this.publicKeyHex()}`,
      auth: auth ? `hex:${auth}` : null,
      body,
    };
    const prep = await this.post<{ payload: string }>("/prepare", env);
    env.sig = `hex:${this.signDigest(Buffer.from(prep.payload, "hex"))}`;
    return (await this.post<{ oid: string }>("/submit", env)).oid;
  }

  async status(): Promise<{
    repo: string | null;
    trunk_seq: number;
    queued: number;
    pending: unknown[];
  }> {
    const [policy, heads, log, pending] = await Promise.all([
      this.get<{ repo: string | null }>("/policy"),
      this.get<{ seq: number }>("/heads"),
      this.get<{ queued: number }>("/log"),
      this.get<{ pending: unknown[] }>("/pending"),
    ]);
    return {
      repo: policy.repo,
      trunk_seq: heads.seq,
      queued: log.queued,
      pending: pending.pending,
    };
  }

  async intents(): Promise<unknown[]> {
    return (await this.get<{ intents: unknown[] }>("/intents")).intents;
  }

  async workspace(): Promise<WorkspaceResponse> {
    return this.get<WorkspaceResponse>("/workspace");
  }

  async provenance(change: string): Promise<unknown> {
    return this.get(`/provenance/${change}`);
  }

  async log(): Promise<LogResponse> {
    return this.get<LogResponse>("/log");
  }

  async pendingApprovals(): Promise<{ pending: PendingEntry[] }> {
    return this.get<{ pending: PendingEntry[] }>("/pending");
  }

  async hasCapability(action: string): Promise<boolean> {
    try {
      await this.findCapability(action);
      return true;
    } catch {
      return false;
    }
  }

  /** Find a live capability delegated to this key — the onboarding hint. */
  async findCapability(action: string): Promise<string> {
    if (this.capability) return this.capability;
    const { caps } = await this.get<{ caps: Cap[] }>("/caps");
    const mine = caps.find(
      (c) =>
        c.audience === this.publicKeyHex() &&
        !c.revoked &&
        c.exp > Date.now() &&
        c.actions.includes(action),
    );
    if (!mine) {
      throw new WeftError(
        `no live capability granting '${action}' is delegated to this agent key ` +
          `(${this.publicKeyHex()}). Ask a human to open the Weft console → ` +
          `Access → mint a Contributor capability for that key.`,
      );
    }
    this.capability = mine.oid;
    return mine.oid;
  }
}

function loadOrCreateSeed(path: string): Buffer {
  if (existsSync(path)) {
    return Buffer.from(readFileSync(path, "utf8").trim(), "hex");
  }
  const { privateKey } = generateKeyPairSync("ed25519");
  const der = privateKey.export({ format: "der", type: "pkcs8" }) as Buffer;
  const seed = der.subarray(der.length - 32);
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, seed.toString("hex"), "utf8");
  try {
    chmodSync(path, 0o600);
  } catch {
    /* best effort — a no-op on Windows */
  }
  return seed;
}

export interface WorkspaceFile {
  content: string;
  digest: string;
  fid: [string, number];
  instruction: boolean;
  line_ids: [string, number][];
}
export interface WorkspaceResponse {
  seq: number;
  files: Record<string, WorkspaceFile>;
}
export interface LogEntry {
  seq: number;
  landing: string;
  changes: { oid: string; model: string; message: string }[];
}
export interface LogResponse {
  log: LogEntry[];
  rejects: unknown[];
  queued: number;
}
export interface PendingEntry {
  manifest: string;
  need: number;
  have: number;
  changes: { oid: string; model: string; message: string }[];
}
interface Cap {
  oid: string;
  audience: string;
  actions: string[];
  exp: number;
  revoked: boolean;
}
