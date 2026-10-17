/**
 * Mirror admitted members into a Cloudflare Access reusable policy so the
 * Access self-hosted apps in front of the Worker admit Artifact Server members
 * alongside any manually managed rules. Local member status stays the authorization
 * boundary; this sync is defense in depth and never fails a member change.
 *
 * Limitation: the Access API has no atomic list edit, so each sync is a GET
 * followed by a full PUT. Incremental syncs are serialized within one isolate,
 * but reconciliation, other isolates, or a human editing concurrently can lose
 * one edit (last PUT wins). Treat the policy as eventually consistent and
 * reconcile it on the scheduled tick; it is an outer gate, never the source
 * of truth.
 */
import {z} from "zod";

import type {IdentityRepository} from "../../../src/core/identity-ports.js";

export interface AccessPolicySyncConfig {
  readonly accountId: string;
  readonly apiToken: string;
  readonly bootstrapAdministratorEmail: string;
  readonly fetch?: typeof fetch;
  readonly policyId: string;
  readonly timeoutMs?: number;
}

const writableFields = [
  "name",
  "decision",
  "include",
  "exclude",
  "require",
  "session_duration",
  "approval_groups",
  "approval_required",
  "isolation_required",
  "purpose_justification_required",
  "purpose_justification_prompt",
  "connection_rules",
  "mfa_config",
] as const;

const policyResponseSchema = z.object({
  result: z.looseObject({include: z.array(z.json())}),
  success: z.literal(true),
});
const emailRuleSchema = z.object({email: z.object({email: z.string()})});

type PolicyRule = z.infer<ReturnType<typeof z.json>>;
type SyncOperation = "add" | "remove";

class AccessSyncFailure extends Error {
  override readonly name = "AccessSyncFailure";
}

/** Decorate a repository so admit/deactivate update the Access policy. */
export function withAccessPolicySync(
  repository: IdentityRepository,
  config: AccessPolicySyncConfig,
): IdentityRepository {
  let queue: Promise<void> = Promise.resolve();
  const sync = (operation: SyncOperation, email: string): Promise<void> => {
    const next = queue.then(() => syncEmail(config, operation, email));
    queue = next;
    return next;
  };
  return {
    findActiveMemberByEmail: (...args) => repository.findActiveMemberByEmail(...args),
    findActiveMemberByExternalIdentity: (...args) => repository.findActiveMemberByExternalIdentity(...args),
    hasMembers: (...args) => repository.hasMembers(...args),
    findMember: (...args) => repository.findMember(...args),
    findMemberByEmail: (...args) => repository.findMemberByEmail(...args),
    consumeLoginAttempt: (...args) => repository.consumeLoginAttempt(...args),
    createLoginAttempt: (...args) => repository.createLoginAttempt(...args),
    listMembers: (...args) => repository.listMembers(...args),
    bindExternalIdentity: (...args) => repository.bindExternalIdentity(...args),
    findApplicationSession: (...args) => repository.findApplicationSession(...args),
    createApplicationSession: (...args) => repository.createApplicationSession(...args),
    revokeApplicationSession: (...args) => repository.revokeApplicationSession(...args),
    createApiKey: (...args) => repository.createApiKey(...args),
    findApiKey: (...args) => repository.findApiKey(...args),
    listApiKeys: (...args) => repository.listApiKeys(...args),
    revokeApiKey: (...args) => repository.revokeApiKey(...args),
    rotateApiKey: (...args) => repository.rotateApiKey(...args),
    admitMember: async (command) => {
      const member = await repository.admitMember(command);
      await sync("add", member.email);
      return member;
    },
    deactivateMember: async (installationId, memberId, updatedAt) => {
      const member = await repository.deactivateMember(
        installationId,
        memberId,
        updatedAt,
      );
      await sync("remove", member.email);
      return member;
    },
  };
}

function normalizeEmail(email: string): string {
  return email.trim().toLocaleLowerCase("en-US");
}

/** Repair missed incremental updates without removing manually managed rules. */
export async function reconcileAccessPolicy(
  repository: IdentityRepository,
  installationId: string,
  config: AccessPolicySyncConfig,
): Promise<void> {
  try {
    const members = await repository.listMembers(installationId);
    const active = new Set([normalizeEmail(config.bootstrapAdministratorEmail)]);
    const inactive = new Set<string>();
    for (const member of members) {
      (member.status === "active" ? active : inactive).add(normalizeEmail(member.email));
    }
    let added = 0;
    let removed = 0;
    await applyChange(config, (include) => {
      const present = new Set<string>();
      const remaining = include.filter((rule) => {
        const parsed = emailRuleSchema.safeParse(rule);
        const email = parsed.success ? normalizeEmail(parsed.data.email.email) : null;
        if (email !== null && inactive.has(email) && !active.has(email)) {
          removed += 1;
          return false;
        }
        if (email !== null) present.add(email);
        return true;
      });
      const missing = [...active].filter((email) => !present.has(email));
      added = missing.length;
      return added === 0 && removed === 0 ? null : [
        ...remaining, ...missing.map((email) => ({email: {email}})),
      ];
    });
    console.info(JSON.stringify({event: "cloudflare_access_policy_reconciled", added, removed}));
  } catch {
    console.warn(JSON.stringify({event: "cloudflare_access_policy_reconcile_failed"}));
  }
}

async function syncEmail(
  config: AccessPolicySyncConfig,
  operation: SyncOperation,
  email: string,
): Promise<void> {
  try {
    await applyChange(config, (include) => nextInclude(
      include, operation, normalizeEmail(email), normalizeEmail(config.bootstrapAdministratorEmail),
    ));
  } catch (cause) {
    console.warn(JSON.stringify({
      event: "cloudflare_access_policy_sync_failed",
      operation,
      reason: cause instanceof AccessSyncFailure
        ? cause.message
        : cause instanceof Error && cause.name === "TimeoutError"
        ? "timeout"
        : "network",
    }));
  }
}

async function applyChange(
  config: AccessPolicySyncConfig,
  transform: (include: PolicyRule[]) => PolicyRule[] | null,
): Promise<void> {
  const url = `https://api.cloudflare.com/client/v4/accounts/${
    encodeURIComponent(config.accountId)
  }/access/policies/${encodeURIComponent(config.policyId)}`;
  const send = config.fetch ?? fetch;
  const signal = AbortSignal.timeout(config.timeoutMs ?? 5000);
  const headers = {
    Authorization: `Bearer ${config.apiToken}`,
    "Content-Type": "application/json",
  };
  const current = await send(url, {headers, signal});
  if (!current.ok) throw new AccessSyncFailure(`get_http_${current.status}`);
  const parsed = policyResponseSchema.safeParse(await current.json());
  if (!parsed.success) throw new AccessSyncFailure("invalid_policy_response");
  const policy = parsed.data.result;
  const include = transform(policy.include);
  if (include === null) return;
  const body = new Map<string, unknown>();
  for (const field of writableFields) {
    if (field in policy) body.set(field, policy[field]);
  }
  body.set("include", include);
  const updated = await send(url, {
    body: JSON.stringify(Object.fromEntries(body)),
    headers,
    method: "PUT",
    signal,
  });
  if (!updated.ok) throw new AccessSyncFailure(`put_http_${updated.status}`);
}

/** Return the new include list, or null when no write is needed or allowed. */
export function nextInclude(
  include: readonly PolicyRule[],
  operation: SyncOperation,
  email: string,
  bootstrapAdministratorEmail: string,
): PolicyRule[] | null {
  const matches = (rule: PolicyRule): boolean => {
    const parsed = emailRuleSchema.safeParse(rule);
    return parsed.success && normalizeEmail(parsed.data.email.email) === normalizeEmail(email);
  };
  email = normalizeEmail(email);
  bootstrapAdministratorEmail = normalizeEmail(bootstrapAdministratorEmail);
  const present = include.some(matches);
  if (operation === "add") {
    return present ? null : [...include, {email: {email}}];
  }
  if (!present || email === bootstrapAdministratorEmail) return null;
  const remaining = include.filter((rule) => !matches(rule));
  if (remaining.length === 0) {
    throw new AccessSyncFailure("refused_empty_include");
  }
  return remaining;
}
