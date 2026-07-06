/**
 * P3′ payfetch — guards public surface (SPEC §7.5). Exactly the wiring seam:
 * the two factories, the guard interface + config + runtime types, and the
 * frozen default configs. Nothing else (internal.ts stays private).
 *
 * `core/policy.ts` imports `TrustGuardConfig` / `SafetyGuardConfig` from here
 * (via the type re-export) as the single source of truth for the §4.1 guard
 * config blocks; the pipeline (§7.4/§7.5) imports the factories + `GuardRuntime`.
 */

export { createTrustGuard } from "./trust.js";
export { createSafetyGuard } from "./safety.js";

export type {
  PrePayGuard,
  GuardId,
  GuardInput,
  GuardResult,
  TrustGuardConfig,
  SafetyGuardConfig,
  GuardRuntime,
} from "./types.js";

export { DEFAULT_TRUST_GUARD_CONFIG, DEFAULT_SAFETY_GUARD_CONFIG } from "./types.js";
