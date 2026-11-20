import { RECOVERY_FAILURES } from './vm_recovery_case.js';

const routes = {
  ENVIRONMENT_NOT_READY: 'check-prerequisites-or-use-offline-evidence',
  REVERSE_UNAVAILABLE: 'check-prerequisites-or-use-offline-evidence',
  RUNTIME_POLICY_BLOCKED: 'use-offline-evidence-no-native-retry',
  ERUNTIME_POLICY: 'use-offline-evidence-no-native-retry',
  ERUNTIME: 'check-prerequisites-or-use-offline-evidence',
  STALE_TASK_REVISION: 'read-current-task-and-replan',
  STALE_SESSION_CONTEXT: 'read-current-context-and-replan',
  INVALID_PHASE_CONTEXT: 'revalidate-context-and-complete-recording-manifest',
  CODE_VERSION_MISMATCH: 'read-exact-observation-code-version',
  ARTIFACT_CHANGED: 'revalidate-original-evidence',
  INVALID_ARGUMENT: 'inspect-operation-schema',
  INVALID_INVESTIGATION: 'inspect-operation-schema',
  NOT_TRIGGERED: 'adjust-scenario-trigger-or-input-before-retrying-observer',
  IDEMPOTENCY_CONFLICT: 'use-fresh-request-key-for-different-arguments',
  IG5_EXECUTION_EFFECT_UNKNOWN: 'inspect-runtime-and-session-before-manual-recovery-no-auto-replay',
  BUDGET_INSUFFICIENT_FOR_CLEANUP_RESERVE: 'avoid-new-resource-acquisition-when-remaining-budget-cannot-cover-cleanup',
  IG5_CANCELLED_BEFORE_DISPATCH: 'stop-business-dispatch-and-run-only-owner-cleanup-until-human-resume',
  RECEIPT_PERSISTENCE_FAILED: 'recover-or-inspect-existing-execution-without-rerunning-side-effect',
  STALE_RESEARCH_PLAN_REVISION: 'refresh-root-brief-and-rebind-plan-revision',
  PRECONDITION_DIGEST_MISMATCH: 'reselect-experiment-against-current-component-and-scenario',
  PREPARATION_BUDGET_EXHAUSTED: 'switch-from-static-preparation-to-discriminating-experiment-or-block-route',
  UNVERIFIED_NEGATIVE_SCOPE: 'confirm-trigger-and-observer-before-claiming-negative-result',
  HELPER_SCENARIO_MISMATCH: 'launch-via-parent-or-ipc-scenario-rather-than-standalone-helper',
  SCENARIO_REQUIRED: 'define-runtime-scenario-before-selecting-dynamic-experiment',
  INLINE_EXPLORATION_NOT_PERMITTED: 'select-explicit-experiment-for-dynamic-or-write-tool',
  CACHE_SHORT_CIRCUIT: 'bypass-parent-memo-cache-or-use-fresh-input-to-trigger-helper-spawn',
  HELPER_NOT_SPAWNED: 'verify-ui-or-ipc-trigger-reaches-child-spawn-path',
  UI_TRIGGER_FAILED: 'run-electron-scenario-discover-mode-to-inspect-real-dom-selectors-and-ipc-channels',
  OBSERVER_LOG_MISSING: 'check-electron-or-node-preload-environment-and-avoid-claiming-verified-handoff',
  OBSERVER_LOG_TRUNCATED: 'increase-bounded-settle-or-timeout-window-and-recollect-complete-observer-log',
  OBSERVER_LOG_CORRUPT: 'discard-corrupt-observer-receipt-and-rerun-isolated-scenario',
  REA_CLI_UNAVAILABLE: 'configure-IG5_REA_ROOT-to-verified-rea-agents-6.4.0-or-inspect-js-sources-directly',
  REA_PIN_MISMATCH: 'restore-intact-pinned-rea-agents-6.4.0-distribution-before-js-app-analysis',
  ELECTRON_RUNTIME_UNAVAILABLE: 'pass-packaged-target-exe-or-configure-IG5_ELECTRON_EXE-for-unpackaged-app-dir',
  STALE_MODULE_MAPPING: 'query-live-modules-base-after-reload-before-reading-dll-rva',
  CROSS_RUN_RECEIPT_MISMATCH: 'bind-all-chain-worker-observations-to-single-run-id-and-correlation-id',
  CROSS_ROOT_REPORT_REJECTED: 'reissue-brief-bound-to-current-root-id-and-component-sha256',
  DEVICE_OR_FRIDA_UNAVAILABLE: 'mark-on-device-dynamic-hook-blocked-and-use-static-or-cpu-emulation-within-scope',
  ANDROID_DEVICE_UNAVAILABLE: 'connect-authorized-adb-device-or-mark-dynamic-device-hook-route-blocked',
  FRIDA_PYTHON_MISSING: 'install-host-frida-in-project-python-or-mark-dynamic-device-hook-blocked',
  FRIDA_SERVER_UNREACHABLE: 'start-matching-frida-server-or-gadget-on-authorized-device',
  FRIDA_SERVER_VERSION_MISMATCH: 'align-host-frida-major-version-with-device-frida-server-before-attaching',
  ANDROID_INSTALLED_APK_MISMATCH: 'verify-installed-package-sha256-matches-registered-apk-before-hooking',
  ANDROID_ABI_OR_LIB_MISMATCH: 'bind-jni-so-from-apk-lib-dir-matching-device-primary-abi',
  JNI_ENV_CALLBACK_REQUIRED: 'function-dereferences-JNIEnv-vtable-do-not-emulate-with-zero-rdi-x0-use-device-hook-or-valid-jnienv-stub',
  SCENARIO_INPUT_UNVERIFIED_FOR_EXPERIMENT: 'prepare-input-via-root-update-prepareInputs-or-declare-sampleHex-with-matching-execution-input-files-before-select',
  SCENARIO_INPUT_FILE_MODIFIED: 're-register-updated-scenario-via-root-update-or-restore-frozen-input-file-bytes',
  SCENARIO_INPUT_NOT_FROZEN: 'call-root-update-scenario-after-writing-input-file-so-scenarioDigest-binds-its-sha256',
  SCENARIO_INPUT_CHANNEL_CONFLICT: 'align-execution-input-files-and-argv-with-bound-scenario-inputChannel-and-sampleHex',
  SCENARIO_INPUT_FILE_MISSING_AT_DISPATCH: 'supply-bound-file-in-input_files-or-prepare-via-root-update-prepareInputs-before-dispatch',
  SCENARIO_INPUT_FILE_MODIFIED_BEFORE_DISPATCH: 'do-not-mutate-bound-input-file-between-select-and-execution-create-new-scenario-instead',
  CONTRACT_DOWNGRADE_FORBIDDEN: 'preserve-nonCooperativeRequired-and-holdoutRequired-on-host-goal-deliverables',
  OBSERVER_FAILED_CANNOT_CLAIM_NEGATIVE: 'fix-observer-preload-or-container-integrity-before-claiming-contract-obligation-falsified',
  PERSISTENT_BLOCK_ALREADY_ESTABLISHED: 'do-not-repeat-unchanged-business-calls-follow-hostGoalRoundStatus-to-conclude-legally',
};

/** Pure static pointers to built-in knowledge_seeds.js card IDs (no cross-layer research import). */
export const KNOWLEDGE_CARD_HINTS = Object.freeze({
  JNI_ENV_CALLBACK_REQUIRED: 'android-apk-jni-workflow',
  ANDROID_DEVICE_UNAVAILABLE: 'android-apk-jni-workflow',
  ANDROID_ABI_OR_LIB_MISMATCH: 'android-apk-jni-workflow',
  ANDROID_INSTALLED_APK_MISMATCH: 'android-apk-jni-workflow',
  DEVICE_OR_FRIDA_UNAVAILABLE: 'android-apk-jni-workflow',
  FRIDA_PYTHON_MISSING: 'android-apk-jni-workflow',
  FRIDA_SERVER_UNREACHABLE: 'android-apk-jni-workflow',
  FRIDA_SERVER_VERSION_MISMATCH: 'android-apk-jni-workflow',
  REA_CLI_UNAVAILABLE: 'electron-process-chain-workflow',
  REA_PIN_MISMATCH: 'electron-process-chain-workflow',
  ELECTRON_RUNTIME_UNAVAILABLE: 'electron-process-chain-workflow',
  HELPER_SCENARIO_MISMATCH: 'electron-process-chain-workflow',
  CACHE_SHORT_CIRCUIT: 'electron-process-chain-workflow',
  HELPER_NOT_SPAWNED: 'electron-process-chain-workflow',
  UI_TRIGGER_FAILED: 'electron-process-chain-workflow',
  NOT_TRIGGERED: 'electron-process-chain-workflow',
  CROSS_RUN_RECEIPT_MISMATCH: 'electron-process-chain-workflow',
  STALE_MODULE_MAPPING: 'firmware-address-alignment',
  INVALID_PHASE_CONTEXT: 'vm-handler-projection-bounds',
  CODE_VERSION_MISMATCH: 'vm-handler-projection-bounds',
});

/** Advice only. Never grants execution, budgets, acceptance or cleanup. */
export function routeFailure(record, occurrences = 1) {
  const code = record.failureCode;
  const recovery = typeof code === 'string' && Object.hasOwn(RECOVERY_FAILURES, code) ? RECOVERY_FAILURES[code] : null;
  const route = typeof code === 'string' && Object.hasOwn(routes, code) ? routes[code] : null;
  const recommendedCardId = typeof code === 'string' && Object.hasOwn(KNOWLEDGE_CARD_HINTS, code)
    ? KNOWLEDGE_CARD_HINTS[code]
    : (recovery ? 'vm-role-experiments' : null);
  const environment = ['ENVIRONMENT_NOT_READY', 'REVERSE_UNAVAILABLE', 'RUNTIME_POLICY_BLOCKED', 'ERUNTIME_POLICY', 'ERUNTIME'].includes(code);
  const cleanup = code === 'CLEANUP_UNCONFIRMED' || record.original?.cleanupConfirmed === false || record.original?.guestCleanupConfirmed === false;
  const repeat = occurrences >= 2;
  return {
    category: cleanup ? 'resource' : environment ? 'environment' : recovery || ['INVALID_PHASE_CONTEXT', 'CODE_VERSION_MISMATCH'].includes(code) ? 'research' : route ? 'usage' : 'unclassified',
    nextCheck: cleanup ? 'recover-original-execution-owner' : record.original?.metadataPublished === true ? 'read-current-metadata-before-retry'
      : record.original?.metadataPublished === false ? 'inspect-metadata-publication-failure' : repeat && !environment ? 'design-discriminating-experiment' : recovery?.[1] || route || 'inspect-original-failure-and-diagnose',
    ...(recommendedCardId ? { recommendedCardId } : {}),
    occurrences, needsRediagnosis: repeat, executionAuthorized: false,
    acceptanceChanged: false, cleanupConfirmed: null,
  };
}
