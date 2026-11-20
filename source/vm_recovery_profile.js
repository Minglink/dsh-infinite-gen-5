import path from 'node:path';
import { loadRecoveryPlan } from './vm_recovery_io.js';
import { recoveryError } from './vm_recovery_case.js';
import { observationProfileSchema, runObservationProfile } from './vm_observation_profile.js';
import { roleProfileSchema, runVmRoleProfile } from './vm_role_profile.js';
import { flowProfileSchema, runVmFlowProfile } from './vm_flow_profile.js';
import { recurrenceProfileSchema,runVmRecurrenceProfile } from './vm_recurrence_profile.js';
import { handlerProfileSchema,runVmHandlerProfile } from './vm_handler_profile.js';
import { contextProfileSchema,runVmContextProfile } from './vm_context_profile.js';
import { progressionSchemas, runVmProgression } from './vm_program.js';
import {instanceSchemas,runVmInstances} from './vm_instance_workflow.js';

export const recoveryProfileSchema = {
  type: 'object', properties: { case_ref: { type: 'object', properties: {
    path: { type: 'string' },
    sha256: { type: 'string', pattern: '^[a-f0-9]{64}$' },
  }, required: ['path', 'sha256'], additionalProperties: false }, observations: observationProfileSchema, roles: roleProfileSchema, flow: flowProfileSchema,recurrences:recurrenceProfileSchema,handlers:handlerProfileSchema,context:contextProfileSchema },
  oneOf: [{ required: ['case_ref'] }, { required: ['observations'] }, { required: ['roles'] }, { required: ['flow'] },{required:['recurrences']},{required:['handlers']},{required:['context']}, ...Object.keys(progressionSchemas).map(k => ({ required: [k] }))], additionalProperties: false,
};
Object.assign(recoveryProfileSchema.properties, progressionSchemas,instanceSchemas);
recoveryProfileSchema.oneOf.push(...Object.keys(instanceSchemas).map(k=>({required:[k]})));
function fields(value, keys, name) {
  if (!value || typeof value !== 'object' || ![Object.prototype, null].includes(Object.getPrototypeOf(value))
    || Reflect.ownKeys(value).some(key => !keys.includes(key) || !Object.hasOwn(Object.getOwnPropertyDescriptor(value, key), 'value'))
    || keys.some(key => !Object.hasOwn(value, key))) recoveryError('INVALID_RECOVERY_REF', `${name} requires exactly ${keys.join(', ')}`);
}
/** A report-producing read operation, never a scheduler or execution gate. */
export function runRecoveryProfile(mgr, args, cfg) {
  fields(args, ['recovery'], 'Use recovery separately from target, engine, workspace, toolset, history and guest_debug');
  for(const mode of Object.keys(instanceSchemas))if(args.recovery&&Object.hasOwn(args.recovery,mode)){fields(args.recovery,[mode],'recovery');return runVmInstances(mgr,mode,args.recovery[mode]);}
  for (const mode of Object.keys(progressionSchemas)) if (args.recovery && Object.hasOwn(args.recovery, mode)) {
    fields(args.recovery, [mode], 'recovery');
    return runVmProgression(mgr, mode, args.recovery[mode], cfg);
  }
  if (args.recovery && Object.hasOwn(args.recovery, 'context')) {
    fields(args.recovery, ['context'], 'recovery');
    return runVmContextProfile(mgr,args.recovery.context);
  }
  if (args.recovery && Object.hasOwn(args.recovery, 'handlers')) {
    fields(args.recovery, ['handlers'], 'recovery');
    return runVmHandlerProfile(mgr,cfg,args.recovery.handlers);
  }
  if (args.recovery && Object.hasOwn(args.recovery, 'recurrences')) {
    fields(args.recovery, ['recurrences'], 'recovery');
    return runVmRecurrenceProfile(mgr,cfg,args.recovery.recurrences);
  }
  if (args.recovery && Object.hasOwn(args.recovery, 'flow')) {
    fields(args.recovery, ['flow'], 'recovery');
    return runVmFlowProfile(mgr, cfg, args.recovery.flow);
  }
  if (args.recovery && Object.hasOwn(args.recovery, 'roles')) {
    fields(args.recovery, ['roles'], 'recovery');
    return runVmRoleProfile(mgr, cfg, args.recovery.roles);
  }
  if (args.recovery && Object.hasOwn(args.recovery, 'observations')) {
    fields(args.recovery, ['observations'], 'recovery');
    return runObservationProfile(mgr, cfg, args.recovery.observations);
  }
  fields(args.recovery, ['case_ref'], 'recovery');
  fields(args.recovery.case_ref, ['path', 'sha256'], 'case_ref');
  const reference = args.recovery.case_ref;
  if (typeof reference.sha256 !== 'string' || !/^[a-f0-9]{64}$/.test(reference.sha256))
    recoveryError('INVALID_RECOVERY_REF', 'case_ref.sha256 is required and must be a lowercase SHA-256');
  const { plan, snapshot } = loadRecoveryPlan(reference.path, { expectedSha256: reference.sha256,
    checkCancelled: () => mgr.checkCancelled() });
  plan.integration.dshPlanningEntry = 'ig5_recovery.recovery';
  mgr.checkCancelled();
  const artifacts = mgr.analysis.artifacts;
  const record = artifacts.save({ kind: 'vm-recovery-plan', action: 'plan', result: { ...plan, caseSnapshot: snapshot } }, { pretty: true, maxBytes: 4 * 1024 * 1024 });
  const reportSha256 = artifacts.metadata(record.id).result.recordSha256;
  return { recovery: {
    schema: plan.schema, caseId: plan.caseId, completionAssessment: plan.completionAssessment,
    sourceOfWorkStates: plan.sourceOfWorkStates, artifactChecksEstablish: plan.artifactChecksEstablish,
    executionAuthority: plan.executionAuthority, executionHeldFromObservations: plan.executionHeldFromObservations,
    executionPerformed: false, changesExecutionAuthority: false,
    reportId: record.id, reportPath: path.join(artifacts.root, 'records', record.id + '.json'), reportSha256,
    sourceCase: plan.sourceCase, bindingSha256: plan.bindingSha256, caseSha256: plan.caseSha256,
    lane: plan.lane, reportedVersionMatch: plan.versionMatch, requestedVersionSeries: plan.requestedVersionSeries,
    stages: plan.stages, nextActions: plan.nextActions.map(({ prerequisites, ...action }) => ({ ...action,
      prerequisitesSummary: { stages: prerequisites.stages, capabilityCount: prerequisites.capabilities.length,
        allCapabilities: 'not-probed', fullRequirementsInReport: true } })),
    deferredActionCount: plan.deferredActions.length, evaluatedEventCount: plan.evaluatedEvents.length,
    staleEventCount: plan.evaluatedEvents.filter(event => event.invalidReasons.length).length,
    referenceChecks: { total: plan.referenceChecks.length,
      matched: plan.referenceChecks.filter(check => check.status === 'identity-matched').length,
      mismatched: plan.referenceChecks.filter(check => check.status === 'identity-mismatch').length,
      unavailable: plan.referenceChecks.filter(check => check.status === 'unavailable').length },
    repeatedFailures: plan.evaluatedEvents.filter(event => event.repeatedWithoutNewInputs >= 2).slice(-4),
    integration: plan.integration, engineeringActions: plan.engineeringActions,
    previewComplete: false, fullReportContainsCaseSnapshotAndAllRequirements: true,
  } };
}
