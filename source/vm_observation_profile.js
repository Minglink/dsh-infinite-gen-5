import { vmContextEvidence, exactReportRef } from './evidence_adapters/vm_context.js';
import { validatePhaseModel } from './vm_phase_model.js';
import path from 'node:path';
import { AnalysisArtifactReader, hashBytes, readStableFile } from './analysis_artifacts.js';
import { readNativeStoreEvents } from './native_store_events.js';

const fail = message => { throw Object.assign(new Error(message), { code: 'INVALID_VM_OBSERVATION' }); };
export const observationProfileSchema = { type: 'object', properties: {
  recordings: { type: 'array', minItems: 1, maxItems: 256, items: { type: 'object', properties: {
    id: { type: 'string' },
    sha256: { type: 'string', pattern: '^[a-f0-9]{64}$' },
  }, required: ['id', 'sha256'], additionalProperties: false } },
  target_sha256: { type: 'string', pattern: '^[a-f0-9]{64}$' },
  phase_context_ref: { type: 'object', properties: { id: { type: 'string' }, sha256: { type: 'string', pattern: '^[a-f0-9]{64}$' } }, required: ['id', 'sha256'], additionalProperties: false },
  phase_model: { type: 'boolean' },
  max_instructions: { type: 'integer', minimum: 1, maximum: 100000 },
  offset: { type: 'integer', minimum: 0, maximum: 100000 },
  limit: { type: 'integer', minimum: 1, maximum: 64 },
}, required: ['recordings', 'target_sha256'], additionalProperties: false };
function object(value, allowed, required) {
  if (!value || typeof value !== 'object' || ![Object.prototype, null].includes(Object.getPrototypeOf(value))
    || Reflect.ownKeys(value).some(key => !allowed.includes(key) || !Object.hasOwn(Object.getOwnPropertyDescriptor(value, key), 'value'))
    || required.some(key => !Object.hasOwn(value, key))) fail('Invalid observation fields');
}
export function validateObservationRequest(value) {
  object(value, ['recordings', 'target_sha256', 'max_instructions', 'offset', 'limit', 'phase_model', 'phase_context_ref'], ['recordings', 'target_sha256']);
  if (value.phase_context_ref !== undefined) { if (value.phase_model !== true) fail('phase_context_ref requires phase_model=true'); object(value.phase_context_ref, ['id', 'sha256'], ['id', 'sha256']); exactReportRef(value.phase_context_ref); }
  if (value.phase_model !== undefined && typeof value.phase_model !== 'boolean') fail('phase_model must be boolean');
  if (typeof value.target_sha256 !== 'string' || !/^[a-f0-9]{64}$/.test(value.target_sha256)) fail('Expected target SHA-256');
  for (const [name, low, high] of [['max_instructions', 1, 100000], ['offset', 0, 100000], ['limit', 1, 64]]) {
    if (value[name] !== undefined && (!Number.isSafeInteger(value[name]) || Object.is(value[name], -0) || value[name] < low || value[name] > high)) fail(name + ' is outside its integer budget');
  }
  if (!Array.isArray(value.recordings) || Object.getPrototypeOf(value.recordings) !== Array.prototype || !value.recordings.length || value.recordings.length > 256
    || Reflect.ownKeys(value.recordings).length !== value.recordings.length + 1) fail('Choose 1..256 dense recording references');
  const ids = new Set();
  for (let index = 0; index < value.recordings.length; index++) {
    const descriptor = Object.getOwnPropertyDescriptor(value.recordings, String(index));
    if (!descriptor || !Object.hasOwn(descriptor, 'value')) fail('Recording references must not contain accessors');
    const ref = descriptor.value; object(ref, ['id', 'sha256'], ['id', 'sha256']);
    if (typeof ref.id !== 'string' || !/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/.test(ref.id)
      || typeof ref.sha256 !== 'string' || !/^[a-f0-9]{64}$/.test(ref.sha256) || ids.has(ref.id)) fail('Invalid or duplicate recording reference');
    ids.add(ref.id);
  }
}
/** Reads committed native recordings. It never calls the debugger or releases ownership. */
export async function loadObservationWindows(mgr, cfg, input) { return readObservationWindows(mgr, cfg, input); }

/** Synchronous bounded immutable-input reader; no filesystem mutation or history scan. */
export function readObservationWindows(mgr, cfg, input, readBudget = null) {
  const remaining = max => readBudget ? Math.max(0, Math.min(max, 8*1024**2-readBudget.bytes)) : max;
  const account = count => { if(readBudget){readBudget.bytes+=count;if(readBudget.bytes>8*1024**2)throw Object.assign(new Error('Research evidence read budget exhausted'),{code:'EVIDENCE_READ_LIMIT'});} };
  validateObservationRequest(input); mgr.checkCancelled();
  if (!cfg || typeof (cfg.artifactDir || cfg.projectRoot) !== 'string') fail('Configured recording artifact root is required');
  const root = path.join(cfg.artifactDir || cfg.projectRoot, 'debug-traces');
  const store = new AnalysisArtifactReader(root), windows = [];
  let reportBytes = 0, traceBytes = 0, storeEventBytes = 0;
  try {
    for (const ref of input.recordings) {
      mgr.checkCancelled();
      const storedMetadata=store.metadata(ref.id);account(storedMetadata.bytes);
      const metadata = storedMetadata.result;
      if (metadata.recordSha256 !== ref.sha256) fail('Recording report SHA-256 differs');
      const { data: report } = readStableFile(path.join(store.directory('records'), ref.id + '.json'), remaining(Math.min(8 * 1024 * 1024, 16 * 1024 * 1024 - reportBytes)));
      reportBytes += report.length;account(report.length);
      if (hashBytes(report) !== ref.sha256) fail('Recording report bytes differ from the requested SHA-256');
      const record = JSON.parse(report.toString('utf8')), body = record.result;
      if (record.id !== ref.id || record.schemaVersion !== 1) fail('Recording report identity differs');
      if (record.kind !== 'debug-trace' || record.action !== 'record' || !body || body.targetSha256 !== input.target_sha256
        || !/^[a-f0-9]{64}$/.test(body.sha256 || '') || body.input?.ref !== 'sha256:' + body.sha256) fail('Recording kind, target or blob reference differs');
      const { data } = store.read(body.input.ref, remaining(1024 * 1024));
      account(data.length);traceBytes += data.length; if (traceBytes > 16 * 1024 * 1024) fail('Raw recording input exceeds 16 MiB');
      if (hashBytes(data) !== body.sha256 || body.bytes !== data.length) fail('Recording blob digest/size differs');
      let eventData, eventReference;
      if (body.storeEvents !== undefined) {
        const events = body.storeEvents;
        if (events?.schema !== 'ig5.native-store-events.v1' || typeof events.sha256 !== 'string' || !/^[a-f0-9]{64}$/.test(events.sha256)
          || events.input?.ref !== 'sha256:' + events.sha256 || events.actualWriteCausalityProved !== false || events.cpuWriteFootprintProved !== false)
          fail('Recording store-event reference/scope differs');
        eventData = store.read(events.input.ref, remaining(1024 * 1024 - data.length)).data;
        if (eventData.length !== events.bytes) fail('Recording store-event byte count differs');
        const parsed = readNativeStoreEvents(eventData, body, data);
        if (events.groups !== parsed.events.length || events.completeDecodedStoreGroups !== parsed.events.filter(event => event.completeDecodedStoreSet).length)
          fail('Recording store-event count/completeness differs');
        account(eventData.length);storeEventBytes += eventData.length;
        eventReference = { sha256: events.sha256, bytes: eventData.length, groups: events.groups, completeDecodedStoreGroups: events.completeDecodedStoreGroups };
      }
      if (traceBytes + storeEventBytes > 16 * 1024 * 1024) fail('Combined recording evidence exceeds 16 MiB');
      const summary = Object.fromEntries(['format', 'targetSha256', 'nativeTargetExecuted', 'finalSnapshotIncluded', 'finalSnapshotCurrent',
        'runId', 'threadId', 'startStopSeq', 'endStopSeq', 'instructionCount', 'confirmedStepStops', 'runtimeBase', 'entry', 'exit',
        'initialFlags', 'stopReason', 'sha256', 'bytes'].filter(key => Object.hasOwn(body, key)).map(key => [key, body[key]]));
      if (body.executionLocation !== undefined && (!body.executionLocation || typeof body.executionLocation !== 'object' || Array.isArray(body.executionLocation))) fail('Invalid recording execution location');
      const location = body.executionLocation ? Object.fromEntries(['kind', 'profileSha256', 'guestCID', 'bundleSha256', 'serverInstanceId', 'sessionId']
        .filter(key => Object.hasOwn(body.executionLocation, key)).map(key => [key, body.executionLocation[key]])) : null;
      for (const [key, value] of Object.entries(location || {})) {
        if (key === 'guestCID' ? !Number.isSafeInteger(value) || value < 1 || value > 0xffffffff
          : typeof value !== 'string' || !value || value.length > 256) fail('Unbounded recording location identity');
      }
      if (body.loadedImage && (typeof body.loadedImage.sha256 !== 'string' || !/^[a-f0-9]{64}$/.test(body.loadedImage.sha256))) fail('Invalid recorded image reference');
      windows.push({ source: { reportId: ref.id, reportSha256: ref.sha256,
        locationFingerprint: hashBytes(Buffer.from(JSON.stringify(location))),
        image: body.loadedImage ? { status: 'metadata-reference-only-blob-not-revalidated', sha256: body.loadedImage.sha256 ?? null } : null,
        ...(eventReference ? { storeEvents: eventReference } : {}) },
      summary, data, executionLocation: location, ...(eventData ? { storeEventData: eventData } : {}) });
    }
  } finally { /* The immutable reader owns no asynchronous handles or resources. */ }
  mgr.checkCancelled();
  return { windows, traceBytes };
}
export async function runObservationProfile(mgr, cfg, input) {
  const { windows, traceBytes } = await loadObservationWindows(mgr, cfg, input);
  const phaseContext = input.phase_context_ref ? vmContextEvidence(mgr.analysis.artifacts, { scope: { sha256: input.target_sha256 } }, input.phase_context_ref).request : null;
  if (phaseContext && traceBytes + windows.reduce((n,w) => n + (w.storeEventData?.length || 0), 0) + [phaseContext.root, ...phaseContext.parents].reduce((n,p) => n + p.bytes.length, 0) > 16 * 1024 ** 2) fail('Combined trace and context evidence exceeds 16 MiB');
  const result = await mgr.analysis.observeNative({ targetSha256: input.target_sha256, windows,
    maxInstructions: input.max_instructions, offset: input.offset, limit: input.limit, ...(input.phase_model === true ? { phaseModel: true, ...(phaseContext ? { phaseContext } : {}) } : {}) }, mgr.scope?.getStore()?.signal);
  mgr.checkCancelled();
  validateObservationResult(result, windows, input, traceBytes);
  if (input.phase_model === true) validatePhaseModel(result, windows, phaseContext);
  else if (result.phaseModel !== undefined) fail('Unrequested phase model');
  const artifacts = mgr.analysis.artifacts;
  const record = artifacts.save({ kind: 'vm-native-observations', action: 'observe', result }, { pretty: true, maxBytes: 4 * 1024 * 1024 });
  return { observations: { schema: result.schema, nativeTargetExecutedByThisRequest: false, businessAccepted: false,
    wholeFunctionCoverageProved: false, changesExecutionAuthority: false, liveExecutionInspected: false,
    architectureProved: false,
    reportId: record.id, reportPath: path.join(artifacts.root, 'records', record.id + '.json'),
    reportSha256: artifacts.metadata(record.id).result.recordSha256, identity: result.identity,
    ...(result.phaseModel ? { phaseModel: { ...result.phaseModel, ...(result.phaseModel.contextAnnotation ? { contextAnnotation: { ...result.phaseModel.contextAnnotation, segments: result.phaseModel.contextAnnotation.segments.slice(0, 4), totalSegments: result.phaseModel.contextAnnotation.segments.length, segmentsPreviewComplete: result.phaseModel.contextAnnotation.segments.length <= 4 } } : {}), groups: result.phaseModel.groups.slice(0, 2), responsePreviewComplete: result.phaseModel.groups.length <= 2 } } : {}),
    totals: result.totals, pagination: result.pagination, phase: 'unclassified',
    codeObservations: { ...result.codeObservations, changes: result.codeObservations.changes.slice(0, 4),
      responsePreviewComplete: result.codeObservations.changes.length <= 4 },
    windows: result.windows.slice(0, 8), windowPreviewComplete: result.windows.length <= 8,
    stopGroups: result.stopGroups.slice(0, 2), eventPreviewComplete: result.stopGroups.length <= 2,
    scope: result.scope, completePageAndWindowManifestSaved: true } };
}

/** Structural/source binding at the host boundary; not independent CPU semantics. */
function validateObservationResult(result, windows, input, traceBytes) {
  const groups = windows.reduce((sum, window) => sum + (window.summary.confirmedStepStops ?? window.summary.instructionCount), 0);
  const offset = input.offset ?? 0, pageSize = input.limit ?? 32;
  const returned = Math.min(pageSize, Math.max(0, groups - offset));
  const last = windows.at(-1).summary;
  if (result?.schema !== 'ig5-native-observations-v1' || result.targetSha256 !== input.target_sha256
    || result.nativeTargetExecutedByThisRequest !== false || result.businessAccepted !== false || result.wholeFunctionCoverageProved !== false
    || result.architectureProved !== false || result.changesExecutionAuthority !== false || result.liveExecutionInspected !== false
    || !Array.isArray(result.windows) || result.windows.length !== windows.length
    || result.windows.some((window, index) => window.reportId !== windows[index].source.reportId || window.reportSha256 !== windows[index].source.reportSha256
      || window.locationFingerprint !== windows[index].source.locationFingerprint || window.traceSha256 !== windows[index].summary.sha256
      || window.bytes !== windows[index].data.length || window.instructionCount !== windows[index].summary.instructionCount
      || window.confirmedStopGroups !== (windows[index].summary.confirmedStepStops ?? windows[index].summary.instructionCount)
      || window.startStopSeq !== windows[index].summary.startStopSeq || window.endStopSeq !== windows[index].summary.endStopSeq
      || window.moduleLoadEpoch !== null || window.memoryEpoch !== null || window.phase !== 'unclassified'
      || JSON.stringify(window.storeEvents) !== JSON.stringify(windows[index].source.storeEvents)
      || JSON.stringify(window.image) !== JSON.stringify(windows[index].source.image))
    || !Array.isArray(result.stopGroups) || result.stopGroups.length !== returned
    || result.pagination?.offset !== offset || result.pagination?.limit !== pageSize
    || result.pagination?.returned !== returned || result.pagination?.entireInputValidated !== true
    || result.pagination?.nextOffset !== (offset + returned < groups ? offset + returned : null)
    || result.pagination?.pageIsWholeRecording !== (offset === 0 && returned === groups)
    || result.identity?.runId !== last.runId || result.identity?.threadId !== last.threadId
    || result.identity?.runtimeBase !== '0x' + BigInt(last.runtimeBase).toString(16)
    || result.identity?.moduleLoadEpoch !== null || result.identity?.addressSpaceAttested !== false
    || result.totals?.windows !== windows.length || result.totals?.stopGroups !== groups
    || result.totals?.instructions !== windows.reduce((sum, window) => sum + window.summary.instructionCount, 0)
    || result.totals?.rawBytes !== traceBytes) fail('Observation worker result scope/identity differs');
  const hex = value => typeof value === 'string' && /^0x[0-9a-f]{1,16}$/.test(value);
  const gprs = 'rax rbx rcx rdx rdi rsi rbp rsp r8 r9 r10 r11 r12 r13 r14 r15'.split(' ');
  const state = value => value && value.assurance === 'recorded-observation-not-predicted-state'
    && hex(value.rip) && hex(value.flags) && BigInt(value.flags) <= 0xffffffffn
    && Number.isSafeInteger(value.sourceLine) && value.sourceLine >= 2
    && value.gprs && Object.keys(value.gprs).length === 16 && gprs.every(key => hex(value.gprs[key]));
  const lines = windows.map(window => Buffer.from(window.data).toString('ascii').split('\n'));
  const events = windows.map(window => window.storeEventData ? readNativeStoreEvents(window.storeEventData, window.summary, window.data) : null);
  const eventBytes = windows.reduce((sum, window) => sum + (window.storeEventData?.length || 0), 0);
  if (eventBytes ? result.totals.storeEventBytes !== eventBytes || result.totals.evidenceBytes !== traceBytes + eventBytes
    : result.totals.storeEventBytes !== undefined || result.totals.evidenceBytes !== undefined) fail('Observation worker store-event byte budget differs');
  let base = 0, index = 0;
  for (let n = 0; n < result.stopGroups.length; n++) {
    const group = result.stopGroups[n], ordinal = offset + n;
    while (ordinal >= base + (windows[index].summary.confirmedStepStops ?? windows[index].summary.instructionCount)) {
      base += windows[index].summary.confirmedStepStops ?? windows[index].summary.instructionCount; index++;
    }
    const window = windows[index], first = window.summary.startStopSeq + ordinal - base;
    if (group.groupIndex !== ordinal || group.recordingId !== window.source.reportId || group.phase !== 'unclassified'
      || group.pauseSequence?.before !== first || group.pauseSequence?.after !== first + 1 || group.pauseSequence?.individuallyAttested !== false
      || !state(group.before) || !state(group.after) || group.before.sourceLine >= lines[index].length || group.after.sourceLine >= lines[index].length
      || !Array.isArray(group.instructions) || group.instructions.length < 1 || group.instructions.length > 2
      || group.intermediateStateAvailable !== (group.instructions.length === 1)
      || group.memoryWrites?.effectsNotInferredFromReads !== true
      || !Array.isArray(group.memoryReads) || group.memoryReads.length > 8) fail('Observation worker stop-group shape differs');
    const expectedEvent = events[index]?.events[ordinal - base];
    if (expectedEvent) {
      const writes = group.memoryWrites;
      if (writes.status !== 'decoded-locations-observed-across-stop' || writes.cpuWriteFootprintProved !== false
        || writes.storeOrder !== events[index].storeOrder || writes.sourceBlobSha256 !== window.source.storeEvents.sha256
        || Object.keys(expectedEvent).some(key => JSON.stringify(writes[key]) !== JSON.stringify(expectedEvent[key])))
        fail('Observation worker store-event group differs');
    } else if (group.memoryWrites?.status !== 'not-recorded-by-this-format') fail('Observation worker invented store events');
    for (let k = 0; k < group.instructions.length; k++) {
      const insn = group.instructions[k];
      const row = Number.isSafeInteger(insn.sourceLine) ? lines[index][insn.sourceLine - 1]?.split(':') : null;
      if (!hex(insn.pc) || typeof insn.bytes !== 'string' || !/^(?:[a-f0-9]{2}){1,15}$/.test(insn.bytes)
        || !row || row.length !== 4 || row[0] !== (k ? 'c' : 'i') || BigInt(row[1]) !== BigInt(insn.pc)
        || row[2] !== String(insn.bytes.length / 2) || row[3].toLowerCase() !== insn.bytes
        || insn.codeObservationSha256 !== hashBytes(Buffer.from(insn.pc + ':' + insn.bytes, 'ascii'))
        || insn.beforeStateAvailable !== (k === 0) || (k && insn.continuationSemanticsValidated !== false)) fail('Observation instruction differs from recorded source row');
    }
    for (const read of group.memoryReads) {
      const row = Number.isSafeInteger(read.sourceLine) ? lines[index][read.sourceLine - 1]?.split(':') : null;
      if (!hex(read.address) || ![1, 2, 4, 8, 16, 32, 64].includes(read.bytes)
        || typeof read.littleEndianHex !== 'string' || !new RegExp('^[a-f0-9]{' + read.bytes * 2 + '}$').test(read.littleEndianHex)
        || !row || row.length !== 4 || row[0] !== 'mr' || BigInt(row[1]) !== BigInt(read.address) || row[2] !== String(read.bytes)
        || BigInt('0x' + read.littleEndianHex.match(/../g).reverse().join('')) !== BigInt(row[3])
        || read.meaning !== 'observed-memory-read-not-bytecode-or-input-classification') fail('Observation memory-read shape differs');
    }
  }
  const code = result.codeObservations;
  if (!code || !Number.isSafeInteger(code.trackedAddresses) || code.trackedAddresses < 1 || code.trackedAddresses > 4096
    || typeof code.trackingComplete !== 'boolean' || code.changeCountIsLowerBound !== !code.trackingComplete
    || !Number.isSafeInteger(code.observedChanges) || code.observedChanges < 0 || code.observedChanges > result.totals.instructions
    || !Array.isArray(code.changes) || code.changes.length !== Math.min(64, code.observedChanges)
    || code.changesPreviewComplete !== (code.changes.length === code.observedChanges) || code.globalCodeEpochKnown !== false) fail('Observation code-tracking scope differs');
}
