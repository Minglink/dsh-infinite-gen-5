import path from 'node:path';
import { createHash } from 'node:crypto';
import {
  SUPPORTED_DELIVERABLE_KINDS,
  SUPPORTED_OBSERVATIONS,
  validateOutputSpec,
  validateExecutableRule,
  hashExecutableCandidate,
  hashOutputSpec,
  canonicalPathKey,
  deriveCanonicalScenarioInput,
  parsePePreferredImageBase,
  evaluateBoundedTransform,
  extractObservedOutputHex,
} from './investigation_verifier.js';
import {
  inspectApkNativeLibraryMembership,
  inspectElfJniCharacteristics,
} from './native_android_provider.js';

const STATIC_TOOLS = new Set([
  'ig5_open', 'ig5_funcs', 'ig5_strings', 'ig5_decompile', 'ig5_bytes',
  'ig5_cfg', 'ig5_xrefs', 'ig5_calls', 'ig5_ir', 'ig5_slice', 'ig5_struct',
  'ig5_listing', 'ig5_fingerprint', 'ig5_package',
]);
const DYNAMIC_TOOLS = new Set(['ig5_dbg', 'ig5_emulate', 'ig5_capture', 'ig5_api_trace', 'ig5_app_observe']);

export function verifyDeliverableAgainstArtifacts(deliv, rootTask, mgr) {
  const missing = [];
  const verifiedReceipts = [];

  if (!SUPPORTED_DELIVERABLE_KINDS.has(deliv.kind)) {
    return {
      deliverableId: deliv.id,
      kind: deliv.kind,
      status: 'unsupported',
      missing: [`unsupported-deliverable-kind(${deliv.kind})`],
      verifiedReceipts,
    };
  }

  const reqObs = Array.isArray(deliv.requiredObservations) ? deliv.requiredObservations : [];
  if (reqObs.length === 0) {
    return {
      deliverableId: deliv.id,
      kind: deliv.kind,
      status: 'unsupported',
      missing: ['empty-required-observations'],
      verifiedReceipts,
    };
  }
  const unsupportedObs = reqObs.filter(o => !SUPPORTED_OBSERVATIONS.has(o));
  if (unsupportedObs.length > 0) {
    return {
      deliverableId: deliv.id,
      kind: deliv.kind,
      status: 'unsupported',
      missing: unsupportedObs.map(o => `unsupported-observation-obligation(${o})`),
      verifiedReceipts,
    };
  }

  const unresolvedCx = rootTask.counterexamples.filter(c => c.status === 'unresolved');
  if (unresolvedCx.length > 0) {
    missing.push(`unresolved-counterexamples(${unresolvedCx.map(c => c.counterexampleId).join(',')})`);
  }

  const cand = deliv.candidateExplanation;
  if (!cand) {
    missing.push('candidate-explanation-not-submitted');
    return {
      deliverableId: deliv.id,
      kind: deliv.kind,
      status: rootTask.receipts.length > 0 ? 'partial' : 'unverified',
      missing,
      verifiedReceipts,
    };
  }
  if (deliv.contractRevisedRequiresUpdate) {
    missing.push('goal-contract-revised-requires-candidate-reverification');
  }
  if (cand.needsReassessment) {
    missing.push('candidate-explanation-needs-reassessment-after-refutation');
  }

  // Validate executable candidate representation and fixed outputSpec
  let outputSpec = null;
  let outputSpecDigest = null;
  let executableRule = null;
  if (!cand.outputSpec) {
    missing.push('missing-output-spec');
  } else if (!cand.executableRule) {
    missing.push('missing-executable-candidate-rule');
  } else {
    try {
      outputSpec = validateOutputSpec(cand.outputSpec);
      outputSpecDigest = hashOutputSpec(outputSpec);
      executableRule = validateExecutableRule(cand.executableRule, outputSpec);
      const expectedSha = hashExecutableCandidate(executableRule, outputSpec);
      if (cand.ruleSha256 && cand.ruleSha256 !== expectedSha) {
        missing.push('candidate-rule-sha256-mismatch');
      }
      if (cand.outputSpecDigest && cand.outputSpecDigest !== outputSpecDigest) {
        missing.push('candidate-output-spec-digest-mismatch');
      }
      if (cand.ruleBlobRef && mgr.analysis?.artifacts?.read) {
        const { data } = mgr.analysis.artifacts.read(cand.ruleBlobRef);
        const blobSha = createHash('sha256').update(data).digest('hex');
        if (blobSha !== expectedSha) missing.push('candidate-rule-artifact-tampered');
      }
    } catch (err) {
      missing.push(`invalid-executable-candidate(${err.code || 'INVALID'})`);
    }
  }

  if (reqObs.includes('static-locate')) {
    const componentHashes = new Set(rootTask.components.map(c => c.sha256));
    const componentPaths = new Set(rootTask.components.map(c => canonicalPathKey(c.path)).filter(Boolean));
    const staticIds = cand.staticReceiptIds?.length
      ? cand.staticReceiptIds
      : rootTask.receipts.filter(r => STATIC_TOOLS.has(r.tool) && r.outcome === 'success').map(r => r.reportId);
    let staticVerified = false;
    for (const id of staticIds) {
      try {
        const rec = mgr.analysis.artifacts.get(id);
        const evSha = rec?.result?.runtimeIdentity?.evidence?.sha256 || rec?.result?.replayOutput?._ig5?.sha256 || rec?.result?.replayOutput?.sha256 || rec?.result?.replayOutput?.input?.sha256 || null;
        const recTarget = rec?.result?.cleanArgsSummary?.target || rec?.result?.cleanArgsSummary?.path || rec?.result?.replayOutput?.target || rec?.result?.replayOutput?.association?.target || rec?.result?.replayOutput?.targetAppPath || null;
        const hashAligned = !evSha || componentHashes.size === 0 || componentHashes.has(evSha);
        const pathAligned = !recTarget || componentPaths.size === 0 || componentPaths.has(canonicalPathKey(recTarget));
        if (rec?.outcome === 'success' && STATIC_TOOLS.has(rec.tool) && hashAligned && pathAligned) {
          staticVerified = true;
          verifiedReceipts.push({ reportId: id, role: 'static-locate', tool: rec.tool });
          break;
        }
      } catch {
        // Unreadable or tampered artifact does not satisfy verification.
      }
    }
    if (!staticVerified) missing.push('missing-verified-static-receipt');
  }

  // io-transform ALWAYS requires verified dynamic runtime observations bound to real scenarios, launch witnesses, & runs
  const vectors = Array.isArray(cand.testVectors) ? cand.testVectors : [];
  const usedReceipts = new Set();
  const usedRunIds = new Set();
  const usedExpIds = new Set();
  const usedScenarioDigests = new Set();
  const distinctSystemInputs = new Set();
  const nonHoldoutInputs = new Set();
  const verifiedHoldoutInputs = new Set();
  let verifiedVectorCount = 0;

  for (const tv of vectors) {
    if (usedReceipts.has(tv.receiptId)) {
      missing.push(`duplicate-receipt-in-test-vectors(${tv.receiptId})`);
      continue;
    }
    const summaryReceipt = rootTask.receipts.find(r => r.reportId === tv.receiptId);
    if (!summaryReceipt || summaryReceipt.outcome !== 'success') {
      missing.push(`unlinked-or-failed-system-receipt(${tv.receiptId})`);
      continue;
    }
    const exp = rootTask.experiments.find(e => e.expId === summaryReceipt.expId);
    if (!exp || exp.mode !== 'explicit' || !exp.scenarioSnapshot) {
      missing.push(`receipt-not-bound-to-explicit-scenario-experiment(${tv.receiptId})`);
      continue;
    }
    const snap = exp.scenarioSnapshot;
    const comp = rootTask.components.find(c => c.componentId === snap.componentId);
    if (!comp || comp.sha256 !== snap.targetSha256 || canonicalPathKey(comp.path) !== canonicalPathKey(snap.targetPath)) {
      missing.push(`component-hash-mismatch-for-scenario(${snap.scenarioId})`);
      continue;
    }

    let vectorValid = true;
    const actualIsHoldout = Boolean(snap.isHoldout && exp.kind === 'holdout-verify');
    if (snap.verifiableForDeliverable === false) {
      missing.push(`exploratory-unverified-input-experiment-cannot-verify-deliverable(${exp.expId})`);
      vectorValid = false;
    }
    if (tv.scenarioId && tv.scenarioId !== snap.scenarioId) {
      missing.push(`vector-scenario-mismatch(claimed=${tv.scenarioId},actual=${snap.scenarioId})`);
      vectorValid = false;
    }
    const isPlannedFile = snap.inputProvenanceState === 'planned-awaiting-materialization';
    const expectedInputHex = snap.inputProvenanceVerified
      ? snap.inputHex
      : (isPlannedFile ? snap.plannedInputHex : null);
    const expectedInputSha256 = snap.inputProvenanceVerified
      ? snap.inputSha256
      : (isPlannedFile ? snap.plannedInputSha256 : null);
    const expectedBlobRef = snap.inputBlobRef || (isPlannedFile ? snap.plannedInputBlobRef : null);

    if ((!snap.inputProvenanceVerified && !isPlannedFile) || !expectedInputHex || expectedInputHex.length % 2 !== 0 || !/^[0-9a-f]+$/i.test(expectedInputHex)) {
      missing.push(`unverified-input-provenance(${snap.scenarioId}:${snap.inputProvenanceReason || 'missing-channel-binding'})`);
      vectorValid = false;
    } else {
      if (expectedBlobRef && mgr.analysis?.artifacts?.read) {
        try {
          const readFn = snap.sensitiveInput && typeof mgr.analysis.artifacts.readSensitive === 'function'
            ? mgr.analysis.artifacts.readSensitive.bind(mgr.analysis.artifacts)
            : mgr.analysis.artifacts.read.bind(mgr.analysis.artifacts);
          const { data } = readFn(expectedBlobRef);
          if (createHash('sha256').update(data).digest('hex') !== expectedInputSha256) {
            missing.push(`input-artifact-tampered(${snap.scenarioId})`);
            vectorValid = false;
          }
        } catch (err) {
          missing.push(err?.code === 'ARTIFACT_CHANGED'
            ? `input-artifact-tampered(${snap.scenarioId})`
            : `input-artifact-unreadable(${snap.scenarioId})`);
          vectorValid = false;
        }
      }
      if (tv.inputHex !== undefined && tv.inputHex !== expectedInputHex) {
        missing.push(`vector-input-mismatch(claimed=${tv.inputHex},actual=${expectedInputHex})`);
        vectorValid = false;
      }
    }
    if (tv.isHoldout !== undefined && Boolean(tv.isHoldout) !== actualIsHoldout) {
      missing.push(`vector-holdout-label-mismatch(claimed=${tv.isHoldout},actual=${actualIsHoldout})`);
      vectorValid = false;
    }

    if (usedExpIds.has(exp.expId)) {
      missing.push(`duplicate-experiment-across-vectors(${exp.expId})`);
      vectorValid = false;
    }
    if (usedScenarioDigests.has(snap.scenarioDigest)) {
      missing.push(`duplicate-scenario-across-vectors(${snap.scenarioId})`);
      vectorValid = false;
    }

    let rec;
    try {
      rec = mgr.analysis.artifacts.get(tv.receiptId);
    } catch {
      missing.push(`unreadable-artifact-receipt(${tv.receiptId})`);
      continue;
    }
    if (rec?.outcome !== 'success' || !DYNAMIC_TOOLS.has(rec.tool)) {
      missing.push(`non-dynamic-or-failed-receipt(${tv.receiptId})`);
      continue;
    }

    let recOut = rec.result?.replayOutput;
    if (recOut === undefined && rec.result?.replayBlobRef && mgr.analysis?.artifacts?.read) {
      try {
        recOut = JSON.parse(mgr.analysis.artifacts.read(rec.result.replayBlobRef).data.toString('utf8'));
      } catch {
        recOut = {};
      }
    }
    recOut = recOut || {};
    const recWithOut = rec.result?.replayOutput !== undefined
      ? rec
      : { ...rec, result: { ...(rec.result || {}), replayOutput: recOut } };

    if (rec.result?.research?.id && rec.result.research.id !== rootTask.rootId) {
      missing.push(`cross-root-receipt-rejected(${tv.receiptId})`);
      vectorValid = false;
    }
    if (rec.result?.research?.exp && rec.result.research.exp !== exp.expId) {
      missing.push(`cross-experiment-receipt-rejected(${tv.receiptId})`);
      vectorValid = false;
    }

    // Bind dynamic receipt directly to the frozen component target path & SHA-256!
    const recTarget = rec.result?.cleanArgsSummary?.target
      || rec.result?.cleanArgsSummary?.path
      || recOut._ig5?.target
      || recOut.target
      || null;
    if (!recTarget || canonicalPathKey(recTarget) !== canonicalPathKey(snap.targetPath)) {
      missing.push(`receipt-target-path-mismatch(${tv.caseId}:expected=${snap.targetPath},actual=${recTarget || 'absent'})`);
      vectorValid = false;
    }
    const recSha = rec.result?.runtimeIdentity?.evidence?.sha256
      || recOut._ig5?.sha256
      || recOut.sha256
      || recOut.apkSha256
      || null;
    if (recSha && recSha !== snap.targetSha256) {
      missing.push(`receipt-target-sha256-mismatch(${tv.caseId}:expected=${snap.targetSha256},actual=${recSha})`);
      vectorValid = false;
    }

    const runId = rec.result?.runtimeIdentity?.runId || recOut.runId || null;
    let startSummary = null;
    let startExpForHoldout = null;
    if (rec.tool === 'ig5_dbg') {
      if (!runId) {
        missing.push(`missing-debugger-run-id(${tv.receiptId})`);
        vectorValid = false;
      } else if (usedRunIds.has(runId)) {
        missing.push(`duplicate-debugger-run-id(${runId})`);
        vectorValid = false;
      }
      // Mandatory verified launch witness (`ig5_dbg:start`) in the same experiment or an earlier explicit experiment
      // on the exact same scenario & live runId within this investigation (architecture §8: a single debugger run may span short experiments).
      startSummary = rootTask.receipts.find(r => {
        if (r.action !== 'ig5_dbg:start' || r.outcome !== 'success') return false;
        if (r.expId === exp.expId) return true;
        const rRunId = r.runtimeIdentity?.runId || r.observedMetrics?.runId || null;
        if (!runId || rRunId !== runId) return false;
        const startExp = rootTask.experiments.find(e => e.expId === r.expId);
        return Boolean(
          startExp
          && startExp.mode === 'explicit'
          && startExp.scenarioSnapshot?.scenarioDigest === snap.scenarioDigest
          && startExp.scenarioSnapshot?.targetSha256 === snap.targetSha256
          && canonicalPathKey(startExp.scenarioSnapshot?.targetPath) === canonicalPathKey(snap.targetPath),
        );
      });
      startExpForHoldout = startSummary
        ? rootTask.experiments.find(e => e.expId === startSummary.expId)
        : null;
      if (!startSummary) {
        missing.push(`missing-verified-launch-witness(${exp.expId})`);
        vectorValid = false;
      } else {
        let startRec = null;
        try {
          startRec = mgr.analysis.artifacts.get(startSummary.reportId);
        } catch {
          missing.push(`unreadable-launch-witness(${startSummary.reportId})`);
          vectorValid = false;
        }
        if (startRec) {
          const startTarget = startRec.result?.cleanArgsSummary?.target || startRec.result?.replayOutput?._ig5?.target || null;
          if (!startTarget || canonicalPathKey(startTarget) !== canonicalPathKey(snap.targetPath)) {
            missing.push(`launch-witness-target-mismatch(${exp.expId})`);
            vectorValid = false;
          }
          const startSha = startRec.result?.runtimeIdentity?.evidence?.sha256
            || startRec.result?.replayOutput?._ig5?.sha256
            || startRec.result?.replayOutput?.sha256
            || null;
          const verifiedRunSha = recSha || startSha;
          if (!verifiedRunSha) {
            missing.push(`missing-target-sha256-evidence(${exp.expId})`);
            vectorValid = false;
          } else if (verifiedRunSha !== snap.targetSha256 || (startSha && startSha !== snap.targetSha256)) {
            missing.push(`launch-witness-sha256-mismatch(${exp.expId})`);
            vectorValid = false;
          }
          const startRunId = startRec.result?.runtimeIdentity?.runId || startRec.result?.replayOutput?.runId || null;
          if (!startRunId || (runId && startRunId !== runId)) {
            missing.push(`start-run-id-mismatch(${exp.expId})`);
            vectorValid = false;
          }
          const launchArgv = startRec.result?.runtimeIdentity?.launchScenario?.argv ?? startRec.result?.replayOutput?.launchScenario?.argv;
          const launchCwd = startRec.result?.runtimeIdentity?.launchScenario?.cwd ?? startRec.result?.replayOutput?.launchScenario?.cwd;
          if (!Array.isArray(launchArgv) || JSON.stringify(launchArgv) !== JSON.stringify(snap.args)) {
            missing.push(`start-argv-mismatch(${exp.expId})`);
            vectorValid = false;
          }
          if (snap.cwd && launchCwd && canonicalPathKey(launchCwd) !== canonicalPathKey(snap.cwd)) {
            missing.push(`start-cwd-mismatch(${exp.expId})`);
            vectorValid = false;
          }
          if (startSummary.receiptSeq !== undefined && summaryReceipt.receiptSeq !== undefined && startSummary.receiptSeq >= summaryReceipt.receiptSeq) {
            missing.push(`observation-precedes-launch-witness(${exp.expId})`);
            vectorValid = false;
          }
          if (Array.isArray(launchArgv) && snap.inputChannel && expectedInputHex) {
            const liveDerived = deriveCanonicalScenarioInput({
              args: launchArgv,
              cwd: launchCwd || snap.cwd,
              inputSpec: { ...snap.inputChannel, sampleHex: expectedInputHex },
            });
            const startWitness = startRec.result?.executionInputWitness || null;
            const postCleanupWitnessOk = liveDerived.provenanceState === 'planned-awaiting-materialization'
              && startWitness
              && startWitness.inputSha256 === expectedInputSha256;
            if (!postCleanupWitnessOk && (!liveDerived.verified || liveDerived.canonicalInputHex !== expectedInputHex || liveDerived.canonicalInputSha256 !== expectedInputSha256)) {
              missing.push(`launch-channel-input-mismatch(${exp.expId})`);
              vectorValid = false;
            }
          }
        }
      }
    }

    // Verify immutable execution-time input witness (`executionInputWitness`) for planned-file and channel-bound runs!
    const execWitness = rec.result?.executionInputWitness
      || (startSummary && (() => { try { return mgr.analysis.artifacts.get(startSummary.reportId)?.result?.executionInputWitness || null; } catch { return null; } })())
      || null;
    if (isPlannedFile && !execWitness) {
      missing.push(`missing-execution-input-witness-for-planned-file(${tv.caseId})`);
      vectorValid = false;
    }
    if (execWitness && expectedInputSha256) {
      if (execWitness.contractRevision !== undefined && execWitness.contractRevision !== null
        && exp.boundContractRevision !== undefined && execWitness.contractRevision !== exp.boundContractRevision) {
        missing.push(`execution-witness-contract-revision-mismatch(${tv.caseId})`);
        vectorValid = false;
      }
      if (execWitness.witnessBlobRef && mgr.analysis?.artifacts?.read) {
        try {
          const readFn = execWitness.sensitiveBlob && typeof mgr.analysis.artifacts.readSensitive === 'function'
            ? mgr.analysis.artifacts.readSensitive.bind(mgr.analysis.artifacts)
            : mgr.analysis.artifacts.read.bind(mgr.analysis.artifacts);
          const { data: wBytes } = readFn(execWitness.witnessBlobRef);
          const wSha = createHash('sha256').update(wBytes).digest('hex');
          if (wSha !== execWitness.inputSha256) {
            missing.push(`execution-input-witness-tampered(${tv.caseId})`);
            vectorValid = false;
          } else if (wSha !== expectedInputSha256 || wBytes.toString('hex') !== expectedInputHex) {
            missing.push(`execution-input-contradicts-scenario(${tv.caseId}:expected=${expectedInputSha256},actual=${wSha})`);
            vectorValid = false;
          }
        } catch (err) {
          missing.push(err?.code === 'ARTIFACT_CHANGED'
            ? `execution-input-witness-tampered(${tv.caseId})`
            : `execution-input-witness-unreadable(${tv.caseId})`);
          vectorValid = false;
        }
      } else if (execWitness.inputSha256 !== expectedInputSha256) {
        missing.push(`execution-input-contradicts-scenario(${tv.caseId})`);
        vectorValid = false;
      }
      if (snap.inputChannel?.kind && execWitness.channel?.kind && execWitness.channel.kind !== snap.inputChannel.kind) {
        missing.push(`execution-channel-kind-mismatch(${tv.caseId}:expected=${snap.inputChannel.kind},actual=${execWitness.channel.kind})`);
        vectorValid = false;
      }
      if (snap.inputChannel?.kind === 'file' && snap.inputChannel?.filePath && execWitness.channel?.filePath) {
        if (canonicalPathKey(execWitness.channel.filePath) !== canonicalPathKey(snap.inputChannel.filePath)) {
          missing.push(`execution-channel-filepath-mismatch(${tv.caseId})`);
          vectorValid = false;
        }
      }
    }

    if (deliv.kind === 'dll-host-transform') {
      const dllComps = rootTask.components.filter(c => c.role === 'dll');
      if (dllComps.length === 0) {
        missing.push('missing-registered-dll-component');
        vectorValid = false;
      } else if (rec.tool !== 'ig5_dbg' || outputSpec?.kind !== 'module-memory') {
        missing.push(`dll-host-transform-requires-dbg-module-memory(${tv.caseId})`);
        vectorValid = false;
      } else {
        const recCtx = recOut.context || rec.result?.runtimeIdentity?.context || {};
        const matchedDll = dllComps.find(c => path.basename(c.path).toLowerCase() === outputSpec.module);
        if (!matchedDll) {
          missing.push(`unregistered-dll-module(${outputSpec.module})`);
          vectorValid = false;
        } else if (!recCtx.moduleSha256 || recCtx.moduleSha256.toLowerCase() !== matchedDll.sha256.toLowerCase()) {
          missing.push(`loaded-dll-sha256-mismatch(${tv.caseId}:expected=${matchedDll.sha256},actual=${recCtx.moduleSha256 || 'absent'})`);
          vectorValid = false;
        }
        if (reqObs.includes('aslr-module-rebasing')) {
          const parsedPrefBase = matchedDll?.path ? parsePePreferredImageBase(matchedDll.path) : null;
          let actualBaseBig = null;
          let prefBaseBig = null;
          try { if (recCtx.moduleBase) actualBaseBig = BigInt(recCtx.moduleBase); } catch { actualBaseBig = null; }
          try { if (parsedPrefBase) prefBaseBig = BigInt(parsedPrefBase); } catch { prefBaseBig = null; }
          if (actualBaseBig === null || prefBaseBig === null || actualBaseBig === prefBaseBig) {
            missing.push(`aslr-rebasing-not-observed(${tv.caseId}:moduleBase=${recCtx.moduleBase || 'none'},preferredBase=${parsedPrefBase || 'unparsed'})`);
            vectorValid = false;
          }
        }
      }
    }

    const isElectronChain = deliv.kind === 'electron-native-chain'
      || (deliv.kind === 'structured-frame-transform' && rootTask.components.some(c => c.role === 'electron-app'));
    if (isElectronChain) {
      const helperComps = rootTask.components.filter(c => c.role === 'helper-pe');
      if (helperComps.length === 0) {
        missing.push('missing-registered-helper-pe-component');
        vectorValid = false;
      } else if (rec.tool !== 'ig5_app_observe' || recOut.action !== 'electron_scenario') {
        missing.push(`electron-chain-requires-parent-electron-scenario(${tv.caseId})`);
        vectorValid = false;
      } else {
        if (!runId || usedRunIds.has(runId)) {
          missing.push(`missing-or-duplicate-electron-run-id(${tv.caseId})`);
          vectorValid = false;
        }
        if (recOut.observerLogIntegrity && recOut.observerLogIntegrity !== 'verified') {
          missing.push(`electron-observer-log-integrity-unverified(${tv.caseId}:${recOut.observerLogIntegrity})`);
          vectorValid = false;
        }
        if ((reqObs.includes('non-cooperative-ui-trigger') || deliv.nonCooperativeRequired) && recOut.fixtureOnlyProtocol === true) {
          missing.push(`cooperative-fixture-protocol-disallowed(${tv.caseId})`);
          vectorValid = false;
        }
        if (reqObs.includes('non-cooperative-ui-trigger')) {
          const hasClickStep = Array.isArray(recOut.uiClickWitness?.stepWitnesses)
            && recOut.uiClickWitness.stepWitnesses.some(sw => sw.op === 'click' && sw.boundingRect);
          if (recOut.triggerMode !== 'ui-click' || recOut.uiClickWitness?.ok !== true || !hasClickStep) {
            missing.push(`missing-verified-browserwindow-ui-click-witness(${tv.caseId})`);
            vectorValid = false;
          }
        }
        if (recOut.observedInputHex !== expectedInputHex) {
          missing.push(`electron-ipc-input-mismatch(${tv.caseId}:expected=${expectedInputHex},actual=${recOut.observedInputHex})`);
          vectorValid = false;
        }
        const edges = Array.isArray(recOut.handoffEdges) ? recOut.handoffEdges : [];
        const hasKernelLineage = Array.isArray(recOut.verifiedProcessLineage);
        const validEdge = edges.find(ed => ed.exitCode === 0
          && (!hasKernelLineage || ed.kernelProcessVerified === true)
          && helperComps.some(hc => hc.sha256 === ed.executableSha256));
        if (!validEdge) {
          missing.push(`missing-verified-parent-to-helper-handoff(${tv.caseId}:${recOut.observationDiagnosis || 'no-kernel-verified-helper-sha'})`);
          vectorValid = false;
        }
        if (recOut.cleanup?.cleanupVerified !== true) {
          missing.push(`electron-process-tree-cleanup-unverified(${tv.caseId})`);
          vectorValid = false;
        }
      }
    }

    const isProcessChain = deliv.kind === 'process-chain-transform'
      || (deliv.kind === 'structured-frame-transform' && !isElectronChain && rootTask.components.some(c => ['worker-pe', 'broker-pe'].includes(c.role)));
    if (isProcessChain) {
      const workerComps = rootTask.components.filter(c => c.role === 'worker-pe');
      const brokerComps = rootTask.components.filter(c => c.role === 'broker-pe');
      const requiredSubComps = [...brokerComps, ...workerComps];
      if (workerComps.length < 2 && deliv.kind === 'process-chain-transform') {
        missing.push('process-chain-requires-at-least-2-worker-components');
        vectorValid = false;
      } else if (requiredSubComps.length < 1) {
        missing.push('structured-process-chain-requires-worker-component');
        vectorValid = false;
      } else if (rec.tool !== 'ig5_app_observe' || recOut.action !== 'process_chain_scenario') {
        missing.push(`process-chain-requires-chain-scenario-receipt(${tv.caseId})`);
        vectorValid = false;
      } else {
        if (!runId || usedRunIds.has(runId)) {
          missing.push(`missing-or-duplicate-chain-run-id(${tv.caseId})`);
          vectorValid = false;
        }
        if ((reqObs.includes('non-cooperative-ui-trigger') || deliv.nonCooperativeRequired) && recOut.fixtureOnlyProtocol === true) {
          missing.push(`cooperative-fixture-protocol-disallowed(${tv.caseId})`);
          vectorValid = false;
        }
        if (recOut.inputChannelWitness?.channelBindingConflict) {
          missing.push(`process-chain-channel-binding-conflict(${tv.caseId}:${recOut.inputChannelWitness.channelBindingConflict})`);
          vectorValid = false;
        }
        if (recOut.observedInputHex !== expectedInputHex) {
          missing.push(`process-chain-input-mismatch(${tv.caseId}:expected=${expectedInputHex},actual=${recOut.observedInputHex})`);
          vectorValid = false;
        }
        // Strict kernel-observed lineage check: NEVER fall back to applicationReported stdout JSON!
        const lineage = Array.isArray(recOut.verifiedProcessLineage) ? recOut.verifiedProcessLineage : null;
        if (!lineage) {
          missing.push(`process-chain-missing-kernel-verified-lineage(${tv.caseId})`);
          vectorValid = false;
        } else {
          const observedPids = new Set(lineage.map(inst => Number(inst.pid)).filter(n => Number.isSafeInteger(n)));
          const entryInst = lineage.find(inst => inst.sha256 === snap.targetSha256 && inst.creationIdentity);
          if (!entryInst) {
            missing.push(`process-chain-entry-creation-identity-unverified(${tv.caseId})`);
            vectorValid = false;
          }
          for (const reqComp of requiredSubComps) {
            const matchedInst = lineage.find(inst => inst.sha256 === reqComp.sha256
              && inst.relationOrigin === 'win32-job-kernel-observed'
              && Boolean(inst.creationIdentity)
              && observedPids.has(Number(inst.parentPid))
              && inst.exitCode === 0);
            if (!matchedInst) {
              missing.push(`missing-system-observed-worker-execution(${tv.caseId}:${reqComp.componentId})`);
              vectorValid = false;
            }
          }
        }
        if (recOut.cleanup?.cleanupVerified !== true) {
          missing.push(`process-chain-cleanup-unverified(${tv.caseId})`);
          vectorValid = false;
        }
      }
    }

    if (deliv.kind === 'apk-jni-chain') {
      const apkComp = rootTask.components.find(c => c.role === 'apk');
      const jniComp = rootTask.components.find(c => c.role === 'jni-so');
      if (!apkComp || !jniComp) {
        missing.push('apk-jni-chain-requires-both-apk-and-jni-so-components');
        vectorValid = false;
      } else {
        const hasApkStatic = rootTask.receipts.some(r => r.tool === 'ig5_package' && r.action === 'ig5_package:apk' && r.outcome === 'success');
        if (!hasApkStatic) {
          missing.push('missing-verified-apk-static-package-receipt');
          vectorValid = false;
        }

        // Verify the registered jni-so is an actual ZIP member (`lib/<abi>/*.so`) of the registered APK!
        let apkMembership = null;
        try {
          apkMembership = inspectApkNativeLibraryMembership(apkComp.path);
        } catch (err) {
          missing.push(`apk-membership-inspection-failed(${err.code || 'ERROR'})`);
          vectorValid = false;
        }
        const matchedZipLib = apkMembership?.nativeLibraries?.find(l => l.sha256 === jniComp.sha256) || null;
        if (apkMembership && !matchedZipLib) {
          missing.push(`jni-so-not-member-of-registered-apk(${jniComp.componentId})`);
          vectorValid = false;
        }

        if (reqObs.includes('dynamic-device-hook')) {
          if (rec.tool !== 'ig5_app_observe' || recOut.action !== 'android_session_poll') {
            missing.push(`dynamic-device-hook-requires-android-session-poll-receipt(${tv.caseId})`);
            vectorValid = false;
          } else {
            if (!runId || usedRunIds.has(runId)) {
              missing.push(`missing-or-duplicate-android-run-id(${tv.caseId})`);
              vectorValid = false;
            }
            if (recOut.apkSha256 !== apkComp.sha256) {
              missing.push(`android-installed-apk-sha256-mismatch(${tv.caseId})`);
              vectorValid = false;
            }
            if (!recOut.pidIdentityIntact || recOut.sessionHealth !== 'healthy' || !recOut.procStarttimeTicks) {
              missing.push(`android-session-unhealthy-or-pid-restarted(${tv.caseId}:${recOut.sessionHealth || 'unknown'})`);
              vectorValid = false;
            }
            if (matchedZipLib && recOut.devicePrimaryAbi && matchedZipLib.abi !== recOut.devicePrimaryAbi) {
              // Check if device selected another ABI or mismatched ABI
              const expectedEntry = recOut.expectedJniLibs?.[matchedZipLib.fileName];
              if (!expectedEntry || expectedEntry.sha256 !== jniComp.sha256) {
                missing.push(`android-loaded-abi-or-so-sha256-mismatch(${tv.caseId}:soAbi=${matchedZipLib.abi},deviceAbi=${recOut.devicePrimaryAbi})`);
                vectorValid = false;
              }
            }
            const libName = matchedZipLib?.fileName || path.basename(jniComp.path);
            const procMaps = recOut.procMapsByLib?.[libName] || [];
            const moduleBoundEvent = Array.isArray(recOut.hookEvents)
              && recOut.hookEvents.some(ev => ev?.kind === 'module-bound' && ev.library === libName);
            if (procMaps.length === 0 && !moduleBoundEvent) {
              missing.push(`android-jni-library-not-mapped-in-process(${tv.caseId}:${libName})`);
              vectorValid = false;
            }
            if (recOut.observedInputHex !== expectedInputHex) {
              missing.push(`android-hook-input-mismatch(${tv.caseId}:expected=${expectedInputHex},actual=${recOut.observedInputHex || 'absent'})`);
              vectorValid = false;
            }
          }
        } else {
          // Static + CPU-slice Unicorn emulation scope (`apk-jni-static-emulation`)
          if (rec.tool !== 'ig5_emulate') {
            missing.push(`apk-jni-chain-requires-emulate-receipt(${tv.caseId})`);
            vectorValid = false;
          } else {
            const elfInfo = inspectElfJniCharacteristics(jniComp.path);
            if (elfInfo.dereferencesJniEnvVtable) {
              const argsRegs = rec.result?.cleanArgsSummary?.registers || recOut.initialRegisters || {};
              const envReg = Number(argsRegs.rdi ?? argsRegs.x0 ?? 0);
              if (!envReg || envReg === 0) {
                missing.push(`jni-env-vtable-required-zero-jnienv-emulation-invalid(${tv.caseId})`);
                vectorValid = false;
              }
            }
          }
        }
      }
    }

    // Holdout pre-commitment & chronology check across ALL candidate revisions (including revision 1!):
    // Candidate rule & outputSpec MUST be frozen BEFORE holdout selection and observation, and revised
    // candidates MUST use a fresh unseen holdout input never executed prior to candidate commit!
    if (actualIsHoldout) {
      const candRev = cand.candidateRevision || 0;
      const candSeq = cand.candidateCommittedSeq || 0;
      const selSeq = exp.selectedSeq || 0;
      const recSeq = summaryReceipt.receiptSeq || 0;
      const ruleBoundMatches = Boolean(exp.boundCandidateRuleSha256 && exp.boundCandidateRuleSha256 === cand.ruleSha256);
      const outSpecBoundMatches = Boolean(
        outputSpecDigest && exp.boundOutputSpecDigest && exp.boundOutputSpecDigest === outputSpecDigest,
      );
      const startChronologyValid = !startSummary || !startExpForHoldout || (
        startExpForHoldout.boundCandidateRuleSha256 === cand.ruleSha256
        && startExpForHoldout.boundOutputSpecDigest === outputSpecDigest
        && startExpForHoldout.selectedAtCandidateRevision === candRev
        && (startExpForHoldout.selectedSeq || 0) > candSeq
        && (startSummary.receiptSeq || 0) > candSeq
      );
      const chronologyValid = candRev >= 1
        && exp.selectedAtCandidateRevision === candRev
        && candSeq > 0
        && selSeq > candSeq
        && recSeq > selSeq
        && startChronologyValid;
      if (!ruleBoundMatches || !outSpecBoundMatches || !chronologyValid) {
        missing.push(
          candRev >= 2
            ? `holdout-consumed-by-prior-candidate-revision(${exp.expId})`
            : `holdout-not-bound-to-precommitted-candidate(${exp.expId})`,
        );
        vectorValid = false;
      } else if (expectedInputHex) {
        const previouslyExposed = rootTask.experiments.some(other => {
          const otherIn = other.scenarioSnapshot?.inputHex || other.scenarioSnapshot?.plannedInputHex || null;
          return other.expId !== exp.expId
            && (other.selectedSeq || 0) < candSeq
            && Array.isArray(other.receiptIds) && other.receiptIds.length > 0
            && otherIn === expectedInputHex;
        });
        if (previouslyExposed) {
          missing.push(`holdout-input-previously-exposed(${exp.expId}:${expectedInputHex})`);
          vectorValid = false;
        }
      }
    }

    if (!executableRule || !outputSpec) {
      continue;
    }

    // Evaluate executable rule and extract observed bytes even if chronology/provenance flagged above,
    // so all concrete mismatches on the vector are surfaced accurately in denialReasons.
    const evalInputHex = expectedInputHex || (typeof snap.claimedSampleHex === 'string' ? snap.claimedSampleHex : null);
    let computedHex = null;
    let evalError = null;
    if (evalInputHex) {
      try {
        computedHex = evaluateBoundedTransform(executableRule, evalInputHex);
      } catch (err) {
        evalError = err;
      }
    }
    const extracted = extractObservedOutputHex(recWithOut, outputSpec);
    if (evalInputHex && extracted.ok && (evalError || computedHex !== extracted.observedHex)) {
      const asciiStr = Buffer.from(evalInputHex, 'hex').toString('ascii').trim();
      if (/^[0-9a-f]{2,}$/i.test(asciiStr) && asciiStr.length % 2 === 0) {
        try {
          const decodedComputed = evaluateBoundedTransform(executableRule, asciiStr.toLowerCase());
          if (decodedComputed === extracted.observedHex) {
            computedHex = decodedComputed;
            evalError = null;
          }
        } catch {
          // keep original evalError / computedHex
        }
      }
    }
    if (evalError) {
      missing.push(`candidate-execution-error(${tv.caseId}:${evalError.code || evalError.message})`);
      vectorValid = false;
    }
    if (computedHex !== null && tv.predictedHex !== undefined && tv.predictedHex !== computedHex) {
      missing.push(`caller-prediction-contradicts-executable-rule(${tv.caseId}:claimed=${tv.predictedHex},computed=${computedHex})`);
      vectorValid = false;
    }
    if (!extracted.ok) {
      missing.push(`output-extraction-failed(${tv.caseId}:${extracted.reason})`);
      vectorValid = false;
    } else if (computedHex !== null && extracted.observedHex !== computedHex) {
      missing.push(`candidate-execution-mismatch(${tv.caseId}:computed=${computedHex},observed=${extracted.observedHex})`);
      vectorValid = false;
    }

    if (!vectorValid) {
      continue;
    }

    usedReceipts.add(tv.receiptId);
    usedExpIds.add(exp.expId);
    usedScenarioDigests.add(snap.scenarioDigest);
    if (runId) usedRunIds.add(runId);
    distinctSystemInputs.add(expectedInputHex);
    verifiedVectorCount += 1;
    verifiedReceipts.push({
      reportId: tv.receiptId,
      expId: exp.expId,
      scenarioId: snap.scenarioId,
      runId,
      inputHex: expectedInputHex,
      inputSha256: expectedInputSha256,
      computedHex,
      observedHex: extracted.observedHex,
      role: actualIsHoldout ? 'holdout-dynamic' : 'discovery-dynamic',
      tool: rec.tool,
      caseId: tv.caseId,
    });
    if (actualIsHoldout) verifiedHoldoutInputs.add(expectedInputHex);
    else nonHoldoutInputs.add(expectedInputHex);
  }

  if (verifiedVectorCount < deliv.minDistinctInputs || distinctSystemInputs.size < deliv.minDistinctInputs) {
    missing.push(`insufficient-distinct-dynamic-inputs(${distinctSystemInputs.size}/${deliv.minDistinctInputs})`);
  }
  if (deliv.holdoutRequired) {
    const hasDisjointHoldout = [...verifiedHoldoutInputs].some(inHex => !nonHoldoutInputs.has(inHex));
    if (!hasDisjointHoldout) {
      missing.push('missing-independent-holdout-verification');
    }
  }

  const status = missing.length === 0 ? 'satisfied' : (verifiedReceipts.length > 0 || rootTask.receipts.length > 0 ? 'partial' : 'unverified');
  return {
    deliverableId: deliv.id,
    kind: deliv.kind,
    status,
    candidateRuleSha256: cand.ruleSha256 || null,
    missing,
    verifiedReceipts,
  };
}

export function assessRootInvestigation({ rootTask, mgr, execution, hostGoal = null }) {
  const hasHostSession = execution?.agent?.session !== undefined;
  const coordOptions = { allowLocalFallback: !hasHostSession };
  const control = mgr.coordination?.controlStatus
    ? mgr.coordination.controlStatus(execution?.agent, coordOptions)
    : { cancelled: false, cleanupReservations: [], pendingReceipts: [], budget: null };

  const ops = mgr.coordination?.operationsForInvestigation
    ? mgr.coordination.operationsForInvestigation(execution?.agent, rootTask.rootId, coordOptions)
    : [];
  const pendingReceipts = ops.filter(op => op.researchLinkStatus === 'receipt-pending');
  const unknownEffects = ops.filter(op => op.status === 'effect-unknown');

  const activeReservations = (control.cleanupReservations || []).filter(r => r.status === 'active');
  const unknownReservations = (control.cleanupReservations || []).filter(r => r.status === 'unknown');
  const confirmedReservations = (control.cleanupReservations || []).filter(r => r.status === 'confirmed' || r.status === 'released-unstarted');

  const componentPaths = new Set(rootTask.components.map(c => c.path.toLowerCase()));
  const liveDebuggerSessions = [];
  if (mgr.debugOwners instanceof Map) {
    for (const [targetKey, dbgEngine] of mgr.debugOwners.entries()) {
      if (componentPaths.has(String(targetKey).toLowerCase())) {
        liveDebuggerSessions.push({ resourceKey: `live-dbg:${targetKey}`, resourceType: dbgEngine, status: 'active' });
      }
    }
  } else if (mgr.sessions instanceof Map) {
    for (const s of mgr.sessions.values()) {
      if (s?.engine === 'x64dbg' && s?.target && componentPaths.has(String(s.target).toLowerCase())
        && s.runtime?.state && s.runtime.state !== 'no-task') {
        liveDebuggerSessions.push({ resourceKey: `live-dbg:${s.target}`, status: 'active' });
      }
    }
  }

  // For android_session_poll, target is the APK path while scenario component may be the APK or JNI .so:
  // also check live appObserver / androidProvider active sessions for pending cleanup!
  const liveObserverSessions = [];
  if (mgr.appObserver?.activeSessions instanceof Map) {
    for (const sess of mgr.appObserver.activeSessions.values()) {
      if (componentPaths.has(String(sess.target).toLowerCase())) {
        liveObserverSessions.push({ resourceKey: `app:${sess.target.toLowerCase()}`, resourceType: 'app-observer', targetPath: sess.target, status: 'active' });
      }
    }
  }
  if (mgr.androidProvider?.sessions instanceof Map) {
    for (const sess of mgr.androidProvider.sessions.values()) {
      if (!sess.apkPath || componentPaths.has(String(sess.apkPath).toLowerCase())) {
        liveObserverSessions.push({
          resourceKey: sess.resourceKey,
          resourceType: 'android-device-session',
          deviceSerial: sess.deviceSerial,
          packageName: sess.packageName,
          status: 'active',
        });
      }
    }
  }

  const pendingCleanup = [
    ...activeReservations.map(r => ({
      resourceKey: r.resourceKey,
      resourceType: r.resourceType,
      ...(r.targetPath ? { targetPath: r.targetPath } : {}),
      ...(r.deviceSerial ? { deviceSerial: r.deviceSerial } : {}),
      ...(r.packageName ? { packageName: r.packageName } : {}),
      status: r.status,
      ownerAgentId: r.ownerAgentId,
      reservedCalls: r.reservedCalls,
    })),
    ...unknownReservations.map(r => ({
      resourceKey: r.resourceKey,
      resourceType: r.resourceType,
      ...(r.targetPath ? { targetPath: r.targetPath } : {}),
      ...(r.deviceSerial ? { deviceSerial: r.deviceSerial } : {}),
      ...(r.packageName ? { packageName: r.packageName } : {}),
      status: r.status,
      ownerAgentId: r.ownerAgentId,
      reservedCalls: r.reservedCalls,
    })),
    ...liveDebuggerSessions,
    ...liveObserverSessions.filter(ls => !activeReservations.some(ar => ar.resourceKey === ls.resourceKey)),
  ];

  let cleanup = 'not-needed';
  if (unknownReservations.length > 0) cleanup = 'unknown';
  else if (activeReservations.length > 0 || liveDebuggerSessions.length > 0 || liveObserverSessions.length > 0) cleanup = 'pending';
  else if (confirmedReservations.length > 0 || rootTask.receipts.some(r => r.isCleanup && r.outcome === 'success')) cleanup = 'confirmed';

  const budgetExhausted = Boolean(control.budget && (control.budget.limit - control.budget.used - (control.budget.reserved || 0)) <= 0);
  const hostGoalState = hostGoal?.status || null;

  let stopReason = null;
  if (control.cancelled) stopReason = control.cancelReason || 'user-cancelled';
  else if (hostGoalState === 'paused') stopReason = 'host-goal-paused';
  else if (hostGoalState === 'blocked') stopReason = 'host-goal-blocked';
  else if (unknownEffects.length > 0) stopReason = 'effect-unknown';
  else if (budgetExhausted) stopReason = 'budget-exhausted';

  const workState = stopReason ? 'stopped' : 'active';

  const deliverableReports = rootTask.deliverables.map(d => verifyDeliverableAgainstArtifacts(d, rootTask, mgr));
  const blockingReasons = [];
  if (pendingReceipts.length > 0) blockingReasons.push(`receipt-link-pending(${pendingReceipts.length})`);
  if (unknownEffects.length > 0) blockingReasons.push(`execution-effect-unknown(${unknownEffects.length})`);
  for (const dr of deliverableReports) {
    for (const m of dr.missing) blockingReasons.push(`${dr.deliverableId}:${m}`);
  }

  const allRoutesBlocked = (rootTask.routes.length > 0 && rootTask.routes.every(r => r.status === 'blocked'))
    || Boolean(rootTask.terminalFinding);
  let assessment = 'unverified';
  if (deliverableReports.length > 0 && deliverableReports.every(d => d.status === 'satisfied') && pendingReceipts.length === 0 && unknownEffects.length === 0 && !rootTask.terminalFinding) {
    assessment = 'satisfied';
  } else if (deliverableReports.some(d => d.status === 'unsupported')) {
    assessment = 'unsupported';
  } else if (allRoutesBlocked) {
    assessment = 'blocked';
  } else if (deliverableReports.some(d => d.status === 'partial' || d.status === 'satisfied') || rootTask.receipts.length > 0) {
    assessment = 'partial';
  }

  const cleanupBlocksCompletion = cleanup === 'pending' || cleanup === 'unknown';
  const denialReasons = [...blockingReasons];
  if (rootTask.terminalFinding) {
    denialReasons.push(`terminal-finding:${rootTask.terminalFinding.classification}`);
  }
  if (cleanupBlocksCompletion) denialReasons.push(`resource-cleanup-${cleanup}`);

  let goalContractAligned = true;
  if (hostGoal?.goalId) {
    if (rootTask.origin?.hostGoalId !== hostGoal.goalId) {
      goalContractAligned = false;
      denialReasons.push(`host-goal-id-mismatch(bound=${rootTask.origin?.hostGoalId || 'none'},current=${hostGoal.goalId})`);
    }
    if (!['complete', 'completed'].includes(hostGoalState)
      && Number.isSafeInteger(hostGoal.revision)
      && rootTask.origin?.hostGoalRevision !== hostGoal.revision) {
      goalContractAligned = false;
      denialReasons.push(`host-goal-revision-mismatch(bound=${rootTask.origin?.hostGoalRevision ?? 'none'},current=${hostGoal.revision})`);
    }
    if (typeof hostGoal.goal === 'string' && hostGoal.goal.trim() && rootTask.origin?.hostGoalObjectiveDigest) {
      const liveDigest = createHash('sha256').update(hostGoal.goal.trim()).digest('hex');
      if (liveDigest !== rootTask.origin.hostGoalObjectiveDigest) {
        goalContractAligned = false;
        denialReasons.push('host-goal-objective-changed');
      }
    }
  }

  const canCompleteHostGoal = assessment === 'satisfied' && !cleanupBlocksCompletion && goalContractAligned;
  const hostGoalCompleted = ['complete', 'completed'].includes(hostGoalState);
  const hostCompletedWithoutInvestigationAcceptance = hostGoalCompleted && !canCompleteHostGoal;
  const goalAssessmentAligned = hostGoalCompleted ? canCompleteHostGoal : goalContractAligned;

  const staticReceiptCount = rootTask.receipts.filter(r => !r.isCleanup && STATIC_TOOLS.has(r.tool)).length;
  const dynamicReceiptCount = rootTask.receipts.filter(r => !r.isCleanup && DYNAMIC_TOOLS.has(r.tool)).length;
  const cleanupReceiptCount = rootTask.receipts.filter(r => r.isCleanup).length;
  const failedReceiptCount = rootTask.receipts.filter(r => r.outcome !== 'success').length;

  const currentGoalRound = Number.isSafeInteger(hostGoal?.roundsStarted) ? hostGoal.roundsStarted : null;
  const hostGoalRoundStatus = {
    currentRound: currentGoalRound,
    minRoundsForHostBlocked: 3,
    canCallHostBlockedNow: currentGoalRound === null ? null : currentGoalRound >= 3,
  };

  return {
    rootId: rootTask.rootId,
    revision: rootTask.revision,
    planRevision: rootTask.planRevision,
    workState,
    stopReason,
    assessment,
    cleanup,
    canCompleteHostGoal,
    denialReasons,
    terminalFinding: rootTask.terminalFinding || null,
    hostGoalRoundStatus,
    deliverables: deliverableReports,
    unresolvedCounterexamples: rootTask.counterexamples.filter(c => c.status === 'unresolved'),
    pendingCleanup,
    pendingReceiptsCount: pendingReceipts.length,
    unknownEffectsCount: unknownEffects.length,
    budget: control.budget || null,
    decisionCostMetrics: {
      staticObservationCalls: staticReceiptCount,
      dynamicObservationCalls: dynamicReceiptCount,
      cleanupCalls: cleanupReceiptCount,
      failedDispatchedCalls: failedReceiptCount,
      recordedEvaluations: rootTask.evaluations.length,
      planRevisions: rootTask.planRevision,
    },
    hostGoalState,
    investigationAssessment: assessment,
    goalAssessmentAligned,
    hostCompletedWithoutInvestigationAcceptance,
  };
}
