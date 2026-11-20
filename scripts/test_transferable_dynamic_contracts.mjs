// Deterministic unit & component regressions for P0/P1/P2/P3 & runtime portability.
// Pure Node (< 2s): zero LLM calls, zero external devices, zero developer-path assumptions.

import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { test } from 'node:test';

import {
  collectVerifiedOwnedProcessTree,
  terminateVerifiedOwnedProcessesStrict,
  resolveControlledPythonBinary,
} from '../source/native_process_container.js';
import {
  PINNED_REA_FILES,
  verifyReaDistributionIntegrity,
  resolveReaCliPath,
  resolveElectronLaunchTarget,
  parseFramedObserverLog,
} from '../source/native_rea_bridge.js';
import {
  AndroidDynamicProvider,
  inspectElfJniCharacteristics,
} from '../source/native_android_provider.js';
import {
  parsePePreferredImageBase,
  validateOutputSpec,
  validateExecutableRule,
  evaluateBoundedTransform,
} from '../source/investigation_verifier.js';
import { RootInvestigationStore } from '../source/investigation_root.js';
import { assessRootInvestigation } from '../source/investigation_assessment.js';
import { runWorkspace } from '../source/investigation_workflow.js';
import { planRootInvestigation } from '../source/experiment_planner.js';
import { AnalysisArtifacts } from '../source/analysis_artifacts.js';
import { DelegationControl } from '../source/delegation_control.js';
import { runManagedToolExecution } from '../source/delegation_execution.js';
import { installAutonomyHost } from '../source/autonomy_host.js';

const sha256 = (b) => createHash('sha256').update(b).digest('hex');

function makeSyntheticPe64WithBase(imageBaseBigInt) {
  const buf = Buffer.alloc(0x400, 0);
  buf.write('MZ', 0, 'ascii');
  buf.writeUInt32LE(0x80, 0x3c);
  buf.write('PE\0\0', 0x80, 'ascii');
  buf.writeUInt16LE(0x8664, 0x84);
  buf.writeUInt16LE(0xf0, 0x94);
  const opt = 0x80 + 24;
  buf.writeUInt16LE(0x20b, opt);
  buf.writeBigUInt64LE(BigInt(imageBaseBigInt), opt + 24);
  return buf;
}

function makeMinimalElf64So({ usesJniEnv = false, machine = 0x3e } = {}) {
  const buf = Buffer.alloc(0x400, 0);
  buf.write('\x7fELF', 0, 'binary');
  buf[4] = 2; // 64-bit
  buf[5] = 1; // LE
  buf[6] = 1;
  buf.writeUInt16LE(3, 16); // ET_DYN
  buf.writeUInt16LE(machine, 18);
  if (usesJniEnv && machine === 0x3e) {
    // mov rax, [rdi] (48 8b 07); call qword ptr [rax + 0x560] (ff 90 60 05 00 00); ret (c3)
    Buffer.from('488b07ff9060050000c3', 'hex').copy(buf, 0x100);
  } else if (machine === 0x3e) {
    // mov eax, edx; xor eax, 0x5a; ret
    Buffer.from('89d083f05ac3', 'hex').copy(buf, 0x100);
  }
  return buf;
}

function createZipApkWithEntries(apkPath, entries) {
  const py = resolveControlledPythonBinary();
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ig5-mkapk-'));
  try {
    const specList = [];
    for (const [idx, [entryName, dataBuf]] of entries.entries()) {
      const f = path.join(tmpDir, `entry_${idx}.bin`);
      fs.writeFileSync(f, dataBuf);
      specList.push({ name: entryName, file: f });
    }
    const specFile = path.join(tmpDir, 'spec.json');
    fs.writeFileSync(specFile, JSON.stringify(specList), 'utf8');
    execFileSync(py, [
      '-c',
      'import json, sys, zipfile\nspecs = json.load(open(sys.argv[1], "r", encoding="utf-8"))\nwith zipfile.ZipFile(sys.argv[2], "w", compression=zipfile.ZIP_DEFLATED) as zf:\n  for s in specs: zf.write(s["file"], s["name"])',
      specFile,
      apkPath,
    ], { windowsHide: true });
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

test('P0.1: Missing creationIdentity, enumeration failure, or recycled PID NEVER invokes kill and returns unknown', () => {
  const killed = [];
  const killSpy = (pid) => killed.push(pid);

  // 1. Missing creationIdentity on target record -> status="unknown", zero kills
  const rMissing = terminateVerifiedOwnedProcessesStrict(
    [{ pid: 4444, creationIdentity: null, imagePath: 'C:\\app\\worker.exe' }],
    {
      queryImpl: () => ({
        status: 'ok',
        processes: [{ ProcessId: 4444, ParentProcessId: 1000, CreationId: '134000000000000000', ExecutablePath: 'C:\\app\\worker.exe' }],
      }),
      killImpl: killSpy,
    },
  );
  assert.equal(rMissing.status, 'unknown');
  assert.equal(killed.length, 0);
  assert.equal(rMissing.refusedUnknownPids.length, 1);

  // 2. Enumeration failure -> status="unknown" (never empty zero-residual!), zero kills
  const rEnumFail = terminateVerifiedOwnedProcessesStrict(
    [{ pid: 4444, creationIdentity: '134000000000000000', imagePath: 'C:\\app\\worker.exe' }],
    {
      queryImpl: () => ({ status: 'enumeration-failed', error: 'CIM_FAILED', processes: null }),
      killImpl: killSpy,
    },
  );
  assert.equal(rEnumFail.status, 'unknown');
  assert.equal(killed.length, 0);

  // 3. Recycled PID (different CreationId) & executable path conflict -> zero kills
  const rRecycled = terminateVerifiedOwnedProcessesStrict(
    [
      { pid: 4444, creationIdentity: '134000000000000000', imagePath: 'C:\\app\\worker.exe' },
      { pid: 5555, creationIdentity: '134000000000000005', imagePath: 'C:\\app\\worker.exe' },
    ],
    {
      queryImpl: () => ({
        status: 'ok',
        processes: [
          { ProcessId: 4444, ParentProcessId: 1, CreationId: '134999999999999999', ExecutablePath: 'C:\\app\\worker.exe' },
          { ProcessId: 5555, ParentProcessId: 1, CreationId: '134000000000000005', ExecutablePath: 'C:\\other\\bystander.exe' },
        ],
      }),
      killImpl: killSpy,
    },
  );
  assert.equal(rRecycled.status, 'unknown');
  assert.deepEqual(rRecycled.skippedRecycledPids, [4444]);
  assert.equal(rRecycled.refusedUnknownPids[0].pid, 5555);
  assert.equal(killed.length, 0);

  // 4. Descendant missing CreationId in tree collection -> status="unknown", excluded from owned
  const treeRes = collectVerifiedOwnedProcessTree({
    status: 'ok',
    processes: [
      { ProcessId: 100, ParentProcessId: 10, CreationId: '5000', ExecutablePath: 'C:\\a.exe' },
      { ProcessId: 101, ParentProcessId: 100, CreationId: null, ExecutablePath: 'C:\\b.exe' },
    ],
  }, 100, '5000');
  assert.equal(treeRes.status, 'unknown');
  assert.equal(treeRes.owned.length, 1);
  assert.equal(treeRes.ambiguousOrMissingIdentity.length, 1);

  // 5. Framed observer log integrity detects missing, truncated, and corrupt logs
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'ig5-obs-log-'));
  try {
    const missingLog = parseFramedObserverLog(path.join(tmp, 'nope.jsonl'), 'run-1');
    assert.equal(missingLog.integrity, 'missing');

    const truncPath = path.join(tmp, 'trunc.jsonl');
    fs.writeFileSync(truncPath, JSON.stringify({ seq: 1, runId: 'run-1', kind: 'observer-log-open' }) + '\n', 'utf8');
    assert.equal(parseFramedObserverLog(truncPath, 'run-1').integrity, 'truncated');

    const okPath = path.join(tmp, 'ok.jsonl');
    fs.writeFileSync(
      okPath,
      JSON.stringify({ seq: 1, runId: 'run-1', kind: 'observer-log-open' }) + '\n'
      + JSON.stringify({ seq: 2, runId: 'run-1', kind: 'observer-log-close' }) + '\n',
      'utf8',
    );
    assert.equal(parseFramedObserverLog(okPath, 'run-1').integrity, 'verified');
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('P0.2 & P1.2: Forged stdout PIDs, bystander workers, non-standard PE ImageBase, and variable-length frame rules', async () => {
  const tmp = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), 'ig5-p02-'));
  const cfg = { projectRoot: path.join(tmp, 'projects'), artifactDir: path.join(tmp, 'artifacts') };
  const artifacts = new AnalysisArtifacts(cfg.artifactDir);
  const rStore = new RootInvestigationStore({ projectRoot: cfg.projectRoot });
  const coord = new DelegationControl({ root: cfg.projectRoot });
  const mgr = { rootInvestigations: rStore, coordination: coord, analysis: { artifacts }, sessions: new Map() };
  const rootAgent = { id: 'root-p02', session: { id: 'root-p02', header: { id: 'root-p02' } } };

  try {
    // 1. Non-standard PE64 ImageBase (0x220000000) parsed directly from PE header
    const customDllPath = path.join(tmp, 'custom_base.dll');
    fs.writeFileSync(customDllPath, makeSyntheticPe64WithBase(0x220000000n));
    assert.equal(parsePePreferredImageBase(customDllPath), '0x220000000');

    // 2. Variable-length structured frame rule (`ig5-bounded-frame-rule-v1`) across 3B and 6B inputs
    const outSpec = validateOutputSpec({ kind: 'app-output', channel: 'process-chain', minByteLength: 6, maxByteLength: 64 });
    const frameRule = validateExecutableRule({
      schema: 'ig5-bounded-frame-rule-v1',
      headerHex: 'a55a',
      lengthField: { kind: 'payload-len-u8', bias: 0 },
      prevInit: 0x33,
      constants: { key: '11223344' },
      bodyByteExpr: {
        op: 'xor',
        args: [
          { op: 'xor', args: [{ op: 'in', index: { op: 'i' } }, { op: 'const', name: 'key', index: { op: 'mod', args: [{ op: 'i' }, 4] } }] },
          { op: 'prev' },
        ],
      },
      trailerChecksum: { kind: 'crc16ccitt-be', scope: 'header-and-body' },
    }, outSpec);
    const eval3B = evaluateBoundedTransform(frameRule, '414243');
    const eval6B = evaluateBoundedTransform(frameRule, '010203040506');
    assert.equal(eval3B.length, (2 + 1 + 3 + 2) * 2); // 8 bytes = 16 hex chars
    assert.equal(eval6B.length, (2 + 1 + 6 + 2) * 2); // 11 bytes = 22 hex chars
    assert(eval3B.startsWith('a55a03'));
    assert(eval6B.startsWith('a55a06'));

    // 3. Forged stdout JSON + bystander worker MUST FAIL process-chain verification!
    const entryExe = path.join(tmp, 'entry.exe');
    const worker1Exe = path.join(tmp, 'w1.exe');
    const worker2Exe = path.join(tmp, 'w2.exe');
    fs.writeFileSync(entryExe, makeSyntheticPe64WithBase(0x140000000n));
    fs.writeFileSync(worker1Exe, makeSyntheticPe64WithBase(0x140010000n));
    fs.writeFileSync(worker2Exe, makeSyntheticPe64WithBase(0x140020000n));
    const entrySha = sha256(fs.readFileSync(entryExe));
    const w1Sha = sha256(fs.readFileSync(worker1Exe));

    const created = runWorkspace(mgr, cfg, {
      workspace: {
        action: 'root-create',
        goal: 'Reject forged stdout and bystander PIDs',
        root: {
          deliverables: [{
            id: 'd-chain',
            kind: 'structured-frame-transform',
            requiredObservations: ['static-locate', 'dynamic-runtime-observation', 'multi-process-lineage'],
            minDistinctInputs: 1,
            holdoutRequired: false,
            nonCooperativeRequired: true,
          }],
          components: [
            { componentId: 'c-entry', path: entryExe, role: 'main-pe' },
            { componentId: 'c-w1', path: worker1Exe, role: 'worker-pe' },
            { componentId: 'c-w2', path: worker2Exe, role: 'worker-pe' },
          ],
          scenarios: [{
            scenarioId: 's1',
            componentId: 'c-entry',
            launchMode: 'via-parent',
            args: ['--in=414243'],
            cwd: tmp,
            inputSpec: { kind: 'cli-arg', argIndex: 0, prefix: '--in=', encoding: 'hex', isHoldout: false },
          }],
        },
      },
    }, { agent: rootAgent }).workspace;

    // Static receipt
    const staticRec = artifacts.save({
      kind: 'managed-operation-receipt',
      action: 'ig5_open',
      operationId: 'op-static-1',
      tool: 'ig5_open',
      investigationId: created.rootId,
      outcome: 'success',
      result: { cleanArgsSummary: { path: entryExe }, outcome: 'success', replayOutput: { _ig5: { sha256: entrySha, target: entryExe } } },
    });
    rStore.recordSystemReceipt({ rootId: created.rootId, receiptRecord: staticRec, operation: { operationId: 'op-static-1' } });

    const sel = rStore.selectExperiment(created.rootId, {
      kind: 'dynamic-breakpoint-read',
      scenarioId: 's1',
      componentId: 'c-entry',
      hypothesis: 'Test forged stdout',
      observer: 'job-container',
    });

    // Forge a receipt where outputHex is 100% mathematically right (`eval3B`) AND applicationReported claims
    // w1 & w2 ran, AND w1 is even in lineage as a bystander (`parentPid: 999` outside entry `pid: 500`), while w2 never ran!
    const forgedRec = artifacts.save({
      kind: 'managed-operation-receipt',
      action: 'ig5_app_observe:process_chain_scenario',
      operationId: 'op-forged-1',
      tool: 'ig5_app_observe',
      investigationId: created.rootId,
      experimentId: sel.experiment.expId,
      outcome: 'success',
      result: {
        cleanArgsSummary: { target: entryExe, action: 'process_chain_scenario' },
        outcome: 'success',
        runtimeIdentity: { runId: 'chain-run-forged-1' },
        replayOutput: {
          ok: true,
          action: 'process_chain_scenario',
          fixtureOnlyProtocol: false,
          runId: 'chain-run-forged-1',
          target: entryExe,
          observedInputHex: '414243',
          outputHex: eval3B,
          verifiedProcessLineage: [
            { pid: 500, parentPid: 100, creationIdentity: '90001', sha256: entrySha, relationOrigin: 'win32-job-kernel-observed', exitCode: 0 },
            // Bystander w1 with unconnected parentPid 999!
            { pid: 501, parentPid: 999, creationIdentity: '90002', sha256: w1Sha, relationOrigin: 'win32-job-kernel-observed', exitCode: 0 },
          ],
          applicationReported: {
            trustLevel: 'untrusted-target-claim',
            parsedJson: { ok: true, stage1Pid: 501, stage2Pid: 8888, finalOutHex: eval3B },
          },
          cleanup: { cleanupVerified: true },
        },
      },
    });
    rStore.recordSystemReceipt({ rootId: created.rootId, receiptRecord: forgedRec, operation: { operationId: 'op-forged-1' } });

    rStore.submitCandidateExplanation(created.rootId, {
      deliverableId: 'd-chain',
      summary: 'Correct math but unverified intermediate workers',
      outputSpec: outSpec,
      executableRule: frameRule,
      testVectors: [{ caseId: 'v1', receiptId: forgedRec.id, isHoldout: false }],
    }, artifacts);

    const assessed = assessRootInvestigation({ rootTask: rStore.get(created.rootId), mgr, execution: { agent: rootAgent } });
    assert.equal(assessed.assessment, 'partial');
    assert.equal(assessed.canCompleteHostGoal, false);
    assert(assessed.denialReasons.some((r) => r.includes('missing-system-observed-worker-execution(v1:c-w1)')));
    assert(assessed.denialReasons.some((r) => r.includes('missing-system-observed-worker-execution(v1:c-w2)')));
  } finally {
    await artifacts.dispose();
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('P2: AndroidDynamicProvider & verifier enforce 5-link APK->ABI->SO->maps->hook provenance and JNIEnv vtable guard', async () => {
  const tmp = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), 'ig5-p2-android-'));
  const cfg = { projectRoot: path.join(tmp, 'projects'), artifactDir: path.join(tmp, 'artifacts') };
  const artifacts = new AnalysisArtifacts(cfg.artifactDir);
  const rStore = new RootInvestigationStore({ projectRoot: cfg.projectRoot });
  const coord = new DelegationControl({ root: cfg.projectRoot });

  try {
    const jniEnvSo = makeMinimalElf64So({ usesJniEnv: true, machine: 0x3e });
    const straySo = makeMinimalElf64So({ usesJniEnv: false, machine: 0x3e });
    const jniSoPath = path.join(tmp, 'libvault_jni.so');
    const straySoPath = path.join(tmp, 'libstray.so');
    fs.writeFileSync(jniSoPath, jniEnvSo);
    fs.writeFileSync(straySoPath, straySo);

    assert.equal(inspectElfJniCharacteristics(jniSoPath).dereferencesJniEnvVtable, true);
    assert.equal(inspectElfJniCharacteristics(straySoPath).dereferencesJniEnvVtable, false);

    const apkPath = path.join(tmp, 'VaultApp.apk');
    createZipApkWithEntries(apkPath, [
      ['AndroidManifest.xml', Buffer.from('manifest-placeholder')],
      ['lib/x86_64/libvault_jni.so', jniEnvSo],
    ]);
    const apkSha = sha256(fs.readFileSync(apkPath));

    // Controlled mock Android transport testing version mismatch, ABI mismatch, cross-APK mismatch, PID drift, and valid run
    const transportState = {
      serverVersion: '16.7.19',
      installedApkSha: apkSha,
      deviceAbi: 'x86_64',
      procStarttime: '44556677',
      nextInputHex: '10203040',
      nextOutputHex: '50607080',
      killedSpawned: 0,
    };

    const mockTransport = {
      adbAvailable: () => true,
      adbPath: () => 'mock-adb',
      listDevices: () => ({ ok: true, devices: [{ serial: 'emu-5554', state: 'device', detail: 'sdk_gphone64_x86_64' }] }),
      queryDeviceProps: () => ({ ok: true, primaryAbi: transportState.deviceAbi, supportedAbis: [transportState.deviceAbi], sdkInt: 34 }),
      queryInstalledPackageSha256: () => ({ ok: true, remoteApkPath: '/data/app/com.ig5.vault/base.apk', installedApkSha256: transportState.installedApkSha }),
      queryProcStarttime: () => ({ ok: true, starttime: transportState.procStarttime }),
      queryProcMapsForLib: (_s, _pid, lib) => [`7f10000000-7f10002000 r-xp 00000000fe:00 /data/app/com.ig5.vault/lib/x86_64/${lib}`],
      probeFrida: () => ({
        ok: true,
        fridaInstalled: true,
        hostFridaVersion: '16.7.19',
        serverReachable: true,
        serverVersion: transportState.serverVersion,
        versionCompatible: transportState.serverVersion.split('.')[0] === '16',
      }),
      triggerAppIntent: () => ({ ok: true, stdout: 'Starting: Intent' }),
      async startFridaWorkerSession(scfg) {
        const events = [
          { seq: 1, runId: scfg.runId, kind: 'probe-script-loaded', pid: 7123 },
          { seq: 2, runId: scfg.runId, kind: 'module-bound', layer: 'jni', library: 'libvault_jni.so', moduleBase: '0x7f10000000' },
        ];
        return {
          pid: 7123,
          spawnedByIg5: scfg.mode === 'spawn',
          getEvents: () => ({
            hookEvents: [
              ...events,
              {
                seq: 3,
                runId: scfg.runId,
                kind: 'hook-hit',
                layer: 'jni',
                library: 'libvault_jni.so',
                symbol: 'Java_com_ig5_vault_Bridge_seal',
                inputHex: transportState.nextInputHex,
                outputHex: transportState.nextOutputHex,
              },
            ],
            scriptErrors: [],
            detachInfo: null,
          }),
          async stop(cmd) {
            if (scfg.mode === 'spawn' && cmd !== 'KEEP') transportState.killedSpawned += 1;
            return { stopReason: 'owner-stop', scriptUnloaded: true, sessionDetached: true, killedSpawnedPid: scfg.mode === 'spawn' };
          },
        };
      },
    };

    const provider = new AndroidDynamicProvider(cfg, { transport: mockTransport });
    const mgr = { rootInvestigations: rStore, coordination: coord, analysis: { artifacts }, androidProvider: provider, sessions: new Map() };
    const rootAgent = { id: 'root-and', session: { id: 'root-and', header: { id: 'root-and' } } };

    // Negative 1: Frida server major version mismatch -> FRIDA_SERVER_VERSION_MISMATCH
    transportState.serverVersion = '15.1.0';
    await assert.rejects(
      () => provider.startSession({
        deviceSerial: 'emu-5554',
        packageName: 'com.ig5.vault',
        apkPath,
        probeSpecs: [{ layer: 'jni', library: 'libvault_jni.so', symbol: 'Java_com_ig5_vault_Bridge_seal' }],
      }),
      (err) => err.code === 'FRIDA_SERVER_VERSION_MISMATCH',
    );
    transportState.serverVersion = '16.7.19';

    // Negative 2: Installed APK SHA-256 mismatch -> ANDROID_INSTALLED_APK_MISMATCH
    transportState.installedApkSha = 'f'.repeat(64);
    await assert.rejects(
      () => provider.startSession({
        deviceSerial: 'emu-5554',
        packageName: 'com.ig5.vault',
        apkPath,
        probeSpecs: [{ layer: 'jni', library: 'libvault_jni.so', symbol: 'Java_com_ig5_vault_Bridge_seal' }],
      }),
      (err) => err.code === 'ANDROID_INSTALLED_APK_MISMATCH',
    );
    transportState.installedApkSha = apkSha;

    // Negative 3: Device ABI mismatch (`arm64-v8a` device vs `x86_64`-only APK) -> ANDROID_ABI_OR_LIB_MISMATCH
    transportState.deviceAbi = 'arm64-v8a';
    await assert.rejects(
      () => provider.startSession({
        deviceSerial: 'emu-5554',
        packageName: 'com.ig5.vault',
        apkPath,
        probeSpecs: [{ layer: 'jni', library: 'libvault_jni.so', symbol: 'Java_com_ig5_vault_Bridge_seal' }],
      }),
      (err) => err.code === 'ANDROID_ABI_OR_LIB_MISMATCH',
    );
    transportState.deviceAbi = 'x86_64';

    // Negative 4: Zero-JNIEnv Unicorn emulation on a `.so` that dereferences `JNIEnv*` vtable MUST be rejected!
    const emuRoot = rStore.create({
      rootSessionId: 'root-and',
      goal: 'Reject zero-JNIEnv Unicorn emulation when JNIEnv vtable is dereferenced',
      deliverables: [{
        id: 'd-emu',
        kind: 'apk-jni-chain',
        requiredObservations: ['static-locate', 'apk-jni-static-emulation'],
        minDistinctInputs: 1,
        holdoutRequired: false,
      }],
    });
    rStore.registerComponent(emuRoot.rootId, { componentId: 'c-apk', path: apkPath, role: 'apk' });
    rStore.registerComponent(emuRoot.rootId, { componentId: 'c-so', path: jniSoPath, role: 'jni-so' });
    rStore.upsertScenario(emuRoot.rootId, {
      scenarioId: 's-emu',
      componentId: 'c-so',
      launchMode: 'via-parent',
      inputSpec: { kind: 'emulate', sampleHex: '10203040', isHoldout: false },
    }, artifacts);
    const apkStaticRec = artifacts.save({
      kind: 'managed-operation-receipt',
      action: 'ig5_package:apk',
      operationId: 'op-apk-s',
      tool: 'ig5_package',
      investigationId: emuRoot.rootId,
      outcome: 'success',
      result: { cleanArgsSummary: { path: apkPath }, outcome: 'success', replayOutput: { sha256: apkSha, target: apkPath } },
    });
    rStore.recordSystemReceipt({ rootId: emuRoot.rootId, receiptRecord: apkStaticRec, operation: { operationId: 'op-apk-s' } });
    const emuSel = rStore.selectExperiment(emuRoot.rootId, { kind: 'dynamic-breakpoint-read', scenarioId: 's-emu', componentId: 'c-so', hypothesis: 'zero env', observer: 'unicorn' });
    const zeroEnvEmuRec = artifacts.save({
      kind: 'managed-operation-receipt',
      action: 'ig5_emulate',
      operationId: 'op-emu-0',
      tool: 'ig5_emulate',
      investigationId: emuRoot.rootId,
      experimentId: emuSel.experiment.expId,
      outcome: 'success',
      result: {
        cleanArgsSummary: { target: jniSoPath, abi: 'sysv64' },
        outcome: 'success',
        replayOutput: { _ig5: { target: jniSoPath, sha256: sha256(jniEnvSo) }, registers: { rax: '0x80706050' } },
      },
    });
    rStore.recordSystemReceipt({ rootId: emuRoot.rootId, receiptRecord: zeroEnvEmuRec, operation: { operationId: 'op-emu-0' } });
    rStore.submitCandidateExplanation(emuRoot.rootId, {
      deliverableId: 'd-emu',
      summary: 'Add 0x40',
      outputSpec: { kind: 'emulate-capture', register: 'rax', byteLength: 4, endian: 'little' },
      executableRule: { schema: 'ig5-bounded-byte-rule-v1', outputLength: 4, byteExpr: { op: 'add', args: [{ op: 'in', index: { op: 'i' } }, 0x40] } },
      testVectors: [{ caseId: 'e1', receiptId: zeroEnvEmuRec.id, isHoldout: false }],
    }, artifacts);
    const emuAssess = assessRootInvestigation({ rootTask: rStore.get(emuRoot.rootId), mgr, execution: { agent: rootAgent } });
    assert.equal(emuAssess.canCompleteHostGoal, false);
    assert(emuAssess.denialReasons.some((r) => r.includes('jni-env-vtable-required-zero-jnienv-emulation-invalid')));

    // Positive 5: Full `dynamic-device-hook` workflow (2 discovery + pre-commit + 1 unseen holdout + owner stop) -> satisfied!
    const dynRoot = rStore.create({
      rootSessionId: 'root-and',
      goal: 'Verify real dynamic-device-hook contract end-to-end',
      deliverables: [{
        id: 'd-dyn',
        kind: 'apk-jni-chain',
        requiredObservations: ['static-locate', 'dynamic-runtime-observation', 'dynamic-device-hook'],
        minDistinctInputs: 2,
        holdoutRequired: true,
      }],
    });
    rStore.registerComponent(dynRoot.rootId, { componentId: 'c-apk', path: apkPath, role: 'apk' });
    rStore.registerComponent(dynRoot.rootId, { componentId: 'c-so', path: jniSoPath, role: 'jni-so' });
    rStore.recordSystemReceipt({ rootId: dynRoot.rootId, receiptRecord: apkStaticRec, operation: { operationId: 'op-apk-s' } });

    const runDeviceObservation = async (scenId, inHex, outHex, isHoldout) => {
      rStore.upsertScenario(dynRoot.rootId, {
        scenarioId: scenId,
        componentId: 'c-apk',
        launchMode: 'via-parent',
        inputSpec: { kind: 'android-intent', extraKey: 'payload', extraValue: inHex, encoding: 'hex', isHoldout },
      }, artifacts);
      const expSel = rStore.selectExperiment(dynRoot.rootId, {
        kind: isHoldout ? 'holdout-verify' : 'dynamic-breakpoint-read',
        scenarioId: scenId,
        componentId: 'c-apk',
        hypothesis: 'Observe JNI byteArray hook',
        observer: 'frida-jni-hook',
      });
      transportState.nextInputHex = inHex;
      transportState.nextOutputHex = outHex;
      await provider.startSession({
        deviceSerial: 'emu-5554',
        packageName: 'com.ig5.vault',
        apkPath,
        ownerAgentId: 'root-and',
        probeSpecs: [{ layer: 'jni', library: 'libvault_jni.so', symbol: 'Java_com_ig5_vault_Bridge_seal', argByteArrayIndex: 2, returnIsByteArray: true }],
      });
      const pollOut = await provider.pollOrTriggerSession({
        deviceSerial: 'emu-5554',
        packageName: 'com.ig5.vault',
        triggerComponent: 'com.ig5.vault/.MainActivity',
        triggerExtras: { payload: inHex },
        settleMs: 10,
        ownerAgentId: 'root-and',
      });
      await provider.stopSession({ deviceSerial: 'emu-5554', packageName: 'com.ig5.vault', ownerAgentId: 'root-and' });
      const pollRec = artifacts.save({
        kind: 'managed-operation-receipt',
        action: 'ig5_app_observe:android_session_poll',
        operationId: `op-${scenId}`,
        tool: 'ig5_app_observe',
        investigationId: dynRoot.rootId,
        experimentId: expSel.experiment.expId,
        outcome: 'success',
        result: {
          cleanArgsSummary: { action: 'android_session_poll', device_serial: 'emu-5554', package_name: 'com.ig5.vault' },
          outcome: 'success',
          runtimeIdentity: { runId: pollOut.runId },
          replayOutput: pollOut,
        },
      });
      rStore.recordSystemReceipt({ rootId: dynRoot.rootId, receiptRecord: pollRec, operation: { operationId: `op-${scenId}` } });
      return pollRec.id;
    };

    const d1 = await runDeviceObservation('s-d1', '10203040', '50607080', false);
    const d2 = await runDeviceObservation('s-d2', '01020304', '41424344', false);

    // Pre-commit BEFORE holdout!
    rStore.submitCandidateExplanation(dynRoot.rootId, {
      deliverableId: 'd-dyn',
      summary: 'Each byte + 0x40',
      outputSpec: { kind: 'app-output', channel: 'android-hook', byteLength: 4 },
      executableRule: { schema: 'ig5-bounded-byte-rule-v1', outputLength: 4, byteExpr: { op: 'add', args: [{ op: 'in', index: { op: 'i' } }, 0x40] } },
    }, artifacts);

    const h1 = await runDeviceObservation('s-hold', '21222324', '61626364', true);
    rStore.submitCandidateExplanation(dynRoot.rootId, {
      deliverableId: 'd-dyn',
      testVectors: [
        { caseId: 'd1', receiptId: d1, isHoldout: false },
        { caseId: 'd2', receiptId: d2, isHoldout: false },
        { caseId: 'h1', receiptId: h1, isHoldout: true },
      ],
    }, artifacts);

    const dynAssess = assessRootInvestigation({ rootTask: rStore.get(dynRoot.rootId), mgr, execution: { agent: rootAgent } });
    assert.equal(dynAssess.assessment, 'satisfied');
    assert.equal(dynAssess.cleanup, 'not-needed');
    assert.equal(dynAssess.canCompleteHostGoal, true);
    assert.equal(transportState.killedSpawned, 3);
  } finally {
    await artifacts.dispose();
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('Section VII & P3: Zero developer-path fallback, full REA dist/dep verification, and root planner cleanup/static routing', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'ig5-portability-'));
  const prevReaRoot = process.env.IG5_REA_ROOT;
  const prevReaCli = process.env.IG5_REA_CLI;
  const prevElExe = process.env.IG5_ELECTRON_EXE;
  const prevRtRoot = process.env.IG5_RUNTIME_ROOT;

  try {
    delete process.env.IG5_REA_ROOT;
    delete process.env.IG5_REA_CLI;
    delete process.env.IG5_ELECTRON_EXE;
    process.env.IG5_RUNTIME_ROOT = tmp;

    // 1. Clean directory with no REA configured MUST fail with REA_CLI_UNAVAILABLE (never reaching into Desktop!)
    assert.throws(
      () => resolveReaCliPath(tmp, { runtimeRoot: tmp }),
      (err) => err.code === 'REA_CLI_UNAVAILABLE' && err.missingAtom === 'runtime:rea-agents@6.4.0',
    );

    // 2. Unpackaged Electron app dir with no Electron runtime configured MUST fail with ELECTRON_RUNTIME_UNAVAILABLE
    const unpackagedDir = path.join(tmp, 'unpackaged-app');
    fs.mkdirSync(unpackagedDir, { recursive: true });
    fs.writeFileSync(path.join(unpackagedDir, 'main.js'), 'console.log(1);', 'utf8');
    assert.throws(
      () => resolveElectronLaunchTarget(unpackagedDir, { cfg: { runtimeRoot: tmp } }),
      (err) => err.code === 'ELECTRON_RUNTIME_UNAVAILABLE' && err.missingAtom === 'runtime:electron',
    );

    // 3. Packaged Electron app with its own `<App>.exe` + `resources/app.asar` selects its own `.exe`!
    const packagedDir = path.join(tmp, 'packaged-app');
    fs.mkdirSync(path.join(packagedDir, 'resources'), { recursive: true });
    fs.writeFileSync(path.join(packagedDir, 'resources', 'app.asar'), 'asar-bytes', 'utf8');
    const ownExe = path.join(packagedDir, 'MyStudio.exe');
    fs.writeFileSync(ownExe, 'MZ-fake', 'utf8');
    const resolvedLaunch = resolveElectronLaunchTarget(packagedDir, { cfg: { runtimeRoot: tmp } });
    assert.equal(resolvedLaunch.runtimeSelection, 'target-packaged-executable');
    assert.equal(resolvedLaunch.executable, ownExe);

    // 4. Tampered `dist/cli.js` in a staged REA root is rejected even if `scripts/rea.mjs` matches PINNED_REA_MJS_SHA256!
    const fakeReaRoot = path.join(tmp, 'fake-rea');
    fs.mkdirSync(path.join(fakeReaRoot, 'scripts'), { recursive: true });
    fs.mkdirSync(path.join(fakeReaRoot, 'dist', 'composition'), { recursive: true });
    const realVendorRea = path.resolve(import.meta.dirname, '..', 'vendor', 'rea', 'rea.mjs');
    fs.copyFileSync(realVendorRea, path.join(fakeReaRoot, 'scripts', 'rea.mjs'));
    fs.writeFileSync(path.join(fakeReaRoot, 'package.json'), '{}', 'utf8');
    fs.writeFileSync(path.join(fakeReaRoot, 'dist', 'cli.js'), '// tampered dist!\n', 'utf8');
    assert.throws(
      () => verifyReaDistributionIntegrity(fakeReaRoot),
      (err) => err.code === 'REA_PIN_MISMATCH' || err.code === 'REA_DIST_INCOMPLETE',
    );
    assert.equal(Object.keys(PINNED_REA_FILES).length >= 5, true);

    // 5. Planner routes `electron-app` to `ig5_package:js_app` and `android:` reservation to `android_session_stop`
    const fakeTask = {
      kind: 'root-investigation',
      rootId: 'r-plan-1',
      planRevision: 2,
      deliverables: [{ id: 'd1', kind: 'electron-native-chain', candidateExplanation: null }],
      components: [{ componentId: 'c1', path: unpackagedDir, role: 'electron-app' }],
      scenarios: [],
      routes: [],
      experiments: [],
      receipts: [],
    };
    const fakeAssess = {
      workState: 'active',
      stopReason: null,
      canCompleteHostGoal: false,
      pendingReceiptsCount: 0,
      unknownEffectsCount: 0,
      unresolvedCounterexamples: [],
      deliverables: [],
      pendingCleanup: [
        { resourceKey: 'android:emu-5554:com.ig5.vault', status: 'active', deviceSerial: 'emu-5554', packageName: 'com.ig5.vault' },
      ],
    };
    const plan = planRootInvestigation({ rootTask: fakeTask, assessment: fakeAssess });
    assert.equal(plan.candidates[0].kind, 'cleanup-owned-resource');
    assert.equal(plan.candidates[0].request.action, 'android_session_stop');
    assert.equal(plan.candidates[1].kind, 'inline-static-locate');
    assert.equal(plan.candidates[1].request.tool, 'ig5_package');
    assert.equal(plan.candidates[1].request.action, 'js_app');
  } finally {
    if (prevReaRoot === undefined) delete process.env.IG5_REA_ROOT; else process.env.IG5_REA_ROOT = prevReaRoot;
    if (prevReaCli === undefined) delete process.env.IG5_REA_CLI; else process.env.IG5_REA_CLI = prevReaCli;
    if (prevElExe === undefined) delete process.env.IG5_ELECTRON_EXE; else process.env.IG5_ELECTRON_EXE = prevElExe;
    if (prevRtRoot === undefined) delete process.env.IG5_RUNTIME_ROOT; else process.env.IG5_RUNTIME_ROOT = prevRtRoot;
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('Input Lifecycle 8 Counterexamples + Post-Cleanup Blob Witness + Multi-File Order Independence', async () => {
  const tmp = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), 'ig5-input-lifecycle-'));
  const cfg = { projectRoot: path.join(tmp, 'projects'), artifactDir: path.join(tmp, 'artifacts') };
  const artifacts = new AnalysisArtifacts(cfg.artifactDir);
  const rStore = new RootInvestigationStore({ projectRoot: cfg.projectRoot });
  const coord = new DelegationControl({ root: cfg.projectRoot });
  const mgr = { rootInvestigations: rStore, coordination: coord, analysis: { artifacts }, artifacts, sessions: new Map() };
  const rootAgent = { id: 'root-life', session: { id: 'root-life', header: { id: 'root-life' } } };

  try {
    const entryExe = path.join(tmp, 'entry_cli.exe');
    const worker1Exe = path.join(tmp, 'worker_a.exe');
    const worker2Exe = path.join(tmp, 'worker_b.exe');
    fs.writeFileSync(entryExe, makeSyntheticPe64WithBase(0x140000000n));
    fs.writeFileSync(worker1Exe, makeSyntheticPe64WithBase(0x140010000n));
    fs.writeFileSync(worker2Exe, makeSyntheticPe64WithBase(0x140020000n));
    const entrySha = sha256(fs.readFileSync(entryExe));
    const w1Sha = sha256(fs.readFileSync(worker1Exe));
    const w2Sha = sha256(fs.readFileSync(worker2Exe));

    // Contract propagation & anti-downgrade on host-goal bound deliverables
    assert.throws(
      () => rStore.create({
        rootSessionId: 'root-life',
        goal: 'Downgrade attempt',
        hostGoal: { goalId: 'goal-1', revision: 1, goal: 'Downgrade attempt' },
        deliverables: [{ id: 'd-down', kind: 'process-chain-transform', nonCooperativeRequired: false }],
      }),
      (err) => err.code === 'CONTRACT_DOWNGRADE_FORBIDDEN',
    );
    assert.throws(
      () => rStore.create({
        rootSessionId: 'root-life',
        goal: 'Holdout downgrade attempt',
        hostGoal: { goalId: 'goal-1', revision: 1, goal: 'Holdout downgrade attempt' },
        deliverables: [{ id: 'd-down2', kind: 'structured-frame-transform', holdoutRequired: false }],
      }),
      (err) => err.code === 'CONTRACT_DOWNGRADE_FORBIDDEN',
    );

    const created = runWorkspace(mgr, cfg, {
      workspace: {
        action: 'root-create',
        goal: 'Verify managed input lifecycle and multi-file binding',
        root: {
          deliverables: [{
            id: 'd1',
            kind: 'process-chain-transform',
            requiredObservations: ['static-locate', 'dynamic-runtime-observation', 'multi-process-lineage'],
            minDistinctInputs: 2,
            holdoutRequired: true,
          }],
          components: [
            { componentId: 'c-main', path: entryExe, role: 'main-pe' },
            { componentId: 'c-w1', path: worker1Exe, role: 'worker-pe' },
            { componentId: 'c-w2', path: worker2Exe, role: 'worker-pe' },
          ],
        },
      },
    }, { agent: rootAgent, hostGoal: { goalId: 'goal-life', revision: 1, goal: 'Verify managed input lifecycle and multi-file binding' } }).workspace;

    // Default propagation on host-goal bound deliverable: nonCooperativeRequired === true!
    assert.equal(created.deliverables[0].nonCooperativeRequired, true);

    const staticRec = artifacts.save({
      kind: 'managed-operation-receipt',
      action: 'ig5_open',
      operationId: 'op-static-life',
      tool: 'ig5_open',
      investigationId: created.rootId,
      outcome: 'success',
      result: { cleanArgsSummary: { path: entryExe }, outcome: 'success', replayOutput: { _ig5: { sha256: entrySha, target: entryExe } } },
    });
    rStore.recordSystemReceipt({ rootId: created.rootId, receiptRecord: staticRec, operation: { operationId: 'op-static-life' } });

    // Counterexample 1: Missing file WITHOUT sampleHex -> rejected at select; explore allowed with verifiableForDeliverable=false
    const missingPath = path.join(tmp, 'missing_no_hex.in');
    rStore.upsertScenario(created.rootId, {
      scenarioId: 's-missing-unplanned',
      componentId: 'c-main',
      args: [missingPath],
      cwd: tmp,
      inputSpec: { kind: 'file', filePath: missingPath, argIndex: 0, isHoldout: false },
    }, artifacts);
    assert.throws(
      () => rStore.selectExperiment(created.rootId, {
        kind: 'dynamic-breakpoint-read',
        scenarioId: 's-missing-unplanned',
        componentId: 'c-main',
        hypothesis: 'Should reject unplanned missing file',
      }, artifacts),
      (err) => err.code === 'SCENARIO_INPUT_UNVERIFIED_FOR_EXPERIMENT',
    );
    const exploreSel = rStore.selectExperiment(created.rootId, {
      kind: 'explore',
      scenarioId: 's-missing-unplanned',
      componentId: 'c-main',
      hypothesis: 'Exploratory run marks snapshot non-verifiable',
    }, artifacts);
    assert.equal(exploreSel.experiment.scenarioSnapshot.verifiableForDeliverable, false);

    // If file is created on disk AFTER ENOENT registration without sampleHex -> rejected until re-frozen via root-update!
    fs.writeFileSync(missingPath, Buffer.from('aa', 'hex'));
    assert.throws(
      () => rStore.selectExperiment(created.rootId, {
        kind: 'dynamic-breakpoint-read',
        scenarioId: 's-missing-unplanned',
        componentId: 'c-main',
        hypothesis: 'Must reject unfrozen post-registration file',
      }, artifacts),
      (err) => err.code === 'SCENARIO_INPUT_NOT_FROZEN',
    );

    // Counterexample 2: File modified on disk after registration (at select AND before dispatch)
    const modPath = path.join(tmp, 'mod_test.in');
    fs.writeFileSync(modPath, Buffer.from('112233', 'hex'));
    rStore.upsertScenario(created.rootId, {
      scenarioId: 's-mod',
      componentId: 'c-main',
      args: [modPath],
      cwd: tmp,
      inputSpec: { kind: 'file', filePath: modPath, argIndex: 0, isHoldout: false },
    }, artifacts);
    fs.writeFileSync(modPath, Buffer.from('ffeedd', 'hex'));
    assert.throws(
      () => rStore.selectExperiment(created.rootId, {
        kind: 'dynamic-breakpoint-read',
        scenarioId: 's-mod',
        componentId: 'c-main',
        hypothesis: 'Detect disk drift at select',
      }, artifacts),
      (err) => err.code === 'SCENARIO_INPUT_FILE_MODIFIED',
    );
    // Restore original bytes -> select succeeds -> modify before dispatch -> validateDispatchBinding rejects!
    fs.writeFileSync(modPath, Buffer.from('112233', 'hex'));
    const modSel = rStore.selectExperiment(created.rootId, {
      kind: 'dynamic-breakpoint-read',
      scenarioId: 's-mod',
      componentId: 'c-main',
      hypothesis: 'Detect disk drift before dispatch',
    }, artifacts);
    fs.writeFileSync(modPath, Buffer.from('998877', 'hex'));
    assert.throws(
      () => rStore.validateDispatchBinding({
        research: { ...modSel.researchBinding, key: 'mod-step-0', step: 0 },
        toolName: 'ig5_app_observe',
        action: 'ig5_app_observe:process_chain_scenario',
        cleanArgs: { target: entryExe, action: 'process_chain_scenario', args: [modPath], cwd: tmp },
      }),
      (err) => err.code === 'SCENARIO_INPUT_FILE_MODIFIED_BEFORE_DISPATCH',
    );

    // Counterexample 3: argv points to a different file than inputSpec.filePath -> rejected!
    const otherFile = path.join(tmp, 'other.in');
    fs.writeFileSync(otherFile, Buffer.from('0102', 'hex'));
    rStore.upsertScenario(created.rootId, {
      scenarioId: 's-wrong-argv',
      componentId: 'c-main',
      args: [otherFile],
      cwd: tmp,
      inputSpec: { kind: 'file', filePath: modPath, argIndex: 0, isHoldout: false },
    }, artifacts);
    assert.throws(
      () => rStore.selectExperiment(created.rootId, {
        kind: 'dynamic-breakpoint-read',
        scenarioId: 's-wrong-argv',
        componentId: 'c-main',
        hypothesis: 'Reject unbound argv file',
      }, artifacts),
      (err) => err.code === 'SCENARIO_INPUT_UNVERIFIED_FOR_EXPERIMENT',
    );

    // Counterexample 5: Declared sampleHex conflicts with file / input_files channel -> rejected!
    rStore.upsertScenario(created.rootId, {
      scenarioId: 's-conflict-disk',
      componentId: 'c-main',
      args: [otherFile],
      cwd: tmp,
      inputSpec: { kind: 'file', filePath: otherFile, argIndex: 0, sampleHex: 'deadbeef', isHoldout: false },
    }, artifacts);
    assert.throws(
      () => rStore.selectExperiment(created.rootId, {
        kind: 'dynamic-breakpoint-read',
        scenarioId: 's-conflict-disk',
        componentId: 'c-main',
        hypothesis: 'Reject sampleHex contradicting disk file',
      }, artifacts),
      (err) => err.code === 'SCENARIO_INPUT_CHANNEL_CONFLICT',
    );

    // Positive + Counterexample 4 & 7:
    // Discovery 1 via `prepareInputs` + multi-file `[decoy, real]` order
    // Discovery 2 via `planned-awaiting-materialization` (`sampleHex` before file exists) + multi-file `[real, decoy]` order
    const runSubDir = path.join(tmp, 'spool_run');
    const cfgFile = path.join(runSubDir, 'cfg.json');
    const disc1File = path.join(runSubDir, 'disc1.bin');
    const disc2File = path.join(runSubDir, 'disc2.bin');
    const holdFile = path.join(runSubDir, 'hold_unseen.bin');
    const cfgHex = Buffer.from('{"mode":1}', 'utf8').toString('hex');

    runWorkspace(mgr, cfg, {
      workspace: {
        action: 'root-update',
        id: created.rootId,
        root: {
          prepareInputs: [
            { path: cfgFile, hex: cfgHex },
            { path: disc1File, hex: '102030' },
          ],
          scenarios: [
            {
              scenarioId: 's-disc-1',
              componentId: 'c-main',
              launchMode: 'via-parent',
              args: ['--cfg', cfgFile, '--in', disc1File],
              cwd: runSubDir,
              inputSpec: { kind: 'file', filePath: disc1File, argIndex: 3, sampleHex: '102030', isHoldout: false },
            },
            {
              // disc2File does NOT exist on disk yet — planned-awaiting-materialization!
              scenarioId: 's-disc-2',
              componentId: 'c-main',
              launchMode: 'via-parent',
              args: ['--cfg', cfgFile, '--in', disc2File],
              cwd: runSubDir,
              inputSpec: { kind: 'file', filePath: disc2File, argIndex: 3, sampleHex: '41424344', isHoldout: false },
            },
          ],
        },
      },
    }, { agent: rootAgent });

    const makeLineage = (tag) => [
      { pid: 1000, parentPid: 100, creationIdentity: `c-${tag}-0`, sha256: entrySha, relationOrigin: 'win32-job-kernel-observed', exitCode: 0 },
      { pid: 1001, parentPid: 1000, creationIdentity: `c-${tag}-1`, sha256: w1Sha, relationOrigin: 'win32-job-kernel-observed', exitCode: 0 },
      { pid: 1002, parentPid: 1001, creationIdentity: `c-${tag}-2`, sha256: w2Sha, relationOrigin: 'win32-job-kernel-observed', exitCode: 0 },
    ];
    const xor55Hex = (hex) => Buffer.from(hex, 'hex').map((b) => b ^ 0x55).toString('hex');

    const selD1 = rStore.selectExperiment(created.rootId, {
      kind: 'dynamic-breakpoint-read',
      scenarioId: 's-disc-1',
      componentId: 'c-main',
      hypothesis: 'Multi-file order [cfg, payload]',
    }, artifacts);

    // Execute D1 with `[cfg, disc1]` order
    const execD1 = await runManagedToolExecution({
      mgr,
      toolName: 'ig5_app_observe',
      rawArgs: {
        action: 'process_chain_scenario',
        target: entryExe,
        args: ['--cfg', cfgFile, '--in', disc1File],
        cwd: runSubDir,
        input_files: [
          { path: cfgFile, hex: cfgHex },
          { path: disc1File, hex: '102030' },
        ],
        research: { ...selD1.researchBinding, key: 'd1-step-0', step: 0 },
      },
      execution: { agent: rootAgent },
      runCore: async (_args, _sig, { boundScenarioSnapshot }) => {
        assert.equal(boundScenarioSnapshot.inputChannel.filePath, disc1File);
        return {
          ok: true,
          action: 'process_chain_scenario',
          fixtureOnlyProtocol: false,
          runId: 'run-life-d1',
          target: entryExe,
          observedInputHex: '102030',
          inputChannelWitness: {
            kind: 'file',
            filePath: disc1File,
            sha256: sha256(Buffer.from('102030', 'hex')),
            byteLength: 3,
            consumptionProof: 'channel-delivered-prelaunch-verified-not-syscall-traced',
          },
          outputHex: xor55Hex('102030'),
          verifiedProcessLineage: makeLineage('d1'),
          cleanup: { cleanupVerified: true },
        };
      },
    });

    const selD2 = rStore.selectExperiment(created.rootId, {
      kind: 'dynamic-breakpoint-read',
      scenarioId: 's-disc-2',
      componentId: 'c-main',
      hypothesis: 'Planned file materialized at execution in reverse [payload, cfg] order',
    }, artifacts);
    assert.equal(selD2.experiment.scenarioSnapshot.inputProvenanceState, 'planned-awaiting-materialization');

    // Counterexample 5b: Passing wrong hex in `input_files` for planned file -> rejected BEFORE runCore!
    await assert.rejects(
      () => runManagedToolExecution({
        mgr,
        toolName: 'ig5_app_observe',
        rawArgs: {
          action: 'process_chain_scenario',
          target: entryExe,
          args: ['--cfg', cfgFile, '--in', disc2File],
          cwd: runSubDir,
          input_files: [{ path: disc2File, hex: 'ffffffff' }],
          research: { ...selD2.researchBinding, key: 'bad-mat', step: 0 },
        },
        execution: { agent: rootAgent },
        runCore: async () => { throw new Error('MUST NOT REACH runCore'); },
      }),
      (err) => err.code === 'SCENARIO_INPUT_CHANNEL_CONFLICT',
    );

    // Execute D2 with `[disc2, cfg]` order (reversed!)
    const execD2 = await runManagedToolExecution({
      mgr,
      toolName: 'ig5_app_observe',
      rawArgs: {
        action: 'process_chain_scenario',
        target: entryExe,
        args: ['--cfg', cfgFile, '--in', disc2File],
        cwd: runSubDir,
        input_files: [
          { path: disc2File, hex: '41424344' },
          { path: cfgFile, hex: cfgHex },
        ],
        research: { ...selD2.researchBinding, key: 'd2-step-0', step: 0 },
      },
      execution: { agent: rootAgent },
      runCore: async (_args, _sig, { boundScenarioSnapshot }) => {
        assert.equal(boundScenarioSnapshot.inputChannel.filePath, disc2File);
        fs.writeFileSync(disc2File, Buffer.from('41424344', 'hex'));
        return {
          ok: true,
          action: 'process_chain_scenario',
          fixtureOnlyProtocol: false,
          runId: 'run-life-d2',
          target: entryExe,
          observedInputHex: '41424344',
          inputChannelWitness: {
            kind: 'file',
            filePath: disc2File,
            sha256: sha256(Buffer.from('41424344', 'hex')),
            byteLength: 4,
            consumptionProof: 'channel-delivered-prelaunch-verified-not-syscall-traced',
          },
          outputHex: xor55Hex('41424344'),
          verifiedProcessLineage: makeLineage('d2'),
          cleanup: { cleanupVerified: true },
        };
      },
    });

    // Pre-commit variable-length XOR 0x55 frame rule BEFORE holdout!
    const outSpec = { kind: 'app-output', channel: 'process-chain', minByteLength: 1, maxByteLength: 32 };
    const rule = {
      schema: 'ig5-bounded-frame-rule-v1',
      headerHex: '',
      lengthField: { kind: 'none', bias: 0 },
      prevInit: 0,
      bodyByteExpr: { op: 'xor', args: [{ op: 'in', index: { op: 'i' } }, 0x55] },
      trailerChecksum: { kind: 'none', scope: 'body' },
    };
    rStore.submitCandidateExplanation(created.rootId, {
      deliverableId: 'd1',
      summary: 'XOR 0x55 per payload byte',
      outputSpec: outSpec,
      executableRule: rule,
    }, artifacts);

    // Register & execute unseen holdout (`hold_unseen.bin`, 5 bytes)
    rStore.upsertScenario(created.rootId, {
      scenarioId: 's-hold',
      componentId: 'c-main',
      launchMode: 'via-parent',
      args: ['--cfg', cfgFile, '--in', holdFile],
      cwd: runSubDir,
      inputSpec: { kind: 'file', filePath: holdFile, argIndex: 3, sampleHex: '0102030405', isHoldout: true },
    }, artifacts);
    const selHold = rStore.selectExperiment(created.rootId, {
      kind: 'holdout-verify',
      scenarioId: 's-hold',
      componentId: 'c-main',
      hypothesis: 'Unseen 5-byte holdout',
    }, artifacts);
    const execHold = await runManagedToolExecution({
      mgr,
      toolName: 'ig5_app_observe',
      rawArgs: {
        action: 'process_chain_scenario',
        target: entryExe,
        args: ['--cfg', cfgFile, '--in', holdFile],
        cwd: runSubDir,
        input_files: [
          { path: cfgFile, hex: cfgHex },
          { path: holdFile, hex: '0102030405' },
        ],
        research: { ...selHold.researchBinding, key: 'h-step-0', step: 0 },
      },
      execution: { agent: rootAgent },
      runCore: async () => ({
        ok: true,
        action: 'process_chain_scenario',
        fixtureOnlyProtocol: false,
        runId: 'run-life-hold',
        target: entryExe,
        observedInputHex: '0102030405',
        inputChannelWitness: {
          kind: 'file',
          filePath: holdFile,
          sha256: sha256(Buffer.from('0102030405', 'hex')),
          byteLength: 5,
          consumptionProof: 'channel-delivered-prelaunch-verified-not-syscall-traced',
        },
        outputHex: xor55Hex('0102030405'),
        verifiedProcessLineage: makeLineage('hold'),
        cleanup: { cleanupVerified: true },
      }),
    });

    // Counterexample 7: Delete ENTIRE `spool_run` temporary input directory AFTER execution receipts are committed!
    fs.rmSync(runSubDir, { recursive: true, force: true });
    assert.equal(fs.existsSync(disc1File), false);
    assert.equal(fs.existsSync(disc2File), false);
    assert.equal(fs.existsSync(holdFile), false);

    rStore.submitCandidateExplanation(created.rootId, {
      deliverableId: 'd1',
      testVectors: [
        { caseId: 'd1', receiptId: execD1._managedExecution.reportId, isHoldout: false },
        { caseId: 'd2', receiptId: execD2._managedExecution.reportId, isHoldout: false },
        { caseId: 'h1', receiptId: execHold._managedExecution.reportId, isHoldout: true },
      ],
    }, artifacts);

    const okAssess = assessRootInvestigation({ rootTask: rStore.get(created.rootId), mgr, execution: { agent: rootAgent } });
    assert.equal(okAssess.assessment, 'satisfied');
    assert.equal(okAssess.canCompleteHostGoal, true);

    // Counterexample 8: Tampering with `witnessBlobRef` bytes in artifact store -> rejected!
    const holdArt = artifacts.get(execHold._managedExecution.reportId);
    const witnessRef = holdArt.result.executionInputWitness.witnessBlobRef;
    const blobDiskPath = path.join(cfg.artifactDir, 'blobs', `${witnessRef.slice(7)}.bin`);
    const origBlobBytes = fs.readFileSync(blobDiskPath);
    fs.writeFileSync(blobDiskPath, Buffer.from('corrupted-witness-bytes', 'utf8'));
    const tamperedAssess = assessRootInvestigation({ rootTask: rStore.get(created.rootId), mgr, execution: { agent: rootAgent } });
    assert.equal(tamperedAssess.canCompleteHostGoal, false);
    assert(tamperedAssess.denialReasons.some((r) => r.includes('execution-input-witness-tampered') || r.includes('input-artifact-tampered')));
    // Restore untampered blob so Counterexample 6 tests pure holdout-borrowing rejection independently!
    fs.writeFileSync(blobDiskPath, origBlobBytes);

    // Counterexample 6: Submitting a DIFFERENT candidate rule revision AFTER holdout exposure and trying to reuse the consumed holdout receipt -> rejected!
    const tweakedRule = {
      ...rule,
      constants: { zero: '00' },
      bodyByteExpr: { op: 'add', args: [rule.bodyByteExpr, { op: 'const', name: 'zero', index: 0 }] },
    };
    rStore.submitCandidateExplanation(created.rootId, {
      deliverableId: 'd1',
      summary: 'Modified candidate rule trying to borrow already-exposed holdout',
      outputSpec: outSpec,
      executableRule: tweakedRule,
      testVectors: [
        { caseId: 'd1', receiptId: execD1._managedExecution.reportId, isHoldout: false },
        { caseId: 'd2', receiptId: execD2._managedExecution.reportId, isHoldout: false },
        { caseId: 'h1', receiptId: execHold._managedExecution.reportId, isHoldout: true },
      ],
    }, artifacts);
    const borrowedAssess = assessRootInvestigation({ rootTask: rStore.get(created.rootId), mgr, execution: { agent: rootAgent } });
    assert.equal(borrowedAssess.canCompleteHostGoal, false);
    assert(borrowedAssess.denialReasons.some((r) => r.includes('holdout-consumed-by-prior-candidate-revision') || r.includes('holdout-experiment-selected-before-candidate-commit') || r.includes('holdout-precedes-candidate-precommit')));
  } finally {
    await artifacts.dispose();
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('Negative-Case Legal Stopping Protocol: Broken Observer Rejection, Persistent Block Anti-Loop, and Host 3-Round Gate', async () => {
  const tmp = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), 'ig5-neg-stop-'));
  const cfg = { projectRoot: path.join(tmp, 'projects'), artifactDir: path.join(tmp, 'artifacts') };
  const artifacts = new AnalysisArtifacts(cfg.artifactDir);
  const rStore = new RootInvestigationStore({ projectRoot: cfg.projectRoot });
  const coord = new DelegationControl({ root: cfg.projectRoot });
  const mgr = { rootInvestigations: rStore, coordination: coord, analysis: { artifacts }, artifacts, sessions: new Map() };
  const rootAgent = { id: 'root-neg', session: { id: 'root-neg', header: { id: 'root-neg' } } };

  let liveGoalState = {
    id: 'goal-neg-1',
    revision: 1,
    objective: 'Audit multi-process pipeline',
    phase: 'active',
    activation: 'active',
    roundsStarted: 1,
    maxGoalRounds: 10,
  };
  const mockCtx = {
    on() { return () => {}; },
    get(svc) {
      if (svc === 'goals') return { get: () => liveGoalState };
      if (svc === 'agents') return { roots: () => [rootAgent], get: () => rootAgent };
      return undefined;
    },
  };
  const host = installAutonomyHost(mockCtx, { cfg, getManager: () => mgr });

  try {
    const entryExe = path.join(tmp, 'fake_coord.exe');
    const workerExe = path.join(tmp, 'unused_worker.exe');
    fs.writeFileSync(entryExe, makeSyntheticPe64WithBase(0x140000000n));
    fs.writeFileSync(workerExe, makeSyntheticPe64WithBase(0x140010000n));
    const entrySha = sha256(fs.readFileSync(entryExe));

    const created = rStore.create({
      rootSessionId: 'root-neg',
      goal: 'Audit multi-process pipeline',
      hostGoal: { goalId: 'goal-neg-1', revision: 1, goal: 'Audit multi-process pipeline' },
      deliverables: [{
        id: 'd-neg',
        kind: 'process-chain-transform',
        requiredObservations: ['static-locate', 'dynamic-runtime-observation', 'multi-process-lineage'],
      }],
    });
    rStore.registerComponent(created.rootId, { componentId: 'c-main', path: entryExe, role: 'main-pe' });
    rStore.registerComponent(created.rootId, { componentId: 'c-w1', path: workerExe, role: 'worker-pe' });
    rStore.upsertScenario(created.rootId, {
      scenarioId: 's-neg',
      componentId: 'c-main',
      args: ['4142'],
      cwd: tmp,
      inputSpec: { kind: 'cli-arg', argIndex: 0, encoding: 'hex', isHoldout: false },
    }, artifacts);

    const staticRec = artifacts.save({
      kind: 'managed-operation-receipt',
      action: 'ig5_decompile',
      operationId: 'op-neg-static',
      tool: 'ig5_decompile',
      investigationId: created.rootId,
      outcome: 'success',
      result: { cleanArgsSummary: { path: entryExe }, outcome: 'success', replayOutput: { _ig5: { sha256: entrySha, target: entryExe } } },
    });
    rStore.recordSystemReceipt({ rootId: created.rootId, receiptRecord: staticRec, operation: { operationId: 'op-neg-static' } });

    const selBroken = rStore.selectExperiment(created.rootId, {
      kind: 'dynamic-breakpoint-read',
      scenarioId: 's-neg',
      componentId: 'c-main',
      hypothesis: 'First run has truncated observer log',
    }, artifacts);
    const brokenDynRec = artifacts.save({
      kind: 'managed-operation-receipt',
      action: 'ig5_app_observe:process_chain_scenario',
      operationId: 'op-neg-broken',
      tool: 'ig5_app_observe',
      investigationId: created.rootId,
      experimentId: selBroken.experiment.expId,
      outcome: 'success',
      result: {
        cleanArgsSummary: { target: entryExe, action: 'process_chain_scenario' },
        outcome: 'success',
        replayOutput: {
          ok: true,
          action: 'process_chain_scenario',
          observerLogIntegrity: 'truncated',
          verifiedProcessLineage: [],
          cleanup: { cleanupVerified: true, enumerationStatus: 'enumeration-failed' },
        },
      },
    });
    rStore.recordSystemReceipt({ rootId: created.rootId, receiptRecord: brokenDynRec, operation: { operationId: 'op-neg-broken' } });

    // 1. Broken observer MUST NOT be accepted as negative contract falsification (either in terminalFinding or update_goal blocked)!
    assert.throws(
      () => rStore.submitTerminalFinding(created.rootId, {
        classification: 'contract-obligation-falsified',
        summary: 'Claiming worker absent from truncated log',
        receiptIds: [staticRec.id, brokenDynRec.id],
      }, artifacts),
      (err) => err.code === 'OBSERVER_FAILED_CANNOT_CLAIM_NEGATIVE',
    );
    liveGoalState.roundsStarted = 3;
    const brokenGate = host.beforePreExecute({
      name: 'update_goal',
      agent: rootAgent,
      arguments: { goal_id: 'goal-neg-1', revision: 1, action: 'blocked', blocked_reason: 'Target forged worker execution' },
    });
    assert.equal(brokenGate?.kind, 'deny');
    assert.match(brokenGate.reason, /OBSERVER_FAILED_CANNOT_CLAIM_NEGATIVE/);

    // 2. Healthy dynamic receipt proves entry ran cleanly with zero child spawns!
    const selHealthy = rStore.selectExperiment(created.rootId, {
      kind: 'dynamic-breakpoint-read',
      scenarioId: 's-neg',
      componentId: 'c-main',
      hypothesis: 'Healthy Job Object run',
    }, artifacts);
    const healthyDynRec = artifacts.save({
      kind: 'managed-operation-receipt',
      action: 'ig5_app_observe:process_chain_scenario',
      operationId: 'op-neg-healthy',
      tool: 'ig5_app_observe',
      investigationId: created.rootId,
      experimentId: selHealthy.experiment.expId,
      outcome: 'success',
      result: {
        cleanArgsSummary: { target: entryExe, action: 'process_chain_scenario' },
        outcome: 'success',
        replayOutput: {
          ok: true,
          action: 'process_chain_scenario',
          observerLogIntegrity: 'verified',
          verifiedProcessLineage: [
            { pid: 2000, parentPid: 100, creationIdentity: 'c-2000', sha256: entrySha, relationOrigin: 'win32-job-kernel-observed', exitCode: 0 },
          ],
          cleanup: { cleanupVerified: true, enumerationStatus: 'ok' },
        },
      },
    });
    rStore.recordSystemReceipt({ rootId: created.rootId, receiptRecord: healthyDynRec, operation: { operationId: 'op-neg-healthy' } });

    rStore.submitTerminalFinding(created.rootId, {
      classification: 'contract-obligation-falsified',
      summary: 'Decompilation and healthy kernel Job Object lineage both show fake_coord.exe never spawns unused_worker.exe',
      receiptIds: [staticRec.id, healthyDynRec.id],
    }, artifacts);

    // 3. Persistent block stops redundant selectExperiment churn!
    assert.throws(
      () => rStore.selectExperiment(created.rootId, {
        kind: 'dynamic-breakpoint-read',
        scenarioId: 's-neg',
        componentId: 'c-main',
        hypothesis: 'Redundant repeat after terminal finding',
      }, artifacts),
      (err) => err.code === 'PERSISTENT_BLOCK_ALREADY_ESTABLISHED',
    );

    // 4. Round 1 and Round 2 deny `update_goal(action="blocked")` cleanly with round-advancement instruction; Round 3 allows it!
    liveGoalState.roundsStarted = 1;
    const r1Assess = assessRootInvestigation({ rootTask: rStore.get(created.rootId), mgr, execution: { agent: rootAgent }, hostGoal: { ...liveGoalState, goalId: liveGoalState.id, goal: liveGoalState.objective, status: 'active' } });
    assert.equal(r1Assess.assessment, 'blocked');
    assert.equal(r1Assess.hostGoalRoundStatus.canCallHostBlockedNow, false);
    const r1Gate = host.beforePreExecute({
      name: 'update_goal',
      agent: rootAgent,
      arguments: { goal_id: 'goal-neg-1', revision: 1, action: 'blocked', blocked_reason: 'Worker execution falsified' },
    });
    assert.equal(r1Gate?.kind, 'deny');
    assert.match(r1Gate.reason, /HOST_GOAL_ROUND_THRESHOLD_NOT_MET/);

    liveGoalState.roundsStarted = 2;
    const r2Gate = host.beforePreExecute({
      name: 'update_goal',
      agent: rootAgent,
      arguments: { goal_id: 'goal-neg-1', revision: 1, action: 'blocked', blocked_reason: 'Worker execution falsified' },
    });
    assert.equal(r2Gate?.kind, 'deny');

    // Active debugger session still blocks `update_goal(action="blocked")` even in Round 3 until cleaned up!
    liveGoalState.roundsStarted = 3;
    mgr.sessions.set('dbg-open-1', { engine: 'x64dbg', target: entryExe, runtime: { state: 'suspended' } });
    const uncleanedGate = host.beforePreExecute({
      name: 'update_goal',
      agent: rootAgent,
      arguments: { goal_id: 'goal-neg-1', revision: 1, action: 'blocked', blocked_reason: 'Worker execution falsified' },
    });
    assert.equal(uncleanedGate?.kind, 'deny');
    assert.match(uncleanedGate.reason, /cleanup is still pending/);

    mgr.sessions.clear();
    const r3Gate = host.beforePreExecute({
      name: 'update_goal',
      agent: rootAgent,
      arguments: { goal_id: 'goal-neg-1', revision: 1, action: 'blocked', blocked_reason: 'Worker execution falsified' },
    });
    assert.equal(r3Gate, undefined);

    // 5. If active goal changes to a goal WITHOUT a bound rootTask in an IG5-managed session, `blocked` is denied until bound!
    liveGoalState = {
      id: 'goal-unbound-neg',
      revision: 1,
      objective: 'Audit unbound goal',
      phase: 'active',
      activation: 'active',
      roundsStarted: 3,
      maxGoalRounds: 10,
    };
    const unboundBlockedGate = host.beforePreExecute({
      name: 'update_goal',
      agent: rootAgent,
      arguments: { goal_id: 'goal-unbound-neg', revision: 1, action: 'blocked', blocked_reason: 'Unbound block attempt' },
    });
    assert.equal(unboundBlockedGate?.kind, 'deny');
    assert.match(unboundBlockedGate.reason, /no bound IG5 root investigation/);

    // 6. JS_APP_DIR code identity ignores mutable runtime cache `.json` files while detecting `package.json` / `.js` edits,
    //    and `root-update` `deliverables` upgrades default `io-transform` -> `structured-frame-transform` with anti-downgrade!
    const jsAppDir = path.join(tmp, 'js-app-ident');
    fs.mkdirSync(jsAppDir, { recursive: true });
    fs.writeFileSync(path.join(jsAppDir, 'package.json'), '{"name":"ident","main":"main.js"}', 'utf8');
    fs.writeFileSync(path.join(jsAppDir, 'main.js'), 'console.log(1);', 'utf8');
    const upRoot = runWorkspace(mgr, cfg, {
      workspace: { action: 'root-create', goal: 'Upgrade deliverable test', root: { component: { componentId: 'c-js', path: jsAppDir, role: 'electron-app' } } },
    }, { agent: rootAgent, hostGoal: { goalId: 'goal-up', revision: 1, goal: 'Upgrade deliverable test' } }).workspace;
    assert.equal(upRoot.deliverables[0].kind, 'io-transform');

    // Runtime writes `recent_frames.json` inside `jsAppDir` -> component SHA-256 MUST remain intact!
    fs.writeFileSync(path.join(jsAppDir, 'recent_frames.json'), '{"4142":"deadbeef"}', 'utf8');
    const upgraded = runWorkspace(mgr, cfg, {
      workspace: {
        action: 'root-update',
        id: upRoot.rootId,
        root: {
          deliverables: [{
            id: 'deliv-primary',
            kind: 'structured-frame-transform',
            requiredObservations: ['static-locate', 'dynamic-runtime-observation', 'parent-to-helper-handoff', 'non-cooperative-ui-trigger'],
          }],
        },
      },
    }, { agent: rootAgent, hostGoal: { goalId: 'goal-up', revision: 1, goal: 'Upgrade deliverable test' } }).workspace;
    assert.equal(upgraded.task.deliverables[0].kind, 'structured-frame-transform');
    assert.equal(upgraded.task.deliverables[0].nonCooperativeRequired, true);
    assert.throws(
      () => rStore.upsertDeliverable(upRoot.rootId, { id: 'deliv-primary', nonCooperativeRequired: false }),
      (err) => err.code === 'CONTRACT_DOWNGRADE_FORBIDDEN',
    );
    assert.throws(
      () => rStore.upsertDeliverable(upRoot.rootId, { id: 'deliv-primary', requiredObservations: ['static-locate'] }),
      (err) => err.code === 'CONTRACT_DOWNGRADE_FORBIDDEN',
    );
  } finally {
    host.dispose();
    await artifacts.dispose();
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});
