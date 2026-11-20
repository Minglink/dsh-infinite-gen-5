import { createCaptureService } from './source/capture_service.js';
import { inspectCapturePayload, materializeCapturePayload } from './source/capture_payload.js';
import { buildCaptureStateTrace } from './source/capture_state_trace.js';
import { correlateCaptureTraffic } from './source/traffic_correlate.js';
import { NativeAppObserver } from './source/native_rea_bridge.js';
import {
  AndroidDynamicProvider,
  probeAndroidCapabilityClosure,
  diagnoseAndroidSymptom,
  repackAndSignOwnedFixtureApk,
  verifyOrRepairDexIntegrity,
  inspectApkNativeLibraryMembership,
} from './source/native_android_bridge.js';
import fs from 'node:fs';

export function defineCaptureTools(ctx, mgr, cfg, render) {
  mgr.capture ??= createCaptureService(mgr, cfg);
  mgr.appObserver ??= new NativeAppObserver(cfg);
  mgr.androidProvider ??= new AndroidDynamicProvider(cfg);
  const output = { schema: { type: 'object', additionalProperties: true },
    render: render || ((_args, value) => [{ type: 'text', text: JSON.stringify(value) }]) };
  const identity = { id: { type: 'string' },
    session_id: { type: 'string' } };
  const trace = { type: 'object', properties: { id: { type: 'string', maxLength: 64 }, session_id: identity.session_id,
    start: { type: 'string', enum: ['session-start', 'unknown'] },
    complete: { type: 'boolean' },
    ids: { type: 'array', minItems: 1, maxItems: 128, items: identity.id } }, required: ['id', 'session_id', 'start', 'complete', 'ids'], additionalProperties: false };
  const symbol = fallback => ({ type: 'object', properties: { source: { type: 'string', enum: [fallback, 'body-field'] },
    offset: { type: 'integer', minimum: 0, maximum: 1048575 }, size: { type: 'integer', minimum: 1, maximum: 8 } }, required: ['source'], additionalProperties: false });

  const uiActionSchema = {
    type: 'object',
    properties: {
      op: { type: 'string', enum: ['fill', 'select', 'click', 'read-dom'] },
      selector: { type: 'string', maxLength: 256 },
      value: { type: 'string', maxLength: 1024 },
      property: { type: 'string', enum: ['textContent', 'value'] },
      ignorePlaceholder: { type: 'string', maxLength: 256 },
    },
    required: ['op', 'selector'],
    additionalProperties: false,
  };

  const androidProbeSpecSchema = {
    type: 'object',
    properties: {
      layer: { type: 'string', enum: ['java', 'jni'] },
      className: { type: 'string', maxLength: 256 },
      methodName: { type: 'string', maxLength: 128 },
      library: { type: 'string', maxLength: 128 },
      symbol: { type: 'string', maxLength: 256 },
      offset: { type: 'string', maxLength: 32 },
      argByteArrayIndex: { type: 'integer', minimum: 0, maximum: 8 },
      returnIsByteArray: { type: 'boolean' },
    },
    required: ['layer'],
    additionalProperties: false,
  };

  return [
    { name: 'ig5_capture', description: 'Read-only HTTP/HTTPS/WS proxy evidence: status, list, get, export, review, inspect_payload, materialize, state_trace, or correlate.',
      parameters: { type: 'object', properties: { action: { type: 'string', enum: ['status', 'list', 'get', 'export', 'review', 'inspect_payload', 'materialize', 'state_trace', 'correlate'] }, ...identity,
        sample: { type: 'object', properties: { path: { type: 'string', maxLength: 4096 },
          sha256: { type: 'string' } }, required: ['path'], additionalProperties: false },
        traces: { type: 'array', minItems: 1, maxItems: 32, items: trace },
        holdout: { type: 'array', maxItems: 32, items: trace },
        symbols: { type: 'object', properties: { request: symbol('http-route'), response: symbol('http-status') }, additionalProperties: false },
        offset: { type: 'integer', minimum: 0, maximum: 1000000 }, limit: { type: 'integer', minimum: 1, maximum: 100 },
        body: { type: 'string', enum: ['request', 'response'] } }, required: ['action'], additionalProperties: false }, output,
      execute(args = {}) {
        if (args.action === 'status') return mgr.capture.status();
        if (args.action === 'list') return mgr.capture.list(args);
        if (args.action === 'get') return mgr.capture.get(args.id, args);
        if (args.action === 'export') return mgr.capture.export(args);
        if (args.action === 'review') return mgr.capture.review(args);
        if (args.action === 'inspect_payload') return inspectCapturePayload(mgr.capture, args);
        if (args.action === 'materialize') return materializeCapturePayload(mgr.capture, args);
        if (args.action === 'state_trace') return buildCaptureStateTrace(mgr.capture, args);
        if (args.action === 'correlate') return correlateCaptureTraffic(mgr.capture, args);
        throw Object.assign(new Error('Capture action must be status, list, get, export, review, inspect_payload, materialize, state_trace or correlate'), { code: 'CAPTURE_INVALID_INPUT' });
      } },
    { name: 'ig5_capture_control', description: 'APPROVAL REQUIRED. Start/stop loopback HTTP/HTTPS/WS proxy or replay one saved request.',
      parameters: { type: 'object', properties: { action: { type: 'string', enum: ['start', 'stop', 'replay'] }, ...identity,
        port: { type: 'integer', minimum: 0, maximum: 65535 },
        scope: { type: 'array', minItems: 1, maxItems: 32, items: { type: 'string', maxLength: 2048 } },
        tls: { type: 'boolean' },
        request: { type: 'object', properties: {
          method: { type: 'string', maxLength: 32 }, path: { type: 'string', maxLength: 8192 },
          headers: { type: 'object', additionalProperties: { type: 'string', maxLength: 8192 } },
          body: { type: 'object', properties: { encoding: { type: 'string', enum: ['hex', 'base64'] }, data: { type: 'string', maxLength: 2097152 } }, required: ['encoding', 'data'], additionalProperties: false },
        }, additionalProperties: false } }, required: ['action'], additionalProperties: false }, output,
      execute: (args, execution) => mgr.capture.control(args, execution) },
    {
      name: 'ig5_app_observe',
      description: 'APPROVAL REQUIRED. Run/inspect owned multi-component Win32 Job Object scenarios (Electron/process-chain) or managed Android ADB/Frida sessions.',
      parameters: {
        type: 'object',
        properties: {
          action: {
            type: 'string',
            enum: [
              'electron_scenario',
              'process_chain_scenario',
              'start',
              'stop',
              'status',
              'android_probe',
              'android_session_start',
              'android_session_poll',
              'android_session_stop',
            ],
          },
          target: { type: 'string', maxLength: 4096 },
          scenario_mode: { type: 'string', enum: ['discover', 'execute'] },
          trigger_mode: { type: 'string', enum: ['ui-click', 'ipc-invoke', 'headless-ipc'] },
          ui_actions: { type: 'array', minItems: 1, maxItems: 16, items: uiActionSchema },
          bridge_global: { type: 'string', maxLength: 128 },
          bridge_method: { type: 'string', maxLength: 128 },
          payload: { type: 'string', maxLength: 1024 },
          input_encoding: { type: 'string', enum: ['hex', 'utf8', 'ascii'] },
          args: { type: 'array', maxItems: 32, items: { type: 'string', maxLength: 512 } },
          cwd: { type: 'string', maxLength: 4096 },
          stdin_hex: { type: 'string', pattern: '^([0-9a-fA-F]{2}){0,4096}$' },
          input_files: {
            type: 'array',
            maxItems: 8,
            items: {
              type: 'object',
              properties: { path: { type: 'string', maxLength: 512 }, hex: { type: 'string', pattern: '^([0-9a-fA-F]{2}){1,4096}$' } },
              required: ['path', 'hex'],
              additionalProperties: false,
            },
          },
          output_channel: {
            type: 'object',
            properties: {
              kind: { type: 'string', enum: ['dom', 'ipc-return', 'child-stdout', 'file', 'stdout-hex', 'stdout-bytes', 'stdout-regex', 'file-bytes', 'file-hex'] },
              selector: { type: 'string', maxLength: 256 },
              path: { type: 'string', maxLength: 512 },
              pattern: { type: 'string', maxLength: 256 },
            },
            required: ['kind'],
            additionalProperties: false,
          },
          payload_hex: { type: 'string', pattern: '^([0-9a-fA-F]{2}){1,256}$' },
          corr_id: { type: 'string', maxLength: 64 },
          bypass_cache: { type: 'boolean' },
          restart_worker1: { type: 'boolean' },
          legacy_fixture_protocol: { type: 'boolean' },
          electron_binary: { type: 'string', maxLength: 4096 },
          hold_ms: { type: 'integer', minimum: 500, maximum: 60000 },
          timeout_ms: { type: 'integer', minimum: 500, maximum: 120000 },
          symptom_code: { type: 'string', maxLength: 64 },
          output_apk_path: { type: 'string', maxLength: 4096 },
          device_serial: { type: 'string', maxLength: 128 },
          package_name: { type: 'string', maxLength: 256 },
          attach_mode: { type: 'string', enum: ['spawn', 'attach'] },
          attach_pid: { type: 'integer', minimum: 1 },
          probe_specs: { type: 'array', minItems: 1, maxItems: 16, items: androidProbeSpecSchema },
          trigger_component: { type: 'string', maxLength: 256 },
          trigger_action: { type: 'string', maxLength: 256 },
          trigger_extras: { type: 'object', additionalProperties: { type: 'string', maxLength: 512 } },
        },
        required: ['action'],
        additionalProperties: false,
      },
      output,
      async execute(args = {}, execution = null) {
        const signal = execution?.signal || null;
        const callerId = execution?.agent?.id || 'local';
        if (args.action === 'electron_scenario') {
          if (!args.target) throw Object.assign(new Error('electron_scenario requires target'), { code: 'INVALID_ARGUMENT' });
          return mgr.appObserver.runElectronScenario({
            target: args.target,
            scenarioMode: args.scenario_mode || 'execute',
            payload: args.payload ?? null,
            inputEncoding: args.input_encoding ?? null,
            uiActions: args.ui_actions ?? null,
            bridgeGlobal: args.bridge_global ?? null,
            bridgeMethod: args.bridge_method ?? null,
            outputChannel: args.output_channel ?? null,
            bypassCache: Boolean(args.bypass_cache),
            triggerMode: args.trigger_mode || 'ui-click',
            legacyFixtureProtocol: Boolean(args.legacy_fixture_protocol),
            timeoutMs: args.timeout_ms || 30_000,
            electronExe: args.electron_binary || null,
            signal,
          });
        }
        if (args.action === 'process_chain_scenario') {
          if (!args.target) throw Object.assign(new Error('process_chain_scenario requires target'), { code: 'INVALID_ARGUMENT' });
          return mgr.appObserver.runProcessChainScenario({
            target: args.target,
            args: args.args ?? null,
            cwd: args.cwd ?? null,
            stdinHex: args.stdin_hex ?? null,
            inputFiles: args.input_files ?? null,
            outputChannel: args.output_channel ?? null,
            declaredInputChannel: execution?._boundScenarioSnapshot?.inputChannel ?? null,
            payloadHex: args.payload_hex ?? null,
            corrId: args.corr_id ?? null,
            restartWorker1: Boolean(args.restart_worker1),
            legacyFixtureProtocol: Boolean(args.legacy_fixture_protocol),
            timeoutMs: args.timeout_ms || 20_000,
            signal,
          });
        }
        if (args.action === 'start') {
          if (!args.target) throw Object.assign(new Error('start requires target'), { code: 'INVALID_ARGUMENT' });
          return mgr.appObserver.startHeldChainSession({
            target: args.target,
            args: args.args ?? null,
            payloadHex: args.payload_hex || '41424344',
            holdMs: args.hold_ms || 30_000,
          });
        }
        if (args.action === 'stop') {
          if (!args.target) throw Object.assign(new Error('stop requires target'), { code: 'INVALID_ARGUMENT' });
          return mgr.appObserver.stopHeldChainSession({ target: args.target, disposition: 'STOP' });
        }
        if (args.action === 'status') {
          return {
            ...mgr.appObserver.status(),
            activeAndroidSessions: mgr.androidProvider.status(),
          };
        }
        if (args.action === 'android_probe') {
          const closure = probeAndroidCapabilityClosure({ timeoutMs: args.timeout_ms || 8_000, cfg });
          const dynamicReadiness = mgr.androidProvider.probeReadiness({ deviceSerial: args.device_serial || null, timeoutMs: args.timeout_ms || 8_000 });
          const symptom = args.symptom_code ? diagnoseAndroidSymptom(args.symptom_code) : null;
          let dexCheck = null;
          let apkMembership = null;
          let repackResult = null;
          if (args.target && args.target.toLowerCase().endsWith('.dex') && fs.existsSync(args.target)) {
            dexCheck = verifyOrRepairDexIntegrity(fs.readFileSync(args.target));
          } else if (args.target && args.target.toLowerCase().endsWith('.apk') && fs.existsSync(args.target)) {
            apkMembership = inspectApkNativeLibraryMembership(args.target, { cfg });
            if (args.output_apk_path) {
              repackResult = repackAndSignOwnedFixtureApk({
                inputApkPath: args.target,
                outputApkPath: args.output_apk_path,
                timeoutMs: args.timeout_ms || 30_000,
                cfg,
              });
            }
          }
          return {
            ok: true,
            action: 'android_probe',
            closure,
            dynamicReadiness,
            apkMembership,
            symptom,
            dexCheck,
            repackResult,
          };
        }
        if (args.action === 'android_session_start') {
          return mgr.androidProvider.startSession({
            deviceSerial: args.device_serial,
            packageName: args.package_name,
            apkPath: args.target,
            mode: args.attach_mode || 'spawn',
            attachPid: args.attach_pid ?? null,
            probeSpecs: args.probe_specs,
            timeoutMs: args.timeout_ms || 30_000,
            ownerAgentId: callerId,
            signal,
          });
        }
        if (args.action === 'android_session_poll') {
          return mgr.androidProvider.pollOrTriggerSession({
            deviceSerial: args.device_serial,
            packageName: args.package_name,
            triggerComponent: args.trigger_component ?? null,
            triggerAction: args.trigger_action ?? null,
            triggerExtras: args.trigger_extras ?? null,
            ownerAgentId: callerId,
          });
        }
        if (args.action === 'android_session_stop') {
          return mgr.androidProvider.stopSession({
            deviceSerial: args.device_serial,
            packageName: args.package_name,
            ownerAgentId: callerId,
            disposition: 'STOP',
          });
        }
        throw Object.assign(new Error('Unsupported ig5_app_observe action'), { code: 'INVALID_ARGUMENT' });
      },
    },
  ];
}
