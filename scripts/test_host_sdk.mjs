// Isolated compatibility checks against actual services shipped in a DSH app.asar.
// This never starts DSH or an analysis/debug worker and never changes its profile.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import childProcess from 'node:child_process';
import { builtinModules, syncBuiltinESMExports } from 'node:module';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { createHash, randomUUID } from 'node:crypto';
import vm from 'node:vm';

function option(name, fallback) {
  const index = process.argv.indexOf(name);
  if (index < 0) return fallback;
  assert(process.argv[index + 1] && !process.argv[index + 1].startsWith('--'), `${name} needs a value`);
  return process.argv[index + 1];
}
const here = path.dirname(fileURLToPath(import.meta.url));
const pluginRoot = path.resolve(option('--plugin-root', process.env.IG5_PLUGIN_UNDER_TEST || path.join(here, '..')));
const asar = path.resolve(option('--asar', process.env.IG5_TEST_ASAR || path.join(process.env.LOCALAPPDATA || '', 'Programs', 'DeepSeek Harness', 'resources', 'app.asar')));
const reportRoot = path.resolve(option('--evidence', process.env.IG5_SDK_EVIDENCE || path.join(os.tmpdir(), `ig5-host-sdk-${randomUUID()}`)));
assert(fs.statSync(asar).isFile(), 'A real DSH app.asar is required; this check must not silently skip');
assert(fs.statSync(path.join(pluginRoot, 'index.js')).isFile(), 'IG5 plugin entry is required');
assert(reportRoot !== pluginRoot && !reportRoot.startsWith(pluginRoot + path.sep), 'Evidence must be outside the plugin under test');
fs.mkdirSync(reportRoot, { recursive: true });
const sdkRoot = fs.mkdtempSync(path.join(reportRoot, 'sdk-'));
const runRoot = fs.mkdtempSync(path.join(reportRoot, 'isolated-profile-'));
const fd = fs.openSync(asar, 'r');
const first = Buffer.alloc(8); fs.readSync(fd, first, 0, 8, 0);
const headerSize = first.readUInt32LE(4);
assert(headerSize > 8 && headerSize <= 16 * 1024 * 1024, 'ASAR header budget');
const header = Buffer.alloc(headerSize); fs.readSync(fd, header, 0, header.length, 8);
const inventory = JSON.parse(header.subarray(8, 8 + header.readUInt32LE(4)).toString());
const entry = filename => filename.split('/').reduce((node, part) => node?.files?.[part], inventory);
let copiedBytes = 0, copiedFiles = 0;
function read(filename) {
  const info = entry(filename);
  assert(info && !info.files && !info.unpacked && Number.isSafeInteger(info.size), `Packed SDK file required: ${filename}`);
  copiedBytes += info.size; copiedFiles++;
  assert(copiedBytes <= 128 * 1024 * 1024 && copiedFiles <= 8192, 'SDK extraction budget');
  const bytes = Buffer.alloc(info.size);
  assert.equal(fs.readSync(fd, bytes, 0, bytes.length, 8 + headerSize + Number(info.offset)), bytes.length);
  return bytes;
}
const application = JSON.parse(read('package.json'));
// DSH compatibility preflight reads the app-boot package identity, which can
// differ from an Electron wrapper or a community build's display version.
const appBoot = JSON.parse(read('dsh/node_modules/@deepseek-ai/dsh-app-boot/package.json'));
const runtimeVersion = appBoot.version;
const bootSourcePath = 'dsh/node_modules/@deepseek-ai/dsh-app-boot/lib/index.js';
const bootBytes = read(bootSourcePath), bootCode = bootBytes.toString();
const bootEvidencePath = path.join(sdkRoot, 'host-compatibility', 'app-boot-index.js');
fs.mkdirSync(path.dirname(bootEvidencePath), { recursive: true }); fs.writeFileSync(bootEvidencePath, bootBytes);
const copied = new Set(), native = new Set(builtinModules.flatMap(name => [name, `node:${name}`]));
const sdkVersions = {};
function copyPackage(name) {
  if (copied.has(name) || native.has(name) || name.startsWith('node:')) return;
  copied.add(name);
  const source = `dsh/node_modules/${name}`, root = entry(source);
  assert(root?.files, `Installed SDK dependency absent: ${name}`);
  const dependencies = new Set();
  function walk(node, relative = '') {
    for (const [basename, info] of Object.entries(node.files || {})) {
      const filename = relative + basename;
      if (info.files) walk(info, `${filename}/`);
      else if (/\.(?:js|mjs|cjs|json)$/.test(filename)) {
        const bytes = read(`${source}/${filename}`), destination = path.resolve(sdkRoot, 'node_modules', name, filename);
        assert(destination.startsWith(sdkRoot + path.sep), 'SDK copy must remain within evidence');
        fs.mkdirSync(path.dirname(destination), { recursive: true }); fs.writeFileSync(destination, bytes);
        if (filename === 'package.json') {
          const metadata = JSON.parse(bytes);
          if (metadata.name === name) sdkVersions[name] = metadata.version;
        }
        if (/\.(?:js|mjs|cjs)$/.test(filename)) {
          for (const match of bytes.toString().matchAll(/(?:^|\n)\s*(?:import|export)[^;\n]*?\bfrom\s*["']([^"']+)["']|(?:^|\n)\s*import\s*["']([^"']+)["']|\brequire\(["']([^"']+)["']\)/g)) {
            const dependency = match[1] || match[2] || match[3];
            if (!dependency.startsWith('.') && !dependency.startsWith('/') && !native.has(dependency) && !dependency.startsWith('node:')) {
              dependencies.add(dependency.startsWith('@') ? dependency.split('/').slice(0, 2).join('/') : dependency.split('/')[0]);
            }
          }
        }
      }
    }
  }
  walk(root);
  for (const dependency of dependencies) copyPackage(dependency);
}
const requiredPackages = ['@deepseek-ai/cordis', '@deepseek-ai/dsh-tools', '@deepseek-ai/dsh-system-prompt', '@deepseek-ai/dsh-scope', '@deepseek-ai/dsh-skill', '@deepseek-ai/dsh-commands', '@deepseek-ai/dsh-session-projection', 'semver', '@deepseek-ai/dsh-client-ui-slots'];
const frontendContracts = [];
try {
  for (const name of requiredPackages) copyPackage(name);
  for (const [name, filename, symbols] of [
    ['dsh-client-ui-conversation', 'client.js', ['conversation.view', 'conversation.input.dock', 'openView', 'inputActions', 'captureInsertion', 'insertText']],
    ['dsh-client-ui-sidebar', 'client.js', ['sidebar.panellist']],
    ['dsh-client-ui-layout', 'client.js', ['main']],
    ['dsh-client-modules', 'index.js', ['__ModuleLoader__', 'factory']],
  ]) {
    const source = `dsh/node_modules/@deepseek-ai/${name}/lib/${filename}`, bytes = read(source);
    for (const symbol of symbols) assert(bytes.includes(Buffer.from(symbol)), `Actual frontend SDK contract absent: ${name} ${symbol}`);
    const destination = path.join(sdkRoot, 'frontend-contracts', `${name}-${filename}`);
    fs.mkdirSync(path.dirname(destination), { recursive: true }); fs.writeFileSync(destination, bytes);
    frontendContracts.push({ source, bytes: bytes.length, sha256: createHash('sha256').update(bytes).digest('hex'), symbols, destination, verification: 'Static symbols in actual installed bundle; browser interactions are verified separately' });
  }
} finally { fs.closeSync(fd); }
const load = name => {
  const directory = path.join(sdkRoot, 'node_modules', name), metadata = JSON.parse(fs.readFileSync(path.join(directory, 'package.json'), 'utf8'));
  return import(pathToFileURL(path.join(directory, metadata.main || 'index.js')).href);
};
const [{ Context, Service }, { default: Tools }, { default: SystemPrompt }, { createScope }, { default: Skills }, { default: Commands }, { default: Projections }, semverModule, { SlotCore }] = await Promise.all(requiredPackages.map(load));
const semver = semverModule.default || semverModule;
const metadata = JSON.parse(fs.readFileSync(path.join(pluginRoot, 'package.json'), 'utf8'));
const declaredPeers = Object.entries(metadata.peerDependencies || {}).filter(([name]) => name === '@deepseek-ai/dsh' || name.startsWith('@deepseek-ai/dsh-'));
assert(semver.valid(runtimeVersion), 'Real app-boot runtime version must be semantic');
for (const [name, range] of declaredPeers) assert(semver.satisfies(runtimeVersion, range, { includePrerelease: true }), `Actual DSH ${runtimeVersion} does not satisfy ${name} ${range}`);
function extractedFunction(name) {
  const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const match = bootCode.match(new RegExp(`^function ${escaped}\\([\\s\\S]*?^\\}`, 'm'));
  assert(match, `Actual app-boot compatibility helper is absent: ${name}`);
  return match[0];
}
const evaluatorSource = extractedFunction('evaluatePluginCompatibility');
const objectHelper = /const fields = (objectOf(?:\$\d+)?)\(/.exec(evaluatorSource)?.[1];
assert(objectHelper, 'Actual evaluator object validator must be identified');
const compatibilityFunctions = [extractedFunction(objectHelper), extractedFunction('runtimeVersionOf'), extractedFunction('identityField'), evaluatorSource];
// Execute verbatim installed evaluator functions in an isolated VM. Inject
// the real SDK semver and supply the version explicitly; boot dependencies and
// application startup are not imported by this check.
const evaluateCompatibility = vm.runInNewContext(`${compatibilityFunctions.join('\n')}\nevaluatePluginCompatibility`, { semver, getDshRuntimeVersion: () => runtimeVersion });
assert.equal(evaluateCompatibility(metadata, {}, runtimeVersion), undefined);
const compatibilityMatrix = [];
if (declaredPeers.length) {
  assert.equal(metadata.peerDependenciesMeta?.['@deepseek-ai/dsh']?.optional, true, 'Host peer must be optional to avoid implicit host installation');
  for (const [version, expected] of [
    [runtimeVersion, true], ['0.2.0-rc.1', true], ['0.2.0-rc.2', true], ['0.2.1-alpha.1', true], ['0.2.1-alpha.2', true], ['0.2.1', true],
    ['0.1.7-rc.2', false], ['0.1.9', false], ['0.3.0-alpha.1', false], ['0.3.0', false], ['0.3.1', false],
  ]) {
    const accepted = evaluateCompatibility(metadata, {}, version) === undefined;
    compatibilityMatrix.push({ version, expected, accepted });
    assert.equal(accepted, expected, `Actual installed app-boot evaluator boundary ${version}`);
  }
}
const compatibility = { verification: 'Verbatim functions extracted from actual installed app-boot, called with actual SDK semver; not a full boot-module import', source: bootSourcePath, evidencePath: bootEvidencePath, sha256: createHash('sha256').update(bootBytes).digest('hex'), helperNames: [objectHelper, 'runtimeVersionOf', 'identityField', 'evaluatePluginCompatibility'], runtimeVersionOrigin: `${appBoot.name}/package.json`, peerConstraintPresent: !!declaredPeers.length, matrix: compatibilityMatrix };
const writeNames = ['ig5_rename', 'ig5_patch_bytes', 'ig5_comment', 'ig5_analyze', 'ig5_set_type', 'ig5_undo', 'ig5_run_idapython', 'ig5_dbg', 'ig5_struct', 'ig5_switch_repair', 'ig5_emulate', 'ig5_sync'];
const blockedProcesses = [], processIdentityQueries = [], originals = new Map();
for (const name of ['spawn', 'exec', 'execFile', 'fork', 'spawnSync', 'execSync', 'execFileSync']) {
  originals.set(name, childProcess[name]);
  childProcess[name] = (...args) => {
    const identityArguments = ['-NoLogo', '-NoProfile', '-NonInteractive', '-Command', `(Get-Process -Id ${process.pid} -ErrorAction Stop).StartTime.ToUniversalTime().Ticks.ToString()`];
    // The project metadata lock uses this exact read-only query for this test
    // process's OS creation identity. Permit it without allowing any worker,
    // other executable, process mutation, or arbitrary PowerShell command.
    if (name === 'execFileSync' && args[0] === 'powershell.exe' && JSON.stringify(args[1]) === JSON.stringify(identityArguments) && args[2]?.windowsHide === true && args[2]?.timeout === 5000) {
      processIdentityQueries.push({ pid: process.pid, kind: 'own-process-creation-identity', windowsHide: true });
      return originals.get(name)(...args);
    }
    blockedProcesses.push(name); throw new Error('Isolated SDK check forbids analysis/debug workers and arbitrary child processes');
  };
}
syncBuiltinESMExports();
const assertions = [], approvals = [], commandEvents = [], outputFailures = [], preCalls = [];
let context, owner, approvalOwner, approvalOutcome = 'rejected';
function pass(description) { assertions.push(description); console.log(`PASS ${description}`); }
function minimal(schema) {
  if (schema.const !== undefined) return schema.const;
  if (schema.enum) return schema.enum[0];
  if (schema.oneOf) return minimal(schema.oneOf[0]);
  if (schema.type === 'object') return Object.fromEntries((schema.required || []).map(name => [name, minimal(schema.properties[name])]));
  if (schema.type === 'array') return [];
  if (schema.type === 'number' || schema.type === 'integer') return 0;
  if (schema.type === 'boolean') return false;
  if (schema.type === 'null') return null;
  return 'sdk-test';
}
function nonJsonPaths(value, location = '$', found = []) {
  if (value === undefined || typeof value === 'bigint' || typeof value === 'function' || typeof value === 'symbol' || typeof value === 'number' && !Number.isFinite(value)) found.push({ location, type: typeof value });
  else if (value && typeof value === 'object') for (const [key, item] of Object.entries(value)) nonJsonPaths(item, `${location}.${key}`, found);
  return found;
}
try {
  const slots = new SlotCore(), slotDisposers = [];
  const declare = slots.register({ name: 'root', children: { 'conversation.input.dock': { kind: 'list', scope: 'session' }, 'conversation.view': { kind: 'list', scope: 'session' }, 'sidebar.panellist': { kind: 'list', scope: 'root' }, main: { kind: 'keyed', scope: 'root' } } }, () => null);
  let client;
  const sandbox = {
    // Component functions are registered, never rendered here. React rendering
    // is a separate browser check; this placeholder only supplies the factory's
    // createElement reference while the real SlotCore validates registrations.
    window: { __ModuleLoader__: { load(registration) { assert.equal(registration.id, metadata.name); assert.equal(typeof registration.factory, 'function'); client = registration.factory(name => { assert.equal(name, 'react'); return { createElement: () => null }; }); } } },
    console, setTimeout: () => 0, clearTimeout() {},
  };
  vm.runInNewContext(fs.readFileSync(path.join(pluginRoot, 'client.js'), 'utf8'), sandbox, { timeout: 5000 });
  assert.equal(client?.name, metadata.name); assert.equal(typeof client.apply, 'function');
  client.apply({ slots: { inject(_name, callback) { return callback(); }, register(options, component) { const dispose = slots.register(options, component); slotDisposers.push(dispose); return dispose; } } });
  assert.equal(slots.entriesOfSlot('conversation.input.dock')[0]?.options.id, 'ig5-badge');
  assert.equal(slots.entriesOfSlot('conversation.view')[0]?.options.id, 'ig5');
  assert.equal(slots.entriesOfSlot('sidebar.panellist')[0]?.options.id, 'ig5-workbench-panel');
  assert.equal(slots.entriesOfSlot('main')[0]?.options.key, 'ig5-workbench-panel');
  assert.equal(slotDisposers.length, 4);
  for (const dispose of slotDisposers.reverse()) dispose();
  for (const name of ['conversation.input.dock', 'conversation.view', 'sidebar.panellist', 'main']) assert.equal(slots.entriesOfSlot(name).length, 0);
  declare();
  pass('Actual installed SlotCore accepts all four IG5 client registrations and clean disposal; native frontend symbols verified separately');
  if (declaredPeers.length) pass('Actual installed app-boot evaluator accepts the declared 0.2 host range and excludes 0.1/0.3 including 0.3 prereleases');
  const plugin = await import(pathToFileURL(path.join(pluginRoot, 'index.js')).href);
  context = new Context();
  context.on('tools/pre-execute', (execution, next) => { preCalls.push(execution.name); return next(); }, { global: true });
  await context.plugin(SystemPrompt, {}); await context.plugin(Tools);
  await context.plugin(Skills, {}); await context.plugin(Commands); await context.plugin(Projections);
  approvalOwner = context.plugin(class TestApproval extends Service {
    constructor(ctx) { super(ctx, 'approval'); }
    async request(value) {
      assert(value.agent?.ctx && value.signal instanceof AbortSignal && typeof value.callId === 'string');
      assert(typeof value.reason === 'string' && value.displayReason?.en && value.displayReason?.zh);
      approvals.push({ toolName: value.toolName, callId: value.callId, outcome: approvalOutcome });
      if (approvalOutcome === 'test-channel-throws') throw new Error('Synthetic approval channel failure');
      return approvalOutcome;
    }
  });
  await approvalOwner;
  const agents = [];
  await context.plugin(Object.assign(inner => {
    for (const id of ['sdk-A', 'sdk-B']) {
      const agent = { id, session: { append(type, data) { const event = { seq: commandEvents.length, type, data }; commandEvents.push(event); return event; } } };
      agent.ctx = createScope(inner, agent).ctx; agents.push(agent);
    }
  }, { inject: ['tools', 'systemPrompt'] }));
  owner = context.plugin(plugin, { reverse: false, toolset: 'core', artifactDir: path.join(runRoot, 'artifacts'), projectRoot: path.join(runRoot, 'projects'), stateRoot: path.join(runRoot, 'state') });
  await owner;
  const [a, b] = agents;
  assert.equal(context.tools.schemas().length, 8); assert.equal(context.tools.schemas(a).length, 8);
  const command = context.commands.find(a, 'ig5'); assert(command); assert.equal(context.commands.list(a).filter(item => item.name === 'ig5').length, 1);
  const switchResult = await context.commands.execute(a, '/ig5 toolset full', [], new AbortController().signal);
  assert.equal(switchResult.result.kind, 'success');
  const schemas = context.tools.schemas(a);
  assert.equal(schemas.length, 38); assert.equal(context.tools.schemas(b).length, 8); assert.equal(context.tools.schemas().length, 8);
  assert(schemas.every(schema => schema.name.startsWith('ig5_') && schema.parameters.type === 'object'));
  assert.equal(context.tools.get('ig5_crypto', b), undefined); assert(context.tools.get('ig5_crypto', a));
  pass('Actual IG5 Core8/Full38 schemas through installed DSH registry; two agent scopes remain isolated');
  const skills = (await context.skills.list({ scope: a })).filter(item => item.name.startsWith('ig5-'));
  assert.equal(skills.length, 7);
  for (const summary of skills) { const skill = await context.skills.get(summary.name, { scope: a }); assert(skill?.content?.length > 50); assert.equal(skill.invocation.modelInvocable, true); }
  pass('All seven actual bundled skills register and load through installed DSH Skill service');
  const snapshot = context.sessionProjections.restore({}, [], 0, { id: 'isolated-sdk-session' }, 0).snapshot;
  assert.equal(snapshot.values.ig5dash.calls, 0);
  pass('Actual IG5 session projection registers and validates through installed DSH projection service');
  const execute = (name, args = {}, agent = a) => context.tools.execute({ name, arguments: args, agent, signal: new AbortController().signal, callId: `sdk-${name}` });
  for (const name of ['ig5_status', 'ig5_profile']) {
    const result = await execute(name);
    if (result.isError) {
      // Diagnostic direct calls are strictly these two read-only functions; no
      // mutation/execution tool ever bypasses the real registry approval seam.
      const rawValue = await context.tools.get(name, a).execute({}, { agent: a, signal: new AbortController().signal });
      outputFailures.push({ name, error: result.error, nonJsonPaths: nonJsonPaths(rawValue) });
      console.error(`FAIL ${name} canonical output: ${JSON.stringify(outputFailures.at(-1))}`);
    } else assert(result.value && Array.isArray(result.content));
  }
  const status = await context.commands.execute(a, '/ig5 status', [], new AbortController().signal);
  assert.equal(status.result.kind, 'success'); assert.match(status.result.text, /sessions/);
  const refusedCommand = await context.commands.execute(a, '/ig5 patch', [], new AbortController().signal);
  assert.equal(refusedCommand.result.kind, 'error'); assert.equal(approvals.length, 0);
  assert.equal(commandEvents.filter(event => event.type === 'command/run').length, 3);
  pass('Actual /ig5 command lifecycle works; unsupported write commands are rejected');
  if (!outputFailures.length) pass('Actual status/profile canonical outputs pass installed DSH output validation');
  for (const name of writeNames) {
    const schema = schemas.find(item => item.name === name); assert(schema, `Write schema ${name}`);
    const result = await execute(name, minimal(schema.parameters));
    assert.equal(result.isError, true, `${name} must be rejected`);
    assert.match(JSON.stringify(result), /approval (?:was )?rejected|user rejected tool/, `${name} must reach the real approval seam; received ${JSON.stringify(result)}; pre calls ${JSON.stringify(preCalls)}; approvals ${JSON.stringify(approvals)}`);
    assert.equal(approvals.at(-1)?.toolName, name);
  }
  assert.equal(approvals.length, 12); assert.deepEqual(blockedProcesses, []);
  pass('All twelve real write/execution schemas reach DSH approval and are denied without starting a worker');
  approvalOutcome = 'cancelled';
  const cancelled = await execute('ig5_rename', minimal(schemas.find(item => item.name === 'ig5_rename').parameters));
  assert.equal(cancelled.isError, true); assert.match(JSON.stringify(cancelled), /ABORTED_BEFORE_DISPATCH|cancelled|取消/);
  approvalOutcome = 'unavailable';
  const unavailable = await execute('ig5_rename', minimal(schemas.find(item => item.name === 'ig5_rename').parameters));
  assert.equal(unavailable.isError, true); assert.match(JSON.stringify(unavailable), /approval|审批/);
  for (const outcome of ['unknown-test-outcome', 'test-channel-throws']) {
    approvalOutcome = outcome;
    const refused = await execute('ig5_rename', minimal(schemas.find(item => item.name === 'ig5_rename').parameters));
    assert.equal(refused.isError, true); assert.match(JSON.stringify(refused), /approval|审批/);
    assert.doesNotMatch(JSON.stringify(refused), /worker 不在运行/);
  }
  approvalOutcome = 'allowed-once';
  const approvedWithoutTarget = await execute('ig5_rename', minimal(schemas.find(item => item.name === 'ig5_rename').parameters));
  assert.equal(approvedWithoutTarget.isError, true);
  assert.match(JSON.stringify(approvedWithoutTarget), /worker 不在运行/, 'One confirmed approval reaches the real body; absent target keeps the check inert');
  assert.equal(approvals.at(-1)?.outcome, 'allowed-once');
  const requestsBeforeAgentless = approvals.length;
  // Temporarily expose this real definition globally only in the isolated test
  // context, so the actual registry can exercise the missing-agent gate.
  const globalWrite = context.plugin(Object.assign(inner => inner.tools.register(context.tools.get('ig5_rename', a)), { inject: ['tools'] }));
  await globalWrite;
  try {
    const agentless = await context.tools.execute({ name: 'ig5_rename', arguments: minimal(schemas.find(item => item.name === 'ig5_rename').parameters), signal: new AbortController().signal, callId: 'sdk-agentless-rename' });
    assert.equal(agentless.isError, true); assert.match(JSON.stringify(agentless), /active agent|approval|审批/);
    assert.doesNotMatch(JSON.stringify(agentless), /worker 不在运行/); assert.equal(approvals.length, requestsBeforeAgentless);
  } finally { await globalWrite.dispose(); }
  await approvalOwner.dispose(); approvalOwner = null;
  assert.equal(context.get('approval'), undefined);
  const noChannel = await execute('ig5_rename', minimal(schemas.find(item => item.name === 'ig5_rename').parameters));
  assert.equal(noChannel.isError, true); assert.match(JSON.stringify(noChannel), /approval|审批/);
  assert.deepEqual(blockedProcesses, []);
  assert.doesNotMatch(JSON.stringify(noChannel), /worker 不在运行/);
  pass('Cancelled, unavailable, unknown, throwing, missing-agent and missing-service approvals fail closed; confirmed approval reaches the inert body');
  assert.equal((await context.commands.execute(b, '/ig5 toolset full', [], new AbortController().signal)).result.kind, 'success');
  assert.equal((await context.commands.execute(a, '/ig5 toolset core', [], new AbortController().signal)).result.kind, 'success');
  assert.equal(context.tools.schemas(a).length, 8); assert.equal(context.tools.schemas(b).length, 38);
  pass('Core/Full command changes remain independent after real policy denials');
  await owner.dispose(); owner = null;
  assert.equal(context.tools.schemas(a).length, 0); assert.equal(context.tools.schemas(b).length, 0);
  assert.equal((await context.skills.list({ scope: a })).filter(item => item.name.startsWith('ig5-')).length, 0);
  assert.equal(context.commands.find(a, 'ig5'), undefined);
  assert.equal(context.sessionProjections.restore({}, [], 0, { id: 'disposed-sdk-session' }, 0).snapshot.values.ig5dash, undefined);
  pass('Actual Cordis owner unload removes all scoped tools, bundled skills, slash command and projection');
  const report = { ok: !outputFailures.length, timestamp: new Date().toISOString(), pluginRoot, pluginVersion: metadata.version, pluginEntrySha256: createHash('sha256').update(fs.readFileSync(path.join(pluginRoot, 'index.js'))).digest('hex'), host: { asar, name: application.name, version: runtimeVersion, desktopVersion: application.version, runtimePackage: appBoot.name, sdkVersions }, frontendContracts, compatibility, peerDependencies: Object.fromEntries(declaredPeers), extraction: { sdkRoot, packages: copied.size, files: copiedFiles, bytes: copiedBytes }, runRoot, assertions, outputFailures, deniedWriteTools: writeNames, approvals, nativeWorkersStarted: 0, childProcessesStarted: processIdentityQueries.length, processIdentityQueries, limits: 'Actual installed service API checks in an isolated Cordis context; no desktop GUI launch, model API call, engine analysis or debugger execution. SlotCore checks registrations only, with a placeholder React reference; rendering is verified separately. Only the explicit read-only own-process creation-identity query may start PowerShell.' };
  fs.writeFileSync(path.join(reportRoot, 'host-sdk.json'), JSON.stringify(report, null, 2));
  assert.deepEqual(outputFailures, [], 'Real DSH canonical output validation must pass');
  console.log(`PASS installed DSH ${runtimeVersion} SDK; report ${path.join(reportRoot, 'host-sdk.json')}`);
} catch (error) {
  fs.writeFileSync(path.join(reportRoot, 'host-sdk.json'), JSON.stringify({ ok: false, timestamp: new Date().toISOString(), pluginRoot, pluginVersion: metadata.version, host: { asar, name: application.name, version: runtimeVersion, desktopVersion: application.version, runtimePackage: appBoot.name, sdkVersions }, frontendContracts, compatibility, peerDependencies: Object.fromEntries(declaredPeers), extraction: { sdkRoot, packages: copied.size, files: copiedFiles, bytes: copiedBytes }, runRoot, assertions, outputFailures, approvals, preCalls, blockedProcesses, nativeWorkersStarted: 0, childProcessesStarted: processIdentityQueries.length, processIdentityQueries, error: { name: error.name, message: error.message }, limits: 'Isolated actual installed service API check; no desktop GUI or engine process started.' }, null, 2));
  throw error;
} finally {
  await owner?.dispose(); await approvalOwner?.dispose(); await context?.fiber?.dispose();
  for (const [name, original] of originals) childProcess[name] = original;
  syncBuiltinESMExports();
}
