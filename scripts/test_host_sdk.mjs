// Isolated compatibility checks against actual services shipped in a DSH app.asar.
// This never starts DSH or a native analysis/debug worker or changes its profile.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import childProcess from 'node:child_process';
import { builtinModules, syncBuiltinESMExports } from 'node:module';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { createHash, randomUUID } from 'node:crypto';
import vm from 'node:vm';
import { publicDocument } from './fixtures/research_v2.mjs';

function option(name, fallback) {
  const index = process.argv.indexOf(name);
  if (index < 0) return fallback;
  assert(process.argv[index + 1] && !process.argv[index + 1].startsWith('--'), `${name} needs a value`);
  return process.argv[index + 1];
}
const here = path.dirname(fileURLToPath(import.meta.url));
const pluginRoot = path.resolve(option('--plugin-root', process.env.IG5_PLUGIN_UNDER_TEST || path.join(here, '..')));
const asar = path.resolve(option('--asar', process.env.IG5_TEST_ASAR || path.join(process.env.LOCALAPPDATA || '', 'Programs', 'DeepSeek Harness', 'resources', 'app.asar')));
const explicitEvidence = process.argv.includes('--evidence') || Boolean(process.env.IG5_SDK_EVIDENCE);
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
const requiredPackages = ['@deepseek-ai/cordis', '@deepseek-ai/dsh-tools', '@deepseek-ai/dsh-system-prompt', '@deepseek-ai/dsh-scope', '@deepseek-ai/dsh-skill', '@deepseek-ai/dsh-commands', '@deepseek-ai/dsh-session-projection', 'semver'];
const standaloneSlotsPkgPresent = Boolean(entry('dsh/node_modules/@deepseek-ai/dsh-client-ui-slots')?.files);
if (standaloneSlotsPkgPresent) requiredPackages.push('@deepseek-ai/dsh-client-ui-slots');
const nativeExecutorPkgPresent = Boolean(entry('dsh/node_modules/@deepseek-ai/dsh-tool-executor-native')?.files);
if (nativeExecutorPkgPresent) requiredPackages.push('@deepseek-ai/dsh-tool-executor-native');
const frontendContracts = [];
let bundledFrontendAsset = null;
try {
  for (const name of requiredPackages) copyPackage(name);
  if (!standaloneSlotsPkgPresent) {
    const webAssetsDir = entry('dsh/node_modules/@deepseek-ai/dsh-web-frontend/dist/assets');
    assert(webAssetsDir?.files, 'Neither standalone @deepseek-ai/dsh-client-ui-slots nor @deepseek-ai/dsh-web-frontend/dist/assets is present in app.asar');
    const indexJsName = Object.keys(webAssetsDir.files).find(n => /^index-.*\.js$/.test(n));
    assert(indexJsName, 'Bundled host frontend index-*.js absent in @deepseek-ai/dsh-web-frontend/dist/assets');
    const webSource = `dsh/node_modules/@deepseek-ai/dsh-web-frontend/dist/assets/${indexJsName}`;
    const webBytes = read(webSource);
    const webSymbols = ['@deepseek-ai/dsh-client-ui-slots', 'SlotCore', 'entriesOfSlot', 'registerFactory'];
    for (const symbol of webSymbols) assert(webBytes.includes(Buffer.from(symbol)), `Bundled frontend slot contract absent: ${webSource} ${symbol}`);
    const webDest = path.join(sdkRoot, 'frontend-contracts', `dsh-web-frontend-${indexJsName}`);
    fs.mkdirSync(path.dirname(webDest), { recursive: true }); fs.writeFileSync(webDest, webBytes);
    const webFrontendPkg = JSON.parse(read('dsh/node_modules/@deepseek-ai/dsh-web-frontend/package.json'));
    sdkVersions['@deepseek-ai/dsh-web-frontend'] = webFrontendPkg.version;
    bundledFrontendAsset = { source: webSource, destination: webDest, bytes: webBytes };
    frontendContracts.push({ source: webSource, bytes: webBytes.length, sha256: createHash('sha256').update(webBytes).digest('hex'), symbols: webSymbols, destination: webDest, verification: 'Verbatim SlotCore extracted from @deepseek-ai/dsh-web-frontend host bundle exposing "@deepseek-ai/dsh-client-ui-slots" in window.__ModuleLoader__' });
  }
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
function extractBundledSlotsModule(frontendBytes) {
  const text = frontendBytes.toString('utf8');
  const mapMatch = /"@deepseek-ai\/dsh-client-ui-slots":([A-Za-z_$][A-Za-z0-9_$]*)/.exec(text);
  assert(mapMatch, 'Host frontend bundle does not expose "@deepseek-ai/dsh-client-ui-slots" in its module map');
  const modIdent = mapMatch[1];
  const escaped = modIdent.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const declRe = new RegExp(`(?:const|let|var)\\s+${escaped}=(Object\\.freeze\\(Object\\.defineProperty\\(\\{[^}]*\\bSlotCore:[A-Za-z_$][A-Za-z0-9_$]*[^}]*\\},Symbol\\.toStringTag,\\{value:"Module"\\}\\)\\))`);
  const declMatch = declRe.exec(text);
  assert(declMatch, `Bundled SlotCore module definition for ${modIdent} not found in @deepseek-ai/dsh-web-frontend`);
  const boundaryToken = 'Symbol.toStringTag,{value:"Module"}));';
  const prevIdx = text.lastIndexOf(boundaryToken, declMatch.index);
  assert(prevIdx >= 0 && declMatch.index - prevIdx < 32768, 'Preceding module boundary for bundled SlotCore not found');
  const sliceSource = `${text.slice(prevIdx + boundaryToken.length, declMatch.index)}const ${modIdent}=${declMatch[1]};\n${modIdent}`;
  const evaluated = vm.runInNewContext(sliceSource, { Error, Map, Set, WeakSet, Object, Symbol, queueMicrotask }, { timeout: 5000 });
  assert.equal(typeof evaluated?.SlotCore, 'function', 'Extracted SlotCore constructor must be a function');
  assert.equal(typeof evaluated?.resolveSlotLabel, 'function', 'Extracted resolveSlotLabel helper must be a function');
  return evaluated;
}
const loadedPackages = await Promise.all(requiredPackages.map(load));
const [{ Context, Service }, { default: Tools }, { default: SystemPrompt }, { createScope }, { default: Skills }, { default: Commands }, { default: Projections }, semverModule] = loadedPackages;
const { SlotCore } = standaloneSlotsPkgPresent
  ? loadedPackages[requiredPackages.indexOf('@deepseek-ai/dsh-client-ui-slots')]
  : extractBundledSlotsModule(bundledFrontendAsset.bytes);
const NativeToolExecutor = nativeExecutorPkgPresent
  ? loadedPackages[requiredPackages.indexOf('@deepseek-ai/dsh-tool-executor-native')]
  : null;
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
const extraCompatHelpers = evaluatorSource.includes('unmetRequirements(')
  ? ['satisfies', 'unmetRequirements']
  : [];
const helperNames = [objectHelper, 'runtimeVersionOf', 'identityField', ...extraCompatHelpers, 'evaluatePluginCompatibility'];
const compatibilityFunctions = helperNames.map(extractedFunction);
// Execute verbatim installed evaluator functions in an isolated VM. Inject
// the real SDK semver and supply the version explicitly; boot dependencies and
// application startup are not imported by this check.
const evaluateCompatibility = vm.runInNewContext(`${compatibilityFunctions.join('\n')}\nevaluatePluginCompatibility`, { semver, Object, JSON, Error, getDshRuntimeVersion: () => runtimeVersion });
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
const compatibility = { verification: 'Verbatim functions extracted from actual installed app-boot, called with actual SDK semver; not a full boot-module import', source: bootSourcePath, evidencePath: bootEvidencePath, sha256: createHash('sha256').update(bootBytes).digest('hex'), helperNames, runtimeVersionOrigin: `${appBoot.name}/package.json`, peerConstraintPresent: !!declaredPeers.length, matrix: compatibilityMatrix };
const writeNames = ['ig5_rename', 'ig5_patch_bytes', 'ig5_comment', 'ig5_analyze', 'ig5_set_type', 'ig5_undo', 'ig5_run_idapython', 'ig5_dbg', 'ig5_struct', 'ig5_switch_repair', 'ig5_emulate', 'ig5_sync', 'ig5_capture_control', 'ig5_app_observe'];
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
let context, owner, approvalOwner, approvalOutcome = 'rejected', sdkCheckPassed = false;
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
  if (NativeToolExecutor) await context.plugin(NativeToolExecutor);
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
      const agent = { id, session: { header: { id, cwd: runRoot }, log: [], append(type, data) { const event = { seq: this.log.length, type, data }; this.log.push(event); commandEvents.push(event); return event; } } };
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
  assert.equal(schemas.length, 44); assert.equal(context.tools.schemas(b).length, 8); assert.equal(context.tools.schemas().length, 8);
  assert(schemas.every(schema => schema.name.startsWith('ig5_') && schema.parameters.type === 'object'));
  assert.equal(context.tools.get('ig5_crypto', b), undefined); assert(context.tools.get('ig5_crypto', a));
  pass('Actual IG5 Core8/Full44 schemas through installed DSH registry; two agent scopes remain isolated');
  const knowledgeSchema = schemas.find(s => s.name === 'ig5_profile').parameters.properties.knowledge;
  assert.deepEqual(knowledgeSchema.required, ['action']);
  const skills = (await context.skills.list({ scope: a })).filter(item => item.name.startsWith('ig5-'));
  assert.equal(skills.length, 8);
  for (const summary of skills) { const skill = await context.skills.get(summary.name, { scope: a }); assert(skill?.content?.length > 50); assert.equal(skill.invocation.modelInvocable, true); }
  pass('All eight actual bundled skills register and load through installed DSH Skill service');
  const snapshot = context.sessionProjections.restore({}, [], 0, { id: 'isolated-sdk-session' }, 0).snapshot;
  assert.equal(snapshot.values.ig5dash.calls, 0);
  pass('Actual IG5 session projection registers and validates through installed DSH projection service');
  const dashEvents=[
    {seq:0,type:'tool/call',data:{callId:'dash-a',name:'ig5_ir'}},
    {seq:1,type:'tool/call',data:{callId:'dash-b',name:'ig5_decompile'}},
    {seq:2,type:'tool/result',data:{message:{toolCallId:'dash-a',isError:true,content:[{type:'text',text:'expected diagnostic refusal'}]}}},
    {seq:3,type:'tool/result',data:{message:{toolCallId:'dash-a',isError:true,content:[]}}},
    {seq:4,type:'tool/result',data:{message:{toolCallId:'dash-b',isError:false,content:[]}}},
  ];
  const staleDash={ig5dash:{ver:1,seq:4,val:{running:'ig5_ir',calls:999,errors:0,pending:{'dash-a':'ig5_ir'}}}};
  const repaired=context.sessionProjections.restore(staleDash,dashEvents,0,{id:'isolated-sdk-replayed-session'},0);
  assert.equal(repaired.snapshot.values.ig5dash.running,null);
  assert.equal(repaired.snapshot.values.ig5dash.calls,2);assert.equal(repaired.snapshot.values.ig5dash.errors,1);
  assert.equal(repaired.checkpoint.ig5dash.ver,2);
  pass('Actual projection service refolds old version1 cache and settles toolCallId/error/concurrent/replayed results once');
  let sdkCallSeq = 0;
  const executeSingleCall = async ({ name, args = {}, agent, signal = new AbortController().signal, callId = `sdk-${name}-${++sdkCallSeq}` }) => {
    if (!nativeExecutorPkgPresent) {
      return context.tools.execute({ name, arguments: args, ...(agent === undefined ? {} : { agent }), signal, callId });
    }
    const batch = await context.tools.execute({
      calls: [{ id: callId, name, arguments: JSON.stringify(args ?? {}) }],
      ...(agent === undefined ? {} : { agent }),
      signal,
    });
    const settled = batch.results[0].result;
    if (!settled.isError && settled.value === undefined && settled.content?.[0]?.type === 'text') {
      try {
        return { ...settled, value: JSON.parse(settled.content[0].text) };
      } catch {
        return settled;
      }
    }
    return settled;
  };
  const execute = (name, args = {}, agent = a) => executeSingleCall({ name, args, agent });
  const researchLookup = await execute('ig5_profile', { knowledge: { action: 'search', query: '混合布尔算术' } });
  assert.equal(researchLookup.isError, false);
  const researchRef = researchLookup.value.knowledge.items[0].ref;
  assert.equal(researchRef.id, 'mba-synthesis');
  const researchRead = await execute('ig5_profile', { knowledge: { action: 'read', ref: researchRef } });
  assert.equal(researchRead.isError, false); assert.equal(researchRead.value.knowledge.semanticVerified, false);
  assert.equal(researchRead.value.knowledge.executionAuthorized, false);
  const originalDocuments = await execute('ig5_profile', { knowledge: { action: 'documents', query: 'MBA' } });
  assert.equal(originalDocuments.isError, false); assert.equal(originalDocuments.value.knowledge.total, 0);
  assert.equal((await execute('ig5_profile', { knowledge: { action: 'status' }, target: 'never-opened.exe' })).isError, true);
  assert.equal((await execute('ig5_profile', { knowledge: { action: 'crawl' } })).isError, true);
  pass('Actual DSH registry executes explicit research search/read with exact refs and rejects mixed or execution actions');
  const {publishPublicKnowledgeV2}=await import(pathToFileURL(path.join(pluginRoot,'source/knowledge_publish_v2.js')).href);
  const v2Published=publishPublicKnowledgeV2({projectRoot:path.join(runRoot,'projects'),expectedGeneration:'absent',upserts:[publicDocument('v2-sdk-fixture','SDK v2 original-note fixture')],withdrawals:[]});
  const v2Lookup=await execute('ig5_profile',{knowledge:{action:'documents',query:'fixture'}});assert.equal(v2Lookup.isError,false);assert.equal(v2Lookup.value.knowledge.items[0].ref.id,'v2-sdk-fixture');
  const v2Ref=v2Lookup.value.knowledge.items[0].ref,v2Read=await execute('ig5_profile',{knowledge:{action:'read',ref:v2Ref}});assert.equal(v2Read.isError,false);assert.equal(v2Read.value.knowledge.metadata.schema,'ig5-source-document-v2');assert.equal(v2Read.value.knowledge.body,'SDK v2 original-note fixture');assert.equal(v2Read.value.knowledge.executionAuthorized,false);
  publishPublicKnowledgeV2({projectRoot:path.join(runRoot,'projects'),expectedGeneration:v2Published.generation,upserts:[],withdrawals:[{ref:v2Ref,reason:'SDK fixture withdrawal',replacementRef:null}]});
  const v2History=await execute('ig5_profile',{knowledge:{action:'read',ref:v2Ref}});assert.equal(v2History.isError,false);assert.equal(v2History.value.knowledge.recordState,'withdrawn');
  assert.equal((await execute('ig5_profile',{knowledge:{action:'read',ref:researchRef}})).isError,false);
  pass('Actual DSH reads sharded v2 data and withdrawn history while preserving v1 references and original permissions');
  const memoryOriginal = a.session.append('tool/result', { message: { toolCallId: 'memory-evidence', content: [{ type: 'text', text: 'counterexample guard=0xffffffffffffffff; conclusion remains unknown' }] } });
  const memoryStatus = await execute('ig5_profile', { memory: { action: 'status' } });
  assert.equal(memoryStatus.isError, false, JSON.stringify(memoryStatus));
  assert.equal(memoryStatus.value.memory.automaticRestoreRegistered, true);
  const found = await execute('ig5_profile', { memory: { action: 'search', query: 'counterexample' } });
  assert.equal(found.isError, false); const memoryRef = found.value.memory.hits[0].ref;
  assert.equal(found.value.memory.recovery.automaticCheckpointSaved, false);
  assert.equal(found.value.memory.recovery.read[0].memory.ref.sha256, memoryRef.sha256);
  assert.match(found.value.memory.recovery.checkpointDraft.text, /Caller-unverified/);
  const readMemory = await execute('ig5_profile', { memory: { action: 'read', ref: memoryRef } });
  assert.equal(readMemory.isError, false); assert.deepEqual(JSON.parse(readMemory.value.memory.text), memoryOriginal);
  const foreignMemory = await execute('ig5_profile', { memory: { action: 'read', ref: memoryRef } }, b);
  assert.equal(foreignMemory.isError, true);
  a.session.append('compaction/summary', { summary: [{ type: 'text', text: 'Details omitted' }], shadowedSeqs: [memoryOriginal.seq] });
  const restored = await execute('ig5_profile', { memory: { action: 'restore' } });
  assert.equal(restored.isError, false); assert.equal(restored.value.memory.summaries.length, 1);
  const expanded = await execute('ig5_profile', { memory: { action: 'expand', ref: { kind: 'summary', id: restored.value.memory.summaries[0].id, sha256: restored.value.memory.summaries[0].sha256 } } });
  assert.equal(expanded.isError, false); assert.deepEqual(expanded.value.memory.refs, [memoryRef]);
  const promptA = await context.systemPrompt.assemble({ scope: a });
  const promptGlobal = await context.systemPrompt.assemble({});
  assert(promptA.contexts.some(p => p.name === 'ig5-lcm-history' && p.text.includes('search/read/expand')));
  assert(!promptGlobal.contexts.some(p => p.name === 'ig5-lcm-history'));
  assert.equal(context.tools.schemas(a).length, 44);
  pass('Actual installed DSH registry executes LCM capture/search/read/restore/expand, rejects cross-session refs and assembles scoped recovery context without global injection');
  const catalog = await execute('ig5_profile', { capabilities: true });
  assert.equal(catalog.isError, false);
  assert.equal(catalog.value.capabilities.nativeProbePerformed, false);
  assert(catalog.value.capabilities.entries.some(e => e.operation === 'function-context' && e.provider === 'ghidra'));
  const mixedCatalog = await execute('ig5_profile', { capabilities: true, toolset: 'core' });
  assert.equal(mixedCatalog.isError, true);
  assert.equal(context.tools.schemas(a).length, 44);
  pass('Actual DSH registry validates read-only capability schema/output and rejects mixed toolset mutation');
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
  const recoveryCasePath = path.join(runRoot, 'recovery-case.json');
  const recoveryCaseBytes = fs.readFileSync(path.join(pluginRoot, 'scripts/fixtures/vm_recovery_case.example.json'));
  fs.writeFileSync(recoveryCasePath, recoveryCaseBytes);
  const recoveryCaseSha256 = createHash('sha256').update(recoveryCaseBytes).digest('hex');
  const recoveryResult = await execute('ig5_recovery', { recovery: { case_ref: { path: recoveryCasePath, sha256: recoveryCaseSha256 } } });
  assert.equal(recoveryResult.isError, false, JSON.stringify(recoveryResult));
  const recoveryView = recoveryResult.value.recovery;
  assert.equal(recoveryView.completionAssessment.businessAccepted, false);
  assert.equal(recoveryView.integration.dshPlanningEntry, 'ig5_recovery.recovery');
  assert.equal(createHash('sha256').update(fs.readFileSync(recoveryView.reportPath)).digest('hex'), recoveryView.reportSha256);
  assert.equal(approvals.length, 0); assert.deepEqual(blockedProcesses, []);
  const changedRecoveryCase = await execute('ig5_recovery', { recovery: { case_ref: { path: recoveryCasePath, sha256: '0'.repeat(64) } } });
  assert.equal(changedRecoveryCase.isError, true);
  assert.match(JSON.stringify(changedRecoveryCase), /differ from the supplied SHA-256/);
  pass('Actual profile recovery schema/output/read-only report path validates through DSH registry; changed case rejected before referenced reads');
  const { AnalysisArtifacts } = await import(pathToFileURL(path.join(pluginRoot, 'source/analysis_artifacts.js')).href);
  const { observationWindow, observationTarget } = await import(pathToFileURL(path.join(pluginRoot, 'scripts/fixtures/vm_observation_cases.mjs')).href);
  const observationStore = new AnalysisArtifacts(path.join(runRoot, 'artifacts', 'debug-traces'));
  try {
    const fixture = observationWindow({ cpuid: true }), input = observationStore.put(fixture.data);
    const record = observationStore.save({ kind: 'debug-trace', action: 'record', result: { ...fixture.summary, input } });
    const observations = { recordings: [{ id: record.id, sha256: observationStore.metadata(record.id).result.recordSha256 }], target_sha256: observationTarget, limit: 1 };
    const response = await execute('ig5_recovery', { recovery: { observations } });
    assert.equal(response.isError, false, JSON.stringify(response));
    const view = response.value.observations;
    assert.equal(view.totals.instructions, 4); assert.equal(view.totals.stopGroups, 2);
    assert.equal(view.stopGroups[0].intermediateStateAvailable, false); assert.equal(view.businessAccepted, false);
    assert.equal(createHash('sha256').update(fs.readFileSync(view.reportPath)).digest('hex'), view.reportSha256);
    const wrongDigest = structuredClone(observations); wrongDigest.recordings[0].sha256 = '0'.repeat(64);
    for (const args of [{ recovery: { observations: wrongDigest } }, { recovery: { observations, case_ref: { path: recoveryCasePath, sha256: recoveryCaseSha256 } } }, { recovery: { observations }, toolset: 'full' }])
      assert.equal((await execute('ig5_profile', args)).isError, true);
    assert.equal(approvals.length, 0); assert.deepEqual(blockedProcesses, []);
    pass('Actual profile observations schema/worker/report passes DSH registry; mixed modes and wrong SHA rejected without native execution');
    const phaseResponse = await execute('ig5_recovery', { recovery: { observations: { ...observations, phase_model: true } } });
    assert.equal(phaseResponse.isError, false, JSON.stringify(phaseResponse));
    assert.equal(phaseResponse.value.observations.phaseModel.phaseVerified, false);
    assert.equal(phaseResponse.value.observations.phaseModel.groups[0].versions[1].version.binding.beforeStateAvailable, false);
    assert.equal(phaseResponse.value.observations.phaseModel.codeEpochs.globalCodeEpochKnown, false);
    assert.equal((await execute('ig5_recovery', { recovery: { observations: { ...observations, phase_model: 'true' } } })).isError, true);
    assert.equal((await execute('ig5_recovery', { recovery: { observations: { ...observations, phase_model: true, dispatch: 'verified' } } })).isError, true);
    assert.equal(approvals.length, 0); assert.deepEqual(blockedProcesses, []);
    pass('Actual DSH opt-in phase model binds CPUID byte observations and rejects caller phase promotion without native dispatch');
    const { buildPhaseContextCase } = await import(pathToFileURL(path.join(pluginRoot, 'scripts/fixtures/vm_phase_context_cases.mjs')).href);
    const phaseArtifacts = new AnalysisArtifacts(path.join(runRoot, 'artifacts', 'analysis-data'));
    try {
      const built = await buildPhaseContextCase({ artifacts: phaseArtifacts }, { artifactDir: path.join(runRoot, 'artifacts') });
      const annotated = await execute('ig5_recovery', { recovery: { observations: { ...built.request, offset: 99, limit: 5 } } });
      assert.equal(annotated.isError, false, JSON.stringify(annotated));
      const annotation = annotated.value.observations.phaseModel.contextAnnotation;
      assert.equal(annotation.audit.status, 'pass'); assert.equal(annotation.matchedGroups, 16);
      assert.equal(annotation.totalSegments, 16); assert.equal(annotation.segmentsPreviewComplete, false);
      assert.equal(annotated.value.observations.phaseModel.groups[1].contextPhase.kind, 'fetch-dispatch-candidate');
      assert.equal(annotation.phaseClassificationProved, false);
      assert.equal((await execute('ig5_recovery', { recovery: { observations: { ...built.request, phase_model: false } } })).isError, true);
      assert.equal(approvals.length, 0); assert.deepEqual(blockedProcesses, []);
      const declared=await execute('ig5_recovery',{recovery:{declare_contract:{contract:{schema:'ig5-function-contract-v1',targetSha256:built.request.target_sha256,
        entryRva:'0x0',normalReturn:'native-ret',input:{register:'rcx',bits:8,minimum:'0x0',maximum:'0xff'},
        outputs:{returnRegister:'rax',memory:[]},environment:'single-threaded-no-external-calls',exclusions:['Synthetic recording format only; no native execution']}}}});
      assert.equal(declared.isError,false,JSON.stringify(declared));
      const contractRef={id:declared.value.declare_contract.reportId,sha256:declared.value.declare_contract.reportSha256},contextRef={id:built.model.reportId,sha256:built.model.reportSha256};
      const comparison=await execute('ig5_recovery',{recovery:{role_compare:{context_refs:[contextRef],contract_ref:contractRef}}});
      assert.equal(comparison.isError,false,JSON.stringify(comparison));
      const validated=await execute('ig5_recovery',{recovery:{role_validate:{comparison_ref:{id:comparison.value.role_compare.reportId,sha256:comparison.value.role_compare.reportSha256},
        recording_bindings:[{context_ref:contextRef,recordings:[built.debugRef]}]}}});
      assert.equal(validated.isError,false,JSON.stringify(validated));assert.equal(validated.value.role_validate.independence.rawCaptureRevalidated,true);
      assert.equal(validated.value.role_validate.independence.distinctObservedRuns,1);assert.equal(approvals.length,0);assert.deepEqual(blockedProcesses,[]);
      pass('Actual DSH role-validation schema rebinds synthetic raw context sources without promoting single-run evidence or executing targets');
    } finally { await phaseArtifacts.dispose(); }
    pass('Actual DSH phase context rebinds candidate cycles to committed raw groups, bounds previews and preserves unknown VM phases');
    {
      const { branchMemoryCode, bytecodeContract } = await import(pathToFileURL(path.join(pluginRoot,'scripts/fixtures/vm_bytecode_cases.mjs')).href);
      const inputPath=path.join(runRoot,'owned-branch-memory.bin'),sha=createHash('sha256').update(branchMemoryCode).digest('hex');fs.writeFileSync(inputPath,branchMemoryCode);
      const declared=await execute('ig5_recovery',{recovery:{declare_contract:{contract:bytecodeContract(sha)}}});
      assert.equal(declared.isError,false,JSON.stringify(declared));
      const contractRef={id:declared.value.declare_contract.reportId,sha256:declared.value.declare_contract.reportSha256};
      const program=await execute('ig5_recovery',{recovery:{program:{image_ref:{path:inputPath,sha256:sha},contract_ref:contractRef}}});
      assert.equal(program.isError,false,JSON.stringify(program));
      const programRef={id:program.value.program.reportId,sha256:program.value.program.reportSha256};
      const verified=await execute('ig5_recovery',{recovery:{function_check:{program_ref:programRef}}});
      assert.equal(verified.isError,false,JSON.stringify(verified));assert.equal(verified.value.function_check.finiteTesting.cases,256);
      assert.equal(verified.value.function_check.modelContractAccepted,true);assert.equal(verified.value.function_check.businessAccepted,false);
      assert.equal((await execute('ig5_recovery',{recovery:{function_check:{program_ref:programRef,oracle:'caller-code'}}})).isError,true);
      assert.equal(approvals.length,0);assert.deepEqual(blockedProcesses,[]);
      pass('Actual DSH schema/dispatcher executes the fixed finite VM model oracle and rejects caller verifier overrides without native dispatch');
    }
    {
      const {smallVm}=await import(pathToFileURL(path.join(pluginRoot,'scripts/fixtures/vm_instance_cases.mjs')).href);
      const bytes=Buffer.from(JSON.stringify(smallVm({haltOnly:true}))),inputPath=path.join(runRoot,'declared-small-vm.json');fs.writeFileSync(inputPath,bytes);
      const compared=await execute('ig5_recovery',{recovery:{instances:{source_refs:[{path:inputPath,sha256:createHash('sha256').update(bytes).digest('hex')}]}}});assert.equal(compared.isError,false,JSON.stringify(compared));
      const checked=await execute('ig5_recovery',{recovery:{instance_check:{comparison_ref:compared.value.instances.reportRef}}});assert.equal(checked.isError,false,JSON.stringify(checked));assert.equal(checked.value.instance_check.checks[0].initialResultSensitivity,true);assert.equal(checked.value.instance_check.businessAccepted,false);
      assert.equal((await execute('ig5_recovery',{recovery:{instance_check:{comparison_ref:compared.value.instances.reportRef,oracle:'arbitrary'}}})).isError,true);assert.equal(approvals.length,0);assert.deepEqual(blockedProcesses,[]);
      pass('Actual DSH schema and original data worker check explicit small-VM instances and HALT initial-result distinction without native execution');
    }
    const { storeEventCase } = await import(pathToFileURL(path.join(pluginRoot, 'scripts/fixtures/vm_store_event_cases.mjs')).href);
    const { saveDebugTrace } = await import(pathToFileURL(path.join(pluginRoot, 'source/debug_trace.js')).href);
    const storeFixture = storeEventCase();
    const stored = await saveDebugTrace({ artifactDir: path.join(runRoot, 'artifacts') }, { target: path.join(runRoot, 'synthetic-not-executed.exe'), sha256: observationTarget }, storeFixture.native, { record_events: true });
    const storeResponse = await execute('ig5_recovery', { recovery: { observations: { recordings: [{ id: stored.traceReportId, sha256: stored.traceReportSha256 }], target_sha256: observationTarget } } });
    assert.equal(storeResponse.isError, false, JSON.stringify(storeResponse));
    assert.equal(storeResponse.value.observations.stopGroups[0].memoryWrites.stores[0].afterHex, '8877665544332211');
    assert.equal(storeResponse.value.observations.stopGroups[0].memoryWrites.actualWriteCausalityProved, false);
    assert.equal(approvals.length, 0); assert.deepEqual(blockedProcesses, []);
    pass('Actual DSH schema/output preserves optional source-bound store events and unknown CPU/write proof');
  } finally { await observationStore.dispose(); }
  const flowSchema=schemas.find(item=>item.name==='ig5_recovery').parameters.properties.recovery.properties.flow;
  assert.equal(flowSchema.additionalProperties,false);assert.deepEqual(flowSchema.required,['roles_ref','target']);
  assert.equal(flowSchema.properties.semantic_check.type,'boolean');
  for(const args of [
    {recovery:{flow:{roles_ref:{id:'invalid',sha256:'a'.repeat(64)},target:path.join(runRoot,'never-opened.exe')}}},
    {recovery:{flow:{roles_ref:{id:'invalid',sha256:'a'.repeat(64)},target:path.join(runRoot,'never-opened.exe'),projection_decoder:'native'}}},
    {recovery:{flow:{roles_ref:{id:'invalid',sha256:'a'.repeat(64)},target:path.join(runRoot,'never-opened.exe'),semantic_check:true}}},
    {recovery:{flow:{roles_ref:{id:'invalid',sha256:'a'.repeat(64)},target:path.join(runRoot,'never-opened.exe'),semantic_check:'true'}}},
  ])assert.equal((await execute('ig5_recovery',args)).isError,true);
  assert.equal(approvals.length,0);assert.deepEqual(blockedProcesses,[]);
  pass('Actual DSH flow schema and invalid-reference/decoder-override refusals preserve no native dispatch');
  const recurrenceSchema=schemas.find(item=>item.name==='ig5_recovery').parameters.properties.recovery.properties.recurrences;
  assert.equal(recurrenceSchema.additionalProperties,false);assert.deepEqual(recurrenceSchema.required,['flow_ref']);
  assert.deepEqual(recurrenceSchema.properties.sample_strategy.enum,['first4-last4','distinct-source-targets']);
  assert.equal(recurrenceSchema.properties.pair_offset.maximum,255);
  for(const args of [
    {recovery:{recurrences:{flow_ref:{id:'invalid',sha256:'a'.repeat(64)}}}},
    {recovery:{recurrences:{flow_ref:{id:'11111111-1111-1111-1111-111111111111',sha256:'a'.repeat(64)},target:path.join(runRoot,'never-opened.exe')}}},
    {recovery:{recurrences:{flow_ref:{id:'invalid',sha256:'a'.repeat(64)}},flow:{}}},
  ])assert.equal((await execute('ig5_recovery',args)).isError,true);
  assert.equal(approvals.length,0);assert.deepEqual(blockedProcesses,[]);
  pass('Actual DSH recurrence schema rejects uncommitted references, caller target and mixed modes without native dispatch');
  const researchSchema = schemas.find(item => item.name === 'ig5_workspace').parameters.properties.workspace.properties.research;
  assert.equal(researchSchema.additionalProperties, false);
  assert(researchSchema.properties.operation.enum.includes('revise-hypothesis'));
  assert.equal(researchSchema.properties.value.oneOf.length, 4);
  assert(researchSchema.properties.value.oneOf.every(s => s.additionalProperties === false));
  const researchRequest = { target: path.join(runRoot, 'never-opened.exe'), workspace: { action: 'research-update', id: randomUUID(), research: {
    operation: 'initialize', expected_research_revision: 0, expected_task_revision: 0, scope_digest: 'a'.repeat(64),
    value: { question: 'Bounded question', inputDomain: 'Listed inputs', returns: 'Recorded return', outputs: 'None', sideEffects: 'Unknown', environment: 'Offline', exclusions: 'Unobserved paths' },
  } } };
  const validResearch = await execute('ig5_workspace', researchRequest);
  assert.equal(validResearch.isError, true); assert.match(JSON.stringify(validResearch), /workspace requires an opened static target/);
  const invalidResearch = structuredClone(researchRequest); invalidResearch.workspace.research.value.verified = true;
  const invalidResearchResult = await execute('ig5_workspace', invalidResearch);
  assert.equal(invalidResearchResult.isError, true);
  assert.doesNotMatch(JSON.stringify(invalidResearchResult), /workspace requires an opened static target/, 'Unknown nested verification field must fail runtime envelope before target dispatch');
  assert.equal(approvals.length, 0); assert.deepEqual(blockedProcesses, []);
  pass('Actual DSH registers the bounded research schema; runtime envelope rejects caller verification before target dispatch; Core8/Full43 unchanged');
  const caseSchema=schemas.find(item=>item.name==='ig5_workspace').parameters.properties.workspace;
  for(const action of ['case-status','case-index','case-search','case-read','method-registry','method-applicability','experiment-shadow','candidate-prepare','candidate-verify','candidate-read','candidate-simplify','cff-overlay','cff-read','cff-state'])assert(caseSchema.properties.action.enum.includes(action));
  const caseRead=await execute('ig5_workspace',{target:path.join(runRoot,'never-opened.exe'),workspace:{action:'case-status',id:randomUUID()}});
  assert.equal(caseRead.isError,true);assert.match(JSON.stringify(caseRead),/opened static target/);
  for(const extra of [{projectId:'forged'},{scope:{kind:'private'}},{runId:'forged'},{execute:true}]){
    const denied=await execute('ig5_workspace',{target:path.join(runRoot,'never-opened.exe'),workspace:{action:'case-search',id:randomUUID(),query:'known result',...extra}});
    assert.equal(denied.isError,true);assert.match(JSON.stringify(denied),/Invalid private case index fields/);
  }
  assert.equal(approvals.length,0);assert.deepEqual(blockedProcesses,[]);
  pass('Actual DSH private-case schema rejects forged scope/run/execution before static-target lookup; no new gate or worker');
  for(const action of ['method-registry','method-applicability']){
    const denied=await execute('ig5_workspace',{target:path.join(runRoot,'never-opened.exe'),workspace:{action,id:randomUUID(),...(action==='method-applicability'?{method_id:'address-space-check'}:{})}});
    assert.equal(denied.isError,true);assert.match(JSON.stringify(denied),/opened static target/);
  }
  const forgedMethod=await execute('ig5_workspace',{target:path.join(runRoot,'never-opened.exe'),workspace:{action:'method-applicability',id:randomUUID(),method_id:'address-space-check',predicates:{'static-observation':true}}});
  assert.equal(forgedMethod.isError,true);assert.match(JSON.stringify(forgedMethod),/Invalid fixed method query fields/);
  assert.equal(approvals.length,0);assert.deepEqual(blockedProcesses,[]);
  pass('Actual DSH method schema rejects caller predicates and requires an opened static target without native execution');
  for(const mode of ['off','shadow']){
    const denied=await execute('ig5_workspace',{target:path.join(runRoot,'never-opened.exe'),workspace:{action:'experiment-shadow',id:randomUUID(),mode}});
    assert.equal(denied.isError,true);assert.match(JSON.stringify(denied),/opened static target/);
  }
  for(const extra of [{mode:'assist'},{mode:'shadow',existingToolRequest:{}},{mode:'shadow',budget:40}]){
    const denied=await execute('ig5_workspace',{target:path.join(runRoot,'never-opened.exe'),workspace:{action:'experiment-shadow',id:randomUUID(),...extra}});
    assert.equal(denied.isError,true);assert.match(JSON.stringify(denied),/Invalid experiment shadow fields|Only off.shadow/);
  }
  assert.equal(approvals.length,0);assert.deepEqual(blockedProcesses,[]);
  pass('Actual DSH shadow schema rejects assist and executable proposal injection without starting a worker');
  const candidateRef={id:randomUUID(),sha256:'a'.repeat(64)};
  const candidateAST={nodes:[{id:0,op:'const',bits:8,args:[],value:'0x0'}],root:0};
  for(const workspace of [{action:'candidate-prepare',source_ref:candidateRef,root_node:0},{action:'candidate-verify',candidate_ref:candidateRef,candidate_ast:candidateAST},{action:'candidate-read',report_ref:candidateRef}]){
    const result=await execute('ig5_workspace',{target:path.join(runRoot,'never-opened.exe'),workspace:{id:randomUUID(),...workspace}});assert.equal(result.isError,true);assert.match(JSON.stringify(result),/opened static target/);
  }
  const forgedCandidate=await execute('ig5_workspace',{target:path.join(runRoot,'never-opened.exe'),workspace:{action:'candidate-verify',id:randomUUID(),candidate_ref:candidateRef,candidate_ast:candidateAST,verified:true}});
  assert.equal(forgedCandidate.isError,true);assert.match(JSON.stringify(forgedCandidate),/Invalid candidate contract fields/);
  assert.equal(approvals.length,0);assert.deepEqual(blockedProcesses,[]);
  pass('Actual DSH candidate schema requires opened static target and rejects caller verified authority without native dispatch');
  const simplify=await execute('ig5_workspace',{target:path.join(runRoot,'never-opened.exe'),workspace:{action:'candidate-simplify',id:randomUUID(),candidate_ref:candidateRef}});
  assert.equal(simplify.isError,true);assert.match(JSON.stringify(simplify),/opened static target/);
  for(const extra of [{provider:'external'},{candidate_ast:candidateAST},{verified:true},{timeoutMs:999999},{path:'C:/untrusted'}]){
    const denied=await execute('ig5_workspace',{target:path.join(runRoot,'never-opened.exe'),workspace:{action:'candidate-simplify',id:randomUUID(),candidate_ref:candidateRef,...extra}});assert.equal(denied.isError,true);assert.match(JSON.stringify(denied),/Invalid candidate contract fields/);
  }
  assert.equal(approvals.length,0);assert.deepEqual(blockedProcesses,[]);
  pass('Actual DSH fixed single-provider schema rejects alternate provider/code/path/budget and grants no new authority');
  for(const workspace of [{action:'cff-overlay',snapshot_id:randomUUID(),verification_ref:candidateRef},{action:'cff-read',report_ref:candidateRef}]){
    const result=await execute('ig5_workspace',{target:path.join(runRoot,'never-opened.exe'),workspace:{id:randomUUID(),...workspace}});assert.equal(result.isError,true);assert.match(JSON.stringify(result),/opened static target/);
  }
  for(const extra of [{graph:{}},{state_variable:'rax'},{verified:true},{execute:true},{budget:999999}]){
    const result=await execute('ig5_workspace',{target:path.join(runRoot,'never-opened.exe'),workspace:{action:'cff-overlay',id:randomUUID(),snapshot_id:randomUUID(),...extra}});assert.equal(result.isError,true);assert.match(JSON.stringify(result),/Invalid CFF read-only fields/);
  }
  assert.equal(approvals.length,0);assert.deepEqual(blockedProcesses,[]);
  pass('Actual DSH CFF schema requires current opened target, rejects graph/state/proof/budget injection and preserves original approvals');
  const verificationSchema = schemas.find(item => item.name === 'ig5_workspace').parameters.properties.workspace.properties.verification;
  assert.equal(verificationSchema.additionalProperties, false);
  assert.equal(verificationSchema.properties.expected_research_revision.type, 'integer');
  const verifyInput = { expected_research_revision: 0, expected_task_revision: 0, scope_digest: 'a'.repeat(64), evidence_id: randomUUID(), obligation_id: randomUUID() };
  const validVerification = await execute('ig5_workspace', { target: path.join(runRoot, 'never-opened.exe'), workspace: { action: 'research-verify', id: randomUUID(), verification: verifyInput } });
  assert.equal(validVerification.isError, true); assert.match(JSON.stringify(validVerification), /opened static target/);
  for (const extra of [{ command: 'arbitrary' }, { verifier_script: 'arbitrary.py' }, { passed: true }]) {
    const rejected = await execute('ig5_workspace', { target: path.join(runRoot, 'never-opened.exe'), workspace: { action: 'research-verify', id: randomUUID(), verification: { ...verifyInput, ...extra } } });
    assert.equal(rejected.isError, true); assert.match(JSON.stringify(rejected), /Fixed verification requires/);
  }
  assert.equal(approvals.length, 0); assert.deepEqual(blockedProcesses, []);
  pass('Actual DSH fixed verifier entry rejects command/script/verdict overrides before target dispatch and preserves the original execution gates');
  assert(schemas.find(item => item.name === 'ig5_workspace').parameters.properties.workspace.properties.action.enum.includes('plan'));
  const planOverride = await execute('ig5_workspace', { target: path.join(runRoot, 'never-opened.exe'), workspace: { action: 'plan', id: randomUUID(), auto_execute: true } });
  assert.equal(planOverride.isError, true); assert.match(JSON.stringify(planOverride), /workspace field is not valid/);
  const planRead = await execute('ig5_workspace', { target: path.join(runRoot, 'never-opened.exe'), workspace: { action: 'plan', id: randomUUID() } });
  assert.equal(planRead.isError, true); assert.match(JSON.stringify(planRead), /opened static target/);
  assert.equal(approvals.length, 0); assert.deepEqual(blockedProcesses, []);
  pass('Actual DSH plan entry rejects automatic execution overrides before dispatch; it remains read-only under Core8/Full43');
  assert(schemas.find(item => item.name === 'ig5_workspace').parameters.properties.workspace.properties.action.enum.includes('resume'));
  const resumeOverride = await execute('ig5_workspace', { target: path.join(runRoot, 'never-opened.exe'), workspace: { action: 'resume', id: randomUUID(), auto_execute: true } });
  assert.equal(resumeOverride.isError, true); assert.match(JSON.stringify(resumeOverride), /workspace field is not valid/);
  const resumeRead = await execute('ig5_workspace', { target: path.join(runRoot, 'never-opened.exe'), workspace: { action: 'resume', id: randomUUID() } });
  assert.equal(resumeRead.isError, true); assert.match(JSON.stringify(resumeRead), /opened static target/);
  pass('Actual DSH resume entry preserves explicit target checks and refuses automatic execution');
  for(const args of [
    {recovery:{recurrences:{flow_ref:{id:'invalid',sha256:'a'.repeat(64)},sample_strategy:'invented'}}},
    {recovery:{recurrences:{flow_ref:{id:'invalid',sha256:'a'.repeat(64)},pair_offset:0}}},
    {recovery:{recurrences:{flow_ref:{id:'invalid',sha256:'a'.repeat(64)},sample_strategy:'distinct-source-targets',pair_offset:256}}},
  ])assert.equal((await execute('ig5_recovery',args)).isError,true);
  assert.deepEqual(blockedProcesses,[]);assert.equal(approvals.length,0);
  pass('Actual DSH diverse-pair schema validates bounded strategy/page selection before any native dispatch');
  const handlerSchema=schemas.find(item=>item.name==='ig5_recovery').parameters.properties.recovery.properties.handlers;
  assert.equal(handlerSchema.additionalProperties,false);assert.deepEqual(handlerSchema.required,['recurrences_ref','target']);
  for(const args of [
    {recovery:{handlers:{recurrences_ref:{id:'invalid',sha256:'a'.repeat(64)},target:path.join(runRoot,'never-opened.exe')}}},
    {recovery:{handlers:{recurrences_ref:{id:'invalid',sha256:'a'.repeat(64)},target:path.join(runRoot,'never-opened.exe'),projection_path:['0x1234']}}},
    {recovery:{handlers:{},recurrences:{}}},
  ])assert.equal((await execute('ig5_recovery',args)).isError,true);
  assert.equal(approvals.length,0);assert.deepEqual(blockedProcesses,[]);
  pass('Actual DSH handler schema rejects uncommitted sources, caller addresses and mixed modes before native dispatch');
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
  assert.equal(approvals.length, 14); assert.deepEqual(blockedProcesses, []);
  pass('All fourteen real write/execution schemas reach DSH approval and are denied without starting a worker');
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
    const agentless = await executeSingleCall({ name: 'ig5_rename', args: minimal(schemas.find(item => item.name === 'ig5_rename').parameters), callId: 'sdk-agentless-rename' });
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
  assert.equal(context.tools.schemas(a).length, 8); assert.equal(context.tools.schemas(b).length, 44);
  pass('Core/Full command changes remain independent after real policy denials');
  // Actual installed tool schema/dispatcher, with controlled session lineage.
  // Native subagent lifecycle is tested separately in the live DSH GUI.
  a.session.header = { id: a.id };
  b.session.header = { id: b.id, parentSession: a.id };
  const budgetStarted = await execute('ig5_profile', { collaboration: { action: 'start', max_calls: 2 } });
  assert.equal(budgetStarted.isError, false);
  assert.equal((await execute('ig5_profile')).isError, false);
  assert.equal((await execute('ig5_profile', {}, b)).isError, false);
  const budgetBlocked = await execute('ig5_profile', {}, b);
  assert.equal(budgetBlocked.isError, true);
  assert.match(JSON.stringify(budgetBlocked), /budget exhausted/);
  const ledger = await execute('ig5_profile', { collaboration: { action: 'status' } }, b);
  assert.equal(ledger.isError, false); assert.equal(ledger.value.collaboration.used, 2);
  assert.deepEqual(ledger.value.collaboration.byAgent, { 'sdk-A': 1, 'sdk-B': 1 });
  pass('Actual installed DSH schema/dispatcher enforces shared parent-child IG5 budget and preserves exempt status after exhaustion');
  const guardDataset=path.join(runRoot,'eval-guard-dataset.json');
  fs.writeFileSync(guardDataset,JSON.stringify({schema:'ig5-eval-pilot-evidence-v1',task:{sentinel:'HOST_EVIDENCE_SENTINEL'},brief:{},historical:{},current:{},catalog:{}}));
  const guardOwner=context.plugin(await import(pathToFileURL(path.join(pluginRoot,'scripts/evals/model_guard.mjs')).href),
    {dataset:guardDataset,variant:'baseline',log:path.join(runRoot,'eval-guard-tools.jsonl')});
  await guardOwner;
  try {
    const visible=await execute('ig5_eval',{action:'task'});
    assert.equal(visible.isError,false);assert.equal(visible.value.sentinel,'HOST_EVIDENCE_SENTINEL');
    assert(visible.content.some(b=>b.type==='text'&&b.text.includes('HOST_EVIDENCE_SENTINEL')));
    assert.equal((await execute('ig5_eval',{action:'task',path:'oracle.mjs'})).isError,true);
    assert.equal((await execute('ig5_status')).isError,true);
  } finally {await guardOwner.dispose();}
  pass('Actual DSH renders model-replay evidence and rejects extra path fields and all non-allowlisted tool dispatch');
  const { memoryResumeFixture } = await import(pathToFileURL(path.join(pluginRoot, 'scripts/evals/memory_resume_fixture.mjs')).href);
  {
    const fusionGuard=context.plugin(await import(pathToFileURL(path.join(pluginRoot,'scripts/evals/fusion/model_guard.mjs')).href),{taskId:'owned-bv-add-zero',group:'A',log:path.join(runRoot,'fusion-eval-tools.jsonl'),runRoot:path.join(runRoot,'fusion-eval')});await fusionGuard;
    try{context.emit('agent/created',{agent:a});const assembled=await context.systemPrompt.assemble({scope:a});assert.deepEqual(assembled.tools.map(t=>t.name),['ig5_fusion_eval']);assert.equal(assembled.sections.length,1);assert.equal(assembled.sections[0].name,'ig5-fusion-fixed-study');const task=await execute('ig5_fusion_eval',{action:'task'});assert.equal(task.isError,false);assert.equal(task.value.payload.id,'owned-bv-add-zero');assert(/^[a-f0-9]{64}$/.test(task.value.sourceSha256));assert.equal((await execute('ig5_fusion_eval',{action:'task',path:'private-judge'})).isError,true);assert.equal((await execute('ig5_fusion_eval',{action:'verify'})).isError,true);assert.equal((await execute('ig5_status')).isError,true);}finally{await fusionGuard.dispose();}
    pass('Actual Harness A-E evaluation boundary renders source hashes, withholds higher-group actions and denies file/tool/extra-field access');
  }
  const resumeDataset = path.join(runRoot, 'resume-dataset.json'); fs.writeFileSync(resumeDataset, JSON.stringify(memoryResumeFixture()));
  const resumeGuard = context.plugin(await import(pathToFileURL(path.join(pluginRoot, 'scripts/evals/memory_resume_guard.mjs')).href),
    { dataset: resumeDataset, variant: 'brief-lcm', log: path.join(runRoot, 'resume-tools.jsonl'), runRoot: path.join(runRoot, 'resume-archive') });
  await resumeGuard;
  try {
    const navigation = await execute('ig5_memory_eval', { action: 'resume' });
    assert.equal(navigation.isError, false); assert.equal(navigation.value.gaps.length, 3);
    assert.equal(navigation.value.executionAuthorized, false);
    assert.equal((await execute('ig5_memory_eval', { action: 'resume', path: 'foreign' })).isError, true);
    assert.equal((await execute('ig5_status')).isError, true);
  } finally { await resumeGuard.dispose(); }
  pass('Actual DSH loads the replay archive after compaction/reopen and enforces the memory-only evaluation boundary');
  await owner.dispose(); owner = null;
  assert(!(await context.systemPrompt.assemble({ scope: a })).contexts.some(p => p.name === 'ig5-lcm-history'));
  assert.equal(context.tools.schemas(a).length, 0); assert.equal(context.tools.schemas(b).length, 0);
  assert.equal((await context.skills.list({ scope: a })).filter(item => item.name.startsWith('ig5-')).length, 0);
  assert.equal(context.commands.find(a, 'ig5'), undefined);
  assert.equal(context.sessionProjections.restore({}, [], 0, { id: 'disposed-sdk-session' }, 0).snapshot.values.ig5dash, undefined);
  pass('Actual Cordis owner unload removes all scoped tools, bundled skills, slash command and projection');
  const report = { ok: !outputFailures.length, timestamp: new Date().toISOString(), pluginRoot, pluginVersion: metadata.version, pluginEntrySha256: createHash('sha256').update(fs.readFileSync(path.join(pluginRoot, 'index.js'))).digest('hex'), host: { asar, name: application.name, version: runtimeVersion, desktopVersion: application.version, runtimePackage: appBoot.name, sdkVersions }, frontendContracts, compatibility, peerDependencies: Object.fromEntries(declaredPeers), extraction: { sdkRoot, packages: copied.size, files: copiedFiles, bytes: copiedBytes }, runRoot, assertions, outputFailures, deniedWriteTools: writeNames, approvals, nativeWorkersStarted: 0, childProcessesStarted: processIdentityQueries.length, processIdentityQueries, limits: 'Actual installed service API checks in an isolated Cordis context; no desktop GUI launch, model API call, engine analysis or debugger execution. SlotCore checks registrations only, with a placeholder React reference; rendering is verified separately. Only the explicit read-only own-process creation-identity query may start PowerShell.' };
  fs.writeFileSync(path.join(reportRoot, 'host-sdk.json'), JSON.stringify(report, null, 2));
  assert.deepEqual(outputFailures, [], 'Real DSH canonical output validation must pass');
  console.log(`PASS installed DSH ${runtimeVersion} SDK; report ${path.join(reportRoot, 'host-sdk.json')}`);
  sdkCheckPassed = true;
} catch (error) {
  fs.writeFileSync(path.join(reportRoot, 'host-sdk.json'), JSON.stringify({ ok: false, timestamp: new Date().toISOString(), pluginRoot, pluginVersion: metadata.version, host: { asar, name: application.name, version: runtimeVersion, desktopVersion: application.version, runtimePackage: appBoot.name, sdkVersions }, frontendContracts, compatibility, peerDependencies: Object.fromEntries(declaredPeers), extraction: { sdkRoot, packages: copied.size, files: copiedFiles, bytes: copiedBytes }, runRoot, assertions, outputFailures, approvals, preCalls, blockedProcesses, nativeWorkersStarted: 0, childProcessesStarted: processIdentityQueries.length, processIdentityQueries, error: { name: error.name, message: error.message }, limits: 'Isolated actual installed service API check; no desktop GUI or engine process started.' }, null, 2));
  throw error;
} finally {
  await owner?.dispose(); await approvalOwner?.dispose(); await context?.fiber?.dispose();
  for (const [name, original] of originals) childProcess[name] = original;
  syncBuiltinESMExports();
  if (!explicitEvidence && sdkCheckPassed) {
    try { fs.rmSync(reportRoot, { recursive: true, force: true }); } catch { /* ignore */ }
  }
}
