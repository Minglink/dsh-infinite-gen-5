import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import test from 'node:test';

const source = fs.readFileSync(new URL('../client.js', import.meta.url), 'utf8');
let currentHarness;
const React = {
  createElement: (type, props, ...children) => ({ type, props: props || {}, children: children.flat(Infinity).filter(x => x !== null && x !== undefined && x !== false) }),
  useState(initial) {
    const h = currentHarness, i = h.cursor++;
    if (!(i in h.cells)) h.cells[i] = typeof initial === 'function' ? initial() : initial;
    return [h.cells[i], value => { h.cells[i] = typeof value === 'function' ? value(h.cells[i]) : value; }];
  },
  useRef(initial) { const h = currentHarness, i = h.cursor++; return h.cells[i] ||= { current: initial }; },
  useMemo(fn, deps) {
    const h = currentHarness, i = h.cursor++, old = h.cells[i];
    if (!old || !same(old.deps, deps)) h.cells[i] = { deps, value: fn() };
    return h.cells[i].value;
  },
  useEffect(fn, deps) {
    const h = currentHarness, i = h.cursor++, old = h.effects[i];
    if (!old || !same(old.deps, deps)) h.pending.push(() => { old?.cleanup?.(); h.effects[i] = { deps, cleanup: fn() }; });
  },
};
const same = (a, b) => !!a && !!b && a.length === b.length && a.every((x, i) => Object.is(x, b[i]));
let request = () => { throw new Error('unexpected network call'); };
let api;
const sandbox = { window: { __ModuleLoader__: { load: value => { api = value.factory(name => { assert.equal(name, 'react'); return React; }); } } }, console, URLSearchParams, fetch: (...args) => request(...args), setTimeout, clearTimeout, location: { href: 'http://localhost/test' }, navigator: {} };
vm.runInNewContext(source, sandbox, { filename: 'client.js' });
const ui = api.__test;
const plain = value => JSON.parse(JSON.stringify(value));
function harness(component, props = {}) {
  return { component, props, cells: [], effects: [], pending: [], cursor: 0, tree: null,
    render(nextProps) { if (nextProps) this.props = nextProps; this.cursor = 0; currentHarness = this; this.tree = component(this.props); currentHarness = null; this.pending.splice(0).forEach(fn => fn()); return this.tree; },
    unmount() { this.effects.forEach(e => e?.cleanup?.()); },
  };
}
function nodes(node, predicate) { if (!node || typeof node !== 'object') return []; return (predicate(node) ? [node] : []).concat((node.children || []).flatMap(x => nodes(x, predicate))); }
function text(node) { return typeof node === 'string' || typeof node === 'number' ? String(node) : (node?.children || []).map(text).join(''); }
function button(tree, label) { const found = nodes(tree, n => n.type === 'button' && text(n) === label)[0]; assert.ok(found, `button ${label}`); return found; }
function row(tree, label) { const found = nodes(tree, n => n.type === 'tr' && text(n).includes(label) && typeof n.props.onClick === 'function')[0]; assert.ok(found, `row ${label}`); return found; }
const response = data => ({ ok: true, status: 200, json: async () => ({ data }) });
const settle = async () => { for (let i = 0; i < 8; i++) await Promise.resolve(); };
function deferred() { let resolve, reject; const promise = new Promise((yes, no) => { resolve = yes; reject = no; }); return { promise, resolve, reject }; }
function markup(node) {
  const escape = value => String(value).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
  if (typeof node === 'string' || typeof node === 'number') return escape(node);
  if (!node) return '';
  assert.ok(node.props && Array.isArray(node.children), 'Objects are not valid as a React child');
  assert.equal(node.props.dangerouslySetInnerHTML, undefined, 'renderer must not inject HTML');
  return `<${typeof node.type === 'string' ? node.type : 'component'}>${(node.children || []).map(markup).join('')}</${typeof node.type === 'string' ? node.type : 'component'}>`;
}

test('CFG layout preserves branches, loops and disconnected blocks without invalid edges', () => {
  const graph = ui.layoutCfg({ blocks: [{ id: 0, succs: [1, 2] }, { id: 1, succs: [0] }, { id: 2, succs: [] }, { id: 9, succs: [] }], edges: [{ from: 0, to: 1 }, { from: 0, to: 2 }, { from: 1, to: 0 }, { from: 0, to: 1 }, { from: 0, to: 99 }] });
  assert.equal(graph.nodes.length, 4); assert.equal(graph.edges.length, 3);
  assert.equal(graph.edges[0].label, '分支 1'); assert.equal(graph.edges[1].label, '分支 2'); assert.equal(graph.edges[2].label, '回边');
  assert.ok(graph.edges.every(e => !/NaN|undefined/.test(e.path)));
  assert.equal(new Set(graph.nodes.map(n => `${n.x},${n.y}`)).size, 4);
});

test('large CFG is bounded and truthfully marks truncation', () => {
  const graph = ui.layoutCfg({ blocks: Array.from({ length: 310 }, (_, id) => ({ id, succs: [id + 1] })) });
  assert.equal(graph.nodes.length, 300); assert.equal(graph.truncated, true); assert.equal(graph.edges.length, 299);
});

test('variable highlighting respects identifiers and never interprets source as HTML', () => {
  const parts = plain(ui.highlightParts('key = monkey + key2 + key; // <script>x</script>', 'key'));
  assert.deepEqual(parts.filter(p => p.match).map(p => p.text), ['key', 'key']);
  const tree = { type: 'pre', props: {}, children: ui.renderCodeLines([{ line_no: 19, code: '<img src=x onerror=alert(1)> key' }], 'key') };
  assert.ok(markup(tree).includes('&lt;img')); assert.ok(!markup(tree).includes('<img'));
  assert.equal(ui.highlightParts('a.b + aXb', 'a.b').filter(p => p.match).length, 1);
});

test('audit normalization uses actual nested journal fields and preserves offset zero', () => {
  const item = ui.normalizeAudit({ ts: '2026-10-09T00:00:00Z', tool: 'ig5_patch_bytes', args: { target: 'C:/sample.exe', ea: '0x401000' }, detail: { before: '90', after: 'cc', fileOffset: 0 }, isError: false });
  assert.equal(item.target, 'C:/sample.exe'); assert.equal(item.ea, '0x401000'); assert.equal(item.fileOffset, 0); assert.equal(item.before, '90');
  assert.equal(ui.normalizedTarget('C:/A/B.EXE'), ui.normalizedTarget('c:\\a\\b.exe'));
  assert.equal(ui.normalizeAudit({ result: { isError: true, value: 'failed' } }).isError, true);
});

test('structure draft serializes target and C declaration without executing a write', () => {
  const declaration = 'struct Packet { char value[32]; };\n// "quoted"';
  const draft = ui.buildStructDraft('C:\\samples\\a.exe', declaration);
  const args = JSON.parse(draft.slice(draft.indexOf('{')));
  assert.equal(args.action, 'define'); assert.equal(args.decl, declaration); assert.equal(args.target, 'C:\\samples\\a.exe'); assert.equal(args.op, undefined);
});

test('structure editor inserts an editable draft through native selection APIs without submit/fetch', () => {
  const calls = [], span = { revision: 4, start: 7, end: 7 };
  const h = harness(ui.StructEditor, { target: 'sample.exe', inputActions: { captureInsertion: () => span, insertText: (...args) => { calls.push(['insert', ...args]); return true; }, persistDraft: () => calls.push(['persist']), submit: () => { throw new Error('must not submit'); } } });
  h.render(); button(h.tree, '生成审批草稿').props.onClick(); h.render();
  const draft = nodes(h.tree, n => n.type === 'textarea' && n.props['aria-label'] === '待发送工具调用草稿')[0];
  draft.props.onChange({ target: { value: draft.props.value + '\n请先核查类型名。' } }); h.render();
  button(h.tree, '插入会话草稿（待发送）').props.onClick(); h.render();
  assert.equal(calls[0][0], 'insert'); assert.equal(calls[0][2], span); assert.ok(calls[0][1].includes('请先核查类型名。')); assert.equal(calls[1][0], 'persist'); assert.match(text(h.tree), /尚未发送或执行/);
});

test('structure editor retains draft when composer is unavailable or refuses stale insertion', () => {
  const h = harness(ui.StructEditor, { target: 'sample.exe' }); h.render(); button(h.tree, '生成审批草稿').props.onClick(); h.render(); button(h.tree, '插入会话草稿（待发送）').props.onClick(); h.render();
  assert.match(text(h.tree), /复制下方草稿/);
  assert.ok(nodes(h.tree, n => n.type === 'textarea' && n.props['aria-label'] === '待发送工具调用草稿')[0].props.value.includes('ig5_struct'));
  const locked = harness(ui.StructEditor, { target: 'sample.exe', inputActions: { captureInsertion: () => ({}), insertText: () => false, persistDraft: () => assert.fail('must not persist rejected insertion') } });
  locked.render(); button(locked.tree, '生成审批草稿').props.onClick(); locked.render(); button(locked.tree, '插入会话草稿（待发送）').props.onClick(); locked.render(); assert.match(text(locked.tree), /暂不可用/);
});

test('CFG nodes retain double-click and keyboard actions instead of being captured by canvas pan', () => {
  const opened = [], h = harness(ui.CfgGraph, { cfg: { blocks: [{ id: 0, start: '0x1000', end: '0x1004', insns: 1, succs: [] }] }, onOpen: block => opened.push(block.start) });
  h.render(); h.render(); const svg = nodes(h.tree, n => n.type === 'svg')[0], block = nodes(h.tree, n => n.type === 'g' && n.props.role === 'button')[0];
  let captured = false;
  svg.props.onPointerDown({ button: 0, target: { closest: () => true }, currentTarget: { setPointerCapture: () => { captured = true; } } });
  assert.equal(captured, false); block.props.onDoubleClick(); block.props.onKeyDown({ key: 'Enter' }); assert.deepEqual(opened, ['0x1000', '0x1000']);
});

test('request generations reject old selections', () => {
  const gate = ui.makeRequestGate(), first = gate.next(), second = gate.next();
  assert.equal(gate.isCurrent(first), false); assert.equal(gate.isCurrent(second), true); gate.next(); assert.equal(gate.isCurrent(second), false);
});

test('POSIX sample identities remain case-sensitive while Windows spellings match', () => {
  assert.notEqual(ui.normalizedTarget('/home/user/A.exe'), ui.normalizedTarget('/home/user/a.exe'));
  assert.equal(ui.normalizedTarget('C:/A/B.EXE'), ui.normalizedTarget('c:\\a\\b.exe'));
});

test('touch pinch preserves its focal point and clamps zoom; touch blocks open read-only', () => {
  for (const viewport of [{ width: 329, height: 360 }, { width: 900, height: 440 }]) {
    const graph = { width: 624, height: 700 }, fit = ui.cfgFitCamera(graph, viewport.width, viewport.height);
    assert.ok(fit.x >= 11.99 && fit.y >= 11.99);
    assert.ok(fit.x + graph.width * fit.scale <= viewport.width - 11.99);
    assert.ok(fit.y + graph.height * fit.scale <= viewport.height - 11.99);
  }
  const start = ui.cfgPinchStart([{ x: 100, y: 100 }, { x: 200, y: 100 }], { scale: 1, x: 0, y: 0 });
  const camera = ui.cfgPinchCamera(start, [{ x: 50, y: 100 }, { x: 250, y: 100 }]);
  assert.equal(camera.scale, 2); assert.equal(camera.x, -150); assert.equal(camera.y, -100);
  assert.equal(ui.cfgPinchCamera(start, [{ x: -10000, y: 100 }, { x: 10000, y: 100 }]).scale, 4);
  const opened = [], h = harness(ui.CfgGraph, { cfg: { blocks: [{ id: 0, start: '0x1000', succs: [] }] }, onOpen: n => opened.push(n.start) });
  h.render(); const svg = nodes(h.tree, n => n.type === 'svg')[0];
  const event = (id, x, y) => ({pointerType: 'touch',pointerId:id,clientX:x,clientY:y,target:{closest:()=>({getAttribute:()=> '0'})},currentTarget:{setPointerCapture(){},getBoundingClientRect:()=>({width:800,left:0,top:0})}});
  svg.props.onPointerDown(event(1,100,100)); svg.props.onPointerUp(event(1,100,100)); assert.deepEqual(opened, ['0x1000']);
  svg.props.onPointerDown(event(2,100,100)); svg.props.onPointerMove(event(2,130,100)); svg.props.onPointerUp(event(2,130,100)); assert.equal(opened.length,1);
  svg.props.onPointerDown(event(3,100,100)); svg.props.onPointerDown(event(4,200,100));
  svg.props.onPointerMove(event(3,50,100)); svg.props.onPointerMove(event(4,250,100));
  svg.props.onPointerUp(event(3,50,100)); svg.props.onPointerUp(event(4,250,100)); assert.equal(opened.length,1);
  for (const id of [5,6,7]) svg.props.onPointerDown(event(id,100,100));
  for (const id of [5,6,7]) svg.props.onPointerUp(event(id,100,100));
  assert.equal(opened.length,1); h.unmount();
});

test('environment view reports missing local runtime and never assumes mobile execution', () => {
  const h = harness(ui.EnvironmentCard, { config: { host: { id: 'linux-arm64', supported: true }, engines: [{ id: 'ghidra', available: false, source: 'bundled', reason: '<missing ARM64 runtime>' }] } });
  h.render(); assert.match(text(h.tree), /Ghidra · 不可用/); assert.ok(markup(h.tree).includes('&lt;missing ARM64 runtime&gt;'));
  h.render({ config: { host: { id: 'ios-arm64', supported: false }, engines: [] } }); assert.match(text(h.tree), /移动界面可用不代表引擎已移植/); h.unmount();
});

test('pending lazy CFG reads cannot replace a newer function or survive same-function reload', async () => {
  const cfgReads = [];
  request = url => {
    const q = new URL(url, 'http://test').searchParams, type = q.get('type'), ea = q.get('ea');
    if (type === 'cfg') { const d = deferred(); cfgReads.push({ ea, d }); return d.promise; }
    return Promise.resolve(response(type === 'funcs' ? { funcs: [{ ea: '0x1000', name: 'one' }, { ea: '0x2000', name: 'two' }], total: 2 } : type === 'decompile' ? { ea, code: 'return 0;' } : { rows: [] }));
  };
  const h = harness(ui.FunctionsView, { target: '/home/sample.exe' }); h.render(); await settle(); h.render();
  row(h.tree, 'one').props.onClick(); h.render(); button(h.tree, '控制流 (CFG)').props.onClick(); h.render();
  row(h.tree, 'two').props.onClick(); h.render(); row(h.tree, 'two').props.onClick(); h.render();
  assert.equal(cfgReads.length, 3);
  cfgReads[2].d.resolve(response({ blocks: [], marker: 'current' })); await settle(); h.render();
  for (const old of cfgReads.slice(0, 2)) old.d.resolve(response({ blocks: [], marker: 'stale' }));
  await settle(); h.render(); assert.equal(nodes(h.tree, n => n.type === ui.CfgGraph)[0].props.cfg.marker, 'current'); h.unmount();
});

test('rapid function selections keep newest code, CFG and variable data', async () => {
  const pending = new Map();
  request = url => {
    const q = new URL(url, 'http://test').searchParams, type = q.get('type'), ea = q.get('ea');
    if (type === 'funcs') return Promise.resolve(response({ funcs: [{ ea: '0x1000', name: 'first', size: 4 }, { ea: '0x2000', name: 'second', size: 4 }], total: 2 }));
    const d = deferred(); pending.set(`${type}:${ea}`, d); return d.promise;
  };
  const h = harness(ui.FunctionsView, { target: 'sample.exe' }); h.render(); await settle(); h.render();
  row(h.tree, 'first').props.onClick(); h.render(); row(h.tree, 'second').props.onClick();
  assert.ok(!pending.has('cfg:0x2000') && !pending.has('slice:0x2000'), 'heavy views are requested on selection of that view');
  for (const ea of ['0x2000', '0x1000']) for (const type of ['decompile', 'xrefs', 'calls']) pending.get(`${type}:${ea}`).resolve(response(type === 'decompile' ? { ea, name: ea === '0x2000' ? 'second' : 'first', code: `code-${ea}` } : { rows: [] }));
  await settle(); h.render(); assert.match(text(h.tree), /code-0x2000/); assert.ok(!text(h.tree).includes('code-0x1000'));
  button(h.tree, '控制流 (CFG)').props.onClick(); h.render(); pending.get('cfg:0x2000').resolve(response({ blocks: [], edges: [], marker: '0x2000' })); await settle(); h.render(); assert.equal(nodes(h.tree, n => n.type === ui.CfgGraph)[0].props.cfg.marker, '0x2000');
  button(h.tree, '变量与切片').props.onClick(); h.render(); pending.get('slice:0x2000').resolve(response({ variables: [{ name: 'v-0x2000' }] })); await settle(); h.render(); assert.match(text(h.tree), /v-0x2000/); assert.ok(!text(h.tree).includes('v-0x1000')); h.unmount();
});

test('focused variable click requests var and highlights returned source line', async () => {
  const urls = [];
  request = url => {
    urls.push(url); const q = new URL(url, 'http://test').searchParams, type = q.get('type');
    return Promise.resolve(response(type === 'funcs' ? { funcs: [{ ea: '0x1000', name: 'main', size: 4 }], total: 1 } : type === 'decompile' ? { ea: '0x1000', name: 'main', code: 'key = 2;' } : type === 'slice' ? { variables: [{ name: 'key', type: 'int', size: 4 }], slice_lines: q.get('var') ? [{ line_no: 4, code: 'key = 2;' }] : [] } : type === 'cfg' ? { blocks: [], edges: [] } : { rows: [] }));
  };
  const h = harness(ui.FunctionsView, { target: 'sample.exe' }); h.render(); await settle(); h.render(); row(h.tree, 'main').props.onClick(); await settle(); h.render(); button(h.tree, '变量与切片').props.onClick(); h.render(); await settle(); h.render(); row(h.tree, 'key').props.onClick(); await settle(); h.render();
  assert.ok(urls.some(url => new URL(url, 'http://test').searchParams.get('var') === 'key')); assert.equal(nodes(h.tree, n => n.type === 'mark').map(text).join(''), 'key'); h.unmount();
});

test('switching target invalidates pending function reads and removes old code', async () => {
  const pending = [];
  request = url => {
    const q = new URL(url, 'http://test').searchParams;
    if (q.get('type') === 'funcs') return Promise.resolve(response({ funcs: [{ ea: '0x1000', name: q.get('target'), size: 4 }], total: 1 }));
    const d = deferred(); pending.push({ d, type: q.get('type') }); return d.promise;
  };
  const h = harness(ui.FunctionsView, { target: 'old.exe' }); h.render(); await settle(); h.render(); row(h.tree, 'old.exe').props.onClick(); h.render(); h.render({ target: 'new.exe' });
  for (const { d, type } of pending) d.resolve(response(type === 'decompile' ? { ea: '0x1000', name: 'old', code: 'STALE_CODE' } : type === 'cfg' ? { blocks: [], edges: [] } : type === 'slice' ? { variables: [] } : { rows: [] }));
  await settle(); h.render(); assert.ok(!text(h.tree).includes('STALE_CODE')); assert.match(text(h.tree), /new.exe/); assert.match(text(h.tree), /选择函数，查看当前静态引擎/); h.unmount();
});

test('CFG block jump uses only read-only disassembly and displays instructions', async () => {
  const urls = [], block = { id: 0, start: '0x1000', end: '0x1004', succs: [], insns: 1 };
  request = url => { urls.push(url); const q = new URL(url, 'http://test').searchParams, type = q.get('type'); return Promise.resolve(response(type === 'funcs' ? { funcs: [{ ea: '0x1000', name: 'main', size: 4 }], total: 1 } : type === 'decompile' ? { ea: '0x1000', name: 'main', code: 'return 0;' } : type === 'cfg' ? { blocks: [block], edges: [] } : type === 'slice' ? { variables: [] } : type === 'disasm' ? { rows: [{ ea: '0x1000', bytes: '90', text: 'nop' }] } : { rows: [] })); };
  const h = harness(ui.FunctionsView, { target: 'sample.exe' }); h.render(); await settle(); h.render(); row(h.tree, 'main').props.onClick(); await settle(); h.render(); button(h.tree, '控制流 (CFG)').props.onClick(); h.render(); await settle(); h.render(); nodes(h.tree, n => n.type === ui.CfgGraph)[0].props.onOpen(block); await settle(); h.render();
  assert.match(text(h.tree), /反汇编（只读）/); assert.match(text(h.tree), /nop/); assert.ok(urls.some(url => url.includes('type=disasm'))); h.unmount();
});

test('audit renderer filters targets, escapes malicious text, paginates and refreshes', async () => {
  const urls = [];
  request = url => { urls.push(url); return Promise.resolve(response({ rows: [{ tool: '<script>alert(1)</script>', args: { target: 'C:/a.exe', ea: '0x1000' }, ts: 'now', detail: { before: '90', after: 'cc', fileOffset: 0 } }, { tool: 'other-target', args: { target: 'C:/b.exe' } }], total: 25, offset: 0, limit: 20 })); };
  const h = harness(ui.PatchesView, { target: 'C:/a.exe' }); h.render(); await settle(); h.render(); assert.ok(!text(h.tree).includes('other-target')); assert.match(text(h.tree), /文件偏移: 0/); assert.ok(markup(h.tree).includes('&lt;script&gt;')); assert.ok(!markup(h.tree).includes('<script>'));
  button(h.tree, '下一页').props.onClick(); h.render(); await settle(); h.render(); assert.ok(urls.some(url => url.includes('offset=20')));
  const before = urls.length; button(h.tree, '刷新记录').props.onClick(); h.render(); await settle(); assert.ok(urls.length > before); h.unmount();
});

test('same target in different engines has a distinct selection and explicit draft engine', () => {
  const reverse = { key: 'same', target: 'C:/a.exe', engine: 'reverse' }, ghidra = { ...reverse, engine: 'ghidra' };
  assert.notEqual(ui.sessionIdentity(reverse), ui.sessionIdentity(ghidra));
  const draft = ui.buildStructDraft('C:/a.exe', 'struct A { int x; };', 'ghidra');
  assert.equal(JSON.parse(draft.slice(draft.indexOf('{'))).engine, 'ghidra');
  assert.equal(ui.parseWorkbenchFocus(JSON.stringify({ v: 1, target: 'a.exe', engine: 'ghidra', ea: '0xfffff80000000001' })).ea, '0xfffff80000000001');
  assert.equal(ui.parseWorkbenchFocus(JSON.stringify({ v: 1, target: 'a.exe', engine: 'x64dbg', ea: '0x1' })), null);
  assert.equal(ui.parseWorkbenchFocus(JSON.stringify({ v: 1, target: 'a.exe', engine: 'reverse', ea: 9007199254740992 })), null);
});

test('switching only engine invalidates pending function reads at the same target', async () => {
  const pending = [];
  request = url => {
    const q = new URL(url, 'http://test').searchParams, engine = q.get('engine'), type = q.get('type');
    assert.ok(['reverse', 'ghidra'].includes(engine));
    if (type === 'funcs') return Promise.resolve(response({ funcs: [{ ea: '0x1000', name: `${engine}-main`, size: 4 }], total: 1 }));
    const d = deferred(); pending.push({ d, type, engine }); return d.promise;
  };
  const h = harness(ui.FunctionsView, { target: 'same.exe', engine: 'reverse' }); h.render(); await settle(); h.render(); row(h.tree, 'reverse-main').props.onClick();
  h.render({ target: 'same.exe', engine: 'ghidra' }); await settle(); h.render(); row(h.tree, 'ghidra-main').props.onClick();
  for (const engine of ['ghidra', 'reverse']) for (const item of pending.filter(x => x.engine === engine)) item.d.resolve(response(item.type === 'decompile' ? { ea: '0x1000', name: engine, code: `${engine}-CODE` } : item.type === 'cfg' ? { blocks: [], edges: [] } : item.type === 'slice' ? { variables: [] } : { rows: [] }));
  await settle(); h.render(); assert.match(text(h.tree), /ghidra-CODE/); assert.ok(!text(h.tree).includes('reverse-CODE')); h.unmount();
});

test('workbench excludes dynamic sessions and validates native focus artifact identity', async () => {
  const sessions = [
    { key: 'r', target: 'same.exe', engine: 'reverse', alive: true, projectId: 'p', artifactId: 'a', dbRevision: 2 },
    { key: 'g', target: 'same.exe', engine: 'ghidra', alive: true, projectId: 'p', artifactId: 'a', dbRevision: 3 },
    { key: 'x', target: 'same.exe', engine: 'x64dbg', alive: true },
  ];
  request = () => Promise.resolve({ ok: true, json: async () => ({ sessions, jobs: [] }) });
  let acknowledgements = 0;
  const focus = { v: 1, target: 'same.exe', engine: 'ghidra', artifactId: 'a', projectId: 'p', ea: '0x1000' };
  const props = { viewRequest: { view: 'ig5', focus: JSON.stringify(focus) }, completeViewRequest: () => acknowledgements++ };
  const h = harness(ui.Workbench, props); h.render(); await settle(); h.render(); h.render();
  const overview = nodes(h.tree, node => node.type === ui.OverviewCard)[0];
  assert.equal(overview.props.sessions.length, 2); assert.equal(overview.props.currentSession.engine, 'ghidra');
  assert.equal(nodes(h.tree, node => node.type === ui.FunctionsView)[0].props.focus.ea, '0x1000'); assert.equal(acknowledgements, 1);
  h.render({ ...props, viewRequest: { view: 'ig5', focus: JSON.stringify({ ...focus, artifactId: 'replaced' }) } }); h.render();
  assert.match(text(h.tree), /身份不匹配/); h.unmount();
});

test('function navigation calls the host openView contract with a target-owned focus', async () => {
  request = () => Promise.resolve({ ok: true, json: async () => ({ sessions: [{ key: 'g', target: 'same.exe', engine: 'ghidra', alive: true, artifactId: 'a' }], jobs: [] }) });
  const calls = [], h = harness(ui.Workbench, { openView: (...args) => calls.push(args) }); h.render(); await settle(); h.render();
  nodes(h.tree, node => node.type === ui.FunctionsView)[0].props.onNavigate({ ea: '0x1000', name: 'main' });
  assert.equal(calls.length, 1); assert.equal(calls[0][0], 'ig5');
  const focus = JSON.parse(calls[0][1]); assert.equal(focus.engine, 'ghidra'); assert.equal(focus.target, 'same.exe'); assert.equal(focus.artifactId, 'a'); h.unmount();
});

test('runtime view reads cached debug_state only and escapes register values', async () => {
  const urls = [];
  request = (url, options) => { urls.push(url); assert.equal(options, undefined); return Promise.resolve(response({ state: 'paused', runId: 'run_A', stopSeq: 3, regs: { rax: '<script>unsafe</script>' } })); };
  const h = harness(ui.RuntimeView, { sessions: [{ key: 'x', target: 'a.exe', engine: 'x64dbg' }], refresh: 1 }); h.render(); await settle(); h.render();
  assert.match(text(h.tree), /run_A/); assert.match(text(h.tree), /只读缓存/); assert.ok(markup(h.tree).includes('&lt;script&gt;')); assert.ok(!markup(h.tree).includes('<script>'));
  assert.ok(urls.every(url => { const q = new URL(url, 'http://test').searchParams; return q.get('type') === 'debug_state' && q.get('engine') === 'x64dbg'; })); h.unmount();
});

test('Ghidra IR selection requests explicit level and keeps source distinct', async () => {
  const urls = [];
  request = url => { urls.push(url); return Promise.resolve(response({ kind: 'pcode', operations: ['COPY r0, 1'] })); };
  const h = harness(ui.IrView, { target: 'a.exe', engine: 'ghidra', ea: '0x1000' }); h.render(); await settle(); h.render();
  nodes(h.tree, node => node.type === 'select')[0].props.onChange({ target: { value: 'raw' } }); h.render(); await settle(); h.render();
  assert.ok(urls.some(url => { const q = new URL(url, 'http://test').searchParams; return q.get('type') === 'ir' && q.get('engine') === 'ghidra' && q.get('level') === 'raw' && q.get('limit') === '120'; }));
  assert.match(text(h.tree), /不对应 Reverse/); assert.match(text(h.tree), /COPY r0/); h.unmount();
});

test('audit view includes only selected engine at the same target', async () => {
  request = url => { assert.equal(new URL(url, 'http://test').searchParams.get('engine'), 'ghidra'); return Promise.resolve(response({ rows: [{ tool: 'ghidra-note', args: { target: 'a.exe', engine: 'ghidra' } }, { tool: 'ig5_sync', args: { target: 'a.exe' }, detail: { destination: { engine: 'ghidra' }, note: 'sync destination evidence' } }, { tool: 'reverse-note', args: { target: 'a.exe' } }], total: 1 })); };
  const h = harness(ui.PatchesView, { target: 'a.exe', engine: 'ghidra' }); h.render(); await settle(); h.render();
  assert.match(text(h.tree), /ghidra-note/); assert.match(text(h.tree), /sync destination evidence/); assert.ok(!text(h.tree).includes('reverse-note')); h.unmount();
});

test('overview preserves partial analysis status instead of presenting completion', () => {
  const h = harness(ui.OverviewCard, { currentSession: { target: 'a.exe', engine: 'ghidra', partial: true, n_funcs: 17 }, sessions: [], runningCount: 0 });
  h.render(); assert.match(text(h.tree), /部分分析结果/); assert.ok(!text(h.tree).includes('分析会话就绪'));
  assert.ok(nodes(h.tree, node => node.props?.className === 'ig5-chip warn').length); h.unmount();
});

test('runtime target switch never labels the previous target snapshot as the new target', async () => {
  const a = { key: 'a', target: 'A.exe', engine: 'x64dbg', artifactId: 'artifact-A' };
  const b = { key: 'b', target: 'B.exe', engine: 'x64dbg', artifactId: 'artifact-B' };
  const oldRefresh = deferred(), nextTarget = deferred(); let aReads = 0;
  request = url => new URL(url, 'http://test').searchParams.get('target') === 'A.exe'
    ? (++aReads === 1 ? Promise.resolve(response({ state: 'paused', runId: 'run-A', regs: { rip: '0xAAA' } })) : oldRefresh.promise)
    : nextTarget.promise;
  const h = harness(ui.RuntimeView, { sessions: [a, b], refresh: 1 }); h.render(); await settle(); h.render();
  assert.match(text(h.tree), /run-A/);
  h.render({ sessions: [a, b], refresh: 2 });
  nodes(h.tree, node => node.type === 'select')[0].props.onChange({ target: { value: ui.sessionIdentity(b) } });
  h.render(); h.render();
  assert.match(text(h.tree), /B.exe/); assert.ok(!text(h.tree).includes('run-A')); assert.ok(!text(h.tree).includes('0xAAA'));
  oldRefresh.resolve(response({ state: 'paused', runId: 'late-A', regs: { rip: '0xAAA' } })); await settle(); h.render();
  assert.ok(!text(h.tree).includes('late-A'));
  nextTarget.resolve(response({ state: 'paused', runId: 'run-B', regs: { rip: '0xBBB' } })); await settle(); h.render();
  assert.match(text(h.tree), /run-B/); assert.ok(!text(h.tree).includes('0xAAA')); h.unmount();
});

test('runtime replacement at the same path hides the old artifact snapshot', async () => {
  const session = { key: 'same', target: 'same.exe', engine: 'x64dbg', artifactId: 'old', attachmentId: 'old-attachment' };
  const next = deferred(); let reads = 0;
  request = () => ++reads === 1 ? Promise.resolve(response({ runId: 'old-run', regs: { rip: '0xAAA' } })) : next.promise;
  const h = harness(ui.RuntimeView, { sessions: [session], refresh: 1 }); h.render(); await settle(); h.render();
  assert.match(text(h.tree), /old-run/);
  h.render({ sessions: [{ ...session, artifactId: 'new', attachmentId: 'new-attachment' }], refresh: 1 }); h.render();
  assert.ok(!text(h.tree).includes('old-run')); assert.ok(!text(h.tree).includes('0xAAA'));
  next.resolve(response({ runId: 'new-run' })); await settle(); h.render(); assert.match(text(h.tree), /new-run/); h.unmount();
});

const scanFixture = (marker = 'AES S-box') => ({ schemaVersion: 2, sourceEngine: 'ghidra',
  entropies: [{ name: '.rdata', ea: '0x140003000', size: 8192, sampledBytes: 4096, entropy: 7.6543, truncated: true,
    interpretation: 'high entropy is only a compression/encryption/random-data clue', coverage: [{ start: '0x140003000', size: 4096 }] }],
  crypto_markers: [{ name: marker, marker, ea: '0x140003110', kind: 'cipher', constantRole: 'substitution-table',
    evidence: { byteOrder: 'byte-array', verifiedBytes: 256, segment: '.rdata', claim: 'constant bytes match; algorithm use and keys are unproven' } }],
  suspicious_apis: [{ module: 'bcrypt.dll', api: 'BCryptDecrypt', category: 'crypto', ea: '0x140005100',
    addressRole: 'import-slot', addressSpace: 'memory', interpretation: 'import presence is a lead; behavior is unproven' }],
  coverage: { bytesRead: 4096, sampling: 'bounded prefix/middle/suffix; unobserved bytes are not classified' },
  truncated: true, limits: { max_bytes: 4096 }, idb_modified: false,
});
const fingerprintFixture = { abi: 'MSVC', total_functions: 4, library_functions_count: 1, library_ratio: 0.25, user_functions_count: 3, sample_library_funcs: [{ name: 'memcpy' }] };
function control(tree, label) { const found = nodes(tree, n => n.props?.['aria-label'] === label)[0]; assert.ok(found, `control ${label}`); return found; }
function edit(h, label, value) { control(h.tree, label).props.onChange({ target: { value } }); h.render(); }

test('scan normalization accepts canonical structured markers/API evidence and legacy aliases', () => {
  const canonical = ui.normalizeScan(scanFixture());
  assert.equal(canonical.crypto_markers[0].name, 'AES S-box'); assert.equal(canonical.suspicious_apis[0].api, 'BCryptDecrypt');
  assert.equal(canonical.suspicious_apis[0].module, 'bcrypt.dll'); assert.equal(canonical.entropies[0].sampledBytes, 4096); assert.equal(canonical.truncated, true);
  const legacy = ui.normalizeScan({ entropy: [{ segment: '.data', entropy: 6.5 }], crypto: ['MD5 IV', { marker: 'SHA-256 K', ea: '0x2000' }], suspiciousApis: ['recv', { name: 'CryptDecrypt', module: 'advapi32.dll' }] });
  assert.equal(legacy.entropies[0].name, '.data'); assert.equal(legacy.crypto_markers[1].name, 'SHA-256 K');
  assert.equal(legacy.suspicious_apis[0].api, 'recv'); assert.equal(legacy.suspicious_apis[1].api, 'CryptDecrypt');
  assert.equal(ui.normalizeScan({ crypto_markers: [], crypto: ['stale legacy'] }).crypto_markers.length, 0);
});

test('scan renderer uses structured canonical hits as text rather than React object children', async () => {
  const urls = [];
  request = (url, options) => { assert.equal(options, undefined); urls.push(url); return Promise.resolve(response(new URL(url, 'http://test').searchParams.get('type') === 'scan' ? scanFixture('<script>sample-marker</script>') : fingerprintFixture)); };
  const h = harness(ui.ScanView, { target: 'sample.exe', engine: 'ghidra' }); h.render(); await settle(); h.render();
  assert.match(text(h.tree), /bcrypt.dll!BCryptDecrypt/); assert.match(text(h.tree), /7.654/); assert.match(text(h.tree), /采样或截断/);
  assert.ok(markup(h.tree).includes('&lt;script&gt;sample-marker&lt;/script&gt;')); assert.ok(!markup(h.tree).includes('<script>'));
  assert.ok(!text(h.tree).includes('[object Object]')); assert.ok(urls.every(url => new URL(url, 'http://test').searchParams.get('engine') === 'ghidra'));
  h.unmount();
});

test('scan target and engine changes hide old evidence before late responses arrive', async () => {
  const reads = [];
  request = url => { const q = new URL(url, 'http://test').searchParams; const d = deferred(); reads.push({ target: q.get('target'), engine: q.get('engine'), type: q.get('type'), d }); return d.promise; };
  const h = harness(ui.ScanView, { target: 'A.exe', engine: 'reverse' }); h.render();
  h.render({ target: 'B.exe', engine: 'ghidra' });
  for (const r of reads.filter(r => r.target === 'B.exe')) r.d.resolve(response(r.type === 'scan' ? scanFixture('CURRENT') : { ...fingerprintFixture, abi: 'CURRENT-ABI' }));
  await settle(); h.render(); assert.match(text(h.tree), /CURRENT/);
  for (const r of reads.filter(r => r.target === 'A.exe')) r.d.resolve(response(r.type === 'scan' ? scanFixture('STALE') : { ...fingerprintFixture, abi: 'STALE-ABI' }));
  await settle(); h.render(); assert.ok(!text(h.tree).includes('STALE'));
  h.render({ target: 'B.exe', engine: 'reverse' }); assert.ok(!text(h.tree).includes('CURRENT'));
  for (const r of reads.filter(r => r.target === 'B.exe' && r.engine === 'reverse')) r.d.resolve(response(r.type === 'scan' ? scanFixture('NEW-ENGINE') : fingerprintFixture));
  await settle(); h.render(); assert.match(text(h.tree), /NEW-ENGINE/); h.unmount();
});

test('analysis draft serializes explicit data/schema and refuses JSON source/action overrides', () => {
  const input = { encoding: 'hex', data: '000141' };
  const draft = ui.buildAnalysisDraft('protocol', 'decode', input, '{"schema":{"fields":[{"name":"len","type":"u16","offset":0}]},"framing":{"type":"length-prefix"}}', 'A.exe');
  const args = JSON.parse(draft.slice(draft.indexOf('{')));
  assert.deepEqual(args.input, input); assert.equal(args.action, 'decode'); assert.equal(args.target, 'A.exe'); assert.equal(args.schema.fields[0].name, 'len');
  for (const key of ['input', 'action', 'target', 'engine', '__proto__', 'constructor', 'prototype']) assert.throws(() => ui.buildAnalysisDraft('crypto', 'inspect', input, `{"${key}":"override"}`, 'A.exe'), /不能覆盖/);
  for (const params of ['[]', 'null', '"string"', 'invalid JSON']) assert.throws(() => ui.buildAnalysisDraft('crypto', 'inspect', input, params, 'A.exe'));
  assert.throws(() => ui.buildAnalysisDraft('protocol', 'transform', input, '{}'), /无效/); assert.throws(() => ui.buildAnalysisDraft('unknown', 'inspect', input, '{}'));
  assert.equal({}.override, undefined);
});

test('data analysis editor inserts an editable draft and never fetches/submits/executes', () => {
  request = () => assert.fail('draft editing must not call HTTP');
  const calls = [], span = { revision: 5, start: 8, end: 8 };
  const h = harness(ui.AnalysisDraft, { target: 'A.exe', inputActions: { captureInsertion: () => span, insertText: (...args) => { calls.push(['insert', ...args]); return true; }, persistDraft: () => calls.push(['persist']), submit: () => assert.fail('must not submit'), execute: () => assert.fail('must not execute') } });
  h.render(); edit(h, '数据分析领域', 'protocol'); edit(h, '数据分析操作', 'decode'); edit(h, '分析数据来源', 'hex'); edit(h, '分析输入文件或字节', '000141');
  edit(h, '分析附加参数 JSON', '{"framing":{"type":"length-prefix"}}'); button(h.tree, '生成分析草稿').props.onClick(); h.render();
  const draft = control(h.tree, '待发送数据分析草稿'); draft.props.onChange({ target: { value: draft.props.value + '\n请核查长度字段假设。' } }); h.render();
  button(h.tree, '插入会话草稿（待发送）').props.onClick(); h.render();
  assert.equal(calls[0][0], 'insert'); assert.equal(calls[0][2], span); assert.ok(calls[0][1].includes('请核查长度字段假设。')); assert.equal(calls[1][0], 'persist'); assert.match(text(h.tree), /尚未发送或执行/);
  h.unmount();
});

test('analysis source/target edits clear old drafts and stale composer insertion does not persist', () => {
  const h = harness(ui.AnalysisDraft, { target: 'A.exe', inputActions: { captureInsertion: () => ({}), insertText: () => false, persistDraft: () => assert.fail('must not persist refused insertion') } });
  h.render(); edit(h, '分析输入文件或字节', 'C:/captures/one.pcap'); button(h.tree, '生成分析草稿').props.onClick(); h.render();
  button(h.tree, '插入会话草稿（待发送）').props.onClick(); h.render(); assert.match(text(h.tree), /编辑器内容已变化/);
  edit(h, '分析输入文件或字节', 'C:/captures/two.pcap'); assert.equal(nodes(h.tree, n => n.props?.['aria-label'] === '待发送数据分析草稿').length, 0);
  button(h.tree, '生成分析草稿').props.onClick(); h.render(); assert.ok(control(h.tree, '待发送数据分析草稿').props.value.includes('two.pcap'));
  h.render({ ...h.props, target: 'B.exe' }); h.render();
  assert.equal(nodes(h.tree, n => n.props?.['aria-label'] === '待发送数据分析草稿').length, 0); h.unmount();
});

test('automatic recovery and inference editors create bounded templates without submitting or reading keys', () => {
  request = () => assert.fail('draft templates must not execute or fetch');
  const h = harness(ui.AnalysisDraft, { target: 'A.exe', engine: 'ghidra', inputActions: { submit: () => assert.fail('must not submit') } });
  h.render(); edit(h, '分析数据来源', 'hex'); edit(h, '分析输入文件或字节', '010203');
  edit(h, '数据分析操作', 'recover'); assert.match(text(h.tree), /完整候选可用 recipe.key_ref/);
  button(h.tree, '填入分析参数模板').props.onClick(); h.render();
  assert.equal(JSON.parse(control(h.tree, '分析附加参数 JSON').props.value).recovery.max_work_bytes, 16777216);
  button(h.tree, '生成分析草稿').props.onClick(); h.render();
  const recovered = control(h.tree, '待发送数据分析草稿').props.value;
  const cryptoArgs = JSON.parse(recovered.slice(recovered.indexOf('{'))); assert.equal(cryptoArgs.action, 'recover'); assert.equal(cryptoArgs.engine, 'ghidra');
  edit(h, '数据分析领域', 'protocol'); edit(h, '数据分析操作', 'infer'); assert.match(text(h.tree), /独立 holdout_samples/);
  button(h.tree, '填入分析参数模板').props.onClick(); h.render();
  assert.equal(JSON.parse(control(h.tree, '分析附加参数 JSON').props.value).inference.boundary, 'unknown');
  button(h.tree, '生成分析草稿').props.onClick(); h.render();
  const inferred = control(h.tree, '待发送数据分析草稿').props.value; assert.equal(JSON.parse(inferred.slice(inferred.indexOf('{'))).action, 'infer'); h.unmount();
});

test('same-target analysis engine changes hide drafts immediately and preserve the new engine', () => {
  const h = harness(ui.AnalysisDraft, { target: 'A.exe', engine: 'reverse' }); h.render(); edit(h, '分析输入文件或字节', 'C:/one.bin');
  button(h.tree, '生成分析草稿').props.onClick(); h.render(); assert.ok(control(h.tree, '待发送数据分析草稿').props.value.includes('reverse'));
  h.render({ target: 'A.exe', engine: 'ghidra' }); assert.equal(nodes(h.tree, n => n.props?.['aria-label'] === '待发送数据分析草稿').length, 0);
  h.render(); button(h.tree, '生成分析草稿').props.onClick(); h.render(); assert.ok(control(h.tree, '待发送数据分析草稿').props.value.includes('ghidra')); h.unmount();
});

test('explicit recovery and inferred decode drafts retain nested key references and delimiter framing', () => {
  const keyRef = { ref: 'sha256:' + 'b'.repeat(64), result_id: '11111111-2222-3333-4444-555555555555' };
  const draft = ui.buildAnalysisDraft('crypto', 'transform', { encoding: 'hex', data: 'ff' }, JSON.stringify({ recipe: { kind: 'xor', key_ref: keyRef } }), 'A.exe', 'ghidra');
  const args = JSON.parse(draft.slice(draft.indexOf('{'))); assert.deepEqual(args.recipe.key_ref, keyRef); assert.equal(args.recipe.key, undefined);
  const decoded = ui.buildAnalysisDraft('protocol', 'decode', { encoding: 'hex', data: '410a' }, JSON.stringify({ framing: { type: 'delimiter', delimiterHex: '0a', includeDelimiter: true }, schema: { fields: [] } }));
  assert.equal(JSON.parse(decoded.slice(decoded.indexOf('{'))).framing.type, 'delimiter');
});

const analysisItem = (id, target = '', engine = 'ghidra') => ({ id, kind: 'protocol', action: 'decode', createdAt: '2026-10-10T09:00:00Z', ...(target ? { association: { target, engine } } : {}) });

test('evidence reuse keeps producer, exact stream span and sensitive key refs without executing guesses', () => {
  const report = { id: '11111111-2222-3333-4444-555555555555', input: { ref: 'sha256:' + 'a'.repeat(64) }, association: { target: 'A.exe', engine: 'ghidra' }, value: { inference: { format: 'stream' } } };
  const protocol = { framing: { type: 'varint-prefix', maxBytes: 5 }, schema: { fields: [] }, decodeInput: { startOffset: 4, byteLength: 20 } };
  const decoded = ui.analysisReuseDraft(report, protocol, 'protocol'), args = JSON.parse(decoded.slice(decoded.indexOf('{')));
  assert.equal(args.offset, 4); assert.equal(args.length, 20); assert.equal(args.input.result_id, report.id); assert.equal(args.engine, 'ghidra');
  assert.throws(() => ui.analysisReuseDraft({ ...report, value: { inference: { format: 'capture' } } }, protocol, 'protocol'), /捕获容器/);
  assert.throws(() => ui.analysisReuseDraft(report, { ...protocol, decodeInput: { startOffset: -1, byteLength: 20 } }, 'protocol'), /范围/);
  const key = { kind: 'xor', keyComplete: true, keyMaterial: { dataRef: { ref: 'sha256:' + 'b'.repeat(64), sensitive: true } } };
  const decrypt = ui.analysisReuseDraft(report, key, 'crypto'), crypto = JSON.parse(decrypt.slice(decrypt.indexOf('{')));
  assert.equal(crypto.recipe.key_ref.result_id, report.id); assert.equal(crypto.recipe.key, undefined);
  assert.throws(() => ui.analysisReuseDraft(report, { ...key, keyComplete: false }, 'crypto'), /补齐/);
});

test('candidate table and byte preview produce editable reuse/archive drafts without submit or key reads', () => {
  request = () => assert.fail('evidence view must not fetch');
  const inserted = [], report = { id: '11111111-2222-3333-4444-555555555555', input: { ref: 'sha256:' + 'a'.repeat(64) }, value: { previewHex: '010203', inference: { format: 'stream', coverage: { status: 'partial', analyzedGroups: 1, eligibleGroups: 2, skippedGroups: 1 }, candidates: [{ framing: { type: 'tlv', typeSize: 1, lengthSize: 1 }, schema: { fields: [] }, score: 0.7, validation: { status: 'not-requested' }, decodeInput: { startOffset: 0, byteLength: 3 } }] } } };
  const h = harness(ui.AnalysisEvidence, { report, inputActions: { captureInsertion: () => ({}), insertText: value => { inserted.push(value); return true; }, persistDraft() {}, submit: () => assert.fail('must not submit') } }); h.render();
  assert.match(text(h.tree), /分析覆盖: partial/); assert.match(text(h.tree), /01 02 03/);
  button(h.tree, '生成复用草稿').props.onClick(); h.render(); assert.match(control(h.tree, '证据复用草稿').props.value, /tlv/);
  button(h.tree, '插入证据草稿（待发送）').props.onClick(); h.render(); assert.equal(inserted.length, 1); assert.match(text(h.tree), /尚未发送或执行/);
  button(h.tree, '生成归档报告草稿').props.onClick(); h.render(); assert.equal(JSON.parse(control(h.tree, '证据复用草稿').props.value.split('\n').slice(1).join('\n')).history.action, 'archive');
  h.render({ ...h.props, report: { ...report, id: 'another-report' } }); assert.equal(nodes(h.tree, node => node.props?.['aria-label'] === '证据复用草稿').length, 0); h.unmount();
});

test('partial audit pages advance opaque cursors, return to prior snapshot and reset on refresh', async () => {
  const queries = []; request = url => { const query = new URL(url, 'http://test').searchParams; queries.push(query); return Promise.resolve(response({ rows: [], total: null, totalLowerBound: 1, hasMore: true, partial: true, nextCursor: query.get('cursor') ? 'older-cursor' : 'first-cursor', issues: ['invalid-json-row'] })); };
  const h = harness(ui.PatchesView, { target: 'A.exe' }); h.render(); await settle(); h.render();
  assert.match(text(h.tree), /有界审计视图/); assert.match(text(h.tree), /至少/); assert.equal(button(h.tree, '下一页').props.disabled, false);
  button(h.tree, '下一页').props.onClick(); h.render(); await settle(); h.render(); assert.equal(queries.at(-1).get('cursor'), 'first-cursor');
  button(h.tree, '上一页').props.onClick(); h.render(); await settle(); h.render(); assert.equal(queries.at(-1).get('cursor'), null);
  button(h.tree, '下一页').props.onClick(); h.render(); await settle(); h.render(); button(h.tree, '刷新记录').props.onClick(); h.render(); await settle(); h.render(); assert.equal(queries.at(-1).get('cursor'), null); h.unmount();
});

test('partial analysis totals remain lower bounds and archived pages reset selection scope', async () => {
  const queries = []; request = url => { const query = new URL(url, 'http://test').searchParams; queries.push(query); return Promise.resolve(response({ items: [analysisItem('partial-result')], total: null, totalLowerBound: 12, partial: true, indexing: true, hasMore: true })); };
  const h = harness(ui.AnalysisView, {}); h.render(); await settle(); h.render(); assert.match(text(h.tree), /索引尚未完成/); assert.match(text(h.tree), /至少 12/); assert.equal(button(h.tree, '下一页分析结果').props.disabled, false);
  button(h.tree, '下一页分析结果').props.onClick(); h.render(); await settle(); h.render(); assert.equal(queries.at(-1).get('offset'), '20');
  button(h.tree, '活动报告').props.onClick(); h.render(); await settle(); h.render(); assert.equal(queries.at(-1).get('archived'), 'true'); assert.equal(queries.at(-1).get('offset'), '0'); h.unmount();
});

test('analysis ref editor keeps the explicit producer result ID inside input and clears changed drafts', () => {
  const inserted = [];
  request = () => assert.fail('draft editor must not fetch or execute');
  const h = harness(ui.AnalysisDraft, { target: 'fixture.exe', inputActions: { captureInsertion: () => ({}), insertText: value => { inserted.push(value); return true; }, persistDraft() {}, submit: () => assert.fail('must not submit') } });
  h.render();
  nodes(h.tree, n => n.type === 'select' && n.props['aria-label'] === '分析数据来源')[0].props.onChange({ target: { value: 'ref' } }); h.render();
  const ref = 'sha256:' + 'a'.repeat(64), resultId = '11111111-2222-3333-4444-555555555555';
  nodes(h.tree, n => n.type === 'input' && n.props['aria-label'] === '分析输入文件或字节')[0].props.onChange({ target: { value: ref } }); h.render();
  const producer = nodes(h.tree, n => n.type === 'input' && n.props['aria-label'] === '来源分析报告 ID')[0]; assert.ok(producer);
  producer.props.onChange({ target: { value: resultId } }); h.render();
  button(h.tree, '生成分析草稿').props.onClick(); h.render();
  const draft = nodes(h.tree, n => n.type === 'textarea' && n.props['aria-label'] === '待发送数据分析草稿')[0];
  const args = JSON.parse(draft.props.value.slice(draft.props.value.indexOf('{')));
  assert.deepEqual(plain(args.input), { ref, result_id: resultId }); assert.equal(args.result_id, undefined);
  button(h.tree, '插入会话草稿（待发送）').props.onClick(); assert.equal(inserted.length, 1);
  nodes(h.tree, n => n.type === 'input' && n.props['aria-label'] === '来源分析报告 ID')[0].props.onChange({ target: { value: '' } }); h.render();
  assert.equal(nodes(h.tree, n => n.type === 'textarea' && n.props['aria-label'] === '待发送数据分析草稿').length, 0);
  button(h.tree, '生成分析草稿').props.onClick(); h.render();
  const unbound = nodes(h.tree, n => n.type === 'textarea' && n.props['aria-label'] === '待发送数据分析草稿')[0];
  assert.equal(JSON.parse(unbound.props.value.slice(unbound.props.value.indexOf('{'))).input.result_id, undefined);
  h.unmount();
});

function analysisButton(tree, id) { const found = nodes(tree, n => n.type === 'button' && n.props.key === id)[0]; assert.ok(found, `analysis ${id}`); return found; }
test('analysis index/result use GET without target or engine for all data and escape evidence', async () => {
  const urls = [];
  request = (url, options) => { assert.equal(options, undefined); urls.push(url); const q = new URL(url, 'http://test').searchParams;
    return Promise.resolve(response(q.get('type') === 'analyses' ? { items: [analysisItem('all-1', 'G.exe', 'ghidra')], total: 1 } : { resultId: 'all-1', responseTruncated: true, note: '<img src=x onerror=alert(1)>' })); };
  const h = harness(ui.AnalysisView, { target: '', engine: 'reverse' }); h.render(); await settle(); h.render();
  analysisButton(h.tree, 'all-1').props.onClick(); h.render(); await settle(); h.render();
  assert.ok(urls.every(url => { const q = new URL(url, 'http://test').searchParams; return ['analyses', 'analysis_result'].includes(q.get('type')) && !q.get('target') && !q.has('engine'); }));
  assert.match(text(h.tree), /有界摘要/); assert.ok(markup(h.tree).includes('&lt;img')); assert.ok(!markup(h.tree).includes('<img')); h.unmount();
});

test('analysis target filter sends selected engine and clears late list/result from old scope', async () => {
  const reads = [];
  request = (url, options) => { assert.equal(options, undefined); const q = new URL(url, 'http://test').searchParams; const d = deferred(); reads.push({ q, d }); return d.promise; };
  const h = harness(ui.AnalysisView, { target: 'A.exe', engine: 'ghidra' }); h.render();
  reads[0].d.resolve(response({ items: [analysisItem('all-result')], total: 1 })); await settle(); h.render();
  analysisButton(h.tree, 'all-result').props.onClick(); h.render();
  button(h.tree, '全部数据结果').props.onClick(); h.render();
  assert.equal(reads.at(-1).q.get('target'), 'A.exe'); assert.equal(reads.at(-1).q.get('engine'), 'ghidra');
  h.render({ target: 'B.exe', engine: 'reverse' });
  const newList = reads.at(-1); assert.equal(newList.q.get('target'), 'B.exe'); assert.equal(newList.q.get('engine'), 'reverse');
  newList.d.resolve(response({ items: [analysisItem('current-B', 'B.exe', 'reverse')], total: 1 })); await settle(); h.render();
  for (const old of reads.slice(1, -1)) old.d.resolve(response(old.q.get('type') === 'analyses' ? { items: [analysisItem('STALE-A', 'A.exe')], total: 1 } : { note: 'STALE-ALL-RESULT' }));
  await settle(); h.render(); assert.ok(!text(h.tree).includes('STALE')); analysisButton(h.tree, 'current-B'); h.unmount();
});

test('analysis rapid selections reject late results and do not execute an analysis tool', async () => {
  const pending = new Map(), urls = [];
  request = (url, options) => { assert.equal(options, undefined); urls.push(url); const q = new URL(url, 'http://test').searchParams;
    if (q.get('type') === 'analyses') return Promise.resolve(response({ items: [analysisItem('one'), analysisItem('two')] }));
    assert.equal(q.get('type'), 'analysis_result'); const d = deferred(); pending.set(q.get('id'), d); return d.promise; };
  const h = harness(ui.AnalysisView, {}); h.render(); await settle(); h.render();
  analysisButton(h.tree, 'one').props.onClick(); h.render(); analysisButton(h.tree, 'two').props.onClick(); h.render();
  pending.get('two').resolve(response({ marker: 'CURRENT-TWO' })); await settle(); h.render();
  pending.get('one').resolve(response({ marker: 'STALE-ONE' })); await settle(); h.render();
  assert.match(text(h.tree), /CURRENT-TWO/); assert.ok(!text(h.tree).includes('STALE-ONE')); assert.ok(urls.every(url => url.startsWith('/ig5-data?'))); h.unmount();
});

test('analysis current-target filter without a loaded target reports guidance without a request', async () => {
  let reads = 0;
  request = () => { reads++; return Promise.resolve(response({ items: [] })); };
  const h = harness(ui.AnalysisView, { target: '' }); h.render(); await settle(); h.render();
  button(h.tree, '全部数据结果').props.onClick(); h.render(); h.render();
  assert.equal(reads, 1); assert.match(text(h.tree), /请载入目标或选择全部数据结果/); h.unmount();
});

test('analysis history paginates, rejects late page responses and resets offset when scope changes', async () => {
  const reads = [];
  request = (url, options) => { assert.equal(options, undefined); const q = new URL(url, 'http://test').searchParams; assert.equal(q.get('type'), 'analyses'); const d = deferred(); reads.push({ q, d }); return d.promise; };
  const offset = () => Number(reads.at(-1).q.get('offset') || 0);
  const h = harness(ui.AnalysisView, { target: 'A.exe', engine: 'ghidra' }); h.render();
  assert.equal(offset(), 0);
  reads[0].d.resolve(response({ items: [analysisItem('PAGE0')], total: 65, offset: 0 })); await settle(); h.render();
  const next = button(h.tree, '下一页分析结果'); assert.equal(Boolean(next.props.disabled), false); next.props.onClick(); h.render();
  assert.equal(offset(), 20); const latePage = reads.at(-1);
  button(h.tree, '刷新分析结果').props.onClick(); h.render(); assert.equal(offset(), 20);
  const freshPage = reads.at(-1); assert.notEqual(freshPage, latePage);
  freshPage.d.resolve(response({ items: [analysisItem('CURRENT-PAGE20')], total: 65, offset: 20 })); await settle(); h.render();
  latePage.d.resolve(response({ items: [analysisItem('STALE-PAGE20')], total: 65, offset: 20 })); await settle(); h.render();
  analysisButton(h.tree, 'CURRENT-PAGE20'); assert.ok(!text(h.tree).includes('STALE-PAGE20'));
  const previous = button(h.tree, '上一页分析结果'); assert.equal(Boolean(previous.props.disabled), false); previous.props.onClick(); h.render(); assert.equal(offset(), 0);
  reads.at(-1).d.resolve(response({ items: [analysisItem('PAGE0-RETURN')], total: 65, offset: 0 })); await settle(); h.render();
  button(h.tree, '下一页分析结果').props.onClick(); h.render(); const lateAllPage = reads.at(-1); assert.equal(offset(), 20);
  button(h.tree, '全部数据结果').props.onClick(); h.render();
  assert.equal(offset(), 0); assert.equal(reads.at(-1).q.get('target'), 'A.exe'); assert.equal(reads.at(-1).q.get('engine'), 'ghidra');
  reads.at(-1).d.resolve(response({ items: [analysisItem('A-PAGE0', 'A.exe', 'ghidra')], total: 45, offset: 0 })); await settle(); h.render();
  lateAllPage.d.resolve(response({ items: [analysisItem('STALE-ALL-PAGE20')], total: 65, offset: 20 })); await settle(); h.render();
  analysisButton(h.tree, 'A-PAGE0'); assert.ok(!text(h.tree).includes('STALE-ALL'));
  button(h.tree, '下一页分析结果').props.onClick(); h.render(); const lateTargetPage = reads.at(-1); assert.equal(offset(), 20);
  h.render({ target: 'B.exe', engine: 'reverse' });
  assert.equal(offset(), 0); assert.equal(reads.at(-1).q.get('target'), 'B.exe'); assert.equal(reads.at(-1).q.get('engine'), 'reverse');
  reads.at(-1).d.resolve(response({ items: [analysisItem('B-PAGE0', 'B.exe', 'reverse')], total: 1, offset: 0 })); await settle(); h.render();
  lateTargetPage.d.resolve(response({ items: [analysisItem('STALE-A-PAGE20', 'A.exe', 'ghidra')], total: 45, offset: 20 })); await settle(); h.render();
  analysisButton(h.tree, 'B-PAGE0'); assert.ok(!text(h.tree).includes('STALE-A'));
  assert.equal(button(h.tree, '上一页分析结果').props.disabled, true); assert.equal(button(h.tree, '下一页分析结果').props.disabled, true);
  h.unmount();
});
