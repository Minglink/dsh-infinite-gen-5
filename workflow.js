import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SKILL_NAMES = Object.freeze([
  'ig5-triage', 'ig5-deep-dive', 'ig5-patch-and-sign', 'ig5-diff', 'ig5-debug-live',
  'ig5-crypto', 'ig5-protocol',
]);

/** The eight schemas advertised by the core toolset. Full uses all supplied definitions. */
export const CORE_TOOL_NAMES = Object.freeze([
  'ig5_doctor', 'ig5_open', 'ig5_status', 'ig5_funcs', 'ig5_strings',
  'ig5_decompile', 'ig5_close', 'ig5_profile',
]);

function loadSkills() {
  return SKILL_NAMES.map((name) => {
    const directory = path.join(HERE, 'skills', name);
    const file = path.join(directory, 'SKILL.md');
    const text = fs.readFileSync(file, 'utf8');
    const match = /^---\r?\n([\s\S]*?)\r?\n---\r?\n([\s\S]+)$/.exec(text);
    if (!match) throw new Error(`IG5 skill ${name} requires frontmatter and instructions`);
    const fields = {};
    for (const line of match[1].split(/\r?\n/)) {
      const field = /^(name|description):\s*(.+)$/.exec(line);
      if (field) fields[field[1]] = field[2].startsWith('"') ? JSON.parse(field[2]) : field[2];
    }
    if (fields.name !== name || !fields.description?.trim()) throw new Error(`Invalid IG5 skill metadata: ${name}`);
    return {
      name,
      description: fields.description,
      source: 'bundled',
      path: file,
      resourceBase: { kind: 'directory', path: directory },
      invocation: { modelInvocable: true, userInvocable: true },
      content: match[2].trim(),
    };
  });
}

function pathInput(input) {
  const value = input.trim();
  if (!value) return '';
  const quote = value[0];
  if (quote === '"' || quote === "'") {
    if (value.at(-1) !== quote || value.length < 3) throw new Error('样本路径引号不完整或路径为空');
    return value.slice(1, -1);
  }
  return value;
}

/**
 * Own the global core baseline and agent-owned advanced tools when scoped DSH
 * registries are available. Older hosts explicitly retain instance-wide mode.
 * @param {object} ctx Cordis context with the injected tools service.
 * @param {object} options Resolved cfg, worker mgr, all definitions, and optional formatError(error, cfg).
 * @returns {{getToolset: function, setToolset: function, snapshot: function, dispose: function}} Lifecycle controller; dispose may be awaited.
 */
export function installWorkflow(ctx, { cfg, mgr, definitions, formatError = (error) => String(error?.message ?? error) }) {
  const catalog = new Map(definitions.map((definition) => [definition.name, definition]));
  if (catalog.size !== definitions.length) throw new Error('Duplicate IG5 tool definition');
  for (const name of CORE_TOOL_NAMES) if (!catalog.has(name)) throw new Error(`Missing core IG5 tool: ${name}`);
  const activeTools = new Map();
  const activeSkills = new Set();
  const activeCommands = new Set();
  const fibers = [];
  const listeners = [];
  const scopedTools = new Map();
  const closedScopes = new WeakSet();
  const scoped = typeof ctx.tools.restrict === 'function' && typeof ctx.on === 'function';
  const defaultToolset = cfg.toolset ?? 'core';
  let toolset;
  let disposed = false;
  let disposing;

  function subjectOf(subject) {
    const agent = subject?.agent ?? (subject?.ctx ? subject : undefined);
    const agentCtx = agent?.ctx ?? subject?.agentCtx ?? (subject?.tools ? subject : undefined);
    return { agent, agentCtx };
  }

  function scopedState(subject) {
    if (disposed) throw new Error('IG5 workflow has been disposed');
    const { agent, agentCtx } = subjectOf(subject);
    if (!agentCtx) return null;
    if (agentCtx === ctx || closedScopes.has(agentCtx)) throw new Error('IG5 agent scope is unavailable or disposed');
    let state = scopedTools.get(agentCtx);
    if (state) return state;
    const service = agentCtx.tools;
    if (typeof service?.register !== 'function' || typeof service?.restrict !== 'function') throw new Error('DSH agent context does not support scoped tools');
    // An empty deny mask changes no capabilities but the real DSH implementation
    // rejects an unscoped service. Never trust a different-looking global proxy.
    const proof = service.restrict({ deny: [] });
    if (typeof proof !== 'function') throw new Error('DSH scoped tool registry must return a disposer');
    proof();
    state = { agent, agentCtx, service, mode: 'core', tools: new Map() };
    scopedTools.set(agentCtx, state);
    try { changeTools(state.tools, service, defaultToolset === 'full' ? [...catalog.keys()].filter(name => !CORE_TOOL_NAMES.includes(name)) : []); state.mode = defaultToolset; }
    catch (error) { scopedTools.delete(agentCtx); throw error; }
    return state;
  }

  function snapshot(subject) {
    const state = scoped && subject ? scopedState(subject) : null;
    return {
      toolset: state?.mode ?? toolset,
      toolsetScope: scoped ? 'agent' : 'plugin-instance',
      toolsetPersistent: false,
      ...(scoped ? { defaultToolset, agentScopeAvailable: !!state, ...(state?.agent?.id ? { agentId: state.agent.id } : {}) } : {}),
      activeTools: [...activeTools.keys(), ...(state ? state.tools.keys() : [])],
      availableTools: [...catalog.keys()],
      skills: [...activeSkills],
      commands: [...activeCommands],
    };
  }

  function register(service, definition) {
    const dispose = service.register(definition);
    if (typeof dispose !== 'function') throw new Error('DSH registry must return a registration disposer');
    return dispose;
  }

  function changeTools(owned, service, names) {
    const wanted = new Set(names);
    const additions = [];
    try {
      for (const name of wanted) {
        if (owned.has(name)) continue;
        const dispose = register(service, catalog.get(name));
        owned.set(name, dispose);
        additions.push(name);
      }
    } catch (error) {
      for (const name of additions.reverse()) { owned.get(name)(); owned.delete(name); }
      throw error;
    }
    for (const [name, dispose] of owned) {
      if (!wanted.has(name)) { dispose(); owned.delete(name); }
    }
  }

  function setToolset(mode, subject) {
    if (disposed) throw new Error('IG5 workflow has been disposed');
    if (mode !== 'core' && mode !== 'full') throw new Error('toolset 必须为 core 或 full');
    if (scoped) {
      const state = scopedState(subject);
      if (!state) throw Object.assign(new Error('Changing IG5 tools requires the current agent context'), { code: 'AGENT_SCOPE_REQUIRED' });
      changeTools(state.tools, state.service, mode === 'full' ? [...catalog.keys()].filter(name => !CORE_TOOL_NAMES.includes(name)) : []);
      state.mode = mode;
    } else {
      changeTools(activeTools, ctx.tools, mode === 'core' ? CORE_TOOL_NAMES : catalog.keys());
      toolset = mode;
    }
    return snapshot(subject);
  }

  function removeScope(agentCtx) {
    const state = scopedTools.get(agentCtx);
    if (state) {
      for (const remove of [...state.tools.values()].reverse()) remove();
      state.tools.clear(); scopedTools.delete(agentCtx);
    }
    if (agentCtx && typeof agentCtx === 'object') closedScopes.add(agentCtx);
  }

  function selectedTarget(input, engine) {
    const explicit = pathInput(input);
    if (explicit) return explicit;
    const sessions = [...mgr.sessions.values()].filter((session) => mgr.alive(session) && session.engine !== 'x64dbg' && (!engine || session.engine === engine));
    if (sessions.length !== 1) throw new Error(sessions.length ? '当前有多个目标，请在 export 后指定路径' : '当前没有打开的目标');
    return sessions[0].target;
  }

  async function readCommandTool(name, args, invocation) {
    // Only these read operations may bypass model execution; no write tool is
    // reachable from this command. Writes remain on the host approval pipeline.
    if (!['ig5_status', 'ig5_open', 'ig5_export_diff', 'ig5_profile'].includes(name)) throw new Error('Command only supports IG5 read operations');
    if (invocation.signal?.aborted) throw new Error('IG5 命令已取消');
    const definition = catalog.get(name);
    if (!definition) throw new Error(`IG5 tool is unavailable: ${name}`);
    return definition.execute(args, { agent: invocation.agent, signal: invocation.signal });
  }

  const command = {
    name: 'ig5',
    description: '统一逆向工作流：引擎自检信息、状态、打开样本、导出补丁副本、切换 Core8/Full 工具面。',
    input: { hint: 'status | engines | open [--engine reverse|ghidra] <path> | export [--engine reverse|ghidra] [path] | toolset [core|full]' },
    async handler(invocation) {
      try {
        if (disposed) throw new Error('IG5 workflow has been disposed');
        if (invocation.signal?.aborted) throw new Error('IG5 命令已取消');
        const match = /^\s*(\S+)?(?:\s+([\s\S]*))?$/.exec(invocation.rawInput || '');
        if (!match) throw new Error('用法：/ig5 status|open|export|toolset');
        const action = (match[1] || 'status').toLowerCase();
        let input = (match[2] || '').trim();
        let engine;
        const selection = /^--engine\s+(reverse|ghidra)(?:\s+|$)/.exec(input);
        if (selection) { engine = selection[1]; input = input.slice(selection[0].length).trim(); }
        let result;
        if (action === 'status' && !input) result = await readCommandTool('ig5_status', {}, invocation);
        else if (action === 'engines' && !input) result = await readCommandTool('ig5_profile', {}, invocation);
        else if (action === 'open') {
          const target = pathInput(input);
          if (!target) throw new Error('用法：/ig5 open <样本完整路径>');
          result = await readCommandTool('ig5_open', { path: target, ...(engine ? { engine } : {}) }, invocation);
        } else if (action === 'export') {
          result = await readCommandTool('ig5_export_diff', { target: selectedTarget(input, engine), ...(engine ? { engine } : {}) }, invocation);
        } else if (action === 'toolset') {
          result = input ? setToolset(input.toLowerCase(), invocation) : snapshot(invocation);
        } else throw new Error('用法：/ig5 status | open <path> | export [path] | toolset [core|full]');
        return { kind: 'success', text: JSON.stringify(result, null, 2) };
      } catch (error) {
        return { kind: 'error', text: formatError(error, cfg) };
      }
    },
  };

  async function dispose() {
    if (disposing) return disposing;
    disposed = true;
    for (const remove of listeners.splice(0).reverse()) remove();
    for (const agentCtx of [...scopedTools.keys()]) removeScope(agentCtx);
    for (const remove of [...activeTools.values()].reverse()) remove();
    activeTools.clear();
    disposing = Promise.all(fibers.map((fiber) => fiber.dispose())).then(() => {
      activeSkills.clear();
      activeCommands.clear();
    });
    return disposing;
  }

  try {
    if (defaultToolset !== 'core' && defaultToolset !== 'full') throw new Error('toolset 必须为 core 或 full');
    if (scoped) {
      changeTools(activeTools, ctx.tools, CORE_TOOL_NAMES); toolset = 'core';
      listeners.push(ctx.on('agent/created', ({ agent }) => { scopedState(agent); }));
      listeners.push(ctx.on('agent/disposed', ({ agent }) => { removeScope(agent?.ctx); }));
      fibers.push(ctx.inject(['agents'], (scope) => {
        if (disposed) return;
        const agents = scope.get('agents');
        const existing = typeof agents?.list === 'function' ? agents.list() : [];
        for (const agent of existing) scopedState(agent);
      }));
    } else setToolset(defaultToolset);
    const skills = loadSkills();
    fibers.push(ctx.inject(['skills'], (scope) => {
      if (disposed) return;
      const service = scope.get('skills');
      const removes = [];
      try {
        for (const skill of skills) {
          removes.push(register(service, skill));
          activeSkills.add(skill.name);
        }
      } catch (error) {
        for (const remove of removes.reverse()) remove();
        activeSkills.clear();
        throw error;
      }
      return () => { for (const remove of removes.reverse()) remove(); activeSkills.clear(); };
    }));
    fibers.push(ctx.inject(['commands'], (scope) => {
      if (disposed) return;
      const remove = register(scope.get('commands'), command);
      activeCommands.add(command.name);
      return () => { remove(); activeCommands.delete(command.name); };
    }));
    // Agent registries own their effects independently of the plugin fiber.
    // Explicitly lift those effects when this workflow owner unloads or reloads.
    ctx.effect(() => () => dispose());
  } catch (error) {
    void dispose();
    throw error;
  }
  return { getToolset: subject => snapshot(subject).toolset, setToolset, snapshot, dispose };
}
