import fs from 'node:fs';
import path from 'node:path';
import { createHash, randomUUID } from 'node:crypto';
import { normalizeHex } from './address_ref.js';
import { captureAttachmentLease, probeAttachmentLease, processCreationIdentity, validAttachmentLease } from './attachment_lease.js';

const SCHEMA_VERSION = 1;
const clone = value => value === undefined ? undefined : structuredClone(value);
const canonicalPath = value => process.platform === 'win32' ? path.resolve(value).toLowerCase() : path.resolve(value);
let ownProcessIdentity;

const processIdentity = processCreationIdentity;

function physicalIdentity(filename) {
  try {
    const stat = fs.statSync(filename, { bigint: true });
    return stat.ino === 0n ? null : `${stat.dev.toString(16)}:${stat.ino.toString(16)}${stat.birthtimeNs > 0n ? `:${stat.birthtimeNs.toString(16)}` : ''}`;
  } catch (error) {
    if (['ENOENT', 'ENOTDIR'].includes(error.code)) return null;
    throw error;
  }
}

function realPathOrParent(filename) {
  let existing = filename;
  const suffix = [];
  while (!fs.existsSync(existing)) {
    const parent = path.dirname(existing);
    if (parent === existing) return filename;
    suffix.unshift(path.basename(existing)); existing = parent;
  }
  return path.join(fs.realpathSync.native(existing), ...suffix);
}

function fail(code, message) { const error = new Error(message); error.code = code; throw error; }
function required(value, name) {
  if (typeof value !== 'string' || !value.trim()) fail('INVALID_ARGUMENT', `${name} is required`);
  return value;
}
function revision(value, name = 'revision') {
  if (!Number.isSafeInteger(value) || value < 0) fail('INVALID_ARGUMENT', `${name} must be a non-negative safe integer`);
  return value;
}
function next(value, name) {
  if (value === Number.MAX_SAFE_INTEGER) fail('REVISION_OVERFLOW', `${name} cannot be incremented safely`);
  return value + 1;
}
function initial() { return { schemaVersion: SCHEMA_VERSION, revision: 0, projects: {}, artifacts: {}, targets: {}, databases: {}, attachments: {}, runtimes: {} }; }
function found(collection, id, name) { if (!Object.hasOwn(collection, id)) fail('NOT_FOUND', `${name} not found: ${id}`); return collection[id]; }

/** Hash a stable file descriptor, detecting replacement or edits during the read. */
function fingerprint(target) {
  const fd = fs.openSync(target, 'r');
  try {
    const before = fs.fstatSync(fd, { bigint: true });
    if (!before.isFile()) fail('INVALID_TARGET', 'Target must be a regular file');
    const hash = createHash('sha256');
    const buffer = Buffer.allocUnsafe(1024 * 1024);
    let count;
    while ((count = fs.readSync(fd, buffer, 0, buffer.length, null)) > 0) hash.update(buffer.subarray(0, count));
    const after = fs.fstatSync(fd, { bigint: true });
    const current = fs.statSync(target, { bigint: true });
    for (const key of ['dev', 'ino', 'size', 'mtimeNs', 'ctimeNs']) {
      if (before[key] !== after[key] || after[key] !== current[key]) fail('TARGET_CHANGED', 'Target changed while its identity was being calculated');
    }
    return { sha256: hash.digest('hex'), size: before.size.toString() };
  } finally { fs.closeSync(fd); }
}

/** Synchronous metadata store. OS owner probes never start a target/engine or open an engine DB. */
export class ProjectStore {
  constructor({ root } = {}) {
    this.root = path.resolve(required(root, 'root'));
    this.file = path.join(this.root, 'projects.json');
    this.lockFile = path.join(this.root, 'projects.lock');
    fs.mkdirSync(this.root, { recursive: true });
    if (ownProcessIdentity === undefined) ownProcessIdentity = processIdentity(process.pid);
    this._read();
  }

  _read() {
    if (!fs.existsSync(this.file)) return initial();
    let data;
    try { data = JSON.parse(fs.readFileSync(this.file, 'utf8')); }
    catch (error) { fail('STORE_CORRUPT', `Cannot read project metadata: ${error.message}`); }
    if (data.schemaVersion !== SCHEMA_VERSION || !Number.isSafeInteger(data.revision) || data.revision < 0 ||
      ['projects', 'artifacts', 'targets', 'databases', 'attachments', 'runtimes'].some(key => !data[key] || typeof data[key] !== 'object' || Array.isArray(data[key])) ||
      (data.investigations !== undefined && (!data.investigations || typeof data.investigations !== 'object' || Array.isArray(data.investigations)))) {
      fail('STORE_SCHEMA_MISMATCH', 'Unsupported or invalid project metadata schema');
    }
    return data;
  }

  _lockOwner() {
    try {
      const stat = fs.lstatSync(this.lockFile);
      if (!stat.isDirectory() || stat.isSymbolicLink()) return null;
      const owner = JSON.parse(fs.readFileSync(path.join(this.lockFile, 'owner.json'), 'utf8'));
      if (owner.schema !== 1 || !Number.isSafeInteger(owner.pid) || owner.pid <= 0 ||
        !/^[0-9a-f-]{36}$/.test(owner.nonce) || !(owner.creationIdentity === null || typeof owner.creationIdentity === 'string')) return null;
      return owner;
    } catch { return null; }
  }

  _recoverLock() {
    if (!fs.existsSync(this.lockFile)) return true;
    const owner = this._lockOwner();
    if (!owner) fail('STORE_BUSY', 'Unrecognized project lock; leave it intact. After verifying no IG5 process owns it, move projects.lock aside for manual recovery');
    let stale = false;
    try {
      process.kill(owner.pid, 0);
      const identity = owner.pid === process.pid ? ownProcessIdentity : processIdentity(owner.pid);
      stale = !!identity && !!owner.creationIdentity && identity !== owner.creationIdentity;
    } catch (error) { stale = error.code === 'ESRCH'; }
    if (!stale) return false;
    // A fixed, nonempty tombstone is retained. Two contenders cannot move a
    // newly acquired lock over it after both observed the same dead owner.
    const tombstone = path.join(this.root, `.projects-stale-lock-${owner.nonce}`);
    try { fs.renameSync(this.lockFile, tombstone); return true; }
    catch (error) {
      if (!fs.existsSync(this.lockFile)) return true;
      if (fs.existsSync(tombstone) || ['EPERM', 'EACCES', 'EEXIST', 'ENOTEMPTY', 'ENOENT'].includes(error.code)) return false;
      throw error;
    }
  }

  _acquireLock() {
    const owner = { schema: 1, pid: process.pid, creationIdentity: ownProcessIdentity, nonce: randomUUID() };
    const claim = path.join(this.root, `.projects-lock-${owner.nonce}.claim`);
    fs.mkdirSync(claim);
    try {
      const fd = fs.openSync(path.join(claim, 'owner.json'), 'wx');
      try { fs.writeFileSync(fd, JSON.stringify(owner), 'utf8'); fs.fsyncSync(fd); }
      finally { fs.closeSync(fd); }
      for (let attempt = 0; attempt < 3; attempt++) {
        if (fs.existsSync(this.lockFile) && !this._recoverLock()) break;
        try { fs.renameSync(claim, this.lockFile); return owner; }
        catch (error) {
          if (!['EPERM', 'EACCES', 'EEXIST', 'ENOTEMPTY', 'ENOENT'].includes(error.code)) throw error;
        }
      }
      fail('STORE_BUSY', 'Project metadata has a live or unverified owner; no update was applied');
    } finally {
      if (fs.existsSync(claim)) {
        if (fs.existsSync(path.join(claim, 'owner.json'))) fs.unlinkSync(path.join(claim, 'owner.json'));
        fs.rmdirSync(claim);
      }
    }
  }

  _releaseLock(owner) {
    if (this._lockOwner()?.nonce !== owner.nonce) fail('STORE_LOCK_CHANGED', 'Project lock ownership changed; the replacement lock was left intact');
    // Use the same fixed, nonempty tombstone for both recovery and release.
    // A delayed contender may have read this owner before normal release and
    // checked its PID after exit. Retaining the nonce prevents it from moving
    // a replacement lock. These small records require explicit offline cleanup.
    fs.renameSync(this.lockFile, path.join(this.root, `.projects-stale-lock-${owner.nonce}`));
  }

  _write(update) {
    const lock = this._acquireLock();
    let temporary;
    try {
      const data = this._read();
      const result = update(data);
      data.revision = next(data.revision, 'store revision');
      temporary = path.join(this.root, `.projects-${randomUUID()}.tmp`);
      const fd = fs.openSync(temporary, 'wx');
      try { fs.writeFileSync(fd, JSON.stringify(data, null, 2) + '\n', 'utf8'); fs.fsyncSync(fd); }
      finally { fs.closeSync(fd); }
      fs.renameSync(temporary, this.file);
      temporary = null;
      return clone(result);
    } finally {
      if (temporary && fs.existsSync(temporary)) fs.unlinkSync(temporary);
      this._releaseLock(lock);
    }
  }

  open(target, options = {}) {
    target = path.resolve(required(target, 'target'));
    const identity = fingerprint(target);
    const artifactId = `artifact_${identity.sha256}`;
    return this._write(data => {
      const now = new Date().toISOString();
      const parent = options.derivedFrom ? found(data.artifacts, options.derivedFrom, 'Parent artifact') : null;
      if (parent?.artifactId === artifactId) fail('INVALID_DERIVATION', 'A derived artifact must have different bytes from its parent');
      let project;
      if (options.projectId) project = found(data.projects, options.projectId, 'Project');
      else if (parent) project = Object.values(data.projects).find(item => item.artifactIds.includes(parent.artifactId));
      else project = Object.values(data.projects).find(item => item.artifactIds.includes(artifactId));
      if (!project) {
        const projectId = `project_${randomUUID()}`;
        project = data.projects[projectId] = { projectId, originalArtifactId: artifactId, originalHash: identity.sha256, artifactIds: [], createdAt: now, updatedAt: now };
      }
      if (parent && !project.artifactIds.includes(parent.artifactId)) fail('PROJECT_IDENTITY_MISMATCH', 'Parent artifact is not part of the selected project');
      const artifact = data.artifacts[artifactId] ??= { artifactId, ...identity, paths: [], derivedFrom: [], createdAt: now };
      if (!artifact.paths.includes(target)) artifact.paths.push(target);
      if (parent && !artifact.derivedFrom.includes(parent.artifactId)) artifact.derivedFrom.push(parent.artifactId);
      if (!project.artifactIds.includes(artifactId)) project.artifactIds.push(artifactId);
      project.updatedAt = now;
      data.targets[canonicalPath(target)] = { target, projectId: project.projectId, artifactId, sha256: identity.sha256 };
      return { projectId: project.projectId, artifactId, ...identity, target, project, artifact };
    });
  }

  register(target, options) { return this.open(target, options); }
  /** Separate InvestigationStore instances use these transactions in their own root. */
  readInvestigationRecords() { return clone(this._read().investigations ?? {}); }
  updateInvestigationRecords(update) {
    if (typeof update !== 'function') fail('INVALID_ARGUMENT', 'Investigation update requires a synchronous function');
    return this._write(data => {
      const records = data.investigations ??= {};
      const result = update(records);
      if (result && typeof result.then === 'function') fail('INVALID_ARGUMENT', 'Investigation transactions must be synchronous');
      return result;
    });
  }
  listProjects() { return clone(Object.values(this._read().projects)); }
  getProject(id) { return clone(found(this._read().projects, id, 'Project')); }
  getArtifact(id) { return clone(found(this._read().artifacts, id, 'Artifact')); }
  resolveTarget(target) { return clone(this._read().targets[canonicalPath(required(target, 'target'))] ?? null); }

  _databasePath(databasePath) {
    const absolute = path.resolve(databasePath);
    const location = (filename, base = fs.realpathSync.native(this.root)) => {
      const relative = path.relative(base, filename);
      return !relative.startsWith(`..${path.sep}`) && relative !== '..' && !path.isAbsolute(relative)
        ? { stored: relative, key: `root:${process.platform === 'win32' ? relative.toLowerCase() : relative}` }
        : { stored: filename, key: canonicalPath(filename) };
    };
    const logical = location(absolute, this.root), real = location(realPathOrParent(absolute));
    return { stored: logical.stored, key: real.key, logicalKey: logical.key, physicalIdentity: physicalIdentity(absolute) };
  }

  _attachment(data, attachmentId) {
    const attachment = found(data.attachments, attachmentId, 'Engine attachment');
    const database = found(data.databases, attachment.databaseId, 'Engine database');
    return { ...attachment, databasePath: path.resolve(this.root, database.databasePath), dbRevision: database.dbRevision };
  }

  attachEngine({ projectId, artifactId, engine, sessionId, databasePath, reuseAttachmentId, workerPid } = {}) {
    required(projectId, 'projectId'); required(artifactId, 'artifactId'); required(sessionId, 'sessionId');
    if (typeof engine !== 'string' || !/^[a-z][a-z0-9_-]{0,47}$/.test(engine)) fail('INVALID_ARGUMENT', 'engine must be a normalized identifier');
    const lease = workerPid === undefined ? undefined : captureAttachmentLease(workerPid, ownProcessIdentity);
    return this._write(data => {
      const project = found(data.projects, projectId, 'Project');
      if (!project.artifactIds.includes(artifactId)) fail('PROJECT_IDENTITY_MISMATCH', 'Artifact is not part of this project');
      const attachmentId = reuseAttachmentId ?? `attachment_${randomUUID()}`;
      const location = this._databasePath(databasePath ?? path.join(this.root, 'projects', projectId, 'engines', engine, attachmentId));
      let databaseId = `database_${createHash('sha256').update(location.key).digest('hex')}`;
      const keys = [location.key, location.logicalKey];
      const legacyIds = keys.map(key => `database_${createHash('sha256').update(key).digest('hex')}`);
      const matches = Object.values(data.databases).filter(item => legacyIds.includes(item.databaseId) ||
        keys.some(key => (item.pathKeys || []).includes(key)) ||
        (location.physicalIdentity && item.physicalIdentity === location.physicalIdentity &&
          (item.activeAttachmentId || location.physicalIdentity.split(':').length === 3)) ||
        (location.physicalIdentity && [item.databasePath, ...(item.aliases || [])]
          .some(filename => physicalIdentity(path.resolve(this.root, filename)) === location.physicalIdentity)));
      if (matches.length > 1) fail('DATABASE_ALIAS_CONFLICT', 'Multiple database records refer to this physical database; resolve their revisions before reopening');
      let database = matches[0];
      if (database) databaseId = database.databaseId;
      if (database && (database.artifactId !== artifactId || database.engine !== engine)) fail('DATABASE_IDENTITY_MISMATCH', 'Database path is already bound to another artifact or engine');
      if (reuseAttachmentId) {
        const attachment = found(data.attachments, reuseAttachmentId, 'Engine attachment');
        if (attachment.projectId !== projectId || attachment.artifactId !== artifactId || attachment.engine !== engine || attachment.sessionId !== sessionId || attachment.state !== 'active') fail('ATTACHMENT_IDENTITY_MISMATCH', 'Only the owning session can explicitly reuse its active attachment');
        if (databasePath !== undefined && attachment.databaseId !== databaseId) fail('DATABASE_IDENTITY_MISMATCH', 'Explicit reuse cannot change the database path');
        if (lease && (!validAttachmentLease(attachment.lease) || ['host', 'worker'].some(key => lease[key].pid !== attachment.lease[key].pid || !lease[key].creationIdentity || lease[key].creationIdentity !== attachment.lease[key].creationIdentity))) fail('ATTACHMENT_IDENTITY_MISMATCH', 'Explicit reuse cannot replace or guess an attachment process owner');
        return this._attachment(data, reuseAttachmentId);
      }
      if (database?.activeAttachmentId) fail('DATABASE_IN_USE', 'Database already has an active attachment; explicitly reuse that attachment or close it first');
      const now = new Date().toISOString();
      database ??= data.databases[databaseId] = { databaseId, artifactId, engine, databasePath: location.stored, dbRevision: 0, createdAt: now, activeAttachmentId: null };
      database.pathKeys = [...new Set([...(database.pathKeys || []), ...keys])];
      database.aliases = [...new Set([...(database.aliases || []), location.stored])];
      database.physicalIdentity = location.physicalIdentity;
      database.activeAttachmentId = attachmentId;
      data.attachments[attachmentId] = { attachmentId, projectId, artifactId, engine, sessionId, databaseId, state: 'active', createdAt: now, ...(lease ? { lease } : {}) };
      return this._attachment(data, attachmentId);
    });
  }

  getAttachment(id) { const data = this._read(); return clone(this._attachment(data, id)); }
  listAttachments({ projectId, artifactId, sessionId } = {}) {
    const data = this._read();
    return clone(Object.values(data.attachments).filter(item => (!projectId || item.projectId === projectId) && (!artifactId || item.artifactId === artifactId) && (!sessionId || item.sessionId === sessionId)).map(item => this._attachment(data, item.attachmentId)));
  }
  closeAttachment(id) {
    return this._write(data => {
      const attachment = found(data.attachments, id, 'Engine attachment');
      attachment.state = 'closed';
      attachment.closedAt = new Date().toISOString();
      const database = found(data.databases, attachment.databaseId, 'Engine database');
      if (database.activeAttachmentId === id) database.activeAttachmentId = null;
      return this._attachment(data, id);
    });
  }

  /** Startup recovery never infers a worker owner from a legacy sessionId string. */
  recoverAttachments({ limit = 64 } = {}) {
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 256) fail('INVALID_ARGUMENT', 'Attachment recovery limit must be 1..256');
    const active = Object.values(this._read().attachments).filter(item => item.state === 'active');
    const result = { recovered: [], retained: [], examined: Math.min(limit, active.length), truncated: active.length > limit };
    for (const attachment of active.slice(0, limit)) {
      const check = probeAttachmentLease(attachment.lease);
      if (!check.releasable) { result.retained.push({ attachmentId: attachment.attachmentId, reason: check.reason }); continue; }
      try {
        const recovered = this.recoverAttachment(attachment.attachmentId, attachment.lease.nonce);
        if (recovered.recovered || recovered.alreadyClosed) result.recovered.push(attachment.attachmentId);
        else result.retained.push({ attachmentId: attachment.attachmentId, reason: recovered.reason });
      } catch (error) {
        if (error.code !== 'ATTACHMENT_OWNER_CHANGED') throw error;
        result.retained.push({ attachmentId: attachment.attachmentId, reason: 'owner-changed' });
      }
    }
    return result;
  }

  /** Nonce and complete owner identity are rechecked under the metadata lock. */
  recoverAttachment(id, nonce) {
    const snapshot = found(this._read().attachments, id, 'Engine attachment');
    if (!validAttachmentLease(snapshot.lease) || snapshot.lease.nonce !== nonce) fail('ATTACHMENT_OWNER_CHANGED', 'Attachment recovery owner does not match; lease was retained');
    if (snapshot.state === 'closed') return { attachmentId: id, nonce, recovered: false, alreadyClosed: true };
    const check = probeAttachmentLease(snapshot.lease);
    if (!check.releasable) return { attachmentId: id, nonce, recovered: false, reason: check.reason };
    return this._write(data => {
      const attachment = found(data.attachments, id, 'Engine attachment');
      if (JSON.stringify(attachment.lease) !== JSON.stringify(snapshot.lease)) fail('ATTACHMENT_OWNER_CHANGED', 'Attachment owner changed during recovery; replacement lease was retained');
      if (attachment.state === 'closed') return { attachmentId: id, nonce, recovered: false, alreadyClosed: true };
      const finalCheck = probeAttachmentLease(attachment.lease);
      if (!finalCheck.releasable) return { attachmentId: id, nonce, recovered: false, reason: finalCheck.reason };
      attachment.state = 'closed'; attachment.closedAt = new Date().toISOString();
      attachment.recovery = { nonce, reason: 'both-owners-dead', at: attachment.closedAt };
      const database = found(data.databases, attachment.databaseId, 'Engine database');
      if (database.activeAttachmentId === id) database.activeAttachmentId = null;
      return { attachmentId: id, nonce, recovered: true, alreadyClosed: false };
    });
  }
  /** Call after a successful engine commit. expectedRevision protects stale plans; it is not an engine transaction. */
  bumpRevision(id, { expectedRevision, reason = 'mutation' } = {}) {
    return this._write(data => {
      const attachment = found(data.attachments, id, 'Engine attachment');
      const database = found(data.databases, attachment.databaseId, 'Engine database');
      if (attachment.state !== 'active' || database.activeAttachmentId !== id) fail('ATTACHMENT_CLOSED', 'Cannot update a closed or superseded attachment');
      if (expectedRevision !== undefined && revision(expectedRevision) !== database.dbRevision) fail('STALE_DATABASE_REVISION', 'Database changed after the operation plan was prepared');
      database.dbRevision = next(database.dbRevision, 'database revision');
      database.lastMutation = { reason: String(reason), at: new Date().toISOString(), dbRevision: database.dbRevision };
      return this._attachment(data, id);
    });
  }

  createRuntime({ projectId, artifactId, engine, sessionId, attachmentId } = {}) {
    required(projectId, 'projectId'); required(artifactId, 'artifactId'); required(engine, 'engine'); required(sessionId, 'sessionId');
    return this._write(data => {
      const project = found(data.projects, projectId, 'Project');
      if (!project.artifactIds.includes(artifactId)) fail('PROJECT_IDENTITY_MISMATCH', 'Artifact is not part of this project');
      if (attachmentId) {
        const attachment = found(data.attachments, attachmentId, 'Engine attachment');
        if (attachment.projectId !== projectId || attachment.artifactId !== artifactId || attachment.engine !== engine || attachment.sessionId !== sessionId || attachment.state !== 'active') fail('ATTACHMENT_IDENTITY_MISMATCH', 'Runtime attachment must belong to this project, artifact, engine, and session');
      }
      const runId = `run_${randomUUID()}`;
      return data.runtimes[runId] = { runId, projectId, artifactId, engine, sessionId, ...(attachmentId ? { attachmentId } : {}), state: 'created', epoch: 0, stopSeq: 0, modules: {}, createdAt: new Date().toISOString() };
    });
  }
  getRuntime(id) { return clone(found(this._read().runtimes, id, 'Runtime')); }
  recordRuntimeEvent(runId, event = {}) {
    return this._write(data => {
      const runtime = found(data.runtimes, runId, 'Runtime');
      if (runtime.state === 'stopped') fail('RUNTIME_STOPPED', 'A stopped runtime cannot accept new events');
      if (event.type === 'started') {
        if (runtime.state !== 'created') fail('INVALID_RUNTIME_TRANSITION', 'Only a created runtime can start');
        runtime.state = 'running';
      } else if (event.type === 'resumed') {
        if (runtime.state !== 'paused') fail('INVALID_RUNTIME_TRANSITION', 'Only a paused runtime can resume');
        runtime.state = 'running';
      } else if (event.type === 'paused') {
        if (runtime.state !== 'running') fail('INVALID_RUNTIME_TRANSITION', 'Only a running runtime can pause');
        runtime.state = 'paused'; runtime.stopSeq = next(runtime.stopSeq, 'stop sequence');
      } else if (event.type === 'module-loaded') {
        required(event.moduleId, 'moduleId'); required(event.artifactId, 'artifactId');
        found(data.artifacts, event.artifactId, 'Module artifact');
        const base = normalizeHex(event.base, 'base'), size = normalizeHex(event.size, 'size');
        if (BigInt(size) === 0n || BigInt(base) + BigInt(size) > (1n << 64n)) fail('INVALID_MAPPING', 'Invalid module range');
        runtime.epoch = next(runtime.epoch, 'module epoch');
        Object.defineProperty(runtime.modules, event.moduleId, { enumerable: true, configurable: true, writable: true, value: { moduleId: event.moduleId, artifactId: event.artifactId, base, size, loaded: true, runId, moduleLoadEpoch: runtime.epoch } });
      } else if (event.type === 'module-unloaded') {
        const module = found(runtime.modules, required(event.moduleId, 'moduleId'), 'Loaded module');
        if (!module.loaded) fail('INVALID_RUNTIME_TRANSITION', 'Module is already unloaded');
        runtime.epoch = next(runtime.epoch, 'module epoch'); module.loaded = false; module.moduleLoadEpoch = runtime.epoch;
      } else if (event.type === 'stopped') {
        runtime.state = 'stopped'; runtime.epoch = next(runtime.epoch, 'module epoch');
        for (const module of Object.values(runtime.modules)) { module.loaded = false; module.moduleLoadEpoch = runtime.epoch; }
      } else fail('INVALID_RUNTIME_EVENT', 'Unsupported runtime event');
      runtime.updatedAt = new Date().toISOString();
      return runtime;
    });
  }
  assertRuntimeContext({ runId, epoch, stopSeq, moduleId, moduleLoadEpoch } = {}) {
    const runtime = found(this._read().runtimes, required(runId, 'runId'), 'Runtime');
    if (runtime.state !== 'paused') fail('RUNTIME_NOT_PAUSED', 'Runtime context is only valid while paused');
    if ((epoch !== undefined && revision(epoch, 'epoch') !== runtime.epoch) || (stopSeq !== undefined && revision(stopSeq, 'stopSeq') !== runtime.stopSeq)) fail('STALE_RUNTIME_CONTEXT', 'Runtime load map or pause changed');
    if (moduleId !== undefined) {
      const module = found(runtime.modules, moduleId, 'Module');
      if (!module.loaded || (moduleLoadEpoch !== undefined && revision(moduleLoadEpoch, 'moduleLoadEpoch') !== module.moduleLoadEpoch)) fail('STALE_RUNTIME_CONTEXT', 'Module load changed');
      return clone({ ...module, stopSeq: runtime.stopSeq, state: runtime.state });
    }
    return clone(runtime);
  }
}
