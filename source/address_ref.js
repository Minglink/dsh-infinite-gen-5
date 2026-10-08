const MAX_ADDRESS = (1n << 64n) - 1n;
const SPACES = new Set(['static', 'runtime', 'file', 'stack', 'register', 'unique', 'external', 'overlay']);
const KINDS = new Set(['rva', 'va', 'file', 'offset']);

function fail(code, message) {
  const error = new Error(message);
  error.code = code;
  throw error;
}

export function normalizeHex(value, field = 'value') {
  if (typeof value !== 'bigint' && (typeof value !== 'string' || !/^0x[0-9a-f]+$/i.test(value))) {
    fail('INVALID_ADDRESS', `${field} must be a hexadecimal string or bigint; JavaScript numbers are not accepted`);
  }
  const number = BigInt(value);
  if (number < 0n || number > MAX_ADDRESS) fail('ADDRESS_OVERFLOW', `${field} is outside the unsigned 64-bit address range`);
  return `0x${number.toString(16)}`;
}

function integer(value, field) {
  if (!Number.isSafeInteger(value) || value < 0) fail('INVALID_CONTEXT', `${field} must be a non-negative safe integer`);
  return value;
}

function identifier(value, field) {
  if (typeof value !== 'string' || !value.trim()) fail('INVALID_CONTEXT', `${field} is required`);
  return value;
}

export function createAddressRef(input) {
  if (!input || typeof input !== 'object') fail('INVALID_ADDRESS', 'AddressRef must be an object');
  const space = input.space;
  const kind = input.kind;
  if (!SPACES.has(space) || !KINDS.has(kind)) fail('INVALID_ADDRESS', 'Unknown address space or kind');
  if (space === 'runtime' && kind !== 'va') fail('ADDRESS_SPACE_MISMATCH', 'Runtime addresses must use va');
  if (space === 'file' && kind !== 'file') fail('ADDRESS_SPACE_MISMATCH', 'File addresses must use file offsets');
  if (space === 'static' && kind === 'offset') fail('ADDRESS_SPACE_MISMATCH', 'Static addresses require rva, va, or file');
  if (!['static', 'runtime', 'file'].includes(space) && kind !== 'offset') fail('ADDRESS_SPACE_MISMATCH', `${space} addresses require an engine-specific offset`);
  const ref = { artifactId: identifier(input.artifactId, 'artifactId'), space, kind, value: normalizeHex(input.value) };
  for (const key of ['projectId', 'moduleId', 'engine']) if (input[key] !== undefined) ref[key] = identifier(input[key], key);
  if (input.dbRevision !== undefined) ref.dbRevision = integer(input.dbRevision, 'dbRevision');
  if (space === 'runtime') {
    ref.moduleId = identifier(input.moduleId, 'moduleId');
    ref.runId = identifier(input.runId, 'runId');
    ref.moduleLoadEpoch = integer(input.moduleLoadEpoch, 'moduleLoadEpoch');
    ref.stopSeq = integer(input.stopSeq, 'stopSeq');
  } else if (['runId', 'moduleLoadEpoch', 'stopSeq'].some(key => input[key] !== undefined)) {
    fail('ADDRESS_SPACE_MISMATCH', 'Static and non-runtime references cannot carry a runtime context');
  }
  return ref;
}

function number(value, field) { return BigInt(normalizeHex(value, field)); }

function checkedRange(base, size, label) {
  if (size <= 0n || base + size > MAX_ADDRESS + 1n) fail('INVALID_MAPPING', `${label} has an invalid range`);
  return { base, end: base + size };
}

function sectionsOf(mapping) {
  if (!Array.isArray(mapping.sections) || !mapping.sections.length) fail('MAPPING_REQUIRED', 'Explicit section mappings are required for file offsets');
  return mapping.sections.map((section, index) => {
    const rva = number(section.rva, `sections[${index}].rva`);
    const virtualSize = number(section.virtualSize, `sections[${index}].virtualSize`);
    const fileOffset = section.fileOffset === undefined ? null : number(section.fileOffset, `sections[${index}].fileOffset`);
    const fileSize = section.fileSize === undefined ? 0n : number(section.fileSize, `sections[${index}].fileSize`);
    checkedRange(rva, virtualSize, 'section virtual mapping');
    if (fileSize && fileOffset === null) fail('INVALID_MAPPING', 'A file-backed section requires fileOffset');
    if (fileSize) checkedRange(fileOffset, fileSize, 'section file mapping');
    return { rva, virtualSize, fileOffset, fileSize, loaded: section.loaded !== false };
  });
}

function fileToRva(value, mapping) {
  const sections = sectionsOf(mapping);
  const matches = sections.filter(s => s.loaded && s.fileOffset !== null && value >= s.fileOffset && value < s.fileOffset + s.fileSize);
  if (matches.length !== 1) fail(matches.length ? 'AMBIGUOUS_MAPPING' : 'UNMAPPED_ADDRESS', 'File offset does not identify exactly one loaded section');
  const section = matches[0];
  const delta = value - section.fileOffset;
  if (delta >= section.virtualSize) fail('UNMAPPED_ADDRESS', 'File padding is outside the explicitly mapped virtual range');
  const rva = section.rva + delta;
  const destinations = sections.filter(s => s.loaded && rva >= s.rva && rva < s.rva + s.virtualSize);
  if (destinations.length !== 1 || destinations[0] !== section) fail('AMBIGUOUS_MAPPING', 'File offset maps to an ambiguous virtual address');
  return rva;
}

function rvaToFile(value, mapping) {
  const sections = sectionsOf(mapping);
  const matches = sections.filter(s => s.loaded && value >= s.rva && value < s.rva + s.virtualSize);
  if (matches.length !== 1) fail(matches.length ? 'AMBIGUOUS_MAPPING' : 'UNMAPPED_ADDRESS', 'RVA does not identify exactly one loaded section');
  const section = matches[0];
  const delta = value - section.rva;
  if (section.fileOffset === null || delta >= section.fileSize) fail('NOT_FILE_BACKED', 'Address is in BSS or another region without file bytes');
  const offset = section.fileOffset + delta;
  const destinations = sections.filter(s => s.loaded && s.fileOffset !== null && offset >= s.fileOffset && offset < s.fileOffset + s.fileSize);
  if (destinations.length !== 1 || destinations[0] !== section) fail('AMBIGUOUS_MAPPING', 'RVA maps to an ambiguous file offset');
  return offset;
}

function loadedModule(mapping, ref) {
  const module = mapping.module;
  if (!module || module.loaded !== true) fail('MAPPING_REQUIRED', 'An explicitly loaded module mapping is required');
  identifier(module.moduleId, 'module.moduleId');
  identifier(module.runId, 'module.runId');
  integer(module.moduleLoadEpoch, 'module.moduleLoadEpoch');
  integer(module.stopSeq, 'module.stopSeq');
  if (module.artifactId !== ref.artifactId || (ref.moduleId && ref.moduleId !== module.moduleId)) fail('ADDRESS_IDENTITY_MISMATCH', 'Module mapping belongs to a different artifact or module');
  if (ref.space === 'runtime' && ['runId', 'moduleLoadEpoch', 'stopSeq'].some(key => ref[key] !== module[key])) fail('STALE_RUNTIME_CONTEXT', 'Runtime reference belongs to an old run, module load, or pause');
  const base = number(module.base, 'module.base');
  const size = number(module.size, 'module.size');
  checkedRange(base, size, 'loaded module');
  return { ...module, base, size };
}

/** Convert only through caller-supplied image/section/load mappings. No process or engine is consulted. */
export function convertAddress(input, destination, mapping = {}) {
  const ref = createAddressRef(input);
  const kind = typeof destination === 'string' ? destination : destination?.kind;
  const space = typeof destination === 'object' && destination.space ? destination.space : (kind === 'file' ? 'file' : 'static');
  if (!['static', 'runtime', 'file'].includes(ref.space) || !['static', 'runtime', 'file'].includes(space)) fail('UNSUPPORTED_ADDRESS_SPACE', 'Engine-specific spaces cannot be converted by an image or module formula');
  if (!['rva', 'va', 'file'].includes(kind) || (space === 'runtime' && kind !== 'va') || (space === 'file' && kind !== 'file')) fail('ADDRESS_SPACE_MISMATCH', 'Invalid conversion destination');
  if (ref.space === space && ref.kind === kind && space !== 'runtime') return { ...ref };
  let rva;
  const value = BigInt(ref.value);
  if (ref.space === 'runtime') {
    const module = loadedModule(mapping, ref);
    if (value < module.base || value >= module.base + module.size) fail('UNMAPPED_ADDRESS', 'Runtime address is outside the loaded module');
    rva = value - module.base;
  } else if (ref.kind === 'file') rva = fileToRva(value, mapping);
  else if (ref.kind === 'rva') rva = value;
  else {
    if (mapping.imageBase === undefined) fail('MAPPING_REQUIRED', 'An explicit imageBase is required for a static VA');
    const base = number(mapping.imageBase, 'imageBase');
    if (value < base) fail('UNMAPPED_ADDRESS', 'Static VA precedes imageBase');
    rva = value - base;
  }
  if (mapping.imageSize !== undefined && rva >= number(mapping.imageSize, 'imageSize')) fail('UNMAPPED_ADDRESS', 'RVA is outside the image');
  const identity = { artifactId: ref.artifactId, ...(ref.projectId ? { projectId: ref.projectId } : {}), ...(ref.moduleId ? { moduleId: ref.moduleId } : {}), ...(ref.engine ? { engine: ref.engine } : {}), ...(ref.dbRevision !== undefined ? { dbRevision: ref.dbRevision } : {}) };
  if (space === 'runtime') {
    const module = loadedModule(mapping, ref);
    if (rva >= module.size) fail('UNMAPPED_ADDRESS', 'RVA is outside the loaded module');
    return createAddressRef({ ...identity, space, kind, value: normalizeHex(module.base + rva), moduleId: module.moduleId, runId: module.runId, moduleLoadEpoch: module.moduleLoadEpoch, stopSeq: module.stopSeq });
  }
  let output = rva;
  if (kind === 'file') output = rvaToFile(rva, mapping);
  else if (kind === 'va') {
    if (mapping.imageBase === undefined) fail('MAPPING_REQUIRED', 'An explicit imageBase is required for a static VA');
    output = number(mapping.imageBase, 'imageBase') + rva;
  }
  return createAddressRef({ ...identity, space, kind, value: normalizeHex(output) });
}
