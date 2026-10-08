// Deterministic, bounded function matching. Scores are evidence, not proof of equivalence.
const synthetic = /^(?:sub_|loc_|nullsub_|j_|FUN_)[0-9a-f_]+$/i;
const overlap = (left = [], right = []) => {
  const a = new Set(left), b = new Set(right);
  if (!a.size && !b.size) return 1;
  let shared = 0;
  for (const item of a) if (b.has(item)) shared++;
  return shared / (a.size + b.size - shared || 1);
};
const histogram = (a = {}, b = {}) => {
  let shared = 0, total = 0;
  for (const key of new Set([...Object.keys(a), ...Object.keys(b)])) {
    shared += Math.min(a[key] || 0, b[key] || 0);
    total += Math.max(a[key] || 0, b[key] || 0);
  }
  return total ? shared / total : 1;
};
const ratio = (a, b) => Math.min(a || 1, b || 1) / Math.max(a || 1, b || 1);

export function functionSimilarity(left, right) {
  if (left.semantic_hash && left.semantic_hash === right.semantic_hash) return 1;
  const named = !synthetic.test(left.name) && left.name === right.name;
  return Math.min(0.999, 0.26 * histogram(left.mnemonics, right.mnemonics)
    + 0.22 * overlap(left.topology, right.topology)
    + 0.17 * overlap(left.constants, right.constants)
    + 0.08 * overlap(left.strings, right.strings)
    + 0.08 * ratio(left.call_degree + 1, right.call_degree + 1)
    + 0.09 * ratio(left.instructions, right.instructions) + (named ? 0.1 : 0));
}

function changedBlocks(left, right) {
  const unmatched = [...(right.blocks || [])];
  const removed = [];
  for (const block of left.blocks || []) {
    const index = unmatched.findIndex((candidate) => candidate.hash === block.hash);
    if (index >= 0) unmatched.splice(index, 1);
    else removed.push(block);
  }
  return { old: removed.map(({ start, end, insns }) => ({ start, end, insns })),
    new: unmatched.map(({ start, end, insns }) => ({ start, end, insns })) };
}

export function compareSemantics(left, right, options = {}) {
  const threshold = Number(options.threshold ?? 0.62);
  if (!Number.isFinite(threshold) || threshold < 0 || threshold > 1) throw new Error('threshold must be between 0 and 1');
  const limit = Math.max(1, Math.min(Number(options.limit) || 100, 1000));
  const a = left.functions || [], b = right.functions || [];
  if (a.length > 2000 || b.length > 2000) throw new Error('semantic snapshot exceeds 2000 functions');
  const edges = [];
  for (let i = 0; i < a.length; i++) {
    const candidates = [];
    for (let j = 0; j < b.length; j++) {
      if (ratio(a[i].instructions, b[j].instructions) < 0.2 && a[i].name !== b[j].name) continue;
      const score = functionSimilarity(a[i], b[j]);
      if (score >= threshold) candidates.push({ i, j, score });
    }
    candidates.sort((x, y) => y.score - x.score || x.j - y.j);
    for (const edge of candidates.slice(0, 3)) {
      edge.margin = edge.score - (candidates.find((item) => item.j !== edge.j)?.score ?? 0);
      edges.push(edge);
    }
  }
  edges.sort((x, y) => y.score - x.score || y.margin - x.margin || x.i - y.i || x.j - y.j);
  const usedA = new Set(), usedB = new Set(), matches = [];
  for (const edge of edges) {
    if (usedA.has(edge.i) || usedB.has(edge.j)) continue;
    usedA.add(edge.i); usedB.add(edge.j);
    const old = a[edge.i], next = b[edge.j];
    const changed = old.semantic_hash !== next.semantic_hash;
    matches.push({ old: { ea: old.ea, name: old.name }, new: { ea: next.ea, name: next.name },
      score: Number(edge.score.toFixed(4)), ambiguous: edge.margin < 0.05,
      changed, bytesChanged: old.bytes_hash !== next.bytes_hash,
      evidence: { cfg: Number(overlap(old.topology, next.topology).toFixed(4)),
        mnemonics: Number(histogram(old.mnemonics, next.mnemonics).toFixed(4)),
        constantsAdded: (next.constants || []).filter((item) => !(old.constants || []).includes(item)),
        constantsRemoved: (old.constants || []).filter((item) => !(next.constants || []).includes(item)) },
      ...(changed ? { changedBlocks: changedBlocks(old, next) } : {}) });
  }
  const changes = matches.filter((item) => item.changed).sort((x, y) => Number(x.ambiguous) - Number(y.ambiguous) || y.score - x.score);
  return { algorithm: 'normalized instructions, CFG neighborhood labels, constants and call degree',
    summary: { leftCompared: a.length, rightCompared: b.length, matched: matches.length,
      changed: changes.length, unchanged: matches.length - changes.length,
      unmatchedLeft: a.length - usedA.size, unmatchedRight: b.length - usedB.size,
      incomplete: !!left.truncated || !!right.truncated },
    changes: changes.slice(0, limit), matches: matches.slice(0, limit),
    unmatchedLeft: a.filter((_, index) => !usedA.has(index)).slice(0, limit).map(({ ea, name }) => ({ ea, name })),
    unmatchedRight: b.filter((_, index) => !usedB.has(index)).slice(0, limit).map(({ ea, name }) => ({ ea, name })),
    note: 'Heuristic matches and changed blocks are patch-analysis candidates; they do not establish a vulnerability or semantic equivalence.' };
}
