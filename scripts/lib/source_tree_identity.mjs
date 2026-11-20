import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';

const SKIP_DIRS = new Set([
  'runtimes',
  'third_party',
  'node_modules',
  '.git',
  '.downloads',
  'scratch',
  '__pycache__',
  'labs',
]);

export function sha256File(filePath) {
  return createHash('sha256').update(fs.readFileSync(filePath)).digest('hex');
}

/**
 * Compute a deterministic SHA-256 inventory of the full IG5 plugin source, scripts,
 * fixtures, adapters, worker, docs, and CI gate files (excluding gitignored vendor trees).
 */
export function computeSourceTreeIdentity(repoRoot) {
  const root = path.resolve(repoRoot);
  const files = [];

  function walk(dir) {
    for (const entry of fs.readdirSync(dir).sort()) {
      if (SKIP_DIRS.has(entry)) continue;
      if (entry.endsWith('.pyc') || entry.endsWith('.pyo')) continue;
      const full = path.join(dir, entry);
      const st = fs.lstatSync(full);
      if (st.isSymbolicLink()) continue;
      if (st.isDirectory()) {
        walk(full);
      } else if (st.isFile()) {
        const rel = path.relative(root, full).split(path.sep).join('/');
        // Exclude large binary vendor blobs tracked separately in pinned manifests
        if (rel.startsWith('worker/trace_vendor/triton') && (rel.endsWith('.pyd') || rel.endsWith('.dll'))) continue;
        if (rel.endsWith('.dll') || rel.endsWith('.dp32') || rel.endsWith('.dp64') || rel.endsWith('.jar')) continue;
        files.push({ path: rel, bytes: st.size, sha256: sha256File(full) });
      }
    }
  }

  walk(root);
  const canonicalRows = files.map(f => `${f.sha256}  ${f.bytes}  ${f.path}`).join('\n');
  const treeDigest = createHash('sha256').update(canonicalRows, 'utf8').digest('hex');
  return {
    repoRoot: root,
    treeDigest,
    fileCount: files.length,
    files,
  };
}
