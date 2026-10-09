"""Acquire the exact IG5 Ghidra baseline and verify every file against Git blobs.

This maintainer command does not replace the desktop source snapshot or fetch a
moving branch. It fails on a changed archive, truncated Git tree, links, extra
files, or a pre-existing destination with different contents.
"""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import urllib.request
import zipfile

COMMIT = '8b6bbb857accdfa20dc5b2f5dea471178c2e9fbc'
TAG = 'Ghidra_12.1.4_build'
ARCHIVE_SHA256 = '2022b89e44236c7f697d3a61b2b791ccc970e0c8423f57466df364c6745258e8'
REPOSITORY = 'https://github.com/NationalSecurityAgency/ghidra'


def validate_existing_source_entry(existing, expected):
    """Build outcomes may grow; verified source identity must remain exact."""
    for name, value in expected.items():
        if name != 'runtimeBuiltLocally' and existing.get(name) != value:
            raise ValueError('Existing fixed-source provenance differs: ' + name)


def download(url, path):
    if not path.exists():
        request = urllib.request.Request(url, headers={'User-Agent': 'IG5-source-builder/1.0'})
        with urllib.request.urlopen(request, timeout=300) as response, path.open('wb') as output:
            while data := response.read(1024 * 1024):
                output.write(data)


def acquire(source_root, cache_root):
    destination = source_root / 'ghidra-12.1.4'
    provenance = source_root / 'provenance'
    cache_root.mkdir(parents=True, exist_ok=True)
    provenance.mkdir(parents=True, exist_ok=True)
    archive = cache_root / 'source.zip'
    tree_path = cache_root / 'tree.json'
    archive_url = f'https://codeload.github.com/NationalSecurityAgency/ghidra/zip/{COMMIT}'
    tree_url = f'https://api.github.com/repos/NationalSecurityAgency/ghidra/git/trees/{COMMIT}?recursive=1'
    download(archive_url, archive)
    download(tree_url, tree_path)
    archive_hash = hashlib.file_digest(archive.open('rb'), 'sha256').hexdigest()
    if archive_hash != ARCHIVE_SHA256:
        raise ValueError('Pinned source archive SHA-256 mismatch')
    tree = json.loads(tree_path.read_text(encoding='utf-8'))
    if tree.get('truncated') or tree.get('sha') != COMMIT:
        raise ValueError('Git tree is truncated or does not identify the pinned commit')
    entries = {row['path']: row for row in tree['tree'] if row['type'] != 'tree'}
    if any(row['type'] != 'blob' or row['mode'] not in ('100644', '100755') for row in entries.values()):
        raise ValueError('Unresolved gitlink or symlink in pinned source; refuse incomplete extraction')
    files = []
    verified = set()
    normalized = []
    prefix = f'ghidra-{COMMIT}/'
    if destination.is_symlink() or destination.is_junction():
        raise ValueError('Source destination cannot be a link or junction')
    destination.mkdir(parents=True, exist_ok=True)
    if any(path.is_symlink() or path.is_junction() for path in destination.rglob('*')):
        raise ValueError('Existing source tree contains links or junctions')
    with zipfile.ZipFile(archive) as package:
        for member in package.infolist():
            if member.is_dir():
                continue
            if not member.filename.startswith(prefix):
                raise ValueError('Unexpected archive root')
            relative = member.filename[len(prefix):]
            components = PurePosixPath(relative)
            if components.is_absolute() or '..' in components.parts or '\\' in relative:
                raise ValueError('Unsafe archive member')
            expected = entries.get(relative)
            if expected is None or relative in verified:
                raise ValueError('Unexpected or duplicate archive file: ' + relative)
            data = package.read(member)
            git_sha = hashlib.sha1(b'blob ' + str(len(data)).encode('ascii') + b'\0' + data).hexdigest()
            if git_sha != expected['sha'] and components.suffix in ('.bat', '.sln', '.vcproj', '.vcxproj'):
                # GitHub git-archive honors upstream eol=crlf. Store canonical
                # Git bytes and verify those, never accept merely similar text.
                candidate = data.replace(b'\r\n', b'\n')
                candidate_sha = hashlib.sha1(b'blob ' + str(len(candidate)).encode('ascii') + b'\0' + candidate).hexdigest()
                if candidate_sha == expected['sha']:
                    data = candidate
                    git_sha = candidate_sha
                    normalized.append(relative)
            if git_sha != expected['sha']:
                raise ValueError('Git blob mismatch: ' + relative)
            sha256 = hashlib.sha256(data).hexdigest()
            target = destination.joinpath(*components.parts)
            if target.exists() and hashlib.file_digest(target.open('rb'), 'sha256').hexdigest() != sha256:
                raise ValueError('Existing source content differs: ' + relative)
            target.parent.mkdir(parents=True, exist_ok=True)
            if not target.exists():
                target.write_bytes(data)
            if expected['mode'] == '100755':
                target.chmod(target.stat().st_mode | 0o111)
            files.append({'path': relative, 'bytes': len(data), 'sha256': sha256})
            verified.add(relative)
    if verified != set(entries):
        raise ValueError('Archive omits Git files')
    actual = {path.relative_to(destination).as_posix() for path in destination.rglob('*') if path.is_file()}
    if actual != verified:
        raise ValueError('Existing source directory contains unexpected files')
    files.sort(key=lambda row: row['path'])
    tree_hash = hashlib.sha256(json.dumps(files, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()).hexdigest()
    inventory_name = 'ghidra-12.1.4.files.json'
    (provenance / inventory_name).write_text(json.dumps(files, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    (provenance / 'ghidra-12.1.4.git-tree.json').write_bytes(tree_path.read_bytes())
    entry = {
        'directory': 'ghidra-12.1.4', 'sourceKind': 'official-fixed-build-baseline',
        'version': '12.1.4', 'tag': TAG, 'commit': COMMIT, 'repository': REPOSITORY,
        'archiveURL': archive_url, 'archiveSHA256': archive_hash,
        'gitTreeProof': 'provenance/ghidra-12.1.4.git-tree.json',
        'gitBlobContentsVerified': True, 'verifiedGitBlobs': len(files), 'treeTruncated': False,
        'gitArchiveEolNormalized': normalized,
        'fileCount': len(files), 'bytes': sum(row['bytes'] for row in files), 'treeSHA256': tree_hash,
        'fileInventory': 'provenance/' + inventory_name,
        'licenses': ['LICENSE', 'NOTICE', 'licenses', 'GPL/licenses'],
        'runtimeBuiltLocally': False,
        'knownMissing': ['Build output and downloaded dependency caches live in the maintainer build workspace, not in this immutable source tree.'],
        'maintenanceOverlay': '../../adapters/ghidra/native-core',
    }
    manifest_path = source_root / 'manifest.json'
    manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
    old_entry = next((row for row in manifest['sources'] if row['directory'] == entry['directory']), None)
    if old_entry is not None:
        validate_existing_source_entry(old_entry, entry)
    if old_entry is None:
        manifest['sources'].append(entry)
        manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(old_entry if old_entry is not None else entry, ensure_ascii=False))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    plugin = Path(__file__).resolve().parent.parent
    parser.add_argument('--source-root', type=Path, default=plugin / 'third_party/sources')
    parser.add_argument('--cache-root', type=Path, required=True)
    args = parser.parse_args()
    acquire(args.source_root.resolve(), args.cache_root.resolve())
