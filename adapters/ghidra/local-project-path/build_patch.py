"""Maintainer build: change only Ghidra's local filesystem path validation.

The pinned upstream tree stays untouched. The two ZIPs are rebuilt with one
replacement payload each, while every unrelated uncompressed entry is checked.
Run through scripts/patch_ghidra_project_paths.ps1; no network/build dependencies.
"""
import argparse
import datetime
import difflib
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import uuid
import zipfile

PATCH_ID = 'ig5-ghidra-local-project-path-v1'
UPSTREAM_COMMIT = '8b6bbb857accdfa20dc5b2f5dea471178c2e9fbc'
SOURCE_SHA256 = '5c24fa79fbb45911df24aff4538ed42137430d60f80f32bf253e521499cd0dcd'
JAVA_ENTRY = 'ghidra/framework/protocol/ghidra/GhidraURL.java'
CLASS_ENTRY = JAVA_ENTRY[:-5] + '.class'


def sha(data):
    return hashlib.sha256(data).hexdigest()


def file_sha(file):
    with file.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def patched_source(original):
    text = original.decode('utf-8').replace('\r\n', '\n')
    # Only these two call sites belong to OS project-directory validation.
    # The same original helper validates database/repository paths elsewhere.
    for old, new in [
        ('\t\t\tcheckValidProjectPath(path, 2);', '\t\t\tcheckValidLocalProjectPath(path, 2);'),
        ('\t\tcheckValidProjectPath(path, scanIndex);', '\t\tcheckValidLocalProjectPath(path, scanIndex);'),
    ]:
        if text.count(old) != 1:
            raise ValueError('Pinned GhidraURL call-site anchor changed')
        text = text.replace(old, new)
    anchor = '\tprivate static void checkValidProjectPath(String path, int startIndex) {'
    helper = '''\t/**
\t * IG5 change: local filesystem project directories may contain legitimate
\t * hidden directories, such as .dsh. Project names and domain/repository
\t * paths continue to use the original strict checkValidProjectPath helper.
\t */
\tprivate static void checkValidLocalProjectPath(String path, int startIndex) {
\t\tString str = path.substring(startIndex);
\t\tif (str.length() != 0) {
\t\t\tfor (String element : str.split("/")) {
\t\t\t\t// Also reject Win32 aliases of dot traversal (e.g., ".. ").
\t\t\t\tif (element.startsWith(".")) {
\t\t\t\t\tif (element.matches("[. ]+")) {
\t\t\t\t\t\tthrow new IllegalArgumentException("Dot path traversal is not permitted");
\t\t\t\t\t}
\t\t\t\t\t// Prefixing changes only the leading-dot rule; all characters
\t\t\t\t\t// still pass through the upstream whitelist validation.
\t\t\t\t\tNamingUtilities.checkName("ig5" + element, null);
\t\t\t\t}
\t\t\t\telse {
\t\t\t\t\tNamingUtilities.checkName(element, null);
\t\t\t\t}
\t\t\t}
\t\t}
\t}

'''
    if text.count(anchor) != 1:
        raise ValueError('Pinned GhidraURL helper anchor changed')
    text = text.replace(anchor, helper + anchor)
    text = text.replace(
        '\t * Path element naming restrictions are imposed based upon \n'
        '\t * {@link NamingUtilities#checkName(String, String)} restrictions.  These restrictions',
        '\t * Local path elements use the {@link NamingUtilities#checkName(String, String)}\n'
        '\t * character restrictions, permitting leading dots except dot traversal. These restrictions',
    )
    return text.encode('utf-8')


def replace_zip(input_file, output_file, entry, payload):
    with zipfile.ZipFile(input_file) as previous, zipfile.ZipFile(output_file, 'w') as updated:
        names = previous.namelist()
        if names.count(entry) != 1 or len(names) != len(set(names)):
            raise ValueError('Expected exactly one ZIP entry and no duplicate members')
        if any(name.upper().endswith(('.SF', '.RSA', '.DSA')) for name in names):
            raise ValueError('Signed runtime JAR requires a separate signing workflow')
        updated.comment = previous.comment
        for info in previous.infolist():
            updated.writestr(info, payload if info.filename == entry else previous.read(info))
    changed = []
    with zipfile.ZipFile(input_file) as previous, zipfile.ZipFile(output_file) as updated:
        if previous.namelist() != updated.namelist() or updated.testzip() is not None:
            raise ValueError('ZIP entry order or CRC changed unexpectedly')
        for name in previous.namelist():
            if sha(previous.read(name)) != sha(updated.read(name)):
                changed.append(name)
        if any(name != entry for name in changed):
            raise ValueError('Unrelated runtime payload was modified')
    return changed


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--project', required=True)
    parser.add_argument('--runtime-root')
    parser.add_argument('--artifact-root', required=True)
    args = parser.parse_args()
    project = Path(args.project).resolve()
    runtime = Path(args.runtime_root).resolve() if args.runtime_root else project / 'runtimes/ghidra'
    config_file = runtime / 'runtime.json'
    config = json.loads(config_file.read_text(encoding='utf-8-sig'))
    if str(config.get('version')) != '12.1.4':
        raise ValueError('This source patch supports only fixed Ghidra 12.1.4')
    ghidra_home = (runtime / config['ghidraHome']).resolve()
    java_home = (runtime / config['javaHome']).resolve()
    if not ghidra_home.is_relative_to(runtime) or not java_home.is_relative_to(runtime):
        raise ValueError('Runtime compiler and target must stay inside the selected maintainer runtime')
    jar = ghidra_home / 'Ghidra/Framework/Project/lib/Project.jar'
    source_zip = jar.with_name('Project-src.zip')
    upstream = project / 'third_party/sources/ghidra-12.1.4/Ghidra/Framework/Project/src/main/java' / JAVA_ENTRY
    original = upstream.read_bytes()
    if sha(original) != SOURCE_SHA256:
        raise ValueError('Fixed upstream GhidraURL source SHA-256 does not match')
    notice_root = runtime / 'licenses/ig5-local-project-path'
    prior = config.get('localProjectPathPatch', {})
    # setup regenerates runtime.json before applying patches. The separately
    # shipped proof recovers the same verified state without recompressing ZIPs.
    recovered_proof = False
    if not prior and (notice_root / 'build-proof.json').is_file():
        prior = json.loads((notice_root / 'build-proof.json').read_text(encoding='utf-8'))
        recovered_proof = True
    input_jar_hash, input_source_hash = file_sha(jar), file_sha(source_zip)
    patched = patched_source(original)
    with zipfile.ZipFile(jar) as archive:
        original_class = archive.read(CLASS_ENTRY)
    with zipfile.ZipFile(source_zip) as archive:
        input_source = archive.read(JAVA_ENTRY)
    if prior:
        if prior.get('patch') != PATCH_ID:
            raise ValueError('Unrecognized prior local project path patch proof')
        if (input_source != patched or input_jar_hash != prior.get('patchedJarSHA256') or
                input_source_hash != prior.get('patchedSourceZipSHA256') or
                sha(original_class) != prior.get('patchedClassSHA256')):
            raise ValueError('Already patched runtime no longer matches its build proof')
        if prior.get('sourceRoot') != 'licenses/ig5-local-project-path':
            raise ValueError('Patch proof source root does not match the fixed notice directory')
        notices = notice_root
        if ((notices / 'upstream-GhidraURL.java').read_bytes() != original or
                (notices / 'GhidraURL.java').read_bytes() != patched or
                sha((notices / 'local-project-path.patch').read_bytes()) != prior.get('patchSHA256')):
            raise ValueError('Already patched source/patch notices do not match their proof')
        shutil.copyfile(project / 'adapters/ghidra/local-project-path/NOTICE.txt', notices / 'NOTICE.txt')
        shutil.copyfile(project / 'adapters/ghidra/local-project-path/README.md', notices / 'README.md')
        authentication_note = ('Original runtime authenticity belongs to its authenticated release download, sealed '
                               'inventory or fixed-source full-build proof. This patch independently verifies '
                               'the fixed Java source entry and unchanged unrelated payloads, not the entire original JAR provenance.')
        if recovered_proof or not prior.get('originalRuntimeAuthentication'):
            prior['originalRuntimeAuthentication'] = authentication_note
            (notices / 'build-proof.json').write_text(json.dumps(prior, indent=2) + '\n', encoding='utf-8')
            config['localProjectPathPatch'] = prior
            config['licenses'] = list(dict.fromkeys([*config.get('licenses', []), prior['sourceRoot']]))
            config_file.write_text(json.dumps(config, indent=2) + '\n', encoding='utf-8')
        print(json.dumps({'ok': True, 'alreadyPatched': True, 'patch': PATCH_ID,
                          'jarSHA256': input_jar_hash, 'sourceZipSHA256': input_source_hash}))
        return
    # Source ZIP provenance allows the authenticated official distribution and
    # the locally built DEV distribution without pretending their JARs match.
    if input_source.replace(b'\r\n', b'\n') != original.replace(b'\r\n', b'\n'):
        raise ValueError('Project source ZIP GhidraURL does not match the fixed upstream source')

    build = Path(args.artifact_root).resolve() / ('ghidra-project-path-' + uuid.uuid4().hex)
    build.mkdir(parents=True)
    shutil.copyfile(jar, build / 'original-Project.jar')
    shutil.copyfile(source_zip, build / 'original-Project-src.zip')
    java_file = build / 'source' / JAVA_ENTRY
    java_file.parent.mkdir(parents=True)
    java_file.write_bytes(patched)
    patch = ''.join(difflib.unified_diff(
        original.decode('utf-8').replace('\r\n', '\n').splitlines(True),
        patched.decode('utf-8').splitlines(True),
        fromfile='a/' + JAVA_ENTRY, tofile='b/' + JAVA_ENTRY,
    )).encode('utf-8')
    patch_root = project / 'adapters/ghidra/local-project-path'
    (patch_root / 'local-project-path.patch').write_bytes(patch)
    classes = build / 'classes'
    classes.mkdir()
    classpath = os.pathsep.join(str(file).replace('\\', '/') for file in sorted(ghidra_home.rglob('*.jar')))
    javac = java_home / 'bin/javac.exe'
    javac_args = ['--release', '21', '-encoding', 'UTF-8', '-proc:none', '-classpath', classpath,
                  '-d', str(classes).replace('\\', '/'), str(java_file).replace('\\', '/')]
    argfile = build / 'javac.args'
    argfile.write_text('\n'.join('"' + value.replace('"', '\\"') + '"' for value in javac_args), encoding='utf-8')
    command = [str(javac), '@' + str(argfile)]
    completed = subprocess.run(command, capture_output=True, encoding='utf-8', errors='replace', timeout=120)
    (build / 'javac.log').write_text(completed.stdout + completed.stderr, encoding='utf-8')
    if completed.returncode:
        raise RuntimeError('GhidraURL javac failed; inspect artifact javac.log')
    class_files = list(classes.rglob('*.class'))
    if len(class_files) != 1 or class_files[0].relative_to(classes).as_posix() != CLASS_ENTRY:
        raise ValueError('Expected javac to compile only GhidraURL.class')
    compiled = class_files[0].read_bytes()
    changed_jar = replace_zip(jar, build / 'Project.jar', CLASS_ENTRY, compiled)
    changed_source = replace_zip(source_zip, build / 'Project-src.zip', JAVA_ENTRY, patched)
    proof = {
        'schemaVersion': 1, 'patch': PATCH_ID, 'version': '12.1.4', 'commit': UPSTREAM_COMMIT,
        'scope': 'Only local absolute filesystem directory elements permit legitimate leading dots. Dot/space-only traversal aliases are rejected. Project names, internal project paths and repository names/paths retain upstream validation.',
        'upstreamSourceSHA256': SOURCE_SHA256, 'originalJarSHA256': input_jar_hash,
        'originalSourceZipSHA256': input_source_hash, 'originalClassSHA256': sha(original_class),
        'originalSourceZipEntrySHA256': sha(input_source),
        'buildInputJarSHA256': input_jar_hash, 'buildInputSourceZipSHA256': input_source_hash,
        'patchedJarSHA256': file_sha(build / 'Project.jar'),
        'patchedSourceZipSHA256': file_sha(build / 'Project-src.zip'),
        'patchedSourceSHA256': sha(patched), 'patchedClassSHA256': sha(compiled), 'patchSHA256': sha(patch),
        'changedJarEntries': changed_jar, 'changedSourceZipEntries': changed_source,
        'compiler': subprocess.check_output([str(javac), '-version'], encoding='utf-8').strip(),
        'compilerSHA256': file_sha(javac),
        'compileArguments': ['--release', '21', '-encoding', 'UTF-8', '-proc:none', '-classpath', '<all bundled Ghidra JARs>', '-d', '<artifact>/classes', '<artifact>/source/' + JAVA_ENTRY],
        'artifactBackupDirectory': str(build),
        'sourceRoot': 'licenses/ig5-local-project-path',
        'jarPath': jar.relative_to(runtime).as_posix(),
        'sourceZipPath': source_zip.relative_to(runtime).as_posix(),
        'builtUtc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'upstreamTreeModified': False, 'unrelatedUncompressedEntriesVerifiedUnchanged': True,
        'originalRuntimeAuthentication': 'Original runtime authenticity belongs to its authenticated release download, sealed inventory or fixed-source full-build proof. This patch independently verifies the fixed Java source entry and unchanged unrelated payloads, not the entire original JAR provenance.',
    }
    notices = runtime / proof['sourceRoot']
    notices.mkdir(parents=True, exist_ok=True)
    (notices / 'upstream-GhidraURL.java').write_bytes(original)
    (notices / 'GhidraURL.java').write_bytes(patched)
    (notices / 'local-project-path.patch').write_bytes(patch)
    shutil.copyfile(ghidra_home / 'licenses/Apache_License_2.0.txt', notices / 'LICENSE')
    shutil.copyfile(patch_root / 'NOTICE.txt', notices / 'NOTICE.txt')
    shutil.copyfile(patch_root / 'README.md', notices / 'README.md')
    (notices / 'build-proof.json').write_text(json.dumps(proof, indent=2) + '\n', encoding='utf-8')
    (build / 'build-proof.json').write_text(json.dumps(proof, indent=2) + '\n', encoding='utf-8')
    # Publish only after compilation and complete ZIP payload verification.
    shutil.copyfile(build / 'Project.jar', jar)
    shutil.copyfile(build / 'Project-src.zip', source_zip)
    config['localProjectPathPatch'] = proof
    config['licenses'] = list(dict.fromkeys([*config.get('licenses', []), proof['sourceRoot']]))
    config_file.write_text(json.dumps(config, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'ok': True, 'patch': PATCH_ID, 'jarSHA256': proof['patchedJarSHA256'],
                      'sourceZipSHA256': proof['patchedSourceZipSHA256'], 'artifacts': str(build)}, ensure_ascii=False))


if __name__ == '__main__':
    main()
