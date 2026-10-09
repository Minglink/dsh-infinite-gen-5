"""ZIP a sealed portable directory and verify every archived file against its manifest."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import uuid
import zipfile


def native(path):
    value = os.path.abspath(str(path))
    if os.name == 'nt' and not value.startswith('\\\\?\\'):
        return '\\\\?\\UNC\\' + value[2:] if value.startswith('\\\\') else '\\\\?\\' + value
    return value


def digest(stream):
    result = hashlib.sha256()
    while chunk := stream.read(1024 * 1024):
        result.update(chunk)
    return result.hexdigest()


def publish_new(staging, destination):
    if os.name == 'nt':
        os.rename(native(staging), native(destination))  # Windows refuses existing destinations.
    else:
        os.link(native(staging), native(destination))
        os.unlink(native(staging))


def package(root, output):
    if os.path.lexists(native(output)) or os.path.lexists(native(output.with_name(output.name + '.sha256'))):
        raise ValueError('ZIP and checksum outputs must both be new files')
    root, output = root.resolve(), output.resolve()
    if output.exists() or root in output.parents:
        raise ValueError('Output must be a new ZIP outside the portable directory')
    with open(native(root / 'manifest.json'), 'rb') as stream:
        manifest_bytes = stream.read()
    manifest = json.loads(manifest_bytes.decode('utf-8-sig'))
    if manifest.get('schemaVersion') != 1 or manifest.get('platform') != 'win32-x64':
        raise ValueError('Expected sealed Windows portable manifest')
    expected = {}
    for row in manifest['files']:
        name = row['path']
        path = PurePosixPath(name)
        if not name or path.is_absolute() or '..' in path.parts or '\\' in name or ':' in name or str(path) != name or name in expected:
            raise ValueError('Invalid or duplicate archive path: ' + name)
        expected[name] = row
    if 'manifest.json' in expected:
        raise ValueError('Manifest cannot inventory itself')
    expected['manifest.json'] = {'bytes': len(manifest_bytes), 'sha256': hashlib.sha256(manifest_bytes).hexdigest()}
    actual = set()
    for directory, directories, files in os.walk(native(root)):
        for name in directories + files:
            if os.path.islink(os.path.join(directory, name)):
                raise ValueError('Portable archive cannot contain symlinks')
        for name in files:
            actual.add(os.path.relpath(os.path.join(directory, name), native(root)).replace('\\', '/'))
    if actual != expected.keys():
        raise ValueError('Portable tree differs from manifest: ' + repr(sorted(actual ^ expected.keys())[:10]))
    output.parent.mkdir(parents=True, exist_ok=True)
    staging = output.with_name(output.name + '.partial-' + uuid.uuid4().hex)
    checksum = output.with_name(output.name + '.sha256')
    checksum_staging = checksum.with_name(checksum.name + '.partial-' + uuid.uuid4().hex)
    zip_owned = checksum_owned = checksum_published = False
    checksum_identity = None
    try:
        with zipfile.ZipFile(native(staging), 'x', compression=zipfile.ZIP_DEFLATED, compresslevel=6, allowZip64=True) as archive:
            zip_owned = True
            for name, row in sorted(expected.items()):
                count, content_hash = 0, hashlib.sha256()
                with open(native(root / name), 'rb') as source, archive.open(name, 'w', force_zip64=True) as destination:
                    while chunk := source.read(1024 * 1024):
                        count += len(chunk)
                        content_hash.update(chunk)
                        destination.write(chunk)
                if count != row['bytes'] or content_hash.hexdigest() != row['sha256']:
                    raise ValueError('Portable source changed: ' + name)
        with zipfile.ZipFile(native(staging)) as archive:
            if len(archive.infolist()) != len(expected) or set(archive.namelist()) != expected.keys():
                raise ValueError('Archive inventory differs')
            for name, row in expected.items():
                if archive.getinfo(name).file_size != row['bytes']:
                    raise ValueError('Archive size mismatch: ' + name)
                with archive.open(name) as stream:
                    if digest(stream) != row['sha256']:
                        raise ValueError('Archive hash mismatch: ' + name)
        with open(native(staging), 'rb') as stream:
            zip_hash = digest(stream)
        with open(native(checksum_staging), 'x', encoding='utf-8') as stream:
            checksum_owned = True
            stream.write(zip_hash + '  ' + output.name + '\n')
        identity = os.stat(native(checksum_staging))
        checksum_identity = (identity.st_dev, identity.st_ino)
        # Two filenames cannot be published atomically. Publish checksum first;
        # if ZIP publication fails, roll back only our unchanged checksum file.
        publish_new(checksum_staging, checksum)
        checksum_published = True
        publish_new(staging, output)
    except Exception:
        if checksum_published and os.path.lexists(native(checksum)):
            identity = os.lstat(native(checksum))
            if (identity.st_dev, identity.st_ino) == checksum_identity:
                os.unlink(native(checksum))
        raise
    finally:
        for path, owned in ((staging, zip_owned), (checksum_staging, checksum_owned)):
            if owned and os.path.exists(native(path)):
                os.unlink(native(path))
    return {'ok': True, 'zip': str(output), 'sha256': zip_hash,
            'filesVerified': len(expected), 'zipBytes': os.stat(native(output)).st_size,
            'uncompressedBytes': sum(row['bytes'] for row in expected.values())}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('portable_root', type=Path)
    parser.add_argument('output_zip', type=Path)
    arguments = parser.parse_args()
    # Machine-readable JSON must survive Windows console code-page conversion.
    print(json.dumps(package(arguments.portable_root, arguments.output_zip)))
