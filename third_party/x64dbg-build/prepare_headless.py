"""Apply the maintained headless build overlay to a verified upstream copy.

The original vendored snapshot remains unchanged. The patch series removes GUI
build dependencies, fixes a bounded hardware callback replacement race, and
uses the native one-shot breakpoint path for asynchronous pause.
"""
from pathlib import Path
import argparse
import hashlib
import json
import os
import shutil
import subprocess
import tempfile


def prepare(source, patches):
    source, patches = Path(source), Path(patches)
    lock = json.loads((patches / "build-lock.json").read_text(encoding="utf-8"))
    pending = []
    # Validate every input before modifying a reusable private checkout.
    for item in lock["modifiedFiles"]:
        target = source / item["path"]
        digest = hashlib.sha256(target.read_bytes()).hexdigest()
        if digest == item["patchedSHA256"]:
            continue
        if digest != item["upstreamSHA256"]:
            raise RuntimeError("unexpected build source: " + item["path"])
        pending.append(item)
    if pending:
        # A private checkout can sit inside the plugin's Git worktree, whose
        # -text cache attributes otherwise change CRLF patch application. Use
        # an isolated staging tree and fixed Git conversion settings instead.
        env = dict(os.environ)
        for key in ('GIT_DIR', 'GIT_WORK_TREE', 'GIT_INDEX_FILE', 'GIT_CONFIG_COUNT'):
            env.pop(key, None)
        env.update(GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull, GIT_ATTR_NOSYSTEM='1')
        command = ['git', '-c', 'core.autocrlf=true', '-c', 'core.eol=crlf',
                   '-c', 'core.attributesfile=' + os.devnull, 'apply']
        with tempfile.TemporaryDirectory(prefix='ig5-build-overlay-') as folder:
            stage = Path(folder)
            for item in pending:
                target = stage / item['path']
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source / item['path'], target)
            for item in pending:
                patch = str(patches / item['patch'])
                subprocess.run(command + ['--check', '--whitespace=nowarn', patch], cwd=stage, env=env, check=True)
                subprocess.run(command + ['--whitespace=nowarn', patch], cwd=stage, env=env, check=True)
                if hashlib.sha256((stage / item['path']).read_bytes()).hexdigest() != item['patchedSHA256']:
                    raise RuntimeError('patch result mismatch: ' + item['path'])
            for item in pending:
                shutil.copyfile(stage / item['path'], source / item['path'])
    return {"commit": lock["commit"], "patches": [{"path": name, "sha256": hashlib.sha256((patches / name).read_bytes()).hexdigest()} for name in lock["patches"]]}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("source")
    parser.add_argument("patches")
    args = parser.parse_args()
    print(json.dumps(prepare(args.source, args.patches)))
