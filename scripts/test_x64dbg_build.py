"""Validate the real patch series and real compiled products; no debuggee launch."""
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import struct
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
OVERLAY = ROOT / "third_party/x64dbg-build"
LOCK = json.loads((OVERLAY / "build-lock.json").read_text(encoding="utf-8"))
spec = importlib.util.spec_from_file_location("ig5_x64dbg_prepare", OVERLAY / "prepare_headless.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class BuildTests(unittest.TestCase):
    def copy_patch_inputs(self, folder):
        for row in LOCK["modifiedFiles"]:
            target = Path(folder) / row["path"]
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / "third_party/sources/x64dbg-runtime" / row["path"], target)

    def test_exact_patch_and_idempotent_reuse(self):
        with tempfile.TemporaryDirectory(prefix="ig5-headless-build-input-") as temp:
            self.copy_patch_inputs(temp)
            first = mod.prepare(temp, OVERLAY)
            second = mod.prepare(temp, OVERLAY)
            self.assertEqual(first, second)
            for row in LOCK["modifiedFiles"]:
                data = (Path(temp) / row["path"]).read_bytes()
                self.assertEqual(len(data), row["patchedBytes"])
                self.assertEqual(hashlib.sha256(data).hexdigest(), row["patchedSHA256"])

    def test_foreign_build_base_rejected(self):
        with tempfile.TemporaryDirectory(prefix="ig5-headless-build-foreign-") as temp:
            self.copy_patch_inputs(temp)
            target = Path(temp) / "CMakeLists.txt"
            target.write_bytes(target.read_bytes() + b"# foreign source\n")
            original_native = (Path(temp) / LOCK["modifiedFiles"][1]["path"]).read_bytes()
            with self.assertRaisesRegex(RuntimeError, "unexpected build source"):
                mod.prepare(temp, OVERLAY)
            self.assertEqual((Path(temp) / LOCK["modifiedFiles"][1]["path"]).read_bytes(), original_native)

    def test_actual_core_product_proof(self):
        runtime = ROOT / "runtimes/x64dbg"
        proof = json.loads((runtime / "source-build-proof.json").read_text(encoding="utf-8-sig"))
        self.assertEqual(proof["upstreamCommit"], LOCK["commit"])
        self.assertEqual({x["architecture"] for x in proof["architectures"]}, {"x86", "x64"})
        for patch in proof["patches"]:
            self.assertEqual(hashlib.sha256((OVERLAY / patch["path"]).read_bytes()).hexdigest(), patch["sha256"])
        for build in proof["architectures"]:
            self.assertTrue(build["compilerVersion"])
            arch = "x64" if build["architecture"] == "x64" else "x32"
            for row in build["products"]:
                data = (runtime / "snapshot/release" / arch / row["name"]).read_bytes()
                self.assertEqual(len(data), row["bytes"])
                self.assertEqual(hashlib.sha256(data).hexdigest(), row["sha256"])
                pe = struct.unpack_from("<I", data, 0x3c)[0]
                self.assertEqual(data[pe:pe+4], b"PE\0\0")
                self.assertEqual(struct.unpack_from("<H", data, pe+4)[0], 0x8664 if arch == "x64" else 0x14c)

    def test_actual_bridge_product_proof(self):
        proof = json.loads((ROOT / "adapters/x64dbg/native/build-proof.json").read_text(encoding="utf-8-sig"))
        self.assertEqual(proof["protocol"], 2)
        source = hashlib.sha256((ROOT / "adapters/x64dbg/ig5_bridge.cpp").read_bytes()).hexdigest()
        for build in proof["built"]:
            self.assertEqual(build["sourceSHA256"], source)
            portable = ROOT / "adapters/x64dbg/native" / build["product"]
            installed = ROOT / "runtimes/x64dbg/snapshot/release" / ("x64" if build["architecture"] == "x64" else "x32") / "plugins" / build["product"]
            for file in (portable, installed):
                self.assertEqual(hashlib.sha256(file.read_bytes()).hexdigest(), build["productSHA256"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
