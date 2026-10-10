"""One-request stateless IG5 kernel worker. Does not execute its target."""
import argparse
import json
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from kernel_image import BinaryImage
from kernel_analysis import SleighDecoder, analyze

# Keep native diagnostics off the protocol descriptor, even if C code writes
# directly to stdout. Only emit() writes to this saved UTF-8 JSONL channel.
PROTOCOL = os.fdopen(os.dup(sys.stdout.fileno()), 'w', encoding='utf-8', buffering=1)
os.dup2(sys.stderr.fileno(), sys.stdout.fileno())
sys.stdout = sys.stderr
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')


def emit(value):
    PROTOCOL.write(json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(',', ':')) + '\n')


class ImageProvider:
    def __init__(self, image):
        self.image = image
        self.pointer_size = image.bits // 8
        self.byteorder = image.byteorder
        self.imagebase = image.imagebase
        self.ranges = [{'start': r.start, 'end': r.start + r.size, 'executable': bool(r.permissions & 4)} for r in image.regions]
    def read(self, ea, size): return self.image.read(ea, size)
    def is_executable(self, ea): return any(r.start <= ea < r.start + r.size and r.permissions & 4 for r in self.image.regions)
    def symbol(self, ea): return ''


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--runtime-root', required=True)
    parser.add_argument('--ghidra-home', required=True)
    parser.add_argument('--java-home', required=True)
    options = parser.parse_args()
    emit({'ig5': 'ready', 'engine': 'IG5 Kernel', 'capabilities': ['kernel']})
    line = sys.stdin.buffer.readline(1024 * 1024 + 1)
    request = {}
    try:
        if len(line) > 1024 * 1024 or not line.endswith(b'\n'):
            raise ValueError('Kernel request is incomplete or exceeds its input budget')
        request = json.loads(line)
        if not isinstance(request, dict):
            request = {}
            raise ValueError('Kernel request must be a JSON object')
        if request.get('method') != 'kernel': raise ValueError('Unsupported kernel method')
        params = request.get('params', {})
        if not isinstance(params, dict): raise ValueError('Kernel params must be a JSON object')
        if not isinstance(params.get('target'), str) or not params['target']:
            raise ValueError('Kernel target must be a nonempty path string')
        image = BinaryImage.from_file(params['target'])
        action = params.get('action', 'analyze')
        if action == 'info':
            result = {'ok': True, 'engine': 'IG5 Kernel', 'image': image.describe(), 'jvmStarted': False, 'commercialEngineUsed': False}
        elif action == 'analyze':
            decoder = SleighDecoder(options.runtime_root, options.ghidra_home, options.java_home)
            result = analyze(image, decoder, params)
        elif action == 'vtables':
            from kernel_rtti import analyze_vtables
            result = analyze_vtables(ImageProvider(image), params)
            result.update(engine='IG5 Kernel', source={'artifactSHA256': image.sha256, 'jvmStarted': False, 'commercialEngineUsed': False})
        elif action == 'decompile':
            from kernel_decompile import decompile
            result = decompile(image, params, options.ghidra_home)
        else: raise ValueError('Kernel action must be info, analyze, vtables or decompile')
        emit({'id': request.get('id'), 'result': result})
    except Exception as error:
        emit({'id': request.get('id'), 'error': {'code': 'KERNEL_FAILED', 'message': str(error)[:4000]}})


if __name__ == '__main__': main()
