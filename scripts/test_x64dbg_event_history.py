"""Live event-pressure regression; runs only generated PE32/PE64 spin fixtures.

Raw typed SDK requests intentionally withhold event draining, while the production
NativeClient and Adapter implement detection/recovery. No test event injection is
added to the shipped bridge.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('ig5_x64dbg_adapter', ROOT / 'adapters/x64dbg/adapter.py')
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


def fixture(bits):
    data = bytearray(0x400)
    def u16(offset, value): struct.pack_into('<H', data, offset, value)
    def u32(offset, value): struct.pack_into('<I', data, offset, value)
    def u64(offset, value): struct.pack_into('<Q', data, offset, value)
    data[:2] = b'MZ'; u32(0x3c, 0x80); data[0x80:0x84] = b'PE\0\0'
    coff, optional = 0x84, 0x98
    option_size = 0xf0 if bits == 64 else 0xe0
    u16(coff, 0x8664 if bits == 64 else 0x14c); u16(coff + 2, 1)
    u16(coff + 16, option_size); u16(coff + 18, 0x22 if bits == 64 else 0x102)
    u16(optional, 0x20b if bits == 64 else 0x10b)
    u32(optional + 4, 0x200); u32(optional + 16, 0x1000); u32(optional + 20, 0x1000)
    if bits == 64: u64(optional + 24, 0x140000000)
    else: u32(optional + 28, 0x400000)
    u32(optional + 32, 0x1000); u32(optional + 36, 0x200)
    u16(optional + 40, 6); u16(optional + 48, 6)
    u32(optional + 56, 0x2000); u32(optional + 60, 0x200); u16(optional + 68, 3)
    if bits == 64:
        for offset, value in ((72, 0x100000), (80, 0x1000), (88, 0x100000), (96, 0x1000)): u64(optional + offset, value)
        u32(optional + 108, 16)
    else:
        for offset, value in ((72, 0x100000), (76, 0x1000), (80, 0x100000), (84, 0x1000), (92, 16)): u32(optional + offset, value)
    section = optional + option_size
    data[section:section + 5] = b'.text'
    for offset, value in ((8, 0x200), (12, 0x1000), (16, 0x200), (20, 0x200), (36, 0x60000020)): u32(section + offset, value)
    data[0x200:0x202] = b'\xeb\xfe'
    return bytes(data)


def wait_snapshot(client, predicate, budget=3):
    deadline = time.monotonic() + budget
    while time.monotonic() < deadline:
        state = client.request('state')  # deliberately does not consume event history
        if predicate(state): return state
        time.sleep(0.003)
    raise AssertionError('authoritative native state did not reach the requested epoch')


def verify(bits, scratch):
    target = scratch / f'generated-spin-{bits}.exe'
    original = fixture(bits); target.write_bytes(original)
    adapter = mod.Adapter(ROOT / 'runtimes/x64dbg/runtime.json')
    adapter.state_root = scratch / f'state-{bits}'
    def dbg(op, **params): return adapter.dispatch('dbg', {'op': op, 'timeout': 15, **params})
    try:
        adapter.dispatch('open', {'path': str(target)})
        start = dbg('start'); assert start['ok'], start
        assert isinstance(adapter.client, mod.NativeClient)
        dbg('bpt', rva='0x1000')
        entry = dbg('cont'); assert entry['ok'] and entry['eventName'] == 'breakpoint', entry
        dbg('unbpt', rva='0x1000')
        client = adapter.client
        run_id = adapter.run_id
        adapter.deadline = time.monotonic() + 60
        before = client.request('state')
        current = before
        # Each step generates real resume/pause/step callbacks; >256 ring entries.
        for _ in range(140):
            previous = current['stopSeq']
            assert client.cmd_sync('sti')
            current = wait_snapshot(client, lambda s: not s['running'] and s['stopSeq'] > previous)
        first_read = client.request('events', after=0)
        assert first_read['truncated'] is True, first_read
        assert first_read['dropped']['from'] == 1
        assert first_read['dropped']['to'] == first_read['firstAvailableSeq'] - 1
        assert first_read['dropped']['count'] > 0
        assert len(first_read['events']) == 256
        assert client.cmd_sync('run')
        wait_snapshot(client, lambda s: s['running'])
        adapter.deadline = time.monotonic() + 10
        recovered = adapter.wait_state(adapter.event_seq)
        assert recovered['ok'] is False and recovered['eventName'] == 'history-gap', recovered
        assert recovered['event'] is None and recovered['state'] == 'suspended', recovered
        assert recovered['pauseAttempted'] is True and recovered['cleanedUp'] is False
        assert recovered['resynced'] is True and recovered['recoveryRequired'] is False
        assert recovered['historyGap']['dropped']['count'] > 0
        assert recovered['runId'] == run_id
        assert adapter.client is client and adapter.proc.poll() is None
        actual = client.request('state')
        assert actual['debugging'] and not actual['running']
        assert recovered['stopSeq'] == actual['stopSeq'] > current['stopSeq']
        print(json.dumps({'stage': 'native-gap-recovered', 'bits': bits, 'firstReadDropped': first_read['dropped'],
                          'recovery': recovered}, ensure_ascii=False), flush=True)
        refused = dbg('setreg', reg='eax' if bits == 32 else 'rax', value=1)
        assert refused['ok'] is False and refused['eventName'] == 'history-gap'
        refreshed = dbg('state')
        assert refreshed['ok'] and refreshed['cacheInvalidated'] and not adapter.pending_history_gap
        assert dbg('regs')['ok']
        # A fresh guarded register edit proves recovery did not destroy the live
        # transport or leave all writes blocked after the explicit state refresh.
        ax = 'eax' if bits == 32 else 'rax'
        assert dbg('setreg', reg=ax, value=1)['ok']
        assert dbg('regs')['regs'][ax] == '0x1'
        stepped = dbg('step')
        assert stepped['ok'] and stepped['eventName'] == 'step' and stepped['stopSeq'] > recovered['stopSeq'], stepped
        stopped = dbg('stop')
        assert stopped['ok'] and stopped['state'] == 'no-task', stopped
        assert target.read_bytes() == original
        # Reuse this JSONL adapter after replacing its debugger process. Native
        # sequence numbers restart at zero and must not inherit the old wait mark.
        adapter.dispatch('close', {})
        adapter.dispatch('open', {'path': str(target)})
        restarted = dbg('start')
        assert restarted['ok'] and restarted['runId'] != run_id and restarted['stopSeq'] > 0, restarted
        assert dbg('stop')['state'] == 'no-task'
        return {'bits': bits, 'fixture': str(target), 'fixtureSHA256': hashlib.sha256(original).hexdigest(),
                'nativeRunEpoch': actual['nativeRunEpoch'], 'firstReadDropped': first_read['dropped'],
                'firstAvailableSeq': first_read['firstAvailableSeq'], 'recovery': recovered,
                'freshRegisterWriteReadback': '0x1', 'restartAfterCleanup': True,
                'nextStepStopSeq': stepped['stopSeq'],
                'stopped': stopped['state'], 'result': 'passed'}
    finally:
        adapter.dispatch('close', {})


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    scratch = Path(tempfile.mkdtemp(prefix='ig5-event-history-'))
    result = {'scratch': str(scratch), 'runs': [verify(bits, scratch) for bits in (64, 32)]}
    encoded = json.dumps(result, ensure_ascii=False, indent=2)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded, encoding='utf-8')
    print(encoded)
