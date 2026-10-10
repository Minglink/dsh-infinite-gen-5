"""Real pause -> step regression on generated PE self loops, both architectures.

Uses real core/bridge callbacks and authoritative stop epochs. The optional
baseline mode requires the original step timeout; it never marks that as a fix.
"""
import argparse
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_x64dbg_event_history import fixture, mod, wait_snapshot


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def verify(bits, scenario, scratch, expect_broken=False):
    folder = scratch / f'{bits}-{scenario}'
    folder.mkdir()
    target = folder / 'generated-self-loop.exe'
    original = fixture(bits)
    target.write_bytes(original)
    adapter = mod.Adapter(ROOT / 'runtimes/x64dbg/runtime.json')
    adapter.state_root = folder / 'state'
    proof = {'bits': bits, 'scenario': scenario, 'fixture': str(target),
             'fixtureSHA256': hashlib.sha256(original).hexdigest(), 'expectBroken': expect_broken,
             'coreSHA256': sha256(ROOT / 'runtimes/x64dbg/snapshot/release' / ('x64' if bits == 64 else 'x32') / ('x64dbg.dll' if bits == 64 else 'x32dbg.dll'))}
    def dbg(op, **params):
        return adapter.dispatch('dbg', {'op': op, 'timeout': 15, **params})
    try:
        adapter.dispatch('open', {'path': str(target)})
        assert dbg('start')['ok']
        assert isinstance(adapter.client, mod.NativeClient)
        dbg('bpt', rva='0x1000')
        hit = dbg('cont')
        assert hit['ok'] and hit['eventName'] == 'breakpoint', hit
        dbg('unbpt', rva='0x1000')
        client, run_id, debugger_pid = adapter.client, adapter.run_id, adapter.proc.pid
        proof.update(runId=run_id, debuggerPid=debugger_pid, log=str(adapter.log.name))
        adapter.deadline = time.monotonic() + 60
        current = client.request('state')
        if scenario == 'history-gap':
            for _ in range(140):
                stop = current['stopSeq']
                assert client.cmd_sync('sti')
                current = wait_snapshot(client, lambda state: not state['running'] and state['stopSeq'] > stop)
            history = client.request('events', after=0)
            assert history['truncated'] and history['dropped']['count'] > 0, history
            proof['historyDropped'] = history['dropped']
        else:
            history = client.request('events', after=0)
            assert not history['truncated'] and history['eventSeq'] < 256, history
            proof['prePauseEventSeq'] = history['eventSeq']
        assert client.cmd_sync('run')
        running = wait_snapshot(client, lambda state: state['running'])
        assert running['debugging']
        if scenario == 'history-gap':
            adapter.deadline = time.monotonic() + 15
            paused = adapter.wait_state(adapter.event_seq)
            assert not paused['ok'] and paused['eventName'] == 'history-gap', paused
            assert paused['state'] == 'suspended' and paused['pauseAttempted'] and paused['resynced'], paused
            assert not paused['cleanedUp'] and not paused['recoveryRequired'], paused
            refused = dbg('step', timeout=1)
            assert not refused['ok'] and refused['eventName'] == 'history-gap', refused
            refreshed = dbg('state')
            assert refreshed['ok'] and refreshed['cacheInvalidated'], refreshed
            assert not adapter.pending_history_gap
            proof.update(recovery=paused, refusedStep=refused, refreshedState=refreshed)
        else:
            paused = dbg('suspend')
            assert paused['ok'] and paused['state'] == 'suspended', paused
            proof['paused'] = paused
        adapter.deadline = time.monotonic() + 3
        actual = client.request('state')
        assert actual['debugging'] and not actual['running']
        assert actual['stopSeq'] > current['stopSeq']
        proof['preStepNativeState'] = actual
        try:
            stepped = dbg('step', timeout=0.8 if expect_broken else 2)
        except mod.RpcError as error:
            if not expect_broken:
                raise
            assert error.code == 'ETIMEDOUT' and error.detail['cleanedUp'], error.detail
            assert adapter.client is None and adapter.proc is None
            proof.update(result='reproduced-original-timeout', stepError={'code': error.code, 'message': str(error), **error.detail},
                         trailingEvents=adapter.event_list(max(0, adapter.event_seq - 8)))
            return proof
        if expect_broken:
            raise AssertionError('expected original pause-step timeout was not reproduced')
        assert stepped['ok'] and stepped['eventName'] == 'step' and stepped['state'] == 'suspended', stepped
        assert stepped['runId'] == run_id and adapter.client is client and adapter.proc.pid == debugger_pid
        adapter.deadline = time.monotonic() + 3
        native = client.request('state')
        assert native['debugging'] and not native['running']
        assert native['stopSeq'] == stepped['stopSeq'] > actual['stopSeq']
        regs = dbg('regs')
        ip = regs['regs']['rip' if bits == 64 else 'eip']
        assert ip == hex(int(fixture_base(bits)) + 0x1000), regs
        over = dbg('stepover', timeout=2)
        assert over['ok'] and over['eventName'] == 'step' and over['stopSeq'] > stepped['stopSeq'], over
        # A second asynchronous pause proves subsequent callbacks do not retain
        # the prior software-breakpoint restoration state.
        adapter.deadline = time.monotonic() + 3
        assert client.cmd_sync('run')
        wait_snapshot(client, lambda state: state['running'])
        again = dbg('suspend')
        assert again['ok'] and again['state'] == 'suspended'
        repeated = dbg('step', timeout=2)
        assert repeated['ok'] and repeated['eventName'] == 'step' and repeated['stopSeq'] > again['stopSeq'], repeated
        stop = dbg('stop')
        assert stop['ok'] and stop['state'] == 'no-task', stop
        proof.update(result='passed', stepped=stepped, postStepNativeState=native, stepOver=over,
                     repeatedPause=again, repeatedStep=repeated, stopped=stop['state'])
        return proof
    finally:
        adapter.dispatch('close', {})
        assert target.read_bytes() == original


def fixture_base(bits):
    return 0x140000000 if bits == 64 else 0x400000


if __name__ == '__main__':
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8')
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path)
    parser.add_argument('--expect-broken', action='store_true')
    parser.add_argument('--bits', choices=('32', '64', 'both'), default='both')
    parser.add_argument('--scenario', choices=('normal', 'history-gap', 'both'), default='both')
    args = parser.parse_args()
    scratch = Path(tempfile.mkdtemp(prefix='ig5-pause-step-'))
    output = args.output or scratch / 'acceptance.json'
    result = {'scratch': str(scratch), 'scope': 'generated PE32/PE64 self loops; real native pause and step callbacks', 'runs': []}
    try:
        for bits in ((64, 32) if args.bits == 'both' else (int(args.bits),)):
            for scenario in (('normal', 'history-gap') if args.scenario == 'both' else (args.scenario,)):
                row = verify(bits, scenario, scratch, args.expect_broken)
                result['runs'].append(row)
                print(json.dumps({'bits': bits, 'scenario': scenario, 'result': row['result'], 'log': row['log']}, ensure_ascii=False), flush=True)
        result['ok'] = True
    except Exception as error:
        result.update(ok=False, error=repr(error))
        raise
    finally:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
        print('Evidence:', output, flush=True)
