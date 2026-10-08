# -*- coding: utf-8 -*-
"""IG5 idalib worker (无限五代) — JSON-RPC over stdio, 1 database = 1 process.

Protocol: one JSON object per line on stdin -> one JSON object per line on stdout.
  request : {"id": <n>, "method": "<name>", "params": {...}}
  response: {"id": <n>, "result": {...}}  |  {"id": <n>, "error": "<traceback>"}
  ready   : {"ig5": "ready"}  (after idapro loads; IDA plugin banner noise may
            interleave on stdout and is ignored by the manager)
  progress: {"ig5": "progress", "id": <n>, "payload": {...}}  — pushed while the
            named request runs; the manager routes it to that request's listener.

Analysis is chunked per segment (`ida_auto.plan_and_wait`) so a long auto-analysis
reports real progress instead of blocking silently.

Bootstrap is zero-touch on the IDA install: IDADIR env var (idapro/config.py
honors it over ida-config.json) + sys.path insert of <IDA>/idalib/python.
`import idapro` stays the first import, as required by idalib.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import time
import traceback

_ida_dir = None
_idapro = None
_hexrays_ready = False
_open = False
_target = None
_progress_rid = None
_t0 = 0.0
_op_journal = []  # 写操作回滚日志：[{kind, ...inverse data}]（idalib 无自动 undo 录音，自管）
_worker_module_dir = os.path.dirname(os.path.abspath(__file__))


def bootstrap(ida_dir: str) -> None:
    global _ida_dir, _idapro
    # Windows Python decodes stdio with the ANSI code page; the manager speaks
    # UTF-8, so a non-ASCII target path would arrive as mojibake without this.
    for stream in (sys.stdin, sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    _ida_dir = os.path.abspath(ida_dir)
    if not os.path.isdir(_ida_dir):
        raise RuntimeError(f"IDA dir not found: {_ida_dir}")
    os.environ["IDADIR"] = _ida_dir
    os.environ.pop("IDA_IS_INTERACTIVE", None)
    sys.path.insert(0, os.path.join(_ida_dir, "idalib", "python"))
    import idapro  # must be the first import after sys.path setup

    _idapro = idapro


def out(obj: dict) -> None:
    sys.stdout.write(json.dumps(obj, ensure_ascii=False) + "\n")
    sys.stdout.flush()


def emit_progress(payload: dict) -> None:
    payload.setdefault("elapsedMs", int((time.time() - _t0) * 1000))
    out({"ig5": "progress", "id": _progress_rid, "payload": payload})


# ---------------------------------------------------------------- methods ---

def m_ping(params: dict) -> dict:
    return {"pong": True, "pid": os.getpid(), "open": _open, "target": _target}


def m_doctor(params: dict) -> dict:
    ver = None
    try:
        ver = _idapro.get_library_version()
    except Exception:
        pass
    caps = {}
    for mod, attr in (("ida_auto", "plan_and_wait"), ("ida_auto", "auto_wait"), ("ida_auto", "auto_make_code")):
        try:
            caps[f"{mod}.{attr}"] = hasattr(__import__(mod), attr)
        except Exception:
            caps[f"{mod}.{attr}"] = False
    return {
        "python": sys.version.split()[0],
        "pythonExe": sys.executable,
        "idaDir": _ida_dir,
        "idalib": "loaded",
        "idaVersion": list(ver) if ver else None,
        "caps": caps,
    }


def _collect_info(functions=None) -> dict:
    import ida_segment
    import ida_ida
    import ida_entry
    import ida_funcs
    import idautils

    segs = []
    for i in range(ida_segment.get_segm_qty()):
        s = ida_segment.getnseg(i)
        if s is None:
            continue
        segs.append({
            "name": ida_segment.get_segm_name(s),
            "start": hex(s.start_ea),
            "end": hex(s.end_ea),
            "size": int(s.end_ea - s.start_ea),
        })
    n_funcs = functions if isinstance(functions, int) else ida_funcs.get_func_qty()
    if not n_funcs:
        n_funcs = sum(1 for _ in idautils.Functions())
    entries = []
    for i in range(min(ida_entry.get_entry_qty(), 8)):
        entries.append({"ea": hex(ida_entry.get_entry(i)), "name": ida_entry.get_entry_name(i)})
    try:
        bits = 64 if ida_ida.inf_is_64bit() else 32
    except Exception:
        bits = None
    try:
        proc = ida_ida.inf_get_procname()
        proc = proc.decode(errors="replace") if isinstance(proc, bytes) else str(proc)
    except Exception:
        proc = None
    return {"segments": segs, "n_funcs": n_funcs, "entries": entries, "bits": bits, "proc": proc}


def _segment_ranges():
    import ida_segment

    ranges = []
    for i in range(ida_segment.get_segm_qty()):
        s = ida_segment.getnseg(i)
        if s is None or s.end_ea <= s.start_ea:
            continue
        ranges.append((int(s.start_ea), int(s.end_ea), ida_segment.get_segm_name(s)))
    return ranges


def _analyze_with_progress(emit) -> int:
    """Auto-analyze in address slices, emitting real progress between chunks."""
    import ida_auto
    import ida_funcs

    ranges = _segment_ranges()
    total = sum(e - s for s, e, _ in ranges) or 1
    # ~80 slices total keeps a smooth bar on big binaries without flooding the pipe.
    slice_size = max(0x4000, total // 80)
    slices = []
    for (start, end, name) in ranges:
        pos = start
        while pos < end:
            nxt = min(pos + slice_size, end)
            slices.append((pos, nxt, name))
            pos = nxt

    done = 0
    last_pct = -1

    def snap(stage: str, seg_name=None, force=False):
        nonlocal last_pct
        pct = min(100, int(done * 100 / total))
        if not force and pct == last_pct:
            return
        last_pct = pct
        emit({
            "stage": stage,
            "pct": pct,
            "bytes": done,
            "totalBytes": total,
            "functions": ida_funcs.get_func_qty(),
            "segment": seg_name,
            "slices": len(slices),
        })

    snap("analyzing", slices[0][2] if slices else None, force=True)
    plan = getattr(ida_auto, "plan_and_wait", None)
    for (start, end, name) in slices:
        if plan is not None:
            try:
                plan(start, end)
            except Exception:
                plan = None
        if plan is None:
            try:
                ida_auto.auto_make_code(start)
            except Exception:
                pass
            try:
                ida_auto.auto_wait()
            except Exception:
                pass
        done += end - start
        snap("analyzing", name)
    snap("analyzing", None, force=True)
    emit({"stage": "finalizing", "pct": 100, "bytes": total, "totalBytes": total,
          "functions": ida_funcs.get_func_qty(), "slices": len(slices)})
    try:
        ida_auto.auto_wait()
    except Exception:
        pass
    return ida_funcs.get_func_qty()


def m_open(params: dict) -> dict:
    global _open, _target, _t0

    path = params.get("path")
    if not path or not os.path.isfile(path):
        raise ValueError(f"target file not found: {path!r}")
    auto = bool(params.get("auto", True))
    fresh = bool(params.get("fresh", False))
    _t0 = time.time()

    if fresh:
        for suffix in (".i64", ".idb"):
            db = path + suffix
            if os.path.isfile(db):
                bak = f"{db}.bak-{int(time.time())}"
                shutil.move(db, bak)
                emit_progress({"stage": "fresh", "pct": 0, "detail": f"旧 IDB 已备份 {os.path.basename(bak)}"})

    emit_progress({"stage": "loading", "pct": 0, "detail": os.path.basename(path)})
    rc = _idapro.open_database(path, False)
    if rc != 0:
        raise RuntimeError(f"open_database rc={rc}")
    _open = True
    _target = path
    emit_progress({"stage": "loaded", "pct": 2})

    n_funcs = 0
    if auto:
        n_funcs = _analyze_with_progress(emit_progress)
    else:
        emit_progress({"stage": "skipped-analysis", "pct": 100})

    emit_progress({"stage": "decompiler", "pct": 100, "functions": n_funcs})
    global _hexrays_ready
    if not _hexrays_ready:
        try:
            _hexrays_ready = bool(import_hexrays())
        except Exception:
            _hexrays_ready = False

    info = _collect_info(n_funcs)
    info["target"] = path
    info["elapsedMs"] = int((time.time() - _t0) * 1000)
    info["reusedIdb"] = not fresh
    emit_progress({"stage": "done", "pct": 100, "functions": info["n_funcs"]})
    return info


def import_hexrays() -> bool:
    import ida_hexrays

    return bool(ida_hexrays.init_hexrays_plugin())


def m_stats(params: dict) -> dict:
    if not _open:
        return {"open": False}
    info = _collect_info()
    info["open"] = True
    info["target"] = _target
    return info


def m_funcs(params: dict) -> dict:
    import ida_funcs
    import ida_name
    import idautils

    offset = int(params.get("offset") or 0)
    limit = max(1, min(int(params.get("limit") or 30), 200))
    flt = (params.get("filter") or "").lower()
    filter_lib = bool(params.get("user_only") or params.get("filter_library"))
    rows = []
    total = 0
    for fea in idautils.Functions():
        name = ida_name.get_name(fea)
        if flt and flt not in name.lower():
            continue
        f = ida_funcs.get_func(fea)
        is_lib = bool(f and (f.flags & ida_funcs.FUNC_LIB))
        if filter_lib and is_lib:
            continue
        total += 1
        if len(rows) < limit and total > offset:
            rows.append({
                "ea": hex(fea),
                "name": name,
                "size": (f.end_ea - f.start_ea) if f else 0,
                "is_lib": is_lib,
            })
    return {"total": total, "offset": offset, "funcs": rows}


def m_strings(params: dict) -> dict:
    import idautils

    offset = int(params.get("offset") or 0)
    limit = max(1, min(int(params.get("limit") or 30), 200))
    try:
        idautils.Strings().setup(strtypes=["C"])
    except Exception:
        pass
    items = []
    total = 0
    for s in idautils.Strings():
        total += 1
        if len(items) < limit and total > offset:
            try:
                text = str(s)
            except Exception:
                text = ""
            items.append({"ea": hex(int(s.ea)), "length": int(s.length), "text": text[:200]})
    return {"total": total, "offset": offset, "strings": items}


def _resolve_ea(params: dict):
    import ida_name
    import idautils

    if params.get("ea"):
        return int(params["ea"], 16)
    want = params.get("name")
    if want:
        for fea in idautils.Functions():
            if ida_name.get_name(fea) == want:
                return fea
        raise ValueError(f"function not found by name: {want!r}")
    first = next(iter(idautils.Functions()), None)
    if first is None:
        raise ValueError("no functions in database")
    return first


def tif_from_serial(text):
    import ida_typeinf

    tif = ida_typeinf.tinfo_t()
    return tif


def m_rename(params: dict) -> dict:
    """ida_name.set_name(ea, name, flags=0) — 审批门之后的写操作。"""
    import ida_name

    if not _open:
        raise RuntimeError("no database open")
    ea = _resolve_ea(params)
    new = str(params.get("new_name") or "").strip()
    if not new:
        raise ValueError("new_name is required")
    old = ida_name.get_name(ea)
    flags = int(params.get("flags") or 0)
    ok = bool(ida_name.set_name(ea, new, flags))
    if ok:
        _op_journal.append({"kind": "rename", "ea": int(ea), "old": old})
    return {"ok": ok, "ea": hex(ea), "old": old, "new": ida_name.get_name(ea)}


def _hex_to_bytes(hex_text: str) -> bytes:
    clean = "".join(hex_text.split()).replace("0x", "").replace(",", "")
    if len(clean) % 2 != 0:
        raise ValueError("hex payload must have even length")
    if len(clean) // 2 > 4096:
        raise ValueError("patch too large (max 4096 bytes per call)")
    return bytes.fromhex(clean)


def m_patch(params: dict) -> dict:
    """ida_bytes.get_bytes + patch_bytes — 返回 before/after 与文件偏移供 diff 留档。"""
    import ida_bytes
    import ida_loader

    if not _open:
        raise RuntimeError("no database open")
    ea = _resolve_ea(params)
    buf = _hex_to_bytes(str(params.get("hex") or ""))
    if not buf:
        raise ValueError("hex payload is empty")
    if any(not ida_bytes.is_loaded(ea + offset) for offset in range(len(buf))):
        raise ValueError('patch range is not fully readable in the database')
    before = ida_bytes.get_bytes(ea, len(buf)) or b""
    if len(before) != len(buf):
        raise ValueError('patch range is not fully readable in the database')
    if params.get('expected') is not None and before != _hex_to_bytes(str(params['expected'])):
        raise ValueError('original bytes no longer match expected; patch was not applied')
    ida_bytes.patch_bytes(ea, buf)
    after = ida_bytes.get_bytes(ea, len(buf)) or b""
    if after != before:
        _op_journal.append({"kind": "bytes", "ea": int(ea), "before": before.hex()})
    return {
        "ok": after == buf,
        "ea": hex(ea),
        "size": len(buf),
        "before": before.hex(),
        "after": after.hex(),
        "applied": after == buf,
        "fileOffset": int(ida_loader.get_fileregion_offset(ea)),
    }


def m_bytes(params: dict) -> dict:
    """静态读取：ida_bytes.get_bytes（读 DB 当前内容，非调试态）。"""
    import ida_bytes

    if not _open:
        raise RuntimeError("no database open")
    ea = _resolve_ea(params)
    size = max(1, min(int(params.get("size") or 64), 4096))
    data = ida_bytes.get_bytes(ea, size) or b""
    return {"ea": hex(ea), "size": len(data), "hex": data.hex()}


def m_search(params: dict) -> dict:
    """字节特征码搜索（支持 ?? 通配）：ida_bytes.find_bytes + mask。"""
    import ida_bytes
    import ida_segment

    if not _open:
        raise RuntimeError("no database open")
    pattern = str(params.get("pattern") or "").strip()
    if not pattern:
        raise ValueError("pattern is required (hex, ?? = wildcard)")
    tokens = pattern.replace(",", " ").split()
    data = bytearray()
    mask = bytearray()
    for tok in tokens:
        if tok == "?" or tok == "??":
            data.append(0)
            mask.append(0)
        else:
            b = bytes.fromhex(tok)
            data += b
            mask += b"\xff" * len(b)
    if not data:
        raise ValueError("empty pattern")
    limit = max(1, min(int(params.get("limit") or 30), 200))
    start = int(params["start"], 16) if params.get("start") else ida_segment.getnseg(0).start_ea
    end = int(params["end"], 16) if params.get("end") else ida_idaapi_badaddr()
    flags = int(getattr(ida_bytes, "BIN_SEARCH_FORWARD", 1)) | int(getattr(ida_bytes, "BIN_SEARCH_NOSHOW", 0))
    hits = []
    cursor = start
    total = 0
    while len(hits) < limit:
        ea = ida_bytes.find_bytes(bytes(data), cursor, range_end=end, mask=bytes(mask), flags=flags)
        if ea is None or ea == ida_idaapi_badaddr():
            break
        total += 1
        hits.append(hex(ea))
        cursor = ea + 1
    return {"pattern": pattern, "total": total, "hits": hits, "size": len(data)}


def m_listing(params: dict) -> dict:
    """枚举：segments | imports | exports（IDA 各窗口的 agent 化重写）。"""
    import ida_entry
    import ida_loader
    import ida_nalt
    import ida_segment

    if not _open:
        raise RuntimeError("no database open")
    kind = str(params.get("kind") or "segments")
    limit = max(1, min(int(params.get("limit") or 100), 500))
    offset = int(params.get("offset") or 0)
    rows = []
    total = 0

    def take():
        return rows if len(rows) < limit else None

    if kind == "segments":
        for i in range(ida_segment.get_segm_qty()):
            s = ida_segment.getnseg(i)
            if s is None:
                continue
            total += 1
            if total > offset and len(rows) < limit:
                rows.append({
                    "name": ida_segment.get_segm_name(s),
                    "start": hex(s.start_ea),
                    "end": hex(s.end_ea),
                    "size": int(s.end_ea - s.start_ea),
                    "class": ida_segment.get_segm_class(s),
                    "perm": int(s.perm),
                })
    elif kind == "imports":
        qty = ida_nalt.get_import_module_qty()
        mod_name = ""

        def cb(ea, name, ordinal):  # 原型：callback(ea, name, ordinal) —— ida_nalt.py 实证
            nonlocal total
            total += 1
            if total > offset and len(rows) < limit:
                rows.append({"module": mod_name,
                             "ea": hex(ea), "name": name or f"#{ordinal}", "ordinal": int(ordinal)})
            return 0 if len(rows) < limit else 1  # 非 0 = 停止枚举

        for mi in range(qty):
            if len(rows) >= limit:
                break
            mod_name = ida_nalt.get_import_module_name(mi) or f"#{mi}"
            ida_nalt.enum_import_names(mi, cb)
    elif kind == "exports":
        total = int(ida_entry.get_entry_qty())
        for i in range(offset, min(total, offset + limit)):
            rows.append({
                "ordinal": int(ida_entry.get_entry_ordinal(i)),
                "ea": hex(ida_entry.get_entry(i)),
                "name": ida_entry.get_entry_name(i),
            })
    else:
        raise ValueError(f"unknown kind: {kind!r}")
    return {"kind": kind, "total": total, "offset": offset, "items": rows}


def m_undo(params: dict) -> dict:
    """自管回滚（新造）：弹出最近一条写操作日志并应用逆操作。
    journal 覆盖：bytes(patch) / rename / comment / set_type / create_function / delete_function。"""
    import ida_bytes
    import ida_funcs
    import ida_name
    import ida_nalt
    import ida_typeinf

    if not _open:
        raise RuntimeError("no database open")
    if params.get("action") == "list":
        safe = []
        for e in reversed(_op_journal[-30:]):
            item = {}
            for k, v in e.items():
                item[k] = ("<tinfo_t>" if k == "old_tif" and v is not None else None) if k == "old_tif" else v
            item["ea"] = hex(e["ea"])
            safe.append(item)
        return {"ok": True, "journal": safe}
    if not _op_journal:
        return {"ok": False, "action": "undo", "note": "回滚日志为空"}
    entry = _op_journal.pop()
    kind = entry.get("kind")
    ea = entry.get("ea")
    if kind == "bytes":
        ida_bytes.patch_bytes(ea, bytes.fromhex(entry["before"]))
        return {"ok": True, "action": "undo", "kind": kind, "ea": hex(ea), "restored": entry["before"]}
    if kind == "rename":
        ok = bool(ida_name.set_name(ea, entry["old"]))
        return {"ok": ok, "action": "undo", "kind": kind, "ea": hex(ea), "name": entry["old"]}
    if kind == "comment":
        ok = bool(ida_bytes.set_cmt(ea, entry["old"] or "", False))
        return {"ok": ok, "action": "undo", "kind": kind, "ea": hex(ea)}
    if kind == "set_type":
        old = entry.get("old_tif")
        if old is None:
            return {"ok": False, "action": "undo", "kind": kind, "note": "原无类型，无法自动恢复（保留现类型）"}
        ok = bool(ida_nalt.set_tinfo(ea, old))
        return {"ok": ok, "action": "undo", "kind": kind, "ea": hex(ea)}
    if kind == "create_function":
        ok = bool(ida_funcs.del_func(ea))
        return {"ok": ok, "action": "undo", "kind": kind, "ea": hex(ea)}
    if kind == "delete_function":
        ok = bool(ida_funcs.add_func(ea))
        return {"ok": ok, "action": "undo", "kind": kind, "ea": hex(ea)}
    return {"ok": False, "action": "undo", "note": f"未知日志类型 {kind!r}"}


def tif_from_serial(text):
    import ida_typeinf

    tif = ida_typeinf.tinfo_t()
    return tif


def m_fileoffset(params: dict) -> dict:
    import ida_loader

    if not _open:
        raise RuntimeError("no database open")
    ea = _resolve_ea(params)
    return {"ea": hex(ea), "fileOffset": int(ida_loader.get_fileregion_offset(ea))}


def m_idapython(params: dict) -> dict:
    """脚本逃生舱：exec 用户代码，捕获 stdout（审批门内；超时由 host rpc 超时兜底杀进程）。"""
    import io
    import contextlib

    if not _open:
        raise RuntimeError("no database open")
    code = str(params.get("code") or "")
    if not code.strip():
        raise ValueError("code is required")
    buf = io.StringIO()
    g = {"__name__": "ig5-idapython"}
    err = None
    try:
        with contextlib.redirect_stdout(buf):
            exec(code, g)  # noqa: S102 — 逃生舱本义，审批门后方
    except Exception:
        import traceback as _tb

        err = _tb.format_exc(limit=4)
    return {"ok": err is None, "output": buf.getvalue()[-4000:], "error": err}


CRYPTO_MARKERS = [
    ("AES sbox", "637C777BF26B6FC5"),
    ("MD5 init", "0123456789ABCDEF"),
    ("SHA-256 K", "428A2F98D728AE22"),
    ("CRC32 table", "0000000096300777"),
]

SUSPICIOUS_APIS = [
    "VirtualAlloc", "VirtualProtect", "WriteProcessMemory", "CreateRemoteThread",
    "WinExec", "ShellExecute", "URLDownloadToFile", "InternetOpenUrl",
    "RegSetValue", "CryptEncrypt", "CryptDecrypt", "SetWindowsHookEx",
    "LoadLibrary", "GetProcAddress", "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
]


def m_scan(params: dict) -> dict:
    """静态情报扫描（新造）：加密常数 / 可疑 API / 段熵 / 字符串族。"""
    import ida_bytes
    import ida_nalt
    import ida_segment
    import idautils
    import math

    if not _open:
        raise RuntimeError("no database open")

    # 1) 加密常数（find_bytes 精确命中）
    crypto = []
    for label, pat in CRYPTO_MARKERS:
        try:
            ea = ida_bytes.find_bytes(bytes.fromhex(pat), 0, flags=int(getattr(ida_bytes, "BIN_SEARCH_FORWARD", 1)) | int(getattr(ida_bytes, "BIN_SEARCH_NOSHOW", 0)))
            if ea is not None and ea != ida_idaapi_badaddr():
                crypto.append({"marker": label, "ea": hex(ea)})
        except Exception:
            pass

    # 2) 可疑导入 API
    susp = []
    try:
        names = []
        cur_mod = [""]

        def cb(ea, name, ordinal):  # 原型：callback(ea, name, ordinal)
            names.append((cur_mod[0], name or f"#{ordinal}"))
            return 0

        for mi in range(ida_nalt.get_import_module_qty()):
            cur_mod[0] = ida_nalt.get_import_module_name(mi) or f"#{mi}"
            ida_nalt.enum_import_names(mi, cb)
        mods = {}
        for mod, name in names:
            mods[mod] = mods.get(mod, 0) + 1
            for api in SUSPICIOUS_APIS:
                if api.lower() in (name or "").lower():
                    susp.append({"module": mod, "api": name})
                    break
        import_summary = {"modules": len(mods), "functions": len(names), "byModule": dict(sorted(mods.items(), key=lambda kv: -kv[1])[:12])}
    except Exception:
        import_summary = {"error": "import enumeration failed"}

    # 3) 段熵（采样每段前 64KB）
    seg_entropy = []
    for i in range(ida_segment.get_segm_qty()):
        s = ida_segment.getnseg(i)
        if s is None:
            continue
        span = min(int(s.end_ea - s.start_ea), 65536)
        if span <= 0:
            continue
        data = ida_bytes.get_bytes(s.start_ea, span) or b""
        if not data:
            continue
        freq = [0] * 256
        for b in data:
            freq[b] += 1
        ent = 0.0
        n = len(data)
        for c in freq:
            if c:
                p = c / n
                ent -= p * math.log2(p)
        seg_entropy.append({"segment": ida_segment.get_segm_name(s), "entropy": round(ent, 2),
                            "flag": ent > 7.2})

    # 4) 字符串族计数
    families = {"crypto": 0, "network": 0, "exec": 0, "registry": 0, "total": 0}
    try:
        try:
            import ida_strlist

            ida_strlist.build_strlist()  # 显式重建串表（idautils.Strings 惰性缓存在新库上可能为空）
        except Exception:
            pass
        idautils.Strings().setup(strtypes=["C"])
        for st in idautils.Strings():
            families["total"] += 1
            if families["total"] > 20000:
                break
            t = str(st).lower()
            if any(k in t for k in ("aes", "md5", "sha", "rsa", "base64", "des", "rc4")):
                families["crypto"] += 1
            if any(k in t for k in ("http", "tcp", "socket", "dns", "host")):
                families["network"] += 1
            if any(k in t for k in ("cmd", "powershell", "schtasks", "regsvr32")):
                families["exec"] += 1
            if any(k in t for k in ("software\\", "hkey_", "currentversion")):
                families["registry"] += 1
    except Exception:
        pass

    return {"crypto": crypto, "suspiciousApis": susp[:30], "entropy": seg_entropy,
            "stringFamilies": families}


def m_dbg(params: dict) -> dict:
    """调试车道（bochs 优先）：load/start/bpt/unbpt/regs/step/stepover/cont/suspend/readmem/writemem/stop。"""
    import ida_dbg
    import ida_idaapi
    import ida_idd

    if not _open:
        raise RuntimeError("no database open")
    op = str(params.get("op") or "")
    ea = int(params["ea"], 16) if params.get("ea") else ida_idaapi.BADADDR

    def state():
        code = int(ida_dbg.get_process_state())
        name = {ida_dbg.DSTATE_NOTASK: "no-task", ida_dbg.DSTATE_RUN: "running",
                ida_dbg.DSTATE_SUSP: "suspended"}.get(code, "unknown")
        return {"state": name, "stateCode": code}

    def timeout(default=15):
        # The engine treats -1 as infinite. Keep every headless wait bounded.
        value = params.get("timeout")
        return max(1, min(int(default if value is None else value), 60))

    def wait_for_state(expected, seconds):
        wf = ida_dbg.WFNE_ANY if expected == ida_dbg.DSTATE_NOTASK else ida_dbg.WFNE_SUSP
        wf |= ida_dbg.WFNE_SILENT
        deadline = time.monotonic() + seconds
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return {"ok": False, "event": ida_dbg.DEC_TIMEOUT, "eventName": "timeout",
                        "error": "debugger event wait timed out", **state()}
            try:
                event = int(ida_dbg.wait_for_next_event(wf, max(1, min(seconds, int(remaining) + 1))))
            except Exception as e:
                return {"ok": False, "error": f"debugger event wait failed: {e}", **state()}
            names = {ida_dbg.DEC_TIMEOUT: "timeout", ida_dbg.DEC_ERROR: "error",
                     ida_dbg.DEC_NOTASK: "no-task"}
            for name in ("PROCESS_STARTED", "PROCESS_EXITED", "BREAKPOINT", "STEP", "EXCEPTION",
                         "PROCESS_SUSPENDED", "THREAD_STARTED", "THREAD_EXITED", "LIB_LOADED", "LIB_UNLOADED"):
                value = getattr(ida_idd, name, None)
                if value is not None:
                    names[int(value)] = name.lower().replace("_", "-")
            result = {"ok": event > 0, "event": event, "eventName": names.get(event, str(event)), **state()}
            if event > 0:
                try:
                    current = ida_dbg.get_debug_event()
                    result['context'] = {'pid': int(current.pid), 'tid': int(current.tid),
                                         'ea': hex(current.ea), 'handled': bool(current.handled)}
                    if event in (getattr(ida_idd, 'PROCESS_STARTED', None), getattr(ida_idd, 'PROCESS_ATTACHED', None), getattr(ida_idd, 'LIB_LOADED', None)):
                        result['context']['module'] = {'name': ida_idd.get_event_module_name(current),
                                                       'base': hex(ida_idd.get_event_module_base(current)),
                                                       'size': int(ida_idd.get_event_module_size(current))}
                    if event == getattr(ida_idd, 'EXCEPTION', None):
                        result['context']['exception'] = {
                            'code': hex(ida_idd.get_event_exc_code(current)),
                            'ea': hex(ida_idd.get_event_exc_ea(current)),
                            'info': ida_idd.get_event_exc_info(current)}
                except Exception:
                    pass
            if event <= 0:
                result["error"] = f"debugger event wait returned {result['eventName']}"
                return result
            if result["stateCode"] == expected:
                return result
            if expected != ida_dbg.DSTATE_NOTASK:
                result.update(ok=False, error="debugger did not reach the expected process state")
                return result
            # Exit can report thread/library events before the process-exit event.

    wait_seconds = timeout(30 if op == "cont" else 15) if op in (
        "start", "step", "stepover", "cont", "suspend", "stop") else None
    if op == "load":
        last_err = None
        backend = str(params.get('backend') or 'auto')
        choices = {'auto': ('bochs', 'win32'), 'bochs': ('bochs',), 'win32': ('win32',)}
        if backend not in choices:
            raise ValueError('backend must be auto, bochs or win32')
        for name in choices[backend]:
            try:
                if bool(ida_dbg.load_debugger(name, False)):
                    return {"ok": True, "op": op, "debugger": name}
            except Exception as e:
                last_err = e
        return {"ok": False, "op": op, "error": f"no debugger loaded ({last_err})"}
    if op == "start":
        if hasattr(ida_dbg, 'set_debugger_options'):
            ida_dbg.set_debugger_options(ida_dbg.DOPT_ENTRY_BPT | ida_dbg.DOPT_START_BPT)
        r = int(ida_dbg.start_process(params.get("path") or _target or None, params.get("args") or None, params.get("dir") or None))
        if r != 1:
            reason = 'debugger start was cancelled; check backend configuration' if r == 0 else 'debugger could not create the process'
            return {"ok": False, "op": op, "rc": r, "error": reason, **state()}
        return {"op": op, "rc": r, **wait_for_state(ida_dbg.DSTATE_SUSP, wait_seconds)}
    if op == "bpt":
        return {"ok": bool(ida_dbg.add_bpt(ea)), "op": op, "ea": hex(ea)}
    if op == "unbpt":
        return {"ok": bool(ida_dbg.del_bpt(ea)), "op": op, "ea": hex(ea)}
    if op == "regs":
        if ida_dbg.get_process_state() != ida_dbg.DSTATE_SUSP:
            return {"ok": False, "op": op, "regs": {}, "error": "register reads require a suspended process", **state()}
        import ida_ida

        bits = 64 if ida_ida.inf_is_64bit() else (32 if ida_ida.inf_is_32bit_exactly() else 16)
        registers = {
            64: ("rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rip", "rsp", "rbp",
                 "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"),
            32: ("eax", "ebx", "ecx", "edx", "esi", "edi", "eip", "esp", "ebp"),
            16: ("ax", "bx", "cx", "dx", "si", "di", "ip", "sp", "bp"),
        }[bits]
        out = {}
        for reg in (*registers, "cf", "zf"):
            try:
                out[reg] = hex(int(ida_dbg.get_reg_val(reg)))
            except Exception:
                pass
        result = {"ok": bool(out), "op": op, "bits": bits, "regs": out, **state()}
        try:
            import ida_nalt
            result['databaseBase'] = hex(ida_nalt.get_imagebase())
        except Exception:
            pass
        if not out:
            result["error"] = "no register values could be read"
        return result
    if op == 'setreg':
        if ida_dbg.get_process_state() != ida_dbg.DSTATE_SUSP:
            return {'ok': False, 'op': op, 'error': 'register writes require a suspended process', **state()}
        name = str(params.get('reg') or '').lower()
        if name not in ('rax rbx rcx rdx rsi rdi rip rsp rbp r8 r9 r10 r11 r12 r13 r14 r15 eax ebx ecx edx esi edi eip esp ebp eflags').split():
            raise ValueError('unsupported register name')
        value = int(str(params['value']), 0)
        old = int(ida_dbg.get_reg_val(name))
        ok = bool(ida_dbg.set_reg_val(name, value))
        return {'ok': ok, 'op': op, 'reg': name, 'before': hex(old),
                'after': hex(int(ida_dbg.get_reg_val(name))), **state()}
    if op in ("step", "stepover"):
        if ida_dbg.get_process_state() != ida_dbg.DSTATE_SUSP:
            return {"ok": False, "op": op, "error": "stepping requires a suspended process", **state()}
        r = bool(ida_dbg.step_into() if op == "step" else ida_dbg.step_over())
        if not r:
            return {"ok": False, "op": op, "error": "debugger rejected the step", **state()}
        return {"op": op, **wait_for_state(ida_dbg.DSTATE_SUSP, wait_seconds)}
    if op == "cont":
        r = bool(ida_dbg.continue_process())
        if not r:
            return {"ok": False, "op": op, "error": "debugger rejected continue", **state()}
        return {"op": op, **wait_for_state(ida_dbg.DSTATE_SUSP, wait_seconds)}
    if op == "suspend":
        if ida_dbg.get_process_state() == ida_dbg.DSTATE_SUSP:
            return {"ok": True, "op": op, **state()}
        if not ida_dbg.suspend_process():
            return {"ok": False, "op": op, "error": "debugger rejected suspend", **state()}
        return {"op": op, **wait_for_state(ida_dbg.DSTATE_SUSP, wait_seconds)}
    if op == "readmem":
        size = max(1, min(int(params.get("size") or 64), 4096))
        try:
            buf = ida_idd.dbg_read_memory(ea, size)
        except Exception as e:
            return {"ok": False, "op": op, "error": str(e), **state()}
        if buf is None or not buf:
            return {"ok": False, "op": op, "error": "debugger memory read failed", **state()}
        return {"ok": True, "op": op, "ea": hex(ea), "size": len(buf), "hex": bytes(buf).hex(), **state()}
    if op == "writemem":
        data = _hex_to_bytes(str(params.get("hex") or ""))
        if not data or len(data) > 4096:
            raise ValueError('debug memory writes require 1..4096 bytes')
        try:
            ok = bool(ida_idd.dbg_write_memory(ea, data))
        except Exception as e:
            return {"ok": False, "op": op, "error": str(e)}
        return {"ok": ok, "op": op, "ea": hex(ea), "written": len(data) if ok else 0, **state()}
    if op == "stop":
        try:
            ok = bool(ida_dbg.exit_process())
        except Exception as e:
            return {"ok": False, "op": op, "error": str(e), **state()}
        if not ok:
            return {"ok": False, "op": op, "error": "debugger rejected process exit", **state()}
        return {"op": op, **wait_for_state(ida_dbg.DSTATE_NOTASK, wait_seconds)}
    raise ValueError(f"unknown dbg op: {op!r}")


def m_comment(params: dict) -> dict:
    """ida_bytes.set_cmt(ea, comm, rptble)。"""
    import ida_bytes

    if not _open:
        raise RuntimeError("no database open")
    ea = _resolve_ea(params)
    text = str(params.get("text") or "")
    rptble = bool(params.get("repeatable", False))
    old = ida_bytes.get_cmt(ea, False) or ""
    ok = bool(ida_bytes.set_cmt(ea, text, rptble))
    if ok:
        _op_journal.append({"kind": "comment", "ea": int(ea), "old": old})
    return {"ok": ok, "ea": hex(ea), "text": text[:200]}


def m_xrefs(params: dict) -> dict:
    """交叉引用：idautils.XrefsTo / XrefsFrom。支持 ea / name / str=<文本>。"""
    import ida_name
    import ida_funcs
    import idautils

    if not _open:
        raise RuntimeError("no database open")
    limit = max(1, min(int(params.get("limit") or 30), 200))
    direction = params.get("direction") or "to"

    eas = []
    if params.get("str"):
        needle = str(params["str"]).lower()
        try:
            idautils.Strings().setup(strtypes=["C"])
        except Exception:
            pass
        for s in idautils.Strings():
            if needle in str(s).lower():
                eas.append(int(s.ea))
                if len(eas) >= 8:
                    break
        if not eas:
            return {"total": 0, "hits": []}
    else:
        eas = [_resolve_ea(params)]

    rows = []
    total = 0
    for target in eas:
        xrefs = idautils.XrefsTo(target, 0) if direction == "to" else idautils.XrefsFrom(target, 0)
        for x in xrefs:
            total += 1
            if len(rows) < limit:
                other = x.frm if direction == "to" else x.to
                f = ida_funcs.get_func(other)
                rows.append({
                    "target": hex(target),
                    "other": hex(other),
                    "type": int(x.type),
                    "func": ida_name.get_name(f.start_ea) if f else None,
                    "func_ea": hex(f.start_ea) if f else None,
                })
    return {"total": total, "hits": rows, "targets": [hex(e) for e in eas]}


def m_calls(params: dict) -> dict:
    """调用图：callees（本函数调用了谁）/ callers（谁调用了本函数）。"""
    import ida_funcs
    import ida_name
    import idautils

    if not _open:
        raise RuntimeError("no database open")
    limit = max(1, min(int(params.get("limit") or 30), 200))
    direction = params.get("direction") or "callees"
    ea = _resolve_ea(params)
    f = ida_funcs.get_func(ea)
    if f is None:
        raise ValueError(f"not inside a function: {hex(ea)}")

    found = {}

    def note(other_ea):
        of = ida_funcs.get_func(other_ea)
        if of is None:
            return
        key = of.start_ea
        if key == f.start_ea:
            return
        if key not in found:
            found[key] = {"ea": hex(key), "name": ida_name.get_name(key), "refs": 0}
        found[key]["refs"] += 1

    if direction == "callers":
        for x in idautils.XrefsTo(f.start_ea, 0):
            note(x.frm)
    else:
        for item in idautils.FuncItems(f.start_ea):
            for ref in idautils.CodeRefsFrom(item, 0):
                note(ref)

    rows = sorted(found.values(), key=lambda r: -r["refs"])[:limit]
    return {"ea": hex(f.start_ea), "name": ida_name.get_name(f.start_ea), "direction": direction, "total": len(found), "calls": rows}


def m_analyze(params: dict) -> dict:
    """分析引擎显式控制（agent 视角重写 IDA 的 Options→Analysis 手工操作）。
    action: create_function | delete_function | undefine | mark_code | reanalyze"""
    import ida_auto
    import ida_bytes
    import ida_funcs

    if not _open:
        raise RuntimeError("no database open")
    action = str(params.get("action") or "")
    ea = _resolve_ea(params) if params.get("ea") or params.get("name") else None
    end = int(params["end"], 16) if params.get("end") else None
    size = int(params.get("size") or 0)

    if action == "create_function":
        if ea is None:
            raise ValueError("ea is required for create_function")
        ok = bool(ida_funcs.add_func(ea, end if end is not None else ida_idaapi_badaddr()))
        if ok:
            _op_journal.append({"kind": "create_function", "ea": int(ea)})
        return {"ok": ok, "action": action, "ea": hex(ea)}
    if action == "delete_function":
        if ea is None:
            raise ValueError("ea is required for delete_function")
        ok = bool(ida_funcs.del_func(ea))
        if ok:
            _op_journal.append({"kind": "delete_function", "ea": int(ea)})
        return {"ok": ok, "action": action, "ea": hex(ea)}
    if action == "undefine":
        if ea is None:
            raise ValueError("ea is required for undefine")
        ida_bytes.del_items(ea, 0, size or 16)
        return {"ok": True, "action": action, "ea": hex(ea), "bytes": size or 16}
    if action in ("mark_code", "reanalyze"):
        if ea is None:
            raise ValueError("ea is required")
        stop = end if end is not None else ea + (size or 4096)
        kind = getattr(ida_auto, "AU_CODE", 1) if action == "mark_code" else getattr(ida_auto, "AU_USED", 2)
        try:
            ida_auto.auto_mark_range(ea, stop, kind)
        except Exception:
            pass
        try:
            ida_auto.auto_wait()
        except Exception:
            pass
        return {"ok": True, "action": action, "ea": hex(ea), "end": hex(stop)}
    raise ValueError(f"unknown action: {action!r}")


def ida_idaapi_badaddr():
    import ida_idaapi

    return ida_idaapi.BADADDR


def m_set_type(params: dict) -> dict:
    """类型应用：parse_decl + apply_tinfo（agent 提议类型 → 审批 → 落到 IDB）。"""
    import ida_nalt
    import ida_typeinf

    if not _open:
        raise RuntimeError("no database open")
    ea = _resolve_ea(params)
    decl = str(params.get("decl") or "").strip()
    typename = str(params.get("typename") or "").strip()
    old_tif = ida_typeinf.tinfo_t()
    had_old = bool(ida_nalt.get_tinfo(old_tif, ea))
    tif = ida_typeinf.tinfo_t()
    if typename:
        if not tif.get_named_type(None, typename):
            raise ValueError(f"named type not found in local types: {typename!r}")
    elif decl:
        # 规范化：确保是完整声明（补 ;）
        text = decl if decl.rstrip().endswith((";", "}")) else decl + ";"
        parsed = ida_typeinf.parse_decl(tif, None, text, int(getattr(ida_typeinf, "PT_SIL", 0)))
        if not parsed and tif.empty():
            raise ValueError(f"parse_decl failed for: {decl!r}")
    else:
        raise ValueError("decl or typename is required")
    ok = bool(ida_typeinf.apply_tinfo(ea, tif, int(getattr(ida_typeinf, "TINFO_DEFINITE", 0))))
    if ok:
        _op_journal.append({"kind": "set_type", "ea": int(ea), "old_tif": old_tif if had_old else None})
    return {"ok": ok, "ea": hex(ea), "type": str(tif) if not tif.empty() else None, "decl": decl or typename}


def m_decompile(params: dict) -> dict:
    global _hexrays_ready
    import ida_bytes
    import ida_funcs
    import ida_hexrays
    import ida_name
    import idautils

    if _open is False:
        raise RuntimeError("no database open")
    if not _hexrays_ready:
        if not ida_hexrays.init_hexrays_plugin():
            raise RuntimeError("hexrays init failed (decompiler unavailable for this arch)")
        _hexrays_ready = True
    ea = _resolve_ea(params)
    cf = ida_hexrays.decompile(ea)
    code = str(cf)
    f = ida_funcs.get_func(ea)
    result = {
        "ea": hex(ea),
        "name": ida_name.get_name(ea),
        "size": (f.end_ea - f.start_ea) if f else 0,
        "lines": code.count("\n") + 1,
        "code": code,
    }
    # style=llm：微调 Hex-Rays 输出 —— 附调用图与字符串引用摘要，喂模型更省 token
    if str(params.get("style") or "") == "llm" and f is not None:
        callees = {}
        strings = []
        for item in idautils.FuncItems(f.start_ea):
            for ref in idautils.CodeRefsFrom(item, 0):
                callee = ida_funcs.get_func(ref)
                if callee and callee.start_ea != f.start_ea:
                    key = ida_name.get_name(callee.start_ea)
                    callees[key] = callees.get(key, 0) + 1
            for dref in idautils.DataRefsFrom(item):
                if dref == item:
                    continue
                raw = ida_bytes.get_strlit_contents(dref, -1, 0)
                if raw:
                    try:
                        text = raw.decode("utf-8", "replace")
                    except Exception:
                        text = ""
                    if text and text not in strings:
                        strings.append(text[:120])
        result["meta"] = {
            "callees": sorted(callees.items(), key=lambda kv: -kv[1])[:20],
            "strings": strings[:20],
        }
    return result


def m_struct(params: dict) -> dict:
    """结构体类型系统：定义、解析、查看与应用结构体（Local Types / Til 核心能力）。"""
    if not _open:
        raise RuntimeError("database not open")
    import ida_typeinf
    til = ida_typeinf.get_idati()
    action = str(params.get("action") or "list")

    if action == "define":
        decl = str(params.get("decl") or "").strip()
        if not decl:
            raise ValueError("decl is required for action='define'")
        err_count = ida_typeinf.parse_decls(til, decl, None, ida_typeinf.HTI_DCL)
        if err_count > 0:
            raise RuntimeError(f"parse_decls failed with {err_count} errors. Check C syntax.")
        name = params.get("name")
        if not name:
            import re
            m = re.search(r'(?:struct|union|enum)\s+([A-Za-z_][A-Za-z0-9_]*)', decl)
            if m:
                name = m.group(1)
        details = None
        if name:
            tif = ida_typeinf.tinfo_t()
            if tif.get_named_type(til, name):
                details = {"name": name, "size": tif.get_size()}
        return {"status": "ok", "action": "define", "name": name, "details": details}

    elif action == "get":
        name = str(params.get("name") or "").strip()
        if not name:
            raise ValueError("name is required for action='get'")
        tif = ida_typeinf.tinfo_t()
        if not tif.get_named_type(til, name):
            raise KeyError(f"Type {name!r} not found in database local types")
        res = {
            "name": name,
            "size": tif.get_size(),
            "is_struct": tif.is_struct(),
            "is_union": tif.is_union(),
            "is_enum": tif.is_enum(),
            "fields": [],
        }
        # Full C declaration for the workbench's reviewable edit draft.
        try:
            res['decl'] = tif._print(name, ida_typeinf.PRTYPE_MULTI | ida_typeinf.PRTYPE_DEF | ida_typeinf.PRTYPE_SEMI) or ''
        except Exception:
            res['decl'] = ''
        if tif.is_udt():
            udt = ida_typeinf.udt_type_data_t()
            if tif.get_udt_details(udt):
                for m in udt:
                    res["fields"].append({
                        "name": m.name,
                        "offset": m.offset // 8,
                        "size": m.size // 8,
                        "type": str(m.type),
                    })
        return res

    elif action == "list":
        limit = int(params.get("limit") or 100)
        filter_str = str(params.get("filter") or "").lower()
        items = []
        qty = ida_typeinf.get_ordinal_limit(til) if hasattr(ida_typeinf, "get_ordinal_limit") else 1000
        total_count = ida_typeinf.get_ordinal_count(til) if hasattr(ida_typeinf, "get_ordinal_count") else qty
        for ord_id in range(1, qty):
            tif = ida_typeinf.tinfo_t()
            if tif.get_numbered_type(til, ord_id):
                tname = tif.get_type_name() or tif.dstr() or f"ord_{ord_id}"
                if filter_str and filter_str not in tname.lower():
                    continue
                items.append({
                    "ordinal": ord_id,
                    "name": tname,
                    "size": tif.get_size(),
                    "is_struct": tif.is_struct(),
                })
                if len(items) >= limit:
                    break
        return {"total_types": total_count, "items": items}

    elif action == "apply":
        ea_str = params.get("ea")
        type_name = str(params.get("name") or "")
        if not ea_str or not type_name:
            raise ValueError("ea and name are required for action='apply'")
        ea = int(str(ea_str), 16) if str(ea_str).startswith("0x") else int(str(ea_str))
        tif = ida_typeinf.tinfo_t()
        if not tif.get_named_type(til, type_name):
            raise KeyError(f"Type {type_name!r} not found")
        ok = ida_typeinf.apply_tinfo(ea, tif, ida_typeinf.TINFO_DEFINITE)
        return {"status": "ok", "ea": hex(ea), "type": type_name, "applied": bool(ok)}

    else:
        raise ValueError(f"unknown struct action: {action!r}")


def m_cfg(params: dict) -> dict:
    """控制流图 (CFG) 拓扑提取与 Mermaid 流程图生成。"""
    if not _open:
        raise RuntimeError("database not open")
    import ida_funcs, ida_gdl, ida_lines, ida_bytes, ida_idaapi, ida_name
    ea_val = params.get("ea")
    name_val = params.get("name")

    pfn = None
    if ea_val:
        ea = int(str(ea_val), 16) if str(ea_val).startswith("0x") else int(str(ea_val))
        pfn = ida_funcs.get_func(ea)
    elif name_val:
        ea = ida_name.get_name_ea(ida_idaapi.BADADDR, name_val)
        if ea != ida_idaapi.BADADDR:
            pfn = ida_funcs.get_func(ea)

    if not pfn:
        raise ValueError(f"Function not found at ea={ea_val!r} name={name_val!r}")

    fc = ida_gdl.FlowChart(pfn)
    blocks = []
    edges = []
    fname = ida_funcs.get_func_name(pfn.start_ea)
    mermaid_lines = [f"%% CFG for {fname} ({hex(pfn.start_ea)})", "flowchart TD"]

    for b in fc:
        succs = [s.id for s in b.succs()]
        preds = [p.id for p in b.preds()]
        n_insns = 0
        cur_ea = b.start_ea
        first_disasm = ""
        last_disasm = ""
        while cur_ea < b.end_ea:
            dis = ida_lines.tag_remove(ida_lines.generate_disasm_line(cur_ea, 0) or "").strip()
            if not first_disasm:
                first_disasm = dis
            last_disasm = dis
            n_insns += 1
            cur_ea = ida_bytes.next_head(cur_ea, b.end_ea)
            if cur_ea == ida_idaapi.BADADDR or cur_ea <= b.start_ea:
                break

        b_info = {
            "id": b.id,
            "start": hex(b.start_ea),
            "end": hex(b.end_ea),
            "insns": n_insns,
            "succs": succs,
            "preds": preds,
            "first": first_disasm[:50],
            "last": last_disasm[:50],
        }
        blocks.append(b_info)

        sanitized_dis = first_disasm[:25].replace('"', "'").replace('[', '(').replace(']', ')')
        mermaid_lines.append(f'  B{b.id}["B{b.id} {hex(b.start_ea)}<br/>{sanitized_dis}"]')

        for sid in succs:
            edges.append({"from": b.id, "to": sid})
            mermaid_lines.append(f"  B{b.id} --> B{sid}")

    return {
        "func": fname,
        "start_ea": hex(pfn.start_ea),
        "total_blocks": len(blocks),
        "total_edges": len(edges),
        "blocks": blocks,
        "edges": edges,
        "mermaid": "\n".join(mermaid_lines),
    }


def m_slice(params: dict) -> dict:
    """微代码与局部变量追踪：提取函数局部变量列表与关注切片。"""
    if not _open:
        raise RuntimeError("database not open")
    import ida_funcs, ida_hexrays
    if not _hexrays_ready:
        if not ida_hexrays.init_hexrays_plugin():
            raise RuntimeError("Hex-Rays decompiler plugin failed to initialize")

    ea_val = params.get("ea")
    if not ea_val:
        raise ValueError("ea is required")
    ea = int(str(ea_val), 16) if str(ea_val).startswith("0x") else int(str(ea_val))
    pfn = ida_funcs.get_func(ea)
    if not pfn:
        raise ValueError(f"No function at {hex(ea)}")

    cfunc = ida_hexrays.decompile(pfn.start_ea)
    if not cfunc:
        raise RuntimeError("Failed to decompile function")

    variables = []
    for idx, lv in enumerate(cfunc.get_lvars()):
        variables.append({
            "index": idx,
            "name": lv.name,
            "type": str(lv.tif),
            "size": lv.width,
            "is_arg": lv.is_arg_var,
            "used": lv.used,
        })

    target_var = params.get("var")
    var_lines = []
    if target_var:
        lines = str(cfunc).split("\n")
        for i, line in enumerate(lines):
            if target_var in line:
                var_lines.append({"line_no": i + 1, "code": line.strip()})

    return {
        "func": ida_funcs.get_func_name(pfn.start_ea),
        "ea": hex(pfn.start_ea),
        "total_variables": len(variables),
        "variables": variables,
        "slice_variable": target_var,
        "slice_lines": var_lines if target_var else None,
    }


def m_fingerprint(params: dict) -> dict:
    """编译器指纹与库函数识别（FLIRT / Library Filter）。"""
    if not _open:
        raise RuntimeError("database not open")
    import ida_funcs, ida_nalt

    abi = ida_nalt.get_abi_name() or "unknown"
    total = ida_funcs.get_func_qty()
    lib_funcs = []
    user_funcs = []

    for i in range(total):
        fn = ida_funcs.getn_func(i)
        if not fn:
            continue
        name = ida_funcs.get_func_name(fn.start_ea)
        is_lib = bool(fn.flags & ida_funcs.FUNC_LIB)
        if is_lib:
            if len(lib_funcs) < 100:
                lib_funcs.append({"ea": hex(fn.start_ea), "name": name})
        else:
            if len(user_funcs) < 100:
                user_funcs.append({"ea": hex(fn.start_ea), "name": name})

    lib_count = sum(1 for i in range(total) if (ida_funcs.getn_func(i).flags & ida_funcs.FUNC_LIB))
    return {
        "abi": abi,
        "total_functions": total,
        "library_functions_count": lib_count,
        "user_functions_count": total - lib_count,
        "library_ratio": round(lib_count / max(1, total), 3),
        "sample_library_funcs": lib_funcs[:30],
        "sample_user_funcs": user_funcs[:30],
    }


METHODS = {
    "ping": m_ping,
    "doctor": m_doctor,
    "open": m_open,
    "stats": m_stats,
    "funcs": m_funcs,
    "strings": m_strings,
    "decompile": m_decompile,
    "calls": m_calls,
    "analyze": m_analyze,
    "set_type": m_set_type,
    "rename": m_rename,
    "patch": m_patch,
    "comment": m_comment,
    "xrefs": m_xrefs,
    "bytes": m_bytes,
    "search": m_search,
    "listing": m_listing,
    "undo": m_undo,
    "fileoffset": m_fileoffset,
    "idapython": m_idapython,
    "scan": m_scan,
    "dbg": m_dbg,
    "struct": m_struct,
    "cfg": m_cfg,
    "slice": m_slice,
    "fingerprint": m_fingerprint,
}


def _extended(module, method, params):
    if not _open:
        raise RuntimeError('no database open')
    # The embedded runtime can replace sys.path after a database is loaded.
    if _worker_module_dir not in sys.path:
        sys.path.insert(0, _worker_module_dir)
    return getattr(__import__(module), method)(params)


for _method in ('stack', 'switches', 'switch_repair', 'vtables', 'microcode'):
    METHODS[_method] = lambda params, method=_method: _extended('advanced_analysis', 'm_' + method, params)
for _method in ('disasm', 'semantics', 'emulate'):
    METHODS[_method] = lambda params, method=_method: _extended('execution_analysis', 'm_' + method, params)


def serve() -> None:
    global _progress_rid
    out({"ig5": "ready", "pid": os.getpid()})
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except Exception:
            continue
        rid = req.get("id")
        method = req.get("method")
        params = req.get("params") or {}
        fn = METHODS.get(method)
        if fn is None:
            out({"id": rid, "error": f"unknown method: {method!r}"})
            continue
        _progress_rid = rid
        try:
            out({"id": rid, "result": fn(params)})
        except Exception:
            out({"id": rid, "error": traceback.format_exc(limit=4)})
        finally:
            _progress_rid = None


def main() -> None:
    global _t0
    ap = argparse.ArgumentParser()
    ap.add_argument("--ida-dir", required=True)
    ap.add_argument("--doctor", action="store_true")
    ap.add_argument("--selftest")
    args = ap.parse_args()
    bootstrap(args.ida_dir)
    if args.doctor:
        out({"id": 0, "result": m_doctor({})})
        return
    if args.selftest:
        _t0 = time.time()
        out({"id": 1, "result": m_open({"path": args.selftest, "auto": True})})
        return
    serve()


if __name__ == "__main__":
    main()
