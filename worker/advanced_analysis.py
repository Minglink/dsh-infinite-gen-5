"""Bounded Reverse analysis adapters. Importing this module does not load an engine."""
from __future__ import annotations

import re

_retained_optimizer_filters = []  # Keep a failed-to-remove native callback alive until worker teardown.


def _integer(value, name, low=None, high=None):
    if isinstance(value, bool):
        raise ValueError(f"{name} must be an integer")
    try:
        number = int(value, 0) if isinstance(value, str) else int(value)
    except (TypeError, ValueError, OverflowError):
        raise ValueError(f"{name} must be an integer") from None
    if isinstance(value, float) and number != value:
        raise ValueError(f"{name} must be an integer")
    if (low is not None and number < low) or (high is not None and number > high):
        raise ValueError(f"{name} is outside the supported range")
    return number


def _limit(params, name, default, maximum):
    return _integer(params.get(name, default), name, 1, maximum)


def _ea(params, key="ea"):
    import ida_idaapi
    import ida_name
    value = params.get(key)
    if value is None or value == "":
        if key == "ea" and params.get("name"):
            result = int(ida_name.get_name_ea(ida_idaapi.BADADDR, str(params["name"])))
        else:
            raise ValueError(f"{key} or symbol name is required")
    elif isinstance(value, str):
        try:
            result = int(value, 16)
        except ValueError:
            raise ValueError(f"{key} must be a hexadecimal address") from None
    else:
        result = _integer(value, key, 0)
    if result < 0 or result == ida_idaapi.BADADDR:
        raise ValueError(f"{key} does not resolve to a valid address")
    return result


def _function(params):
    import ida_funcs
    ea = _ea(params)
    pfn = ida_funcs.get_func(ea)
    if pfn is None:
        raise ValueError(f"no function contains {hex(ea)}")
    return pfn


def m_stack(params):
    """Recover persisted frame types and offsets without invoking a decompiler."""
    import ida_frame
    import ida_funcs
    import ida_range
    import ida_typeinf

    pfn = _function(params)
    limit = _limit(params, "limit", 512, 4096)
    parts = {}
    for label, part in (("locals", ida_frame.FPC_LVARS), ("savedregs", ida_frame.FPC_SAVREGS),
                        ("retaddr", ida_frame.FPC_RETADDR), ("args", ida_frame.FPC_ARGS)):
        span = ida_range.range_t()
        ida_frame.get_frame_part(span, pfn, part)
        parts[label] = {"start": int(span.start_ea), "end": int(span.end_ea),
                        "size": max(0, int(span.end_ea - span.start_ea))}
    tif = ida_typeinf.tinfo_t()
    present = bool(ida_frame.get_func_frame(tif, pfn))
    result = {"ok": True, "ea": hex(pfn.start_ea), "func": ida_funcs.get_func_name(pfn.start_ea),
              "has_frame": present, "parts": parts, "members": [], "total_members": 0,
              "frame_size": int(ida_frame.get_frame_size(pfn)),
              "return_address_size": int(ida_frame.get_frame_retsize(pfn)),
              "offset_basis": "frame structure bytes; fp_offset is frame-pointer relative"}
    if not present:
        result["note"] = "No persisted frame type; no frame or local variables were synthesized."
        return result
    udt = ida_typeinf.udt_type_data_t()
    if not tif.get_udt_details(udt):
        return {**result, "ok": False, "error": "frame type does not expose structure details"}
    result["frame_type_size"] = int(tif.get_size())
    result["total_members"] = len(udt)
    for member in list(udt)[:limit]:
        offset_bits, size_bits = int(member.offset), int(member.size)
        offset = offset_bits // 8
        if member.is_retaddr():
            kind = "retaddr"
        elif member.is_savregs():
            kind = "savedregs"
        else:
            kind = next((name for name, span in parts.items()
                         if span["start"] <= offset < span["end"]), "unclassified")
        result["members"].append({"name": str(member.name), "type": str(member.type),
                                   "offset": offset, "offset_bits": offset_bits,
                                   "size": (size_bits + 7) // 8, "size_bits": size_bits,
                                   "fp_offset": int(ida_frame.soff_to_fpoff(pfn, offset)),
                                   "kind": kind, "is_gap": bool(member.is_gap())})
    result["truncated"] = len(udt) > limit
    return result


def _switch_record(ea, si, max_cases):
    import ida_idaapi
    import ida_xref
    calculated = ida_xref.calc_switch_cases(ea, si)
    cases = []
    error = None
    truncated = False
    if calculated is None:
        error = "Reverse could not calculate this switch's cases"
    else:
        if len(calculated.cases) != len(calculated.targets):
            error = "switch case and target vectors have different lengths"
        else:
            remaining = max_cases
            for index, values in enumerate(calculated.cases):
                if remaining <= 0:
                    truncated = True
                    break
                kept = min(len(values), remaining)
                truncated = truncated or kept < len(values)
                cases.append({"values": [int(values[i]) for i in range(kept)],
                              "target": hex(int(calculated.targets[index]))})
                remaining -= kept
    result = {"ea": hex(ea), "flags": int(si.flags), "ncases": int(si.ncases),
              "jumps": hex(int(si.jumps)), "element_size": int(si.get_jtable_element_size()),
              "table_entries": int(si.get_jtable_size()), "shift": int(si.get_shift()),
              "lowcase": int(si.get_lowcase()), "sparse": bool(si.is_sparse()),
              "indirect": bool(si.is_indirect()), "custom": bool(si.is_custom()),
              "default": hex(int(si.defjump)) if si.has_default() and si.defjump != ida_idaapi.BADADDR else None,
              "elbase": hex(int(si.elbase)) if si.has_elbase() else None,
              "values_table": hex(int(si.values)) if si.is_sparse() else None,
              "cases": cases, "truncated": truncated}
    if error:
        result["error"] = error
    return result


def m_switches(params):
    """Enumerate actual switch metadata at an EA or throughout its containing function."""
    import ida_funcs
    import ida_nalt
    import idautils

    ea = _ea(params)
    limit = _limit(params, "limit", 128, 1024)
    max_cases = _limit(params, "max_cases", 2048, 65535)
    pfn = ida_funcs.get_func(ea)
    if bool(params.get("exact", False)) or pfn is None:
        addresses = (ea,)
    else:
        addresses = idautils.FuncItems(pfn.start_ea)
    records = []
    total = 0
    for address in addresses:
        si = ida_nalt.get_switch_info(address)
        if si is None:
            continue
        total += 1
        if len(records) < limit:
            records.append(_switch_record(int(address), si, max_cases))
    return {"ok": True, "ea": hex(ea), "func": ida_funcs.get_func_name(pfn.start_ea) if pfn else None,
            "total": total, "switches": records, "truncated": total > limit}


def m_switch_repair(params):
    """Preview or explicitly apply a validated direct table or existing-switch xref rebuild."""
    import ida_bytes
    import ida_idaapi
    import ida_idp
    import ida_nalt
    import ida_segment
    import ida_ua
    import ida_xref

    ea = _ea(params)
    action = str(params.get("action", "rebuild"))
    if action not in ("rebuild", "define"):
        raise ValueError("action must be rebuild or define")
    if not isinstance(params.get("apply", False), bool) or not isinstance(params.get("create_instructions", False), bool):
        raise ValueError("apply and create_instructions must be booleans")
    previous = ida_nalt.get_switch_info(ea)
    if action == "rebuild":
        if previous is None:
            raise ValueError("no switch metadata exists; define requires an explicit table layout")
        if previous.is_custom():
            raise ValueError("custom switch xref rebuilding is unsupported")
        si = previous
    else:
        table_key = "table" if params.get("table") is not None else "jumps"
        table = _ea(params, table_key)
        count = _integer(params.get("ncases"), "ncases", 1, 4096)
        width = _integer(params.get("element_size"), "element_size", 1, 8)
        if width not in (1, 2, 4, 8):
            raise ValueError("element_size must be 1, 2, 4, or 8")
        for flag in ("signed", "subtract", "relative"):
            if not isinstance(params.get(flag, False), bool):
                raise ValueError(f"{flag} must be a boolean")
        table_bytes = ida_bytes.get_bytes(table, count * width)
        if table_bytes is None or len(table_bytes) != count * width:
            raise ValueError("the complete jump table must contain readable database bytes")
        si = ida_nalt.switch_info_t()
        si.flags = ida_nalt.SWI_USER
        si.jumps = table
        si.ncases = count
        si.startea = ea
        si.lowcase = _integer(params.get("lowcase", 0), "lowcase", -(1 << 63), (1 << 63) - 1) & ((1 << 64) - 1)
        si.set_jtable_element_size(width)
        si.set_shift(_integer(params.get("shift", 0), "shift", 0, 3))
        base_key = "elbase" if params.get("elbase") is not None else "relative_base"
        if params.get("relative", False) and params.get(base_key) is None:
            raise ValueError("relative tables require an explicit elbase")
        if params.get(base_key) is not None:
            si.set_elbase(_ea(params, base_key))
            si.flags |= ida_nalt.SWI_ELBASE
        if params.get("signed", False):
            si.flags |= ida_nalt.SWI_SIGNED
        if params.get("subtract", False):
            if not si.has_elbase():
                raise ValueError("subtract requires relative_base")
            si.flags |= ida_nalt.SWI_SUBTRACT
        default_key = "default" if params.get("default") is not None else "default_ea"
        if params.get(default_key) is not None:
            si.defjump = _ea(params, default_key)
    if not ida_bytes.is_code(ida_bytes.get_full_flags(ea)):
        raise ValueError("switch ea must already identify a code instruction")
    instruction = ida_ua.insn_t()
    if ida_ua.decode_insn(instruction, ea) <= 0 or not ida_idp.is_indirect_jump_insn(instruction):
        raise ValueError("switch ea must identify a decoded indirect jump instruction")
    calculated = ida_xref.calc_switch_cases(ea, si)
    if calculated is None or not len(calculated.targets):
        raise ValueError("the specified switch layout does not yield any targets")
    targets = sorted(set(int(value) for value in calculated.targets))
    if si.has_default() and si.defjump != ida_idaapi.BADADDR:
        targets = sorted(set(targets + [int(si.defjump)]))
    for target in targets:
        segment = ida_segment.getseg(target)
        if segment is None or not segment.perm & ida_segment.SEGPERM_EXEC:
            raise ValueError(f"switch target {hex(target)} is outside executable segments")
        flags = ida_bytes.get_full_flags(target)
        if params.get("create_instructions", False) and not (ida_bytes.is_code(flags) or ida_bytes.is_unknown(flags)):
            raise ValueError(f"target {hex(target)} contains defined data; instruction creation refused")
    result = {"ok": True, "action": action, "applied": False,
              "switch": _switch_record(ea, si, 4096), "targets": [hex(target) for target in targets],
              "replaces_existing": previous is not None, "created_instructions": []}
    if not params.get("apply", False):
        return result
    # All layout/target checks above precede the first mutation. No automatic undo is claimed.
    if action == "define":
        ida_nalt.set_switch_info(ea, si)
    result["applied"] = True
    result["table_created"] = bool(ida_xref.create_switch_table(ea, si))
    result["xrefs_created"] = bool(ida_xref.create_switch_xrefs(ea, si))
    if params.get("create_instructions", False):
        for target in targets:
            if not ida_bytes.is_code(ida_bytes.get_full_flags(target)):
                size = int(ida_ua.create_insn(target))
                result["created_instructions"].append({"ea": hex(target), "size": size})
    result["ok"] = result["table_created"] and result["xrefs_created"] and all(
        item["size"] > 0 for item in result["created_instructions"])
    if not result["ok"]:
        result["error"] = "switch repair was partially applied; inspect the returned operation results"
    return result


def _predicate_candidate(insn, hx):
    """Conservative structural evidence, never a claim of path feasibility or rewriting."""
    if not hx.is_mcode_jcond(insn.opcode):
        return None
    if insn.l.t == hx.mop_n and (insn.r.t == hx.mop_n or insn.r.empty()):
        return {"kind": "constant-condition", "evidence": "conditional operands are integer constants"}
    direct = {getattr(hx, name, None) for name in
              ("m_jz", "m_jnz", "m_jae", "m_jb", "m_ja", "m_jbe", "m_jg", "m_jge", "m_jl", "m_jle")}
    if insn.opcode in direct and insn.l.t in (hx.mop_r, hx.mop_S) and insn.l.equal_mops(insn.r, 0):
        return {"kind": "self-comparison", "evidence": "both integer comparison operands refer to the same register/stack location"}
    return None


def _microcode_text(mba, max_blocks, max_instructions):
    lines = []
    for index in range(min(int(mba.qty), max_blocks)):
        block = mba.get_mblock(index)
        instruction = block.head
        seen = set()
        while instruction is not None and len(lines) < max_instructions:
            identity = int(instruction.this) if hasattr(instruction, "this") else id(instruction)
            if identity in seen:
                break
            seen.add(identity)
            lines.append({"block": int(block.serial), "ea": hex(int(instruction.ea)),
                          "text": str(instruction.dstr())})
            instruction = instruction.next
    return lines


def _same_native_object(left, right):
    if hasattr(left, "this") and hasattr(right, "this"):
        return int(left.this) == int(right.this)
    return left is right


def _make_rule_filter(hx, mba, rules, max_hits):
    class TemporaryRuleFilter(hx.optinsn_t):
        def __init__(self):
            super().__init__()
            self.hits = []
            self.errors = []
            self.invocations = 0
            self.calls_total = 0

        def func(self, block, insn, optflags):
            self.calls_total += 1
            try:
                if block is None or not _same_native_object(block.mba, mba) or len(self.hits) >= max_hits:
                    return 0
                self.invocations += 1
                rule = {hx.m_xor: "xor-self", hx.m_sub: "sub-self"}.get(int(insn.opcode))
                if rule not in rules:
                    return 0
                # Only top-level, plain integer operands. Never erase a memory read,
                # a nested call, a volatile expression, a barrier, or a persistent insn.
                if (insn.is_fpinsn() or insn.is_mbarrier() or insn.is_persistent() or
                    insn.has_side_effects(True) or insn.l.has_side_effects(True) or insn.r.has_side_effects(True)):
                    return 0
                if insn.l.t not in (hx.mop_r, hx.mop_n) or insn.r.t != insn.l.t or insn.d.t != hx.mop_r:
                    return 0
                width = int(insn.l.size)
                if width not in (1, 2, 4, 8) or int(insn.r.size) != width or int(insn.d.size) != width:
                    return 0
                if not insn.l.equal_mops(insn.r, 0):
                    return 0
                before = str(insn.dstr())
                zero = hx.mop_t()
                zero.make_number(0, width)
                # Native contract requires dirty use/def lists when source uses change.
                block.mark_lists_dirty()
                insn.l.assign(zero)
                insn.r.erase()
                insn.opcode = hx.m_mov
                self.hits.append({"rule": rule, "block": int(block.serial), "ea": hex(int(insn.ea)),
                                  "width": width, "before": before, "after": str(insn.dstr())})
                return 1
            except Exception as error:
                # Exceptions must not cross a native optimizer callback boundary.
                if len(self.errors) < 8:
                    self.errors.append(type(error).__name__)
                return 0

    return TemporaryRuleFilter()


def _optimize_temporary(mba, hx, rules, max_blocks, max_instructions):
    before = _microcode_text(mba, max_blocks, max_instructions)
    optimizer = _make_rule_filter(hx, mba, rules, min(max_instructions, 4096)) if rules else None
    installed, attempted, removed = False, False, not bool(rules)
    changes, error = 0, None
    try:
        if optimizer is not None:
            attempted = True
            optimizer.install()
            installed = True
        changes = int(mba.optimize_local(0))
        if optimizer is not None and optimizer.hits:
            mba.verify(True)
    except Exception:
        error = "Reverse temporary microcode optimization failed"
    finally:
        if optimizer is not None and attempted:
            try:
                removed = bool(optimizer.remove())
            except Exception:
                removed = False
            if not removed:
                _retained_optimizer_filters.append(optimizer)
                error = "Reverse could not remove the temporary rule filter; reopen this target before further microcode work"
    callback_errors = optimizer.errors if optimizer is not None else []
    if callback_errors:
        error = "Reverse temporary rule callback failed; no successful rewrite is claimed"
    result = {"scope": "temporary microcode only", "changes": changes,
              "before": before, "after": _microcode_text(mba, max_blocks, max_instructions),
              "idb_modified": False, "custom_rules": list(rules),
              "filter_installed": installed, "filter_removed": removed,
              "callback_invocations": optimizer.invocations if optimizer is not None else 0,
              "callback_calls_total": optimizer.calls_total if optimizer is not None else 0,
              "rule_hits": optimizer.hits if optimizer is not None else [],
              "callback_errors": callback_errors, "ok": error is None}
    if error:
        result["error"] = error
    return result


def m_microcode(params):
    """Generate real microcode at a requested maturity and inspect its block/instruction graph."""
    import ida_hexrays as hx
    import ida_funcs

    pfn = _function(params)
    names = ("generated", "preoptimized", "locopt", "calls", "glbopt1", "glbopt2", "glbopt3", "lvars")
    maturities = {name: int(getattr(hx, "MMAT_" + name.upper())) for name in names}
    maturity = str(params.get("maturity", "glbopt3")).lower().removeprefix("mmat_")
    if maturity not in maturities:
        raise ValueError("maturity must be one of " + ", ".join(names))
    max_blocks = _limit(params, "max_blocks", 512, 4096)
    max_instructions = _limit(params, "max_instructions", 10000, 100000)
    action = str(params.get("action", "inspect"))
    if action not in ("inspect", "optimize"):
        raise ValueError("microcode action must be inspect or optimize")
    if action == "optimize" and maturity not in ("generated", "preoptimized"):
        raise ValueError("temporary local optimization requires generated or preoptimized maturity")
    rules = params.get("rules", [])
    if not isinstance(rules, list) or any(rule not in ("xor-self", "sub-self") for rule in rules):
        raise ValueError("rules must be an array containing only xor-self or sub-self")
    rules = list(dict.fromkeys(rules))
    if rules and action != "optimize":
        raise ValueError("custom rules require action optimize")
    if _retained_optimizer_filters:
        return {"ok": False, "error": "Reverse has a retained rule filter; reopen this target before further microcode work"}
    if not hx.init_hexrays_plugin():
        return {"ok": False, "error": "Reverse microcode capability is unavailable", "available_maturities": names}
    failure = hx.hexrays_failure_t()
    ranges = hx.mba_ranges_t(pfn)
    mba = hx.gen_microcode(ranges, failure, None, 0, maturities[maturity])
    if mba is None:
        return {"ok": False, "ea": hex(pfn.start_ea), "maturity": maturity,
                "error": "Reverse microcode generation failed", "failure_code": int(failure.code),
                "failure_ea": hex(int(failure.errea))}
    optimization = None
    graph_built = int(mba.maturity) >= maturities["locopt"]
    if action == "optimize":
        optimization = _optimize_temporary(mba, hx, rules, max_blocks, max_instructions)
        if not optimization["ok"]:
            return {"ok": False, "ea": hex(pfn.start_ea), "error": optimization["error"], "optimization": optimization}
        # optimize_local() constructs the graph itself when it is not already ready.
        graph_built = True
    if not graph_built:
        code = int(mba.build_graph())
        if code != int(hx.MERR_OK):
            return {"ok": False, "ea": hex(pfn.start_ea), "error": "Reverse microcode graph construction failed", "failure_code": code}
        graph_built = True
    blocks, edges, candidates = [], [], []
    count = 0
    for index in range(min(int(mba.qty), max_blocks)):
        block = mba.get_mblock(index)
        serial = int(block.serial)
        predecessors = [int(block.pred(i)) for i in range(block.npred())]
        successors = [int(block.succ(i)) for i in range(block.nsucc())]
        row = {"id": serial, "start": hex(int(block.start)), "end": hex(int(block.end)),
               "type": int(block.type), "preds": predecessors, "succs": successors, "instructions": []}
        for target in successors:
            edges.append({"from": serial, "to": target})
        instruction = block.head
        local_seen = set()
        while instruction is not None and count < max_instructions:
            # A native pointer cycle must not cause an unbounded traversal.
            identity = int(instruction.this) if hasattr(instruction, "this") else id(instruction)
            if identity in local_seen:
                row["traversal_error"] = "instruction list contains a cycle"
                break
            local_seen.add(identity)
            text = str(instruction.dstr())
            item = {"index": len(row["instructions"]), "ea": hex(int(instruction.ea)),
                    "opcode": int(instruction.opcode), "text": text,
                    "left": str(instruction.l.dstr()), "right": str(instruction.r.dstr()),
                    "destination": str(instruction.d.dstr())}
            row["instructions"].append(item)
            candidate = _predicate_candidate(instruction, hx)
            if candidate is not None:
                candidates.append({"block": serial, "instruction": item["index"], "ea": item["ea"],
                                   "text": text, "confidence": "candidate", **candidate})
            count += 1
            instruction = instruction.next
        row["truncated"] = instruction is not None
        blocks.append(row)
    actual = next((name for name, value in maturities.items() if value == int(mba.maturity)), str(int(mba.maturity)))
    return {"ok": True, "ea": hex(pfn.start_ea), "func": ida_funcs.get_func_name(pfn.start_ea),
            "requested_maturity": maturity, "maturity": actual, "available_maturities": list(names),
            "total_blocks": int(mba.qty), "returned_instructions": count, "blocks": blocks, "edges": edges,
            "action": action, "graph_built": graph_built, "opaque_predicate_candidates": candidates,
            "optimization": optimization,
            "truncated": int(mba.qty) > len(blocks) or any(block["truncated"] for block in blocks),
            "analysis_note": ("Temporary IR was optimized; database bytes and persisted analysis were not modified. "
                              if action == "optimize" else "Read-only intermediate analysis. ")
                             + "Predicate candidates require semantic verification."}


class _ImageReader:
    def __init__(self):
        import ida_ida
        self.ptrsize = 8 if ida_ida.inf_is_64bit() else 4
        self.order = "big" if ida_ida.inf_is_be() else "little"

    def mapped(self, ea, size=1):
        import ida_segment
        segment = ida_segment.getseg(ea)
        return bool(segment is not None and ea + size <= segment.end_ea)

    def read(self, ea, size):
        import ida_bytes
        if not self.mapped(ea, size):
            raise ValueError("RTTI pointer is outside mapped segments")
        data = ida_bytes.get_bytes(ea, size)
        if data is None or len(data) != size:
            raise ValueError("RTTI structure contains unreadable bytes")
        return bytes(data)

    def uint(self, ea, size=4, signed=False):
        return int.from_bytes(self.read(ea, size), self.order, signed=signed)

    def pointer(self, ea):
        return self.uint(ea, self.ptrsize)

    def string(self, ea, maximum=512):
        data = bytearray()
        for offset in range(maximum):
            value = self.uint(ea + offset, 1)
            if value == 0:
                try:
                    return data.decode("ascii")
                except UnicodeDecodeError:
                    raise ValueError("RTTI name is not an ASCII ABI name") from None
            if value < 0x20 or value > 0x7e:
                raise ValueError("RTTI name contains nonprintable bytes")
            data.append(value)
        raise ValueError("RTTI name is not terminated within the size limit")

    def executable(self, ea):
        import ida_segment
        segment = ida_segment.getseg(ea)
        return bool(segment is not None and segment.perm & ida_segment.SEGPERM_EXEC)


def _display_type(raw, abi):
    import ida_name
    symbol = raw.lstrip(".") if abi == "msvc" else "_ZTS" + raw.lstrip("*")
    display = ida_name.demangle_name(symbol, ida_name.MNG_LONG_FORM)
    return str(display) if display else raw


def _msvc_type(reader, ea):
    reader.read(ea, reader.ptrsize * 2)
    raw = reader.string(ea + reader.ptrsize * 2)
    if not raw.startswith(".?A") or not raw.endswith("@@"):
        raise ValueError("MSVC TypeDescriptor name does not have a recognized decorated form")
    return {"ea": hex(ea), "raw_name": raw, "name": _display_type(raw, "msvc")}


def _msvc_rtti(reader, address_point, max_bases):
    col = reader.pointer(address_point - reader.ptrsize)
    signature = reader.uint(col)
    if reader.order != "little" or signature != (1 if reader.ptrsize == 8 else 0):
        raise ValueError("complete-object locator signature does not match the target ABI")
    offset, cd_offset = reader.uint(col + 4), reader.uint(col + 8)
    if reader.ptrsize == 8:
        self_rva = reader.uint(col + 20)
        image_base = col - self_rva
        if image_base < 0 or image_base & 0xfff:
            raise ValueError("complete-object locator self RVA yields an invalid image base")
        resolve = lambda value: image_base + value
        type_ea, hierarchy = resolve(reader.uint(col + 12)), resolve(reader.uint(col + 16))
    else:
        image_base = None
        resolve = lambda value: value
        type_ea, hierarchy = reader.pointer(col + 12), reader.pointer(col + 16)
    main_type = _msvc_type(reader, type_ea)
    chd_signature, attributes = reader.uint(hierarchy), reader.uint(hierarchy + 4)
    count = reader.uint(hierarchy + 8)
    if chd_signature != 0 or not 1 <= count <= 4096:
        raise ValueError("class-hierarchy descriptor signature or base count is invalid")
    array = resolve(reader.uint(hierarchy + 12))
    reader.read(array, min(count, max_bases) * 4)
    bases, errors, edges, active = [], [], [], []
    for index in range(min(count, max_bases)):
        descriptor = resolve(reader.uint(array + index * 4))
        try:
            reader.read(descriptor, 24)
            base_type = _msvc_type(reader, resolve(reader.uint(descriptor)))
            contained = reader.uint(descriptor + 4)
            if contained >= count or index + contained >= count:
                raise ValueError("base descriptor subtree exceeds the hierarchy array")
            base = {"index": index, "descriptor": hex(descriptor), "type": base_type,
                    "contained_bases": contained, "mdisp": reader.uint(descriptor + 8, signed=True),
                    "pdisp": reader.uint(descriptor + 12, signed=True),
                    "vdisp": reader.uint(descriptor + 16, signed=True),
                    "attributes": reader.uint(descriptor + 20)}
            while active and index > active[-1][1]:
                active.pop()
            if active:
                edges.append({"derived_index": active[-1][0], "base_index": index,
                              "evidence": "BaseClassArray preorder and numContainedBases"})
            bases.append(base)
            if contained:
                active.append((index, index + contained))
        except ValueError as error:
            errors.append({"index": index, "descriptor": hex(descriptor), "error": str(error)})
            active.clear()
    return {"abi": "msvc", "type": main_type,
            "complete_object_locator": {"ea": hex(col), "signature": signature, "offset": offset,
                                        "constructor_displacement": cd_offset,
                                        "image_base": hex(image_base) if image_base is not None else None},
            "class_hierarchy": {"ea": hex(hierarchy), "attributes": attributes,
                                "base_count": count, "base_array": hex(array)},
            "bases": bases, "inheritance_edges": edges, "parse_errors": errors,
            "truncated": count > max_bases}


def _itanium_type(reader, ea, max_bases, depth=0, seen=None):
    import ida_name
    seen = set() if seen is None else set(seen)
    if ea in seen or depth > 16:
        return {"ea": hex(ea), "error": "RTTI recursion cycle or depth limit", "bases": []}
    seen.add(ea)
    vptr, name_ptr = reader.pointer(ea), reader.pointer(ea + reader.ptrsize)
    raw = reader.string(name_ptr)
    # A genuine RTTI ABI name is either a length-prefixed identifier or an encoding.
    if not raw or not re.match(r"\*?(?:[1-9][0-9]*[A-Za-z_]|N|Z)", raw):
        raise ValueError("typeinfo name has no recognized ABI encoding")
    if not reader.mapped(vptr):
        raise ValueError("typeinfo runtime vtable pointer is outside mapped segments")
    vptr_names = [str(ida_name.get_name(vptr) or ""), str(ida_name.get_name(vptr - 2 * reader.ptrsize) or "")]
    vptr_name = next((name for name in vptr_names if "__class_type_info" in name or
                      "__si_class_type_info" in name or "__vmi_class_type_info" in name), "")
    result = {"ea": hex(ea), "raw_name": raw, "name": _display_type(raw, "itanium"),
              "vptr": hex(vptr), "vptr_symbol": vptr_name or None, "bases": [], "kind": "unknown"}
    # Names of the runtime typeinfo vtables provide evidence for the variant layout.
    if "__vmi_class_type_info" in vptr_name:
        result["kind"] = "vmi-class"
        result["flags"] = reader.uint(ea + 2 * reader.ptrsize)
        count = reader.uint(ea + 2 * reader.ptrsize + 4)
        if count > 4096:
            raise ValueError("typeinfo base count exceeds the parser limit")
        result["base_count"] = count
        result["truncated"] = count > max_bases
        start = ea + 2 * reader.ptrsize + 8
        for index in range(min(count, max_bases)):
            entry = start + index * reader.ptrsize * 2
            base_ea = reader.pointer(entry)
            offset_flags = reader.uint(entry + reader.ptrsize, reader.ptrsize, signed=True)
            try:
                base_type = _itanium_type(reader, base_ea, max_bases, depth + 1, seen)
            except ValueError as error:
                base_type = {"ea": hex(base_ea), "error": str(error)}
            result["bases"].append({"type": base_type, "offset": offset_flags >> 8,
                                    "virtual": bool(offset_flags & 1), "public": bool(offset_flags & 2),
                                    "offset_basis": "vtable vbase-offset entry" if offset_flags & 1 else "object bytes",
                                    "evidence": "__vmi_class_type_info base_info"})
    elif "__si_class_type_info" in vptr_name:
        result["kind"] = "si-class"
        base_ea = reader.pointer(ea + 2 * reader.ptrsize)
        try:
            base_type = _itanium_type(reader, base_ea, max_bases, depth + 1, seen)
        except ValueError as error:
            base_type = {"ea": hex(base_ea), "error": str(error)}
        result["bases"].append({"type": base_type, "offset": 0, "virtual": False, "public": True,
                                "evidence": "__si_class_type_info single public nonvirtual base"})
    elif "__class_type_info" in vptr_name:
        result["kind"] = "class"
    else:
        result["note"] = "Runtime typeinfo vtable variant is unidentified; inheritance layout was not inferred."
    return result


def _itanium_rtti(reader, address_point, max_bases):
    import ida_name
    offset = reader.uint(address_point - 2 * reader.ptrsize, reader.ptrsize, signed=True)
    if abs(offset) > 0x10000000:
        raise ValueError("vtable offset-to-top exceeds the supported object displacement")
    type_ea = reader.pointer(address_point - reader.ptrsize)
    if not type_ea:
        raise ValueError("vtable has no RTTI typeinfo pointer")
    info = _itanium_type(reader, type_ea, max_bases)
    if info["kind"] == "unknown" and not (
        str(ida_name.get_name(address_point - 2 * reader.ptrsize) or "").startswith("_ZTV") or
        str(ida_name.get_name(type_ea) or "").startswith("_ZTI")):
        raise ValueError("unnamed typeinfo has no identifiable runtime RTTI variant")
    return {"abi": "itanium", "offset_to_top": offset, "type": info,
            "bases": info["bases"], "evidence": "offset-to-top/typeinfo/address-point ABI header"}


def _vtable_at(reader, ea, abi, max_slots, max_bases):
    import ida_funcs
    import ida_name
    symbol = str(ida_name.get_name(ea) or "")
    if symbol.startswith("_ZTV"):
        ea += reader.ptrsize * 2
    parsers = (("msvc", _msvc_rtti), ("itanium", _itanium_rtti))
    errors = []
    rtti = None
    for label, parser in parsers:
        if abi != "auto" and abi != label:
            continue
        try:
            rtti = parser(reader, ea, max_bases)
            break
        except ValueError as error:
            errors.append({"abi": label, "error": str(error)})
    if rtti is None:
        return {"ok": False, "ea": hex(ea), "symbol": symbol or None, "rtti": None,
                "slots": [], "errors": errors,
                "note": "No supported RTTI header was validated; stripped or RTTI-disabled tables are not asserted as classes."}
    slots = []
    stop_reason = "slot limit"
    for index in range(max_slots):
        slot_ea = ea + index * reader.ptrsize
        try:
            target = reader.pointer(slot_ea)
        except ValueError:
            stop_reason = "unreadable slot"
            break
        if not reader.executable(target):
            stop_reason = "next slot is not an executable address"
            break
        slots.append({"index": index, "offset": index * reader.ptrsize, "ea": hex(slot_ea), "target": hex(target),
                      "name": str(ida_name.get_name(target) or ida_funcs.get_func_name(target) or "")})
    if not slots:
        return {"ok": False, "ea": hex(ea), "symbol": symbol or None, "rtti": rtti,
                "slots": [], "error": "RTTI header was parsed but no executable virtual-function slot was found"}
    declaration = "struct IG5_vftable_" + format(ea, "x") + " {\n" + "\n".join(
        f"    void (*slot_{slot['index']:03d})(void); /* +0x{slot['offset']:x} -> {slot['target']} */"
        for slot in slots) + "\n};"
    return {"ok": True, "ea": hex(ea), "symbol": symbol or str(ida_name.get_name(ea) or "") or None,
            "pointer_size": reader.ptrsize, "rtti": rtti, "slots": slots, "slot_count": len(slots),
            "struct_decl": declaration, "signature_note": "Slot prototypes are placeholders; argument and return types are not inferred.",
            "truncated": len(slots) == max_slots, "stop_reason": stop_reason}


def m_vtables(params):
    """Recover only ABI-backed vtable/RTTI evidence; bounded discovery also handles stripped PE RTTI."""
    import ida_bytes
    import ida_segment
    import idautils

    abi = str(params.get("abi", "auto")).lower()
    if abi not in ("auto", "msvc", "itanium"):
        raise ValueError("abi must be auto, msvc, or itanium")
    max_slots = _limit(params, "max_slots", 128, 4096)
    max_bases = _limit(params, "max_bases", 128, 1024)
    limit = _limit(params, "limit", 64, 512)
    reader = _ImageReader()
    if params.get("ea") is not None or params.get("name"):
        table = _vtable_at(reader, _ea(params), abi, max_slots, max_bases)
        if params.get("offset") is not None:
            offset = _integer(params["offset"], "offset", 0, reader.ptrsize * 4096)
            if offset % reader.ptrsize:
                raise ValueError("offset must be aligned to the target pointer size")
            table["selected_slot"] = next((slot for slot in table["slots"] if slot["offset"] == offset), None)
            if table["selected_slot"] is None:
                table["selection_error"] = "offset does not identify a recovered executable slot"
        return {"ok": table["ok"], "tables": [table] if table["ok"] else [],
                "total": int(table["ok"]), "requested": table, "scanned_bytes": 0}
    if params.get("offset") is not None:
        raise ValueError("offset resolution requires an explicit vtable ea or name")
    max_scan = _limit(params, "max_scan_bytes", 8 * 1024 * 1024, 64 * 1024 * 1024)
    tables, seen = [], set()
    names_examined = 0
    for ea, name in idautils.Names():
        names_examined += 1
        if names_examined > 200000 or len(tables) >= limit:
            break
        if not (str(name).startswith("??_7") or str(name).startswith("_ZTV")):
            continue
        table = _vtable_at(reader, int(ea), abi, max_slots, max_bases)
        if table["ok"] and table["ea"] not in seen:
            seen.add(table["ea"])
            tables.append(table)
    scanned = 0
    segment = ida_segment.get_first_seg()
    while segment is not None and scanned < max_scan and len(tables) < limit:
        if not segment.perm & ida_segment.SEGPERM_EXEC:
            start = (int(segment.start_ea) + reader.ptrsize - 1) // reader.ptrsize * reader.ptrsize
            end = min(int(segment.end_ea), start + max_scan - scanned)
            while start < end and len(tables) < limit:
                size = min(65536, end - start)
                data = ida_bytes.get_bytes(start, size)
                scanned += size
                if data is not None:
                    for offset in range(0, len(data) - reader.ptrsize + 1, reader.ptrsize):
                        target = int.from_bytes(data[offset:offset + reader.ptrsize], reader.order)
                        ea = start + offset
                        if hex(ea) in seen or not reader.executable(target):
                            continue
                        table = _vtable_at(reader, ea, abi, max_slots, max_bases)
                        if table["ok"]:
                            seen.add(table["ea"])
                            tables.append(table)
                            if len(tables) >= limit:
                                break
                start += size
        segment = ida_segment.get_next_seg(segment.start_ea)
    return {"ok": True, "abi": abi, "tables": tables, "total": len(tables),
            "scanned_bytes": scanned, "names_examined": min(names_examined, 200000),
            "truncated": len(tables) >= limit or scanned >= max_scan or names_examined > 200000,
            "analysis_note": "Counts cover validated RTTI-backed tables within the scan limits, not every class in the binary."}


READ_METHODS = {"stack": m_stack, "switches": m_switches, "vtables": m_vtables, "microcode": m_microcode}
WRITE_METHODS = {"switch_repair": m_switch_repair}
