"""Engine-neutral, bounded C++ RTTI and virtual-table byte analysis.

This module owns the ABI parsing algorithm. A provider supplies only memory,
permissions and existing symbols; no commercial analysis API is imported.
Required provider members: pointer_size, byteorder, imagebase, read(ea, size),
is_executable(ea), symbol(ea), and ranges (or sections). A range is a mapping
with integer start/end, optional readable/executable booleans. Optional members
are symbols() yielding (ea, name), resolve_symbol(name), and demangle(raw, abi).
The public entry point is analyze_vtables(provider, params, *, limits=None).

An address is a virtual address in the provider's current image. Explicit
table+offset selection resolves only recovered slots, never register origins.
Inheritance results describe validated ABI records, not reconstructed source.
"""

from dataclasses import dataclass
import re


class RTTIError(ValueError):
    """The supplied bytes cannot establish the requested ABI structure."""


class BudgetExceeded(RTTIError):
    """Shared analysis work budget exhausted; discovery must stop."""


_DEFAULT_LIMITS = {
    "read_bytes": 32 * 1024 * 1024,
    "read_calls": 200000,
    "candidates": 8192,
    "type_nodes": 8192,
    "depth": 16,
    "name_bytes": 512,
    "symbols": 200000,
    "ranges": 4096,
}
_HARD_LIMITS = {
    "read_bytes": 128 * 1024 * 1024,
    "read_calls": 1000000,
    "candidates": 65536,
    "type_nodes": 65536,
    "depth": 32,
    "name_bytes": 4096,
    "symbols": 200000,
    "ranges": 16384,
}


def _integer(value, name, minimum=0, maximum=None):
    if isinstance(value, bool):
        raise ValueError(name + " must be an integer")
    if isinstance(value, str):
        try:
            value = int(value, 16 if value.lower().startswith("0x") else 10)
        except ValueError:
            raise ValueError(name + " must be an integer") from None
    if not isinstance(value, int) or value < minimum or (maximum is not None and value > maximum):
        raise ValueError(name + " is outside the supported integer range")
    return value


def _limit(params, key, default, maximum):
    return _integer(params.get(key, default), key, 1, maximum)


class _Budget:
    def __init__(self, limits):
        self.limits = dict(_DEFAULT_LIMITS)
        if limits is not None:
            if not isinstance(limits, dict) or any(key not in _HARD_LIMITS for key in limits):
                raise ValueError("limits must contain only recognized budget keys")
            for key, value in limits.items():
                self.limits[key] = _integer(value, key, 1, _HARD_LIMITS[key])
        self.used = {key: 0 for key in ("read_bytes", "read_calls", "candidates", "type_nodes")}
        self.exhausted = None

    def consume(self, key, amount=1):
        if self.used[key] + amount > self.limits[key]:
            self.exhausted = key
            raise BudgetExceeded("RTTI analysis " + key + " budget exhausted")
        self.used[key] += amount

    def report(self):
        return {"limits": dict(self.limits), "used": dict(self.used), "exhausted": self.exhausted}


@dataclass(frozen=True)
class _Range:
    start: int
    end: int
    readable: bool
    executable: bool


class _Reader:
    def __init__(self, provider, budget):
        self.provider = provider
        self.budget = budget
        self.ptrsize = _integer(getattr(provider, "pointer_size", None), "pointer_size", 4, 8)
        if self.ptrsize not in (4, 8):
            raise ValueError("pointer_size must be 4 or 8")
        self.order = getattr(provider, "byteorder", None)
        if self.order not in ("little", "big"):
            raise ValueError("byteorder must be little or big")
        self.address_max = (1 << (8 * self.ptrsize)) - 1
        self.imagebase = _integer(getattr(provider, "imagebase", None), "imagebase", 0, self.address_max)
        for name in ("read", "is_executable", "symbol"):
            if not callable(getattr(provider, name, None)):
                raise ValueError("provider must supply " + name)
        source = getattr(provider, "ranges", None)
        if source is None:
            source = getattr(provider, "sections", None)
        if source is None:
            raise ValueError("provider must supply mapped ranges or sections")
        source = source() if callable(source) else source
        self.ranges = []
        for item in source:
            if len(self.ranges) >= budget.limits["ranges"]:
                raise ValueError("provider mapped-range count exceeds the limit")
            if isinstance(item, dict):
                start, end = item.get("start"), item.get("end")
                readable = item.get("readable", True)
                executable = item.get("executable", False)
            elif isinstance(item, (tuple, list)) and len(item) in (2, 3):
                start, end = item[:2]
                readable, executable = True, item[2] if len(item) == 3 else False
            else:
                raise ValueError("provider range must contain start/end")
            start = _integer(start, "range start", 0, self.address_max)
            end = _integer(end, "range end", start + 1, self.address_max + 1)
            if not isinstance(readable, bool) or not isinstance(executable, bool):
                raise ValueError("provider range permissions must be booleans")
            self.ranges.append(_Range(start, end, readable, executable))
        self.ranges.sort(key=lambda item: (item.start, item.end))
        if not self.ranges:
            raise ValueError("provider has no mapped ranges")
        for previous, current in zip(self.ranges, self.ranges[1:]):
            if current.start < previous.end:
                raise ValueError("provider mapped ranges overlap")

    def mapped(self, ea, size=1):
        if (not isinstance(ea, int) or isinstance(ea, bool) or ea < 0 or size < 1
                or ea > self.address_max or size > self.address_max + 1 - ea):
            return False
        return any(item.readable and item.start <= ea and ea + size <= item.end for item in self.ranges)

    def read(self, ea, size):
        if not self.mapped(ea, size):
            raise RTTIError("RTTI pointer is outside readable mapped ranges")
        self.budget.consume("read_calls")
        self.budget.consume("read_bytes", size)
        try:
            data = self.provider.read(ea, size)
        except Exception:
            raise RTTIError("provider memory read failed") from None
        if not isinstance(data, (bytes, bytearray, memoryview)) or len(data) != size:
            raise RTTIError("RTTI structure contains unreadable bytes")
        return bytes(data)

    def uint(self, ea, size=4, signed=False):
        return int.from_bytes(self.read(ea, size), self.order, signed=signed)

    def pointer(self, ea):
        value = self.uint(ea, self.ptrsize)
        if value == 0:
            raise RTTIError("RTTI structure contains a null pointer")
        return value

    def resolve_rva(self, value):
        if value == 0 or value > self.address_max - self.imagebase:
            raise RTTIError("RTTI RVA is null or overflows the target address space")
        result = self.imagebase + value
        if not self.mapped(result):
            raise RTTIError("RTTI RVA is outside readable mapped ranges")
        return result

    def string(self, ea):
        data = bytearray()
        for offset in range(self.budget.limits["name_bytes"]):
            value = self.uint(ea + offset, 1)
            if value == 0:
                return data.decode("ascii")
            if value < 0x20 or value > 0x7e:
                raise RTTIError("RTTI name contains nonprintable or non-ASCII bytes")
            data.append(value)
        raise RTTIError("RTTI name is not terminated within the size limit")

    def executable(self, ea):
        if not isinstance(ea, int) or isinstance(ea, bool) or not 0 < ea <= self.address_max:
            return False
        if not any(item.start <= ea < item.end for item in self.ranges):
            return False
        try:
            return bool(self.provider.is_executable(ea))
        except Exception:
            raise RTTIError("provider executable-permission query failed") from None

    def symbol(self, ea):
        if not isinstance(ea, int) or ea < 0 or ea > self.address_max:
            return ""
        try:
            name = self.provider.symbol(ea)
        except Exception:
            raise RTTIError("provider symbol query failed") from None
        return str(name or "")[:4096]

    def display(self, raw, abi):
        demangle = getattr(self.provider, "demangle", None)
        if callable(demangle):
            try:
                value = demangle(raw, abi)
            except Exception:
                value = None
            if value:
                return str(value)[:4096]
        # Decode only the simple encodings we can establish without a demangler.
        if abi == "msvc" and re.fullmatch(r"\.\?A[UV](?:[A-Za-z_][A-Za-z_0-9]*@)+@", raw):
            return "::".join(reversed(raw[4:-2].split("@")))
        if abi == "itanium":
            value = raw.lstrip("*")
            nested = value.startswith("N") and value.endswith("E")
            value = value[1:-1] if nested else value
            names = []
            while value:
                match = re.match(r"([1-9][0-9]*)([A-Za-z_])", value)
                if match is None:
                    break
                size, start = int(match.group(1)), len(match.group(1))
                if size > len(value) - start:
                    break
                name = value[start:start + size]
                if not re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]*", name):
                    break
                names.append(name)
                value = value[start + size:]
            if names and not value and (nested or len(names) == 1):
                return "::".join(names)
        return raw


def _msvc_type(reader, ea):
    reader.budget.consume("type_nodes")
    reader.read(ea, reader.ptrsize * 2)
    raw = reader.string(ea + reader.ptrsize * 2)
    if not re.fullmatch(r"\.\?A[UV].+@@", raw):
        raise RTTIError("MSVC TypeDescriptor name has no recognized class/struct encoding")
    return {"ea": hex(ea), "raw_name": raw, "name": reader.display(raw, "msvc")}


def _msvc_rtti(reader, address_point, max_bases):
    if reader.order != "little":
        raise RTTIError("MSVC RTTI requires a little-endian image")
    col = reader.pointer(address_point - reader.ptrsize)
    reader.read(col, 24 if reader.ptrsize == 8 else 20)
    signature = reader.uint(col)
    if signature != (1 if reader.ptrsize == 8 else 0):
        raise RTTIError("complete-object locator signature does not match the target ABI")
    offset, cd_offset = reader.uint(col + 4), reader.uint(col + 8)
    if reader.ptrsize == 8:
        self_rva = reader.uint(col + 20)
        if self_rva == 0 or self_rva > col or col - self_rva != reader.imagebase:
            raise RTTIError("complete-object locator self RVA disagrees with the provider image base")
        resolve = reader.resolve_rva
        type_ea, hierarchy = resolve(reader.uint(col + 12)), resolve(reader.uint(col + 16))
    else:
        resolve = lambda value: value
        type_ea, hierarchy = reader.pointer(col + 12), reader.pointer(col + 16)
    main_type = _msvc_type(reader, type_ea)
    reader.read(hierarchy, 16)
    chd_signature, attributes, count = reader.uint(hierarchy), reader.uint(hierarchy + 4), reader.uint(hierarchy + 8)
    if chd_signature != 0 or not 1 <= count <= 4096:
        raise RTTIError("class-hierarchy descriptor signature or base count is invalid")
    array = resolve(reader.uint(hierarchy + 12))
    reader.read(array, min(count, max_bases) * 4)
    bases, edges, active = [], [], []
    for index in range(min(count, max_bases)):
        descriptor = resolve(reader.uint(array + index * 4))
        reader.read(descriptor, 24)
        base_type = _msvc_type(reader, resolve(reader.uint(descriptor)))
        contained = reader.uint(descriptor + 4)
        if contained >= count or index + contained >= count:
            raise RTTIError("base descriptor subtree exceeds the hierarchy array")
        while active and index > active[-1][1]:
            active.pop()
        if index == 0 and (base_type["ea"] != main_type["ea"] or contained != count - 1):
            raise RTTIError("hierarchy root does not describe the complete object type")
        if index and not active:
            raise RTTIError("base descriptor is detached from the hierarchy root")
        if active and index + contained > active[-1][1]:
            raise RTTIError("base descriptor subtree exceeds its parent subtree")
        base = {"index": index, "descriptor": hex(descriptor), "type": base_type,
                "contained_bases": contained, "mdisp": reader.uint(descriptor + 8, signed=True),
                "pdisp": reader.uint(descriptor + 12, signed=True),
                "vdisp": reader.uint(descriptor + 16, signed=True),
                "attributes": reader.uint(descriptor + 20)}
        if active:
            edges.append({"derived_index": active[-1][0], "base_index": index,
                          "evidence": "BaseClassArray preorder and numContainedBases"})
        bases.append(base)
        if contained:
            active.append((index, index + contained))
    return {"abi": "msvc", "type": main_type,
            "complete_object_locator": {"ea": hex(col), "signature": signature, "offset": offset,
                                        "constructor_displacement": cd_offset,
                                        "image_base": hex(reader.imagebase) if reader.ptrsize == 8 else None},
            "class_hierarchy": {"ea": hex(hierarchy), "attributes": attributes,
                                "base_count": count, "base_array": hex(array)},
            "bases": bases, "inheritance_edges": edges, "parse_errors": [],
            "truncated": count > max_bases}


def _itanium_type(reader, ea, max_bases, depth=0, seen=frozenset()):
    if ea in seen:
        raise RTTIError("RTTI inheritance contains a pointer cycle")
    if depth > reader.budget.limits["depth"]:
        raise RTTIError("RTTI inheritance exceeds the recursion depth limit")
    reader.budget.consume("type_nodes")
    seen = seen | {ea}
    vptr, name_ptr = reader.pointer(ea), reader.pointer(ea + reader.ptrsize)
    raw = reader.string(name_ptr)
    if not raw or not re.match(r"\*?(?:[1-9][0-9]*[A-Za-z_]|N|Z)", raw):
        raise RTTIError("typeinfo name has no recognized ABI encoding")
    if not reader.mapped(vptr):
        raise RTTIError("typeinfo runtime vtable pointer is outside mapped ranges")
    names = (reader.symbol(vptr), reader.symbol(vptr - 2 * reader.ptrsize))
    vptr_name = next((name for name in names if any(kind in name for kind in
                     ("__class_type_info", "__si_class_type_info", "__vmi_class_type_info"))), "")
    result = {"ea": hex(ea), "raw_name": raw, "name": reader.display(raw, "itanium"),
              "vptr": hex(vptr), "vptr_symbol": vptr_name or None, "bases": [], "kind": "unknown"}
    if "__vmi_class_type_info" in vptr_name:
        result["kind"] = "vmi-class"
        result["flags"] = reader.uint(ea + 2 * reader.ptrsize)
        count = reader.uint(ea + 2 * reader.ptrsize + 4)
        if count > 4096:
            raise RTTIError("typeinfo base count exceeds the parser limit")
        result["base_count"] = count
        result["truncated"] = count > max_bases
        start = ea + 2 * reader.ptrsize + 8
        for index in range(min(count, max_bases)):
            entry = start + index * reader.ptrsize * 2
            base_ea = reader.pointer(entry)
            offset_flags = reader.uint(entry + reader.ptrsize, reader.ptrsize, signed=True)
            if offset_flags & 0xfc:
                raise RTTIError("typeinfo base flags contain unsupported reserved bits")
            base_type = _itanium_type(reader, base_ea, max_bases, depth + 1, seen)
            result["bases"].append({"type": base_type, "offset": offset_flags >> 8,
                                    "virtual": bool(offset_flags & 1), "public": bool(offset_flags & 2),
                                    "offset_basis": "vtable vbase-offset entry" if offset_flags & 1 else "object bytes",
                                    "evidence": "__vmi_class_type_info base_info"})
    elif "__si_class_type_info" in vptr_name:
        result["kind"] = "si-class"
        base_ea = reader.pointer(ea + 2 * reader.ptrsize)
        base_type = _itanium_type(reader, base_ea, max_bases, depth + 1, seen)
        result["bases"].append({"type": base_type, "offset": 0, "virtual": False, "public": True,
                                "evidence": "__si_class_type_info single public nonvirtual base"})
    elif "__class_type_info" in vptr_name:
        result["kind"] = "class"
    else:
        result["note"] = "Runtime typeinfo variant is unidentified; inheritance layout was not inferred."
    return result


def _itanium_rtti(reader, address_point, max_bases):
    offset = reader.uint(address_point - 2 * reader.ptrsize, reader.ptrsize, signed=True)
    if abs(offset) > 0x10000000:
        raise RTTIError("vtable offset-to-top exceeds the supported object displacement")
    type_ea = reader.pointer(address_point - reader.ptrsize)
    info = _itanium_type(reader, type_ea, max_bases)
    if info["kind"] == "unknown" and not (reader.symbol(address_point - 2 * reader.ptrsize).startswith("_ZTV")
            or reader.symbol(type_ea).startswith("_ZTI")):
        raise RTTIError("unnamed typeinfo has no identifiable runtime RTTI variant")
    return {"abi": "itanium", "offset_to_top": offset, "type": info, "bases": info["bases"],
            "truncated": _type_truncated(info), "evidence": "offset-to-top/typeinfo/address-point ABI header"}


def _type_truncated(info):
    return bool(info.get("truncated") or any(_type_truncated(item["type"]) for item in info.get("bases", [])))


def _vtable_at(reader, ea, abi, max_slots, max_bases):
    reader.budget.consume("candidates")
    symbol = reader.symbol(ea)
    input_ea = ea
    named_header = symbol.startswith("_ZTV")
    errors, rtti = [], None
    points = range(2, 34) if named_header else (0,)
    prefix_words = 0
    for words in points:
        point = input_ea + words * reader.ptrsize
        if point > reader.address_max:
            break
        if named_header:
            # Virtual bases may put vbase/vcall offsets before the two ABI
            # header words. A prefix is accepted only when the complete RTTI
            # header and the first executable slot validate at that point.
            if abi == "msvc":
                errors.append({"abi": "msvc", "error": "Itanium _ZTV symbol conflicts with requested MSVC ABI"})
                break
            try:
                if not reader.executable(reader.uint(point, reader.ptrsize)):
                    continue
            except BudgetExceeded:
                raise
            except RTTIError:
                continue
        for label, parser in (("msvc", _msvc_rtti), ("itanium", _itanium_rtti)):
            if abi not in ("auto", label) or (named_header and label != "itanium"):
                continue
            try:
                rtti = parser(reader, point, max_bases)
                ea = point
                prefix_words = words - 2 if named_header else 0
                break
            except BudgetExceeded:
                raise
            except RTTIError as error:
                errors.append({"abi": label, "error": str(error)})
        if rtti is not None:
            break
    if rtti is None:
        return {"ok": False, "ea": hex(ea), "symbol": symbol or None, "rtti": None,
                "slots": [], "errors": errors,
                "note": "No supported RTTI header was validated; named Itanium prefixes are bounded to 32 candidates and RTTI-disabled tables are not asserted as classes."}
    slots, stop_reason = [], "slot limit"
    for index in range(max_slots):
        slot_ea = ea + index * reader.ptrsize
        try:
            target = reader.uint(slot_ea, reader.ptrsize)
        except BudgetExceeded:
            raise
        except RTTIError:
            stop_reason = "unreadable slot"
            break
        if not reader.executable(target):
            stop_reason = "next slot is not an executable address"
            break
        slots.append({"index": index, "offset": index * reader.ptrsize, "ea": hex(slot_ea),
                      "target": hex(target), "name": reader.symbol(target)})
    if not slots:
        return {"ok": False, "ea": hex(ea), "symbol": symbol or None, "rtti": rtti,
                "slots": [], "error": "RTTI was parsed but no executable virtual-function slot was found"}
    declaration = "struct IG5_vftable_" + format(ea, "x") + " {\n" + "\n".join(
        "    void (*slot_%03d)(void); /* +0x%x -> %s */" % (slot["index"], slot["offset"], slot["target"])
        for slot in slots) + "\n};"
    return {"ok": True, "ea": hex(ea), "input_ea": hex(input_ea),
            "header_prefix_words": prefix_words if named_header else None,
            "symbol": symbol or reader.symbol(ea) or None,
            "pointer_size": reader.ptrsize, "rtti": rtti, "slots": slots, "slot_count": len(slots),
            "struct_decl": declaration, "signature_note": "Slot prototypes are placeholders; argument and return types are not inferred.",
            "truncated": len(slots) == max_slots or bool(rtti.get("truncated")), "stop_reason": stop_reason}


def analyze_vtables(provider, params=None, *, limits=None):
    """Recover ABI-backed virtual tables within shared read/scan/node budgets.

    ``ea`` or ``name`` selects one table. An optional ``offset`` is a byte
    displacement in that table. Discovery considers symbol evidence first and
    then aligned pointers in readable, non-executable provider ranges. Results
    are read-only. The caller adds its actual upstream provider/engine identity.
    """
    params = {} if params is None else params
    if not isinstance(params, dict):
        raise ValueError("params must be an object")
    abi = str(params.get("abi", "auto")).lower()
    if abi not in ("auto", "msvc", "itanium"):
        raise ValueError("abi must be auto, msvc, or itanium")
    max_slots = _limit(params, "max_slots", 128, 4096)
    max_bases = _limit(params, "max_bases", 128, 1024)
    limit = _limit(params, "limit", 64, 512)
    max_scan = _limit(params, "max_scan_bytes", 8 * 1024 * 1024, 64 * 1024 * 1024)
    budget = _Budget(limits)
    reader = _Reader(provider, budget)
    explicit = params.get("ea") is not None or bool(params.get("name"))
    if params.get("ea") is not None and params.get("name"):
        raise ValueError("specify ea or name, not both")
    if params.get("offset") is not None and not explicit:
        raise ValueError("offset resolution requires an explicit vtable ea or name")
    result = {"implementation": "ig5-kernel", "abi": abi, "tables": [], "total": 0,
              "scanned_bytes": 0, "names_examined": 0, "truncated": False,
              "analysis_note": "Counts cover validated RTTI-backed tables within the scan limits, not every class in the binary."}
    if explicit:
        if params.get("ea") is not None:
            ea = _integer(params["ea"], "ea", 0, reader.address_max)
        else:
            name = str(params["name"])
            resolve = getattr(provider, "resolve_symbol", None)
            if not callable(resolve) or not name or len(name) > 4096:
                raise ValueError("named table lookup requires a provider resolve_symbol method")
            ea = _integer(resolve(name), "resolved ea", 0, reader.address_max)
        offset = None
        if params.get("offset") is not None:
            offset = _integer(params["offset"], "offset", 0, reader.ptrsize * 4096)
            if offset % reader.ptrsize:
                raise ValueError("offset must be aligned to the target pointer size")
        try:
            table = _vtable_at(reader, ea, abi, max_slots, max_bases)
        except BudgetExceeded as error:
            table = {"ok": False, "ea": hex(ea), "rtti": None, "slots": [], "error": str(error)}
            result["truncated"] = True
        if offset is not None:
            table["selected_slot"] = next((slot for slot in table["slots"] if slot["offset"] == offset), None)
            if table["selected_slot"] is None:
                table["selection_error"] = "offset does not identify a recovered executable slot"
        result.update({"ok": table["ok"], "tables": [table] if table["ok"] else [],
                       "total": int(table["ok"]), "requested": table})
        result["truncated"] = result["truncated"] or bool(table.get("truncated"))
        result["budget"] = budget.report()
        return result

    seen = set()
    scan_errors = []
    exhausted_scan = False
    names_limited = False
    try:
        symbols = getattr(provider, "symbols", None)
        if symbols is not None:
            source = symbols() if callable(symbols) else symbols
            for item in source:
                if result["names_examined"] >= budget.limits["symbols"]:
                    names_limited = True
                    break
                result["names_examined"] += 1
                if not isinstance(item, (tuple, list)) or len(item) != 2:
                    raise ValueError("provider symbols must yield (ea, name) pairs")
                ea, name = item
                if not str(name).startswith(("??_7", "_ZTV")):
                    continue
                ea = _integer(ea, "symbol ea", 0, reader.address_max)
                point = ea + 2 * reader.ptrsize if reader.symbol(ea).startswith("_ZTV") else ea
                if point in seen:
                    continue
                table = _vtable_at(reader, ea, abi, max_slots, max_bases)
                if table["ok"]:
                    seen.add(int(table["ea"], 16))
                    result["tables"].append(table)
                if len(result["tables"]) >= limit:
                    break
        for region in reader.ranges:
            if len(result["tables"]) >= limit:
                break
            if not region.readable or region.executable:
                continue
            start = (region.start + reader.ptrsize - 1) // reader.ptrsize * reader.ptrsize
            end = region.end - (region.end - start) % reader.ptrsize
            while start < end and len(result["tables"]) < limit:
                remaining = max_scan - result["scanned_bytes"]
                size = min(65536, end - start, remaining)
                size -= size % reader.ptrsize
                if size == 0:
                    exhausted_scan = True
                    break
                result["scanned_bytes"] += size
                try:
                    data = reader.read(start, size)
                except BudgetExceeded:
                    raise
                except RTTIError as error:
                    if len(scan_errors) < 32:
                        scan_errors.append({"ea": hex(start), "size": size, "error": str(error)})
                    start += size
                    continue
                for offset in range(0, size, reader.ptrsize):
                    target = int.from_bytes(data[offset:offset + reader.ptrsize], reader.order)
                    ea = start + offset
                    if ea in seen or not reader.executable(target):
                        continue
                    table = _vtable_at(reader, ea, abi, max_slots, max_bases)
                    if table["ok"]:
                        seen.add(int(table["ea"], 16))
                        result["tables"].append(table)
                    if len(result["tables"]) >= limit:
                        break
                start += size
            if exhausted_scan:
                break
    except BudgetExceeded as error:
        result["budget_error"] = str(error)
    result["ok"] = True
    result["total"] = len(result["tables"])
    result["truncated"] = bool(budget.exhausted or names_limited or exhausted_scan
                                or len(result["tables"]) >= limit or scan_errors
                                or any(table["truncated"] for table in result["tables"]))
    if scan_errors:
        result["scan_errors"] = scan_errors
    result["budget"] = budget.report()
    return result
