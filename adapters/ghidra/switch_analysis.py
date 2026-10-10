"""Bounded Ghidra switch evidence and explicit, host-gated jump overrides.

No engine is imported until an operation needs it.  Ghidra's BasicOverride stores
destinations, not a user's case labels or a separately classified default edge.
The worker remains the only transaction, revision, and persistence owner.
"""


def _integer(value, key, minimum, maximum):
    if isinstance(value, bool) or isinstance(value, float):
        raise ValueError(key + ' must be an integer')
    try:
        parsed = int(value, 0) if isinstance(value, str) and value.lower().startswith(('0x', '-0x')) else int(value)
    except (ValueError, TypeError, OverflowError) as error:
        raise ValueError(key + ' must be an integer') from error
    if parsed < minimum or parsed > maximum:
        raise ValueError(key + ' is outside the supported range')
    return parsed


def _boolean(params, key, default=False):
    value = params.get(key, default)
    if not isinstance(value, bool):
        raise ValueError(key + ' must be a boolean')
    return value


def _precise_integer(value):
    # JSON consumers use doubles; large user-specified case indices must not
    # silently change while travelling through the host and workbench.
    return value if -(1 << 53) < value < 1 << 53 else str(value)


def _address_text(address):
    if not address.getAddressSpace().isMemorySpace():
        return str(address)
    return '0x' + (str(address.toString(False)).lstrip('0') or '0')


def _address_number(address):
    space = address.getAddressSpace()
    if not space.isMemorySpace():
        raise ValueError('switch addresses must identify loaded memory')
    return int(address.getOffset()) & ((1 << int(space.getSize())) - 1)


def _table_record(table, max_cases):
    addresses = table.getCases()
    labels = table.getLabelValues()
    # Java JumpTable.decode omits the label entry for an unlabelled destination,
    # rather than inserting null.  Zipping unequal arrays would shift labels.
    mapped = len(addresses) == len(labels)
    count = min(len(addresses), max_cases)
    cases = [{'target': _address_text(addresses[index]),
              'values': [int(labels[index])] if mapped else [],
              'labelKnown': mapped} for index in range(count)]
    loads = table.getLoadTables()
    return {'ea': _address_text(table.getSwitchAddress()), 'ncases': len(addresses),
            'cases': cases, 'labelValues': [int(labels[index]) for index in range(min(len(labels), max_cases))],
            'labelsMapped': mapped, 'labelBits': 32, 'labelSignedness': 'unknown',
            'labelPrecision': 'Ghidra Java Integer view; original 64-bit case values may be truncated',
            'default': None, 'defaultUnknown': True,
            'loadTables': [{'ea': _address_text(loads[index].getAddress()),
                            'element_size': int(loads[index].getSize()),
                            'table_entries': int(loads[index].getNum())} for index in range(min(len(loads), 32))],
            'loadTablesTruncated': len(loads) > 32,
            'truncated': len(addresses) > max_cases or len(labels) > max_cases,
            'source': 'Ghidra HighFunction.getJumpTables',
            'note': 'The Java API does not expose a reliable separately classified default branch.'}


def _jump_tables(worker, params):
    function, result = worker.decompile(params)
    high = result.getHighFunction()
    if high is None:
        raise ValueError('Ghidra decompilation did not return a HighFunction')
    return function, high.getJumpTables()


def read_switches(worker, params):
    """Read the containing function's real decompiler jump-table metadata."""
    worker.require()
    exact = _boolean(params, 'exact')
    limit = _integer(params.get('limit', 128), 'limit', 1, 1024)
    max_cases = _integer(params.get('max_cases', 2048), 'max_cases', 1, 65535)
    address = worker.address(params)
    function, tables = _jump_tables(worker, params)
    selected = [table for table in tables if not exact or table.getSwitchAddress() == address]
    records = []
    remaining = max_cases
    for table in selected[:limit]:
        record = _table_record(table, remaining)
        records.append(record)
        remaining -= len(record['cases'])
    return {'ok': True, 'engine': 'Ghidra', 'ea': _address_text(address),
            'func': str(function.getName()), 'functionEa': _address_text(function.getEntryPoint()),
            'total': len(selected), 'switches': records,
            'truncated': len(selected) > limit or any(record['truncated'] for record in records),
            'revision': worker.revision, 'caseBudget': max_cases,
            'caseBudgetScope': 'all returned switch tables combined',
            'defaultClassification': 'unavailable in the Java JumpTable API'}


def _memory_address(worker, value, key):
    if value in (None, ''):
        raise ValueError(key + ' is required')
    address = worker.address({'ea': value})
    default_space = worker.program.getAddressFactory().getDefaultAddressSpace()
    if address.getAddressSpace() != default_space or not default_space.isMemorySpace():
        raise ValueError(key + ' must be in the default memory address space')
    return address


def _target_from_number(worker, value, space):
    if value < 0 or value >= 1 << int(space.getSize()):
        raise ValueError('jump-table target arithmetic overflows the address space')
    address = worker.program.getAddressFactory().getAddress(format(value, 'x'))
    if address is None or address.getAddressSpace() != space:
        raise ValueError('jump-table target is outside the default address space')
    return address


def _validate_target(worker, target):
    block = worker.program.getMemory().getBlock(target)
    if block is None or not block.isExecute() or not block.isInitialized():
        raise ValueError('switch target ' + _address_text(target) + ' is outside initialized executable memory')
    if worker.program.getListing().getInstructionAt(target) is None:
        raise ValueError('switch target ' + _address_text(target) + ' must identify an existing instruction')


def repair_switch(worker, params):
    """Preview, or commit a validated destination override through worker.commit.

    The host's normal ig5_switch_repair approval gate is mandatory for apply.
    This internal worker adapter neither acquires nor bypasses approval.
    """
    worker.require()
    apply = _boolean(params, 'apply')
    if _boolean(params, 'create_instructions'):
        raise ValueError('Ghidra switch repair requires existing destination instructions; create_instructions is unsupported')
    action = str(params.get('action', 'rebuild'))
    if action not in ('rebuild', 'define'):
        raise ValueError('action must be rebuild or define')
    address = _memory_address(worker, params.get('ea'), 'ea')
    function = worker.function({'ea': _address_text(address)})
    instruction = worker.program.getListing().getInstructionAt(address)
    if instruction is None or not instruction.getFlowType().isJump() or not instruction.getFlowType().isComputed():
        raise ValueError('switch ea must identify an existing computed jump instruction')
    _validate_target(worker, address)
    source = {'ea': _address_text(address), 'default': None, 'defaultUnknown': True}
    if action == 'rebuild':
        _, tables = _jump_tables(worker, {'ea': _address_text(address), **({'timeout': params['timeout']} if 'timeout' in params else {})})
        matching = [table for table in tables if table.getSwitchAddress() == address]
        if len(matching) != 1:
            raise ValueError('one recognized switch is required at ea; use define with an explicit table layout')
        source = _table_record(matching[0], 4096)
        if source['truncated']:
            raise ValueError('recognized switch exceeds the repair destination budget')
        destinations = list(matching[0].getCases())
    else:
        table = _memory_address(worker, params.get('table') if params.get('table') is not None else params.get('jumps'), 'table')
        count = _integer(params.get('ncases'), 'ncases', 1, 4096)
        width = _integer(params.get('element_size'), 'element_size', 1, 8)
        if width not in (1, 2, 4, 8):
            raise ValueError('element_size must be 1, 2, 4, or 8')
        lowcase = _integer(params.get('lowcase', 0), 'lowcase', -(1 << 63), (1 << 63) - 1)
        shift = _integer(params.get('shift', 0), 'shift', 0, 3)
        signed = _boolean(params, 'signed')
        relative = _boolean(params, 'relative')
        subtract = _boolean(params, 'subtract')
        base_value = params.get('elbase') if params.get('elbase') is not None else params.get('relative_base')
        if (relative or subtract) and base_value is None:
            raise ValueError('relative or subtract tables require an explicit elbase')
        base = _address_number(_memory_address(worker, base_value, 'elbase')) if base_value is not None else 0
        bits = int(table.getAddressSpace().getSize())
        if _address_number(table) + count * width > 1 << bits:
            raise ValueError('the complete jump table overflows the address space')
        raw = worker.read_bytes(table, count * width)
        if len(raw) != count * width:
            raise ValueError('the complete jump table must contain readable database bytes')
        order = 'big' if worker.program.getLanguage().isBigEndian() else 'little'
        destinations = []
        cases = []
        for index in range(count):
            entry = int.from_bytes(raw[index * width:(index + 1) * width], order, signed=signed) << shift
            target = _target_from_number(worker, base - entry if subtract else base + entry, table.getAddressSpace())
            destinations.append(target)
            # These values are the user's requested layout, not recovered labels.
            cases.append({'target': _address_text(target), 'requestedValues': [_precise_integer(lowcase + index)]})
        source = {**source, 'jumps': _address_text(table), 'ncases': count, 'element_size': width,
                  'lowcase': _precise_integer(lowcase), 'shift': shift, 'signed': signed, 'byteOrder': order,
                  'elbase': _address_text(_memory_address(worker, base_value, 'elbase')) if base_value is not None else None,
                  'cases': cases, 'source': 'explicit direct-table bytes'}
        default_value = params.get('default') if params.get('default') is not None else params.get('default_ea')
        if default_value is not None:
            default = _memory_address(worker, default_value, 'default')
            destinations.append(default)
            source['requestedDefault'] = _address_text(default)
    if not destinations:
        raise ValueError('the switch layout yields no destinations')
    unique = []
    seen = set()
    for target in destinations:
        _validate_target(worker, target)
        text = _address_text(target)
        if text not in seen:
            seen.add(text)
            unique.append(target)
    preview = {'ok': True, 'engine': 'Ghidra', 'action': action, 'applied': False,
               'ea': _address_text(address), 'switch': source,
               'targets': [_address_text(target) for target in unique], 'created_instructions': [],
               'labelsPersisted': False, 'defaultMetadataPersisted': False,
               'overrideKind': 'destination-set', 'revision': worker.revision,
               'note': 'BasicOverride stores validated destinations; decompiler recovery determines case values. '
                       'A requested default is an additional destination, not a persisted default classification.'}
    if not apply:
        return preview
    from java.util import ArrayList
    from ghidra.program.model.pcode import JumpTable
    from ghidra.program.model.symbol import RefType, SourceType
    from ghidra.app.cmd.function import CreateFunctionCmd

    def write():
        native_destinations = ArrayList()
        for target in unique:
            native_destinations.add(target)
        JumpTable(address, native_destinations, True, 0).writeOverride(function)
        removed = []
        for reference in instruction.getReferencesFrom():
            kind = reference.getReferenceType()
            if kind.isJump() and kind.isComputed() and _address_text(reference.getToAddress()) not in seen:
                removed.append(_address_text(reference.getToAddress()))
                worker.program.getReferenceManager().delete(reference)
        for target in unique:
            existing = instruction.getReferencesFrom()
            if not any(reference.getToAddress() == target and reference.getReferenceType().isJump()
                       and reference.getReferenceType().isComputed()
                       for reference in existing):
                instruction.addOperandReference(0, target, RefType.COMPUTED_JUMP, SourceType.USER_DEFINED)
        CreateFunctionCmd.fixupFunctionBody(worker.program, function, worker.monitor(params))
        return {**preview, 'applied': True, 'referencesAddedOrPresent': len(unique),
                'removedStaleComputedJumpReferences': removed,
                'undoScope': 'worker native session undo; expires at save/close'}

    return worker.commit('switch_repair', params, write)
