"""Typed Ghidra p-code views. No text parsing, host-sized integer conversion or IR mixing."""


def unsigned_hex(value, bits=64):
    return hex(int(value) & ((1 << max(1, int(bits))) - 1))


def varnode_view(program, node):
    if node is None:
        return None
    address = node.getAddress()
    space = address.getAddressSpace()
    kind = ('constant' if node.isConstant() else 'register' if node.isRegister() else
            'unique' if node.isUnique() else 'stack' if address.isStackAddress() else 'memory')
    result = {'space': str(space.getName()), 'spaceId': int(space.getSpaceID()),
              'offset': unsigned_hex(node.getOffset(), 64), 'size': int(node.getSize()), 'kind': kind}
    if kind == 'constant':
        # Varnode constants have an independent value width; space width is not
        # a reliable substitute for sizeof(varnode), especially on 32-bit CPUs.
        result['value'] = unsigned_hex(node.getOffset(), 8 * int(node.getSize()))
    if kind == 'stack':
        result['stackOffset'] = int(node.getOffset())
    if kind == 'register':
        register = program.getRegister(address, node.getSize())
        if register is not None:
            result['register'] = str(register.getName())
    if hasattr(node, 'getHigh'):
        high = node.getHigh()
        if high is not None:
            datatype = high.getDataType()
            result['highVariable'] = {'name': str(high.getName()),
                                      'type': str(datatype.getDisplayName()) if datatype is not None else None}
    if hasattr(node, 'getDef'):
        definition = node.getDef()
        if definition is not None:
            sequence = definition.getSeqnum()
            result['definition'] = {'address': str(sequence.getTarget()), 'time': int(sequence.getTime())}
    return result


def operation_view(program, operation, address, raw_index=None, varnode_budget=128):
    sequence = operation.getSeqnum()
    parent = operation.getParent() if hasattr(operation, 'getParent') else None
    output = operation.getOutput()
    total_inputs = int(operation.getNumInputs())
    output_included = output is not None and varnode_budget > 0
    input_count = min(total_inputs, 64, max(0, varnode_budget - int(output_included)))
    text = str(operation)
    row = {'ea': address, 'opcode': str(operation.getMnemonic()), 'opcodeId': int(operation.getOpcode()),
           'text': text[:4096], 'textTruncated': len(text) > 4096,
           'sequence': {'time': int(sequence.getTime()), 'order': int(sequence.getOrder())},
           'output': varnode_view(program, output) if output_included else None,
           'outputOmitted': output is not None and not output_included,
           'inputs': [varnode_view(program, operation.getInput(index)) for index in range(input_count)],
           'totalInputs': total_inputs, 'inputsTruncated': input_count < total_inputs,
           'block': int(parent.getIndex()) if parent is not None else None}
    if raw_index is not None:
        row['instructionIndex'] = raw_index
    if row['opcode'] in ('LOAD', 'STORE') and row['inputs']:
        token = operation.getInput(0)
        space = program.getAddressFactory().getAddressSpace(int(token.getOffset()))
        row['inputs'][0]['role'] = 'address-space'
        row['inputs'][0]['addressSpace'] = str(space.getName()) if space is not None else None
    return row
