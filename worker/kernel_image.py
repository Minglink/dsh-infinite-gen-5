"""Independent, bounded PE/ELF loader for the IG5 analysis kernel.

Only a format's initialized bytes and explicit loader zero-fill are readable.
File overlays, alignment gaps and unallocated sections are never invented as
memory. Addresses remain Python integers internally and hexadecimal strings in
describe(). No vendor engine, Java process or executable sample is loaded.
"""
from bisect import bisect_right
from dataclasses import dataclass
import hashlib
import os
import stat
import struct


DEFAULT_MAX_BYTES = 64 * 1024 * 1024
MAX_HEADERS = 4096
PERM_READ, PERM_WRITE, PERM_EXEC = 1, 2, 4


class ImageFormatError(ValueError):
    """The input is unsupported, malformed, ambiguous or exceeds a bound."""


def _integer(value, label):
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        raise ImageFormatError(label + ' must be an integer or integer string')
    try:
        result = int(value, 0) if isinstance(value, str) else value
    except ValueError as exc:
        raise ImageFormatError(label + ' is not a valid integer') from exc
    return result


def _power_two(value):
    return value > 0 and value & (value - 1) == 0


def _range(start, size, limit, label):
    if start < 0 or size < 0 or start > limit or size > limit - start:
        raise ImageFormatError(label + ' is truncated or outside its address space')
    return start + size


def _disjoint(ranges, label):
    end = -1
    for start, size in sorted((s, n) for s, n in ranges if n):
        if start < end:
            raise ImageFormatError(label + ' overlap and are ambiguous')
        end = start + size


def _wire_numbers(value):
    """Keep unusually wide lengths/flags exact for a JavaScript JSON consumer."""
    if isinstance(value, int) and not isinstance(value, bool):
        return value if -(2 ** 53 - 1) <= value <= 2 ** 53 - 1 else hex(value)
    if isinstance(value, dict):
        return {key: _wire_numbers(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_wire_numbers(item) for item in value]
    return value


def _snapshot_identity(metadata):
    # Both snapshots are taken from the same open descriptor. Windows Python
    # 3.12 introduces birthtime; do not mix path stat's historical creation-time
    # ctime with fstat's newer change-time ctime semantics.
    birth = getattr(metadata, 'st_birthtime_ns', None) if os.name == 'nt' else None
    origin = birth if birth is not None else metadata.st_ctime_ns
    return (metadata.st_dev, metadata.st_ino, metadata.st_size,
            metadata.st_mtime_ns, origin)


@dataclass(frozen=True)
class BinaryRegion:
    """An immutable memory mapping; data is its file-backed prefix only.

    size may exceed len(data): that tail is defined zero-fill, not missing file
    data. permissions uses R=1, W=2, X=4. A permission of 0 is explicit.
    """
    name: str
    start: int
    size: int
    data: bytes
    permissions: int
    file_offset: int = 0

    @property
    def end(self):
        return self.start + self.size

    @property
    def file_size(self):
        return len(self.data)

    @property
    def zero_fill(self):
        return self.size > len(self.data)

    def describe(self):
        return {'name': self.name, 'start': hex(self.start), 'end': hex(self.end),
                'size': self.size, 'fileOffset': self.file_offset,
                'fileSize': self.file_size, 'zeroFillBytes': self.size - self.file_size,
                'permissions': self.permissions,
                'permissionNames': ''.join(c for bit, c in ((1, 'R'), (2, 'W'), (4, 'X'))
                                          if self.permissions & bit)}


class BinaryImage:
    """Preferred virtual-address snapshot; relocations/imports are not applied.

    PE sections and ELF PT_LOAD segments are the actual memory mappings.
    Uninitialized memory is lazy, so a large BSS never causes a large allocation
    on open. Every read has the same byte budget as the input file by default.
    """
    @classmethod
    def from_file(cls, path, max_bytes=DEFAULT_MAX_BYTES):
        budget = cls._budget(max_bytes)
        flags = os.O_RDONLY | getattr(os, 'O_BINARY', 0) | getattr(os, 'O_NONBLOCK', 0)
        fd = os.open(os.fspath(path), flags)
        try:
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode):
                raise ImageFormatError('binary input must be a regular file')
            if before.st_size > budget:
                raise ImageFormatError('binary input exceeds its byte budget')
            chunks, remaining = [], before.st_size
            while remaining:
                chunk = os.read(fd, min(remaining, 1024 * 1024))
                if not chunk:
                    raise ImageFormatError('binary input changed or was truncated during read')
                chunks.append(chunk)
                remaining -= len(chunk)
            if os.read(fd, 1):
                raise ImageFormatError('binary input grew during read')
            after = os.fstat(fd)
            if _snapshot_identity(before) != _snapshot_identity(after):
                raise ImageFormatError('binary input changed during read')
        finally:
            os.close(fd)
        return cls.from_bytes(b''.join(chunks), name=os.fspath(path), max_bytes=budget)

    @staticmethod
    def _budget(value):
        value = _integer(value, 'byte budget')
        if not 1 <= value <= DEFAULT_MAX_BYTES:
            raise ImageFormatError('byte budget must be in 1..64 MiB')
        return value

    @classmethod
    def from_bytes(cls, data, name='<memory>', max_bytes=DEFAULT_MAX_BYTES):
        budget = cls._budget(max_bytes)
        if not isinstance(data, bytes):
            raise ImageFormatError('binary input must be immutable bytes')
        if len(data) > budget:
            raise ImageFormatError('binary input exceeds its byte budget')
        self = cls.__new__(cls)
        self.path, self._blob, self.max_bytes = str(name), data, budget
        self.sha256 = hashlib.sha256(data).hexdigest()
        self.sections, self.segments, self.data_directories = (), (), ()
        self.endianness, self.entrypoint = 'little', None
        self.machine, self.object_type = None, None
        if data[:2] == b'MZ':
            self._parse_pe()
        elif data[:4] == b'\x7fELF':
            self._parse_elf()
        else:
            raise ImageFormatError('unsupported binary format: expected PE or ELF')
        self.byteorder = self.endianness
        self.regions = tuple(sorted(self.regions, key=lambda r: r.start))
        if not self.regions or len(self.regions) > MAX_HEADERS + 1:
            raise ImageFormatError('binary has no supported loaded regions')
        _disjoint(((r.start, r.size) for r in self.regions), 'loaded virtual regions')
        self._starts = tuple(r.start for r in self.regions)
        if self.entrypoint is not None:
            region = self._region_at(self.entrypoint)
            if region is None or not region.permissions & PERM_EXEC:
                raise ImageFormatError('entry point is not in executable loaded memory')
            if self.entrypoint - region.start >= len(region.data):
                raise ImageFormatError('entry point is not backed by initialized bytes')
        ranges = [(r.file_offset, len(r.data)) for r in self.regions if r.data]
        merged = []
        for start, size in sorted(ranges):
            end = start + size
            if merged and start <= merged[-1][1]:
                merged[-1] = (merged[-1][0], max(merged[-1][1], end))
            else:
                merged.append((start, end))
        self.unmapped_file_bytes = len(data) - sum(end - start for start, end in merged)
        return self

    def _unpack(self, fmt, offset, label):
        size = struct.calcsize(fmt)
        _range(offset, size, len(self._blob), label)
        return struct.unpack_from(fmt, self._blob, offset)

    def _file(self, offset, size, label):
        end = _range(offset, size, len(self._blob), label)
        return self._blob[offset:end]

    def _region_at(self, address):
        index = bisect_right(self._starts, address) - 1
        if index >= 0 and address < self.regions[index].end:
            return self.regions[index]
        return None

    def _covered(self, address, size, initialized=False, file_offset=None):
        end = _range(address, size, 1 << self.bits, 'virtual range')
        if not size:
            return self._region_at(address) is not None
        cursor = address
        while cursor < end:
            region = self._region_at(cursor)
            if region is None:
                return False
            stop = min(end, region.end)
            if initialized and stop > region.start + len(region.data):
                return False
            if file_offset is not None and (region.file_offset + cursor - region.start
                                            != file_offset + cursor - address):
                return False
            cursor = stop
        return True

    def read(self, ea, size):
        ea, size = _integer(ea, 'address'), _integer(size, 'read size')
        if size < 0 or size > self.max_bytes:
            raise ImageFormatError('read exceeds its byte budget')
        if not 0 <= ea < 1 << self.bits:
            raise ImageFormatError('read address is outside target address space')
        end = _range(ea, size, 1 << self.bits, 'read range')
        if not size:
            return b''
        if not self._covered(ea, size):
            raise ImageFormatError('read crosses unmapped memory')
        parts, cursor = [], ea
        while cursor < end:
            region = self._region_at(cursor)
            stop = min(end, region.end)
            offset, count = cursor - region.start, stop - cursor
            backed = max(0, min(count, len(region.data) - offset))
            if backed:
                parts.append(region.data[offset:offset + backed])
            if count > backed:
                parts.append(b'\x00' * (count - backed))
            cursor = stop
        return b''.join(parts)

    def describe(self):
        return _wire_numbers({'format': self.format, 'bits': self.bits,
                'architecture': self.architecture, 'machine': self.machine,
                'endianness': self.endianness, 'byteorder': self.byteorder,
                'objectType': self.object_type,
                'imagebase': hex(self.imagebase),
                'entrypoint': hex(self.entrypoint) if self.entrypoint is not None else None,
                'fileBytes': len(self._blob), 'sha256': self.sha256,
                'mappedBytes': sum(r.size for r in self.regions),
                'unmappedFileBytes': self.unmapped_file_bytes,
                'addressModel': 'preferred-virtual-addresses',
                'relocationsApplied': False, 'importsResolved': False,
                'regions': [r.describe() for r in self.regions],
                'sections': [dict(s) for s in self.sections],
                'segments': [dict(s) for s in self.segments],
                'dataDirectories': [dict(d) for d in self.data_directories]})

    def _parse_pe(self):
        self.format = 'PE'
        (peoff,) = self._unpack('<I', 0x3c, 'DOS header')
        if peoff < 0x40 or self._file(peoff, 4, 'PE signature') != b'PE\0\0':
            raise ImageFormatError('invalid PE signature pointer')
        machine, count, _, _, _, optional_size, _ = self._unpack('<HHIIIHH', peoff + 4, 'COFF header')
        if not 1 <= count <= MAX_HEADERS:
            raise ImageFormatError('PE section count exceeds its bound')
        optional = peoff + 24
        optional_end = _range(optional, optional_size, len(self._blob), 'PE optional header')
        (magic,) = self._unpack('<H', optional, 'PE optional header magic')
        if magic == 0x10b:
            self.bits, minimum, directory_offset = 32, 96, 96
            (self.imagebase,) = self._unpack('<I', optional + 28, 'PE image base')
        elif magic == 0x20b:
            self.bits, minimum, directory_offset = 64, 112, 112
            (self.imagebase,) = self._unpack('<Q', optional + 24, 'PE image base')
        else:
            raise ImageFormatError('unsupported PE optional header magic')
        if optional_size < minimum:
            raise ImageFormatError('PE optional header is truncated')
        if self.imagebase % 65536:
            raise ImageFormatError('PE preferred image base must be aligned to 64 KiB')
        self.machine = machine
        arch = {0x14c: ('x86', 32), 0x8664: ('x86', 64),
                0xaa64: ('arm64', 64), 0x1c0: ('arm', 32),
                0x1c2: ('arm', 32), 0x1c4: ('arm', 32),
                0x200: ('ia64', 64)}
        self.architecture = arch.get(machine, ('unknown', self.bits))[0]
        if machine in arch and arch[machine][1] != self.bits:
            raise ImageFormatError('PE machine and optional header bitness disagree')
        (entry,) = self._unpack('<I', optional + 16, 'PE entry point')
        section_alignment, file_alignment = self._unpack('<II', optional + 32, 'PE alignments')
        image_size, headers_size = self._unpack('<II', optional + 56, 'PE image sizes')
        if (not _power_two(section_alignment) or not _power_two(file_alignment)
                or section_alignment < file_alignment
                or (section_alignment < 4096 and section_alignment != file_alignment)
                or (section_alignment >= 4096 and not 512 <= file_alignment <= 65536)):
            raise ImageFormatError('invalid PE file/section alignment')
        section_table = optional_end
        header_end = _range(section_table, count * 40, len(self._blob), 'PE section table')
        if (headers_size < header_end or headers_size > len(self._blob)
                or headers_size % file_alignment or not image_size
                or image_size % section_alignment or image_size < headers_size):
            raise ImageFormatError('invalid PE header/image size')
        _range(self.imagebase, image_size, 1 << self.bits, 'PE image range')
        if entry >= image_size:
            raise ImageFormatError('PE entry point is outside the image')
        self.entrypoint = self.imagebase + entry if entry else None
        regions = [BinaryRegion('headers', self.imagebase, headers_size,
                                self._file(0, headers_size, 'PE mapped headers'), PERM_READ)]
        sections, raw_ranges = [], [(0, headers_size)]
        for index in range(count):
            off = section_table + index * 40
            name_bytes, virtual_size, rva, raw_size, raw_offset, _, _, _, _, flags = self._unpack(
                '<8sIIIIIIHHI', off, 'PE section header')
            name = name_bytes.split(b'\0', 1)[0].decode('latin-1')
            size = max(virtual_size, raw_size)
            if rva % section_alignment or (raw_size and (raw_offset % file_alignment
                                                        or raw_size % file_alignment)):
                raise ImageFormatError('misaligned PE section')
            _range(rva, size, image_size, 'PE section virtual range')
            payload = self._file(raw_offset, raw_size, 'PE section file range') if raw_size else b''
            if not raw_size and raw_offset > len(self._blob):
                raise ImageFormatError('PE empty section file pointer is outside input')
            permissions = ((PERM_READ if flags & 0x40000000 else 0)
                           | (PERM_WRITE if flags & 0x80000000 else 0)
                           | (PERM_EXEC if flags & 0x20000000 else 0))
            start = self.imagebase + rva
            sections.append({'index': index, 'name': name, 'start': hex(start),
                             'size': size, 'virtualSize': virtual_size,
                             'fileOffset': raw_offset, 'fileSize': raw_size,
                             'permissions': permissions, 'flags': flags, 'mapped': bool(size)})
            if size:
                regions.append(BinaryRegion(name, start, size, payload, permissions, raw_offset))
            if raw_size:
                raw_ranges.append((raw_offset, raw_size))
        _disjoint(raw_ranges, 'PE initialized file ranges')
        self.regions, self.sections = tuple(sorted(regions, key=lambda r: r.start)), tuple(sections)
        _disjoint(((r.start, r.size) for r in self.regions), 'PE virtual ranges')
        self._starts = tuple(r.start for r in self.regions)
        (directory_count,) = self._unpack('<I', optional + directory_offset - 4, 'PE directory count')
        if directory_count > MAX_HEADERS or directory_count * 8 > optional_size - directory_offset:
            raise ImageFormatError('PE data directories exceed the optional header')
        directories = []
        for index in range(directory_count):
            pointer, size = self._unpack('<II', optional + directory_offset + index * 8,
                                         'PE data directory')
            if not pointer and size:
                raise ImageFormatError('PE data directory has an invalid null pointer')
            if pointer:
                if index == 4:  # Certificate table is a file offset, never an RVA.
                    _range(pointer, size, len(self._blob), 'PE certificate file range')
                elif not self._covered(self.imagebase + pointer, size):
                    raise ImageFormatError('PE data directory points into unmapped memory')
            directories.append({'index': index, 'addressKind': 'file-offset' if index == 4 else 'rva',
                                'pointer': hex(pointer), 'size': size})
        self.data_directories = tuple(directories)

    def _parse_elf(self):
        self.format = 'ELF'
        ident = self._file(0, 16, 'ELF identification')
        if ident[4] not in (1, 2) or ident[5] not in (1, 2) or ident[6] != 1:
            raise ImageFormatError('unsupported ELF class, byte order or version')
        self.bits = 32 if ident[4] == 1 else 64
        self.endianness = 'little' if ident[5] == 1 else 'big'
        endian = '<' if ident[5] == 1 else '>'
        fmt = endian + ('HHIIIIIHHHHHH' if self.bits == 32 else 'HHIQQQIHHHHHH')
        (kind, machine, version, entry, phoff, shoff, _, ehsize, phentsize,
         phnum, shentsize, shnum, shstrndx) = self._unpack(fmt, 16, 'ELF header')
        header_size, ph_size, sh_size = (52, 32, 40) if self.bits == 32 else (64, 56, 64)
        if version != 1 or ehsize != header_size or kind not in (2, 3):
            raise ImageFormatError('ELF must be an executable/shared image with a valid header')
        self.machine, self.object_type = machine, 'executable' if kind == 2 else 'shared'
        arch = {3: ('x86', 32), 62: ('x86', 64), 40: ('arm', 32),
                183: ('arm64', 64), 8: ('mips', self.bits),
                20: ('ppc', 32), 21: ('ppc', 64), 243: ('riscv', self.bits),
                2: ('sparc', 32), 43: ('sparc', 64), 22: ('s390', self.bits)}
        self.architecture = arch.get(machine, ('unknown', self.bits))[0]
        if machine in arch and arch[machine][1] != self.bits:
            raise ImageFormatError('ELF machine and class bitness disagree')
        section_fmt = endian + ('IIIIIIIIII' if self.bits == 32 else 'IIQQQQIIQQ')
        # Extended numbering lives in section zero. Decode it before sizing tables.
        if (shoff and not shnum) or phnum == 0xffff or shstrndx == 0xffff:
            if not shoff or shentsize != sh_size or shoff < header_size:
                raise ImageFormatError('ELF extended numbering requires section zero')
            zero = self._unpack(section_fmt, shoff, 'ELF extended section zero')
            if zero[1] != 0:
                raise ImageFormatError('ELF section zero must be NULL')
            if not shnum:
                shnum = zero[5]
            if phnum == 0xffff:
                phnum = zero[7]
            if shstrndx == 0xffff:
                shstrndx = zero[6]
        if not 1 <= phnum <= MAX_HEADERS or not 0 <= shnum <= MAX_HEADERS:
            raise ImageFormatError('ELF header table count exceeds its bound')
        if not phoff or phoff < header_size or phentsize != ph_size:
            raise ImageFormatError('ELF program header table is invalid')
        _range(phoff, phnum * ph_size, len(self._blob), 'ELF program header table')
        tables = [(0, header_size), (phoff, phnum * ph_size)]
        if shnum:
            if not shoff or shoff < header_size or shentsize != sh_size:
                raise ImageFormatError('ELF section header table is invalid')
            _range(shoff, shnum * sh_size, len(self._blob), 'ELF section header table')
            tables.append((shoff, shnum * sh_size))
        elif shoff or shstrndx:
            raise ImageFormatError('ELF absent section table has nonzero pointers')
        _disjoint(tables, 'ELF header tables')
        regions, segments, raw_ranges = [], [], []
        for index in range(phnum):
            off = phoff + index * ph_size
            if self.bits == 32:
                ptype, offset, address, physical, filesz, memsz, flags, align = self._unpack(
                    endian + 'IIIIIIII', off, 'ELF program header')
            else:
                ptype, flags, offset, address, physical, filesz, memsz, align = self._unpack(
                    endian + 'IIQQQQQQ', off, 'ELF program header')
            _range(offset, filesz, len(self._blob), 'ELF segment file range')
            _range(address, memsz, 1 << self.bits, 'ELF segment virtual range')
            if align not in (0, 1) and not _power_two(align):
                raise ImageFormatError('invalid ELF segment alignment')
            if ptype == 1 and (filesz > memsz or (align > 1 and address % align != offset % align)):
                raise ImageFormatError('invalid ELF LOAD size or alignment')
            permissions = ((PERM_READ if flags & 4 else 0)
                           | (PERM_WRITE if flags & 2 else 0)
                           | (PERM_EXEC if flags & 1 else 0))
            segments.append({'index': index, 'type': ptype, 'start': hex(address),
                             'physicalAddress': hex(physical), 'size': memsz,
                             'fileOffset': offset, 'fileSize': filesz, 'alignment': align,
                             'permissions': permissions, 'flags': flags,
                             'mapped': ptype == 1 and memsz > 0})
            if ptype == 1 and memsz:
                regions.append(BinaryRegion('LOAD' + str(index), address, memsz,
                                            self._file(offset, filesz, 'ELF LOAD bytes'),
                                            permissions, offset))
                if filesz:
                    raw_ranges.append((offset, filesz))
        if not regions:
            raise ImageFormatError('ELF has no nonempty LOAD segment')
        _disjoint(raw_ranges, 'ELF LOAD file ranges')
        _disjoint(((r.start, r.size) for r in regions), 'ELF LOAD virtual ranges')
        self.regions = tuple(sorted(regions, key=lambda r: r.start))
        self._starts = tuple(r.start for r in self.regions)
        self.imagebase = min(r.start for r in regions)
        self.entrypoint = entry if entry else None
        self.segments = tuple(segments)
        raw_sections = [self._unpack(section_fmt, shoff + i * sh_size, 'ELF section header')
                        for i in range(shnum)]
        if raw_sections and raw_sections[0][1] != 0:
            raise ImageFormatError('ELF section zero must be NULL')
        if shstrndx >= shnum and shstrndx:
            raise ImageFormatError('ELF section-name table index is invalid')
        names = b''
        if shstrndx:
            string_section = raw_sections[shstrndx]
            if string_section[1] != 3:
                raise ImageFormatError('ELF section-name table must be a string table')
            names = self._file(string_section[4], string_section[5], 'ELF section-name bytes')
            if not names or names[0] != 0 or names[-1] != 0:
                raise ImageFormatError('ELF section-name string table is not terminated')
        sections, allocated = [], []
        for index, record in enumerate(raw_sections):
            name_offset, stype, flags, address, offset, size, link, info, align, entsize = record
            if stype == 0:
                sections.append({'index': index, 'name': '', 'type': 0,
                                 'start': hex(address), 'size': 0, 'fileOffset': offset,
                                 'fileSize': 0, 'permissions': 0, 'mapped': False})
                continue
            if link >= shnum and link:
                raise ImageFormatError('ELF section link index is invalid')
            if stype in (4, 9) and info >= shnum:
                raise ImageFormatError('ELF relocation target section index is invalid')
            if align not in (0, 1) and not _power_two(align):
                raise ImageFormatError('invalid ELF section alignment')
            if entsize and size % entsize:
                raise ImageFormatError('ELF section entries do not fit its size')
            if stype != 8:
                _range(offset, size, len(self._blob), 'ELF section file range')
            name = ''
            if name_offset:
                if not names or name_offset >= len(names):
                    raise ImageFormatError('ELF section name pointer is invalid')
                end = names.find(b'\0', name_offset, min(len(names), name_offset + 1025))
                if end < 0:
                    raise ImageFormatError('ELF section name is unterminated or exceeds 1024 bytes')
                name = names[name_offset:end].decode('latin-1')
            is_allocated = bool(flags & 2) and size > 0
            if is_allocated:
                if align > 1 and address % align:
                    raise ImageFormatError('misaligned ELF allocated section')
                if not self._covered(address, size, initialized=stype != 8,
                                     file_offset=offset if stype != 8 else None):
                    raise ImageFormatError('ELF allocated section contradicts LOAD mapping')
                if stype == 8:
                    for region in self.regions:
                        if max(address, region.start) < min(address + size, region.start + len(region.data)):
                            raise ImageFormatError('ELF NOBITS section overlaps initialized memory')
                allocated.append((address, size))
            sections.append({'index': index, 'name': name, 'type': stype,
                             'start': hex(address), 'size': size, 'fileOffset': offset,
                             'fileSize': 0 if stype == 8 else size,
                             'permissions': PERM_READ | (PERM_WRITE if flags & 1 else 0)
                                            | (PERM_EXEC if flags & 4 else 0),
                             'flags': flags, 'mapped': is_allocated, 'alignment': align})
        _disjoint(allocated, 'ELF allocated section ranges')
        self.sections = tuple(sections)
