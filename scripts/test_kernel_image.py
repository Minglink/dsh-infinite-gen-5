"""Pure-byte PE/ELF loader regression; no external analysis engine is invoked."""
import json
import os
from pathlib import Path
import random
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'worker'))
from kernel_image import BinaryImage, ImageFormatError, PERM_READ, PERM_WRITE, PERM_EXEC


def pe_fixture(bits=64, overlay=b'overlay'):
    peoff, optional = 0x80, 0x98
    optional_size = 240 if bits == 64 else 224
    base = 0x2000000000300000 if bits == 64 else 0x400000
    data = bytearray(0x600)
    data[:2] = b'MZ'
    struct.pack_into('<I', data, 0x3c, peoff)
    data[peoff:peoff + 4] = b'PE\0\0'
    struct.pack_into('<HHIIIHH', data, peoff + 4,
                     0x8664 if bits == 64 else 0x14c, 2, 0, 0, 0, optional_size, 0x22)
    struct.pack_into('<H', data, optional, 0x20b if bits == 64 else 0x10b)
    struct.pack_into('<I', data, optional + 16, 0x1000)
    struct.pack_into('<Q' if bits == 64 else '<I', data,
                     optional + (24 if bits == 64 else 28), base)
    struct.pack_into('<II', data, optional + 32, 0x1000, 0x200)
    struct.pack_into('<II', data, optional + 56, 0x3000, 0x200)
    struct.pack_into('<I', data, optional + (108 if bits == 64 else 92), 16)
    sections = optional + optional_size
    struct.pack_into('<8sIIIIIIHHI', data, sections,
                     b'.text\0\0\0', 0x220, 0x1000, 0x200, 0x200, 0, 0, 0, 0, 0x60000020)
    struct.pack_into('<8sIIIIIIHHI', data, sections + 40,
                     b'.data\0\0\0', 0x400, 0x2000, 0x200, 0x400, 0, 0, 0, 0, 0xc0000040)
    data[0x200:0x400] = b'\xc3' + bytes(i & 255 for i in range(511))
    data[0x400:0x600] = b'DATA' + b'\xa5' * 508
    data.extend(overlay)
    return bytes(data), {'base': base, 'optional': optional, 'sections': sections,
                         'directories': optional + (112 if bits == 64 else 96)}


def elf_fixture(bits=64, byteorder='little', extended=False):
    endian = '<' if byteorder == 'little' else '>'
    base = 0x2000000000500000 if bits == 64 else 0x10000
    ehsize, phsize, shsize = (64, 56, 64) if bits == 64 else (52, 32, 40)
    phoff, shoff, namesoff = ehsize, 0x300, 0x260
    names = b'\0.text\0.data\0.bss\0.shstrtab\0'
    data = bytearray(shoff + 5 * shsize)
    data[:16] = b'\x7fELF' + bytes((2 if bits == 64 else 1, 1 if byteorder == 'little' else 2,
                                     1, 0, 0)) + b'\0' * 7
    machine = (62 if byteorder == 'little' else 183) if bits == 64 else (3 if byteorder == 'little' else 8)
    struct.pack_into(endian + ('HHIQQQIHHHHHH' if bits == 64 else 'HHIIIIIHHHHHH'),
                     data, 16, 2, machine, 1, base + 0x200, phoff, shoff, 0,
                     ehsize, phsize, 0xffff if extended else 2, shsize,
                     0 if extended else 5, 0xffff if extended else 4)
    for index, offset, address, filesz, memsz, flags, align in (
            (0, 0x200, base + 0x200, 0x20, 0x20, 5, 0x20),
            (1, 0x240, base + 0x400, 0x10, 0x40, 6, 0x40)):
        if bits == 64:
            struct.pack_into(endian + 'IIQQQQQQ', data, phoff + index * phsize,
                             1, flags, offset, address, address, filesz, memsz, align)
        else:
            struct.pack_into(endian + 'IIIIIIII', data, phoff + index * phsize,
                             1, offset, address, address, filesz, memsz, flags, align)
    records = [
        (0, 0, 0, 0, 0, 5 if extended else 0, 4 if extended else 0, 2 if extended else 0, 0, 0),
        (1, 1, 6, base + 0x200, 0x200, 0x20, 0, 0, 0x20, 0),
        (7, 1, 3, base + 0x400, 0x240, 0x10, 0, 0, 0x10, 0),
        (13, 8, 3, base + 0x410, 0x250, 0x30, 0, 0, 0x10, 0),
        (18, 3, 0, 0, namesoff, len(names), 0, 0, 1, 0),
    ]
    for index, record in enumerate(records):
        struct.pack_into(endian + ('IIQQQQIIQQ' if bits == 64 else 'IIIIIIIIII'),
                         data, shoff + index * shsize, *record)
    data[0x200:0x220] = b'\xc3' + bytes(range(31))
    data[0x240:0x250] = b'ELF DATA' + b'\x5a' * 8
    data[namesoff:namesoff + len(names)] = names
    return bytes(data), {'base': base, 'phoff': phoff, 'phsize': phsize,
                         'shoff': shoff, 'shsize': shsize, 'endian': endian, 'bits': bits}


def patched(blob, fmt, offset, *values):
    result = bytearray(blob)
    struct.pack_into(fmt, result, offset, *values)
    return bytes(result)


class KernelImageTests(unittest.TestCase):
    def parse_file(self, blob, **kwargs):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'fixture.bin'
            target.write_bytes(blob)
            image = BinaryImage.from_file(target, **kwargs)
            self.assertEqual(target.read_bytes(), blob, 'loader must not mutate source bytes')
            return image

    def rejects(self, blob, **kwargs):
        with self.assertRaises(ImageFormatError):
            self.parse_file(blob, **kwargs)

    def test_pe_32_and_64_real_sections_bss_permissions_overlay(self):
        for bits in (32, 64):
            with self.subTest(bits=bits):
                blob, meta = pe_fixture(bits)
                image = self.parse_file(blob)
                base = meta['base']
                self.assertEqual((image.format, image.bits, image.architecture, image.byteorder),
                                 ('PE', bits, 'x86', 'little'))
                self.assertEqual(image.imagebase, base)
                self.assertEqual(image.entrypoint, base + 0x1000)
                self.assertEqual(image.read(hex(base + 0x2000), 4), b'DATA')
                self.assertEqual(image.read(base + 0x21fe, 4), b'\xa5\xa5\0\0')
                self.assertEqual(image.read(base + 0x2200, 0x200), b'\0' * 0x200)
                self.assertEqual([r.permissions for r in image.regions],
                                 [PERM_READ, PERM_READ | PERM_EXEC, PERM_READ | PERM_WRITE])
                self.assertEqual(image.unmapped_file_bytes, 7)
                self.assertEqual(image.regions[2].data, blob[0x400:0x600])
                self.assertEqual(image.regions[2].size, 0x400)
                for ea in (base + 0x600, base + 0x1500, base + 0x2400):
                    with self.assertRaises(ImageFormatError):
                        image.read(ea, 1)
                with self.assertRaises(ImageFormatError):
                    image.read(base + 0x11ff, 0x1002)
                description = json.loads(json.dumps(image.describe()))
                self.assertEqual(description['imagebase'], hex(base))
                self.assertEqual(description['entrypoint'], hex(base + 0x1000))
                self.assertFalse(description['relocationsApplied'])
                self.assertEqual(description['sections'][1]['start'], hex(base + 0x2000))
                if bits == 64:
                    self.assertGreater(base, 2 ** 53)

    def test_pe_certificate_is_file_offset_and_never_memory(self):
        blob, meta = pe_fixture()
        blob = patched(blob, '<II', meta['directories'] + 4 * 8, 0x600, 7)
        image = self.parse_file(blob)
        self.assertEqual(image.data_directories[4]['addressKind'], 'file-offset')
        self.assertEqual(image.unmapped_file_bytes, 7)
        self.rejects(patched(blob, '<II', meta['directories'] + 4 * 8, len(blob), 1))

    def test_pe_no_entry_zero_sections_and_zero_permissions(self):
        blob, meta = pe_fixture()
        blob = patched(blob, '<I', meta['optional'] + 16, 0)
        blob = patched(blob, '<I', meta['sections'] + 40 + 36, 0)
        image = self.parse_file(blob)
        self.assertIsNone(image.entrypoint)
        self.assertEqual(image.regions[-1].permissions, 0)
        self.assertEqual(image.read(meta['base'] + 0x2000, 4), b'DATA')

    def test_pe_truncations_and_invalid_headers(self):
        blob, meta = pe_fixture()
        for cutoff in (0, 2, 63, 0x3f, 0x83, 0x97, 0xb0, meta['sections'] + 79, 0x1ff, 0x5ff):
            with self.subTest(cutoff=cutoff):
                self.rejects(blob[:cutoff])
        mutations = [('<I', 0x3c, 0xfffffff0), ('<I', 0x3c, 0),
                     ('<H', 0x84, 0x14c), ('<H', 0x86, 0),
                     ('<H', 0x94, 20), ('<H', meta['optional'], 0x999),
                     ('<I', meta['optional'] + 32, 3),
                     ('<I', meta['optional'] + 36, 0),
                     ('<I', meta['optional'] + 60, 0x180),
                     ('<I', meta['optional'] + 56, 0x2000),
                     ('<I', meta['optional'] + 16, 0x3000),
                     ('<I', meta['optional'] + 16, 0x2200),
                     ('<I', meta['optional'] + 108, 17)]
        for fmt, off, value in mutations:
            with self.subTest(offset=off, value=value):
                self.rejects(patched(blob, fmt, off, value))
        self.rejects(patched(blob, '<Q', meta['optional'] + 24, (1 << 64) - 0x1000))

    def test_pe_overlapping_raw_virtual_and_bad_directory_pointers(self):
        blob, meta = pe_fixture()
        off = meta['sections']
        for field, value in ((40 + 12, 0x1000), (40 + 20, 0x200),
                             (12, 0), (20, 0), (20, 0x201), (16, 0x201),
                             (40 + 8, 0xffffffff), (40 + 20, 0x800)):
            with self.subTest(field=field, value=value):
                self.rejects(patched(blob, '<I', off + field, value))
        for pointer, size in ((0, 1), (0x1500, 4), (0x2000, 0x1000), (0xffffffff, 4)):
            self.rejects(patched(blob, '<II', meta['directories'] + 8, pointer, size))

    def test_elf_four_class_endian_variants(self):
        for bits in (32, 64):
            for order in ('little', 'big'):
                with self.subTest(bits=bits, byteorder=order):
                    blob, meta = elf_fixture(bits, order)
                    image = self.parse_file(blob)
                    base = meta['base']
                    self.assertEqual((image.format, image.bits, image.byteorder), ('ELF', bits, order))
                    self.assertEqual(image.imagebase, base + 0x200)
                    self.assertEqual(image.entrypoint, base + 0x200)
                    self.assertEqual(image.read(base + 0x400, 8), b'ELF DATA')
                    self.assertEqual(image.read(base + 0x40e, 4), b'\x5a\x5a\0\0')
                    self.assertEqual(image.read(base + 0x410, 0x30), b'\0' * 0x30)
                    self.assertEqual([r.permissions for r in image.regions], [5, 3])
                    self.assertEqual([s['name'] for s in image.sections],
                                     ['', '.text', '.data', '.bss', '.shstrtab'])
                    self.assertEqual(image.sections[3]['fileSize'], 0)
                    self.assertTrue(image.sections[3]['mapped'])
                    self.assertFalse(image.sections[4]['mapped'])
                    self.assertGreater(image.unmapped_file_bytes, 0)
                    with self.assertRaises(ImageFormatError):
                        image.read(base + 0x300, 1)
                    description = json.loads(json.dumps(image.describe()))
                    self.assertEqual(description['entrypoint'], hex(base + 0x200))
                    if bits == 64:
                        self.assertGreater(image.entrypoint, 2 ** 53)

    def test_elf_extended_numbering(self):
        for bits in (32, 64):
            for order in ('little', 'big'):
                blob, _ = elf_fixture(bits, order, extended=True)
                image = self.parse_file(blob)
                self.assertEqual(len(image.sections), 5)
                self.assertEqual(len(image.segments), 2)

    def test_elf_without_section_table_and_shared_without_entry(self):
        blob, meta = elf_fixture()
        blob = patched(blob, '<H', 16, 3)
        blob = patched(blob, '<Q', 24, 0)
        blob = patched(blob, '<Q', 40, 0)
        blob = patched(blob, '<HH', 60, 0, 0)
        image = self.parse_file(blob)
        self.assertIsNone(image.entrypoint)
        self.assertEqual(image.object_type, 'shared')
        self.assertEqual(image.sections, ())

    def test_elf_bad_ident_header_counts_and_table_pointers(self):
        blob, meta = elf_fixture()
        for cutoff in (1, 15, 16, 63, meta['phoff'] + 111, len(blob) - 1):
            self.rejects(blob[:cutoff])
        for offset, value in ((4, 0), (5, 3), (6, 0)):
            self.rejects(patched(blob, 'B', offset, value))
        for fmt, offset, value in (
                ('<H', 16, 1), ('<H', 18, 3), ('<I', 20, 2),
                ('<Q', 32, 0), ('<Q', 32, (1 << 64) - 1),
                ('<Q', 40, (1 << 64) - 1), ('<Q', 40, meta['phoff']),
                ('<H', 52, 0), ('<H', 54, 55), ('<H', 56, 0),
                ('<H', 56, 4097), ('<H', 58, 63), ('<H', 60, 4097), ('<H', 62, 5),
                ('<Q', 24, meta['base'] + 0x300), ('<Q', 24, meta['base'] + 0x410)):
            with self.subTest(offset=offset, value=value):
                self.rejects(patched(blob, fmt, offset, value))

    def test_elf_bad_load_sizes_overlap_alignment_and_file_pointers(self):
        blob, meta = elf_fixture()
        first, second = meta['phoff'], meta['phoff'] + meta['phsize']
        for fmt, off, value in (
                ('<Q', first + 32, 0x21), ('<Q', first + 8, len(blob)),
                ('<Q', first + 16, (1 << 64) - 16), ('<Q', first + 48, 3),
                ('<Q', first + 16, meta['base'] + 0x201),
                ('<Q', second + 16, meta['base'] + 0x200),
                ('<Q', second + 8, 0x200)):
            with self.subTest(offset=off, value=value):
                self.rejects(patched(blob, fmt, off, value))
        # Unknown/NULL segment is metadata, not automatically executable memory.
        self.rejects(patched(blob, '<I', first, 0))

    def test_elf_bad_section_names_links_allocations_and_bss(self):
        blob, meta = elf_fixture()
        text, bss, strings = (meta['shoff'] + i * meta['shsize'] for i in (1, 3, 4))
        for fmt, off, value in (
                ('<I', text, 1000), ('<I', text + 40, 8),
                ('<Q', text + 24, 0x201), ('<Q', text + 16, meta['base'] + 0x220),
                ('<Q', text + 48, 3), ('<Q', text + 56, 3),
                ('<Q', bss + 16, meta['base'] + 0x400),
                ('<Q', bss + 32, 0x31), ('<I', strings + 4, 1),
                ('<Q', strings + 24, len(blob)), ('<I', meta['shoff'] + 4, 1)):
            with self.subTest(offset=off, value=value):
                self.rejects(patched(blob, fmt, off, value))
        self.rejects(patched(blob, 'B', 0x260, 1))
        self.rejects(patched(blob, 'B', 0x260 + len(b'\0.text\0.data\0.bss\0.shstrtab\0') - 1, 1))

    def test_lazy_large_bss_and_bounded_reads(self):
        blob, meta = elf_fixture()
        second = meta['phoff'] + meta['phsize']
        blob = patched(blob, '<Q', second + 40, 1 << 30)
        image = self.parse_file(blob, max_bytes=2048)
        self.assertEqual(len(image.regions[1].data), 16)
        self.assertEqual(image.regions[1].size, 1 << 30)
        self.assertEqual(image.read(meta['base'] + 0x400 + (1 << 30) - 8, 8), b'\0' * 8)
        with self.assertRaises(ImageFormatError):
            image.read(meta['base'] + 0x410, 2049)

    def test_wide_bss_metadata_is_exact_on_json_wire(self):
        blob, meta = elf_fixture()
        second = meta['phoff'] + meta['phsize']
        blob = patched(blob, '<Q', second + 40, (1 << 53) + 32)
        image = self.parse_file(blob)
        self.assertEqual(image.read(meta['base'] + 0x410, 4), b'\0' * 4)
        description = json.loads(json.dumps(image.describe()))
        self.assertEqual(description['regions'][1]['size'], hex((1 << 53) + 32))
        self.assertEqual(description['mappedBytes'], hex((1 << 53) + 64))

    def test_reads_across_adjacent_mapped_regions_only(self):
        blob, meta = pe_fixture()
        blob = patched(blob, '<I', meta['sections'] + 8, 0x1000)
        image = self.parse_file(blob)
        self.assertEqual(image.read(meta['base'] + 0x1ffe, 6), b'\0\0DATA')

    def test_file_growth_during_snapshot_is_rejected(self):
        blob, _ = pe_fixture()
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'fixture.bin'
            target.write_bytes(blob)
            real_read = os.read
            changed = [False]

            def growing_read(fd, size):
                result = real_read(fd, size)
                if not changed[0]:
                    changed[0] = True
                    with target.open('ab') as stream:
                        stream.write(b'extra')
                return result

            with patch('kernel_image.os.read', side_effect=growing_read):
                with self.assertRaises(ImageFormatError):
                    BinaryImage.from_file(target)

    def test_deterministic_header_mutations_fail_closed_or_preserve_mapping(self):
        rng = random.Random(10873)
        fixtures = [pe_fixture(32)[0], pe_fixture(64)[0],
                    elf_fixture(32, 'big')[0], elf_fixture(64, 'little')[0]]
        for blob in fixtures:
            for _ in range(120):
                mutation = bytearray(blob)
                for _ in range(rng.randint(1, 4)):
                    mutation[rng.randrange(len(blob))] = rng.randrange(256)
                try:
                    image = BinaryImage.from_bytes(bytes(mutation))
                except ImageFormatError:
                    continue
                prior_end = -1
                for region in image.regions:
                    self.assertGreaterEqual(region.start, prior_end)
                    self.assertLessEqual(region.end, 1 << image.bits)
                    self.assertLessEqual(len(region.data), region.size)
                    count = min(region.size, 8)
                    expected = region.data[:count].ljust(count, b'\0')
                    self.assertEqual(image.read(region.start, count), expected)
                    prior_end = region.end

    def test_file_input_budget_read_address_and_types(self):
        blob, meta = pe_fixture()
        self.rejects(blob, max_bytes=len(blob) - 1)
        for budget in (True, 0, -1, 64 * 1024 * 1024 + 1, 1.5):
            with self.subTest(budget=budget):
                self.rejects(blob, max_bytes=budget)
        image = self.parse_file(blob)
        for ea, size in ((True, 1), (1.5, 1), ('garbage', 1), (-1, 1),
                         (1 << 64, 0), ((1 << 64) - 1, 2),
                         (meta['base'], True), (meta['base'], -1)):
            with self.subTest(address=ea, size=size):
                with self.assertRaises(ImageFormatError):
                    image.read(ea, size)
        self.assertEqual(image.read(meta['base'], 0), b'')
        with self.assertRaises(ImageFormatError):
            BinaryImage.from_bytes(bytearray(blob))
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises((ImageFormatError, OSError)):
                BinaryImage.from_file(directory)
        self.rejects(b'RAW DATA')


if __name__ == '__main__':
    unittest.main(verbosity=2)
