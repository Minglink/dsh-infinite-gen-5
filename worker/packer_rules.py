"""Packer and protector knowledge as data: names, byte markers, thresholds and indicator weights.

Kept apart from the analysis code so the table can be reviewed and extended on its own. Everything here is a LEAD:
section names and strings are attacker-controlled, so a name match is reported with confidence ``name-only`` and the
structural indicators (entropy, entry point, emptied code sections, imports) carry the decision.
``validate()`` runs at import: a mistyped key or an impossible weight fails the first test run.
"""
import re

# ---- thresholds -----------------------------------------------------------------------------------------------------
ENTROPY_PACKED = 7.0            # compiled x86/x64 code stays below ~6.8; compressed or encrypted code is above 7.0
ENTROPY_ENCRYPTED = 7.5
MIN_ENTROPY_BYTES = 4096        # smaller samples are too short for an entropy figure to mean anything
VIRTUAL_ONLY_BYTES = 0x4000     # an executable/writable section this large with no file content is an unpack target
FEW_IMPORTS = 12
LOADER_IMPORTS = 30
STATUS_PACKED = 60
STATUS_SUSPECTED = 30

# ---- indicator weights (id -> (weight, description)) ---------------------------------------------------------------
INDICATORS = {
    'entry-outside-sections':   (40, 'The entry point lies outside every section'),
    'entry-in-writable':        (25, 'The entry point is in a writable section'),
    'entry-not-first-code':     (15, 'The entry point is not in the first executable section'),
    'entry-nonstandard-section': (20, 'The entry point is in a section whose name is not a usual code section'),
    'virtual-only-exec':        (30, 'An executable or writable section has a large memory size but no file content (the unpack target)'),
    'emptied-code-section':     (30, 'An executable section has no file content although the image maps it (code removed from the file)'),
    'rwx-section':              (10, 'A section is readable, writable and executable'),
    'high-entropy-exec':        (25, 'An executable section looks compressed or encrypted'),
    'encrypted-exec':           (35, 'An executable section is almost random (very high entropy)'),
    'high-entropy-resources':   (10, 'The resource section looks encrypted'),
    'random-section-names':     (20, 'Several section names are unprintable or random-looking'),
    'nonstandard-section-names': (3, 'Section names outside the usual compiler set (3 per section, capped at 9)'),
    'few-imports':              (20, 'Very few imported functions for an executable of this size'),
    'loader-imports':           (15, 'The import table is little more than LoadLibrary/GetProcAddress'),
    'tls-callbacks':            (5, 'TLS callbacks run before the entry point'),
    'overlay-encrypted':        (5, 'A large high-entropy overlay follows the last section'),
    'header-anomaly':           (10, 'Section table or image size is inconsistent'),
    'upx-like-layout':          (50, 'First section is an empty executable target and the entry section is compressed (UPX-style stub, even with renamed sections)'),
    'signature-name':           (40, 'A section name matches a known packer or protector'),
    'signature-marker':         (50, 'A byte marker of a known packer is present'),
    'elf-no-sections':          (15, 'The ELF file has no section headers'),
    'elf-rwx-segment':          (25, 'A loadable segment is readable, writable and executable'),
    'elf-high-entropy-load':    (30, 'An executable loadable segment looks compressed or encrypted'),
    'elf-entry-in-writable':    (25, 'The entry point is in a writable segment'),
    'elf-entry-not-first-code': (15, 'The entry point is not in the first executable loadable segment'),
    'protector-layout':         (0, 'Emptied original sections, random section names and an entry point in a high-entropy section (protector layout)'),
    'elf-few-loads':            (10, 'Only one or two loadable segments with almost no dynamic linking'),
}

# ---- known packers: section names (lower-case, exact) --------------------------------------------------------------
# kind: compressor = shrinks the file and unpacks at start; protector = adds anti-analysis and/or virtualization.
SECTION_NAMES = {
    'upx0': ('UPX', 'compressor'), 'upx1': ('UPX', 'compressor'), 'upx2': ('UPX', 'compressor'), 'upx!': ('UPX', 'compressor'),
    '.aspack': ('ASPack', 'compressor'), '.adata': ('ASPack', 'compressor'),
    '.themida': ('Themida/WinLicense', 'protector'), '.winlice': ('Themida/WinLicense', 'protector'),
    '.vmp0': ('VMProtect', 'protector'), '.vmp1': ('VMProtect', 'protector'), '.vmp2': ('VMProtect', 'protector'), '.vmp3': ('VMProtect', 'protector'),
    '.enigma': ('Enigma Protector', 'protector'), '.enigma1': ('Enigma Protector', 'protector'), '.enigma2': ('Enigma Protector', 'protector'),
    '.obsidiu': ('Obsidium', 'protector'), '.taz': ('PESpin', 'protector'), '.perplex': ('Perplex', 'compressor'), '.packed': ('Generic Packer', 'compressor'),
    '.mpress1': ('MPRESS', 'compressor'), '.mpress2': ('MPRESS', 'compressor'),
    '.petite': ('Petite', 'compressor'),
    '.nsp0': ('NsPack', 'compressor'), '.nsp1': ('NsPack', 'compressor'), '.nsp2': ('NsPack', 'compressor'), 'nsp0': ('NsPack', 'compressor'), 'nsp1': ('NsPack', 'compressor'), 'nsp2': ('NsPack', 'compressor'),
    'pec2to': ('PECompact', 'compressor'), 'pec2mo': ('PECompact', 'compressor'),
    '.rlpack': ('RLPack', 'compressor'), '.y0da': ("Yoda's Protector", 'protector'), '.yp': ("Yoda's Protector", 'protector'),
}

# ---- byte markers searched in the file ------------------------------------------------------------------------------
MARKERS = (
    (b'UPX!', 'UPX', 'compressor'),
    (b'$Info: This file is packed with the UPX executable packer', 'UPX', 'compressor'),
    (b'ConfuserEx v', 'ConfuserEx', 'protector'),
    (b'MEI\x0c\x0b\x0a\x0b\x0e', 'PyInstaller', 'compressor'),
)
MARKER_SCAN_BYTES = 16 * 1024 * 1024

# ---- ordinary section names: seeing only these is the baseline ----------------------------------------------------
STANDARD_CODE_NAMES = frozenset({'.text', 'text', 'code', '.code', '.init', '.fini', '.plt', '.text$mn', '.textbss', '.itext', '.nep'})
STANDARD_NAMES = frozenset(STANDARD_CODE_NAMES | {
    '.data', '.rdata', '.idata', '.edata', '.pdata', '.xdata', '.bss', '.rsrc', '.reloc', '.tls', '.crt', '.didat', '.gfids', '.00cfg', '.msvcjmc', '.fptable', '.sxdata', '.cormeta',
    '.eh_fram', '.ctors', '.dtors', '.drectve', '.stab', '.stabstr', '.retplne', '.voltbl', '.rodata', '_rdata', '.data1', 'pad1', 'pad2', 'pad3', 'pad4', 'pad5', 'pad6', 'pad7', 'pad8', 'pad9', '.sdata', '.srdata', '.page', 'page', 'init', 'data', 'bss', 'rsrc', 'idata', 'edata', 'tls',
    '.bildata', '.gnu_deb', '.rustc', '.link', '.detourc', '.detourd', '.wixburn', '.ndata', '.minjv', '.gehcont', '.giats', '.rtc', '.xtls', '.tracet', '.trace',
    '.go.buil', '.gopclnt', '.symtab', '.strtab', '.note'})
# MinGW/GNU toolchains name debug sections "/4", ".debug_info", ".zdebug_*"; they are large and compressed but not executable.
DEBUG_NAME = re.compile(r'^(/\d+|\.z?debug_.*)$')
# A name made of ordinary identifier characters; anything else (control bytes, quotes, braces, high bytes) is not what a linker writes.
IDENTIFIER_NAME = re.compile(r'^[A-Za-z0-9._$@\-]{1,8}$')

# ---- imports -------------------------------------------------------------------------------------------------------
LOADER_APIS = frozenset({'loadlibrarya', 'loadlibraryw', 'loadlibraryexa', 'loadlibraryexw', 'getprocaddress', 'virtualalloc', 'virtualprotect', 'virtualfree', 'exitprocess',
                         'getmodulehandlea', 'getmodulehandlew', 'getmodulehandleexa', 'getmodulehandleexw', 'ldrloaddll', 'ldrgetprocedureaddress'})
MANAGED_RUNTIME_DLLS = frozenset({'mscoree.dll'})


def validate():
    problems = []
    for key, (weight, text) in INDICATORS.items():
        if not isinstance(weight, int) or not 0 <= weight <= 100 or not text:
            problems.append(f'indicator {key}')
    for name, (packer, kind) in SECTION_NAMES.items():
        if name != name.lower() or len(name) > 8 or kind not in ('compressor', 'protector') or not packer:
            problems.append(f'section name {name!r}')
    for marker, packer, kind in MARKERS:
        if not marker or kind not in ('compressor', 'protector') or not packer:
            problems.append(f'marker {marker!r}')
    for name in STANDARD_NAMES:
        if name != name.lower():
            problems.append(f'standard name {name!r} must be lower-case')
    if SECTION_NAMES.keys() & STANDARD_NAMES:
        problems.append('a packer section name is also listed as standard: ' + ', '.join(sorted(SECTION_NAMES.keys() & STANDARD_NAMES)))
    if not 0 < STATUS_SUSPECTED < STATUS_PACKED <= 100 or not ENTROPY_PACKED < ENTROPY_ENCRYPTED <= 8:
        problems.append('thresholds')
    if problems:
        raise ValueError('packer_rules is inconsistent: ' + '; '.join(problems))


validate()
