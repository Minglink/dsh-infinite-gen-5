"""Engine-neutral, bounded target memory. Host architecture is not target architecture."""
from dataclasses import dataclass
from types import MappingProxyType
from typing import Callable, Optional

PAGE_SIZE = 4096
MEMORY_BUDGET = 64 * 1024 * 1024
# Engine-neutral masks deliberately match Unicorn's UC_PROT_* values.
PERM_READ, PERM_WRITE, PERM_EXEC = 1, 2, 4
PERM_ALL = PERM_READ | PERM_WRITE | PERM_EXEC


def integer(value, label='integer'):
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        raise ValueError(label + ' must be an integer or decimal/hex string')
    try:
        return int(value, 0) if isinstance(value, str) else value
    except ValueError as exc:
        raise ValueError(label + ' is not a valid integer') from exc


def page_range(base, size, bits):
    base, size = integer(base, 'memory address'), integer(size, 'memory size')
    if base < 0 or size <= 0 or base + size > (1 << bits):
        raise ValueError('memory range outside target address space')
    first, end = base & ~(PAGE_SIZE - 1), (base + size + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1)
    if end - first > MEMORY_BUDGET:
        raise ValueError('emulation memory budget exceeded (64 MiB)')
    return range(first, end, PAGE_SIZE)


@dataclass(frozen=True)
class MemoryRegion:
    """permissions=None means unknown; 0 explicitly means no CPU access.

    Snapshot readers may read bytes independently of CPU access permissions.
    """
    base: int
    size: int
    read: Callable[[int, int], Optional[bytes]]
    name: str = ''
    zero_fill: bool = False
    permissions: Optional[int] = None

    def __post_init__(self):
        object.__setattr__(self, 'base', integer(self.base, 'region address'))
        object.__setattr__(self, 'size', integer(self.size, 'region size'))
        if not callable(self.read):
            raise ValueError('region requires a memory reader')
        if self.permissions is not None and (isinstance(self.permissions, bool)
                or not isinstance(self.permissions, int) or not 0 <= self.permissions <= PERM_ALL):
            raise ValueError('region permissions must be None or a mask in 0..7')


class MemoryImage:
    """Reads original engine memory in bounded chunks; does not own or mutate its database."""
    def __init__(self, arch, bits, entry, regions, source='unknown'):
        if (arch, bits) not in (('x86', 32), ('x86', 64), ('arm64', 64)):
            raise ValueError('CPU emulation supports x86/x64 and ARM64 targets only')
        self.arch, self.bits, self.entry = arch, bits, integer(entry, 'entry')
        self.source = str(source)
        regions = tuple(regions)
        if not all(isinstance(r, MemoryRegion) for r in regions):
            raise ValueError('invalid memory image region')
        self.regions = tuple(sorted(regions, key=lambda r: r.base))
        if not self.regions or len(self.regions) > 4096:
            raise ValueError('memory image must contain 1..4096 regions')
        pages, page_permissions, contributions, unknown_pages, last_end = set(), {}, {}, set(), -1
        for region in self.regions:
            if not isinstance(region, MemoryRegion) or not callable(region.read):
                raise ValueError('invalid memory image region')
            if region.base < last_end:
                raise ValueError('memory image regions overlap')
            last_end = region.base + region.size
            for page in page_range(region.base, region.size, bits):
                pages.add(page)
                # Byte-disjoint regions may share a hardware page. Preserve
                # their union; sub-page permissions cannot be represented.
                permission = PERM_ALL if region.permissions is None else region.permissions
                page_permissions[page] = page_permissions.get(page, 0) | permission
                contributions[page] = contributions.get(page, 0) + 1
                if region.permissions is None:
                    unknown_pages.add(page)
            if len(pages) * PAGE_SIZE > MEMORY_BUDGET:
                raise ValueError('emulation memory budget exceeded (64 MiB)')
        if not any(r.base <= self.entry < r.base + r.size for r in self.regions):
            raise ValueError('entry is not in the memory image')
        self.pages = frozenset(pages)
        self.page_permissions = MappingProxyType(page_permissions)
        self.unknown_permission_regions = sum(region.permissions is None for region in self.regions)
        self.unknown_permission_pages = len(unknown_pages)
        self.page_permission_merges = sum(count > 1 for count in contributions.values())

    def chunks(self, chunk_size=65536):
        if not isinstance(chunk_size, int) or not 1 <= chunk_size <= 65536:
            raise ValueError('invalid snapshot chunk size')
        for region in self.regions:
            for offset in range(0, region.size, chunk_size):
                size = min(chunk_size, region.size - offset)
                data = region.read(offset, size)
                if data is None:
                    if not region.zero_fill:
                        raise ValueError('memory image read unavailable: ' + region.name)
                    yield region.base + offset, None, size
                    continue
                if not isinstance(data, (bytes, bytearray, memoryview)) or len(data) != size:
                    raise ValueError('memory image read returned a partial or invalid buffer: ' + region.name)
                yield region.base + offset, bytes(data), 0
