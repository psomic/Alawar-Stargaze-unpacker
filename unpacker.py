import struct
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, List, Tuple

# ---------- Константы формата ----------
HEADER_SIZE  = 0x0C
ENTRY_SIZE   = 0x80          # 128 байт
NAME_FIELD   = 0x70          # 112 байт под имя
HEADER_FMT   = "<H2xI"       # u16 files_count, pad2, u32 archive_size
ENTRY_FMT    = "<HHH2x"      # u16 name_len, u16 type, u16 hash, pad2
TAIL_FMT     = "<II"         # u32 file_size, u32 offset (relative to mapping start)

SFP_MAGIC    = b"SFP\x01"
SFGP_MAGIC   = b"SFGP"


# ---------- Структуры данных ----------
@dataclass
class Header:
    magic: bytes
    files_count: int
    archive_size: int


@dataclass
class Entry:
    name_len: int
    type: int
    hash: int
    name: str
    file_size: int
    offset: int
    raw_name: bytes = b""

    def __repr__(self) -> str:
        return (f"Entry(name={self.name!r}, type=0x{self.type:04X}, "
                f"hash=0x{self.hash:04X}, size={self.file_size}, "
                f"offset=0x{self.offset:X}, name_len={self.name_len})")


# ---------- Реализации парсеров для конкретных layout ----------
def parse_header_v1(data: bytes, magic: bytes) -> Header:
    """Общий layout для SFP\x01 и SFGP: header 12 байт, entry 128 байт."""
    if len(data) < HEADER_SIZE:
        raise ValueError("Файл меньше заголовка")
    files_count, archive_size = struct.unpack_from(HEADER_FMT, data, 4)
    return Header(magic, files_count, archive_size)


def parse_entry_v1(data: bytes, base: int) -> Entry:
    if base + ENTRY_SIZE > len(data):
        raise ValueError(f"Запись на 0x{base:X} выходит за границы файла")

    name_len, etype, hash_ = struct.unpack_from(ENTRY_FMT, data, base)

    name_off = base + 8
    raw_name = data[name_off : name_off + NAME_FIELD]

    # имя C-строки: режем по нулю, но уважаем name_len
    name_bytes = raw_name.split(b"\x00", 1)[0]
    if 0 < name_len <= NAME_FIELD:
        name_bytes = raw_name[:name_len]
    name = name_bytes.decode("utf-8", errors="replace")

    tail_off = name_off + NAME_FIELD
    file_size, offset = struct.unpack_from(TAIL_FMT, data, tail_off)

    return Entry(name_len, etype, hash_, name, file_size, offset, raw_name)


# ---------- Реестр форматов ----------
@dataclass(frozen=True)
class ArchiveFormat:
    magic: bytes
    name: str
    header_size: int
    entry_size: int
    parse_header: Callable[[bytes, bytes], Header]
    parse_entry: Callable[[bytes, int], Entry]


REGISTRY: List[ArchiveFormat] = [
    ArchiveFormat(
        magic=SFP_MAGIC,
        name="SFP v1",
        header_size=HEADER_SIZE,
        entry_size=ENTRY_SIZE,
        parse_header=parse_header_v1,
        parse_entry=parse_entry_v1,
    ),
    ArchiveFormat(
        magic=SFGP_MAGIC,
        name="SFGP",
        header_size=HEADER_SIZE,
        entry_size=ENTRY_SIZE,
        parse_header=parse_header_v1,
        parse_entry=parse_entry_v1,
    ),
]


def detect_format(data: bytes) -> ArchiveFormat:
    if len(data) < 4:
        raise ValueError("Файл слишком мал для магии")
    for fmt in REGISTRY:
        if data.startswith(fmt.magic):
            return fmt
    known = ", ".join(f.magic.hex() for f in REGISTRY)
    raise ValueError(
        f"Неизвестная магия: {data[:4].hex()} (известные: {known})"
    )


def list_formats() -> None:
    print("Известные форматы:")
    for fmt in REGISTRY:
        print(f"  {fmt.magic.hex():<10} {fmt.name:<10} "
              f"header={fmt.header_size} entry={fmt.entry_size}")


# ---------- Основной парсер ----------
def parse_archive(data: bytes) -> Tuple[ArchiveFormat, Header, List[Entry]]:
    fmt = detect_format(data)
    header = fmt.parse_header(data, fmt.magic)

    entries: List[Entry] = []
    for i in range(header.files_count):
        base = fmt.header_size + i * fmt.entry_size
        entries.append(fmt.parse_entry(data, base))

    return fmt, header, entries


# ---------- Извлечение ----------
def extract_files(data: bytes, entries: List[Entry], out_dir: str | Path) -> None:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    for e in entries:
        safe_name = e.name.replace("\\", "/").lstrip("/")
        dest = out_dir / safe_name
        dest.parent.mkdir(parents=True, exist_ok=True)

        chunk = data[e.offset : e.offset + e.file_size]
        if len(chunk) != e.file_size:
            print(f"[!] {e.name}: ожидалось {e.file_size} байт, "
                  f"получено {len(chunk)} (offset=0x{e.offset:X})")
        dest.write_bytes(chunk)
        print(f"[+] {e.name} -> {dest} ({len(chunk)} байт)")


# ---------- CLI ----------
def main(argv: List[str]) -> int:
    if len(argv) < 2 or argv[1] in ("-h", "--help"):
        print("Использование:")
        print("  python sfp.py <archive> [out_dir]")
        print("  python sfp.py --list-formats")
        return 1 if len(argv) < 2 else 0

    if argv[1] == "--list-formats":
        list_formats()
        return 0

    path = Path(argv[1])
    data = path.read_bytes()

    try:
        fmt, header, entries = parse_archive(data)
    except ValueError as exc:
        print(f"Ошибка: {exc}")
        return 2

    print(f"=== {path.name} ===")
    print(f"Формат:        {fmt.name} ({fmt.magic.hex()})")
    print(f"files_count:   {header.files_count}")
    print(f"archive_size:  {header.archive_size} (0x{header.archive_size:X})")
    print(f"entries:       {len(entries)}")
    print()

    for e in entries:
        print(e)

    if len(argv) >= 3:
        extract_files(data, entries, argv[2])

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
