"""Regenerate portable PE32+ and ELF64 test images without a host compiler."""
from pathlib import Path
from struct import pack_into

HERE = Path(__file__).parent
CODE = bytes.fromhex(
    "55 48 89 e5 48 83 ec 20 31 c9 e8 15 00 00 00 "
    "85 c0 74 08 48 8d 0d e6 0f 00 00 90 48 83 c4 20 5d c3 "
    "cc cc cc 8d 41 07 83 f8 0a 7e 03 83 e8 03 c3"
)
MESSAGE = b"DISECTA fixture\0"


def pe():
    image = bytearray(0x800)
    image[:2] = b"MZ"
    pack_into("<I", image, 0x3C, 0x40)
    image[0x40:0x44] = b"PE\0\0"
    pack_into("<HHIIIHH", image, 0x44, 0x8664, 4, 0, 0, 0, 0xF0, 0x22)
    optional = 0x58
    pack_into("<HBBIIIIIQII", image, optional,
              0x20B, 1, 0, 0x200, 0x400, 0x200, 0x1000, 0x1000,
              0x140000000, 0x1000, 0x200)
    pack_into("<HHHHHHIIIIHHQQQQII", image, optional + 40,
              6, 0, 0, 0, 6, 0, 0, 0x5000, 0x200, 0, 3, 0,
              0x100000, 0x1000, 0x100000, 0x1000, 0, 16)
    sections = [
        (b".text", len(CODE), 0x1000, 0x200, 0x200, 0x60000020),
        (b".rdata", len(MESSAGE), 0x2000, 0x200, 0x400, 0x40000040),
        (b".data", 8, 0x3000, 0x200, 0x600, 0xC0000040),
        (b".bss", 0x200, 0x4000, 0, 0, 0xC0000080),
    ]
    for i, (name, size, rva, file_size, position, flags) in enumerate(sections):
        pack_into("<8sIIIIIIHHI", image, optional + 0xF0 + 40 * i,
                  name, size, rva, file_size, position, 0, 0, 0, 0, flags)
    image[0x200:0x200 + len(CODE)] = CODE
    image[0x400:0x400 + len(MESSAGE)] = MESSAGE
    pack_into("<Q", image, 0x600, 7)
    return image


def elf():
    image = bytearray(0x2400)
    names = b"\0.text\0.rodata\0.bss\0.shstrtab\0"
    ident = b"\x7fELF\x02\x01\x01" + bytes(9)
    pack_into("<16sHHIQQQIHHHHHH", image, 0, ident, 2, 62, 1, 0x401000,
              64, 0x2200, 0, 64, 56, 2, 64, 5, 4)
    pack_into("<IIQQQQQQ", image, 64, 1, 5, 0, 0x400000,
              0x400000, 0x1000 + len(CODE), 0x1000 + len(CODE), 0x1000)
    pack_into("<IIQQQQQQ", image, 120, 1, 6, 0x2000, 0x402000,
              0x402000, len(MESSAGE), 0x210, 0x1000)
    image[0x1000:0x1000 + len(CODE)] = CODE
    image[0x2000:0x2000 + len(MESSAGE)] = MESSAGE
    image[0x2100:0x2100 + len(names)] = names
    sections = [
        (b".text", 1, 6, 0x401000, 0x1000, len(CODE), 16),
        (b".rodata", 1, 2, 0x402000, 0x2000, len(MESSAGE), 1),
        (b".bss", 8, 3, 0x402010, 0x2010, 0x200, 8),
        (b".shstrtab", 3, 0, 0, 0x2100, len(names), 1),
    ]
    for i, (name, kind, flags, address, offset, size, alignment) in enumerate(sections, 1):
        pack_into("<IIQQQQIIQQ", image, 0x2200 + 64 * i,
                  names.index(name), kind, flags, address, offset, size, 0, 0, alignment, 0)
    return image


if __name__ == "__main__":
    (HERE / "branch.exe").write_bytes(pe())
    (HERE / "branch.elf").write_bytes(elf())
