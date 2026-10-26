"""Hermetic ELF/Mach-O byte fixtures. Not runnable samples."""

from __future__ import annotations

import struct

ELF_MAGIC = b"\x7fELF"
MACHO_64_LE = b"\xcf\xfa\xed\xfe"


def build_elf_ident(*, payload: bytes = b"REVENG") -> bytes:
    """Magic-only ELF identity. Enough for identify(); not a full image."""
    return ELF_MAGIC + b"\x02\x01\x01\x00" + payload


def build_macho_ident(*, payload: bytes = b"REVENG") -> bytes:
    """Magic-only Mach-O 64-bit LE header prefix. Enough for identify()."""
    return MACHO_64_LE + payload


def build_minimal_elf64() -> bytes:
    """Tiny ELF64 relocatable that LIEF can parse; not a runnable sample."""
    e_ident = ELF_MAGIC + bytes([2, 1, 1, 0]) + bytes(8)
    text = b"REVENG\x00"
    text_off = 0x40
    shstrtab = b"\x00.text\x00.shstrtab\x00"
    shstrtab_off = 0x50
    shoff = 0x70
    header = struct.pack(
        "<16sHHIQQQIHHHHHH",
        e_ident,
        1,
        62,
        1,
        0,
        0,
        shoff,
        0,
        64,
        0,
        0,
        64,
        3,
        2,
    )
    buf = bytearray(shoff + 3 * 64)
    buf[0:64] = header
    buf[text_off : text_off + len(text)] = text
    buf[shstrtab_off : shstrtab_off + len(shstrtab)] = shstrtab

    def pack_sh(
        name: int,
        typ: int,
        flags: int,
        addr: int,
        off: int,
        size: int,
        link: int,
        info: int,
        addralign: int,
        entsize: int,
    ) -> bytes:
        return struct.pack(
            "<IIQQQQIIQQ",
            name,
            typ,
            flags,
            addr,
            off,
            size,
            link,
            info,
            addralign,
            entsize,
        )

    buf[shoff + 64 : shoff + 128] = pack_sh(1, 1, 6, 0, text_off, len(text), 0, 0, 1, 0)
    buf[shoff + 128 : shoff + 192] = pack_sh(7, 3, 0, 0, shstrtab_off, len(shstrtab), 0, 0, 1, 0)
    return bytes(buf)


def build_minimal_macho64() -> bytes:
    """Tiny Mach-O 64 object that LIEF can parse; not a runnable sample."""
    magic = 0xFEEDFACF
    cpu_type_x86_64 = 0x01000007
    cpu_subtype_x86_64_all = 3
    mh_object = 1
    lc_segment_64 = 0x19
    text = b"REVENG\x00"
    cmdsize = 72 + 80
    text_off = 192
    header = struct.pack(
        "<IIIIIIII",
        magic,
        cpu_type_x86_64,
        cpu_subtype_x86_64_all,
        mh_object,
        1,
        cmdsize,
        0,
        0,
    )
    segname = b"__TEXT".ljust(16, b"\x00")
    sectname = b"__text".ljust(16, b"\x00")
    vm_prot = 5
    segment = (
        struct.pack("<II", lc_segment_64, cmdsize)
        + segname
        + struct.pack("<QQQQ", 0, 0x1000, 0, text_off + len(text))
        + struct.pack("<iiII", vm_prot, vm_prot, 1, 0)
    )
    section = (
        sectname + segname + struct.pack("<QQIIIIIIII", 0, len(text), text_off, 0, 0, 0, 0, 0, 0, 0)
    )
    buf = bytearray(text_off + len(text))
    buf[0:32] = header
    buf[32:104] = segment
    buf[104:184] = section
    buf[text_off : text_off + len(text)] = text
    return bytes(buf)
