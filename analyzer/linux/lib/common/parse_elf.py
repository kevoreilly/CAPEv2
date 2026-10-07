import struct

try:
    HAVE_ELFTOOLS = True
except ImportError:
    HAVE_ELFTOOLS = False

ELF_MAGIC = b"\x7fELF"
EI_CLASS = 4
EI_DATA = 5

ET_EXEC = 2
ET_DYN = 3


def is_elf_image(path) -> bool:
    if not path:
        return False

    try:
        with open(path, "rb") as f:
            buf = f.read(64)
    except IOError:
        return False

    if len(buf) < 16 or buf[:4] != ELF_MAGIC:
        return False

    elf_class = buf[EI_CLASS]
    elf_data = buf[EI_DATA]

    if elf_class not in (1, 2) or elf_data not in (1, 2):
        return False

    fmt_char = "<" if elf_data == 1 else ">"

    try:
        if elf_class == 1:  # ELF32
            if len(buf) < 52:
                return False
            e_type, e_machine = struct.unpack(f"{fmt_char}HH", buf[16:20])
            e_shoff, e_flags, e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum = struct.unpack(
                f"{fmt_char}LLHHHHH", buf[32:52]
            )
        else:  # ELF64
            if len(buf) < 64:
                return False
            e_type, e_machine = struct.unpack(f"{fmt_char}HH", buf[16:20])
            #e_shoff = struct.unpack(f"{fmt_char}Q", buf[40:48])[0]
            e_shentsize, e_shnum = struct.unpack(f"{fmt_char}HH", buf[58:62])

        if e_type not in (ET_EXEC, ET_DYN):
            return False
        if e_shnum > 0 and e_shentsize == 0:
            return False

        return True
    except struct.error:
        return False
