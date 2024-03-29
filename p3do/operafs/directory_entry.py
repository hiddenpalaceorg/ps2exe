import struct


class DirectoryEntry:
    FLAG_FILE = 0x02
    FLAG_SPECIAL_FILE = 0x06
    FLAG_DIRECTORY = 0x07

    SIZE = 72

    FILENAMELENGTH = 32
    ENTRYTYPESIZE = 4

    FMT = f">II{ENTRYTYPESIZE}sIIIII{FILENAMELENGTH}sII"

    def __init__(self, data):
        self.flags, self.id, entry_type, self.block_size, \
        self.byte_length, self.block_length, self.burst, self.gap, file_name, \
        self.last_copy_number, self.copy_offset = struct.unpack(self.FMT, data)
        if not self.id:
            return
        try:
            self.entry_type = entry_type.strip().decode()
        except UnicodeDecodeError:
            self.entry_type = int.from_bytes(entry_type, byteorder="big")
        try:
            self.file_name = file_name.rstrip(b'\x00').decode()
        except UnicodeDecodeError:
            try:
                self.file_name = file_name.rstrip(b'\x00').decode("s-jis")
            except UnicodeDecodeError:
                self.file_name = file_name.rstrip(b'\x00').decode(encoding="cp1252", errors="replace")

    @property
    def size(self):
        return 68 + 4 * (self.last_copy_number + 1)
