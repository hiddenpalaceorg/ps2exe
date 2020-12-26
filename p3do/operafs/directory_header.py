import struct
from typing import List

from p3do.operafs.directory_entry import DirectoryEntry


class DirectoryHeader:
    SIZE = 20
    FMT = ">IIIII"

    def __init__(self, fp, data, loc):
        self.entries: List[DirectoryEntry] = []
        self.next_block, self.prev_block, self.flags, \
        self.first_free, self.first_entry = struct.unpack(self.FMT, data)

        entry_offset = 0
        while entry_offset < self.first_free:
            fp.seek(loc + self.first_entry + entry_offset)
            entry = DirectoryEntry(fp.read(DirectoryEntry.SIZE))
            self.entries.append(entry)
            entry_offset += entry.size
