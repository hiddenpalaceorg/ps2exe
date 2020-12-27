import os
import struct
from typing import List, Any

from xbox.xdvdfs.directory_entry import DirectoryEntry
from xbox.xdvdfs.directory_header import DirectoryHeader


class Directory:

    def __init__(self, fp, volume, loc, name, parent_name=''):
        self.name = name
        self.directories: List[Directory] = []
        self.entries: List[DirectoryEntry] = []
        self._headers: List[DirectoryHeader] = []
        self.path = "/".join(filter(None, [parent_name, name]))
        self.fp = fp
        self.offset = volume.volume_base_offset + (loc * volume.sector_size)
        self.volume = volume
        self.parseDirectoryRecord(self.offset)

    def parseDirectoryRecord(self, offset):
        self.fp.seek(offset)
        left_subtree_offset, right_subtree_offset, start_sector, \
        file_size, file_flags, file_name_size = struct.unpack("HHIIBB", self.fp.read(14))
        left_subtree_offset *= 4
        right_subtree_offset *= 4
        file_name = self.fp.read(file_name_size).decode()
        if left_subtree_offset:
            self.parseDirectoryRecord(self.offset + left_subtree_offset)

        if file_flags & 0x10:
            if file_size:
                self.directories.append(Directory(self.fp, self.volume, start_sector, file_name, self.name))
        else:
            file_offset = self.volume.volume_base_offset + (start_sector * self.volume.sector_size)
            entry = DirectoryEntry(file_name, file_offset, file_size)
            entry.path = "/" + "/".join(filter(None, [self.path, entry.file_name]))
            self.entries.append(entry)


        if right_subtree_offset:
            self.parseDirectoryRecord(self.offset + right_subtree_offset)


