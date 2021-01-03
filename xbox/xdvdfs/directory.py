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
        s = []
        root = DirectoryEntry(self.fp, self.volume, offset)
        s.append(root)
        while len(s) > 0:
            if root.left_subtree_offset:
                root = DirectoryEntry(self.fp, self.volume, self.offset + root.left_subtree_offset)
                s.append(root)
            else:
                root = s.pop()
                if root.file_flags & 0x10:
                    if root.size:
                        dir = Directory(self.fp, self.volume, root.start_sector, root.file_name, self.name)
                        self.directories.append(dir)
                else:
                    root.path = "/" + "/".join(filter(None, [self.path, root.file_name]))
                    self.entries.append(root)
                if root.right_subtree_offset:
                    root = DirectoryEntry(self.fp, self.volume, self.offset + root.right_subtree_offset)
                    s.append(root)
