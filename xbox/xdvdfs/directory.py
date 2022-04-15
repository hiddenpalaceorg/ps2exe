import logging
from typing import List

from xbox.xdvdfs.directory_entry import DirectoryEntry
from xbox.xdvdfs.directory_header import DirectoryHeader

LOGGER = logging.getLogger(__name__)

class Directory:

    def __init__(self, fp, volume, loc, name, size, parent_name=''):
        # First try to seek to the offset, if this fails, bubble up
        self.start_sector = loc
        self.offset = volume.volume_base_offset + (loc * volume.sector_size)
        fp.seek(self.offset)

        self.name = name
        self.size = size
        self.directories: List[Directory] = []
        self.entries: List[DirectoryEntry] = []
        self._headers: List[DirectoryHeader] = []
        self.path = "/".join(filter(None, [parent_name, name]))
        self.fp = fp
        self.volume = volume
        if self.offset >= self.fp.length():
            LOGGER.warning("Directory %s outside of the bounds of this image", self.name)
            return
        self.parseDirectoryRecord(self.offset)

    def parseDirectoryRecord(self, offset):
        s = []
        root = DirectoryEntry(self.fp, self.volume, offset)
        s.append(root)
        while len(s) > 0:
            if root.left_subtree_offset and root.left_subtree_offset + 0xD < self.size:
                root = DirectoryEntry(self.fp, self.volume, self.offset + root.left_subtree_offset)
                s.append(root)
                continue

            root = s.pop()
            if root.file_flags & 0x10:
                if root.size:
                    try:
                        dir = Directory(self.fp, self.volume, root.start_sector, root.file_name, root.size, self.path)
                    except ValueError:
                        continue
                    if dir not in self.directories:
                        self.directories.append(dir)
            else:
                root.path = "/" + "/".join(filter(None, [self.path, root.file_name]))
                if root not in self.entries:
                    self.entries.append(root)

            if root.right_subtree_offset and root.right_subtree_offset + 0xD < self.size:
                root = DirectoryEntry(self.fp, self.volume, self.offset + root.right_subtree_offset)
                s.append(root)

    def __eq__(self, other):
        return self.__dict__ == other.__dict__