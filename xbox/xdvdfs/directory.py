import logging
from typing import List

from xbox.xdvdfs.directory_entry import DirectoryEntry
from xbox.xdvdfs.directory_header import DirectoryHeader
from common.traversal import Traversal, TraversalError

LOGGER = logging.getLogger(__name__)

class Directory:

    def __init__(self, fp, volume, loc, name, size, parent_name='', _walk=None, _ancestors=frozenset()):
        # First try to seek to the offset, if this fails, bubble up
        self.start_sector = loc
        self.offset = volume.volume_base_offset + (loc * volume.sector_size)
        self._walk = _walk if _walk is not None else Traversal()
        self._ancestors = self._walk.enter(self.offset, _ancestors)
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
        # Try to seek to the offset, if this fails, bubble up
        self.fp.seek(self.offset)
        self.parseDirectoryRecord(self.offset)

    def parseDirectoryRecord(self, offset):
        s = [(offset, None)]
        visited = set()

        def read_entry(position):
            if position in visited:
                raise TraversalError("Cyclic directory entry")
            if position < self.offset or position + 14 > self.offset + self.size:
                raise TraversalError("Directory entry outside its extent")
            visited.add(position)
            self._walk.take()
            return DirectoryEntry(self.fp, self.volume, position)

        while s:
            position, root = s.pop()
            if root is None:
                root = read_entry(position)
                if root.right_subtree_offset and root.right_subtree_offset + 0xD < self.size:
                    s.append((self.offset + root.right_subtree_offset, None))
                s.append((position, root))
                if root.left_subtree_offset and root.left_subtree_offset + 0xD < self.size:
                    s.append((self.offset + root.left_subtree_offset, None))
                continue

            if root.file_flags & 0x10:
                if root.size:
                    try:
                        dir = Directory(self.fp, self.volume, root.start_sector, root.file_name, root.size, self.path, self._walk, self._ancestors)
                    except ValueError:
                        continue
                    self.directories.append(dir)
            else:
                root.path = "/" + "/".join(filter(None, [self.path, root.file_name]))
                if root not in self.entries:
                    self.entries.append(root)

    def __eq__(self, other):
        return self.__dict__ == other.__dict__
