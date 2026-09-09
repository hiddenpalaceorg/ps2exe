from typing import List, Any

from p3do.operafs.directory_entry import DirectoryEntry
from p3do.operafs.directory_header import DirectoryHeader
from common.traversal import Traversal, TraversalError


class Directory:

    def __init__(self, fp, loc, name, parent_name='', _walk=None, _ancestors=frozenset()):
        walk = _walk if _walk is not None else Traversal()
        ancestors = walk.enter(loc, _ancestors)
        self.name = name
        self.directories: List[Directory] = []
        self.entries: List[DirectoryEntry] = []
        self._headers: List[DirectoryHeader] = []
        self.path = "/".join(filter(None, [parent_name, name]))
        fp.seek(loc)
        first_header: DirectoryHeader = DirectoryHeader(fp, fp.read(DirectoryHeader.SIZE), loc)
        self._headers.append(first_header)
        next_header_block = first_header.next_block
        seen_headers = {loc}
        while next_header_block != 0xffffffff:
            header_location = loc + (next_header_block * 2048)
            if header_location in seen_headers:
                raise TraversalError("Cyclic directory header")
            seen_headers.add(header_location)
            walk.take()
            fp.seek(header_location)
            header: DirectoryHeader = DirectoryHeader(fp, fp.read(DirectoryHeader.SIZE), header_location)
            next_header_block = header.next_block
            self._headers.append(header)

        for header in self._headers:
            for entry in header.entries:
                walk.take()
                if entry.flags & DirectoryEntry.FLAG_DIRECTORY == DirectoryEntry.FLAG_DIRECTORY:
                    directory = Directory(fp, entry.copy_offset * 2048, entry.file_name, self.path, walk, ancestors)
                    self.directories.append(directory)
                    self.entries.append(entry)
                elif entry.flags & DirectoryEntry.FLAG_FILE == DirectoryEntry.FLAG_FILE:
                    entry.path = "/" + "/".join(filter(None, [self.path, entry.file_name]))
                    self.entries.append(entry)
