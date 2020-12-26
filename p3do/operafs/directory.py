from typing import List, Any

from p3do.operafs.directory_entry import DirectoryEntry
from p3do.operafs.directory_header import DirectoryHeader


class Directory:

    def __init__(self, fp, loc, name, parent_name=''):
        self.name = name
        self.directories: List[Directory] = []
        self.entries: List[DirectoryEntry] = []
        self._headers: List[DirectoryHeader] = []
        self.path = "/".join(filter(None, [parent_name, name]))
        fp.seek(loc)
        first_header: DirectoryHeader = DirectoryHeader(fp, fp.read(DirectoryHeader.SIZE), loc)
        self._headers.append(first_header)
        next_header_block = first_header.next_block
        while next_header_block != 0xffffffff:
            header_location = loc + (next_header_block * 2048)
            fp.seek(header_location)
            header: DirectoryHeader = DirectoryHeader(fp, fp.read(DirectoryHeader.SIZE), loc)
            next_header_block = header.next_block
            self._headers.append(header)

        for header in self._headers:
            for entry in header.entries:
                if entry.flags & DirectoryEntry.FLAG_DIRECTORY == DirectoryEntry.FLAG_DIRECTORY:
                    directory = Directory(fp, entry.copy_offset * 2048, entry.file_name, name)
                    self.directories.append(directory)
                elif entry.flags & DirectoryEntry.FLAG_FILE == DirectoryEntry.FLAG_FILE:
                    entry.path = "/" + "/".join(filter(None, [self.path, entry.file_name]))
                    self.entries.append(entry)
