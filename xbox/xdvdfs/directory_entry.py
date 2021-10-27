import struct


class DirectoryEntry:
    def __init__(self, fp, volume, offset):
        fp.seek(offset)
        self.left_subtree_offset, self.right_subtree_offset, self.start_sector, \
        self.size, self.file_flags, file_name_size = struct.unpack("HHIIBB", fp.read(14))
        self.left_subtree_offset *= 4
        self.right_subtree_offset *= 4
        self.offset = volume.volume_base_offset + (self.start_sector * volume.sector_size)
        self.file_name = fp.read(file_name_size).decode()

    def __eq__(self, other):
        return self.__dict__ == other.__dict__