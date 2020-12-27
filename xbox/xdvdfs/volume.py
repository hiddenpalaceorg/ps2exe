import struct

from xbox.xdvdfs.directory import Directory
from xbox.xdvdfs.utils import filetime_to_dt


class Volume:
    def __init__(self, fp, offset):
        self.fp = fp
        self.volume_base_offset = offset - 0x10000
        self.directory_structure = []
        self.volume_size = fp.length() - self.volume_base_offset
        self.sector_size = 2048
        self.volume_sectors = self.volume_size // self.sector_size
        self.fp.seek(offset + 0x14)
        self.root_directory_sector, self.root_directory_size, tmp_volume_time = struct.unpack("IIQ", self.fp.read(16))
        self.image_creation_time = filetime_to_dt(tmp_volume_time)