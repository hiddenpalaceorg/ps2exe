import struct

from xbox.xdvdfs.directory import Directory
from xbox.xdvdfs.utils import filetime_to_dt


class Volume:
    def __init__(self, fp, offset, sector_offset=0):
        self.fp = fp
        self.sector_size = 2048
        self.volume_base_offset = max(0, offset - 0x10000)
        self.volume_base_offset += sector_offset * self.sector_size
        self.directory_structure = []
        self.volume_size = fp.length() - self.volume_base_offset
        self.volume_sectors = self.volume_size // self.sector_size
        self.fp.seek(offset + 0x14)
        self.root_directory_sector, self.root_directory_size, tmp_volume_time = struct.unpack("IIQ", self.fp.read(16))
        self.image_creation_time = filetime_to_dt(tmp_volume_time)
