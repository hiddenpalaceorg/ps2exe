import logging

import pycdlib.inode
from pycdlib.pycdlibio import PyCdlibIO

from gamecube.path_reader import GamecubePathReader

LOGGER = logging.getLogger(__name__)


class WiiPathReader(GamecubePathReader):
    @property
    def volume_type(self):
        if not self.iso:
            return "wii"
        return f"wii partition {self.iso.partition.disc_infos.volume_group}:{self.iso.partition.disc_infos.index}"

    def open_file(self, file):
        inode_obj = pycdlib.inode.Inode()
        inode_obj.parse(file._fileoffset, file.size, self.iso.partition, 1)
        f = PyCdlibIO(inode_obj, 1)
        f.name = self.get_file_path(file)
        return f
