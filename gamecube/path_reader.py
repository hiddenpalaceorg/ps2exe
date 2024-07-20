import io
import logging

from pycdlib import pycdlib

from common.iso_path_reader.methods.base import IsoPathReader
from common.iso_path_reader.methods.chunked_hash_trait import ChunkedHashTrait

LOGGER = logging.getLogger(__name__)

class GamecubePathReader(ChunkedHashTrait, IsoPathReader):
    volume_type = "gamecube"

    def get_root_dir(self):
        return self.iso.rootnode

    def iso_iterator(self, base_dir, recursive=False, include_dirs=False):
        for entry in base_dir.files:
            yield entry

        if not recursive:
            if include_dirs:
                for dir in base_dir.dirs:
                    yield dir
            return

        for dir in base_dir.dirs:
            if include_dirs:
                yield dir
            yield from self.iso_iterator(dir, recursive)

    def get_file(self, path):
        for file in self.iso_iterator(self.get_root_dir(), recursive=True):
            if file.path == path:
                return file
        raise FileNotFoundError

    def get_file_path(self, file):
        if hasattr(file, "path"):
            return file.path
        return file.name

    def get_file_size(self, file):
        return file.size

    def get_file_date(self, file):
        return None

    def open_file(self, file):
        inode = pycdlib.inode.Inode()
        inode.new(file.size, self.fp, False, file._fileoffset)
        reader = pycdlib.pycdlibio.PyCdlibIO(inode, 2048)
        reader.name = self.get_file_path(file)
        return reader

    def get_file_sector(self, file):
        if file._fileoffset:
            return file._fileoffset // 2048
        return 0

    def is_directory(self, file):
        return file.is_dir()

    def get_pvd(self):
        return {}

    def get_pvd_info(self):
        return {}
